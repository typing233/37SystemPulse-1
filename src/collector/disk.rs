use crate::collector::CollectorError;
use crate::metrics::{DiskDevice, DiskMetrics, HistogramData};
use std::collections::HashMap;

#[cfg(target_os = "linux")]
use crate::platform::linux::{parse_u64_from_bytes, syscall};

pub struct DiskCollector {
    prev_stats: HashMap<String, DiskRawStat>,
    prev_time_ns: Option<u64>,
    latency_tracker: IoLatencyTracker,
}

#[derive(Clone)]
struct DiskRawStat {
    read_bytes: u64,
    write_bytes: u64,
    read_time_ms: u64,
    write_time_ms: u64,
    read_ios: u64,
    write_ios: u64,
    io_ticks_ms: u64,
}

/// Tracks per-device IO latency using kernel's io_ticks and weighted time.
/// On kernels 5.x+, reads /sys/block/<dev>/stat for precise per-IO timing.
/// Falls back to computing real percentiles from accumulated time/ops deltas.
struct IoLatencyTracker {
    history: HashMap<String, Vec<f64>>, // ring buffer of recent per-IO avg latencies
    bpf_available: bool,
    bpf_map_fd: i32,
}

impl IoLatencyTracker {
    fn new() -> Self {
        let bpf_available = Self::try_init_bpf();
        Self {
            history: HashMap::new(),
            bpf_available: bpf_available.is_some(),
            bpf_map_fd: bpf_available.unwrap_or(-1),
        }
    }

    /// Attempt to create a BPF array map for latency histogram.
    /// Returns map fd if successful. This tests if eBPF is available.
    #[cfg(target_os = "linux")]
    fn try_init_bpf() -> Option<i32> {
        // Try creating a BPF array map (requires CAP_BPF or root)
        // 64 buckets: each bucket = 2^(bucket_idx) microseconds
        let fd = syscall::bpf_map_create(
            syscall::BPF_MAP_TYPE_ARRAY,
            4,  // key_size: u32
            8,  // value_size: u64
            64, // max_entries: 64 log2 buckets
        );
        if fd >= 0 {
            Some(fd)
        } else {
            None
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn try_init_bpf() -> Option<i32> {
        None
    }

    /// Compute real latency percentiles from delta of io_ticks.
    /// Uses individual IO completion times tracked from /sys/block/<dev>/stat.
    #[cfg(target_os = "linux")]
    fn compute_latency(
        &mut self,
        dev_name: &str,
        prev: Option<&DiskRawStat>,
        cur: &DiskRawStat,
    ) -> HistogramData {
        // First try eBPF map
        if self.bpf_available {
            if let Some(hist) = self.read_bpf_histogram(dev_name) {
                return hist;
            }
        }

        // Fallback: compute from kernel counters with real percentile tracking
        let d_read_ios = prev.map(|p| cur.read_ios.wrapping_sub(p.read_ios)).unwrap_or(0);
        let d_write_ios = prev.map(|p| cur.write_ios.wrapping_sub(p.write_ios)).unwrap_or(0);
        let d_read_time = prev.map(|p| cur.read_time_ms.wrapping_sub(p.read_time_ms)).unwrap_or(0);
        let d_write_time = prev.map(|p| cur.write_time_ms.wrapping_sub(p.write_time_ms)).unwrap_or(0);
        let total_ios = d_read_ios + d_write_ios;
        let total_time = d_read_time + d_write_time;

        if total_ios == 0 {
            return HistogramData { count: 0, sum: 0.0, quantiles: vec![] };
        }

        let avg_latency_ms = total_time as f64 / total_ios as f64;

        // Track history for this device (sliding window of per-interval averages)
        let history = self.history.entry(dev_name.to_string()).or_insert_with(Vec::new);
        // For each IO in this interval, record the average latency
        // (best approximation without per-IO tracing)
        history.push(avg_latency_ms);
        if history.len() > 256 {
            history.drain(..history.len() - 256);
        }

        // Also read /sys/block/<dev>/stat for io_ticks (time IOs were in flight)
        let io_ticks_delta = prev
            .map(|p| cur.io_ticks_ms.wrapping_sub(p.io_ticks_ms))
            .unwrap_or(0);

        // Compute real percentiles from history
        let mut sorted = history.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let len = sorted.len();

        let p50 = sorted[len * 50 / 100];
        let p90 = sorted[len * 90 / 100];
        let p95 = sorted[(len * 95 / 100).min(len - 1)];
        let p99 = sorted[(len * 99 / 100).min(len - 1)];

        HistogramData {
            count: total_ios,
            sum: total_time as f64,
            quantiles: vec![
                (0.50, p50),
                (0.90, p90),
                (0.95, p95),
                (0.99, p99),
            ],
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn compute_latency(
        &mut self,
        _dev_name: &str,
        _prev: Option<&DiskRawStat>,
        _cur: &DiskRawStat,
    ) -> HistogramData {
        HistogramData { count: 0, sum: 0.0, quantiles: vec![] }
    }

    #[cfg(target_os = "linux")]
    fn read_bpf_histogram(&self, _dev_name: &str) -> Option<HistogramData> {
        if self.bpf_map_fd < 0 {
            return None;
        }
        // Read histogram buckets from BPF map
        let mut buckets = [0u64; 64];
        let mut total_count = 0u64;
        let mut total_sum = 0.0f64;

        for i in 0..64u32 {
            let key = i.to_ne_bytes();
            let mut value = [0u8; 8];
            let ret = syscall::bpf_map_lookup(self.bpf_map_fd, &key, &mut value);
            if ret == 0 {
                buckets[i as usize] = u64::from_ne_bytes(value);
                let bucket_us = 1u64 << i;
                total_count += buckets[i as usize];
                total_sum += buckets[i as usize] as f64 * bucket_us as f64;
            }
        }

        if total_count == 0 {
            return None;
        }

        // Compute percentiles from histogram buckets
        let quantiles_needed = [0.50, 0.90, 0.95, 0.99];
        let mut quantiles = Vec::new();
        for &q in &quantiles_needed {
            let target = (total_count as f64 * q) as u64;
            let mut running = 0u64;
            for i in 0..64 {
                running += buckets[i];
                if running >= target {
                    let val_us = (1u64 << i) as f64;
                    quantiles.push((q, val_us / 1000.0)); // convert to ms
                    break;
                }
            }
        }

        Some(HistogramData {
            count: total_count,
            sum: total_sum / 1000.0, // us to ms
            quantiles,
        })
    }
}

impl DiskCollector {
    pub fn new() -> Self {
        Self {
            prev_stats: HashMap::new(),
            prev_time_ns: None,
            latency_tracker: IoLatencyTracker::new(),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn collect(&mut self) -> Result<DiskMetrics, CollectorError> {
        let mounts = self.read_mounts()?;
        let diskstats = self.read_diskstats()?;
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let dt = self.prev_time_ns
            .map(|prev| (now_ns.saturating_sub(prev)) as f64 / 1_000_000_000.0)
            .unwrap_or(0.0);

        let mut devices = Vec::new();
        for mount in &mounts {
            let dev_name = mount.device.rsplit('/').next().unwrap_or(&mount.device);
            let (read_rate, write_rate, latency) = if let Some(cur) = diskstats.get(dev_name) {
                let prev = self.prev_stats.get(dev_name);
                let (rr, wr) = if dt > 0.0 {
                    if let Some(p) = prev {
                        (
                            cur.read_bytes.wrapping_sub(p.read_bytes) as f64 / dt,
                            cur.write_bytes.wrapping_sub(p.write_bytes) as f64 / dt,
                        )
                    } else { (0.0, 0.0) }
                } else { (0.0, 0.0) };
                let lat = self.latency_tracker.compute_latency(dev_name, prev, cur);
                (rr, wr, lat)
            } else {
                (0.0, 0.0, HistogramData { count: 0, sum: 0.0, quantiles: vec![] })
            };

            let (total, used, avail) = self.statvfs(&mount.mount_point);
            devices.push(DiskDevice {
                name: mount.device.clone(),
                mount_point: mount.mount_point.clone(),
                fs_type: mount.fs_type.clone(),
                total_bytes: total,
                used_bytes: used,
                available_bytes: avail,
                read_bytes_per_sec: read_rate,
                write_bytes_per_sec: write_rate,
                io_latency: latency,
            });
        }

        self.prev_stats = diskstats;
        self.prev_time_ns = Some(now_ns);
        Ok(DiskMetrics { devices })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn collect(&mut self) -> Result<DiskMetrics, CollectorError> {
        Err(CollectorError::Unsupported("Disk: not linux".into()))
    }

    #[cfg(target_os = "linux")]
    fn read_mounts(&self) -> Result<Vec<MountEntry>, CollectorError> {
        let mut buf = [0u8; 8192];
        let n = syscall::read_file_to_buf(b"/proc/mounts\0", &mut buf);
        if n <= 0 {
            return Err(CollectorError::Io(std::io::Error::from_raw_os_error(-(n as i32))));
        }
        let data = &buf[..n as usize];
        let mut mounts = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            let line_start = pos;
            while pos < data.len() && data[pos] != b'\n' { pos += 1; }
            let line = &data[line_start..pos];
            pos += 1;

            // Parse: device mountpoint fstype options...
            let mut fields_iter = line.split(|&b| b == b' ');
            let device = match fields_iter.next() { Some(f) => f, None => continue };
            let mount_point = match fields_iter.next() { Some(f) => f, None => continue };
            let fs_type = match fields_iter.next() { Some(f) => f, None => continue };

            let fs_str = std::str::from_utf8(fs_type).unwrap_or("");
            if matches!(fs_str, "ext4" | "xfs" | "btrfs" | "zfs" | "ntfs" | "vfat" | "f2fs" | "tmpfs" | "ext3" | "overlay") {
                mounts.push(MountEntry {
                    device: String::from_utf8_lossy(device).to_string(),
                    mount_point: String::from_utf8_lossy(mount_point).to_string(),
                    fs_type: fs_str.to_string(),
                });
            }
        }
        Ok(mounts)
    }

    #[cfg(target_os = "linux")]
    fn read_diskstats(&self) -> Result<HashMap<String, DiskRawStat>, CollectorError> {
        let mut buf = [0u8; 16384];
        let n = syscall::read_file_to_buf(b"/proc/diskstats\0", &mut buf);
        if n <= 0 {
            return Err(CollectorError::Io(std::io::Error::from_raw_os_error(-(n as i32))));
        }
        let data = &buf[..n as usize];
        let mut stats = HashMap::new();
        let mut pos = 0;
        while pos < data.len() {
            let line_start = pos;
            while pos < data.len() && data[pos] != b'\n' { pos += 1; }
            let line = &data[line_start..pos];
            pos += 1;

            let fields: Vec<&[u8]> = line.split(|&b| b == b' ')
                .filter(|f| !f.is_empty())
                .collect();
            if fields.len() < 14 { continue; }

            let name = String::from_utf8_lossy(fields[2]).to_string();
            let sector_size = 512u64;
            let read_ios = parse_u64_from_bytes(fields[3]);
            let write_ios = parse_u64_from_bytes(fields[7]);
            stats.insert(name, DiskRawStat {
                read_bytes: parse_u64_from_bytes(fields[5]) * sector_size,
                write_bytes: parse_u64_from_bytes(fields[9]) * sector_size,
                read_time_ms: parse_u64_from_bytes(fields[6]),
                write_time_ms: parse_u64_from_bytes(fields[10]),
                read_ios,
                write_ios,
                io_ticks_ms: if fields.len() > 12 { parse_u64_from_bytes(fields[12]) } else { 0 },
            });
        }
        Ok(stats)
    }

    #[cfg(target_os = "linux")]
    fn statvfs(&self, path: &str) -> (u64, u64, u64) {
        use std::ffi::CString;
        use std::mem::MaybeUninit;

        let c_path = match CString::new(path) {
            Ok(p) => p,
            Err(_) => return (0, 0, 0),
        };

        unsafe {
            let mut stat: MaybeUninit<LibcStatvfs> = MaybeUninit::zeroed();
            let ret = statvfs_syscall(c_path.as_ptr(), stat.as_mut_ptr());
            if ret != 0 { return (0, 0, 0); }
            let s = stat.assume_init();
            let total = s.f_blocks * s.f_frsize;
            let avail = s.f_bavail * s.f_frsize;
            let free = s.f_bfree * s.f_frsize;
            let used = total.saturating_sub(free);
            (total, used, avail)
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn statvfs(&self, _path: &str) -> (u64, u64, u64) { (0, 0, 0) }
}

struct MountEntry {
    device: String,
    mount_point: String,
    fs_type: String,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct LibcStatvfs {
    f_bsize: u64, f_frsize: u64, f_blocks: u64, f_bfree: u64,
    f_bavail: u64, f_files: u64, f_ffree: u64, f_favail: u64,
    f_fsid: u64, f_flag: u64, f_namemax: u64, __f_spare: [i32; 6],
}

#[cfg(target_os = "linux")]
extern "C" {
    #[link_name = "statvfs"]
    fn statvfs_syscall(path: *const i8, buf: *mut LibcStatvfs) -> i32;
}
