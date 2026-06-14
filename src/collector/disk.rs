use crate::collector::CollectorError;
use crate::metrics::{DiskDevice, DiskMetrics, HistogramData};
use std::collections::HashMap;
use std::fs;
use std::io::Read;

pub struct DiskCollector {
    prev_stats: HashMap<String, DiskRawStat>,
    prev_time_ns: Option<u64>,
}

#[derive(Clone)]
struct DiskRawStat {
    read_bytes: u64,
    write_bytes: u64,
    read_time_ms: u64,
    write_time_ms: u64,
    io_count: u64,
}

impl DiskCollector {
    pub fn new() -> Self {
        Self {
            prev_stats: HashMap::new(),
            prev_time_ns: None,
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

        let dt = self
            .prev_time_ns
            .map(|prev| (now_ns.saturating_sub(prev)) as f64 / 1_000_000_000.0)
            .unwrap_or(0.0);

        let mut devices = Vec::new();
        for mount in &mounts {
            let dev_name = mount.device.rsplit('/').next().unwrap_or(&mount.device);
            let (read_rate, write_rate, latency) =
                if let Some(cur) = diskstats.get(dev_name) {
                    let (rr, wr) = if dt > 0.0 {
                        if let Some(prev) = self.prev_stats.get(dev_name) {
                            let rb = cur.read_bytes.wrapping_sub(prev.read_bytes) as f64 / dt;
                            let wb = cur.write_bytes.wrapping_sub(prev.write_bytes) as f64 / dt;
                            (rb, wb)
                        } else {
                            (0.0, 0.0)
                        }
                    } else {
                        (0.0, 0.0)
                    };
                    let lat = self.estimate_latency(dev_name, cur);
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
        Err(CollectorError::Unsupported(
            "Disk collection not implemented for this platform".to_string(),
        ))
    }

    #[cfg(target_os = "linux")]
    fn read_mounts(&self) -> Result<Vec<MountEntry>, CollectorError> {
        let mut buf = String::with_capacity(4096);
        let mut file = fs::File::open("/proc/mounts")?;
        file.read_to_string(&mut buf)?;

        let mut mounts = Vec::new();
        for line in buf.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }
            let fs_type = parts[2];
            if matches!(
                fs_type,
                "ext4" | "xfs" | "btrfs" | "zfs" | "ntfs" | "vfat" | "f2fs" | "tmpfs"
            ) {
                mounts.push(MountEntry {
                    device: parts[0].to_string(),
                    mount_point: parts[1].to_string(),
                    fs_type: fs_type.to_string(),
                });
            }
        }
        Ok(mounts)
    }

    #[cfg(target_os = "linux")]
    fn read_diskstats(&self) -> Result<HashMap<String, DiskRawStat>, CollectorError> {
        let mut buf = String::with_capacity(8192);
        let mut file = fs::File::open("/proc/diskstats")?;
        file.read_to_string(&mut buf)?;

        let mut stats = HashMap::new();
        for line in buf.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 14 {
                continue;
            }
            let name = parts[2].to_string();
            let sector_size = 512u64;
            stats.insert(
                name,
                DiskRawStat {
                    read_bytes: parts[5].parse::<u64>().unwrap_or(0) * sector_size,
                    write_bytes: parts[9].parse::<u64>().unwrap_or(0) * sector_size,
                    read_time_ms: parts[6].parse().unwrap_or(0),
                    write_time_ms: parts[10].parse().unwrap_or(0),
                    io_count: parts[3].parse::<u64>().unwrap_or(0)
                        + parts[7].parse::<u64>().unwrap_or(0),
                },
            );
        }
        Ok(stats)
    }

    fn estimate_latency(&self, dev_name: &str, cur: &DiskRawStat) -> HistogramData {
        let avg_ms = if cur.io_count > 0 {
            (cur.read_time_ms + cur.write_time_ms) as f64 / cur.io_count as f64
        } else {
            0.0
        };
        // Estimate quantiles from average (real impl would use eBPF histograms)
        if let Some(prev) = self.prev_stats.get(dev_name) {
            let d_io = cur.io_count.wrapping_sub(prev.io_count);
            let d_time = (cur.read_time_ms + cur.write_time_ms)
                .wrapping_sub(prev.read_time_ms + prev.write_time_ms);
            let recent_avg = if d_io > 0 {
                d_time as f64 / d_io as f64
            } else {
                avg_ms
            };
            HistogramData {
                count: d_io,
                sum: d_time as f64,
                quantiles: vec![
                    (0.5, recent_avg * 0.8),
                    (0.9, recent_avg * 1.5),
                    (0.95, recent_avg * 2.0),
                    (0.99, recent_avg * 4.0),
                ],
            }
        } else {
            HistogramData {
                count: cur.io_count,
                sum: (cur.read_time_ms + cur.write_time_ms) as f64,
                quantiles: vec![
                    (0.5, avg_ms * 0.8),
                    (0.9, avg_ms * 1.5),
                    (0.95, avg_ms * 2.0),
                    (0.99, avg_ms * 4.0),
                ],
            }
        }
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
            let mut stat: MaybeUninit<libc_statvfs> = MaybeUninit::zeroed();
            let ret = statvfs_syscall(c_path.as_ptr(), stat.as_mut_ptr());
            if ret != 0 {
                return (0, 0, 0);
            }
            let s = stat.assume_init();
            let total = s.f_blocks * s.f_frsize;
            let avail = s.f_bavail * s.f_frsize;
            let free = s.f_bfree * s.f_frsize;
            let used = total.saturating_sub(free);
            (total, used, avail)
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn statvfs(&self, _path: &str) -> (u64, u64, u64) {
        (0, 0, 0)
    }
}

struct MountEntry {
    device: String,
    mount_point: String,
    fs_type: String,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct libc_statvfs {
    f_bsize: u64,
    f_frsize: u64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_favail: u64,
    f_fsid: u64,
    f_flag: u64,
    f_namemax: u64,
    __f_spare: [i32; 6],
}

#[cfg(target_os = "linux")]
extern "C" {
    #[link_name = "statvfs"]
    fn statvfs_syscall(path: *const i8, buf: *mut libc_statvfs) -> i32;
}
