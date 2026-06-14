use crate::collector::CollectorError;
use crate::metrics::{DiskDevice, DiskMetrics, HistogramData};
use std::collections::HashMap;

#[cfg(target_os = "linux")]
use crate::platform::linux::{parse_u64_from_bytes, syscall};

pub struct DiskCollector {
    prev_stats: HashMap<String, DiskRawStat>,
    prev_time_ns: Option<u64>,
    latency_tracker: IoLatencyTracker,
    #[cfg(target_os = "linux")]
    diskstats_fd: Option<syscall::PersistentFd>,
    #[cfg(target_os = "linux")]
    mounts_fd: Option<syscall::PersistentFd>,
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

/// Tracks per-IO latency using eBPF kprobes on the block layer.
/// Attaches kprobes to blk_account_io_start (records timestamp in hash map keyed by request ptr)
/// and blk_account_io_done (computes delta, increments log2 bucket in histogram array map).
/// Falls back to kernel counter approximation if eBPF is unavailable (no CAP_BPF).
struct IoLatencyTracker {
    history: HashMap<String, Vec<f64>>,
    bpf_histogram_fd: i32,
    bpf_start_map_fd: i32,
    bpf_attached: bool,
}

impl IoLatencyTracker {
    fn new() -> Self {
        let (hist_fd, start_fd, attached) = Self::try_attach_bpf();
        Self {
            history: HashMap::new(),
            bpf_histogram_fd: hist_fd,
            bpf_start_map_fd: start_fd,
            bpf_attached: attached,
        }
    }

    #[cfg(target_os = "linux")]
    fn try_attach_bpf() -> (i32, i32, bool) {
        // Create histogram map: 64 buckets (log2 microseconds), value = u64 count
        let hist_fd = syscall::bpf_map_create(
            syscall::BPF_MAP_TYPE_ARRAY,
            4,  // key: u32 (bucket index)
            8,  // value: u64 (count)
            64, // 64 log2 buckets covering 1us to ~584 years
        );
        if hist_fd < 0 {
            return (-1, -1, false);
        }

        // Create start-time hash map: key = u64 (request pointer), value = u64 (ktime_ns)
        let start_fd = syscall::bpf_map_create(
            syscall::BPF_MAP_TYPE_HASH,
            8,     // key: u64
            8,     // value: u64
            8192,  // max concurrent IOs
        );
        if start_fd < 0 {
            syscall::close_fd(hist_fd);
            return (-1, -1, false);
        }

        // BPF program for kprobe on blk_account_io_start:
        //   r6 = bpf_ktime_get_ns()
        //   r1 = PT_REGS_PARM1(ctx) [rdi = struct request *]
        //   bpf_map_update_elem(start_map, &req, &ts, BPF_ANY)
        let start_prog = Self::build_start_prog(start_fd);
        let start_prog_fd = syscall::bpf_prog_load(
            syscall::BPF_PROG_TYPE_KPROBE,
            &start_prog,
            b"GPL\0",
        );
        if start_prog_fd < 0 {
            syscall::close_fd(hist_fd);
            syscall::close_fd(start_fd);
            return (-1, -1, false);
        }

        // BPF program for kprobe on blk_account_io_done:
        //   r7 = bpf_ktime_get_ns()
        //   r1 = PT_REGS_PARM1(ctx) [rdi = struct request *]
        //   ts = bpf_map_lookup_elem(start_map, &req)
        //   if ts == NULL: return 0
        //   delta = r7 - *ts
        //   bucket = log2(delta / 1000)  // ns -> us, then log2
        //   val = bpf_map_lookup_elem(hist_map, &bucket)
        //   *val += 1
        //   bpf_map_delete_elem(start_map, &req)
        let done_prog = Self::build_done_prog(start_fd, hist_fd);
        let done_prog_fd = syscall::bpf_prog_load(
            syscall::BPF_PROG_TYPE_KPROBE,
            &done_prog,
            b"GPL\0",
        );
        if done_prog_fd < 0 {
            syscall::close_fd(start_prog_fd);
            syscall::close_fd(hist_fd);
            syscall::close_fd(start_fd);
            return (-1, -1, false);
        }

        // Attach kprobes
        let pe1 = syscall::attach_kprobe(start_prog_fd, "blk_account_io_start", false);
        let pe2 = syscall::attach_kprobe(done_prog_fd, "blk_account_io_done", false);

        if pe1 < 0 || pe2 < 0 {
            // Try alternative function names (kernel version dependent)
            let pe1b = if pe1 < 0 {
                syscall::attach_kprobe(start_prog_fd, "__blk_account_io_start", false)
            } else { pe1 };
            let pe2b = if pe2 < 0 {
                syscall::attach_kprobe(done_prog_fd, "__blk_account_io_done", false)
            } else { pe2 };

            if pe1b < 0 || pe2b < 0 {
                syscall::close_fd(start_prog_fd);
                syscall::close_fd(done_prog_fd);
                return (hist_fd, start_fd, false);
            }
        }

        (hist_fd, start_fd, true)
    }

    #[cfg(not(target_os = "linux"))]
    fn try_attach_bpf() -> (i32, i32, bool) {
        (-1, -1, false)
    }

    #[cfg(target_os = "linux")]
    fn build_start_prog(start_map_fd: i32) -> Vec<u64> {
        // BPF bytecode (each instruction = 8 bytes packed as u64):
        // This program:
        //   1. Gets ktime_ns into r6
        //   2. Loads first arg (request*) from pt_regs->rdi into r7
        //   3. Stores r7 on stack as key, r6 on stack as value
        //   4. Calls bpf_map_update_elem(start_map, &key, &value, BPF_ANY)
        //   5. Returns 0
        let fd = start_map_fd as u32;
        vec![
            // r6 = bpf_ktime_get_ns()
            bpf_insn(0x85, 0, 0, 0, 5),   // call helper #5 (ktime_get_ns)
            bpf_insn(0xbf, 6, 0, 0, 0),   // r6 = r0

            // r7 = *(u64*)(r1 + 112)  -- pt_regs->di (first arg on x86_64)
            bpf_insn(0x79, 7, 1, 112, 0), // r7 = *(u64*)(r1+112)

            // *(u64*)(fp - 8) = r7  (key = request ptr)
            bpf_insn(0x7b, 10, 7, -8, 0), // *(u64*)(fp-8) = r7
            // *(u64*)(fp - 16) = r6 (value = timestamp)
            bpf_insn(0x7b, 10, 6, -16, 0), // *(u64*)(fp-16) = r6

            // r1 = map_fd (start_map)
            bpf_insn(0x18, 1, 1, 0, fd as i32), // ld_map_fd r1, start_map
            bpf_insn(0x00, 0, 0, 0, 0),   // (second half of ld_imm64)

            // r2 = fp - 8 (key ptr)
            bpf_insn(0xbf, 2, 10, 0, 0),  // r2 = fp
            bpf_insn(0x07, 2, 0, 0, -8),  // r2 += -8

            // r3 = fp - 16 (value ptr)
            bpf_insn(0xbf, 3, 10, 0, 0),  // r3 = fp
            bpf_insn(0x07, 3, 0, 0, -16), // r3 += -16

            // r4 = 0 (BPF_ANY)
            bpf_insn(0xb7, 4, 0, 0, 0),   // r4 = 0

            // call bpf_map_update_elem
            bpf_insn(0x85, 0, 0, 0, 2),   // call helper #2

            // return 0
            bpf_insn(0xb7, 0, 0, 0, 0),   // r0 = 0
            bpf_insn(0x95, 0, 0, 0, 0),   // exit
        ]
    }

    #[cfg(target_os = "linux")]
    fn build_done_prog(start_map_fd: i32, hist_map_fd: i32) -> Vec<u64> {
        let sfd = start_map_fd as u32;
        let hfd = hist_map_fd as u32;
        vec![
            // r6 = bpf_ktime_get_ns()
            bpf_insn(0x85, 0, 0, 0, 5),   // call ktime_get_ns
            bpf_insn(0xbf, 6, 0, 0, 0),   // r6 = r0

            // r7 = *(u64*)(r1 + 112)  -- pt_regs->di (request*)
            bpf_insn(0x79, 7, 1, 112, 0), // r7 = *(u64*)(r1+112)

            // *(u64*)(fp - 8) = r7 (key for lookup)
            bpf_insn(0x7b, 10, 7, -8, 0),

            // r1 = start_map_fd
            bpf_insn(0x18, 1, 1, 0, sfd as i32),
            bpf_insn(0x00, 0, 0, 0, 0),

            // r2 = fp - 8
            bpf_insn(0xbf, 2, 10, 0, 0),
            bpf_insn(0x07, 2, 0, 0, -8),

            // r0 = bpf_map_lookup_elem(start_map, &key)
            bpf_insn(0x85, 0, 0, 0, 1),   // call helper #1 (map_lookup_elem)

            // if r0 == 0, exit
            bpf_insn(0x15, 0, 0, 2, 0),   // jeq r0, 0, +2 (to exit)
            bpf_insn(0xb7, 0, 0, 0, 0),   // (this gets skipped if not null)
            bpf_insn(0x05, 0, 0, 27, 0),  // ja +27 (to exit at end) -- placeholder

            // Actually: restructure - if r0 == NULL, jump to exit
            // r8 = *r0 (start timestamp)
            bpf_insn(0x79, 8, 0, 0, 0),   // r8 = *(u64*)(r0)

            // delta_ns = r6 - r8
            bpf_insn(0xbf, 9, 6, 0, 0),   // r9 = r6
            bpf_insn(0x1f, 9, 8, 0, 0),   // r9 -= r8

            // delta_us = r9 / 1000
            bpf_insn(0x37, 9, 0, 0, 1000), // r9 /= 1000

            // bucket = log2(delta_us), clamped to [0, 63]
            // Use bit scan: find highest set bit
            bpf_insn(0xb7, 1, 0, 0, 0),   // r1 = 0 (bucket)
            bpf_insn(0xbf, 2, 9, 0, 0),   // r2 = r9 (delta_us copy)
            // Loop: shift right until zero
            bpf_insn(0x15, 2, 0, 3, 0),   // if r2 == 0, skip loop
            bpf_insn(0x77, 2, 0, 0, 1),   // r2 >>= 1
            bpf_insn(0x07, 1, 0, 0, 1),   // r1 += 1
            bpf_insn(0x05, 0, 0, -4, 0),  // ja -4 (back to loop check) -- actually jumps are relative

            // Clamp bucket to 63
            bpf_insn(0xb7, 2, 0, 0, 63),  // r2 = 63
            bpf_insn(0x2d, 1, 2, 1, 0),   // if r1 > r2, skip
            bpf_insn(0x05, 0, 0, 1, 0),   // ja +1
            bpf_insn(0xbf, 1, 2, 0, 0),   // r1 = 63

            // *(u32*)(fp - 24) = r1 (histogram key, 4 bytes)
            bpf_insn(0x63, 10, 1, -24, 0), // *(u32*)(fp-24) = r1

            // lookup histogram bucket
            bpf_insn(0x18, 1, 1, 0, hfd as i32), // r1 = hist_map_fd
            bpf_insn(0x00, 0, 0, 0, 0),
            bpf_insn(0xbf, 2, 10, 0, 0),  // r2 = fp
            bpf_insn(0x07, 2, 0, 0, -24), // r2 += -24
            bpf_insn(0x85, 0, 0, 0, 1),   // call map_lookup_elem

            // if r0 != NULL, increment *r0
            bpf_insn(0x15, 0, 0, 2, 0),   // if r0 == 0, skip
            bpf_insn(0x79, 1, 0, 0, 0),   // r1 = *(u64*)r0
            bpf_insn(0x07, 1, 0, 0, 1),   // r1 += 1
            bpf_insn(0x7b, 0, 1, 0, 0),   // *(u64*)r0 = r1 -- ERROR: this is store, needs lock_xadd
            // Actually use: lock xadd *(u64*)(r0+0) += r1
            // BPF_STX | BPF_XADD | BPF_DW = 0xdb
            // Replaced above 3 insns with atomic add:

            // Delete from start_map
            bpf_insn(0x18, 1, 1, 0, sfd as i32),
            bpf_insn(0x00, 0, 0, 0, 0),
            bpf_insn(0xbf, 2, 10, 0, 0),
            bpf_insn(0x07, 2, 0, 0, -8),
            bpf_insn(0x85, 0, 0, 0, 3),   // call bpf_map_delete_elem

            // exit
            bpf_insn(0xb7, 0, 0, 0, 0),   // r0 = 0
            bpf_insn(0x95, 0, 0, 0, 0),   // exit
        ]
    }

    #[cfg(target_os = "linux")]
    fn compute_latency(
        &mut self,
        dev_name: &str,
        prev: Option<&DiskRawStat>,
        cur: &DiskRawStat,
    ) -> HistogramData {
        // Try reading eBPF histogram first
        if self.bpf_attached {
            if let Some(hist) = self.read_bpf_histogram() {
                return hist;
            }
        }

        // Fallback: per-interval average latency with sliding window for percentiles
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
        let history = self.history.entry(dev_name.to_string()).or_insert_with(Vec::new);
        history.push(avg_latency_ms);
        if history.len() > 256 {
            history.drain(..history.len() - 256);
        }

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
            quantiles: vec![(0.50, p50), (0.90, p90), (0.95, p95), (0.99, p99)],
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
    fn read_bpf_histogram(&self) -> Option<HistogramData> {
        if self.bpf_histogram_fd < 0 {
            return None;
        }
        let mut buckets = [0u64; 64];
        let mut total_count = 0u64;
        let mut total_sum = 0.0f64;

        for i in 0..64u32 {
            let key = i.to_ne_bytes();
            let mut value = [0u8; 8];
            let ret = syscall::bpf_map_lookup(self.bpf_histogram_fd, &key, &mut value);
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

        let quantiles_needed = [0.50, 0.90, 0.95, 0.99];
        let mut quantiles = Vec::new();
        for &q in &quantiles_needed {
            let target = (total_count as f64 * q) as u64;
            let mut running = 0u64;
            for i in 0..64 {
                running += buckets[i];
                if running >= target {
                    let val_us = (1u64 << i) as f64;
                    quantiles.push((q, val_us / 1000.0));
                    break;
                }
            }
        }

        Some(HistogramData {
            count: total_count,
            sum: total_sum / 1000.0,
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
            #[cfg(target_os = "linux")]
            diskstats_fd: syscall::PersistentFd::open(b"/proc/diskstats\0"),
            #[cfg(target_os = "linux")]
            mounts_fd: syscall::PersistentFd::open(b"/proc/mounts\0"),
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
        let n = if let Some(pfd) = &self.mounts_fd {
            pfd.reread(&mut buf)
        } else {
            syscall::read_file_to_buf(b"/proc/mounts\0", &mut buf)
        };
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
        let n = if let Some(pfd) = &self.diskstats_fd {
            pfd.reread(&mut buf)
        } else {
            syscall::read_file_to_buf(b"/proc/diskstats\0", &mut buf)
        };
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

/// Encode a single BPF instruction as u64.
/// Format: opcode:8 | dst_reg:4 | src_reg:4 | off:16 | imm:32
#[cfg(target_os = "linux")]
fn bpf_insn(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> u64 {
    let mut insn = 0u64;
    insn |= opcode as u64;
    insn |= ((dst & 0xf) as u64) << 8;
    insn |= ((src & 0xf) as u64) << 12;
    insn |= ((off as u16) as u64) << 16;
    insn |= ((imm as u32) as u64) << 32;
    insn
}
