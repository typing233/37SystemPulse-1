use crate::collector::CollectorError;
use crate::metrics::{CgroupInfo, ProcessInfo, ProcessMetrics};
use std::collections::HashMap;

#[cfg(target_os = "linux")]
use crate::platform::linux::{parse_u64_from_bytes, syscall};

pub struct ProcessCollector {
    prev_ticks: HashMap<u32, ProcTicks>,
    prev_time_ns: Option<u64>,
    clock_ticks_per_sec: u64,
}

#[derive(Clone)]
struct ProcTicks {
    utime: u64,
    stime: u64,
}

impl ProcessCollector {
    pub fn new() -> Self {
        Self {
            prev_ticks: HashMap::new(),
            prev_time_ns: None,
            clock_ticks_per_sec: 100, // standard on Linux
        }
    }

    #[cfg(target_os = "linux")]
    pub fn collect(&mut self) -> Result<ProcessMetrics, CollectorError> {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let dt_secs = self.prev_time_ns
            .map(|prev| (now_ns.saturating_sub(prev)) as f64 / 1_000_000_000.0)
            .unwrap_or(0.0);

        let mut processes = Vec::new();
        let mut children_map: HashMap<u32, Vec<u32>> = HashMap::new();
        let mut new_ticks: HashMap<u32, ProcTicks> = HashMap::new();

        // Read /proc directory using raw getdents64
        let fd = syscall::open_readonly(b"/proc\0");
        if fd < 0 {
            return Err(CollectorError::Io(std::io::Error::from_raw_os_error(-fd)));
        }
        let mut dir_buf = [0u8; 8192];
        let mut pids = Vec::with_capacity(512);
        loop {
            let n = syscall::getdents64(fd, &mut dir_buf);
            if n <= 0 { break; }
            let mut offset = 0;
            while offset < n as usize {
                let ent = unsafe {
                    &*(dir_buf.as_ptr().add(offset) as *const syscall::LinuxDirent64)
                };
                if ent.d_reclen == 0 { break; }
                // Check if entry name is numeric (PID)
                let name_ptr = unsafe { dir_buf.as_ptr().add(offset + 19) };
                let first_byte = unsafe { *name_ptr };
                if first_byte >= b'0' && first_byte <= b'9' {
                    // Parse PID from name
                    let mut pid = 0u32;
                    let mut i = 0;
                    loop {
                        let b = unsafe { *name_ptr.add(i) };
                        if b < b'0' || b > b'9' { break; }
                        pid = pid * 10 + (b - b'0') as u32;
                        i += 1;
                    }
                    if pid > 0 {
                        pids.push(pid);
                    }
                }
                offset += ent.d_reclen as usize;
            }
        }
        syscall::close_fd(fd);

        for pid in &pids {
            if let Ok((info, ticks)) = self.read_process_fast(*pid, dt_secs) {
                children_map.entry(info.ppid).or_default().push(info.pid);
                new_ticks.insert(*pid, ticks);
                processes.push(info);
            }
        }

        // Build children relationships
        for proc in &mut processes {
            if let Some(children) = children_map.get(&proc.pid) {
                proc.children = children.clone();
            }
        }

        self.prev_ticks = new_ticks;
        self.prev_time_ns = Some(now_ns);

        // Sort by CPU% descending, take top 50
        processes.sort_by(|a, b| b.cpu_pct.partial_cmp(&a.cpu_pct).unwrap_or(std::cmp::Ordering::Equal));
        processes.truncate(50);

        // Only count FDs and cgroup details for top processes (expensive operations)
        let mut path_buf = [0u8; 64];
        for proc in &mut processes {
            let fd_path_len = self.format_proc_path(proc.pid, b"fd", &mut path_buf);
            proc.open_fds = syscall::count_dir_entries(&path_buf[..fd_path_len]);
            proc.cgroup = self.read_cgroup(proc.pid);
        }

        Ok(ProcessMetrics { processes })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn collect(&mut self) -> Result<ProcessMetrics, CollectorError> {
        Err(CollectorError::Unsupported("Process: not linux".into()))
    }

    #[cfg(target_os = "linux")]
    fn read_process_fast(&self, pid: u32, dt_secs: f64) -> Result<(ProcessInfo, ProcTicks), CollectorError> {
        let mut path_buf = [0u8; 64];
        let path_len = self.format_proc_path(pid, b"stat", &mut path_buf);
        let mut stat_buf = [0u8; 1024];
        let n = syscall::read_file_to_buf(&path_buf[..path_len], &mut stat_buf);
        if n <= 0 {
            return Err(CollectorError::Io(std::io::Error::from_raw_os_error(-(n as i32))));
        }
        let stat_data = &stat_buf[..n as usize];

        let (name, after_name) = self.parse_comm(stat_data)?;
        let fields: Vec<&[u8]> = after_name.split(|&b| b == b' ')
            .filter(|f| !f.is_empty())
            .collect();
        if fields.len() < 22 {
            return Err(CollectorError::Parse("stat too short".into()));
        }

        let state_byte = fields[0];
        let ppid = parse_u64_from_bytes(fields[1]) as u32;
        let utime = parse_u64_from_bytes(fields[11]);
        let stime = parse_u64_from_bytes(fields[12]);
        let num_threads = parse_u64_from_bytes(fields[17]) as u32;
        let rss_pages = parse_u64_from_bytes(fields[21]);
        let rss_bytes = rss_pages * 4096;

        let cpu_pct = if dt_secs > 0.001 {
            if let Some(prev) = self.prev_ticks.get(&pid) {
                let d_utime = utime.wrapping_sub(prev.utime);
                let d_stime = stime.wrapping_sub(prev.stime);
                let total_ticks = d_utime + d_stime;
                (total_ticks as f64 / (dt_secs * self.clock_ticks_per_sec as f64)) * 100.0
            } else { 0.0 }
        } else { 0.0 };

        let ticks = ProcTicks { utime, stime };
        let state_str = std::str::from_utf8(state_byte).unwrap_or("?").to_string();

        Ok((ProcessInfo {
            pid, ppid, name, state: state_str, cpu_pct,
            mem_bytes: rss_bytes, open_fds: 0, threads: num_threads,
            cgroup: CgroupInfo::default(), children: Vec::new(),
        }, ticks))
    }

    #[cfg(target_os = "linux")]
    fn read_process(&self, pid: u32, dt_secs: f64) -> Result<(ProcessInfo, ProcTicks), CollectorError> {
        // Read /proc/<pid>/stat using raw syscall
        let mut path_buf = [0u8; 64];
        let path_len = self.format_proc_path(pid, b"stat", &mut path_buf);
        let mut stat_buf = [0u8; 1024];
        let n = syscall::read_file_to_buf(&path_buf[..path_len], &mut stat_buf);
        if n <= 0 {
            return Err(CollectorError::Io(std::io::Error::from_raw_os_error(-(n as i32))));
        }
        let stat_data = &stat_buf[..n as usize];

        // Parse: pid (comm) state ppid ... utime stime ...
        let (name, after_name) = self.parse_comm(stat_data)?;
        let fields: Vec<&[u8]> = after_name.split(|&b| b == b' ')
            .filter(|f| !f.is_empty())
            .collect();
        // fields[0] = state, fields[1] = ppid, ...
        // utime is field index 11 (0-based from after comm), stime is 12
        if fields.len() < 22 {
            return Err(CollectorError::Parse("stat too short".into()));
        }

        let state_byte = fields[0];
        let ppid = parse_u64_from_bytes(fields[1]) as u32;
        let utime = parse_u64_from_bytes(fields[11]);
        let stime = parse_u64_from_bytes(fields[12]);
        let num_threads = parse_u64_from_bytes(fields[17]) as u32;
        let rss_pages = parse_u64_from_bytes(fields[21]);
        let rss_bytes = rss_pages * 4096;

        // Compute CPU% as delta / (dt * CLK_TCK) * 100
        let cpu_pct = if dt_secs > 0.001 {
            if let Some(prev) = self.prev_ticks.get(&pid) {
                let d_utime = utime.wrapping_sub(prev.utime);
                let d_stime = stime.wrapping_sub(prev.stime);
                let total_ticks = d_utime + d_stime;
                (total_ticks as f64 / (dt_secs * self.clock_ticks_per_sec as f64)) * 100.0
            } else {
                0.0
            }
        } else {
            0.0
        };

        let ticks = ProcTicks { utime, stime };

        // Count FDs using raw getdents64
        let fd_path_len = self.format_proc_path(pid, b"fd", &mut path_buf);
        let fd_count = syscall::count_dir_entries(&path_buf[..fd_path_len]);

        // Read cgroup info
        let cgroup = self.read_cgroup(pid);

        let state_str = std::str::from_utf8(state_byte).unwrap_or("?").to_string();

        Ok((ProcessInfo {
            pid,
            ppid,
            name,
            state: state_str,
            cpu_pct,
            mem_bytes: rss_bytes,
            open_fds: fd_count,
            threads: num_threads,
            cgroup,
            children: Vec::new(),
        }, ticks))
    }

    #[cfg(target_os = "linux")]
    fn parse_comm<'a>(&self, data: &'a [u8]) -> Result<(String, &'a [u8]), CollectorError> {
        let open = data.iter().position(|&b| b == b'(')
            .ok_or_else(|| CollectorError::Parse("no (".into()))?;
        // rfind ')'
        let close = data.iter().rposition(|&b| b == b')')
            .ok_or_else(|| CollectorError::Parse("no )".into()))?;
        let name = String::from_utf8_lossy(&data[open + 1..close]).to_string();
        let rest = if close + 2 < data.len() { &data[close + 2..] } else { &[] };
        Ok((name, rest))
    }

    #[cfg(target_os = "linux")]
    fn format_proc_path(&self, pid: u32, suffix: &[u8], buf: &mut [u8]) -> usize {
        let prefix = b"/proc/";
        let mut pos = 0;
        buf[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        // Write PID digits
        let mut digits = [0u8; 10];
        let mut d_pos = 0;
        let mut p = pid;
        if p == 0 {
            digits[0] = b'0';
            d_pos = 1;
        } else {
            while p > 0 {
                digits[d_pos] = b'0' + (p % 10) as u8;
                p /= 10;
                d_pos += 1;
            }
        }
        for i in (0..d_pos).rev() {
            buf[pos] = digits[i];
            pos += 1;
        }
        buf[pos] = b'/';
        pos += 1;
        buf[pos..pos + suffix.len()].copy_from_slice(suffix);
        pos += suffix.len();
        buf[pos] = 0; // null terminate
        pos + 1
    }

    #[cfg(target_os = "linux")]
    fn read_cgroup(&self, pid: u32) -> CgroupInfo {
        let mut path_buf = [0u8; 64];
        let path_len = self.format_proc_path(pid, b"cgroup", &mut path_buf);
        let mut buf = [0u8; 512];
        let n = syscall::read_file_to_buf(&path_buf[..path_len], &mut buf);
        if n <= 0 {
            return CgroupInfo::default();
        }
        let data = &buf[..n as usize];

        // Find "0::" line for cgroup v2
        let mut cg_path = String::new();
        let mut pos = 0;
        while pos < data.len() {
            let line_start = pos;
            while pos < data.len() && data[pos] != b'\n' { pos += 1; }
            let line = &data[line_start..pos];
            pos += 1;
            if line.starts_with(b"0::") {
                cg_path = String::from_utf8_lossy(&line[3..]).trim().to_string();
                break;
            }
        }

        if cg_path.is_empty() || cg_path == "/" {
            return CgroupInfo { path: cg_path, ..Default::default() };
        }

        // Read cgroup limits from /sys/fs/cgroup/<path>/
        let cg_base = format!("/sys/fs/cgroup{}", cg_path);
        let cpu_limit = self.read_cgroup_cpu_limit(&cg_base);
        let mem_limit = self.read_cgroup_value(&format!("{}/memory.max\0", cg_base));
        let mem_usage = self.read_cgroup_value(&format!("{}/memory.current\0", cg_base));
        let io_weight = self.read_cgroup_io_weight(&cg_base);

        CgroupInfo {
            path: cg_path,
            cpu_limit_cores: cpu_limit,
            memory_limit_bytes: mem_limit,
            memory_usage_bytes: mem_usage,
            io_weight,
        }
    }

    #[cfg(target_os = "linux")]
    fn read_cgroup_cpu_limit(&self, base: &str) -> Option<f64> {
        let path = format!("{}/cpu.max\0", base);
        let mut buf = [0u8; 64];
        let n = syscall::read_file_to_buf(path.as_bytes(), &mut buf);
        if n <= 0 { return None; }
        let data = &buf[..n as usize];
        // Format: "quota period" or "max period"
        if data.starts_with(b"max") { return None; }
        let fields: Vec<&[u8]> = data.split(|&b| b == b' ' || b == b'\n')
            .filter(|f| !f.is_empty()).collect();
        if fields.len() < 2 { return None; }
        let quota = parse_u64_from_bytes(fields[0]) as f64;
        let period = parse_u64_from_bytes(fields[1]) as f64;
        if period > 0.0 { Some(quota / period) } else { None }
    }

    #[cfg(target_os = "linux")]
    fn read_cgroup_value(&self, path: &str) -> Option<u64> {
        let mut buf = [0u8; 32];
        let n = syscall::read_file_to_buf(path.as_bytes(), &mut buf);
        if n <= 0 { return None; }
        let data = &buf[..n as usize];
        if data.starts_with(b"max") { return None; }
        Some(parse_u64_from_bytes(data))
    }

    #[cfg(target_os = "linux")]
    fn read_cgroup_io_weight(&self, base: &str) -> Option<u32> {
        let path = format!("{}/io.weight\0", base);
        let mut buf = [0u8; 64];
        let n = syscall::read_file_to_buf(path.as_bytes(), &mut buf);
        if n <= 0 { return None; }
        let data = &buf[..n as usize];
        // Format: "default <weight>" or just a number
        if data.starts_with(b"default ") {
            Some(parse_u64_from_bytes(&data[8..]) as u32)
        } else {
            Some(parse_u64_from_bytes(data) as u32)
        }
    }
}
