use crate::collector::CollectorError;
use crate::metrics::{CgroupInfo, ProcessInfo, ProcessMetrics};
use std::collections::HashMap;
use std::fs;
use std::io::Read;

pub struct ProcessCollector;

impl ProcessCollector {
    pub fn new() -> Self {
        Self
    }

    #[cfg(target_os = "linux")]
    pub fn collect(&self) -> Result<ProcessMetrics, CollectorError> {
        let mut processes = Vec::new();
        let mut children_map: HashMap<u32, Vec<u32>> = HashMap::new();

        let entries = fs::read_dir("/proc")?;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Ok(pid) = name_str.parse::<u32>() {
                if let Ok(info) = self.read_process(pid) {
                    children_map
                        .entry(info.ppid)
                        .or_default()
                        .push(info.pid);
                    processes.push(info);
                }
            }
        }

        for proc in &mut processes {
            if let Some(children) = children_map.get(&proc.pid) {
                proc.children = children.clone();
            }
        }

        processes.sort_by(|a, b| b.cpu_pct.partial_cmp(&a.cpu_pct).unwrap_or(std::cmp::Ordering::Equal));
        processes.truncate(100); // Top 100 by CPU

        Ok(ProcessMetrics { processes })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn collect(&self) -> Result<ProcessMetrics, CollectorError> {
        Err(CollectorError::Unsupported(
            "Process collection not implemented for this platform".to_string(),
        ))
    }

    #[cfg(target_os = "linux")]
    fn read_process(&self, pid: u32) -> Result<ProcessInfo, CollectorError> {
        let stat_path = format!("/proc/{}/stat", pid);
        let mut buf = String::with_capacity(512);
        fs::File::open(&stat_path)?.read_to_string(&mut buf)?;

        let (name, rest) = self.parse_stat_line(&buf)?;
        let fields: Vec<&str> = rest.split_whitespace().collect();
        if fields.len() < 22 {
            return Err(CollectorError::Parse("stat too short".to_string()));
        }

        let state = fields[0].to_string();
        let ppid: u32 = fields[1].parse().unwrap_or(0);
        let utime: u64 = fields[11].parse().unwrap_or(0);
        let stime: u64 = fields[12].parse().unwrap_or(0);
        let num_threads: u32 = fields[17].parse().unwrap_or(1);
        let vsize: u64 = fields[20].parse().unwrap_or(0);
        let rss_pages: u64 = fields[21].parse().unwrap_or(0);
        let rss_bytes = rss_pages * 4096;

        let clock_ticks = 100u64; // sysconf(_SC_CLK_TCK) is typically 100
        let cpu_pct = (utime + stime) as f64 / clock_ticks as f64;

        let fd_count = self.count_fds(pid);
        let cgroup = self.read_cgroup(pid);

        Ok(ProcessInfo {
            pid,
            ppid,
            name,
            state,
            cpu_pct,
            mem_bytes: rss_bytes,
            open_fds: fd_count,
            threads: num_threads,
            cgroup,
            children: Vec::new(),
        })
    }

    #[cfg(target_os = "linux")]
    fn parse_stat_line<'a>(&self, line: &'a str) -> Result<(String, &'a str), CollectorError> {
        let open = line.find('(').ok_or_else(|| CollectorError::Parse("no (".to_string()))?;
        let close = line.rfind(')').ok_or_else(|| CollectorError::Parse("no )".to_string()))?;
        let name = line[open + 1..close].to_string();
        let rest = &line[close + 2..];
        Ok((name, rest))
    }

    #[cfg(target_os = "linux")]
    fn count_fds(&self, pid: u32) -> u64 {
        let fd_path = format!("/proc/{}/fd", pid);
        fs::read_dir(&fd_path)
            .map(|entries| entries.count() as u64)
            .unwrap_or(0)
    }

    #[cfg(target_os = "linux")]
    fn read_cgroup(&self, pid: u32) -> CgroupInfo {
        let cgroup_path = format!("/proc/{}/cgroup", pid);
        let mut buf = String::with_capacity(256);
        if fs::File::open(&cgroup_path)
            .and_then(|mut f| f.read_to_string(&mut buf))
            .is_err()
        {
            return CgroupInfo::default();
        }

        let path = buf
            .lines()
            .find(|l| l.starts_with("0::"))
            .map(|l| l.trim_start_matches("0::").to_string())
            .unwrap_or_default();

        if path.is_empty() || path == "/" {
            return CgroupInfo {
                path,
                ..Default::default()
            };
        }

        let cg_base = format!("/sys/fs/cgroup{}", path);
        let cpu_limit = self.read_cgroup_cpu(&cg_base);
        let mem_limit = self.read_cgroup_file_u64(&format!("{}/memory.max", cg_base));
        let mem_usage = self.read_cgroup_file_u64(&format!("{}/memory.current", cg_base));

        CgroupInfo {
            path,
            cpu_limit_cores: cpu_limit,
            memory_limit_bytes: mem_limit,
            memory_usage_bytes: mem_usage,
            io_weight: None,
        }
    }

    #[cfg(target_os = "linux")]
    fn read_cgroup_cpu(&self, base: &str) -> Option<f64> {
        let path = format!("{}/cpu.max", base);
        let mut buf = String::with_capacity(64);
        fs::File::open(&path)
            .and_then(|mut f| f.read_to_string(&mut buf))
            .ok()?;
        let parts: Vec<&str> = buf.trim().split_whitespace().collect();
        if parts.len() < 2 || parts[0] == "max" {
            return None;
        }
        let quota: f64 = parts[0].parse().ok()?;
        let period: f64 = parts[1].parse().ok()?;
        if period > 0.0 {
            Some(quota / period)
        } else {
            None
        }
    }

    #[cfg(target_os = "linux")]
    fn read_cgroup_file_u64(&self, path: &str) -> Option<u64> {
        let mut buf = String::with_capacity(32);
        fs::File::open(path)
            .and_then(|mut f| f.read_to_string(&mut buf))
            .ok()?;
        let trimmed = buf.trim();
        if trimmed == "max" {
            return None;
        }
        trimmed.parse().ok()
    }
}
