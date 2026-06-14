use crate::collector::CollectorError;
use crate::metrics::{CoreMetrics, CpuMetrics};

#[cfg(target_os = "linux")]
use crate::platform::linux::syscall;

pub struct CpuCollector {
    prev_stats: Option<Vec<CpuRawStat>>,
    #[cfg(target_os = "linux")]
    persistent_fd: Option<syscall::PersistentFd>,
}

#[derive(Clone)]
struct CpuRawStat {
    user: u64,
    nice: u64,
    system: u64,
    idle: u64,
    iowait: u64,
    irq: u64,
    softirq: u64,
    steal: u64,
}

impl CpuCollector {
    pub fn new() -> Self {
        Self {
            prev_stats: None,
            #[cfg(target_os = "linux")]
            persistent_fd: syscall::PersistentFd::open(b"/proc/stat\0"),
        }
    }

    pub fn collect(&mut self) -> Result<CpuMetrics, CollectorError> {
        let current = self.read_stat()?;
        let result = match &self.prev_stats {
            Some(prev) => self.compute_delta(prev, &current),
            None => self.zero_metrics(current.len()),
        };
        self.prev_stats = Some(current);
        Ok(result)
    }

    #[cfg(target_os = "linux")]
    fn read_stat(&self) -> Result<Vec<CpuRawStat>, CollectorError> {
        let mut buf = [0u8; 8192];
        let n = if let Some(pfd) = &self.persistent_fd {
            pfd.reread(&mut buf)
        } else {
            syscall::read_file_to_buf(b"/proc/stat\0", &mut buf)
        };
        if n <= 0 {
            return Err(CollectorError::Io(std::io::Error::from_raw_os_error(-n as i32)));
        }
        let data = &buf[..n as usize];
        self.parse_stat_bytes(data)
    }

    #[cfg(not(target_os = "linux"))]
    fn read_stat(&self) -> Result<Vec<CpuRawStat>, CollectorError> {
        Err(CollectorError::Unsupported("CPU: not linux".into()))
    }

    fn parse_stat_bytes(&self, data: &[u8]) -> Result<Vec<CpuRawStat>, CollectorError> {
        let mut stats = Vec::with_capacity(16);
        let mut pos = 0;
        while pos < data.len() {
            // Find line start
            if pos + 3 >= data.len() || data[pos] != b'c' || data[pos + 1] != b'p' || data[pos + 2] != b'u' {
                // skip to next line
                while pos < data.len() && data[pos] != b'\n' {
                    pos += 1;
                }
                pos += 1;
                continue;
            }
            // skip "cpu" or "cpuN" prefix
            pos += 3;
            while pos < data.len() && data[pos] != b' ' && data[pos] != b'\n' {
                pos += 1;
            }
            // Parse 8+ fields
            let mut fields = [0u64; 10];
            for f in &mut fields {
                // skip whitespace
                while pos < data.len() && data[pos] == b' ' {
                    pos += 1;
                }
                if pos >= data.len() || data[pos] == b'\n' {
                    break;
                }
                let start = pos;
                while pos < data.len() && data[pos] >= b'0' && data[pos] <= b'9' {
                    pos += 1;
                }
                *f = crate::platform::linux::parse_u64_from_bytes(&data[start..pos]);
            }
            stats.push(CpuRawStat {
                user: fields[0],
                nice: fields[1],
                system: fields[2],
                idle: fields[3],
                iowait: fields[4],
                irq: fields[5],
                softirq: fields[6],
                steal: fields[7],
            });
            // skip to next line
            while pos < data.len() && data[pos] != b'\n' {
                pos += 1;
            }
            pos += 1;
        }
        if stats.is_empty() {
            return Err(CollectorError::Parse("no cpu stats".into()));
        }
        Ok(stats)
    }

    fn compute_delta(&self, prev: &[CpuRawStat], current: &[CpuRawStat]) -> CpuMetrics {
        let mut per_core = Vec::with_capacity(current.len().saturating_sub(1));
        for i in 1..current.len().min(prev.len()) {
            per_core.push(self.stat_to_pct(&prev[i], &current[i], (i - 1) as u32));
        }
        let total = if !prev.is_empty() && !current.is_empty() {
            self.stat_to_pct(&prev[0], &current[0], 0)
        } else {
            CoreMetrics {
                core_id: 0, user_pct: 0.0, system_pct: 0.0, softirq_pct: 0.0,
                hardirq_pct: 0.0, idle_pct: 100.0, iowait_pct: 0.0, steal_pct: 0.0,
            }
        };
        CpuMetrics { per_core, total }
    }

    fn stat_to_pct(&self, prev: &CpuRawStat, cur: &CpuRawStat, core_id: u32) -> CoreMetrics {
        let d_user = cur.user.wrapping_sub(prev.user) + cur.nice.wrapping_sub(prev.nice);
        let d_sys = cur.system.wrapping_sub(prev.system);
        let d_idle = cur.idle.wrapping_sub(prev.idle);
        let d_iowait = cur.iowait.wrapping_sub(prev.iowait);
        let d_irq = cur.irq.wrapping_sub(prev.irq);
        let d_softirq = cur.softirq.wrapping_sub(prev.softirq);
        let d_steal = cur.steal.wrapping_sub(prev.steal);
        let total = d_user + d_sys + d_idle + d_iowait + d_irq + d_softirq + d_steal;
        if total == 0 {
            return CoreMetrics {
                core_id, user_pct: 0.0, system_pct: 0.0, softirq_pct: 0.0,
                hardirq_pct: 0.0, idle_pct: 100.0, iowait_pct: 0.0, steal_pct: 0.0,
            };
        }
        let pct = |v: u64| -> f64 { (v as f64 / total as f64) * 100.0 };
        CoreMetrics {
            core_id,
            user_pct: pct(d_user),
            system_pct: pct(d_sys),
            softirq_pct: pct(d_softirq),
            hardirq_pct: pct(d_irq),
            idle_pct: pct(d_idle),
            iowait_pct: pct(d_iowait),
            steal_pct: pct(d_steal),
        }
    }

    fn zero_metrics(&self, count: usize) -> CpuMetrics {
        let zero_core = |id: u32| CoreMetrics {
            core_id: id, user_pct: 0.0, system_pct: 0.0, softirq_pct: 0.0,
            hardirq_pct: 0.0, idle_pct: 100.0, iowait_pct: 0.0, steal_pct: 0.0,
        };
        CpuMetrics {
            per_core: (0..count.saturating_sub(1)).map(|i| zero_core(i as u32)).collect(),
            total: zero_core(0),
        }
    }
}
