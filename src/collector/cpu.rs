use crate::collector::CollectorError;
use crate::metrics::{CoreMetrics, CpuMetrics};
use std::fs;
use std::io::Read;

pub struct CpuCollector {
    prev_stats: Option<Vec<CpuRawStat>>,
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
        Self { prev_stats: None }
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
        let mut buf = String::with_capacity(4096);
        let mut file = fs::File::open("/proc/stat")?;
        file.read_to_string(&mut buf)?;

        let mut stats = Vec::new();
        for line in buf.lines() {
            if !line.starts_with("cpu") {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 8 {
                continue;
            }
            let parse = |i: usize| -> u64 { parts[i].parse().unwrap_or(0) };
            stats.push(CpuRawStat {
                user: parse(1),
                nice: parse(2),
                system: parse(3),
                idle: parse(4),
                iowait: if parts.len() > 5 { parse(5) } else { 0 },
                irq: if parts.len() > 6 { parse(6) } else { 0 },
                softirq: if parts.len() > 7 { parse(7) } else { 0 },
                steal: if parts.len() > 8 { parse(8) } else { 0 },
            });
        }
        if stats.is_empty() {
            return Err(CollectorError::Parse("no CPU stats found".to_string()));
        }
        Ok(stats)
    }

    #[cfg(not(target_os = "linux"))]
    fn read_stat(&self) -> Result<Vec<CpuRawStat>, CollectorError> {
        Err(CollectorError::Unsupported(
            "CPU collection not implemented for this platform".to_string(),
        ))
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
                core_id: 0,
                user_pct: 0.0,
                system_pct: 0.0,
                softirq_pct: 0.0,
                hardirq_pct: 0.0,
                idle_pct: 100.0,
                iowait_pct: 0.0,
                steal_pct: 0.0,
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
                core_id,
                user_pct: 0.0,
                system_pct: 0.0,
                softirq_pct: 0.0,
                hardirq_pct: 0.0,
                idle_pct: 100.0,
                iowait_pct: 0.0,
                steal_pct: 0.0,
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
            core_id: id,
            user_pct: 0.0,
            system_pct: 0.0,
            softirq_pct: 0.0,
            hardirq_pct: 0.0,
            idle_pct: 100.0,
            iowait_pct: 0.0,
            steal_pct: 0.0,
        };
        let per_core = (0..count.saturating_sub(1))
            .map(|i| zero_core(i as u32))
            .collect();
        CpuMetrics {
            per_core,
            total: zero_core(0),
        }
    }
}
