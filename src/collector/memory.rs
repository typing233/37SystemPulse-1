use crate::collector::CollectorError;
use crate::metrics::MemoryMetrics;
use std::fs;
use std::io::Read;

pub struct MemoryCollector {
    prev_swap_in: Option<u64>,
    prev_swap_out: Option<u64>,
    prev_time_ns: Option<u64>,
}

impl MemoryCollector {
    pub fn new() -> Self {
        Self {
            prev_swap_in: None,
            prev_swap_out: None,
            prev_time_ns: None,
        }
    }

    #[cfg(target_os = "linux")]
    pub fn collect(&mut self) -> Result<MemoryMetrics, CollectorError> {
        let mut buf = String::with_capacity(4096);
        let mut file = fs::File::open("/proc/meminfo")?;
        file.read_to_string(&mut buf)?;

        let mut total = 0u64;
        let mut free = 0u64;
        let mut available = 0u64;
        let mut buffers = 0u64;
        let mut cached = 0u64;
        let mut swap_total = 0u64;
        let mut swap_free = 0u64;

        for line in buf.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            let val: u64 = parts[1].parse().unwrap_or(0) * 1024; // kB to bytes
            match parts[0] {
                "MemTotal:" => total = val,
                "MemFree:" => free = val,
                "MemAvailable:" => available = val,
                "Buffers:" => buffers = val,
                "Cached:" => cached = val,
                "SwapTotal:" => swap_total = val,
                "SwapFree:" => swap_free = val,
                _ => {}
            }
        }

        let (swap_in_rate, swap_out_rate) = self.compute_swap_rates()?;

        Ok(MemoryMetrics {
            total_bytes: total,
            used_bytes: total.saturating_sub(free + buffers + cached),
            available_bytes: available,
            cached_bytes: cached,
            buffers_bytes: buffers,
            swap_total_bytes: swap_total,
            swap_used_bytes: swap_total.saturating_sub(swap_free),
            swap_in_rate,
            swap_out_rate,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn collect(&mut self) -> Result<MemoryMetrics, CollectorError> {
        Err(CollectorError::Unsupported(
            "Memory collection not implemented for this platform".to_string(),
        ))
    }

    #[cfg(target_os = "linux")]
    fn compute_swap_rates(&mut self) -> Result<(f64, f64), CollectorError> {
        let mut buf = String::with_capacity(2048);
        let mut file = fs::File::open("/proc/vmstat")?;
        file.read_to_string(&mut buf)?;

        let mut pswpin = 0u64;
        let mut pswpout = 0u64;
        for line in buf.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            match parts[0] {
                "pswpin" => pswpin = parts[1].parse().unwrap_or(0),
                "pswpout" => pswpout = parts[1].parse().unwrap_or(0),
                _ => {}
            }
        }

        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let (sin_rate, sout_rate) = match (self.prev_swap_in, self.prev_swap_out, self.prev_time_ns)
        {
            (Some(prev_in), Some(prev_out), Some(prev_t)) => {
                let dt = (now_ns.saturating_sub(prev_t)) as f64 / 1_000_000_000.0;
                if dt > 0.0 {
                    let page_size = 4096.0;
                    let sin = (pswpin.wrapping_sub(prev_in) as f64 * page_size) / dt;
                    let sout = (pswpout.wrapping_sub(prev_out) as f64 * page_size) / dt;
                    (sin, sout)
                } else {
                    (0.0, 0.0)
                }
            }
            _ => (0.0, 0.0),
        };

        self.prev_swap_in = Some(pswpin);
        self.prev_swap_out = Some(pswpout);
        self.prev_time_ns = Some(now_ns);

        Ok((sin_rate, sout_rate))
    }

    #[cfg(not(target_os = "linux"))]
    fn compute_swap_rates(&mut self) -> Result<(f64, f64), CollectorError> {
        Ok((0.0, 0.0))
    }
}
