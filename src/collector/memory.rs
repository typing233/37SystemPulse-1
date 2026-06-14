use crate::collector::CollectorError;
use crate::metrics::MemoryMetrics;

#[cfg(target_os = "linux")]
use crate::platform::linux::{parse_u64_from_bytes, syscall};

pub struct MemoryCollector {
    prev_swap_in: Option<u64>,
    prev_swap_out: Option<u64>,
    prev_time_ns: Option<u64>,
    #[cfg(target_os = "linux")]
    meminfo_fd: Option<syscall::PersistentFd>,
    #[cfg(target_os = "linux")]
    vmstat_fd: Option<syscall::PersistentFd>,
}

impl MemoryCollector {
    pub fn new() -> Self {
        Self {
            prev_swap_in: None,
            prev_swap_out: None,
            prev_time_ns: None,
            #[cfg(target_os = "linux")]
            meminfo_fd: syscall::PersistentFd::open(b"/proc/meminfo\0"),
            #[cfg(target_os = "linux")]
            vmstat_fd: syscall::PersistentFd::open(b"/proc/vmstat\0"),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn collect(&mut self) -> Result<MemoryMetrics, CollectorError> {
        let mut buf = [0u8; 4096];
        let n = if let Some(pfd) = &self.meminfo_fd {
            pfd.reread(&mut buf)
        } else {
            syscall::read_file_to_buf(b"/proc/meminfo\0", &mut buf)
        };
        if n <= 0 {
            return Err(CollectorError::Io(std::io::Error::from_raw_os_error(-n as i32)));
        }
        let data = &buf[..n as usize];

        let mut total = 0u64;
        let mut free = 0u64;
        let mut available = 0u64;
        let mut buffers = 0u64;
        let mut cached = 0u64;
        let mut swap_total = 0u64;
        let mut swap_free = 0u64;

        let mut pos = 0;
        while pos < data.len() {
            let line_start = pos;
            // find end of line
            while pos < data.len() && data[pos] != b'\n' {
                pos += 1;
            }
            let line = &data[line_start..pos];
            pos += 1;

            // Match key and extract value (in kB, convert to bytes)
            if let Some(val) = self.extract_meminfo_value(line) {
                let val_bytes = val * 1024;
                if line.starts_with(b"MemTotal:") { total = val_bytes; }
                else if line.starts_with(b"MemFree:") { free = val_bytes; }
                else if line.starts_with(b"MemAvailable:") { available = val_bytes; }
                else if line.starts_with(b"Buffers:") { buffers = val_bytes; }
                else if line.starts_with(b"Cached:") && !line.starts_with(b"CachedSwap") { cached = val_bytes; }
                else if line.starts_with(b"SwapTotal:") { swap_total = val_bytes; }
                else if line.starts_with(b"SwapFree:") { swap_free = val_bytes; }
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
        Err(CollectorError::Unsupported("Memory: not linux".into()))
    }

    #[cfg(target_os = "linux")]
    fn extract_meminfo_value(&self, line: &[u8]) -> Option<u64> {
        // Find ':' then parse number after whitespace
        let mut i = 0;
        while i < line.len() && line[i] != b':' {
            i += 1;
        }
        i += 1; // skip ':'
        while i < line.len() && line[i] == b' ' {
            i += 1;
        }
        if i >= line.len() {
            return None;
        }
        Some(parse_u64_from_bytes(&line[i..]))
    }

    #[cfg(target_os = "linux")]
    fn compute_swap_rates(&mut self) -> Result<(f64, f64), CollectorError> {
        let mut buf = [0u8; 8192];
        let n = if let Some(pfd) = &self.vmstat_fd {
            pfd.reread(&mut buf)
        } else {
            syscall::read_file_to_buf(b"/proc/vmstat\0", &mut buf)
        };
        if n <= 0 {
            return Ok((0.0, 0.0));
        }
        let data = &buf[..n as usize];

        let mut pswpin = 0u64;
        let mut pswpout = 0u64;
        let mut pos = 0;
        while pos < data.len() {
            let line_start = pos;
            while pos < data.len() && data[pos] != b'\n' {
                pos += 1;
            }
            let line = &data[line_start..pos];
            pos += 1;

            if line.starts_with(b"pswpin ") {
                pswpin = parse_u64_from_bytes(&line[7..]);
            } else if line.starts_with(b"pswpout ") {
                pswpout = parse_u64_from_bytes(&line[8..]);
            }
        }

        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let (sin_rate, sout_rate) = match (self.prev_swap_in, self.prev_swap_out, self.prev_time_ns) {
            (Some(prev_in), Some(prev_out), Some(prev_t)) => {
                let dt = (now_ns.saturating_sub(prev_t)) as f64 / 1_000_000_000.0;
                if dt > 0.0 {
                    let page_size = 4096.0;
                    (
                        (pswpin.wrapping_sub(prev_in) as f64 * page_size) / dt,
                        (pswpout.wrapping_sub(prev_out) as f64 * page_size) / dt,
                    )
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
