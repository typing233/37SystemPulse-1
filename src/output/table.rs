use crate::metrics::SystemSnapshot;
use crate::output::{OutputBackend, OutputError};
use std::io::Write;

pub struct TableBackend;

impl TableBackend {
    pub fn new() -> Self {
        Self
    }
}

impl OutputBackend for TableBackend {
    fn write(&self, snapshot: &SystemSnapshot) -> Result<(), OutputError> {
        let stdout = std::io::stdout();
        let mut w = stdout.lock();

        // Clear screen
        write!(w, "\x1b[2J\x1b[H")?;

        // Header
        writeln!(w, "\x1b[1;36m=== SysPulse Monitor === {}\x1b[0m", snapshot.hostname)?;
        writeln!(w, "Thermal: {:.1}°C max", snapshot.thermal.max_temp_celsius)?;
        writeln!(w)?;

        // CPU
        writeln!(w, "\x1b[1;33m── CPU ──\x1b[0m")?;
        writeln!(
            w,
            "  Total: usr={:.1}% sys={:.1}% sirq={:.1}% hirq={:.1}% idle={:.1}%",
            snapshot.cpu.total.user_pct,
            snapshot.cpu.total.system_pct,
            snapshot.cpu.total.softirq_pct,
            snapshot.cpu.total.hardirq_pct,
            snapshot.cpu.total.idle_pct,
        )?;
        for core in &snapshot.cpu.per_core {
            let bar_len = ((100.0 - core.idle_pct) / 5.0) as usize;
            let bar: String = "█".repeat(bar_len.min(20));
            writeln!(
                w,
                "  core{:>2}: [{:<20}] {:.1}%",
                core.core_id,
                bar,
                100.0 - core.idle_pct,
            )?;
        }
        writeln!(w)?;

        // Memory
        writeln!(w, "\x1b[1;33m── Memory ──\x1b[0m")?;
        let mem = &snapshot.memory;
        writeln!(
            w,
            "  Total: {} | Used: {} | Avail: {} | Cached: {}",
            Self::human_bytes(mem.total_bytes),
            Self::human_bytes(mem.used_bytes),
            Self::human_bytes(mem.available_bytes),
            Self::human_bytes(mem.cached_bytes),
        )?;
        writeln!(
            w,
            "  Swap: {}/{} | In: {}/s Out: {}/s",
            Self::human_bytes(mem.swap_used_bytes),
            Self::human_bytes(mem.swap_total_bytes),
            Self::human_bytes(mem.swap_in_rate as u64),
            Self::human_bytes(mem.swap_out_rate as u64),
        )?;
        writeln!(w)?;

        // Disk
        writeln!(w, "\x1b[1;33m── Disk ──\x1b[0m")?;
        writeln!(
            w,
            "  {:20} {:8} {:>10} {:>10} {:>10} {:>10}",
            "DEVICE", "FS", "TOTAL", "USED", "RD/s", "WR/s"
        )?;
        for dev in &snapshot.disk.devices {
            writeln!(
                w,
                "  {:20} {:8} {:>10} {:>10} {:>10} {:>10}",
                Self::truncate(&dev.mount_point, 20),
                dev.fs_type,
                Self::human_bytes(dev.total_bytes),
                Self::human_bytes(dev.used_bytes),
                Self::human_bytes(dev.read_bytes_per_sec as u64),
                Self::human_bytes(dev.write_bytes_per_sec as u64),
            )?;
            if !dev.io_latency.quantiles.is_empty() {
                write!(w, "    latency:")?;
                for (q, v) in &dev.io_latency.quantiles {
                    write!(w, " p{}={:.1}ms", (q * 100.0) as u32, v)?;
                }
                writeln!(w)?;
            }
        }
        writeln!(w)?;

        // Network
        writeln!(w, "\x1b[1;33m── Network ──\x1b[0m")?;
        writeln!(
            w,
            "  TCP conns: {} | Retransmit: {:.3}% | Loss: {:.3}%",
            snapshot.network.tcp_connections,
            snapshot.network.tcp_retransmit_rate,
            snapshot.network.packet_loss_rate,
        )?;
        for iface in &snapshot.network.interfaces {
            writeln!(
                w,
                "  {}: rx={}/s tx={}/s drop_rx={} drop_tx={}",
                iface.name,
                Self::human_bytes(iface.rx_bytes_per_sec as u64),
                Self::human_bytes(iface.tx_bytes_per_sec as u64),
                iface.rx_dropped,
                iface.tx_dropped,
            )?;
        }
        writeln!(w)?;

        // Processes (top 10)
        writeln!(w, "\x1b[1;33m── Top Processes ──\x1b[0m")?;
        writeln!(
            w,
            "  {:>6} {:>6} {:16} {:>6} {:>10} {:>6} {:20}",
            "PID", "PPID", "NAME", "CPU%", "MEM", "FDs", "CGROUP"
        )?;
        for proc in snapshot.processes.processes.iter().take(10) {
            writeln!(
                w,
                "  {:>6} {:>6} {:16} {:>5.1}% {:>10} {:>6} {:20}",
                proc.pid,
                proc.ppid,
                Self::truncate(&proc.name, 16),
                proc.cpu_pct,
                Self::human_bytes(proc.mem_bytes),
                proc.open_fds,
                Self::truncate(&proc.cgroup.path, 20),
            )?;
        }

        w.flush()?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "table"
    }
}

impl TableBackend {
    fn human_bytes(bytes: u64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        let mut val = bytes as f64;
        for unit in UNITS {
            if val < 1024.0 {
                return format!("{:.1}{}", val, unit);
            }
            val /= 1024.0;
        }
        format!("{:.1}PB", val)
    }

    fn truncate(s: &str, max: usize) -> String {
        if s.len() <= max {
            s.to_string()
        } else {
            format!("{}…", &s[..max - 1])
        }
    }
}
