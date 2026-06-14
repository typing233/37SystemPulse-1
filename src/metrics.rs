use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct Timestamp(pub u64);

impl Timestamp {
    pub fn now() -> Self {
        Self(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_nanos() as u64,
        )
    }

    pub fn as_nanos(&self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone)]
pub enum MetricValue {
    Gauge(f64),
    Counter(u64),
    Histogram(HistogramData),
}

#[derive(Debug, Clone)]
pub struct HistogramData {
    pub count: u64,
    pub sum: f64,
    pub quantiles: Vec<(f64, f64)>,
}

#[derive(Debug, Clone)]
pub struct MetricPoint {
    pub name: String,
    pub tags: HashMap<String, String>,
    pub value: MetricValue,
    pub timestamp: Timestamp,
    pub unit: &'static str,
}

#[derive(Debug, Clone)]
pub struct CpuMetrics {
    pub per_core: Vec<CoreMetrics>,
    pub total: CoreMetrics,
}

#[derive(Debug, Clone)]
pub struct CoreMetrics {
    pub core_id: u32,
    pub user_pct: f64,
    pub system_pct: f64,
    pub softirq_pct: f64,
    pub hardirq_pct: f64,
    pub idle_pct: f64,
    pub iowait_pct: f64,
    pub steal_pct: f64,
}

#[derive(Debug, Clone)]
pub struct MemoryMetrics {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub cached_bytes: u64,
    pub buffers_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
    pub swap_in_rate: f64,
    pub swap_out_rate: f64,
}

#[derive(Debug, Clone)]
pub struct DiskMetrics {
    pub devices: Vec<DiskDevice>,
}

#[derive(Debug, Clone)]
pub struct DiskDevice {
    pub name: String,
    pub mount_point: String,
    pub fs_type: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub read_bytes_per_sec: f64,
    pub write_bytes_per_sec: f64,
    pub io_latency: HistogramData,
}

#[derive(Debug, Clone)]
pub struct NetworkMetrics {
    pub interfaces: Vec<NetworkInterface>,
    pub tcp_connections: u64,
    pub tcp_retransmit_rate: f64,
    pub packet_loss_rate: f64,
}

#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub rx_bytes_per_sec: f64,
    pub tx_bytes_per_sec: f64,
    pub rx_packets_per_sec: f64,
    pub tx_packets_per_sec: f64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
}

#[derive(Debug, Clone)]
pub struct ProcessMetrics {
    pub processes: Vec<ProcessInfo>,
}

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub state: String,
    pub cpu_pct: f64,
    pub mem_bytes: u64,
    pub open_fds: u64,
    pub threads: u32,
    pub cgroup: CgroupInfo,
    pub children: Vec<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct CgroupInfo {
    pub path: String,
    pub cpu_limit_cores: Option<f64>,
    pub memory_limit_bytes: Option<u64>,
    pub memory_usage_bytes: Option<u64>,
    pub io_weight: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct SystemSnapshot {
    pub timestamp: Timestamp,
    pub hostname: String,
    pub cpu: CpuMetrics,
    pub memory: MemoryMetrics,
    pub disk: DiskMetrics,
    pub network: NetworkMetrics,
    pub processes: ProcessMetrics,
    pub thermal: ThermalInfo,
}

#[derive(Debug, Clone)]
pub struct ThermalInfo {
    pub zones: Vec<ThermalZone>,
    pub max_temp_celsius: f64,
}

#[derive(Debug, Clone)]
pub struct ThermalZone {
    pub name: String,
    pub temp_celsius: f64,
    pub zone_type: String,
}

impl SystemSnapshot {
    pub fn to_metric_points(&self) -> Vec<MetricPoint> {
        let mut points = Vec::with_capacity(512);
        let ts = self.timestamp.clone();
        let mut host_tags = HashMap::new();
        host_tags.insert("host".to_string(), self.hostname.clone());

        // ─── CPU per-core ───
        for core in &self.cpu.per_core {
            let mut tags = host_tags.clone();
            tags.insert("core".to_string(), core.core_id.to_string());
            for (name, val) in [
                ("cpu.user", core.user_pct),
                ("cpu.system", core.system_pct),
                ("cpu.softirq", core.softirq_pct),
                ("cpu.hardirq", core.hardirq_pct),
                ("cpu.idle", core.idle_pct),
                ("cpu.iowait", core.iowait_pct),
                ("cpu.steal", core.steal_pct),
            ] {
                points.push(MetricPoint {
                    name: name.to_string(), tags: tags.clone(),
                    value: MetricValue::Gauge(val), timestamp: ts.clone(), unit: "percent",
                });
            }
        }
        // CPU total
        {
            let mut tags = host_tags.clone();
            tags.insert("core".to_string(), "total".to_string());
            for (name, val) in [
                ("cpu.user", self.cpu.total.user_pct),
                ("cpu.system", self.cpu.total.system_pct),
                ("cpu.softirq", self.cpu.total.softirq_pct),
                ("cpu.hardirq", self.cpu.total.hardirq_pct),
                ("cpu.idle", self.cpu.total.idle_pct),
                ("cpu.iowait", self.cpu.total.iowait_pct),
                ("cpu.steal", self.cpu.total.steal_pct),
            ] {
                points.push(MetricPoint {
                    name: name.to_string(), tags: tags.clone(),
                    value: MetricValue::Gauge(val), timestamp: ts.clone(), unit: "percent",
                });
            }
        }

        // ─── Memory ───
        for (name, val, unit) in [
            ("memory.total", self.memory.total_bytes as f64, "bytes"),
            ("memory.used", self.memory.used_bytes as f64, "bytes"),
            ("memory.available", self.memory.available_bytes as f64, "bytes"),
            ("memory.cached", self.memory.cached_bytes as f64, "bytes"),
            ("memory.buffers", self.memory.buffers_bytes as f64, "bytes"),
            ("memory.swap_total", self.memory.swap_total_bytes as f64, "bytes"),
            ("memory.swap_used", self.memory.swap_used_bytes as f64, "bytes"),
            ("memory.swap_in_rate", self.memory.swap_in_rate, "bytes/s"),
            ("memory.swap_out_rate", self.memory.swap_out_rate, "bytes/s"),
        ] {
            points.push(MetricPoint {
                name: name.to_string(), tags: host_tags.clone(),
                value: MetricValue::Gauge(val), timestamp: ts.clone(), unit,
            });
        }

        // ─── Disk (per device) ───
        for dev in &self.disk.devices {
            let mut tags = host_tags.clone();
            tags.insert("device".to_string(), dev.name.clone());
            tags.insert("mount".to_string(), dev.mount_point.clone());
            tags.insert("fstype".to_string(), dev.fs_type.clone());
            for (name, val, unit) in [
                ("disk.total", dev.total_bytes as f64, "bytes"),
                ("disk.used", dev.used_bytes as f64, "bytes"),
                ("disk.available", dev.available_bytes as f64, "bytes"),
                ("disk.read_bytes_per_sec", dev.read_bytes_per_sec, "bytes/s"),
                ("disk.write_bytes_per_sec", dev.write_bytes_per_sec, "bytes/s"),
            ] {
                points.push(MetricPoint {
                    name: name.to_string(), tags: tags.clone(),
                    value: MetricValue::Gauge(val), timestamp: ts.clone(), unit,
                });
            }
            // IO latency as histogram
            if !dev.io_latency.quantiles.is_empty() {
                points.push(MetricPoint {
                    name: "disk.io_latency".to_string(), tags: tags.clone(),
                    value: MetricValue::Histogram(dev.io_latency.clone()),
                    timestamp: ts.clone(), unit: "ms",
                });
            }
        }

        // ─── Network (per interface) ───
        for iface in &self.network.interfaces {
            let mut tags = host_tags.clone();
            tags.insert("interface".to_string(), iface.name.clone());
            for (name, val, unit) in [
                ("net.rx_bytes_per_sec", iface.rx_bytes_per_sec, "bytes/s"),
                ("net.tx_bytes_per_sec", iface.tx_bytes_per_sec, "bytes/s"),
                ("net.rx_packets_per_sec", iface.rx_packets_per_sec, "packets/s"),
                ("net.tx_packets_per_sec", iface.tx_packets_per_sec, "packets/s"),
                ("net.rx_errors", iface.rx_errors as f64, "count"),
                ("net.tx_errors", iface.tx_errors as f64, "count"),
                ("net.rx_dropped", iface.rx_dropped as f64, "count"),
                ("net.tx_dropped", iface.tx_dropped as f64, "count"),
            ] {
                points.push(MetricPoint {
                    name: name.to_string(), tags: tags.clone(),
                    value: MetricValue::Gauge(val), timestamp: ts.clone(), unit,
                });
            }
        }
        // Network global TCP stats
        points.push(MetricPoint {
            name: "net.tcp_connections".to_string(), tags: host_tags.clone(),
            value: MetricValue::Gauge(self.network.tcp_connections as f64),
            timestamp: ts.clone(), unit: "count",
        });
        points.push(MetricPoint {
            name: "net.tcp_retransmit_rate".to_string(), tags: host_tags.clone(),
            value: MetricValue::Gauge(self.network.tcp_retransmit_rate),
            timestamp: ts.clone(), unit: "percent",
        });
        points.push(MetricPoint {
            name: "net.packet_loss_rate".to_string(), tags: host_tags.clone(),
            value: MetricValue::Gauge(self.network.packet_loss_rate),
            timestamp: ts.clone(), unit: "percent",
        });

        // ─── Thermal ───
        for zone in &self.thermal.zones {
            let mut tags = host_tags.clone();
            tags.insert("zone".to_string(), zone.name.clone());
            tags.insert("type".to_string(), zone.zone_type.clone());
            points.push(MetricPoint {
                name: "thermal.temp".to_string(), tags: tags.clone(),
                value: MetricValue::Gauge(zone.temp_celsius),
                timestamp: ts.clone(), unit: "celsius",
            });
        }
        points.push(MetricPoint {
            name: "thermal.max_temp".to_string(), tags: host_tags.clone(),
            value: MetricValue::Gauge(self.thermal.max_temp_celsius),
            timestamp: ts.clone(), unit: "celsius",
        });

        // ─── Processes (top N with full data) ───
        for proc in &self.processes.processes {
            let mut tags = host_tags.clone();
            tags.insert("pid".to_string(), proc.pid.to_string());
            tags.insert("name".to_string(), proc.name.clone());
            tags.insert("ppid".to_string(), proc.ppid.to_string());
            tags.insert("state".to_string(), proc.state.clone());
            if !proc.cgroup.path.is_empty() {
                tags.insert("cgroup".to_string(), proc.cgroup.path.clone());
            }
            points.push(MetricPoint {
                name: "process.cpu".to_string(), tags: tags.clone(),
                value: MetricValue::Gauge(proc.cpu_pct),
                timestamp: ts.clone(), unit: "percent",
            });
            points.push(MetricPoint {
                name: "process.memory".to_string(), tags: tags.clone(),
                value: MetricValue::Gauge(proc.mem_bytes as f64),
                timestamp: ts.clone(), unit: "bytes",
            });
            points.push(MetricPoint {
                name: "process.open_fds".to_string(), tags: tags.clone(),
                value: MetricValue::Gauge(proc.open_fds as f64),
                timestamp: ts.clone(), unit: "count",
            });
            points.push(MetricPoint {
                name: "process.threads".to_string(), tags: tags.clone(),
                value: MetricValue::Gauge(proc.threads as f64),
                timestamp: ts.clone(), unit: "count",
            });
            // Cgroup limits
            if let Some(cpu_lim) = proc.cgroup.cpu_limit_cores {
                points.push(MetricPoint {
                    name: "process.cgroup.cpu_limit".to_string(), tags: tags.clone(),
                    value: MetricValue::Gauge(cpu_lim),
                    timestamp: ts.clone(), unit: "cores",
                });
            }
            if let Some(mem_lim) = proc.cgroup.memory_limit_bytes {
                points.push(MetricPoint {
                    name: "process.cgroup.memory_limit".to_string(), tags: tags.clone(),
                    value: MetricValue::Gauge(mem_lim as f64),
                    timestamp: ts.clone(), unit: "bytes",
                });
            }
            if let Some(mem_use) = proc.cgroup.memory_usage_bytes {
                points.push(MetricPoint {
                    name: "process.cgroup.memory_usage".to_string(), tags: tags.clone(),
                    value: MetricValue::Gauge(mem_use as f64),
                    timestamp: ts.clone(), unit: "bytes",
                });
            }
            if let Some(io_w) = proc.cgroup.io_weight {
                points.push(MetricPoint {
                    name: "process.cgroup.io_weight".to_string(), tags: tags.clone(),
                    value: MetricValue::Gauge(io_w as f64),
                    timestamp: ts.clone(), unit: "weight",
                });
            }
            if !proc.children.is_empty() {
                let children_str = proc.children.iter()
                    .map(|c| c.to_string()).collect::<Vec<_>>().join(",");
                let mut ctags = tags.clone();
                ctags.insert("children".to_string(), children_str);
                points.push(MetricPoint {
                    name: "process.children_count".to_string(), tags: ctags,
                    value: MetricValue::Gauge(proc.children.len() as f64),
                    timestamp: ts.clone(), unit: "count",
                });
            }
        }

        points
    }
}
