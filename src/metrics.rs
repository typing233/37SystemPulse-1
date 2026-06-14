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
    pub quantiles: Vec<(f64, f64)>, // (quantile, value)
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
    pub swap_in_rate: f64,  // bytes/sec
    pub swap_out_rate: f64, // bytes/sec
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
        let mut points = Vec::with_capacity(256);
        let ts = self.timestamp.clone();
        let mut host_tags = HashMap::new();
        host_tags.insert("host".to_string(), self.hostname.clone());

        // CPU metrics
        for core in &self.cpu.per_core {
            let mut tags = host_tags.clone();
            tags.insert("core".to_string(), core.core_id.to_string());
            let fields = [
                ("cpu.user", core.user_pct),
                ("cpu.system", core.system_pct),
                ("cpu.softirq", core.softirq_pct),
                ("cpu.hardirq", core.hardirq_pct),
                ("cpu.idle", core.idle_pct),
                ("cpu.iowait", core.iowait_pct),
                ("cpu.steal", core.steal_pct),
            ];
            for (name, val) in fields {
                points.push(MetricPoint {
                    name: name.to_string(),
                    tags: tags.clone(),
                    value: MetricValue::Gauge(val),
                    timestamp: ts.clone(),
                    unit: "percent",
                });
            }
        }

        // Memory metrics
        let mem_fields: Vec<(&str, u64)> = vec![
            ("memory.total", self.memory.total_bytes),
            ("memory.used", self.memory.used_bytes),
            ("memory.available", self.memory.available_bytes),
            ("memory.cached", self.memory.cached_bytes),
            ("memory.buffers", self.memory.buffers_bytes),
            ("memory.swap_total", self.memory.swap_total_bytes),
            ("memory.swap_used", self.memory.swap_used_bytes),
        ];
        for (name, val) in mem_fields {
            points.push(MetricPoint {
                name: name.to_string(),
                tags: host_tags.clone(),
                value: MetricValue::Gauge(val as f64),
                timestamp: ts.clone(),
                unit: "bytes",
            });
        }
        points.push(MetricPoint {
            name: "memory.swap_in_rate".to_string(),
            tags: host_tags.clone(),
            value: MetricValue::Gauge(self.memory.swap_in_rate),
            timestamp: ts.clone(),
            unit: "bytes/s",
        });
        points.push(MetricPoint {
            name: "memory.swap_out_rate".to_string(),
            tags: host_tags.clone(),
            value: MetricValue::Gauge(self.memory.swap_out_rate),
            timestamp: ts.clone(),
            unit: "bytes/s",
        });

        // Network metrics
        for iface in &self.network.interfaces {
            let mut tags = host_tags.clone();
            tags.insert("interface".to_string(), iface.name.clone());
            points.push(MetricPoint {
                name: "net.rx_bytes_per_sec".to_string(),
                tags: tags.clone(),
                value: MetricValue::Gauge(iface.rx_bytes_per_sec),
                timestamp: ts.clone(),
                unit: "bytes/s",
            });
            points.push(MetricPoint {
                name: "net.tx_bytes_per_sec".to_string(),
                tags: tags.clone(),
                value: MetricValue::Gauge(iface.tx_bytes_per_sec),
                timestamp: ts.clone(),
                unit: "bytes/s",
            });
        }
        points.push(MetricPoint {
            name: "net.tcp_connections".to_string(),
            tags: host_tags.clone(),
            value: MetricValue::Gauge(self.network.tcp_connections as f64),
            timestamp: ts.clone(),
            unit: "count",
        });
        points.push(MetricPoint {
            name: "net.tcp_retransmit_rate".to_string(),
            tags: host_tags.clone(),
            value: MetricValue::Gauge(self.network.tcp_retransmit_rate),
            timestamp: ts.clone(),
            unit: "percent",
        });

        points
    }
}
