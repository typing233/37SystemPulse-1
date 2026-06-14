use crate::collector::CollectorError;
use crate::metrics::{NetworkInterface, NetworkMetrics};
use std::collections::HashMap;
use std::fs;
use std::io::Read;

pub struct NetworkCollector {
    prev_stats: HashMap<String, IfaceRaw>,
    prev_tcp: Option<TcpRaw>,
    prev_time_ns: Option<u64>,
}

#[derive(Clone)]
struct IfaceRaw {
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
    rx_errors: u64,
    tx_errors: u64,
    rx_dropped: u64,
    tx_dropped: u64,
}

#[derive(Clone)]
struct TcpRaw {
    retrans_segs: u64,
    out_segs: u64,
    curr_estab: u64,
    in_errs: u64,
    in_segs: u64,
}

impl NetworkCollector {
    pub fn new() -> Self {
        Self {
            prev_stats: HashMap::new(),
            prev_tcp: None,
            prev_time_ns: None,
        }
    }

    #[cfg(target_os = "linux")]
    pub fn collect(&mut self) -> Result<NetworkMetrics, CollectorError> {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let dt = self
            .prev_time_ns
            .map(|prev| (now_ns.saturating_sub(prev)) as f64 / 1_000_000_000.0)
            .unwrap_or(0.0);

        let current = self.read_net_dev()?;
        let tcp = self.read_snmp()?;

        let mut interfaces = Vec::new();
        for (name, cur) in &current {
            if name == "lo" {
                continue;
            }
            let (rx_rate, tx_rate, rxp_rate, txp_rate) = if dt > 0.0 {
                if let Some(prev) = self.prev_stats.get(name) {
                    (
                        cur.rx_bytes.wrapping_sub(prev.rx_bytes) as f64 / dt,
                        cur.tx_bytes.wrapping_sub(prev.tx_bytes) as f64 / dt,
                        cur.rx_packets.wrapping_sub(prev.rx_packets) as f64 / dt,
                        cur.tx_packets.wrapping_sub(prev.tx_packets) as f64 / dt,
                    )
                } else {
                    (0.0, 0.0, 0.0, 0.0)
                }
            } else {
                (0.0, 0.0, 0.0, 0.0)
            };

            interfaces.push(NetworkInterface {
                name: name.clone(),
                rx_bytes_per_sec: rx_rate,
                tx_bytes_per_sec: tx_rate,
                rx_packets_per_sec: rxp_rate,
                tx_packets_per_sec: txp_rate,
                rx_errors: cur.rx_errors,
                tx_errors: cur.tx_errors,
                rx_dropped: cur.rx_dropped,
                tx_dropped: cur.tx_dropped,
            });
        }

        let (retransmit_rate, packet_loss) = if dt > 0.0 {
            if let Some(prev) = &self.prev_tcp {
                let d_retrans = tcp.retrans_segs.wrapping_sub(prev.retrans_segs);
                let d_out = tcp.out_segs.wrapping_sub(prev.out_segs);
                let d_errs = tcp.in_errs.wrapping_sub(prev.in_errs);
                let d_in = tcp.in_segs.wrapping_sub(prev.in_segs);
                let rr = if d_out > 0 {
                    (d_retrans as f64 / d_out as f64) * 100.0
                } else {
                    0.0
                };
                let pl = if d_in > 0 {
                    (d_errs as f64 / d_in as f64) * 100.0
                } else {
                    0.0
                };
                (rr, pl)
            } else {
                (0.0, 0.0)
            }
        } else {
            (0.0, 0.0)
        };

        self.prev_stats = current;
        self.prev_tcp = Some(tcp.clone());
        self.prev_time_ns = Some(now_ns);

        Ok(NetworkMetrics {
            interfaces,
            tcp_connections: tcp.curr_estab,
            tcp_retransmit_rate: retransmit_rate,
            packet_loss_rate: packet_loss,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn collect(&mut self) -> Result<NetworkMetrics, CollectorError> {
        Err(CollectorError::Unsupported(
            "Network collection not implemented for this platform".to_string(),
        ))
    }

    #[cfg(target_os = "linux")]
    fn read_net_dev(&self) -> Result<HashMap<String, IfaceRaw>, CollectorError> {
        let mut buf = String::with_capacity(4096);
        let mut file = fs::File::open("/proc/net/dev")?;
        file.read_to_string(&mut buf)?;

        let mut stats = HashMap::new();
        for line in buf.lines().skip(2) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 17 {
                continue;
            }
            let name = parts[0].trim_end_matches(':').to_string();
            let parse = |i: usize| -> u64 { parts[i].parse().unwrap_or(0) };
            // If name part includes ':', field indices shift
            let (name, offset) = if parts[0].ends_with(':') {
                (parts[0].trim_end_matches(':').to_string(), 1)
            } else {
                (parts[0].to_string(), 1)
            };
            stats.insert(
                name,
                IfaceRaw {
                    rx_bytes: parse(offset),
                    rx_packets: parse(offset + 1),
                    rx_errors: parse(offset + 2),
                    rx_dropped: parse(offset + 3),
                    tx_bytes: parse(offset + 8),
                    tx_packets: parse(offset + 9),
                    tx_errors: parse(offset + 10),
                    tx_dropped: parse(offset + 11),
                },
            );
        }
        Ok(stats)
    }

    #[cfg(target_os = "linux")]
    fn read_snmp(&self) -> Result<TcpRaw, CollectorError> {
        let mut buf = String::with_capacity(4096);
        let mut file = fs::File::open("/proc/net/snmp")?;
        file.read_to_string(&mut buf)?;

        let mut result = TcpRaw {
            retrans_segs: 0,
            out_segs: 0,
            curr_estab: 0,
            in_errs: 0,
            in_segs: 0,
        };

        let lines: Vec<&str> = buf.lines().collect();
        for i in (0..lines.len()).step_by(2) {
            if !lines[i].starts_with("Tcp:") {
                continue;
            }
            if i + 1 >= lines.len() {
                break;
            }
            let headers: Vec<&str> = lines[i].split_whitespace().collect();
            let values: Vec<&str> = lines[i + 1].split_whitespace().collect();
            for (j, h) in headers.iter().enumerate() {
                if j >= values.len() {
                    break;
                }
                let v: u64 = values[j].parse().unwrap_or(0);
                match *h {
                    "RetransSegs" => result.retrans_segs = v,
                    "OutSegs" => result.out_segs = v,
                    "CurrEstab" => result.curr_estab = v,
                    "InErrs" => result.in_errs = v,
                    "InSegs" => result.in_segs = v,
                    _ => {}
                }
            }
        }
        Ok(result)
    }
}
