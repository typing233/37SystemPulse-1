use crate::collector::CollectorError;
use crate::metrics::{NetworkInterface, NetworkMetrics};
use std::collections::HashMap;

#[cfg(target_os = "linux")]
use crate::platform::linux::{parse_u64_from_bytes, syscall};

pub struct NetworkCollector {
    prev_stats: HashMap<String, IfaceRaw>,
    prev_tcp: Option<TcpRaw>,
    prev_time_ns: Option<u64>,
    #[cfg(target_os = "linux")]
    netdev_fd: Option<syscall::PersistentFd>,
    #[cfg(target_os = "linux")]
    snmp_fd: Option<syscall::PersistentFd>,
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
            #[cfg(target_os = "linux")]
            netdev_fd: syscall::PersistentFd::open(b"/proc/net/dev\0"),
            #[cfg(target_os = "linux")]
            snmp_fd: syscall::PersistentFd::open(b"/proc/net/snmp\0"),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn collect(&mut self) -> Result<NetworkMetrics, CollectorError> {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let dt = self.prev_time_ns
            .map(|prev| (now_ns.saturating_sub(prev)) as f64 / 1_000_000_000.0)
            .unwrap_or(0.0);

        let current = self.read_net_dev()?;
        let tcp = self.read_snmp()?;

        let mut interfaces = Vec::new();
        for (name, cur) in &current {
            if name == "lo" { continue; }
            let (rx_rate, tx_rate, rxp_rate, txp_rate) = if dt > 0.0 {
                if let Some(prev) = self.prev_stats.get(name) {
                    (
                        cur.rx_bytes.wrapping_sub(prev.rx_bytes) as f64 / dt,
                        cur.tx_bytes.wrapping_sub(prev.tx_bytes) as f64 / dt,
                        cur.rx_packets.wrapping_sub(prev.rx_packets) as f64 / dt,
                        cur.tx_packets.wrapping_sub(prev.tx_packets) as f64 / dt,
                    )
                } else { (0.0, 0.0, 0.0, 0.0) }
            } else { (0.0, 0.0, 0.0, 0.0) };

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
                let rr = if d_out > 0 { (d_retrans as f64 / d_out as f64) * 100.0 } else { 0.0 };
                let pl = if d_in > 0 { (d_errs as f64 / d_in as f64) * 100.0 } else { 0.0 };
                (rr, pl)
            } else { (0.0, 0.0) }
        } else { (0.0, 0.0) };

        self.prev_stats = current;
        self.prev_tcp = Some(tcp);
        self.prev_time_ns = Some(now_ns);

        Ok(NetworkMetrics {
            interfaces,
            tcp_connections: self.prev_tcp.as_ref().map(|t| t.curr_estab).unwrap_or(0),
            tcp_retransmit_rate: retransmit_rate,
            packet_loss_rate: packet_loss,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn collect(&mut self) -> Result<NetworkMetrics, CollectorError> {
        Err(CollectorError::Unsupported("Network: not linux".into()))
    }

    #[cfg(target_os = "linux")]
    fn read_net_dev(&self) -> Result<HashMap<String, IfaceRaw>, CollectorError> {
        let mut buf = [0u8; 8192];
        let n = if let Some(pfd) = &self.netdev_fd {
            pfd.reread(&mut buf)
        } else {
            syscall::read_file_to_buf(b"/proc/net/dev\0", &mut buf)
        };
        if n <= 0 {
            return Err(CollectorError::Io(std::io::Error::from_raw_os_error(-(n as i32))));
        }
        let data = &buf[..n as usize];
        let mut stats = HashMap::new();

        // Skip first 2 header lines
        let mut pos = 0;
        let mut line_no = 0;
        while pos < data.len() {
            let line_start = pos;
            while pos < data.len() && data[pos] != b'\n' { pos += 1; }
            let line = &data[line_start..pos];
            pos += 1;
            line_no += 1;
            if line_no <= 2 { continue; }

            // Parse: "  iface: rx_bytes rx_packets rx_errs rx_drop ... tx_bytes tx_packets ..."
            let colon_pos = line.iter().position(|&b| b == b':');
            let (name_part, rest) = match colon_pos {
                Some(cp) => (&line[..cp], &line[cp + 1..]),
                None => continue,
            };
            let name = std::str::from_utf8(name_part).unwrap_or("").trim().to_string();
            if name.is_empty() { continue; }

            let fields: Vec<u64> = rest.split(|&b| b == b' ')
                .filter(|f| !f.is_empty())
                .map(|f| parse_u64_from_bytes(f))
                .collect();
            if fields.len() < 16 { continue; }

            stats.insert(name, IfaceRaw {
                rx_bytes: fields[0],
                rx_packets: fields[1],
                rx_errors: fields[2],
                rx_dropped: fields[3],
                tx_bytes: fields[8],
                tx_packets: fields[9],
                tx_errors: fields[10],
                tx_dropped: fields[11],
            });
        }
        Ok(stats)
    }

    #[cfg(target_os = "linux")]
    fn read_snmp(&self) -> Result<TcpRaw, CollectorError> {
        let mut buf = [0u8; 8192];
        let n = if let Some(pfd) = &self.snmp_fd {
            pfd.reread(&mut buf)
        } else {
            syscall::read_file_to_buf(b"/proc/net/snmp\0", &mut buf)
        };
        if n <= 0 {
            return Ok(TcpRaw { retrans_segs: 0, out_segs: 0, curr_estab: 0, in_errs: 0, in_segs: 0 });
        }
        let data = &buf[..n as usize];
        let mut result = TcpRaw { retrans_segs: 0, out_segs: 0, curr_estab: 0, in_errs: 0, in_segs: 0 };

        let mut pos = 0;
        while pos < data.len() {
            let line_start = pos;
            while pos < data.len() && data[pos] != b'\n' { pos += 1; }
            let header_line = &data[line_start..pos];
            pos += 1;

            if !header_line.starts_with(b"Tcp:") { continue; }
            // Next line has the values
            let val_start = pos;
            while pos < data.len() && data[pos] != b'\n' { pos += 1; }
            let val_line = &data[val_start..pos];
            pos += 1;

            let headers: Vec<&[u8]> = header_line.split(|&b| b == b' ').collect();
            let values: Vec<&[u8]> = val_line.split(|&b| b == b' ').collect();

            for (i, h) in headers.iter().enumerate() {
                if i >= values.len() { break; }
                let v = parse_u64_from_bytes(values[i]);
                if *h == b"RetransSegs" { result.retrans_segs = v; }
                else if *h == b"OutSegs" { result.out_segs = v; }
                else if *h == b"CurrEstab" { result.curr_estab = v; }
                else if *h == b"InErrs" { result.in_errs = v; }
                else if *h == b"InSegs" { result.in_segs = v; }
            }
            break;
        }
        Ok(result)
    }
}
