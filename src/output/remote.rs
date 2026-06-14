use crate::metrics::{MetricValue, SystemSnapshot};
use crate::output::{OutputBackend, OutputError};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// HTTP output backend - sends OTLP-compatible JSON via HTTP POST.
/// Endpoint configurable via SYSPULSE_HTTP_ENDPOINT env var.
pub struct HttpBackend {
    endpoint: String,
}

impl HttpBackend {
    pub fn new() -> Self {
        let endpoint = std::env::var("SYSPULSE_HTTP_ENDPOINT")
            .unwrap_or_else(|_| "127.0.0.1:4318/v1/metrics".to_string());
        Self { endpoint }
    }

    fn format_otlp_json(&self, snapshot: &SystemSnapshot) -> String {
        let points = snapshot.to_metric_points();
        let mut buf = String::with_capacity(points.len() * 256);
        buf.push_str("{\"resourceMetrics\":[{\"resource\":{\"attributes\":[{\"key\":\"host.name\",\"value\":{\"stringValue\":\"");
        buf.push_str(&json_escape(&snapshot.hostname));
        buf.push_str("\"}}]},\"scopeMetrics\":[{\"scope\":{\"name\":\"syspulse\"},\"metrics\":[");

        for (i, point) in points.iter().enumerate() {
            if i > 0 { buf.push(','); }
            buf.push_str("{\"name\":\"");
            buf.push_str(&json_escape(&point.name));
            buf.push_str("\",\"unit\":\"");
            buf.push_str(point.unit);
            buf.push_str("\",");

            match &point.value {
                MetricValue::Gauge(v) => {
                    buf.push_str("\"gauge\":{\"dataPoints\":[{\"asDouble\":");
                    buf.push_str(&format!("{}", v));
                    buf.push_str(",\"timeUnixNano\":\"");
                    buf.push_str(&point.timestamp.as_nanos().to_string());
                    buf.push_str("\",\"attributes\":[");
                    self.write_attributes(&mut buf, &point.tags);
                    buf.push_str("]}]}");
                }
                MetricValue::Counter(v) => {
                    buf.push_str("\"sum\":{\"dataPoints\":[{\"asInt\":\"");
                    buf.push_str(&v.to_string());
                    buf.push_str("\",\"timeUnixNano\":\"");
                    buf.push_str(&point.timestamp.as_nanos().to_string());
                    buf.push_str("\",\"attributes\":[");
                    self.write_attributes(&mut buf, &point.tags);
                    buf.push_str("]}],\"isMonotonic\":true}");
                }
                MetricValue::Histogram(h) => {
                    buf.push_str("\"histogram\":{\"dataPoints\":[{\"count\":\"");
                    buf.push_str(&h.count.to_string());
                    buf.push_str("\",\"sum\":");
                    buf.push_str(&format!("{}", h.sum));
                    buf.push_str(",\"timeUnixNano\":\"");
                    buf.push_str(&point.timestamp.as_nanos().to_string());
                    buf.push_str("\",\"attributes\":[");
                    self.write_attributes(&mut buf, &point.tags);
                    buf.push_str("]}]}");
                }
            }
            buf.push('}');
        }
        buf.push_str("]}]}]}\n");
        buf
    }

    fn write_attributes(&self, buf: &mut String, tags: &std::collections::HashMap<String, String>) {
        let mut first = true;
        for (k, v) in tags {
            if !first { buf.push(','); }
            first = false;
            buf.push_str("{\"key\":\"");
            buf.push_str(&json_escape(k));
            buf.push_str("\",\"value\":{\"stringValue\":\"");
            buf.push_str(&json_escape(v));
            buf.push_str("\"}}");
        }
    }

    fn send_http(&self, body: &[u8]) -> Result<(), OutputError> {
        // Parse host:port from endpoint
        let (host_port, path) = if let Some(idx) = self.endpoint.find('/') {
            (&self.endpoint[..idx], &self.endpoint[idx..])
        } else {
            (self.endpoint.as_str(), "/v1/metrics")
        };

        let mut stream = TcpStream::connect(host_port)
            .map_err(|e| OutputError::Format(format!("http connect {}: {}", host_port, e)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

        let request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            path, host_port, body.len()
        );
        stream.write_all(request.as_bytes())?;
        stream.write_all(body)?;
        stream.flush()?;

        // Read response status
        let mut resp_buf = [0u8; 256];
        let _ = stream.read(&mut resp_buf);
        Ok(())
    }
}

impl OutputBackend for HttpBackend {
    fn write(&self, snapshot: &SystemSnapshot) -> Result<(), OutputError> {
        let body = self.format_otlp_json(snapshot);
        self.send_http(body.as_bytes())
    }

    fn name(&self) -> &'static str { "http" }
}

/// gRPC output backend - sends metrics using gRPC wire format
/// (HTTP/2-like framing: 1-byte compressed flag + 4-byte length + binary payload).
/// Endpoint configurable via SYSPULSE_GRPC_ENDPOINT env var.
pub struct GrpcBackend {
    endpoint: String,
}

impl GrpcBackend {
    pub fn new() -> Self {
        let endpoint = std::env::var("SYSPULSE_GRPC_ENDPOINT")
            .unwrap_or_else(|_| "127.0.0.1:4317".to_string());
        Self { endpoint }
    }

    /// Encode metrics into a simple binary wire format:
    /// For each metric point: [name_len:u16][name][tag_count:u16][tags...][value_type:u8][value][timestamp:u64]
    fn encode_binary(&self, snapshot: &SystemSnapshot) -> Vec<u8> {
        let points = snapshot.to_metric_points();
        let mut buf = Vec::with_capacity(points.len() * 128);

        // Message header: version(1) + point_count(4)
        buf.push(1); // version
        buf.extend_from_slice(&(points.len() as u32).to_be_bytes());

        for point in &points {
            // name
            let name_bytes = point.name.as_bytes();
            buf.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
            buf.extend_from_slice(name_bytes);

            // tags
            buf.extend_from_slice(&(point.tags.len() as u16).to_be_bytes());
            for (k, v) in &point.tags {
                let kb = k.as_bytes();
                let vb = v.as_bytes();
                buf.extend_from_slice(&(kb.len() as u16).to_be_bytes());
                buf.extend_from_slice(kb);
                buf.extend_from_slice(&(vb.len() as u16).to_be_bytes());
                buf.extend_from_slice(vb);
            }

            // value
            match &point.value {
                MetricValue::Gauge(v) => {
                    buf.push(0x01); // gauge type
                    buf.extend_from_slice(&v.to_be_bytes());
                }
                MetricValue::Counter(v) => {
                    buf.push(0x02); // counter type
                    buf.extend_from_slice(&v.to_be_bytes());
                }
                MetricValue::Histogram(h) => {
                    buf.push(0x03); // histogram type
                    buf.extend_from_slice(&h.count.to_be_bytes());
                    buf.extend_from_slice(&h.sum.to_be_bytes());
                    buf.extend_from_slice(&(h.quantiles.len() as u16).to_be_bytes());
                    for (q, v) in &h.quantiles {
                        buf.extend_from_slice(&q.to_be_bytes());
                        buf.extend_from_slice(&v.to_be_bytes());
                    }
                }
            }

            // timestamp
            buf.extend_from_slice(&point.timestamp.as_nanos().to_be_bytes());

            // unit
            let unit_bytes = point.unit.as_bytes();
            buf.extend_from_slice(&(unit_bytes.len() as u8).to_be_bytes());
            buf.extend_from_slice(unit_bytes);
        }
        buf
    }

    /// Send using gRPC wire format: [compressed:u8][length:u32be][payload]
    fn send_grpc(&self, payload: &[u8]) -> Result<(), OutputError> {
        let mut stream = TcpStream::connect(&self.endpoint)
            .map_err(|e| OutputError::Format(format!("grpc connect {}: {}", self.endpoint, e)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

        // gRPC frame: compressed=0, length=payload.len()
        let mut frame = Vec::with_capacity(5 + payload.len());
        frame.push(0); // not compressed
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(payload);

        stream.write_all(&frame)?;
        stream.flush()?;
        Ok(())
    }
}

impl OutputBackend for GrpcBackend {
    fn write(&self, snapshot: &SystemSnapshot) -> Result<(), OutputError> {
        let payload = self.encode_binary(snapshot);
        self.send_grpc(&payload)
    }

    fn name(&self) -> &'static str { "grpc" }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if c < '\x20' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}
