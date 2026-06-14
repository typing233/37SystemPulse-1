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

/// gRPC output backend - sends OTLP metrics via standard gRPC protocol.
/// Implements HTTP/2 connection preface, SETTINGS, HEADERS (HPACK), DATA frames
/// with protobuf-encoded ExportMetricsServiceRequest.
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

    /// Encode metrics into protobuf ExportMetricsServiceRequest
    fn encode_otlp_protobuf(&self, snapshot: &SystemSnapshot) -> Vec<u8> {
        let points = snapshot.to_metric_points();
        let mut buf = Vec::with_capacity(points.len() * 64);

        // ExportMetricsServiceRequest { resource_metrics: [ResourceMetrics] }
        // Field 1: resource_metrics (repeated, wire type 2 = LEN)

        // Build inner ResourceMetrics message first
        let mut rm_buf = Vec::with_capacity(points.len() * 64);

        // ResourceMetrics.resource (field 1, wire type 2)
        let resource_bytes = self.encode_resource(&snapshot.hostname);
        proto_field(&mut rm_buf, 1, &resource_bytes);

        // ResourceMetrics.scope_metrics (field 2, wire type 2)
        let scope_metrics = self.encode_scope_metrics(&points);
        proto_field(&mut rm_buf, 2, &scope_metrics);

        // Wrap in ExportMetricsServiceRequest field 1
        proto_field(&mut buf, 1, &rm_buf);
        buf
    }

    fn encode_resource(&self, hostname: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        // Resource.attributes (field 1, repeated KeyValue)
        let kv = self.encode_key_value("host.name", hostname);
        proto_field(&mut buf, 1, &kv);
        buf
    }

    fn encode_key_value(&self, key: &str, value: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        // KeyValue.key (field 1, string)
        proto_string(&mut buf, 1, key);
        // KeyValue.value (field 2, AnyValue)
        let mut av = Vec::new();
        // AnyValue.string_value (field 1)
        proto_string(&mut av, 1, value);
        proto_field(&mut buf, 2, &av);
        buf
    }

    fn encode_scope_metrics(&self, points: &[crate::metrics::MetricPoint]) -> Vec<u8> {
        let mut buf = Vec::new();
        // ScopeMetrics.scope (field 1)
        let mut scope = Vec::new();
        proto_string(&mut scope, 1, "syspulse"); // InstrumentationScope.name
        proto_field(&mut buf, 1, &scope);

        // ScopeMetrics.metrics (field 2, repeated)
        for point in points {
            let metric = self.encode_metric(point);
            proto_field(&mut buf, 2, &metric);
        }
        buf
    }

    fn encode_metric(&self, point: &crate::metrics::MetricPoint) -> Vec<u8> {
        let mut buf = Vec::new();
        // Metric.name (field 1)
        proto_string(&mut buf, 1, &point.name);
        // Metric.unit (field 3)
        proto_string(&mut buf, 3, point.unit);

        match &point.value {
            MetricValue::Gauge(v) => {
                // Metric.gauge (field 5)
                let gauge = self.encode_gauge(*v, point);
                proto_field(&mut buf, 5, &gauge);
            }
            MetricValue::Counter(v) => {
                // Metric.sum (field 7)
                let sum = self.encode_sum(*v, point);
                proto_field(&mut buf, 7, &sum);
            }
            MetricValue::Histogram(h) => {
                // Metric.histogram (field 9)
                let hist = self.encode_histogram(h, point);
                proto_field(&mut buf, 9, &hist);
            }
        }
        buf
    }

    fn encode_gauge(&self, value: f64, point: &crate::metrics::MetricPoint) -> Vec<u8> {
        let mut buf = Vec::new();
        // Gauge.data_points (field 1)
        let dp = self.encode_number_data_point(value, point);
        proto_field(&mut buf, 1, &dp);
        buf
    }

    fn encode_sum(&self, value: u64, point: &crate::metrics::MetricPoint) -> Vec<u8> {
        let mut buf = Vec::new();
        // Sum.data_points (field 1)
        let dp = self.encode_int_data_point(value as i64, point);
        proto_field(&mut buf, 1, &dp);
        // Sum.is_monotonic (field 3, varint bool = 1)
        proto_varint(&mut buf, 3, 1);
        buf
    }

    fn encode_histogram(&self, h: &crate::metrics::HistogramData, point: &crate::metrics::MetricPoint) -> Vec<u8> {
        let mut buf = Vec::new();
        // Histogram.data_points (field 1)
        let mut dp = Vec::new();
        // HistogramDataPoint.time_unix_nano (field 3, fixed64)
        proto_fixed64(&mut dp, 3, point.timestamp.as_nanos());
        // HistogramDataPoint.count (field 4, fixed64)
        proto_fixed64(&mut dp, 4, h.count);
        // HistogramDataPoint.sum (field 5, double)
        proto_double(&mut dp, 5, h.sum);
        // Attributes
        for (k, v) in &point.tags {
            let kv = self.encode_key_value(k, v);
            proto_field(&mut dp, 9, &kv);
        }
        proto_field(&mut buf, 1, &dp);
        buf
    }

    fn encode_number_data_point(&self, value: f64, point: &crate::metrics::MetricPoint) -> Vec<u8> {
        let mut buf = Vec::new();
        // NumberDataPoint.time_unix_nano (field 3, fixed64)
        proto_fixed64(&mut buf, 3, point.timestamp.as_nanos());
        // NumberDataPoint.as_double (field 7, double)
        proto_double(&mut buf, 7, value);
        // NumberDataPoint.attributes (field 9, repeated KeyValue)
        for (k, v) in &point.tags {
            let kv = self.encode_key_value(k, v);
            proto_field(&mut buf, 9, &kv);
        }
        buf
    }

    fn encode_int_data_point(&self, value: i64, point: &crate::metrics::MetricPoint) -> Vec<u8> {
        let mut buf = Vec::new();
        proto_fixed64(&mut buf, 3, point.timestamp.as_nanos());
        // NumberDataPoint.as_int (field 6, sfixed64)
        proto_sfixed64(&mut buf, 6, value);
        for (k, v) in &point.tags {
            let kv = self.encode_key_value(k, v);
            proto_field(&mut buf, 9, &kv);
        }
        buf
    }

    /// Send via standard gRPC/HTTP2 protocol
    fn send_grpc(&self, payload: &[u8]) -> Result<(), OutputError> {
        let mut stream = TcpStream::connect(&self.endpoint)
            .map_err(|e| OutputError::Format(format!("grpc connect {}: {}", self.endpoint, e)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

        // === HTTP/2 Connection Preface ===
        stream.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")?;

        // === SETTINGS frame (type=0x04, flags=0, stream=0) ===
        // Empty SETTINGS (use defaults)
        let settings_frame = http2_frame(0x04, 0x00, 0, &[]);
        stream.write_all(&settings_frame)?;

        // === HEADERS frame (type=0x01, flags=0x04|0x01 END_HEADERS|END_STREAM not set) ===
        let headers_payload = self.encode_grpc_headers();
        let headers_frame = http2_frame(0x01, 0x04, 1, &headers_payload); // END_HEADERS, stream 1
        stream.write_all(&headers_frame)?;

        // === DATA frame (type=0x00) with gRPC message ===
        // gRPC message format: [compressed:1][length:4][message]
        let mut grpc_msg = Vec::with_capacity(5 + payload.len());
        grpc_msg.push(0x00); // not compressed
        grpc_msg.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        grpc_msg.extend_from_slice(payload);

        let data_frame = http2_frame(0x00, 0x01, 1, &grpc_msg); // END_STREAM, stream 1
        stream.write_all(&data_frame)?;
        stream.flush()?;

        // Read SETTINGS ACK and response (best effort)
        let mut resp_buf = [0u8; 512];
        let _ = stream.read(&mut resp_buf);
        Ok(())
    }

    /// HPACK-encode gRPC headers for OTLP MetricsService/Export
    fn encode_grpc_headers(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);

        // :method POST - indexed (static table index 3)
        buf.push(0x83); // 1000 0011 = indexed field, index 3

        // :scheme http - indexed (static table index 6)
        buf.push(0x86); // 1000 0110 = indexed field, index 6

        // :path /opentelemetry.proto.collector.metrics.v1.MetricsService/Export
        // Literal with indexing, name indexed (static table index 4 = :path)
        buf.push(0x44); // 0100 0100 = literal with indexing, name index 4
        let path = b"/opentelemetry.proto.collector.metrics.v1.MetricsService/Export";
        hpack_encode_string(&mut buf, path);

        // :authority
        buf.push(0x41); // 0100 0001 = literal with indexing, name index 1 (:authority)
        hpack_encode_string(&mut buf, self.endpoint.as_bytes());

        // content-type: application/grpc
        buf.push(0x40); // literal with indexing, new name
        hpack_encode_string(&mut buf, b"content-type");
        hpack_encode_string(&mut buf, b"application/grpc");

        // te: trailers (required for gRPC)
        buf.push(0x40);
        hpack_encode_string(&mut buf, b"te");
        hpack_encode_string(&mut buf, b"trailers");

        buf
    }
}

impl OutputBackend for GrpcBackend {
    fn write(&self, snapshot: &SystemSnapshot) -> Result<(), OutputError> {
        let payload = self.encode_otlp_protobuf(snapshot);
        self.send_grpc(&payload)
    }

    fn name(&self) -> &'static str { "grpc" }
}

// === Protobuf encoding helpers ===

fn proto_varint_encode(value: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut v = value;
    loop {
        let mut byte = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 { byte |= 0x80; }
        buf.push(byte);
        if v == 0 { break; }
    }
    buf
}

fn proto_field(buf: &mut Vec<u8>, field_num: u32, data: &[u8]) {
    let tag = (field_num << 3) | 2; // wire type 2 = LEN
    buf.extend_from_slice(&proto_varint_encode(tag as u64));
    buf.extend_from_slice(&proto_varint_encode(data.len() as u64));
    buf.extend_from_slice(data);
}

fn proto_string(buf: &mut Vec<u8>, field_num: u32, s: &str) {
    proto_field(buf, field_num, s.as_bytes());
}

fn proto_varint(buf: &mut Vec<u8>, field_num: u32, value: u64) {
    let tag = (field_num << 3) | 0; // wire type 0 = VARINT
    buf.extend_from_slice(&proto_varint_encode(tag as u64));
    buf.extend_from_slice(&proto_varint_encode(value));
}

fn proto_fixed64(buf: &mut Vec<u8>, field_num: u32, value: u64) {
    let tag = (field_num << 3) | 1; // wire type 1 = 64-bit
    buf.extend_from_slice(&proto_varint_encode(tag as u64));
    buf.extend_from_slice(&value.to_le_bytes());
}

fn proto_sfixed64(buf: &mut Vec<u8>, field_num: u32, value: i64) {
    let tag = (field_num << 3) | 1;
    buf.extend_from_slice(&proto_varint_encode(tag as u64));
    buf.extend_from_slice(&value.to_le_bytes());
}

fn proto_double(buf: &mut Vec<u8>, field_num: u32, value: f64) {
    let tag = (field_num << 3) | 1; // wire type 1 = 64-bit
    buf.extend_from_slice(&proto_varint_encode(tag as u64));
    buf.extend_from_slice(&value.to_le_bytes());
}

// === HTTP/2 framing ===

fn http2_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut frame = Vec::with_capacity(9 + payload.len());
    // 3-byte length
    frame.push((len >> 16) as u8);
    frame.push((len >> 8) as u8);
    frame.push(len as u8);
    // type, flags
    frame.push(frame_type);
    frame.push(flags);
    // 4-byte stream id (MSB must be 0)
    frame.extend_from_slice(&(stream_id & 0x7FFFFFFF).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

// === HPACK encoding ===

fn hpack_encode_string(buf: &mut Vec<u8>, s: &[u8]) {
    // No Huffman encoding (bit 7 = 0), length as 7-bit prefix integer
    let len = s.len();
    if len < 127 {
        buf.push(len as u8);
    } else {
        buf.push(127);
        let mut remaining = len - 127;
        while remaining >= 128 {
            buf.push((remaining & 0x7F) as u8 | 0x80);
            remaining >>= 7;
        }
        buf.push(remaining as u8);
    }
    buf.extend_from_slice(s);
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
