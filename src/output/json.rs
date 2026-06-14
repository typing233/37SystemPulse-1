use crate::metrics::{MetricValue, SystemSnapshot};
use crate::output::{OutputBackend, OutputError};
use std::io::Write;

pub struct JsonBackend;

impl JsonBackend {
    pub fn new() -> Self {
        Self
    }

    fn format_snapshot(&self, snapshot: &SystemSnapshot) -> String {
        let points = snapshot.to_metric_points();
        let mut buf = String::with_capacity(points.len() * 200);
        buf.push_str("{\"metrics\":[");

        for (i, point) in points.iter().enumerate() {
            if i > 0 {
                buf.push(',');
            }
            buf.push_str("{\"name\":\"");
            buf.push_str(&Self::escape_json(&point.name));
            buf.push_str("\",\"tags\":{");

            let mut first = true;
            let mut sorted_tags: Vec<_> = point.tags.iter().collect();
            sorted_tags.sort_by_key(|(k, _)| k.as_str());
            for (k, v) in sorted_tags {
                if !first {
                    buf.push(',');
                }
                first = false;
                buf.push('"');
                buf.push_str(&Self::escape_json(k));
                buf.push_str("\":\"");
                buf.push_str(&Self::escape_json(v));
                buf.push('"');
            }

            buf.push_str("},\"value\":");
            match &point.value {
                MetricValue::Gauge(v) => buf.push_str(&format!("{}", v)),
                MetricValue::Counter(v) => buf.push_str(&format!("{}", v)),
                MetricValue::Histogram(h) => {
                    buf.push_str(&format!(
                        "{{\"count\":{},\"sum\":{}",
                        h.count, h.sum
                    ));
                    for (q, v) in &h.quantiles {
                        buf.push_str(&format!(",\"p{}\":{}", (q * 100.0) as u32, v));
                    }
                    buf.push('}');
                }
            }

            buf.push_str(",\"timestamp\":");
            buf.push_str(&point.timestamp.as_nanos().to_string());
            buf.push_str(",\"unit\":\"");
            buf.push_str(point.unit);
            buf.push_str("\"}");
        }

        buf.push_str("],\"hostname\":\"");
        buf.push_str(&Self::escape_json(&snapshot.hostname));
        buf.push_str("\",\"timestamp\":");
        buf.push_str(&snapshot.timestamp.as_nanos().to_string());
        buf.push_str("}\n");
        buf
    }

    fn escape_json(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if c < '\x20' => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out
    }
}

impl OutputBackend for JsonBackend {
    fn write(&self, snapshot: &SystemSnapshot) -> Result<(), OutputError> {
        let output = self.format_snapshot(snapshot);
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        handle.write_all(output.as_bytes())?;
        handle.flush()?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "json"
    }
}
