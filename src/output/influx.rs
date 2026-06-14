use crate::metrics::{MetricValue, SystemSnapshot};
use crate::output::{OutputBackend, OutputError};
use std::io::Write;

pub struct InfluxBackend;

impl InfluxBackend {
    pub fn new() -> Self { Self }

    fn escape_tag_value(s: &str) -> String {
        s.replace(' ', "\\ ").replace(',', "\\,").replace('=', "\\=")
    }
}

impl OutputBackend for InfluxBackend {
    fn write(&self, snapshot: &SystemSnapshot) -> Result<(), OutputError> {
        let points = snapshot.to_metric_points();
        let mut buf = String::with_capacity(points.len() * 128);

        for point in &points {
            buf.push_str(&point.name.replace(' ', "\\ ").replace(',', "\\,"));

            let mut tag_pairs: Vec<(&str, &str)> = point.tags.iter()
                .map(|(k, v)| (k.as_str(), v.as_str())).collect();
            tag_pairs.sort_by_key(|(k, _)| *k);
            for (k, v) in &tag_pairs {
                buf.push(',');
                buf.push_str(k);
                buf.push('=');
                buf.push_str(&Self::escape_tag_value(v));
            }

            buf.push(' ');
            match &point.value {
                MetricValue::Gauge(v) => {
                    buf.push_str(&format!("value={}", v));
                }
                MetricValue::Counter(v) => {
                    buf.push_str(&format!("value={}i", v));
                }
                MetricValue::Histogram(h) => {
                    buf.push_str(&format!("count={}i,sum={}", h.count, h.sum));
                    for (q, v) in &h.quantiles {
                        buf.push_str(&format!(",p{}={}", (q * 100.0) as u32, v));
                    }
                }
            }

            buf.push(' ');
            buf.push_str(&point.timestamp.as_nanos().to_string());
            buf.push('\n');
        }

        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        handle.write_all(buf.as_bytes())?;
        handle.flush()?;
        Ok(())
    }

    fn name(&self) -> &'static str { "influx_line_protocol" }
}
