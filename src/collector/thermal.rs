use crate::collector::CollectorError;
use crate::metrics::{ThermalInfo, ThermalZone};
use std::fs;
use std::io::Read;

pub struct ThermalCollector;

impl ThermalCollector {
    pub fn new() -> Self {
        Self
    }

    #[cfg(target_os = "linux")]
    pub fn collect(&self) -> Result<ThermalInfo, CollectorError> {
        let mut zones = Vec::new();
        let thermal_base = "/sys/class/thermal";

        if let Ok(entries) = fs::read_dir(thermal_base) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.starts_with("thermal_zone") {
                    continue;
                }
                let base = format!("{}/{}", thermal_base, name);
                let temp = self.read_temp(&format!("{}/temp", base));
                let zone_type = self.read_string(&format!("{}/type", base));
                zones.push(ThermalZone {
                    name,
                    temp_celsius: temp,
                    zone_type,
                });
            }
        }

        let max_temp = zones
            .iter()
            .map(|z| z.temp_celsius)
            .fold(0.0f64, f64::max);

        Ok(ThermalInfo { zones, max_temp_celsius: max_temp })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn collect(&self) -> Result<ThermalInfo, CollectorError> {
        Ok(ThermalInfo {
            zones: Vec::new(),
            max_temp_celsius: 0.0,
        })
    }

    #[cfg(target_os = "linux")]
    fn read_temp(&self, path: &str) -> f64 {
        let mut buf = String::with_capacity(16);
        if fs::File::open(path)
            .and_then(|mut f| f.read_to_string(&mut buf))
            .is_ok()
        {
            buf.trim()
                .parse::<f64>()
                .map(|v| v / 1000.0)
                .unwrap_or(0.0)
        } else {
            0.0
        }
    }

    #[cfg(target_os = "linux")]
    fn read_string(&self, path: &str) -> String {
        let mut buf = String::with_capacity(64);
        if fs::File::open(path)
            .and_then(|mut f| f.read_to_string(&mut buf))
            .is_ok()
        {
            buf.trim().to_string()
        } else {
            String::new()
        }
    }
}
