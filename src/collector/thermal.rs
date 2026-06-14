use crate::collector::CollectorError;
use crate::metrics::{ThermalInfo, ThermalZone};

#[cfg(target_os = "linux")]
use crate::platform::linux::{parse_u64_from_bytes, syscall};

pub struct ThermalCollector;

impl ThermalCollector {
    pub fn new() -> Self { Self }

    #[cfg(target_os = "linux")]
    pub fn collect(&self) -> Result<ThermalInfo, CollectorError> {
        let mut zones = Vec::new();
        // Scan /sys/class/thermal/thermal_zone*/temp
        for i in 0..16u32 {
            let temp_path = format!("/sys/class/thermal/thermal_zone{}/temp\0", i);
            let mut buf = [0u8; 32];
            let n = syscall::read_file_to_buf(temp_path.as_bytes(), &mut buf);
            if n <= 0 { break; }
            let millideg = parse_u64_from_bytes(&buf[..n as usize]);
            let temp_c = millideg as f64 / 1000.0;

            let type_path = format!("/sys/class/thermal/thermal_zone{}/type\0", i);
            let mut type_buf = [0u8; 64];
            let tn = syscall::read_file_to_buf(type_path.as_bytes(), &mut type_buf);
            let zone_type = if tn > 0 {
                let s = &type_buf[..tn as usize];
                String::from_utf8_lossy(s).trim().to_string()
            } else {
                format!("zone{}", i)
            };

            zones.push(ThermalZone {
                name: format!("thermal_zone{}", i),
                temp_celsius: temp_c,
                zone_type,
            });
        }

        let max_temp = zones.iter().map(|z| z.temp_celsius).fold(0.0f64, f64::max);
        Ok(ThermalInfo { zones, max_temp_celsius: max_temp })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn collect(&self) -> Result<ThermalInfo, CollectorError> {
        Ok(ThermalInfo { zones: Vec::new(), max_temp_celsius: 0.0 })
    }
}
