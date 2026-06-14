use crate::collector::cpu::CpuCollector;
use crate::collector::disk::DiskCollector;
use crate::collector::memory::MemoryCollector;
use crate::collector::network::NetworkCollector;
use crate::collector::process::ProcessCollector;
use crate::collector::thermal::ThermalCollector;
use crate::frequency::FrequencyController;
use crate::metrics::*;
use crate::output::OutputRouter;
use std::time::Duration;

pub struct Engine {
    cpu: CpuCollector,
    memory: MemoryCollector,
    disk: DiskCollector,
    network: NetworkCollector,
    process: ProcessCollector,
    thermal: ThermalCollector,
    freq_ctrl: FrequencyController,
    output: OutputRouter,
    hostname: String,
    interval: Duration,
    last_process_ns: u64,
    last_disk_ns: u64,
    cached_processes: ProcessMetrics,
    cached_disk: DiskMetrics,
}

impl Engine {
    pub fn new(interval: Duration, temp_threshold: f64) -> Self {
        let hostname = Self::get_hostname();
        Self {
            cpu: CpuCollector::new(),
            memory: MemoryCollector::new(),
            disk: DiskCollector::new(),
            network: NetworkCollector::new(),
            process: ProcessCollector::new(),
            thermal: ThermalCollector::new(),
            freq_ctrl: FrequencyController::new(interval, temp_threshold),
            output: OutputRouter::new(),
            hostname,
            interval,
            last_process_ns: 0,
            last_disk_ns: 0,
            cached_processes: ProcessMetrics { processes: Vec::new() },
            cached_disk: DiskMetrics { devices: Vec::new() },
        }
    }

    pub fn output_router(&self) -> &OutputRouter {
        &self.output
    }

    pub fn collect_once(&mut self) -> Result<SystemSnapshot, String> {
        let thermal = self.thermal.collect().unwrap_or(ThermalInfo {
            zones: Vec::new(),
            max_temp_celsius: 0.0,
        });

        let cpu = self.cpu.collect().map_err(|e| format!("cpu: {}", e))?;
        let memory = self.memory.collect().map_err(|e| format!("memory: {}", e))?;
        let network = self.network.collect().map_err(|e| format!("network: {}", e))?;

        // Rate-limit disk collection: minimum 500ms between scans
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let slow_interval_ns = 500_000_000u64.max(self.interval.as_nanos() as u64);

        let disk = if now_ns.saturating_sub(self.last_disk_ns) >= slow_interval_ns {
            self.last_disk_ns = now_ns;
            let d = self.disk.collect().map_err(|e| format!("disk: {}", e))?;
            self.cached_disk = d.clone();
            d
        } else {
            self.cached_disk.clone()
        };

        // Rate-limit process collection: minimum 500ms between scans
        let processes = if now_ns.saturating_sub(self.last_process_ns) >= slow_interval_ns {
            self.last_process_ns = now_ns;
            let p = self.process.collect().map_err(|e| format!("process: {}", e))?;
            self.cached_processes = p.clone();
            p
        } else {
            self.cached_processes.clone()
        };

        Ok(SystemSnapshot {
            timestamp: Timestamp::now(),
            hostname: self.hostname.clone(),
            cpu,
            memory,
            disk,
            network,
            processes,
            thermal,
        })
    }

    pub fn run(&mut self) {
        loop {
            match self.collect_once() {
                Ok(snapshot) => {
                    let temp = snapshot.thermal.max_temp_celsius;
                    if let Err(e) = self.output.write(&snapshot) {
                        eprintln!("output error: {}", e);
                    }
                    let interval = self.freq_ctrl.update(temp);
                    if self.freq_ctrl.is_throttled() {
                        eprintln!(
                            "[throttle] temp={:.1}°C interval={}ms",
                            temp, interval.as_millis()
                        );
                    }
                    std::thread::sleep(interval);
                }
                Err(e) => {
                    eprintln!("collection error: {}", e);
                    std::thread::sleep(self.freq_ctrl.current_interval());
                }
            }
        }
    }

    fn get_hostname() -> String {
        #[cfg(target_os = "linux")]
        {
            std::fs::read_to_string("/etc/hostname")
                .unwrap_or_else(|_| "unknown".to_string())
                .trim()
                .to_string()
        }
        #[cfg(not(target_os = "linux"))]
        {
            "unknown".to_string()
        }
    }
}
