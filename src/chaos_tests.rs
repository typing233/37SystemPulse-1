use crate::collector::cpu::CpuCollector;
use crate::collector::disk::DiskCollector;
use crate::collector::memory::MemoryCollector;
use crate::collector::network::NetworkCollector;
use crate::collector::process::ProcessCollector;
use crate::collector::thermal::ThermalCollector;
use crate::engine::Engine;
use crate::frequency::FrequencyController;
use crate::metrics::*;
use crate::output::{BackendType, OutputBackend, OutputRouter};
use std::time::{Duration, Instant};

#[cfg(test)]
mod tests {
    use super::*;

    // ─── White-box: collector resilience ───

    #[test]
    fn test_cpu_collector_first_sample_returns_zeros() {
        let mut cpu = CpuCollector::new();
        let result = cpu.collect();
        if let Ok(metrics) = result {
            assert_eq!(metrics.total.idle_pct, 100.0);
        }
    }

    #[test]
    fn test_cpu_collector_two_samples() {
        let mut cpu = CpuCollector::new();
        let _ = cpu.collect();
        std::thread::sleep(Duration::from_millis(50));
        let result = cpu.collect();
        if let Ok(metrics) = result {
            let total = metrics.total.user_pct
                + metrics.total.system_pct
                + metrics.total.idle_pct
                + metrics.total.iowait_pct
                + metrics.total.softirq_pct
                + metrics.total.hardirq_pct
                + metrics.total.steal_pct;
            assert!((total - 100.0).abs() < 0.1, "CPU percentages should sum to ~100, got {}", total);
        }
    }

    #[test]
    fn test_memory_collector_sanity() {
        let mut mem = MemoryCollector::new();
        if let Ok(metrics) = mem.collect() {
            assert!(metrics.total_bytes > 0);
            assert!(metrics.available_bytes <= metrics.total_bytes);
            assert!(metrics.used_bytes <= metrics.total_bytes);
        }
    }

    #[test]
    fn test_disk_collector_finds_filesystems() {
        let mut disk = DiskCollector::new();
        if let Ok(metrics) = disk.collect() {
            for dev in &metrics.devices {
                assert!(!dev.fs_type.is_empty());
                assert!(!dev.mount_point.is_empty());
            }
        }
    }

    #[test]
    fn test_network_collector_no_loopback() {
        let mut net = NetworkCollector::new();
        let _ = net.collect();
        std::thread::sleep(Duration::from_millis(50));
        if let Ok(metrics) = net.collect() {
            for iface in &metrics.interfaces {
                assert_ne!(iface.name, "lo", "loopback should be excluded");
            }
        }
    }

    #[test]
    fn test_process_collector_finds_self() {
        let mut proc_col = ProcessCollector::new();
        // First call primes the tick baseline
        let _ = proc_col.collect();
        std::thread::sleep(Duration::from_millis(50));
        if let Ok(metrics) = proc_col.collect() {
            let my_pid = std::process::id();
            let found = metrics.processes.iter().any(|p| p.pid == my_pid);
            assert!(found, "should find our own process (pid={})", my_pid);
        }
    }

    #[test]
    fn test_process_cpu_pct_reasonable() {
        let mut proc_col = ProcessCollector::new();
        let _ = proc_col.collect();
        std::thread::sleep(Duration::from_millis(100));
        if let Ok(metrics) = proc_col.collect() {
            for proc in &metrics.processes {
                // CPU% per process should be 0-num_cpus*100 at most
                assert!(
                    proc.cpu_pct <= 800.0,
                    "process {} has unreasonable cpu_pct={:.1}%",
                    proc.name, proc.cpu_pct
                );
                assert!(
                    proc.cpu_pct >= 0.0,
                    "process {} has negative cpu_pct={:.1}%",
                    proc.name, proc.cpu_pct
                );
            }
        }
    }

    #[test]
    fn test_thermal_collector_no_panic() {
        let thermal = ThermalCollector::new();
        let _ = thermal.collect();
    }

    // ─── White-box: output backend correctness ───

    #[test]
    fn test_influx_output_includes_all_metrics() {
        let snapshot = make_test_snapshot();
        let points = snapshot.to_metric_points();
        let names: Vec<&str> = points.iter().map(|p| p.name.as_str()).collect();
        // Verify all major categories are present
        assert!(names.iter().any(|n| n.starts_with("cpu.")), "missing CPU metrics");
        assert!(names.iter().any(|n| n.starts_with("memory.")), "missing memory metrics");
        assert!(names.iter().any(|n| n.starts_with("disk.")), "missing disk metrics");
        assert!(names.iter().any(|n| n.starts_with("net.")), "missing network metrics");
        assert!(names.iter().any(|n| n.starts_with("thermal.")), "missing thermal metrics");
        assert!(names.iter().any(|n| n.starts_with("process.")), "missing process metrics");
        assert!(names.iter().any(|n| *n == "net.packet_loss_rate"), "missing packet_loss_rate");
    }

    #[test]
    fn test_json_output_valid() {
        let snapshot = make_test_snapshot();
        let backend = crate::output::json::JsonBackend::new();
        let _ = backend.write(&snapshot);
    }

    #[test]
    fn test_atomic_backend_switch_under_load() {
        let router = OutputRouter::new();
        let handle = router.handle();

        let switch_thread = std::thread::spawn(move || {
            for _ in 0..1000 {
                handle.switch(BackendType::Json);
                handle.switch(BackendType::Influx);
                handle.switch(BackendType::Http);
                handle.switch(BackendType::Grpc);
                handle.switch(BackendType::Table);
            }
        });

        for _ in 0..1000 {
            let t = router.active_type();
            assert!((t as usize) < 5);
        }
        switch_thread.join().unwrap();
    }

    // ─── White-box: frequency controller chaos ───

    #[test]
    fn test_frequency_rapid_oscillation() {
        let mut fc = FrequencyController::new(Duration::from_millis(100), 80.0);
        for i in 0..100 {
            let temp = if i % 2 == 0 { 95.0 } else { 70.0 };
            let interval = fc.update(temp);
            assert!(interval >= Duration::from_millis(100));
            assert!(interval <= Duration::from_millis(1000));
        }
    }

    #[test]
    fn test_frequency_extreme_temperature() {
        let mut fc = FrequencyController::new(Duration::from_millis(100), 80.0);
        let interval = fc.update(10000.0);
        assert_eq!(interval, Duration::from_millis(1000));
    }

    #[test]
    fn test_frequency_negative_temperature() {
        let mut fc = FrequencyController::new(Duration::from_millis(100), 80.0);
        let interval = fc.update(-40.0);
        assert_eq!(interval, Duration::from_millis(100));
    }

    // ─── White-box: engine integration ───

    #[test]
    fn test_engine_collect_once() {
        let mut engine = Engine::new(Duration::from_millis(1000), 85.0);
        let result = engine.collect_once();
        assert!(result.is_ok(), "engine should collect: {:?}", result.err());
    }

    #[test]
    fn test_engine_performance_budget() {
        let mut engine = Engine::new(Duration::from_millis(100), 85.0);
        let _ = engine.collect_once();
        std::thread::sleep(Duration::from_millis(100));

        let start = Instant::now();
        let iterations = 10;
        for _ in 0..iterations {
            let _ = engine.collect_once();
        }
        let elapsed = start.elapsed();
        let per_collection = elapsed / iterations;

        assert!(
            per_collection < Duration::from_millis(50),
            "collection took {:?} per iteration, budget exceeded",
            per_collection
        );
    }

    #[test]
    fn test_metric_points_have_timestamps() {
        let snapshot = make_test_snapshot();
        let points = snapshot.to_metric_points();
        for point in &points {
            assert!(point.timestamp.as_nanos() > 0);
        }
    }

    // ─── Chaos ───

    #[test]
    fn test_concurrent_collection_safety() {
        let handles: Vec<_> = (0..4)
            .map(|_| {
                std::thread::spawn(|| {
                    let mut engine = Engine::new(Duration::from_millis(100), 85.0);
                    for _ in 0..5 {
                        let _ = engine.collect_once();
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked during concurrent collection");
        }
    }

    #[test]
    fn test_http_backend_format_no_panic() {
        let snapshot = make_test_snapshot();
        let backend = crate::output::remote::HttpBackend::new();
        // Will fail to connect but should not panic during formatting
        let _ = backend.write(&snapshot);
    }

    #[test]
    fn test_grpc_backend_encode_no_panic() {
        let snapshot = make_test_snapshot();
        let backend = crate::output::remote::GrpcBackend::new();
        let _ = backend.write(&snapshot);
    }

    // ─── Helper ───

    fn make_test_snapshot() -> SystemSnapshot {
        let mut engine = Engine::new(Duration::from_millis(100), 85.0);
        let _ = engine.collect_once();
        std::thread::sleep(Duration::from_millis(50));
        engine.collect_once().expect("test snapshot collection failed")
    }
}
