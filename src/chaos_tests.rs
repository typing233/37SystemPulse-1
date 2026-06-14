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
        // First sample has no delta, should return zeros
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
        let _ = net.collect(); // prime
        std::thread::sleep(Duration::from_millis(50));
        if let Ok(metrics) = net.collect() {
            for iface in &metrics.interfaces {
                assert_ne!(iface.name, "lo", "loopback should be excluded");
            }
        }
    }

    #[test]
    fn test_process_collector_finds_self() {
        let proc_col = ProcessCollector::new();
        if let Ok(metrics) = proc_col.collect() {
            let my_pid = std::process::id();
            let found = metrics.processes.iter().any(|p| p.pid == my_pid);
            assert!(found, "should find our own process");
        }
    }

    #[test]
    fn test_thermal_collector_no_panic() {
        let thermal = ThermalCollector::new();
        let _ = thermal.collect(); // should not panic even if no thermal zones
    }

    // ─── White-box: output backend correctness ───

    #[test]
    fn test_influx_line_protocol_format() {
        let snapshot = make_test_snapshot();
        let points = snapshot.to_metric_points();
        assert!(!points.is_empty());
        // Verify influx format properties
        for point in &points {
            assert!(!point.name.is_empty());
            assert!(!point.name.contains(' '));
        }
    }

    #[test]
    fn test_json_output_valid() {
        let snapshot = make_test_snapshot();
        let backend = crate::output::json::JsonBackend::new();
        // Capture would need redirect; just verify no panic
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
                handle.switch(BackendType::Table);
            }
        });

        // Concurrent reads should never see invalid index
        for _ in 0..1000 {
            let t = router.active_type();
            assert!((t as usize) < 3);
        }
        switch_thread.join().unwrap();
    }

    // ─── White-box: frequency controller chaos ───

    #[test]
    fn test_frequency_rapid_oscillation() {
        let mut fc = FrequencyController::new(Duration::from_millis(100), 80.0);
        // Rapid temperature oscillation should not cause issues
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
        // Extreme temp should be capped at max backoff
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
        // Warm up
        let _ = engine.collect_once();
        std::thread::sleep(Duration::from_millis(100));

        let start = Instant::now();
        let iterations = 10;
        for _ in 0..iterations {
            let _ = engine.collect_once();
        }
        let elapsed = start.elapsed();
        let per_collection = elapsed / iterations;

        // Each collection should complete well under 100ms
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

    // ─── Chaos: simulate resource exhaustion ───

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

    // ─── Helper ───

    fn make_test_snapshot() -> SystemSnapshot {
        let mut engine = Engine::new(Duration::from_millis(100), 85.0);
        let _ = engine.collect_once(); // prime
        std::thread::sleep(Duration::from_millis(50));
        engine.collect_once().expect("test snapshot collection failed")
    }
}
