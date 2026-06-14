mod collector;
mod engine;
mod frequency;
mod metrics;
mod output;
pub mod platform;
#[cfg(test)]
mod chaos_tests;

use engine::Engine;
use output::BackendType;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut interval_ms: u64 = 1000;
    let mut backend = BackendType::Influx;
    let mut temp_threshold: f64 = 85.0;
    let mut one_shot = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-i" | "--interval" => {
                i += 1;
                if i < args.len() {
                    interval_ms = args[i].parse().unwrap_or(1000);
                }
            }
            "-o" | "--output" => {
                i += 1;
                if i < args.len() {
                    backend = match args[i].as_str() {
                        "json" => BackendType::Json,
                        "table" => BackendType::Table,
                        "influx" => BackendType::Influx,
                        "http" => BackendType::Http,
                        "grpc" => BackendType::Grpc,
                        other => {
                            eprintln!("unknown backend: {}, using influx", other);
                            BackendType::Influx
                        }
                    };
                }
            }
            "-t" | "--temp-threshold" => {
                i += 1;
                if i < args.len() {
                    temp_threshold = args[i].parse().unwrap_or(85.0);
                }
            }
            "--once" => {
                one_shot = true;
            }
            "-h" | "--help" => {
                print_usage();
                return;
            }
            _ => {
                eprintln!("unknown arg: {}", args[i]);
            }
        }
        i += 1;
    }

    let interval = Duration::from_millis(interval_ms);
    let mut engine = Engine::new(interval, temp_threshold);
    engine.output_router().switch(backend);

    eprintln!(
        "syspulse: interval={}ms backend={} threshold={:.0}°C",
        interval_ms, backend.as_str(), temp_threshold
    );

    if one_shot {
        match engine.collect_once() {
            Ok(snapshot) => {
                if let Err(e) = engine.output_router().write(&snapshot) {
                    eprintln!("output error: {}", e);
                    std::process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("collection error: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        engine.run();
    }
}

fn print_usage() {
    eprintln!(
        "syspulse - high-performance system monitor

USAGE:
    syspulse [OPTIONS]

OPTIONS:
    -i, --interval <ms>       Sampling interval in milliseconds [default: 1000]
    -o, --output <backend>    Output backend: json|table|influx|http|grpc [default: influx]
    -t, --temp-threshold <C>  Temperature threshold for throttling [default: 85]
        --once                Collect once and exit
    -h, --help                Print this help

OUTPUT BACKENDS:
    influx  - InfluxDB line protocol (piping to telegraf/influxdb)
    json    - NDJSON with OpenTelemetry-compatible structure
    table   - Terminal dashboard with ANSI colors
    http    - OTLP/HTTP POST (set SYSPULSE_HTTP_ENDPOINT=host:port/path)
    grpc    - gRPC binary framing (set SYSPULSE_GRPC_ENDPOINT=host:port)

ARCHITECTURE:
    Zero-copy collectors use raw syscalls (pread/getdents64) into stack buffers.
    eBPF map support for IO latency histograms (requires CAP_BPF).
    Output backends are hot-swappable at runtime via atomic index switch.
    Thermal-driven dynamic frequency control (backs off up to 10x).
"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_backend_switch_all() {
        let router = output::OutputRouter::new();
        for bt in [BackendType::Json, BackendType::Table, BackendType::Influx, BackendType::Http, BackendType::Grpc] {
            router.switch(bt);
            assert_eq!(router.active_type(), bt);
        }
    }

    #[test]
    fn test_backend_type_roundtrip() {
        for v in 0..5 {
            let bt = BackendType::from_usize(v);
            assert_eq!(bt as usize, v);
        }
    }
}
