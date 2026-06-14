use crate::metrics::SystemSnapshot;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

pub mod influx;
pub mod json;
pub mod remote;
pub mod table;

pub trait OutputBackend: Send + Sync {
    fn write(&self, snapshot: &SystemSnapshot) -> Result<(), OutputError>;
    fn name(&self) -> &'static str;
}

#[derive(Debug)]
pub enum OutputError {
    Io(std::io::Error),
    Format(String),
}

impl std::fmt::Display for OutputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO: {}", e),
            Self::Format(s) => write!(f, "Format: {}", s),
        }
    }
}

impl From<std::io::Error> for OutputError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum BackendType {
    Json = 0,
    Table = 1,
    Influx = 2,
    Http = 3,
    Grpc = 4,
}

impl BackendType {
    pub fn from_usize(v: usize) -> Self {
        match v {
            0 => Self::Json,
            1 => Self::Table,
            2 => Self::Influx,
            3 => Self::Http,
            4 => Self::Grpc,
            _ => Self::Json,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Table => "table",
            Self::Influx => "influx",
            Self::Http => "http",
            Self::Grpc => "grpc",
        }
    }
}

pub struct OutputRouter {
    backends: Vec<Box<dyn OutputBackend>>,
    active: Arc<AtomicUsize>,
}

impl OutputRouter {
    pub fn new() -> Self {
        let backends: Vec<Box<dyn OutputBackend>> = vec![
            Box::new(json::JsonBackend::new()),
            Box::new(table::TableBackend::new()),
            Box::new(influx::InfluxBackend::new()),
            Box::new(remote::HttpBackend::new()),
            Box::new(remote::GrpcBackend::new()),
        ];
        Self {
            backends,
            active: Arc::new(AtomicUsize::new(BackendType::Influx as usize)),
        }
    }

    pub fn switch(&self, backend: BackendType) {
        self.active.store(backend as usize, Ordering::Release);
    }

    pub fn active_type(&self) -> BackendType {
        BackendType::from_usize(self.active.load(Ordering::Acquire))
    }

    pub fn handle(&self) -> OutputHandle {
        OutputHandle { active: self.active.clone() }
    }

    pub fn write(&self, snapshot: &SystemSnapshot) -> Result<(), OutputError> {
        let idx = self.active.load(Ordering::Acquire);
        if idx < self.backends.len() {
            self.backends[idx].write(snapshot)
        } else {
            Err(OutputError::Format("invalid backend index".to_string()))
        }
    }
}

pub struct OutputHandle {
    active: Arc<AtomicUsize>,
}

impl OutputHandle {
    pub fn switch(&self, backend: BackendType) {
        self.active.store(backend as usize, Ordering::Release);
    }
}
