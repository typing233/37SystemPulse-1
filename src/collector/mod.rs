use crate::metrics::SystemSnapshot;

pub trait Collector: Send + Sync {
    fn collect(&mut self) -> Result<SystemSnapshot, CollectorError>;
}

#[derive(Debug)]
pub enum CollectorError {
    Io(std::io::Error),
    Parse(String),
    Unsupported(String),
}

impl std::fmt::Display for CollectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {}", e),
            Self::Parse(s) => write!(f, "Parse error: {}", s),
            Self::Unsupported(s) => write!(f, "Unsupported: {}", s),
        }
    }
}

impl From<std::io::Error> for CollectorError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub mod cpu;
pub mod disk;
pub mod memory;
pub mod network;
pub mod process;
pub mod thermal;
