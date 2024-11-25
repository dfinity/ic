use std::fmt;
use std::io;
use std::process::Command;
use std::str::Utf8Error;

pub static DEFAULT_SYSTEMD_NETWORK_DIR: &str = "/run/systemd/network";

pub fn restart_systemd_networkd() {
    let _ = Command::new("timeout")
        .args(["3", "systemctl", "restart", "systemd-networkd"])
        .status();
    // Explicitly don't care about return code status...
}

#[derive(Debug)]
pub enum VirtualizationDetectionError {
    IOError(io::Error),
    Utf8Error(Utf8Error),
}

impl std::error::Error for VirtualizationDetectionError {}

impl From<io::Error> for VirtualizationDetectionError {
    fn from(error: io::Error) -> Self {
        Self::IOError(error)
    }
}

impl From<Utf8Error> for VirtualizationDetectionError {
    fn from(error: Utf8Error) -> Self {
        Self::Utf8Error(error)
    }
}

impl fmt::Display for VirtualizationDetectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IOError(e) => {
                write!(f, "Cannot detect virtualization (I/O error): {}", e)
            }
            Self::Utf8Error(e) => {
                write!(
                    f,
                    "Cannot detect virtualization (failed to decode systemd output): {}",
                    e
                )
            }
        }
    }
}

pub enum VirtualizationType {
    BareMetal,
    Virtualized,
}

pub fn detect_virt() -> Result<VirtualizationType, VirtualizationDetectionError> {
    let stdout = Command::new("systemd-detect-virt").output()?.stdout;
    Ok(match std::str::from_utf8(&stdout)?.trim() {
        "none" => VirtualizationType::BareMetal,
        _ => VirtualizationType::Virtualized,
    })
}
