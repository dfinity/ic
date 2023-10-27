// Select our platform.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux_amd64;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use linux_amd64::*;
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod other;
use core::fmt;
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub use other::*;
use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SnpError {
    SnpNotEnabled { description: String },
    FirmwareError { description: String },
    ReportError { description: String },
}

impl Display for SnpError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
