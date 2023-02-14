// Select our platform.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux_amd64;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use linux_amd64::*;
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod other;
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub use other::*;
