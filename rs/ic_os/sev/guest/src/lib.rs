use anyhow::{Context, Result};
use linux_kernel_command_line::KernelCommandLine;
use std::str::FromStr;

pub mod attestation_package;
pub mod key_deriver;

// Re-export firmware types from the firmware crate (optimally we would just declare it as a module
// of this crate but then there would be a cyclic dependency with the sev_guest_testing crate).
pub use sev_guest_firmware as firmware;

/// Checks if Trusted Execution Environment (via SEV) is active in the Guest Virtual Machine
pub fn is_tee_enabled() -> Result<bool> {
    let cmdline = std::fs::read_to_string("/proc/cmdline")
        .context("Could not read kernel command line from /proc/cmdline")?;
    is_tee_enabled_impl(&cmdline)
}

fn is_tee_enabled_impl(cmdline: &str) -> Result<bool> {
    let kernel_command_line =
        KernelCommandLine::from_str(cmdline).context("Could not parse kernel command line")?;
    Ok(kernel_command_line.get_argument("dfinity.tee").is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_tee_enabled() {
        assert!(is_tee_enabled_impl("root=/dev/disk/by-partuuid/7c0a626e-e5ea-e543-b5c5-300eb8304db7 console=ttyS0 console=tty0 nomodeset dfinity.system=A dfinity.tee=1 security=selinux selinux=1 enforcing=1 root_hash=abc1234").unwrap());
        assert!(!is_tee_enabled_impl("root=/dev/disk/by-partuuid/a78bc3a8-376c-054a-96e7-3904b915d0c5 console=ttyS0 console=tty0 nomodeset dfinity.system=B security=selinux selinux=1 enforcing=1 root_hash=12345").unwrap());
    }
}
