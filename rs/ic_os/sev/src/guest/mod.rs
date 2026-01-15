#[cfg(target_os = "linux")]
use anyhow::{Context, Result, anyhow};

pub mod firmware;
pub mod key_deriver;
pub mod testing;

/// Checks if SEV is active in the Guest Virtual Machine
#[cfg(target_os = "linux")]
pub fn is_sev_active() -> Result<bool> {
    // We read the environment variable set by systemd instead of alternatives:
    // - /dev/sev-guest: This device may not be available early in the boot process even when SEV is
    // active.
    // - cpuid: The call goes through the Host. If we invoked cpuid on every check, a malicious
    // host could intercept the call and return different values thereby making some processes
    // believe that the SEV is active and others believe it is not.
    match std::env::var("SEV_ACTIVE")
        .context("Could not read SEV_ACTIVE environment variable")?
        .as_ref()
    {
        "1" => Ok(true),
        "0" => Ok(false),
        other => Err(anyhow!(
            "SEV_ACTIVE was expected to be 0 or 1 but was: '{other}'"
        )),
    }
}
