use anyhow::{Context, Result};
use raw_cpuid::CpuId;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;

pub mod firmware;
pub mod key_deriver;

/// Checks if SEV is active in the Guest Virtual Machine
pub fn is_sev_active() -> Result<bool> {
    // See https://docs.kernel.org/6.2/x86/amd-memory-encryption.html
    const MSR_AMD64_SEV: u64 = 0xc0010131;

    if Path::new("/dev/sev-guest").exists() {
        return Ok(true);
    }

    let Some(memory_encryption_info) = CpuId::new().get_memory_encryption_info() else {
        // If the CPU does not report memory encryption info, SEV cannot be active.
        return Ok(false);
    };
    if !memory_encryption_info.has_sev() {
        // If the CPU does not support SEV, it cannot be active.
        return Ok(false);
    }

    let msr = File::open("/dev/cpu/0/msr").context("Failed to open /dev/cpu/0/msr")?;
    // MSR reads must be multiplies of 8 bytes, see msr_read in the kernel
    let mut bytes = [0u8; 8];
    msr.read_at(&mut bytes, MSR_AMD64_SEV)
        .context("Failed to read from /dev/cpu/0/msr")?;
    Ok((bytes[0] & 1) != 0)
}
