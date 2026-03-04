use crate::guest_vm_config::vm_resources;
use anyhow::Context;
use config_types::HostOSConfig;

const HUGEPAGE_SIZE_KIB: u64 = 2048; // 2MB hugepages
const KIB_PER_GIB: u64 = 1024 * 1024;
const NR_HUGEPAGES_PATH: &str = "/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages";
const FREE_HUGEPAGES_PATH: &str = "/sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages";

/// Reserve hugepages for the GuestOS virtual machine.
///
/// Reads the HostOS config to check if TEE is enabled. If TEE is enabled, hugepages are skipped
/// (the kernel does not support hugepages for confidential VMs). Otherwise, allocates 2MB hugepages
/// for the Guest VM.
pub(crate) fn reserve_hugepages() -> anyhow::Result<()> {
    let hostos_config: HostOSConfig =
        config_tool::deserialize_config(config_tool::DEFAULT_HOSTOS_CONFIG_OBJECT_PATH)
            .context("Failed to read HostOS config file")?;

    if hostos_config
        .icos_settings
        .enable_trusted_execution_environment
    {
        println!("Skipping hugepage setup: trusted execution environment is enabled");
        return Ok(());
    }

    println!("Setting up huge pages");

    let vm_memory_gib = vm_resources(&hostos_config).1 as u64;
    let hugepages_needed = vm_memory_gib * KIB_PER_GIB / HUGEPAGE_SIZE_KIB;

    println!(
        "Allocating {vm_memory_gib} GiB as huge pages ({hugepages_needed} pages of {HUGEPAGE_SIZE_KIB} KiB)"
    );

    std::fs::write(NR_HUGEPAGES_PATH, format!("{hugepages_needed}\n"))
        .context("Failed to write nr_hugepages")?;

    // Verify allocation
    let allocated: u64 = std::fs::read_to_string(NR_HUGEPAGES_PATH)
        .context("Failed to read nr_hugepages after allocation")?
        .trim()
        .parse()
        .context("Failed to parse nr_hugepages after allocation")?;

    if allocated < hugepages_needed {
        println!(
            "Allocation failed ({allocated} pages allocated, {hugepages_needed} pages requested)"
        );
        println!("Resetting hugepages to 0");
        std::fs::write(NR_HUGEPAGES_PATH, "0\n").context("Failed to reset nr_hugepages")?;
        return Ok(());
    }

    println!("Successfully allocated {allocated} huge pages ({vm_memory_gib} GiB)");
    Ok(())
}

/// Read available huge pages in GiB from /sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages
/// Returns 0 if the file cannot be read or parsed.
pub(crate) fn read_available_hugepages_gib() -> u64 {
    match std::fs::read_to_string(FREE_HUGEPAGES_PATH) {
        Ok(content) => {
            match content.trim().parse::<u64>() {
                Ok(free_hugepages) => {
                    // Convert hugepages to GiB
                    (free_hugepages * HUGEPAGE_SIZE_KIB) / KIB_PER_GIB
                }
                Err(e) => {
                    eprintln!("Failed to parse hugepages: {e}");
                    0
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to read hugepages: {e}");
            0
        }
    }
}
