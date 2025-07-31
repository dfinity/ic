mod crypt;
mod generated_key;
mod partitions;
mod sev;

#[cfg(test)]
mod tests;

use crate::generated_key::{GeneratedKeyDiskEncryption, DEFAULT_GENERATED_KEY_PATH};
use crate::partitions::{partition_setup, PartitionSetup};
use crate::sev::{SevDiskEncryption, PREVIOUS_KEY_PATH};
use anyhow::{bail, Context, Result};
use clap::Parser;
use config::{deserialize_config, DEFAULT_GUESTOS_CONFIG_OBJECT_PATH};
use config_types::GuestOSConfig;
use grub::BootAlternative;
use ic_sev::guest::key_deriver::SevKeyDeriver;
use linux_kernel_command_line::KernelCommandLine;
use nix::unistd::getuid;
use std::ffi::{c_char, c_int, c_void, CStr};
use std::io::Write;
use std::path::Path;
use std::str::FromStr;

const VAR_CRYPT_NAME: &str = "var_crypt";
const STORE_CRYPT_NAME: &str = "vda10-crypt";

#[derive(clap::Parser)]
pub enum Args {
    /// Opens an encrypted partition and activates it under /dev/mapper/.
    CryptOpen { partition: Partition },
    /// Formats an encrypted partition with LUKS2. This will lead to data loss on the partition.
    /// The command does not open the partition, so a second call to open is necessary to use the
    /// partition.
    CryptFormat { partition: Partition },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Partition {
    /// Encrypted var partition, private to the current GuestOS version.
    Var,
    /// Encrypted store partition, shared between GuestOS releases.
    Store,
}

impl Partition {
    pub fn device_path<'a>(&self, partition_setup: &'a PartitionSetup) -> &'a Path {
        match self {
            Partition::Var => &partition_setup.my_var_partition_device,
            Partition::Store => &partition_setup.store_partition_device,
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    // TODO: We could replace this with Linux capabilities but this works well for now.
    if !getuid().is_root() {
        bail!("This program requires root privileges.");
    }

    let guestos_config: GuestOSConfig = deserialize_config(DEFAULT_GUESTOS_CONFIG_OBJECT_PATH)
        .context("Failed to read GuestOS config")?;

    let mut sev_key_deriver = guestos_config
        .icos_settings
        .enable_trusted_execution_environment
        .then(|| SevKeyDeriver::new())
        .transpose()?;

    let kernel_cmdline = std::fs::read_to_string("/proc/cmdline")
        .context("Failed to read /proc/cmdline")?
        .parse::<KernelCommandLine>()
        .context("Failed to parse kernel command line.")?;

    let boot_alternative = BootAlternative::from_str(
        kernel_cmdline
            .get_argument("dfinity.system")
            .context("dfinity.system was not on kernel command line")?,
    )
    .context("Failed to parse dfinity.system from kernel command line")?;

    run(
        args,
        &guestos_config,
        sev_key_deriver.as_mut(),
        Path::new(PREVIOUS_KEY_PATH),
        Path::new(DEFAULT_GENERATED_KEY_PATH),
        &partition_setup(boot_alternative),
    )
}

/// Sets up disk encryption for the specified partition.
/// `sev_key_deriver` must be provided if the GuestOS is configured to use TEE in `guestos_config`.
fn run(
    args: Args,
    guestos_config: &GuestOSConfig,
    sev_key_deriver: Option<&mut SevKeyDeriver>,
    previous_key_path: &Path,
    generated_key_path: &Path,
    partition_setup: &PartitionSetup,
) -> Result<()> {
    libcryptsetup_rs::set_log_callback::<()>(Some(cryptsetup_error), None);

    let mut encryption: Box<dyn DiskEncryption> = if guestos_config
        .icos_settings
        .enable_trusted_execution_environment
    {
        Box::new(SevDiskEncryption {
            partition_setup,
            sev_key_deriver: sev_key_deriver
                .context("SevKeyDeriver was None, but TEE is enabled")?,
            previous_key_path,
        })
    } else {
        Box::new(GeneratedKeyDiskEncryption {
            partition_setup,
            key_path: generated_key_path,
        })
    };

    match args {
        Args::CryptOpen { partition } => encryption
            .open(partition, crypt_name(partition))
            .with_context(|| format!("Failed to open device for partition {partition:?}")),
        Args::CryptFormat { partition } => encryption
            .format(partition)
            .with_context(|| format!("Failed to format device for partition {partition:?}")),
    }
}

fn crypt_name(partition: Partition) -> &'static str {
    match partition {
        Partition::Var => VAR_CRYPT_NAME,
        Partition::Store => STORE_CRYPT_NAME,
    }
}

trait DiskEncryption {
    /// Opens an encrypted device and activates it under /dev/mapper/`crypt_name`.
    fn open(&mut self, partition: Partition, crypt_name: &str) -> Result<()>;
    /// Formats the device with LUKS2 and initializes it with a key.
    fn format(&mut self, partition: Partition) -> Result<()>;
}

extern "C" fn cryptsetup_error(_level: c_int, msg: *const c_char, _usrptr: *mut c_void) {
    eprintln!(
        "libcryptsetup: {}",
        unsafe { CStr::from_ptr(msg) }.to_string_lossy()
    );
}
