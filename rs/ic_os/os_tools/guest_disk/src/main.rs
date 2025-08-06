pub(crate) mod crypt;
mod generated_key;
mod sev;

#[cfg(test)]
mod tests;

use crate::generated_key::{GeneratedKeyDiskEncryption, DEFAULT_GENERATED_KEY_PATH};
use crate::sev::{SevDiskEncryption, PREVIOUS_KEY_PATH};
use anyhow::{bail, Context, Result};
use clap::Parser;
use config::{deserialize_config, DEFAULT_GUESTOS_CONFIG_OBJECT_PATH};
use config_types::GuestOSConfig;
use ic_sev::guest::key_deriver::SevKeyDeriver;
use nix::unistd::getuid;
use std::ffi::{c_char, c_int, c_void, CStr};
use std::path::{Path, PathBuf};

// We depend on the values of these constants in bash scripts and config files so be careful
// when changing them!
const VAR_CRYPT_NAME: &str = "var_crypt";
const STORE_CRYPT_NAME: &str = "vda10-crypt";

#[derive(clap::Parser)]
pub enum Args {
    /// Opens an encrypted partition and activates it under /dev/mapper/.
    CryptOpen {
        partition: Partition,
        device_path: PathBuf,
    },
    /// Formats an encrypted partition with LUKS2. This will lead to data loss on the partition.
    /// The command does not open the partition, so a second call to open is necessary to use the
    /// partition.
    CryptFormat {
        partition: Partition,
        device_path: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Partition {
    /// Encrypted var partition, private to the current GuestOS version.
    Var,
    /// Encrypted store partition, shared between GuestOS releases.
    Store,
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

    run(
        args,
        &guestos_config,
        sev_key_deriver.as_mut(),
        Path::new(PREVIOUS_KEY_PATH),
        Path::new(DEFAULT_GENERATED_KEY_PATH),
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
) -> Result<()> {
    libcryptsetup_rs::set_log_callback::<()>(Some(cryptsetup_log), None);

    let mut encryption: Box<dyn DiskEncryption> = if guestos_config
        .icos_settings
        .enable_trusted_execution_environment
    {
        Box::new(SevDiskEncryption {
            sev_key_deriver: sev_key_deriver
                .context("SevKeyDeriver was None, but TEE is enabled")?,
            guest_vm_type: guestos_config.guest_vm_type,
            previous_key_path,
        })
    } else {
        Box::new(GeneratedKeyDiskEncryption {
            key_path: generated_key_path,
        })
    };

    match args {
        Args::CryptOpen {
            partition,
            device_path,
        } => encryption
            .open(&device_path, partition, crypt_name(partition))
            .with_context(|| format!("Failed to open device for partition {partition:?}")),
        Args::CryptFormat {
            partition,
            device_path,
        } => encryption
            .format(&device_path, partition)
            .with_context(|| format!("Failed to format device for partition {partition:?}")),
    }
}

/// Returns the name of the cryptographic device for the given partition.
/// When opening the encrypted partition, it will be mapped under `/dev/mapper/[crypt_name]`.
fn crypt_name(partition: Partition) -> &'static str {
    match partition {
        Partition::Var => VAR_CRYPT_NAME,
        Partition::Store => STORE_CRYPT_NAME,
    }
}

trait DiskEncryption {
    /// Opens an encrypted device and activates it under /dev/mapper/`crypt_name`.
    fn open(&mut self, device_path: &Path, partition: Partition, crypt_name: &str) -> Result<()>;
    /// Formats the device with LUKS2 and initializes it with a key.
    fn format(&mut self, device_path: &Path, partition: Partition) -> Result<()>;
}

extern "C" fn cryptsetup_log(_level: c_int, msg: *const c_char, _usrptr: *mut c_void) {
    eprintln!(
        "libcryptsetup: {}",
        unsafe { CStr::from_ptr(msg) }.to_string_lossy()
    );
}
