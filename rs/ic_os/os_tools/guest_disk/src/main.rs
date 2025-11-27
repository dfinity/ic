#[cfg(test)]
mod tests;

use anyhow::{Context, Result, bail};
use clap::Parser;
use config::{DEFAULT_GUESTOS_CONFIG_OBJECT_PATH, deserialize_config};
use config_types::GuestOSConfig;
use guest_disk::generated_key::{DEFAULT_GENERATED_KEY_PATH, GeneratedKeyDiskEncryption};
use guest_disk::sev::SevDiskEncryption;
use guest_disk::{DEFAULT_PREVIOUS_SEV_KEY_PATH, DiskEncryption, Partition, crypt_name};
use ic_sev::guest::firmware::SevGuestFirmware;
use nix::unistd::getuid;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::path::{Path, PathBuf};

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

#[cfg(target_os = "linux")]
fn main() -> Result<()> {
    let args = Args::parse();

    // TODO: We could replace this with Linux capabilities but this works well for now.
    if !getuid().is_root() {
        bail!("This program requires root privileges.");
    }

    let guestos_config: GuestOSConfig = deserialize_config(DEFAULT_GUESTOS_CONFIG_OBJECT_PATH)
        .context("Failed to read GuestOS config")?;

    run(
        args,
        &guestos_config,
        ic_sev::guest::is_sev_active().context("Failed to check if SEV is active")?,
        || {
            ::sev::firmware::guest::Firmware::open()
                .context("Failed to open /dev/sev-guest")
                .map(|x| Box::new(x) as _)
        },
        Path::new(DEFAULT_PREVIOUS_SEV_KEY_PATH),
        Path::new(DEFAULT_GENERATED_KEY_PATH),
    )
}

/// Sets up disk encryption for the specified partition.
/// `sev_key_deriver` must be provided if the GuestOS is configured to use TEE in `guestos_config`.
fn run(
    args: Args,
    guestos_config: &GuestOSConfig,
    is_sev_active: bool,
    sev_firmware_factory: impl Fn() -> Result<Box<dyn SevGuestFirmware>>,
    previous_key_path: &Path,
    generated_key_path: &Path,
) -> Result<()> {
    libcryptsetup_rs::set_log_callback::<()>(Some(cryptsetup_log), None);

    let mut encryption: Box<dyn DiskEncryption> = if is_sev_active {
        Box::new(SevDiskEncryption {
            sev_firmware: sev_firmware_factory().context("Failed to open SEV firmware")?,
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

unsafe extern "C" fn cryptsetup_log(_level: c_int, msg: *const c_char, _usrptr: *mut c_void) {
    eprintln!(
        "libcryptsetup: {}",
        unsafe { CStr::from_ptr(msg) }.to_string_lossy()
    );
}
