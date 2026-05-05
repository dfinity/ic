#[cfg(test)]
mod tests;

use anyhow::{Context, Result, bail};
use clap::Parser;
use config_tool::{DEFAULT_GUESTOS_CONFIG_OBJECT_PATH, deserialize_config};
use config_types::GuestOSConfig;
use guest_disk::generated_key::{DEFAULT_GENERATED_KEY_PATH, GeneratedKeyDiskEncryption};
use guest_disk::sev::SevDiskEncryption;
use guest_disk::{
    DEFAULT_PREVIOUS_SEV_KEY_PATH, DEFAULT_STORE_LUKS_HEADER_PATH, DiskEncryption, Partition,
    crypt_name,
};
use nix::unistd::getuid;
use sev_guest::firmware::SevGuestFirmware;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::path::{Path, PathBuf};
use tracing::warn;

const METRICS_DIR: &str = "/run/node_exporter/collector_textfile";

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

impl Args {
    fn partition(&self) -> Partition {
        match self {
            Args::CryptOpen { partition, .. } | Args::CryptFormat { partition, .. } => *partition,
        }
    }
}

#[cfg(target_os = "linux")]
fn main() -> Result<()> {
    ic_os_logging::init_logging();

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
        sev_guest::is_tee_enabled().context("Failed to check if SEV is active")?,
        || {
            ::sev::firmware::guest::Firmware::open()
                .context("Failed to open /dev/sev-guest")
                .map(|x| Box::new(x) as _)
        },
        Path::new(DEFAULT_PREVIOUS_SEV_KEY_PATH),
        Path::new(DEFAULT_STORE_LUKS_HEADER_PATH),
        Path::new(DEFAULT_GENERATED_KEY_PATH),
        Path::new(METRICS_DIR),
    )
}

/// Sets up disk encryption for the specified partition.
/// `sev_key_deriver` must be provided if the GuestOS is configured to use TEE in `guestos_config`.
fn run(
    args: Args,
    guestos_config: &GuestOSConfig,
    is_tee_enabled: bool,
    sev_firmware_factory: impl Fn() -> Result<Box<dyn SevGuestFirmware>>,
    previous_key_path: &Path,
    store_luks_header_path: &Path,
    generated_key_path: &Path,
    metrics_dir: &Path,
) -> Result<()> {
    libcryptsetup_rs::set_log_callback::<()>(Some(cryptsetup_log), None);

    let metrics_file = metrics_file_path(metrics_dir, args.partition());
    let mut encryption: Box<dyn DiskEncryption> = if is_tee_enabled {
        Box::new(SevDiskEncryption {
            sev_firmware: sev_firmware_factory().context("Failed to open SEV firmware")?,
            guest_vm_type: guestos_config.guest_vm_type,
            previous_key_path: previous_key_path.to_path_buf(),
            store_luks_header_path: store_luks_header_path.to_path_buf(),
            metrics_file,
        })
    } else {
        Box::new(GeneratedKeyDiskEncryption {
            key_path: generated_key_path,
            metrics_file: &metrics_file,
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

fn metrics_file_path(metrics_dir: &Path, partition: Partition) -> PathBuf {
    let partition = match partition {
        Partition::Var => "var",
        Partition::Store => "store",
    };

    metrics_dir.join(format!("guest_disk_encryption_{partition}.prom"))
}

unsafe extern "C" fn cryptsetup_log(_level: c_int, msg: *const c_char, _usrptr: *mut c_void) {
    warn!(
        "libcryptsetup: {}",
        unsafe { CStr::from_ptr(msg) }.to_string_lossy()
    );
}
