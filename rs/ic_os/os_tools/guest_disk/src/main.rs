mod crypt;
mod generated_key;
mod partitions;
mod sev;

#[cfg(test)]
mod tests;

use crate::crypt::FormatOptions;
use crate::generated_key::{setup_disk_encryption_with_generated_key, GENERATED_KEY_PATH};
use crate::partitions::{partition_setup, PartitionSetup};
use crate::sev::{setup_disk_encryption_with_sev, PREVIOUS_KEY_PATH};
use anyhow::{Context, Result};
use clap::Parser;
use config::{deserialize_config, DEFAULT_GUESTOS_CONFIG_OBJECT_PATH};
use config_types::GuestOSConfig;
use ic_sev::guest::key_deriver::SevKeyDeriver;
use std::ffi::{c_char, c_int, c_void, CStr};
use std::io::Write;
use std::path::Path;

const VAR_CRYPT_NAME: &str = "var_crypt";
const STORE_CRYPT_NAME: &str = "vda10-crypt";

#[derive(clap::Parser)]
pub enum Args {
    Open { partition: Partition },
    Format { partition: Partition },
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
    match args {
        Args::Open {
            partition,
            allow_format_store,
        } => setup_disk_encryption(partition, allow_format_store),
    }
}

fn crypt_name(partition: Partition) -> &'static str {
    match partition {
        Partition::Var => VAR_CRYPT_NAME,
        Partition::Store => STORE_CRYPT_NAME,
    }
}

fn setup_disk_encryption(partition: Partition, allow_format_store: bool) -> Result<()> {
    let guestos_config: GuestOSConfig = deserialize_config(DEFAULT_GUESTOS_CONFIG_OBJECT_PATH)
        .context("Failed to read GuestOS config")?;

    let mut sev_key_deriver = guestos_config
        .icos_settings
        .enable_trusted_execution_environment
        .then(|| SevKeyDeriver::new())
        .transpose()?;

    setup_disk_encryption_impl(
        partition,
        &guestos_config,
        sev_key_deriver.as_mut(),
        Path::new(PREVIOUS_KEY_PATH),
        Path::new(GENERATED_KEY_PATH),
        &partition_setup(),
        allow_format_store,
    )
}

/// Sets up disk encryption for the specified partition.
/// `sev_key_deriver` must be provided if the GuestOS is configured to use TEE in `guestos_config`.
fn setup_disk_encryption_impl(
    partition: Partition,
    guestos_config: &GuestOSConfig,
    sev_key_deriver: Option<&mut SevKeyDeriver>,
    previous_key_path: &Path,
    generated_key_path: &Path,
    partition_setup: &PartitionSetup,
    allow_format_store: bool,
) -> Result<()> {
    libcryptsetup_rs::set_log_callback::<()>(Some(cryptsetup_error), None);
    let format_options = match partition {
        // If the partition is Var, we always allow formatting.
        Partition::Var => FormatOptions {
            allow_if_uninit: true,
            allow_if_cannot_activate: true,
        },
        // If the partition is Store, we allow formatting only if the caller has specified it.
        Partition::Store => FormatOptions {
            allow_if_uninit: allow_format_store,
            allow_if_cannot_activate: false,
        },
    };

    if guestos_config
        .icos_settings
        .enable_trusted_execution_environment
    {
        setup_disk_encryption_with_sev(
            partition,
            partition_setup,
            crypt_name(partition),
            sev_key_deriver.context("SevKeyDeriver was None, but TEE is enabled")?,
            previous_key_path,
            format_options,
        )
        .with_context(|| {
            format!("Failed to setup disk encryption with SEV for partition {partition:?}")
        })
    } else {
        setup_disk_encryption_with_generated_key(
            partition,
            partition_setup,
            crypt_name(partition),
            generated_key_path,
            format_options,
        )
        .with_context(|| {
            format!(
                "Failed to setup disk encryption with generated key for partition {partition:?}",
            )
        })
    }
}

extern "C" fn cryptsetup_error(level: c_int, msg: *const c_char, usrptr: *mut c_void) {
    eprintln!(
        "libcryptsetup: {}",
        unsafe { CStr::from_ptr(msg) }.to_string_lossy()
    );
}
