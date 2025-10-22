use libcryptsetup_rs::consts::flags::CryptActivate;
use std::path::Path;

pub mod crypt;
pub mod generated_key;
pub mod sev;

pub const DEFAULT_PREVIOUS_SEV_KEY_PATH: &str = "/var/alternative_store.keyfile";

// We depend on the values of these constants in bash scripts and config files so be careful
// when changing them!
const VAR_CRYPT_NAME: &str = "var_crypt";
const STORE_CRYPT_NAME: &str = "vda10-crypt";

pub trait DiskEncryption {
    /// Opens an encrypted device and activates it under /dev/mapper/`crypt_name`.
    fn open(
        &mut self,
        device_path: &Path,
        partition: Partition,
        crypt_name: &str,
    ) -> anyhow::Result<()>;
    /// Formats the device with LUKS2 and initializes it with a key.
    fn format(&mut self, device_path: &Path, partition: Partition) -> anyhow::Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Partition {
    /// Encrypted var partition, private to the current GuestOS version.
    Var,
    /// Encrypted store partition, shared between GuestOS releases.
    Store,
}

/// Returns the name of the cryptographic device for the given partition.
/// When opening the encrypted partition, it will be mapped under `/dev/mapper/[crypt_name]`.
pub fn crypt_name(partition: Partition) -> &'static str {
    match partition {
        Partition::Var => VAR_CRYPT_NAME,
        Partition::Store => STORE_CRYPT_NAME,
    }
}

pub(crate) fn activate_flags(partition: Partition) -> CryptActivate {
    match partition {
        Partition::Var => CryptActivate::empty(),
        Partition::Store => CryptActivate::ALLOW_DISCARDS,
    }
}
