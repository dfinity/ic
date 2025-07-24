use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use libcryptsetup_rs::consts::vals::{CryptKdf, EncryptionFormat};
use libcryptsetup_rs::{CryptInit, CryptParamsLuks2, CryptSettingsHandle};
use libcryptsetup_rs::consts::flags::{CryptActivate, CryptVolumeKey};
use libcryptsetup_rs::Either::Right;
use tempfile::NamedTempFile;
use config::DEFAULT_GUESTOS_CONFIG_OBJECT_PATH;
use config_types::{GuestOSConfig, GuestVMType};
use grub::{BootAlternative, GrubEnv};
use ic_sev::guest::key_deriver::SevKeyDeriver;

const GENERATED_KEY_PATH: &'static str = "/boot/config/store.keyfile";

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Partition {
    /// Encrypted var partition, private to the current GuestOS version.
    Var,
    /// Encrypted store partition, shared between GuestOS releases.
    Store,
}

struct PartitionSetup {
    efi_partition_device: &'static Path,
    grub_partition_device: &'static Path,
    config_partition_device: &'static Path,
    my_boot_partition_device: &'static Path,
    my_root_partition_device: &'static Path,
    my_var_partition_device: &'static Path,
    alternative_boot_partition_device: &'static Path,
    alternative_root_partition_device: &'static Path,
    alternative_var_partition_device: &'static Path,
    store_partition_device: &'static Path,
}

enum DiskEncryptionImplementation {
    Sev(SevDiskEncryptionKeySource),
    Generated(GeneratedDiskEncryptionKeySource),
}

struct DiskEncryption {
    implementation: DiskEncryptionImplementation,
}

impl DiskEncryption {
    fn setup_disk_encryption(&self, partition: Partition) -> Result<()> {
        match self.implementation {
            DiskEncryptionImplementation::Sev(sev) => {}
            DiskEncryptionImplementation::Generated(_) => {}
        }

        let (key, is_new) = self.generate_or_read_key()?;
        let path = match partition {
            self.
        };
        if is_new {
            CryptInit::init(Path::new(""))
        } else {
            println!("Using existing key for partition {:?}: {}", partition, hex::encode(&key));
        }
        open_partition_with_key(&partition, &key)?;
        Ok(())
    }
}

fn open(device: &Path, key: &[u8]) -> Result<()> {
    let mut crypt = CryptInit::init(device)?;
    crypt.activate_handle().activate_by_passphrase(Some("var_crypt"), None, key, CryptActivate::empty())
        .context("Could not activate partition with passphrase")?;
    Ok(())
}

fn format_and_activate(device: &Path, key: &[u8]) -> Result<()> {
    let mut crypt = CryptInit::init(device)?;
    crypt.format_handle().get_type().context("Could not get device format type")? == EncryptionFormat::Luks2;
    crypt.context_handle().format(EncryptionFormat::Luks2, ("aes", "xts-plain64"), None, Right(16), None)?;
    crypt.keyslot_handle().add_by_key(None, None, key, CryptVolumeKey::empty()).context("Could not add key to partition")?;
    crypt.activate_handle().activate_by_passphrase(None, None, key, CryptActivate::empty())
        .context("Could not activate partition with passphrase")?;
    Ok(())
}

trait DiskEncryptionKeySource {
    fn setup_disk_encryption(&self, partition: Partition, partition_setup: &PartitionSetup) -> Result<Vec<u8>>;
}

pub fn new_disk_encryption(enable_trusted_execution_environment: bool) -> Result<Box<dyn DiskEncryptionKeySource>> {
    if enable_trusted_execution_environment {
        SevDiskEncryptionKeySource::new().map(Box::new)
    } else {
        Ok(Box::new(GeneratedDiskEncryptionKeySource::new()))
    }
}

struct SevDiskEncryptionKeySource<'a> {
    sev_key_deriver: &'a mut SevKeyDeriver,
}

impl SevDiskEncryptionKeySource<'_> {
    fn read_key_from_var(&self) -> Option<Vec<u8>> {
        if Path::new("/var/store.keyfile").exists() {
            // If the key file exists, read it
            match std::fs::read("/var/store.keyfile") {
                Ok(key) => Some(key),
                Err(err) => {
                    eprintln!("Could not read /var/store.keyfile: {}", err);
                    None
                }
            }
        } else {
            None
        }
    }
}

impl DiskEncryptionKeySource for SevDiskEncryptionKeySource {
    fn setup_disk_encryption(&self, partition: Partition, partition_setup: &PartitionSetup) -> Result<Vec<u8>> {
        if partition == Partition::Store {
            if let Some(key_from_var) = self.read_key_from_var() {
                println!("Unlocking store with existing key from /var/store.keyfile");
            }
        } else {}
    }
}

struct GeneratedDiskEncryptionKeySource {
    generated_key_path: PathBuf,
}

impl GeneratedDiskEncryptionKeySource {
    pub fn new() -> Self {
        let generated_key_path = PathBuf::from(Self::DEFAULT_KEY_PATH);
        Self { generated_key_path }
    }

    fn generate_or_read_key(&self) -> Result<(Vec<u8>, bool)> {
        if !self.generated_key_path.exists() {
            // Generate a new random key and persist it atomically. Avoid race conditions with other
            // processes by using a temporary file.
            let parent_dir = self.generated_key_path.parent().context("Could not find parent directory for key file")?;
            let mut temp = NamedTempFile::new_in(parent_dir)
                .context("Could not create temporary file for boot partition key")?;
            let rand_key = rand::random::<[u8; 16]>();
            temp.write_all(&rand_key).context("Could not write generated key")?;

            match temp.persist_noclobber(&self.generated_key_path).context("Could not persist boot partition key")? {
                Ok(_) => return Ok((rand_key.to_vec(), true)),
                Err(err) => {
                    if !self.generated_key_path.exists() {
                        return Err(err);
                    }
                    // If the file was created in the meantime, fall through to reading it
                }
            }
        }

        // Read the existing key from disk
        let existing_key = std::fs::read(&self.generated_key_path)
            .context("Could not read existing key file")?;
        Ok((existing_key, false))
    }
}

impl DiskEncryptionKeySource for GeneratedDiskEncryptionKeySource {
    fn setup_disk_encryption(&self, partition: Partition, partition_setup: &PartitionSetup) -> Result<Vec<u8>> {
        let (key, is_new) = self.generate_or_read_key()?;
        let device = match partition {
            Partition::Var => partition_setup.my_var_partition_device,
            Partition::Store => partition_setup.store_partition_device
        };
        open(device, &key)
            .context(format!("Could not open partition {:?} with key", partition))?;
        Ok(key)
    }
}

// fn var_path(guestos_config: &GuestOSConfig) -> Result<PathBuf> {
//     let mut boot_alternative = GrubEnv::read_from(File::open("/boot/grub/grubenv").context("Could not open grub environment")?)
//         .context("Could not read grub environment")?
//         .boot_alternative?;
//
//     let boot_alternative = match guestos_config.guest_vm_type {
//         GuestVMType::Default => boot_alternative,
//         GuestVMType::Upgrade => boot_alternative.get_opposite()
//     };
//
//     let path = match boot_alternative {
//         BootAlternative::A => PathBuf::from("/dev/vda6"),
//         BootAlternative::B => PathBuf::from("/dev/vda9")
//     };
//
//     Ok(path)
// }

fn partition_setup() -> PartitionSetup {
    PartitionSetup {
        efi_partition_device: Path::new("/dev/vda1"),
        grub_partition_device: Path::new("/dev/vda2"),
        config_partition_device: Path::new("/dev/vda3"),
        my_boot_partition_device: Path::new("/dev/vda4"),
        my_root_partition_device: Path::new("/dev/vda5"),
        my_var_partition_device: Path::new("/dev/vda6"),
        alternative_boot_partition_device: Path::new("/dev/vda7"),
        alternative_root_partition_device: Path::new("/dev/vda8"),
        alternative_var_partition_device: Path::new("/dev/vda9"),
        store_partition_device: Path::new("/dev/vda10"),
    }
}

pub fn setup_disk_encryption(partition: Partition, guestos_config: &GuestOSConfig) -> Result<()> {
    let mut sev_key_deriver = if guestos_config.icos_settings.enable_trusted_execution_environment {
        Some(SevKeyDeriver::new()?)
    } else {
        None
    };

    setup_disk_encryption_impl(
        partition,
        guestos_config,
        sev_key_deriver.as_mut(),
        Path::new("/var"),
        Path::new(GENERATED_KEY_PATH),
    )
}

/// Sets up disk encryption for the specified partition.
/// `sev_key_deriver` must be provided if the GuestOS is configured to use TEE in `guestos_config`.
fn setup_disk_encryption_impl(
    partition: Partition,
    guestos_config: &GuestOSConfig,
    sev_key_deriver: Option<&mut SevKeyDeriver>,
    var_path: &Path,
    generated_key_path: &Path,
) -> Result<()> {
    let partition_setup = partition_setup();

    if guestos_config.icos_settings.enable_trusted_execution_environment {
        SevDiskEncryptionKeySource {
            sev_key_deriver: sev_key_deriver.context("SevKeyDeriver was None, but TEE is enabled")?,
        }.setup_disk_encryption(partition, &partition_setup)
            .context(format!("Failed to setup disk encryption for partition {:?}", partition))?;
    } else {
        GeneratedDiskEncryptionKeySource {
            generated_key_path: generated_key_path.to_path_buf(),
        }
            .setup_disk_encryption(partition, &partition_setup)
            .context(format!("Failed to setup disk encryption for partition {:?}", partition))?;
    }
}

disk_encryption.setup_disk_encryption(partition, & partition_setup)
.context(format!("Failed to setup disk encryption for partition {:?}", partition)) ?;

if partition == Partition::Store {
// If the store partition is being set up, ensure the key is written to the generated key path
let key = disk_encryption.generate_or_read_key() ?;
std::fs::write(generated_key_path, key.0).context("Failed to write generated key to store.keyfile") ?;
}

Ok(())
)

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_generated_disk_encryption() {
        let dir = tempdir().unwrap();
        let var = tempdir().unwrap();
        let disk_encryption = GeneratedDiskEncryptionKeySource {
            generated_key_path: dir.path().join("store.keyfile"),
        };

        disk_encryption.setup_disk_encryption(Partition::Var, &partition_setup()).expect("Failed to setup disk encryption for Var partition");
    }
}
