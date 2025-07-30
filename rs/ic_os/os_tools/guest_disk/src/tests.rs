use crate::crypt::{activate_crypt_device, check_passphrase, FormatOptions};
use crate::partitions::PartitionSetup;
use crate::{crypt_name, setup_disk_encryption_impl, Partition, STORE_CRYPT_NAME};
use anyhow::Result;
use config_types::{
    DeploymentEnvironment, GuestOSConfig, ICOSSettings, Ipv6Config, NetworkSettings,
};
use ic_device::device_mapping::{Bytes, TempDevice};
use ic_sev::guest::firmware::MockSevGuestFirmware;
use ic_sev::guest::key_deriver::{Key, SevKeyDeriver};
use libcryptsetup_rs::consts::flags::CryptDeactivate;
use libcryptsetup_rs::CryptDevice;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use tempfile::{tempdir, TempDir};

static TEST_MUTEX: parking_lot::Mutex<()> = parking_lot::const_mutex(());

struct TestFixture<'a> {
    store_device: TempDevice,
    var_device: TempDevice,
    previous_key_path: PathBuf,
    generated_key_path: PathBuf,
    partition_setup: PartitionSetup,
    sev_key_deriver: SevKeyDeriver,
    guestos_config: GuestOSConfig,
    _temp_dir: TempDir,
    _guard: parking_lot::MutexGuard<'a, ()>,
}

impl<'a> TestFixture<'a> {
    fn new(enable_trusted_execution_environment: bool) -> Self {
        let guard = TEST_MUTEX.lock();
        // LUKS2 needs 16 MB of space for the metadata, let's add 2 MB for the data.
        let store_device = TempDevice::new(Bytes(18 * 1024 * 1024).sectors()).unwrap();
        let var_device = TempDevice::new(Bytes(18 * 1024 * 1024).sectors()).unwrap();
        let temp_dir = tempdir().unwrap();
        let previous_key_path = temp_dir.path().join("previous_key");
        let generated_key_path = temp_dir.path().join("generated_key");
        let mut mock_guest_firmware = MockSevGuestFirmware::new();
        mock_guest_firmware
            .expect_get_derived_key()
            .returning(|_, _| Ok([42; 32]));

        let partition_setup = PartitionSetup {
            efi_partition_device: PathBuf::from("/dev/does_not_exist"),
            grub_partition_device: PathBuf::from("/dev/does_not_exist"),
            config_partition_device: PathBuf::from("/dev/does_not_exist"),
            my_boot_partition_device: PathBuf::from("/dev/does_not_exist"),
            my_root_partition_device: PathBuf::from("/dev/does_not_exist"),
            my_var_partition_device: var_device.path().unwrap(),
            alternative_boot_partition_device: PathBuf::from("/dev/does_not_exist"),
            alternative_root_partition_device: PathBuf::from("/dev/does_not_exist"),
            alternative_var_partition_device: PathBuf::from("/dev/does_not_exist"),
            store_partition_device: store_device.path().unwrap(),
        };

        let sev_key_deriver = SevKeyDeriver::new_for_test(Box::new(mock_guest_firmware));

        let guestos_config = Self::create_guestos_config(enable_trusted_execution_environment);

        let fixture = Self {
            _temp_dir: temp_dir,
            store_device,
            var_device,
            previous_key_path,
            generated_key_path,
            partition_setup,
            sev_key_deriver,
            guestos_config,
            _guard: guard,
        };
        fixture.cleanup();
        fixture
    }

    fn create_guestos_config(enable_trusted_execution_environment: bool) -> GuestOSConfig {
        GuestOSConfig {
            config_version: "".to_string(),
            network_settings: NetworkSettings {
                ipv6_config: Ipv6Config::RouterAdvertisement,
                ipv4_config: None,
                domain_name: None,
            },
            icos_settings: ICOSSettings {
                node_reward_type: None,
                mgmt_mac: Default::default(),
                deployment_environment: DeploymentEnvironment::Mainnet,
                logging: Default::default(),
                use_nns_public_key: false,
                nns_urls: vec![],
                use_node_operator_private_key: false,
                enable_trusted_execution_environment,
                use_ssh_authorized_keys: false,
                icos_dev_settings: Default::default(),
            },
            guestos_settings: Default::default(),
            guest_vm_type: Default::default(),
            upgrade_config: Default::default(),
            trusted_execution_environment_config: None,
        }
    }

    fn setup_disk_encryption(
        &mut self,
        partition: Partition,
        allow_format_store: bool,
    ) -> Result<()> {
        setup_disk_encryption_impl(
            partition,
            &self.guestos_config,
            Some(&mut self.sev_key_deriver),
            &self.previous_key_path,
            &self.generated_key_path,
            &self.partition_setup,
            allow_format_store,
        )
    }

    fn detach_device(&self, partition: Partition) {
        let device_name = crypt_name(partition);
        let _ignore = CryptDevice::from_ptr(std::ptr::null_mut())
            .activate_handle()
            .deactivate(device_name, CryptDeactivate::empty());
        assert!(!get_device_path(partition).exists());
    }

    fn cleanup(&self) {
        for partition in [Partition::Store, Partition::Var] {
            self.detach_device(partition);
        }
    }
}

fn assert_device_has_content(encrypted_device_path: &Path, expected_content: &[u8]) {
    assert!(encrypted_device_path.exists());

    let mut contents = vec![0; expected_content.len()];
    File::open(&encrypted_device_path)
        .unwrap_or_else(|_| {
            panic!(
                "Failed to open encrypted device: {}",
                encrypted_device_path.display()
            )
        })
        .read_exact(&mut contents)
        .unwrap_or_else(|_| {
            panic!(
                "Failed to read from encrypted device: {}",
                encrypted_device_path.display()
            )
        });

    assert_eq!(contents, expected_content);
}

fn get_device_path(partition: Partition) -> &'static Path {
    match partition {
        Partition::Store => Path::new("/dev/mapper/vda10-crypt"),
        Partition::Var => Path::new("/dev/mapper/var_crypt"),
    }
}

#[test]
fn test_generated_key_init_and_reopen() {
    for partition in [Partition::Store, Partition::Var] {
        let mut fixture = TestFixture::new(false);
        let device_path = get_device_path(partition);
        // Test initialization
        fixture
            .setup_disk_encryption(partition, true)
            .expect("Failed to setup disk encryption with generated key");

        assert!(device_path.exists());
        fs::write(device_path, "test_data")
            .expect("Failed to write test data to encrypted partition");

        // Test reopening
        fixture.detach_device(partition);
        fixture
            .setup_disk_encryption(partition, false)
            .expect("Failed to reopen partition with generated key");

        assert_device_has_content(device_path, b"test_data");
    }
}

#[test]
fn test_sev_key_init_and_reopen() {
    for partition in [Partition::Store, Partition::Var] {
        let mut fixture = TestFixture::new(true);
        let device_path = get_device_path(partition);

        assert!(!device_path.exists());

        // Test initialization
        fixture
            .setup_disk_encryption(partition, true)
            .expect("Failed to setup disk encryption with SEV");

        assert!(device_path.exists());
        assert!(!fixture.generated_key_path.exists());

        fs::write(device_path, "test_data")
            .expect("Failed to write test data to encrypted partition");

        // Test reopening
        fixture.detach_device(partition);
        fixture
            .setup_disk_encryption(partition, false)
            .expect("Failed to reopen partition with SEV key");

        assert_device_has_content(device_path, b"test_data");
    }
}

#[test]
fn test_fail_if_allow_format_store_is_false() {
    let mut fixture = TestFixture::new(false);

    let result = fixture.setup_disk_encryption(Partition::Store, false);

    assert!(result.is_err());
    assert!(!Path::new("/dev/mapper/vda10-crypt").exists());
}

#[test]
fn test_store_sev_unlock_with_previous_key() {
    let mut fixture = TestFixture::new(true);

    fs::write(&fixture.previous_key_path, "previous key")
        .expect("Failed to write previous key for testing");

    // Let's assume the store partition is already encrypted with a previous key
    let mut device = activate_crypt_device(
        &fixture.partition_setup.store_partition_device,
        STORE_CRYPT_NAME,
        b"previous key",
        FormatOptions {
            allow_if_uninit: true,
            allow_if_cannot_activate: true,
        },
    )
    .unwrap();

    // Let's also assume that an old deprecated key was also added to the device which will be
    // removed (only the previous key and the new key should remain)
    device
        .keyslot_handle()
        .add_by_passphrase(None, b"previous key", b"deprecated key")
        .expect("Failed to add deprecated key slot");

    check_passphrase(
        &fixture.partition_setup.store_partition_device,
        b"previous key",
    )
    .expect("previous key should unlock the store partition");

    check_passphrase(
        &fixture.partition_setup.store_partition_device,
        b"deprecated key",
    )
    .expect("deprecated key should unlock the store partition");

    fs::write("/dev/mapper/vda10-crypt", "hello world").unwrap();

    drop(device);
    fixture.detach_device(Partition::Store);

    // Reopen
    fixture
        .setup_disk_encryption(Partition::Store, false)
        .unwrap();

    assert_device_has_content(Path::new("/dev/mapper/vda10-crypt"), b"hello world");

    check_passphrase(
        &fixture.partition_setup.store_partition_device,
        b"previous key",
    )
    .expect("previous key should unlock the store partition");

    check_passphrase(
        &fixture.partition_setup.store_partition_device,
        &fixture
            .sev_key_deriver
            .derive_key(Key::StorePartitionEncryptionKey)
            .unwrap(),
    )
    .expect("SEV key should unlock the store partition");

    check_passphrase(
        &fixture.partition_setup.store_partition_device,
        b"deprecated key",
    )
    .expect_err("deprecated key should not unlock the store partition");
}

#[test]
fn test_store_sev_unlock_with_current_key_if_previous_key_does_not_work() {
    let mut fixture = TestFixture::new(true);

    fs::write(&fixture.previous_key_path, "previous key")
        .expect("Failed to write previous key for testing");

    // The store partition is encrypted with the current SEV key but not with the previous key.
    activate_crypt_device(
        &fixture.partition_setup.store_partition_device,
        STORE_CRYPT_NAME,
        &fixture
            .sev_key_deriver
            .derive_key(Key::StorePartitionEncryptionKey)
            .unwrap(),
        FormatOptions {
            allow_if_uninit: true,
            allow_if_cannot_activate: true,
        },
    )
    .unwrap();

    fixture.detach_device(Partition::Store);

    // Reopen
    fixture
        .setup_disk_encryption(Partition::Store, false)
        .expect("Failed to reopen store partition");
}

#[test]
fn test_generated_key_reopen_var_partition() {
    let mut fixture = TestFixture::new(false);

    fixture.setup_disk_encryption(Partition::Var, true).unwrap();
    fs::write("/dev/mapper/var_crypt", "some data").unwrap();
    fixture.detach_device(Partition::Var);

    // Reopen
    fixture
        .setup_disk_encryption(Partition::Var, false)
        .unwrap();

    assert_device_has_content(Path::new("/dev/mapper/var_crypt"), b"some data");
}

#[test]
fn test_reopen_store_partition() {
    let mut fixture = TestFixture::new(false);

    fixture
        .setup_disk_encryption(Partition::Store, true)
        .unwrap();
    fs::write("/dev/mapper/vda10-crypt", "some data").unwrap();
    fixture.detach_device(Partition::Store);

    // Reopen
    fixture
        .setup_disk_encryption(Partition::Store, false)
        .unwrap();
    assert_device_has_content(Path::new("/dev/mapper/vda10-crypt"), b"some data");
}

#[test]
fn test_var_partition_reformatting_behavior() {
    let mut fixture = TestFixture::new(false);

    // Test that var partition can be formatted initially
    fixture
        .setup_disk_encryption(Partition::Var, false)
        .unwrap();
    assert!(fs::metadata(&fixture.generated_key_path).unwrap().len() > 0);

    fs::write("/dev/mapper/var_crypt", "original data").unwrap();
    fixture.detach_device(Partition::Var);

    // Test that var partition gets reformatted when key doesn't work
    fs::write(&fixture.generated_key_path, "wrong key").unwrap();

    fixture
        .setup_disk_encryption(Partition::Var, false)
        .unwrap();

    // Verify the partition was reformatted (original data should be gone)
    let mut buf = vec![0; 13];
    File::open("/dev/mapper/var_crypt")
        .unwrap()
        .read_exact(&mut buf)
        .expect("Could not read from encrypted var partition");
    assert_ne!(buf, b"original data");
}

#[test]
fn test_wont_reformat_store_partition_if_key_doesnt_work() {
    let mut fixture = TestFixture::new(false);

    fixture
        .setup_disk_encryption(Partition::Store, true)
        .unwrap();
    fs::write("/dev/mapper/vda10-crypt", "some data").unwrap();

    fixture.detach_device(Partition::Store);

    // Overwrite the key
    fs::write(&fixture.generated_key_path, "wrong key").unwrap();

    // This should fail because store partition won't be reformatted
    fixture
        .setup_disk_encryption(Partition::Store, true)
        .expect_err("Expected setup_disk_encryption to fail due to wrong key");
}
