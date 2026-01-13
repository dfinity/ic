use crate::{Args, Partition, crypt_name, run};
use anyhow::Result;
use config_types::{GuestOSConfig, ICOSSettings};
use guest_disk::crypt::{
    activate_crypt_device, check_encryption_key, deactivate_crypt_device, format_crypt_device,
};
use guest_disk::sev::can_open_store;
use ic_device::device_mapping::{Bytes, TempDevice};
use ic_sev::guest::key_deriver::{Key, derive_key_from_sev_measurement};
use ic_sev::guest::testing::MockSevGuestFirmwareBuilder;
use libcryptsetup_rs::consts::flags::CryptActivate;
use std::fs;
use std::fs::{File, Permissions};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::{TempDir, tempdir};

// All tests interact with the same device mapper and use shared crypt device names, so we must run
// the tests sequentially.
static TEST_MUTEX: parking_lot::Mutex<()> = parking_lot::const_mutex(());

struct TestFixture<'a> {
    device: TempDevice,
    previous_key_path: PathBuf,
    generated_key_path: PathBuf,
    sev_firmware_builder: MockSevGuestFirmwareBuilder,
    guestos_config: GuestOSConfig,
    _temp_dir: TempDir,
    _guard: parking_lot::MutexGuard<'a, ()>,
}

impl<'a> TestFixture<'a> {
    fn new(enable_trusted_execution_environment: bool) -> Self {
        let guard = TEST_MUTEX.lock();
        cleanup();
        // LUKS2 needs 16 MB of space for the metadata, let's add 2 MB for the data.
        let device = TempDevice::new(Bytes(18 * 1024 * 1024).sectors()).unwrap();
        let temp_dir = tempdir().unwrap();
        let previous_key_path = temp_dir.path().join("previous_key");
        let generated_key_path = temp_dir.path().join("generated_key");
        let guestos_config = Self::create_guestos_config(enable_trusted_execution_environment);
        let sev_firmware_builder =
            MockSevGuestFirmwareBuilder::new().with_derived_key(Some([0; 32]));

        Self {
            device,
            previous_key_path,
            generated_key_path,
            sev_firmware_builder,
            guestos_config,
            _temp_dir: temp_dir,
            _guard: guard,
        }
    }

    fn enable_sev(&mut self) {
        self.guestos_config = Self::create_guestos_config(true);
    }

    #[allow(dead_code)]
    fn disable_sev(&mut self) {
        self.guestos_config = Self::create_guestos_config(false);
    }

    fn create_guestos_config(enable_trusted_execution_environment: bool) -> GuestOSConfig {
        GuestOSConfig {
            icos_settings: ICOSSettings {
                enable_trusted_execution_environment,
                ..Default::default()
            },
            ..GuestOSConfig::default()
        }
    }

    fn run(&mut self, args: Args) -> Result<()> {
        run(
            args,
            &self.guestos_config,
            self.guestos_config
                .icos_settings
                .enable_trusted_execution_environment,
            || Ok(Box::new(self.sev_firmware_builder.clone())),
            &self.previous_key_path,
            &self.generated_key_path,
        )
    }

    fn format(&mut self, partition: Partition) -> Result<()> {
        self.run(Args::CryptFormat {
            partition,
            device_path: self.device.path().unwrap(),
        })
    }

    fn open(&mut self, partition: Partition) -> Result<()> {
        self.run(Args::CryptOpen {
            partition,
            device_path: self.device.path().unwrap(),
        })
    }
}

fn assert_device_has_content(encrypted_device_path: &Path, expected_content: &[u8]) {
    assert!(encrypted_device_path.exists());

    let mut contents = vec![0; expected_content.len()];
    File::open(encrypted_device_path)
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

fn deactive_crypt_device_with_check(crypt_device_name: &str) {
    let _ignore = deactivate_crypt_device(crypt_device_name);
    assert!(!Path::new(&format!("/dev/mapper/{crypt_device_name}")).exists());
}

fn get_crypt_device(partition: Partition) -> &'static Path {
    match partition {
        Partition::Store => Path::new("/dev/mapper/vda10-crypt"),
        Partition::Var => Path::new("/dev/mapper/var_crypt"),
    }
}

fn cleanup() {
    for partition in [Partition::Store, Partition::Var] {
        deactive_crypt_device_with_check(crypt_name(partition));
    }
}

#[test]
fn test_generated_key_init_and_reopen() {
    for partition in [Partition::Store, Partition::Var] {
        let mut fixture = TestFixture::new(false);
        let device_path = get_crypt_device(partition);

        // Test format & open
        fixture
            .format(partition)
            .expect("Failed to format device encryption with generated key");
        fixture
            .open(partition)
            .expect("Failed to open device encryption with generated key");

        assert!(device_path.exists());
        fs::write(device_path, "test_data")
            .expect("Failed to write test data to encrypted partition");

        // Test reopening
        deactive_crypt_device_with_check(crypt_name(partition));
        fixture
            .open(partition)
            .expect("Failed to reopen partition with generated key");

        assert_device_has_content(device_path, b"test_data");
        assert!(fixture.generated_key_path.exists());
        assert_eq!(fs::read(&fixture.generated_key_path).unwrap().len(), 16);
        assert_eq!(
            fixture.generated_key_path.metadata().unwrap().permissions(),
            // Type file, readable and writable by owner only
            Permissions::from_mode(0o100600)
        );
    }
}

#[test]
fn test_does_not_change_existing_generated_key() {
    let mut fixture = TestFixture::new(false);
    fs::write(&fixture.generated_key_path, "existing_key")
        .expect("Failed to write existing key for testing");
    fixture.format(Partition::Var).unwrap();
    fixture.open(Partition::Var).unwrap();
    assert_eq!(
        fs::read_to_string(&fixture.generated_key_path).unwrap(),
        "existing_key"
    );
}

#[test]
fn test_sev_key_init_and_reopen() {
    for partition in [Partition::Store, Partition::Var] {
        let mut fixture = TestFixture::new(true);
        let crypt_device_path = get_crypt_device(partition);

        assert!(!crypt_device_path.exists());

        // Test format & open
        fixture
            .format(partition)
            .expect("Failed to format device encryption with generated key");
        fixture
            .open(partition)
            .expect("Failed to open device encryption with generated key");

        assert!(crypt_device_path.exists());
        assert!(!fixture.generated_key_path.exists());

        fs::write(crypt_device_path, "test_data")
            .expect("Failed to write test data to encrypted partition");

        // Test reopening
        deactive_crypt_device_with_check(crypt_name(partition));
        fixture
            .open(partition)
            .expect("Failed to reopen partition with SEV key");

        assert_device_has_content(crypt_device_path, b"test_data");
    }
}

#[test]
fn test_fail_to_open_if_device_is_not_formatted() {
    let mut fixture = TestFixture::new(false);

    fixture
        .open(Partition::Store)
        .expect_err("Expected setup_disk_encryption to fail due to unformatted device");

    assert!(!Path::new("/dev/mapper/vda10-crypt").exists());
}

#[test]
fn test_sev_unlock_store_partition_with_previous_key() {
    const PREVIOUS_KEY: &[u8] = b"previous key";
    const DEPRECATED_KEY: &[u8] = b"deprecated key";

    let mut fixture = TestFixture::new(true);

    fs::write(&fixture.previous_key_path, "previous key")
        .expect("Failed to write previous key for testing");

    // Let's assume the store partition is already encrypted with a previous key
    let mut device = format_crypt_device(&fixture.device.path().unwrap(), PREVIOUS_KEY).unwrap();
    // Let's also assume that an old deprecated key had been added to the device which will be
    // removed (only the previous key and the new SEV key should remain).
    device
        .keyslot_handle()
        .add_by_passphrase(None, b"previous key", b"deprecated key")
        .expect("Failed to add deprecated key slot");

    // Write some data to the disk.
    activate_crypt_device(
        &fixture.device.path().unwrap(),
        "vda10-crypt",
        PREVIOUS_KEY,
        CryptActivate::empty(),
    )
    .expect("Failed to activate device");
    fs::write("/dev/mapper/vda10-crypt", "hello world").unwrap();
    deactive_crypt_device_with_check("vda10-crypt");

    check_encryption_key(&fixture.device.path().unwrap(), PREVIOUS_KEY)
        .expect("previous key should unlock the store partition");

    check_encryption_key(&fixture.device.path().unwrap(), DEPRECATED_KEY)
        .expect("deprecated key should unlock the store partition");

    // This is where the real testing starts. We open the disk with open() - in production, this
    // would happen during an upgrade.
    fixture.open(Partition::Store).unwrap();

    // Check that previous content is still there.
    assert_device_has_content(Path::new("/dev/mapper/vda10-crypt"), b"hello world");

    // Check that the previous key file has been deleted.
    assert!(!fixture.previous_key_path.exists());

    // Check that the SEV key unlocks the device, the previous key unlocks the device, and the
    // deprecated key is removed.
    check_encryption_key(&fixture.device.path().unwrap(), PREVIOUS_KEY)
        .expect("previous key should unlock the store partition");

    let sev_key = derive_key_from_sev_measurement(
        &mut fixture.sev_firmware_builder.build(),
        Key::DiskEncryptionKey {
            device_path: &fixture.device.path().unwrap(),
        },
    )
    .unwrap();

    check_encryption_key(&fixture.device.path().unwrap(), sev_key.as_bytes())
        .expect("SEV key should unlock the store partition");

    check_encryption_key(&fixture.device.path().unwrap(), DEPRECATED_KEY)
        .expect_err("deprecated key should not unlock the store partition");
}

#[test]
fn test_sev_unlock_store_with_current_key_if_previous_key_does_not_work() {
    let mut fixture = TestFixture::new(true);

    fs::write(&fixture.previous_key_path, "previous key")
        .expect("Failed to write previous key for testing");

    // The store partition is encrypted with the current SEV key but not with the previous key.
    format_crypt_device(
        &fixture.device.path().unwrap(),
        derive_key_from_sev_measurement(
            &mut fixture.sev_firmware_builder,
            Key::DiskEncryptionKey {
                device_path: &fixture.device.path().unwrap(),
            },
        )
        .unwrap()
        .as_bytes(),
    )
    .unwrap();

    // Opening it should succeed
    fixture
        .open(Partition::Store)
        .expect("Failed to open store partition");
}

#[test]
fn test_fails_to_open_var_if_key_doesnt_work() {
    let mut fixture = TestFixture::new(false);

    fixture.format(Partition::Var).unwrap();
    fixture.open(Partition::Var).unwrap();
    fs::write("/dev/mapper/var_crypt", "some data").unwrap();

    deactive_crypt_device_with_check("var_crypt");

    // Overwrite the key
    fs::write(&fixture.generated_key_path, "wrong key").unwrap();

    fixture
        .open(Partition::Var)
        .expect_err("Expected setup_disk_encryption to fail due to wrong key");
}

// This test checks that we can open the store partition multiple times with different keys.
// This simulates multiple upgrades after each other.
#[test]
fn test_open_store_multiple_times_with_different_keys() {
    let mut fixture = TestFixture::new(true);
    fixture.format(Partition::Store).unwrap();
    fs::write(
        &fixture.previous_key_path,
        derive_key_from_sev_measurement(
            &mut fixture.sev_firmware_builder,
            Key::DiskEncryptionKey {
                device_path: &fixture.device.path().unwrap(),
            },
        )
        .unwrap(),
    )
    .unwrap();

    for i in 0..5 {
        // Simulate saving the previous key during upgrade.
        fs::write(
            &fixture.previous_key_path,
            derive_key_from_sev_measurement(
                &mut fixture.sev_firmware_builder,
                Key::DiskEncryptionKey {
                    device_path: &fixture.device.path().unwrap(),
                },
            )
            .unwrap(),
        )
        .unwrap();

        // After an upgrade, the firmware derives a new key.
        fixture.sev_firmware_builder = fixture.sev_firmware_builder.with_derived_key(Some([i; 32]));

        fixture
            .open(Partition::Store)
            .unwrap_or_else(|_| panic!("Failed to open store partition on iteration {i}"));
        assert!(Path::new("/dev/mapper/vda10-crypt").exists());
        deactive_crypt_device_with_check("vda10-crypt");
    }
}

#[test]
fn test_can_open_store_with_previous_key() {
    let fixture = TestFixture::new(true);

    // Prepare device encrypted with a previous key and write previous key file
    const PREVIOUS_KEY: &[u8] = b"previous key";
    fs::write(&fixture.previous_key_path, PREVIOUS_KEY).expect("Failed to write previous key");

    // Format device with previous key
    format_crypt_device(&fixture.device.path().unwrap(), PREVIOUS_KEY).unwrap();

    // can_open_store should return true because previous key unlocks the device
    let mut sev_fw = fixture.sev_firmware_builder.build();
    let result = can_open_store(
        &fixture.device.path().unwrap(),
        &fixture.previous_key_path,
        &mut sev_fw,
    )
    .expect("can_open_store returned error");
    assert!(
        result,
        "Expected can_open_store to return true when previous key works"
    );
}

#[test]
fn test_can_open_store_with_derived_key_when_previous_key_fails() {
    let fixture = TestFixture::new(true);

    // Write a previous key that does NOT unlock the device
    fs::write(&fixture.previous_key_path, b"wrong previous key")
        .expect("Failed to write previous key");

    // Format the device with the current SEV derived key
    let sev_key = derive_key_from_sev_measurement(
        &mut fixture.sev_firmware_builder.build(),
        Key::DiskEncryptionKey {
            device_path: &fixture.device.path().unwrap(),
        },
    )
    .unwrap();

    format_crypt_device(&fixture.device.path().unwrap(), sev_key.as_bytes()).unwrap();

    // can_open_store should return true because the derived SEV key can open it
    let mut sev_fw = fixture.sev_firmware_builder.build();
    let result = can_open_store(
        &fixture.device.path().unwrap(),
        &fixture.previous_key_path,
        &mut sev_fw,
    )
    .expect("can_open_store returned error");
    assert!(
        result,
        "Expected can_open_store to return true when derived SEV key works"
    );
}

#[test]
fn test_cannot_open_store_when_no_key_works() {
    let fixture = TestFixture::new(true);

    // No previous key file and device is unformatted -> should return false
    // Ensure previous key file does not exist
    let _ = fs::remove_file(&fixture.previous_key_path);

    // Create an unformatted device (no LUKS header)
    // can_open_store should return false
    let mut sev_fw = fixture.sev_firmware_builder.build();
    let result = can_open_store(
        &fixture.device.path().unwrap(),
        &fixture.previous_key_path,
        &mut sev_fw,
    )
    .expect("can_open_store returned error");
    assert!(
        !result,
        "Expected can_open_store to return false when no key can open the device"
    );
}

#[test]
fn test_cannot_open_with_generated_key_if_sev_is_enabled() {
    for partition in [Partition::Store, Partition::Var] {
        let mut fixture = TestFixture::new(false);
        fixture.format(partition).unwrap();
        fixture.open(partition).unwrap();
        fixture.enable_sev();
        fixture
            .open(partition)
            .expect_err("opening with generated key should fail when SEV is enabled");
    }
}
