use crate::{Args, Partition, crypt_name, metrics_file_path, run};
use anyhow::{Result, anyhow};
use config_types::{GuestOSConfig, GuestVMType, ICOSSettings};
use guest_disk::crypt::{
    KeyslotMetadata, LuksHeaderLocation, SevMetadata, activate_crypt_device,
    backup_luks_header_to_file, check_encryption_key, deactivate_crypt_device, format_crypt_device,
    open_luks2_device, read_keyslot_metadata, remove_assigned_tokens, write_keyslot_metadata,
};
use guest_disk::sev::{SevDiskEncryption, can_open_store};
use ic_device::device_mapping::{Bytes, TempDevice};
use ic_os_logging::init_logging;
use itertools::Either::Right;
use libcryptsetup_rs::consts::flags::{CryptActivate, CryptVolumeKey};
use libcryptsetup_rs::consts::vals::{CryptKdf, EncryptionFormat, KeyslotInfo};
use libcryptsetup_rs::{
    CryptDevice, CryptInit, CryptParamsLuks2Ref, CryptSettingsHandle, TokenInput,
};
use prometheus::Registry;
use serde_json::json;
use sev::Generation;
use sev::firmware::host::TcbVersion;
use sev::parser::ByteParser;
use sev_guest::key_deriver::{Key, derive_key_from_sev_measurement};
use sev_guest_testing::MockSevGuestFirmwareBuilder;
use std::fs;
use std::fs::{File, OpenOptions, Permissions};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::{TempDir, tempdir};

// All tests interact with the same device mapper and use shared crypt device names, so we must run
// the tests sequentially.
static TEST_MUTEX: parking_lot::Mutex<()> = parking_lot::const_mutex(());

const TEST_VOLUME_KEY_BYTES: usize = 512 / 8;
const TEST_PBKDF_ITERATIONS: u32 = 1000;

struct TestFixture<'a> {
    device: TempDevice,
    previous_key_path: PathBuf,
    store_luks_header_path: PathBuf,
    generated_key_path: PathBuf,
    sev_firmware_builder: MockSevGuestFirmwareBuilder,
    guestos_config: GuestOSConfig,
    _temp_dir: TempDir,
    _guard: parking_lot::MutexGuard<'a, ()>,
    metrics_dir: PathBuf,
}

impl<'a> TestFixture<'a> {
    fn new(enable_trusted_execution_environment: bool) -> Self {
        let guard = TEST_MUTEX.lock();
        cleanup();
        // LUKS2 needs 16 MB of space for the metadata, let's add 2 MB for the data.
        let device = TempDevice::new(Bytes(18 * 1024 * 1024).sectors()).unwrap();
        let temp_dir = tempdir().unwrap();
        let previous_key_path = temp_dir.path().join("previous_key");
        let store_luks_header_path = temp_dir.path().join("store.header");
        let generated_key_path = temp_dir.path().join("generated_key");
        let guestos_config = Self::create_guestos_config(enable_trusted_execution_environment);
        let sev_firmware_builder = MockSevGuestFirmwareBuilder::new()
            .with_derived_key(Some([0; 32]))
            .with_launch_tcb(Self::default_launch_tcb());
        let metrics_dir = temp_dir.path().to_path_buf();

        Self {
            device,
            previous_key_path,
            store_luks_header_path,
            generated_key_path,
            sev_firmware_builder,
            guestos_config,
            _temp_dir: temp_dir,
            _guard: guard,
            metrics_dir,
        }
    }

    fn default_launch_tcb() -> TcbVersion {
        TcbVersion::new(None, 1, 2, 3, 4)
    }

    fn default_launch_tcb_as_u64() -> u64 {
        u64::from_le_bytes(
            Self::default_launch_tcb()
                .to_bytes_with(Generation::Milan)
                .unwrap(),
        )
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
            &self.store_luks_header_path,
            &self.generated_key_path,
            &self.metrics_dir,
        )
    }

    fn metrics_file(&self, partition: Partition) -> PathBuf {
        metrics_file_path(&self.metrics_dir, partition)
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

    fn can_open_store(&self) -> Result<bool> {
        let mut sev_fw = self.sev_firmware_builder.build();
        can_open_store(
            &self.device.path().unwrap(),
            &self.previous_key_path,
            &self.store_luks_header_path,
            &mut sev_fw,
        )
    }

    fn header_location(&self, partition: Partition) -> LuksHeaderLocation<'_> {
        match partition {
            Partition::Store => LuksHeaderLocation::Detached(&self.store_luks_header_path),
            Partition::Var => LuksHeaderLocation::Attached,
        }
    }

    fn open_crypt_device(&self, partition: Partition) -> CryptDevice {
        open_luks2_device(
            &self.device.path().unwrap(),
            self.header_location(partition),
            false,
        )
        .unwrap()
    }

    fn read_keyslot_metadata(&self, partition: Partition) -> Vec<KeyslotMetadata> {
        let mut crypt_device = self.open_crypt_device(partition);
        read_keyslot_metadata(&mut crypt_device).unwrap()
    }

    fn has_attached_luks2_header(&self) -> bool {
        open_luks2_device(
            &self.device.path().unwrap(),
            LuksHeaderLocation::Attached,
            false,
        )
        .is_ok()
    }

    fn has_detached_luks2_header(&self) -> bool {
        open_luks2_device(
            &self.device.path().unwrap(),
            LuksHeaderLocation::Detached(&self.store_luks_header_path),
            false,
        )
        .is_ok()
    }

    fn assert_no_detached_store_header(&self) {
        assert!(!self.store_luks_header_path.exists());
        assert!(!self.has_detached_luks2_header());
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
        Partition::Store => Path::new("/dev/mapper/store-crypt"),
        Partition::Var => Path::new("/dev/mapper/var_crypt"),
    }
}

fn create_crypt_device_luks_parameters(
    device_path: &Path,
    passphrase: &[u8],
    cipher: &str,
    cipher_mode: &str,
    volume_key_size: usize,
    pbkdf_type: CryptKdf,
    pbkdf_iterations: u32,
) {
    let mut crypt_device = CryptInit::init(device_path).unwrap();

    let mut pbkdf_params = CryptSettingsHandle::get_pbkdf_type_params(&pbkdf_type).unwrap();
    pbkdf_params.iterations = pbkdf_iterations;
    crypt_device
        .settings_handle()
        .set_pbkdf_type(&pbkdf_params)
        .unwrap();

    crypt_device
        .context_handle()
        .format::<CryptParamsLuks2Ref>(
            EncryptionFormat::Luks2,
            (cipher, cipher_mode),
            None,
            Right(volume_key_size),
            None,
        )
        .unwrap();

    crypt_device
        .keyslot_handle()
        .add_by_key(None, None, passphrase, CryptVolumeKey::empty())
        .unwrap();
}

fn cleanup() {
    for partition in [Partition::Store, Partition::Var] {
        deactive_crypt_device_with_check(crypt_name(partition));
    }
}

fn corrupt_attached_luks_header(device_path: &Path) {
    // The test device size reserves 16 MiB for LUKS2 metadata and 2 MiB for payload.
    let mut device = OpenOptions::new().write(true).open(device_path).unwrap();
    device.write_all(&vec![0_u8; 16 * 1024 * 1024]).unwrap();
}

fn add_raw_metadata_token(crypt_device: &mut CryptDevice, token: serde_json::Value) {
    crypt_device
        .token_handle()
        .json_set(TokenInput::AddToken(&token))
        .unwrap();
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
        if partition == Partition::Store {
            assert!(!fixture.store_luks_header_path.exists());
        }
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
        let device_path = fixture.device.path().unwrap();
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

        let tcb_after_format = {
            let mut cd =
                open_luks2_device(&device_path, fixture.header_location(partition), false).unwrap();
            read_keyslot_metadata(&mut cd).unwrap()[0]
                .sev_metadata
                .tcb_version
        };

        // Test reopening
        deactive_crypt_device_with_check(crypt_name(partition));
        fixture
            .open(partition)
            .expect("Failed to reopen partition with SEV key");

        assert_device_has_content(crypt_device_path, b"test_data");

        let tcb_after_reopen = {
            let mut cd =
                open_luks2_device(&device_path, fixture.header_location(partition), false).unwrap();
            read_keyslot_metadata(&mut cd).unwrap()[0]
                .sev_metadata
                .tcb_version
        };
        assert_eq!(
            tcb_after_reopen, tcb_after_format,
            "token TCB must not change when firmware is unchanged"
        );

        if partition == Partition::Store {
            assert!(fixture.store_luks_header_path.exists());
            assert!(fixture.has_detached_luks2_header());
            // The store partition is formatted with a detached header only; no attached
            // LUKS header should be present on the data device.
            assert!(!fixture.has_attached_luks2_header());
        }
    }
}

#[test]
fn test_detached_header_is_only_used_for_store_when_sev_is_enabled() {
    // When the store partition uses a detached header, there must not be an attached
    // LUKS header on the data device. The var partition always uses an attached header.
    for (enable_sev, partition, expect_detached_header, expect_attached_header) in [
        (false, Partition::Store, false, true),
        (true, Partition::Store, true, false),
        (true, Partition::Var, false, true),
    ] {
        let mut fixture = TestFixture::new(enable_sev);

        fixture
            .format(partition)
            .expect("Failed to format encrypted partition");
        fixture
            .open(partition)
            .expect("Failed to open encrypted partition");

        assert_eq!(
            fixture.store_luks_header_path.exists(),
            expect_detached_header,
            "unexpected detached header state for {:?} with SEV enabled = {}",
            partition,
            enable_sev
        );

        assert_eq!(
            fixture.has_detached_luks2_header(),
            expect_detached_header,
            "unexpected detached LUKS header state for {:?} with SEV enabled = {}",
            partition,
            enable_sev
        );

        assert_eq!(
            fixture.has_attached_luks2_header(),
            expect_attached_header,
            "unexpected attached LUKS header state for {:?} with SEV enabled = {}",
            partition,
            enable_sev
        );
    }
}

#[test]
fn test_fail_to_open_if_device_is_not_formatted() {
    let mut fixture = TestFixture::new(false);

    fixture
        .open(Partition::Store)
        .expect_err("Expected setup_disk_encryption to fail due to unformatted device");

    assert!(!Path::new("/dev/mapper/store-crypt").exists());
}

#[test]
fn test_format_store_refuses_existing_detached_header() {
    let temp_dir = tempdir().unwrap();
    let store_luks_header_path = temp_dir.path().join("store.header");

    fs::write(&store_luks_header_path, b"stale header")
        .expect("Failed to write stale detached Store header");

    let mut encryption = SevDiskEncryption {
        sev_firmware: Box::new(MockSevGuestFirmwareBuilder::new()),
        previous_key_path: temp_dir.path().join("previous_key"),
        store_luks_header_path: store_luks_header_path.clone(),
        guest_vm_type: GuestVMType::Default,
        metrics_registry: Registry::new(),
    };

    let err = guest_disk::DiskEncryption::format(
        &mut encryption,
        &temp_dir.path().join("dummy_device"),
        Partition::Store,
    )
    .expect_err("formatting Store should fail when a detached header already exists");

    assert!(
        format!("{err:#}").contains("Refusing to format Store because detached LUKS header"),
        "Unexpected error: {err:#}"
    );
    assert_eq!(
        fs::read(&store_luks_header_path).unwrap(),
        b"stale header",
        "existing detached Store header should be left untouched"
    );
}

#[test]
fn test_sev_unlock_store_partition_with_previous_key() {
    const PREVIOUS_KEY: &[u8] = b"previous key";
    const DEPRECATED_KEY: &[u8] = b"deprecated key";

    let mut fixture = TestFixture::new(true);

    fs::write(&fixture.previous_key_path, "previous key")
        .expect("Failed to write previous key for testing");

    // Let's assume the store partition is already encrypted with a previous key
    let (mut device, _keyslot) = format_crypt_device(
        &fixture.device.path().unwrap(),
        LuksHeaderLocation::Attached,
        PREVIOUS_KEY,
    )
    .unwrap();

    backup_luks_header_to_file(
        &fixture.device.path().unwrap(),
        &fixture.store_luks_header_path,
    )
    .expect("Failed to simulate upgrade-protocol detached Store header backup");

    // Let's also assume that an old deprecated key had been added to the device which will be
    // removed (only the previous key and the new SEV key should remain).
    device
        .keyslot_handle()
        .add_by_passphrase(None, b"previous key", b"deprecated key")
        .expect("Failed to add deprecated key slot");

    drop(device);

    // Write some data to the disk.
    activate_crypt_device(
        &fixture.device.path().unwrap(),
        LuksHeaderLocation::Attached,
        "store-crypt",
        PREVIOUS_KEY,
        CryptActivate::empty(),
        false,
        None,
    )
    .expect("Failed to activate device");
    fs::write("/dev/mapper/store-crypt", "hello world").unwrap();

    deactive_crypt_device_with_check("store-crypt");
    backup_luks_header_to_file(
        &fixture.device.path().unwrap(),
        &fixture.store_luks_header_path,
    )
    .expect("Failed to simulate upgrade-protocol detached Store header backup");

    check_encryption_key(
        &fixture.device.path().unwrap(),
        LuksHeaderLocation::Attached,
        PREVIOUS_KEY,
    )
    .expect("previous key should unlock the store partition");

    check_encryption_key(
        &fixture.device.path().unwrap(),
        LuksHeaderLocation::Attached,
        DEPRECATED_KEY,
    )
    .expect("deprecated key should unlock the store partition");

    // This is where the real testing starts. We open the disk with open() - in production, this
    // would happen during an upgrade.
    fixture.open(Partition::Store).unwrap();

    // Check that previous content is still there.
    assert_device_has_content(Path::new("/dev/mapper/store-crypt"), b"hello world");
    assert!(fixture.store_luks_header_path.exists());
    assert!(fixture.has_detached_luks2_header());

    // Check that the previous key file has been deleted.
    assert!(!fixture.previous_key_path.exists());

    // Check that the SEV key unlocks the device, the previous key is removed from the
    // detached header, and the deprecated key is removed.
    check_encryption_key(
        &fixture.device.path().unwrap(),
        LuksHeaderLocation::Detached(&fixture.store_luks_header_path),
        PREVIOUS_KEY,
    )
    .expect_err("previous key should no longer unlock the detached Store header");

    // The attached header is wiped during open() when a detached header is available.
    check_encryption_key(
        &fixture.device.path().unwrap(),
        LuksHeaderLocation::Attached,
        PREVIOUS_KEY,
    )
    .expect_err("attached Store header should have been wiped during open()");

    let sev_key = derive_key_from_sev_measurement(
        &mut fixture.sev_firmware_builder.build(),
        Key::DiskEncryptionKey {
            device_path: &fixture.device.path().unwrap(),
        },
        TestFixture::default_launch_tcb_as_u64(),
    )
    .unwrap();

    check_encryption_key(
        &fixture.device.path().unwrap(),
        LuksHeaderLocation::Detached(&fixture.store_luks_header_path),
        sev_key.as_bytes(),
    )
    .expect("SEV key should unlock the store partition");

    // The attached header has been wiped, so no key should unlock it.
    check_encryption_key(
        &fixture.device.path().unwrap(),
        LuksHeaderLocation::Attached,
        sev_key.as_bytes(),
    )
    .expect_err("attached Store header should have been wiped during open()");

    check_encryption_key(
        &fixture.device.path().unwrap(),
        LuksHeaderLocation::Detached(&fixture.store_luks_header_path),
        DEPRECATED_KEY,
    )
    .expect_err("deprecated key should not unlock the store partition");

    let mut device = open_luks2_device(
        &fixture.device.path().unwrap(),
        LuksHeaderLocation::Detached(&fixture.store_luks_header_path),
        false,
    )
    .expect("Failed to open detached Store header");
    let mut keyslot_handle = device.keyslot_handle();

    // Test the all keys have correct params
    let mut active_keyslot_count = 0;
    for key_slot in 0..32 {
        if matches!(
            keyslot_handle
                .status(key_slot)
                .expect("Failed to get keyslot status"),
            KeyslotInfo::Active | KeyslotInfo::ActiveLast
        ) {
            active_keyslot_count += 1;
            let pbkdf = keyslot_handle
                .get_pbkdf(key_slot)
                .expect("Failed to get PBKDF params for active keyslot");
            assert_eq!(pbkdf.type_, CryptKdf::Pbkdf2);
            assert_eq!(pbkdf.iterations, TEST_PBKDF_ITERATIONS);
        }
    }
    assert_eq!(active_keyslot_count, 1);
}

#[test]
fn test_sev_upgrade_vm_keeps_previous_key_file() {
    const PREVIOUS_KEY: &[u8] = b"previous key";

    let mut fixture = TestFixture::new(true);
    fixture.guestos_config.guest_vm_type = GuestVMType::Upgrade;

    fs::write(&fixture.previous_key_path, PREVIOUS_KEY)
        .expect("Failed to write previous key for testing");

    format_crypt_device(
        &fixture.device.path().unwrap(),
        LuksHeaderLocation::Attached,
        PREVIOUS_KEY,
    )
    .unwrap();

    backup_luks_header_to_file(
        &fixture.device.path().unwrap(),
        &fixture.store_luks_header_path,
    )
    .expect("Failed to back up detached Store header");

    fixture
        .open(Partition::Store)
        .expect("opening Store with previous key should succeed during upgrade");

    assert!(
        fixture.previous_key_path.exists(),
        "Upgrade Guest VM should preserve previous key file"
    );
    assert_eq!(
        fs::read(&fixture.previous_key_path).unwrap(),
        PREVIOUS_KEY,
        "Upgrade Guest VM should keep the previous key file contents unchanged"
    );
}

#[test]
fn test_guestos_upgrade_migrates_store_without_existing_sev_metadata() {
    const PREVIOUS_KEY: &[u8] = b"previous key";
    const PAYLOAD: &[u8] = b"migration without sevmetadata";

    let mut fixture = TestFixture::new(true);

    fs::write(&fixture.previous_key_path, PREVIOUS_KEY)
        .expect("Failed to write previous key for testing");

    format_crypt_device(
        &fixture.device.path().unwrap(),
        LuksHeaderLocation::Attached,
        PREVIOUS_KEY,
    )
    .unwrap();

    backup_luks_header_to_file(
        &fixture.device.path().unwrap(),
        &fixture.store_luks_header_path,
    )
    .expect("Failed to simulate upgrade-protocol detached Store header backup");

    let pre_migration_metadata = fixture.read_keyslot_metadata(Partition::Store);
    assert!(
        pre_migration_metadata.is_empty(),
        "pre-migration Store should have no SEV metadata tokens"
    );

    activate_crypt_device(
        &fixture.device.path().unwrap(),
        LuksHeaderLocation::Attached,
        "store-crypt",
        PREVIOUS_KEY,
        CryptActivate::empty(),
        false,
        None,
    )
    .expect("Failed to activate Store with previous key");
    fs::write("/dev/mapper/store-crypt", PAYLOAD).unwrap();
    deactive_crypt_device_with_check("store-crypt");

    backup_luks_header_to_file(
        &fixture.device.path().unwrap(),
        &fixture.store_luks_header_path,
    )
    .expect("Failed to refresh detached Store header backup");

    fixture
        .open(Partition::Store)
        .expect("GuestOS upgrade migration without sevmetadata should succeed");

    assert_device_has_content(Path::new("/dev/mapper/store-crypt"), PAYLOAD);
    assert!(!fixture.previous_key_path.exists());

    let metadata = fixture.read_keyslot_metadata(Partition::Store);
    assert_eq!(
        metadata.len(),
        1,
        "only the new SEV keyslot should have metadata"
    );
    assert_eq!(
        metadata[0].sev_metadata.tcb_version,
        TestFixture::default_launch_tcb_as_u64()
    );

    let sev_key = derive_key_from_sev_measurement(
        &mut fixture.sev_firmware_builder.build(),
        Key::DiskEncryptionKey {
            device_path: &fixture.device.path().unwrap(),
        },
        TestFixture::default_launch_tcb_as_u64(),
    )
    .unwrap();

    check_encryption_key(
        &fixture.device.path().unwrap(),
        LuksHeaderLocation::Detached(&fixture.store_luks_header_path),
        PREVIOUS_KEY,
    )
    .expect_err("previous key should no longer unlock the detached Store header after migration");
    check_encryption_key(
        &fixture.device.path().unwrap(),
        LuksHeaderLocation::Detached(&fixture.store_luks_header_path),
        sev_key.as_bytes(),
    )
    .expect("new SEV key should unlock the detached Store header after migration");
}

#[test]
fn test_sev_unlock_store_with_current_key_if_previous_key_does_not_work() {
    let mut fixture = TestFixture::new(true);

    fs::write(&fixture.previous_key_path, "previous key")
        .expect("Failed to write previous key for testing");

    // The store partition is encrypted with the current SEV key but not with the previous key.
    let (mut crypt_device, keyslot) = format_crypt_device(
        &fixture.device.path().unwrap(),
        LuksHeaderLocation::Attached,
        derive_key_from_sev_measurement(
            &mut fixture.sev_firmware_builder,
            Key::DiskEncryptionKey {
                device_path: &fixture.device.path().unwrap(),
            },
            TestFixture::default_launch_tcb_as_u64(),
        )
        .unwrap()
        .as_bytes(),
    )
    .unwrap();

    write_keyslot_metadata(
        &mut crypt_device,
        &KeyslotMetadata::new_sev(
            keyslot,
            SevMetadata {
                launch_measurement_hex: hex::encode([42_u8; 48]),
                tcb_version: TestFixture::default_launch_tcb_as_u64(),
            },
        ),
    )
    .unwrap();

    backup_luks_header_to_file(
        &fixture.device.path().unwrap(),
        &fixture.store_luks_header_path,
    )
    .expect("Failed to simulate upgrade-protocol detached Store header backup");

    // Opening it should succeed
    fixture
        .open(Partition::Store)
        .expect("Failed to open store partition");
    assert!(fixture.has_detached_luks2_header());

    let mut device = fixture.open_crypt_device(Partition::Store);
    let mut keyslot_handle = device.keyslot_handle();
    let active_count = (0..32u32)
        .filter(|&k| {
            matches!(
                keyslot_handle.status(k).unwrap(),
                KeyslotInfo::Active | KeyslotInfo::ActiveLast
            )
        })
        .count();
    assert_eq!(active_count, 1);
}

#[test]
fn test_open_store_after_format_crypt_device_with_detached_header() {
    let mut fixture = TestFixture::new(true);

    let (mut crypt_device, keyslot) = format_crypt_device(
        &fixture.device.path().unwrap(),
        LuksHeaderLocation::Detached(&fixture.store_luks_header_path),
        derive_key_from_sev_measurement(
            &mut fixture.sev_firmware_builder,
            Key::DiskEncryptionKey {
                device_path: &fixture.device.path().unwrap(),
            },
            TestFixture::default_launch_tcb_as_u64(),
        )
        .unwrap()
        .as_bytes(),
    )
    .unwrap();

    write_keyslot_metadata(
        &mut crypt_device,
        &KeyslotMetadata::new_sev(
            keyslot,
            SevMetadata {
                launch_measurement_hex: hex::encode([42_u8; 48]),
                tcb_version: TestFixture::default_launch_tcb_as_u64(),
            },
        ),
    )
    .unwrap();

    assert!(fixture.has_detached_luks2_header());
    assert!(!fixture.has_attached_luks2_header());

    fixture
        .open(Partition::Store)
        .expect("opening Store should succeed after formatting with a detached header");

    assert!(Path::new("/dev/mapper/store-crypt").exists());
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
    init_logging();
    let mut fixture = TestFixture::new(true);
    fixture.format(Partition::Store).unwrap();
    corrupt_attached_luks_header(&fixture.device.path().unwrap());

    for i in 0..5 {
        // Simulate saving the previous key during upgrade.
        fs::write(
            &fixture.previous_key_path,
            derive_key_from_sev_measurement(
                &mut fixture.sev_firmware_builder,
                Key::DiskEncryptionKey {
                    device_path: &fixture.device.path().unwrap(),
                },
                TestFixture::default_launch_tcb_as_u64(),
            )
            .unwrap(),
        )
        .unwrap();

        // After an upgrade, the firmware derives a new key.
        fixture.sev_firmware_builder = fixture.sev_firmware_builder.with_derived_key(Some([i; 32]));

        fixture
            .open(Partition::Store)
            .unwrap_or_else(|e| panic!("Failed to open store partition on iteration {i}: {e:#}"));
        assert!(Path::new("/dev/mapper/store-crypt").exists());
        deactive_crypt_device_with_check("store-crypt");
    }

    // setup_store_with_previous_key now destroys the old keyslot, so only one token should
    // survive after the final iteration.
    let metadata = fixture.read_keyslot_metadata(Partition::Store);
    assert_eq!(metadata.len(), 1);
    assert_eq!(
        metadata[0].sev_metadata.tcb_version,
        TestFixture::default_launch_tcb_as_u64()
    );
}

#[test]
fn test_can_open_store_with_previous_key() {
    let fixture = TestFixture::new(true);

    // Prepare device encrypted with a previous key and write previous key file
    const PREVIOUS_KEY: &[u8] = b"previous key";
    fs::write(&fixture.previous_key_path, PREVIOUS_KEY).expect("Failed to write previous key");

    // Format device with previous key
    format_crypt_device(
        &fixture.device.path().unwrap(),
        LuksHeaderLocation::Detached(&fixture.store_luks_header_path),
        PREVIOUS_KEY,
    )
    .unwrap();

    // can_open_store should return true because previous key unlocks the device
    let result = fixture
        .can_open_store()
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
        TestFixture::default_launch_tcb_as_u64(),
    )
    .unwrap();

    let (mut crypt_device, keyslot) = format_crypt_device(
        &fixture.device.path().unwrap(),
        LuksHeaderLocation::Detached(&fixture.store_luks_header_path),
        sev_key.as_bytes(),
    )
    .unwrap();

    write_keyslot_metadata(
        &mut crypt_device,
        &KeyslotMetadata::new_sev(
            keyslot,
            SevMetadata {
                launch_measurement_hex: hex::encode([42_u8; 48]),
                tcb_version: TestFixture::default_launch_tcb_as_u64(),
            },
        ),
    )
    .unwrap();

    // can_open_store should return true because the derived SEV key can open it
    let result = fixture
        .can_open_store()
        .expect("can_open_store returned error");
    assert!(
        result,
        "Expected can_open_store to return true when derived SEV key works"
    );
}

#[test]
fn test_can_open_store_errors_when_all_tokens_are_malformed() {
    let mut fixture = TestFixture::new(true);
    fixture.format(Partition::Store).unwrap();

    let keyslot = fixture.read_keyslot_metadata(Partition::Store)[0]
        .keyslot()
        .unwrap();
    let mut crypt_device = fixture.open_crypt_device(Partition::Store);
    remove_assigned_tokens(&mut crypt_device, keyslot).unwrap();
    add_raw_metadata_token(
        &mut crypt_device,
        json!({
            "type": "ic-key-metadata",
            "keyslots": [],
            "sev_metadata": {
                "launch_measurement_hex": hex::encode([7_u8; 48]),
                "tcb_version": 123_u64,
            }
        }),
    );

    let err = fixture
        .can_open_store()
        .expect_err("all malformed metadata tokens should produce an error");

    assert!(
        format!("{err:#}").contains("All IC key-slot metadata tokens are malformed"),
        "Unexpected error: {err:#}"
    );
}

#[test]
fn test_can_open_store_ignores_malformed_tokens_when_a_valid_one_works() {
    let mut fixture = TestFixture::new(true);
    fixture.format(Partition::Store).unwrap();

    let mut crypt_device = fixture.open_crypt_device(Partition::Store);
    add_raw_metadata_token(
        &mut crypt_device,
        json!({
            "type": "ic-key-metadata",
            "keyslots": [],
            "sev_metadata": {
                "launch_measurement_hex": hex::encode([9_u8; 48]),
                "tcb_version": 456_u64,
            }
        }),
    );

    let result = fixture
        .can_open_store()
        .expect("a malformed token should be ignored when another valid token works");

    assert!(result);
}

#[test]
fn test_can_open_store_with_detached_header_after_attached_header_is_corrupted() {
    let mut fixture = TestFixture::new(true);

    fixture.format(Partition::Store).unwrap();
    // The store partition is formatted with a detached header only, so corrupting the area
    // where an attached header would be must not affect the result.
    corrupt_attached_luks_header(&fixture.device.path().unwrap());

    let result = fixture
        .can_open_store()
        .expect("can_open_store returned error");

    assert!(
        result,
        "Expected can_open_store to return true when the detached header works"
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
    let result = fixture
        .can_open_store()
        .expect("can_open_store returned error");
    assert!(
        !result,
        "Expected can_open_store to return false when no key can open the device"
    );
    fixture.assert_no_detached_store_header();
}

#[test]
fn test_format_store_populates_detached_header_and_sets_permissions() {
    let mut fixture = TestFixture::new(true);

    fixture.format(Partition::Store).unwrap();

    assert!(fixture.store_luks_header_path.exists());
    let metadata = fixture.store_luks_header_path.metadata().unwrap();
    assert_eq!(
        metadata.len(),
        16 * 1024 * 1024,
        "detached Store LUKS header should be 16 MiB"
    );
    assert_eq!(
        metadata.permissions().mode() & 0o777,
        0o644,
        "detached Store LUKS header should be world-readable and owner-writable"
    );
}

#[test]
fn test_open_store_succeeds_with_detached_header_after_attached_header_is_corrupted() {
    let mut fixture = TestFixture::new(true);

    fixture.format(Partition::Store).unwrap();

    assert!(fixture.store_luks_header_path.exists());
    // The store partition is formatted with a detached header only; there is no attached
    // LUKS header on the data device.
    assert!(!fixture.has_attached_luks2_header());

    // Corrupting the area on the data device where an attached header would have been must
    // not affect opening because only the detached header is used.
    corrupt_attached_luks_header(&fixture.device.path().unwrap());

    fixture
        .open(Partition::Store)
        .expect("opening Store should succeed with the detached header even if the attached header is corrupted");

    assert!(Path::new("/dev/mapper/store-crypt").exists());
}

/// Test that the attached LUKS header is NOT wiped when the detached header cannot be read by
/// libcryptsetup.
#[test]
fn test_open_store_keeps_attached_header_when_detached_header_is_corrupt() {
    const PREVIOUS_KEY: &[u8] = b"previous key";

    let mut fixture = TestFixture::new(true);

    fs::write(&fixture.previous_key_path, PREVIOUS_KEY)
        .expect("Failed to write previous key for testing");

    // Simulate a legacy device that has both an attached and a detached header.
    format_crypt_device(
        &fixture.device.path().unwrap(),
        LuksHeaderLocation::Attached,
        PREVIOUS_KEY,
    )
    .expect("Failed to format device with attached header");

    assert!(fixture.has_attached_luks2_header());

    // Corrupt the detached header so libcryptsetup can no longer read it.
    fs::write(&fixture.store_luks_header_path, b"not a valid LUKS header")
        .expect("Failed to corrupt detached header");

    // Opening the store must fail because the detached header is unreadable.
    fixture
        .open(Partition::Store)
        .expect_err("opening Store should fail when the detached header is corrupt");

    // Crucially, the attached header must still be present: the wipe guard must have refused
    // to wipe it because the detached header could not be verified.
    assert!(
        fixture.has_attached_luks2_header(),
        "attached LUKS header must not be wiped when the detached header is unreadable"
    );
}

/// Test that opening the store partition wipes a legacy attached LUKS header when a detached
/// header is available. This simulates upgrading from an older GuestOS that wrote both an
/// attached and a detached header.
#[test]
fn test_open_store_wipes_attached_header_when_detached_header_is_available() {
    const PREVIOUS_KEY: &[u8] = b"previous key";

    let mut fixture = TestFixture::new(true);

    fs::write(&fixture.previous_key_path, PREVIOUS_KEY)
        .expect("Failed to write previous key for testing");

    // Simulate a legacy device that has both an attached and a detached header.
    format_crypt_device(
        &fixture.device.path().unwrap(),
        LuksHeaderLocation::Attached,
        PREVIOUS_KEY,
    )
    .expect("Failed to format device with attached header");

    backup_luks_header_to_file(
        &fixture.device.path().unwrap(),
        &fixture.store_luks_header_path,
    )
    .expect("Failed to create detached header backup");

    // Both headers should be present before opening.
    assert!(fixture.has_attached_luks2_header());
    assert!(fixture.has_detached_luks2_header());

    // Opening the store should wipe the attached header.
    fixture
        .open(Partition::Store)
        .expect("opening Store should succeed");

    // The attached header should now be gone.
    assert!(
        !fixture.has_attached_luks2_header(),
        "attached LUKS header should have been wiped during open()"
    );
    // The detached header must still be present and valid.
    assert!(
        fixture.has_detached_luks2_header(),
        "detached LUKS header should still be present after open()"
    );
    assert!(fixture.store_luks_header_path.exists());

    deactive_crypt_device_with_check("store-crypt");

    // Opening again should still succeed (using only the detached header).
    fixture
        .open(Partition::Store)
        .expect("opening Store should succeed again after attached header wipe");

    assert!(Path::new("/dev/mapper/store-crypt").exists());
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

#[test]
fn test_sev_firmware_upgrade_rotates_keyslot_metadata() {
    for partition in [Partition::Store, Partition::Var] {
        let mut fixture = TestFixture::new(true);
        let device_path = fixture.device.path().unwrap().to_path_buf();
        let crypt_device_path = get_crypt_device(partition);

        let initial_tcb = TcbVersion::new(None, 1, 0, 0, 0);
        let initial_tcb_u64 =
            u64::from_le_bytes(initial_tcb.to_bytes_with(Generation::Milan).unwrap());
        fixture.sev_firmware_builder = MockSevGuestFirmwareBuilder::new()
            .with_derived_key(Some([1; 32]))
            .with_launch_tcb(initial_tcb);
        fixture.format(partition).unwrap();

        let initial_stored_tcb = {
            let mut cd =
                open_luks2_device(&device_path, fixture.header_location(partition), false).unwrap();
            read_keyslot_metadata(&mut cd).unwrap()[0]
                .sev_metadata
                .tcb_version
        };
        assert_eq!(initial_stored_tcb, initial_tcb_u64);

        fixture.open(partition).unwrap();
        fs::write(crypt_device_path, "data before upgrade").unwrap();
        deactive_crypt_device_with_check(crypt_name(partition));

        let upgraded_tcb = TcbVersion::new(None, 2, 0, 0, 0);
        fixture.sev_firmware_builder = MockSevGuestFirmwareBuilder::new()
            .with_derived_key(Some([1; 32]))
            .with_launch_tcb(upgraded_tcb);

        fixture
            .open(partition)
            .expect("open after firmware upgrade should succeed");
        assert_device_has_content(crypt_device_path, b"data before upgrade");
        deactive_crypt_device_with_check(crypt_name(partition));

        let upgraded_stored_tcb = {
            let mut cd =
                open_luks2_device(&device_path, fixture.header_location(partition), false).unwrap();
            read_keyslot_metadata(&mut cd).unwrap()[0]
                .sev_metadata
                .tcb_version
        };
        assert_ne!(upgraded_stored_tcb, initial_stored_tcb);

        fixture
            .open(partition)
            .expect("re-open after TCB rotation should succeed");
        deactive_crypt_device_with_check(crypt_name(partition));

        let final_stored_tcb = {
            let mut cd =
                open_luks2_device(&device_path, fixture.header_location(partition), false).unwrap();
            read_keyslot_metadata(&mut cd).unwrap()[0]
                .sev_metadata
                .tcb_version
        };
        assert_eq!(final_stored_tcb, upgraded_stored_tcb);
    }
}

/// Simulates a firmware upgrade followed by a GuestOS upgrade.
///
/// 1. GuestOS-A formats and opens Store at TCB=1.
/// 2. Firmware upgrade (TCB 1→2): GuestOS-A opens Store, TCB rotation happens.
/// 3. GuestOS upgrade (A→B): previous key is written by the upgrade protocol,
///    GuestOS-B opens Store using the previous key and adds its own SEV-derived key.
///
/// The store should remain accessible through both transitions, with the final
/// keyslot reflecting GuestOS-B's measurement and the post-firmware TCB.
#[test]
fn test_firmware_upgrade_then_guestos_upgrade() {
    const PAYLOAD: &[u8] = b"firmware-then-guestos-upgrade";

    let guestos_a_measurement = [0xAA_u8; 48];
    let guestos_b_measurement = [0xBB_u8; 48];

    let initial_tcb = TcbVersion::new(None, 1, 0, 0, 0);
    let initial_tcb_u64 =
        u64::from_le_bytes(initial_tcb.to_bytes_with(Generation::Milan).unwrap());
    let upgraded_tcb = TcbVersion::new(None, 2, 0, 0, 0);
    let upgraded_tcb_u64 =
        u64::from_le_bytes(upgraded_tcb.to_bytes_with(Generation::Milan).unwrap());

    let mut fixture = TestFixture::new(true);
    let device_path = fixture.device.path().unwrap().to_path_buf();
    let crypt_device_path = get_crypt_device(Partition::Store);

    // 1. GuestOS-A formats and opens at TCB=1.
    fixture.sev_firmware_builder = MockSevGuestFirmwareBuilder::new()
        .with_derived_key(Some([10; 32]))
        .with_measurement(guestos_a_measurement)
        .with_launch_tcb(initial_tcb);
    fixture.format(Partition::Store).unwrap();
    fixture.open(Partition::Store).unwrap();
    fs::write(crypt_device_path, PAYLOAD).unwrap();
    deactive_crypt_device_with_check("store-crypt");

    // 2. Firmware upgrade (TCB 1→2). Same GuestOS, same measurement.
    fixture.sev_firmware_builder = MockSevGuestFirmwareBuilder::new()
        .with_derived_key(Some([10; 32]))
        .with_measurement(guestos_a_measurement)
        .with_launch_tcb(upgraded_tcb);
    fixture
        .open(Partition::Store)
        .expect("open after firmware upgrade should succeed");
    assert_device_has_content(crypt_device_path, PAYLOAD);
    deactive_crypt_device_with_check("store-crypt");

    let after_fw_metadata = fixture.read_keyslot_metadata(Partition::Store);
    assert_eq!(after_fw_metadata.len(), 1);
    assert_eq!(
        after_fw_metadata[0].sev_metadata.tcb_version,
        upgraded_tcb_u64,
        "firmware upgrade should rotate TCB"
    );

    // 3. GuestOS upgrade (A→B). The upgrade protocol writes the previous key.
    let guestos_a_key = derive_key_from_sev_measurement(
        &mut fixture.sev_firmware_builder.build(),
        Key::DiskEncryptionKey {
            device_path: &device_path,
        },
        upgraded_tcb_u64,
    )
    .unwrap();
    fs::write(&fixture.previous_key_path, guestos_a_key.as_bytes())
        .expect("Failed to write previous key for GuestOS upgrade");

    fixture.sev_firmware_builder = MockSevGuestFirmwareBuilder::new()
        .with_derived_key(Some([20; 32]))
        .with_measurement(guestos_b_measurement)
        .with_launch_tcb(upgraded_tcb);

    fixture
        .open(Partition::Store)
        .expect("open after GuestOS upgrade should succeed");
    assert_device_has_content(crypt_device_path, PAYLOAD);
    assert!(
        !fixture.previous_key_path.exists(),
        "previous key should be consumed after GuestOS upgrade"
    );
    deactive_crypt_device_with_check("store-crypt");

    let final_metadata = fixture.read_keyslot_metadata(Partition::Store);
    assert_eq!(final_metadata.len(), 1);
    assert_eq!(
        final_metadata[0].sev_metadata.tcb_version, upgraded_tcb_u64,
        "final keyslot should have the upgraded TCB"
    );
    assert_eq!(
        final_metadata[0].sev_metadata.launch_measurement_hex,
        hex::encode(guestos_b_measurement),
        "final keyslot should have GuestOS-B's measurement"
    );

    // GuestOS-A's key should no longer unlock the device.
    check_encryption_key(
        &device_path,
        LuksHeaderLocation::Detached(&fixture.store_luks_header_path),
        guestos_a_key.as_bytes(),
    )
    .expect_err("GuestOS-A key should no longer unlock after firmware + GuestOS upgrade");

    // GuestOS-B's key should work.
    let guestos_b_key = derive_key_from_sev_measurement(
        &mut fixture.sev_firmware_builder.build(),
        Key::DiskEncryptionKey {
            device_path: &device_path,
        },
        upgraded_tcb_u64,
    )
    .unwrap();
    check_encryption_key(
        &device_path,
        LuksHeaderLocation::Detached(&fixture.store_luks_header_path),
        guestos_b_key.as_bytes(),
    )
    .expect("GuestOS-B key should unlock after firmware + GuestOS upgrade");
}

/// Simulates a GuestOS upgrade followed by a firmware upgrade, then a GuestOS rollback.
///
/// GuestOS rollback means switching to the other boot alternative. No previous key file
/// is written. The rolled-back GuestOS uses its own frozen detached LUKS header (from its
/// own var partition) and must open the device via candidate enumeration.
///
/// 1. GuestOS-A formats and opens Store at TCB=1.
/// 2. GuestOS upgrade (A→B): previous key written, GuestOS-B opens at TCB=1.
/// 3. Firmware upgrade (TCB 1→2): GuestOS-B opens, TCB rotation.
/// 4. Rollback to GuestOS-A: no previous key, uses its own frozen header (still at TCB=1).
///    Opens via candidate enumeration (token TCB=1 ≤ current TCB=2), then TCB rotation.
#[test]
fn test_guestos_upgrade_then_firmware_upgrade_then_rollback() {
    const PAYLOAD: &[u8] = b"guestos-upgrade-fw-upgrade-rollback";

    let guestos_a_measurement = [0xAA_u8; 48];
    let guestos_b_measurement = [0xBB_u8; 48];

    let initial_tcb = TcbVersion::new(None, 1, 0, 0, 0);
    let initial_tcb_u64 =
        u64::from_le_bytes(initial_tcb.to_bytes_with(Generation::Milan).unwrap());
    let upgraded_tcb = TcbVersion::new(None, 2, 0, 0, 0);
    let upgraded_tcb_u64 =
        u64::from_le_bytes(upgraded_tcb.to_bytes_with(Generation::Milan).unwrap());

    let mut fixture = TestFixture::new(true);
    let device_path = fixture.device.path().unwrap().to_path_buf();
    let crypt_device_path = get_crypt_device(Partition::Store);
    let snapshot_dir = tempdir().unwrap();
    let guestos_a_header = snapshot_dir.path().join("guestos_a_header");

    // 1. GuestOS-A formats and opens at TCB=1.
    fixture.sev_firmware_builder = MockSevGuestFirmwareBuilder::new()
        .with_derived_key(Some([10; 32]))
        .with_measurement(guestos_a_measurement)
        .with_launch_tcb(initial_tcb);
    fixture.format(Partition::Store).unwrap();
    fixture.open(Partition::Store).unwrap();
    fs::write(crypt_device_path, PAYLOAD).unwrap();
    deactive_crypt_device_with_check("store-crypt");

    // Snapshot GuestOS-A's detached header (frozen on its var partition).
    fs::copy(&fixture.store_luks_header_path, &guestos_a_header)
        .expect("Failed to snapshot GuestOS-A detached header");

    // 2. GuestOS upgrade (A→B): upgrade protocol writes previous key.
    let guestos_a_key = derive_key_from_sev_measurement(
        &mut fixture.sev_firmware_builder.build(),
        Key::DiskEncryptionKey {
            device_path: &device_path,
        },
        initial_tcb_u64,
    )
    .unwrap();
    fs::write(&fixture.previous_key_path, guestos_a_key.as_bytes())
        .expect("Failed to write previous key for GuestOS upgrade");

    fixture.sev_firmware_builder = MockSevGuestFirmwareBuilder::new()
        .with_derived_key(Some([20; 32]))
        .with_measurement(guestos_b_measurement)
        .with_launch_tcb(initial_tcb);

    fixture
        .open(Partition::Store)
        .expect("GuestOS-B should open after upgrade");
    deactive_crypt_device_with_check("store-crypt");

    // 3. Firmware upgrade (TCB 1→2). GuestOS-B opens, TCB rotation.
    fixture.sev_firmware_builder = MockSevGuestFirmwareBuilder::new()
        .with_derived_key(Some([20; 32]))
        .with_measurement(guestos_b_measurement)
        .with_launch_tcb(upgraded_tcb);

    fixture
        .open(Partition::Store)
        .expect("GuestOS-B should open after firmware upgrade");
    assert_device_has_content(crypt_device_path, PAYLOAD);
    deactive_crypt_device_with_check("store-crypt");

    // 4. Rollback to GuestOS-A: switch boot alternative.
    //    No previous key file is written. GuestOS-A uses its own frozen detached header.
    assert!(
        !fixture.previous_key_path.exists(),
        "no previous key should exist during rollback"
    );

    // Restore GuestOS-A's frozen header (still at TCB=1 from step 1).
    fs::copy(&guestos_a_header, &fixture.store_luks_header_path)
        .expect("Failed to restore GuestOS-A detached header");

    let pre_rollback_metadata = fixture.read_keyslot_metadata(Partition::Store);
    assert_eq!(pre_rollback_metadata.len(), 1);
    assert_eq!(
        pre_rollback_metadata[0].sev_metadata.tcb_version,
        initial_tcb_u64,
        "frozen GuestOS-A header should still have the old TCB"
    );

    // GuestOS-A boots: same measurement as before, firmware at TCB=2.
    fixture.sev_firmware_builder = MockSevGuestFirmwareBuilder::new()
        .with_derived_key(Some([10; 32]))
        .with_measurement(guestos_a_measurement)
        .with_launch_tcb(upgraded_tcb);

    fixture
        .open(Partition::Store)
        .expect("GuestOS-A should open after rollback using candidate enumeration");
    assert_device_has_content(crypt_device_path, PAYLOAD);
    deactive_crypt_device_with_check("store-crypt");

    // The token should now be rotated to the upgraded TCB.
    let post_rollback_metadata = fixture.read_keyslot_metadata(Partition::Store);
    assert_eq!(post_rollback_metadata.len(), 1);
    assert_eq!(
        post_rollback_metadata[0].sev_metadata.tcb_version,
        upgraded_tcb_u64,
        "rollback open should rotate TCB from 1 to 2"
    );

    // Re-opening should work with the rotated TCB (no candidate enumeration needed).
    fixture
        .open(Partition::Store)
        .expect("re-open after rollback should succeed");
    deactive_crypt_device_with_check("store-crypt");
}

fn assert_verification_result_with_tampered_luks_parameters(
    enable_trusted_execution_environment: bool,
    cipher: &str,
    cipher_mode: &str,
    volume_key_size: usize,
    pbkdf_type: CryptKdf,
    pbkdf_iterations: u32,
    expected_error: &str,
) {
    let mut fixture = TestFixture::new(enable_trusted_execution_environment);
    let device_path = fixture.device.path().unwrap().to_path_buf();
    // Reuse the same key material the implementation would use to open the device.
    // In the TEE case the key is derived from the SEV measurement and never persisted,
    // while in the non-TEE case we first let the implementation format the device so it
    // can generate and store the key file that this tampering setup must reuse.
    let passphrase = if enable_trusted_execution_environment {
        let mut sev_firmware = fixture.sev_firmware_builder.build();
        derive_key_from_sev_measurement(
            &mut sev_firmware,
            Key::DiskEncryptionKey {
                device_path: &device_path,
            },
            TestFixture::default_launch_tcb_as_u64(),
        )
        .unwrap()
        .as_bytes()
        .to_vec()
    } else {
        fixture
            .format(Partition::Var)
            .expect("Failed to format var partition to generate key");
        fs::read(&fixture.generated_key_path).expect("Failed to read generated key")
    };

    create_crypt_device_luks_parameters(
        &device_path,
        &passphrase,
        cipher,
        cipher_mode,
        volume_key_size,
        pbkdf_type,
        pbkdf_iterations,
    );

    if enable_trusted_execution_environment {
        let open_err = fixture
            .open(Partition::Var)
            .expect_err("Open should fail because LUKS parameters are invalid");
        assert!(
            format!("{open_err:#}").contains(expected_error),
            "Unexpected error message: {open_err:#}"
        );
    } else {
        fixture
            .open(Partition::Var)
            .expect("Failed to open var partition");
    }
}

#[test]
fn test_verification_cipher_tampered() {
    for enable_trusted_execution_environment in [true, false] {
        assert_verification_result_with_tampered_luks_parameters(
            enable_trusted_execution_environment,
            "cipher_null",
            "ecb",
            TEST_VOLUME_KEY_BYTES,
            CryptKdf::Pbkdf2,
            TEST_PBKDF_ITERATIONS,
            "Unexpected cipher",
        );
    }
}

#[test]
fn test_verification_volume_key_size_tampered() {
    assert_verification_result_with_tampered_luks_parameters(
        true,
        "aes",
        "xts-plain64",
        256 / 8,
        CryptKdf::Pbkdf2,
        TEST_PBKDF_ITERATIONS,
        "Unexpected volume key size",
    );
}

#[test]
fn test_verification_pbkdf_type_tampered() {
    assert_verification_result_with_tampered_luks_parameters(
        true,
        "aes",
        "xts-plain64",
        TEST_VOLUME_KEY_BYTES,
        CryptKdf::Argon2I,
        TEST_PBKDF_ITERATIONS,
        "Unexpected keyslot PBKDF type",
    );
}

#[test]
fn test_metrics_export() {
    let mut fixture = TestFixture::new(false);

    // Format the device
    fixture
        .format(Partition::Var)
        .expect("Failed to format device");

    // Open the device which will export metrics
    fixture.open(Partition::Var).expect("Failed to open device");

    // Read and verify the metrics content
    let metrics_content = fs::read_to_string(fixture.metrics_file(Partition::Var))
        .expect("Failed to read metrics file");

    // Check that the metrics file contains expected content
    assert!(
        metrics_content.contains("guest_disk_encryption_info"),
        "Missing encryption info metric: {metrics_content}"
    );
    assert!(
        metrics_content.contains("format=\"Luks2\""),
        "Missing or incorrect format label: {metrics_content}"
    );
    assert!(
        metrics_content.contains("cipher=\"aes-xts-plain64\""),
        "Missing or incorrect cipher label: {metrics_content}"
    );
    assert!(
        metrics_content.contains("keyslot_pbkdf_type=\"Pbkdf2\""),
        "Missing or incorrect keyslot_pbkdf_type label: {metrics_content}"
    );
    // TODO: Fix keyslot_pbkdf_iterations to 1000 and replace with
    // keyslot_pbkdf_iterations=\"1000\"
    assert!(
        metrics_content.contains("keyslot_pbkdf_iterations="),
        "Missing or incorrect keyslot_pbkdf_iterations label: {metrics_content}"
    );
    assert!(
        metrics_content.contains("volume_key_size=\"64\""),
        "Missing or incorrect volume_key_size label: {metrics_content}"
    );
    assert!(
        metrics_content.contains("num_keyslots=\"1\""),
        "Missing or incorrect num_keyslots label: {metrics_content}"
    );
    assert!(
        metrics_content.contains("keyslot_cipher=\"aes-xts-plain64\""),
        "Missing or incorrect keyslot_cipher label: {metrics_content}"
    );
    assert!(
        metrics_content.contains("keyslot_key_size=\"64\""),
        "Missing or incorrect keyslot_key_size label: {metrics_content}"
    );
    assert!(
        metrics_content.contains("passes_verification=\"true\""),
        "Missing or incorrect passes_verification label: {metrics_content}"
    );
}

#[test]
fn test_store_attached_luks2_header_status_metric_absent() {
    let mut fixture = TestFixture::new(true);

    // Format the store partition with a detached header only; there is no attached header on the
    // data device.
    fixture
        .format(Partition::Store)
        .expect("Failed to format store partition");

    fixture
        .open(Partition::Store)
        .expect("Failed to open store partition");

    let metrics_content = fs::read_to_string(fixture.metrics_file(Partition::Store))
        .expect("Failed to read metrics file");

    assert!(
        metrics_content.contains("guest_disk_store_attached_luks2_header_status"),
        "Missing attached LUKS2 header status metric: {metrics_content}"
    );
    assert!(
        metrics_content.contains("status=\"absent\""),
        "Expected status=\"absent\" label: {metrics_content}"
    );
    assert!(
        !metrics_content.contains("status=\"present\""),
        "Did not expect status=\"present\" label: {metrics_content}"
    );
}

#[test]
fn test_store_attached_luks2_header_status_metric_present() {
    const PREVIOUS_KEY: &[u8] = b"previous key";

    let mut fixture = TestFixture::new(true);

    fs::write(&fixture.previous_key_path, PREVIOUS_KEY)
        .expect("Failed to write previous key for testing");

    // Simulate a legacy device that has both an attached and a detached header.
    format_crypt_device(
        &fixture.device.path().unwrap(),
        LuksHeaderLocation::Attached,
        PREVIOUS_KEY,
    )
    .expect("Failed to format device with attached header");

    backup_luks_header_to_file(
        &fixture.device.path().unwrap(),
        &fixture.store_luks_header_path,
    )
    .expect("Failed to create detached header backup");

    assert!(fixture.has_attached_luks2_header());

    fixture
        .open(Partition::Store)
        .expect("opening Store should succeed");

    // After opening, the attached header is wiped because a detached header is available.
    // The metric reflects the end result, so it must report "absent".
    assert!(
        !fixture.has_attached_luks2_header(),
        "attached LUKS header should have been wiped during open()"
    );

    let metrics_content = fs::read_to_string(fixture.metrics_file(Partition::Store))
        .expect("Failed to read metrics file");

    assert!(
        metrics_content.contains("guest_disk_store_attached_luks2_header_status"),
        "Missing attached LUKS2 header status metric: {metrics_content}"
    );
    assert!(
        metrics_content.contains("status=\"absent\""),
        "Expected status=\"absent\" after wipe: {metrics_content}"
    );
    // The LUKS parameters metric must still be present (not overwritten by the header status
    // metric).
    assert!(
        metrics_content.contains("guest_disk_encryption_info"),
        "Missing encryption info metric: {metrics_content}"
    );
}

#[test]
fn test_run_returns_sev_firmware_factory_error() {
    let temp_dir = tempdir().unwrap();
    let guestos_config = TestFixture::create_guestos_config(true);
    let device_path = temp_dir.path().join("dummy_device");

    let err = run(
        Args::CryptOpen {
            partition: Partition::Store,
            device_path,
        },
        &guestos_config,
        true,
        || Err(anyhow!("boom")),
        &temp_dir.path().join("previous_key"),
        &temp_dir.path().join("store.header"),
        &temp_dir.path().join("generated_key"),
        temp_dir.path(),
    )
    .expect_err("run should fail when SEV firmware cannot be opened");

    assert!(
        format!("{err:#}").contains("Failed to open SEV firmware"),
        "Unexpected error: {err:#}"
    );
    assert!(
        format!("{err:#}").contains("boom"),
        "Unexpected error: {err:#}"
    );
}
