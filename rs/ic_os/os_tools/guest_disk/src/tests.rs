//! Tests for the guest disk encryption tooling.
//!
//! The test topology mirrors the real GuestOS disk layout:
//!   - one shared **store** device (shared across GuestOS releases, uses a detached
//!     LUKS header when TEE/SEV is enabled), and
//!   - two **var** devices, one per A/B boot slot (private to a GuestOS version,
//!     always uses an attached LUKS header).
//!
//! [`TestFixture`] owns the block devices and the A/B slots; [`PartitionView`] is a
//! lightweight view of a single partition that borrows the fixture's run context and
//! carries all partition-specific LUKS inspection and device-mapper helpers. Simple
//! tests touch only the store or the active slot's var device; the A/B slot machinery
//! ([`TestFixture::upgrade_sev_guestos_to`] / [`TestFixture::rollback`]) supports
//! upgrade/rollback tests.

use crate::{Args, Partition, crypt_name, metrics_file_path, run};
use anyhow::{Result, anyhow};
use guest_disk::DiskEncryption;
use guest_disk::crypt::{
    IC_KEY_TOKEN_TYPE, KeyslotToken, LUKS2_N_KEYSLOTS, LUKS2_N_TOKENS, LuksHeaderLocation,
    SINGLE_KEYSLOT_INDEX, SINGLE_TOKEN_INDEX, SevMetadata, deactivate_crypt_device,
    format_crypt_device, open_luks2_device, read_single_keyslot_token,
};
use guest_disk::sev::{SevDiskEncryption, can_open, rekey};
use ic_device::device_mapping::{Bytes, TempDevice};
use ic_os_logging::init_logging;
use itertools::Either::Right;
use libcryptsetup_rs::consts::flags::CryptVolumeKey;
use libcryptsetup_rs::consts::vals::{CryptKdf, EncryptionFormat, KeyslotInfo};
use libcryptsetup_rs::{
    CryptDevice, CryptInit, CryptParamsLuks2Ref, CryptSettingsHandle, CryptTokenInfo, TokenInput,
};
use prometheus::Registry;
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

fn default_launch_tcb() -> TcbVersion {
    TcbVersion::new(None, 1, 2, 3, 4)
}

fn default_launch_tcb_as_u64() -> u64 {
    u64::from_le_bytes(
        default_launch_tcb()
            .to_bytes_with(Generation::Milan)
            .unwrap(),
    )
}

/// The default launch measurement for slot A. Tests that assert on keyslot metadata
/// expect this value (and its derived key) to be written by the SEV format path.
fn default_launch_measurement() -> [u8; 48] {
    std::array::from_fn(|i| i as u8)
}

fn default_launch_measurement_as_hex() -> String {
    hex::encode(default_launch_measurement())
}

/// Counts the number of active LUKS2 keyslots on the given crypt device.
fn count_active_keyslots(crypt_device: &mut CryptDevice) -> usize {
    let mut keyslot_handle = crypt_device.keyslot_handle();
    (0..LUKS2_N_KEYSLOTS)
        .filter(|&keyslot| {
            matches!(
                keyslot_handle.status(keyslot).unwrap(),
                KeyslotInfo::Active | KeyslotInfo::ActiveLast
            )
        })
        .count()
}

/// A lightweight view of one encrypted partition, borrowing its run context from the
/// owning [`TestFixture`].
struct PartitionView<'a> {
    /// Back-reference to the fixture supplying the run context (config, firmware, paths).
    fixture: &'a TestFixture,
    partition: Partition,
    device_path: PathBuf,
    /// Path of the detached LUKS header, if this partition uses one; `None` for an attached header.
    detached_header_path: Option<PathBuf>,
}

impl<'a> PartitionView<'a> {
    fn new(
        fixture: &'a TestFixture,
        partition: Partition,
        device_path: PathBuf,
        detached_header_path: Option<PathBuf>,
    ) -> Self {
        Self {
            fixture,
            partition,
            device_path,
            detached_header_path,
        }
    }

    fn device_path(&self) -> &Path {
        &self.device_path
    }

    /// The LUKS header location for this partition, borrowing the stored detached path if any.
    fn header_location(&self) -> LuksHeaderLocation<'_> {
        match &self.detached_header_path {
            Some(path) => LuksHeaderLocation::Detached(path),
            None => LuksHeaderLocation::Attached,
        }
    }

    fn crypt_name(&self) -> &'static str {
        crypt_name(self.partition)
    }

    /// `/dev/mapper/<crypt_name>` — the activated device path for this partition.
    fn mapper_path(&self) -> PathBuf {
        PathBuf::from(format!("/dev/mapper/{}", self.crypt_name()))
    }

    /// Formats this partition's device with LUKS2 (data loss on the device).
    fn format(&self) -> Result<()> {
        self.fixture.run(Args::CryptFormat {
            partition: self.partition,
            device_path: self.device_path.clone(),
        })
    }

    /// Opens this partition's device and activates it under `/dev/mapper/<crypt_name>`.
    fn open(&self) -> Result<()> {
        self.fixture.run(Args::CryptOpen {
            partition: self.partition,
            device_path: self.device_path.clone(),
        })
    }

    fn open_crypt_device(&self) -> CryptDevice {
        open_luks2_device(&self.device_path, self.header_location()).unwrap()
    }

    fn has_attached_luks2_header(&self) -> bool {
        open_luks2_device(&self.device_path, LuksHeaderLocation::Attached).is_ok()
    }

    fn has_detached_luks2_header(&self) -> bool {
        match &self.detached_header_path {
            Some(header_path) => {
                open_luks2_device(&self.device_path, LuksHeaderLocation::Detached(header_path))
                    .is_ok()
            }
            // A partition configured for an attached header has no detached header to inspect.
            None => false,
        }
    }

    /// Asserts that there is only a single token at index 0 and returns it.
    fn read_keyslot_token(&self) -> KeyslotToken {
        self.assert_single_metadata_token();
        let token = read_single_keyslot_token(&mut self.open_crypt_device()).unwrap();
        assert_eq!(token.keyslots, [SINGLE_KEYSLOT_INDEX.to_string()]);
        token
    }

    /// Asserts that the device carries no token at all.
    fn assert_no_metadata_token(&self) {
        let mut crypt_device = self.open_crypt_device();
        for token_id in 0..LUKS2_N_TOKENS {
            assert!(
                matches!(
                    crypt_device.token_handle().status(token_id).unwrap(),
                    CryptTokenInfo::Inactive
                ),
                "did not expect token {token_id} on the device"
            );
        }
    }

    /// Asserts the single-token invariant: the only token on the device is the
    /// `{IC_KEY_TOKEN_TYPE}` token, in the first token position; all other tokens are
    /// inactive.
    fn assert_single_metadata_token(&self) {
        let mut crypt_device = self.open_crypt_device();
        for token_id in 0..LUKS2_N_TOKENS {
            let status = crypt_device.token_handle().status(token_id).unwrap();
            let expected = if token_id == SINGLE_TOKEN_INDEX {
                matches!(
                    status,
                    CryptTokenInfo::ExternalUnknown(ref token_type)
                        if token_type == IC_KEY_TOKEN_TYPE
                )
            } else {
                matches!(status, CryptTokenInfo::Inactive)
            };
            assert!(
                expected,
                "token {token_id}: expected the only token to be the {IC_KEY_TOKEN_TYPE} token \
                 in the first position and all other positions to be inactive"
            );
        }
    }

    fn active_keyslot_count(&self) -> usize {
        count_active_keyslots(&mut self.open_crypt_device())
    }

    /// Zeroes the region of the data device where an attached LUKS2 header would live.
    fn corrupt_attached_header(&self) {
        // The test device size reserves 16 MiB for LUKS2 metadata and 2 MiB for payload.
        let mut device = OpenOptions::new()
            .write(true)
            .open(&self.device_path)
            .unwrap();
        device.write_all(&vec![0_u8; 16 * 1024 * 1024]).unwrap();
    }

    /// Deactivates the device-mapper entry for this partition and asserts it is gone.
    fn deactivate(&self) {
        deactivate_crypt_device_with_check(self.crypt_name());
    }

    fn write_payload(&self, data: &[u8]) {
        fs::write(self.mapper_path(), data).unwrap();
    }

    fn assert_payload(&self, expected: &[u8]) {
        assert_device_has_content(&self.mapper_path(), expected);
    }
}

/// One boot slot: its own var block device, its var directory (holding the previous
/// key, generated key, detached Store header and metrics for this slot), and the SEV
/// launch measurement identifying the GuestOS version installed on this slot.
struct BootSlot {
    name: &'static str,
    launch_measurement: [u8; 48],
    var_dir: TempDir,
    var_device: TempDevice,
}

impl BootSlot {
    fn new(name: &'static str, launch_measurement: [u8; 48]) -> Self {
        let var_device = TempDevice::new(Bytes(18 * 1024 * 1024).sectors()).unwrap();
        Self {
            name,
            launch_measurement,
            var_dir: tempdir().unwrap(),
            var_device,
        }
    }

    /// Path of the detached Store LUKS header file on this slot's var partition.
    fn store_header_path(&self) -> PathBuf {
        self.var_dir.path().join("store.header")
    }

    /// Path of the generated-key file on this slot's var partition.
    fn generated_key_path(&self) -> PathBuf {
        self.var_dir.path().join("generated_key")
    }

    fn metrics_dir(&self) -> &Path {
        self.var_dir.path()
    }
}

/// Test fixture modelling the GuestOS disk topology: one shared store device plus two
/// A/B boot slots, each with its own var device and var directory.
///
/// `active_slot` is the slot currently "booted". Simple tests that do not care about
/// A/B leave it at 0 (slot A); upgrade/rollback tests flip it via [`Self::upgrade_sev_guestos_to`]
/// / [`Self::rollback`].
struct TestFixture {
    store_device_path: PathBuf,
    _store_device: TempDevice,
    slots: [BootSlot; 2],
    active_slot: usize,
    sev_enabled: bool,
    launch_tcb: TcbVersion,
    _guard: parking_lot::MutexGuard<'static, ()>,
}

impl TestFixture {
    /// Fixture with SEV disk encryption enabled (store uses a detached header, keys are
    /// derived from the SEV launch measurement).
    fn new_sev() -> Self {
        Self::new(true)
    }

    /// Fixture with a generated (non-SEV) disk key: TEE/SEV disabled, store uses an attached
    /// header.
    fn new_with_generated_key() -> Self {
        Self::new(false)
    }

    fn new(sev_enabled: bool) -> Self {
        let guard = TEST_MUTEX.lock();
        cleanup();
        // LUKS2 needs 16 MiB of space for the metadata, let's add 2 MiB for the data.
        let store_device = TempDevice::new(Bytes(18 * 1024 * 1024).sectors()).unwrap();
        let store_device_path = store_device.path().unwrap();
        Self {
            store_device_path,
            _store_device: store_device,
            slots: [
                BootSlot::new("A", default_launch_measurement()),
                BootSlot::new("B", [0_u8; 48]),
            ],
            active_slot: 0,
            sev_enabled,
            launch_tcb: default_launch_tcb(),
            _guard: guard,
        }
    }

    /// A view of the partition of the given kind, resolved against the active slot.
    fn partition(&self, partition: Partition) -> PartitionView<'_> {
        match partition {
            Partition::Store => self.store_partition(),
            Partition::Var => self.var_partition(),
        }
    }

    /// A view of the shared store device. Uses a detached header (pointing at the active
    /// slot's Store header file) only under SEV; otherwise an attached header.
    fn store_partition(&self) -> PartitionView<'_> {
        // SEV: the store partition carries its LUKS header detached (on the var partition).
        let detached_header_path = self.sev_enabled.then(|| self.store_header_path());
        PartitionView::new(
            self,
            Partition::Store,
            self.store_device_path.clone(),
            detached_header_path,
        )
    }

    /// A view of the active slot's var device.
    fn var_partition(&self) -> PartitionView<'_> {
        PartitionView::new(
            self,
            Partition::Var,
            self.active_boot_slot()
                .var_device
                .path()
                .expect("var path is required"),
            None,
        )
    }

    fn active_boot_slot(&self) -> &BootSlot {
        &self.slots[self.active_slot]
    }

    fn store_device_path(&self) -> &Path {
        &self.store_device_path
    }

    fn store_header_path(&self) -> PathBuf {
        self.active_boot_slot().store_header_path()
    }

    fn generated_key_path(&self) -> PathBuf {
        self.active_boot_slot().generated_key_path()
    }

    fn metrics_dir(&self) -> &Path {
        self.active_boot_slot().metrics_dir()
    }

    fn metrics_file(&self, partition: Partition) -> PathBuf {
        metrics_file_path(self.metrics_dir(), partition)
    }

    /// Builds a SEV firmware mock from the global chip properties and the active slot's
    /// measurement.
    fn sev_firmware_builder(&self) -> MockSevGuestFirmwareBuilder {
        MockSevGuestFirmwareBuilder::new()
            .with_measurement(self.active_boot_slot().launch_measurement)
            .with_launch_tcb(self.launch_tcb)
    }

    fn run(&self, args: Args) -> Result<()> {
        let store_luks_header_path = self.store_header_path();
        let generated_key_path = self.generated_key_path();
        run(
            args,
            self.sev_enabled,
            || Ok(Box::new(self.sev_firmware_builder())),
            &store_luks_header_path,
            &generated_key_path,
            self.metrics_dir(),
        )
    }

    /// Derives the current SEV disk-encryption key for the given partition's data device,
    /// using the active slot's measurement.
    fn derive_sev_key(&self, partition: Partition) -> Vec<u8> {
        let device_path = self.partition(partition).device_path().to_path_buf();
        let mut firmware = self.sev_firmware_builder();
        derive_key_from_sev_measurement(
            &mut firmware,
            Key::DiskEncryptionKey {
                device_path: &device_path,
            },
        )
        .unwrap()
        .into_bytes()
    }

    /// SEV: whether the store partition can be unlocked locally with the SEV-derived key
    /// (used to decide whether key exchange can be skipped).
    fn can_open_store(&self) -> Result<bool> {
        let store_luks_header_path = self.store_header_path();
        let mut firmware = self.sev_firmware_builder();
        can_open(
            self.store_device_path(),
            LuksHeaderLocation::Detached(&store_luks_header_path),
            &mut firmware,
        )
    }

    fn assert_no_detached_store_header(&self) {
        let store_header_path = self.store_header_path();
        assert!(!store_header_path.exists());
        assert!(!self.store_partition().has_detached_luks2_header());
    }

    /// SEV upgrade protocol: installs a new GuestOS version (identified by its SEV launch
    /// measurement) on the other boot slot, then runs the upgrade key exchange: the old
    /// GuestOS serves its derived key and detached header, and the upgrade client (running
    /// the new GuestOS's code) copies the header to the new slot's var partition and
    /// re-keys it to the new GuestOS's derived key. Returns the result of opening the
    /// store so callers can attach context (e.g. an iteration index).
    fn upgrade_sev_guestos_to(&mut self, new_launch_measurement: [u8; 48]) -> Result<()> {
        // The old GuestOS's orchestrator derives and serves its Store key.
        let served_key = self.derive_sev_key(Partition::Store);

        let target = 1 - self.active_slot;

        // "Install" the new GuestOS on the target slot.
        self.slots[target].launch_measurement = new_launch_measurement;

        // Format the target's var partition (drop old, create fresh).
        let _ = std::mem::replace(&mut self.slots[target].var_dir, tempdir().unwrap());

        // The upgrade client copies the served detached Store header from the current var
        // to the target's var partition and re-keys it with the new GuestOS's derived key.
        let src_header = self.slots[self.active_slot].store_header_path();
        let dst_header = self.slots[target].store_header_path();
        fs::copy(&src_header, &dst_header)
            .expect("Failed to copy detached Store header during upgrade");
        let mut upgrade_vm_firmware = self
            .sev_firmware_builder()
            .with_measurement(new_launch_measurement);
        rekey(
            self.store_device_path(),
            LuksHeaderLocation::Detached(&dst_header),
            &served_key,
            &mut upgrade_vm_firmware,
        )
        .expect("Failed to re-key the Store LUKS header during upgrade");

        self.active_slot = target;
        self.store_partition().open()
    }

    /// Switches to the other boot slot with no key exchange or var formatting.
    /// The other slot boots with its own frozen var partition (detached Store header and
    /// the keyslot for its own launch measurement from its last boot).
    fn rollback(&mut self) {
        self.active_slot = 1 - self.active_slot;
        self.store_partition().open().unwrap();
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

fn deactivate_crypt_device_with_check(crypt_device_name: &str) {
    let _ignore = deactivate_crypt_device(crypt_device_name);
    assert!(!Path::new(&format!("/dev/mapper/{crypt_device_name}")).exists());
}

fn cleanup() {
    for partition in [Partition::Store, Partition::Var] {
        deactivate_crypt_device_with_check(crypt_name(partition));
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

#[test]
fn test_generated_key_init_and_reopen() {
    for partition_name in [Partition::Store, Partition::Var] {
        let fixture = TestFixture::new_with_generated_key();
        let partition = fixture.partition(partition_name);
        let mapper_path = partition.mapper_path();

        // Test format & open
        partition
            .format()
            .expect("Failed to format device encryption with generated key");
        partition
            .open()
            .expect("Failed to open device encryption with generated key");

        assert!(
            mapper_path.exists(),
            "mapper device for {partition_name:?} should exist after open"
        );
        partition.write_payload(b"test_data");

        // Test reopening
        partition.deactivate();
        partition
            .open()
            .expect("Failed to reopen partition with generated key");

        partition.assert_payload(b"test_data");

        let generated_key_path = fixture.generated_key_path();
        assert!(generated_key_path.exists());
        assert_eq!(fs::read(&generated_key_path).unwrap().len(), 16);
        assert_eq!(
            generated_key_path.metadata().unwrap().permissions(),
            // Type file, readable and writable by owner only
            Permissions::from_mode(0o100600)
        );
        if partition_name == Partition::Store {
            assert!(
                !fixture.store_header_path().exists(),
                "detached Store header should not exist for {partition_name:?} with generated key"
            );
        }
        // Generated-key partitions carry no metadata token.
        partition.assert_no_metadata_token();
    }
}

#[test]
fn test_does_not_change_existing_generated_key() {
    let fixture = TestFixture::new_with_generated_key();
    let generated_key_path = fixture.generated_key_path();
    fs::write(&generated_key_path, "existing_key")
        .expect("Failed to write existing key for testing");
    fixture.var_partition().format().unwrap();
    fixture.var_partition().open().unwrap();
    assert_eq!(
        fs::read_to_string(&generated_key_path).unwrap(),
        "existing_key"
    );
}

#[test]
fn test_sev_key_init_and_reopen() {
    for partition_name in [Partition::Store, Partition::Var] {
        let fixture = TestFixture::new_sev();
        let partition = fixture.partition(partition_name);
        let mapper_path = partition.mapper_path();

        assert!(
            !mapper_path.exists(),
            "mapper for {partition_name:?} should not exist before open"
        );

        // Test format & open
        partition
            .format()
            .expect("Failed to format device encryption with generated key");
        partition
            .open()
            .expect("Failed to open device encryption with generated key");

        assert!(mapper_path.exists());
        assert!(
            !fixture.generated_key_path().exists(),
            "generated key should not exist for {partition_name:?} when SEV is enabled"
        );

        partition.write_payload(b"test_data");

        // Test reopening
        partition.deactivate();
        partition
            .open()
            .expect("Failed to reopen partition with SEV key");

        partition.assert_payload(b"test_data");
        partition.assert_single_metadata_token();

        if partition_name == Partition::Store {
            assert!(fixture.store_header_path().exists());
            assert!(partition.has_detached_luks2_header());
            // The store partition is formatted with a detached header only; no attached
            // LUKS header should be present on the data device.
            assert!(!partition.has_attached_luks2_header());
        }
    }
}

#[test]
fn test_sev_format_writes_keyslot_token() {
    for partition in [Partition::Store, Partition::Var] {
        let fixture = TestFixture::new_sev();
        fixture.partition(partition).format().unwrap();

        let token = fixture.partition(partition).read_keyslot_token();
        assert_eq!(
            token.sev_metadata.launch_measurement_hex,
            default_launch_measurement_as_hex()
        );
        assert_eq!(token.sev_metadata.tcb_version, default_launch_tcb_as_u64());
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
        let fixture = if enable_sev {
            TestFixture::new_sev()
        } else {
            TestFixture::new_with_generated_key()
        };

        fixture
            .partition(partition)
            .format()
            .expect("Failed to format encrypted partition");
        fixture
            .partition(partition)
            .open()
            .expect("Failed to open encrypted partition");

        assert_eq!(
            fixture.store_header_path().exists(),
            expect_detached_header,
            "unexpected detached header state for {:?} with SEV enabled = {}",
            partition,
            enable_sev
        );

        assert_eq!(
            fixture.partition(partition).has_detached_luks2_header(),
            expect_detached_header,
            "unexpected detached LUKS header state for {:?} with SEV enabled = {}",
            partition,
            enable_sev
        );

        assert_eq!(
            fixture.partition(partition).has_attached_luks2_header(),
            expect_attached_header,
            "unexpected attached LUKS header state for {:?} with SEV enabled = {}",
            partition,
            enable_sev
        );
    }
}

#[test]
fn test_fail_to_open_if_device_is_not_formatted() {
    let fixture = TestFixture::new_with_generated_key();

    fixture
        .store_partition()
        .open()
        .expect_err("Expected setup_disk_encryption to fail due to unformatted device");

    assert!(
        !fixture.store_partition().mapper_path().exists(),
        "store mapper device should not exist after failed open"
    );
}

#[test]
fn test_format_store_refuses_existing_detached_header() {
    let fixture = TestFixture::new_sev();

    // Pre-write a stale detached Store header that must refuse reformatting.
    let store_header_path = fixture.store_header_path();
    fs::write(&store_header_path, b"stale header")
        .expect("Failed to write stale detached Store header");

    let mut encryption = SevDiskEncryption {
        sev_firmware: Box::new(MockSevGuestFirmwareBuilder::new()),
        store_luks_header_path: store_header_path.clone(),
        metrics_registry: Registry::new(),
    };

    let err = encryption
        .format(fixture.store_device_path(), Partition::Store)
        .expect_err("formatting Store should fail when a detached header already exists");

    assert!(
        format!("{err:#}").contains("Refusing to format Store because detached LUKS header"),
        "Unexpected error: {err:#}"
    );
    assert_eq!(
        fs::read(&store_header_path).unwrap(),
        b"stale header",
        "existing detached Store header should be left untouched"
    );
}

/// Tests that a GuestOS rollback works without key exchange: the rolled-back
/// GuestOS uses its own frozen detached header, whose keyslot matches its own launch
/// measurement.
#[test]
fn test_rollback_uses_frozen_header_without_key_exchange() {
    let mut fixture = TestFixture::new_sev();

    // Slot A formats and writes data.
    fixture.store_partition().format().unwrap();
    fixture.store_partition().open().unwrap();
    fixture.store_partition().write_payload(b"rollback data");
    fixture.store_partition().deactivate();

    // Upgrade to the other slot.
    fixture.upgrade_sev_guestos_to([0x11; 48]).unwrap();
    fixture.store_partition().deactivate();

    // Rollback: the original slot boots with its own frozen header and keyslot.
    fixture.rollback();
    fixture.store_partition().assert_payload(b"rollback data");
    assert_eq!(fixture.active_boot_slot().name, "A");
    fixture.store_partition().deactivate();

    // The original slot can reopen after rollback.
    fixture.store_partition().open().unwrap();
    fixture.store_partition().assert_payload(b"rollback data");
    fixture.store_partition().deactivate();
}

/// The store cannot be opened by a GuestOS whose launch measurement does not match the
/// keyslot in the detached header (its SEV-derived key differs).
#[test]
fn test_open_store_fails_with_wrong_launch_measurement() {
    let mut fixture = TestFixture::new_sev();

    fixture.store_partition().format().unwrap();

    // Simulate a different GuestOS booting from the same slot.
    fixture.slots[fixture.active_slot].launch_measurement = [0xAA; 48];
    fixture
        .store_partition()
        .open()
        .expect_err("opening Store with a mismatched launch measurement must fail");
    assert!(
        !fixture.store_partition().mapper_path().exists(),
        "no mapper device should exist after the failed open"
    );
}

#[test]
fn test_open_store_after_format_crypt_device_with_detached_header() {
    let fixture = TestFixture::new_sev();

    // Format the store device with a detached header locked by the current SEV key.
    let sev_key = fixture.derive_sev_key(Partition::Store);
    format_crypt_device(
        fixture.store_device_path(),
        LuksHeaderLocation::Detached(&fixture.store_header_path()),
        &sev_key,
    )
    .expect("Failed to format Store device with current SEV key");

    assert!(fixture.store_partition().has_detached_luks2_header());
    assert!(!fixture.store_partition().has_attached_luks2_header());

    fixture
        .store_partition()
        .open()
        .expect("opening Store should succeed after formatting with a detached header");

    assert!(
        fixture.store_partition().mapper_path().exists(),
        "store mapper device should exist after open"
    );
}

#[test]
fn test_fails_to_open_var_if_key_doesnt_work() {
    let fixture = TestFixture::new_with_generated_key();

    fixture.var_partition().format().unwrap();
    fixture.var_partition().open().unwrap();
    fixture
        .partition(Partition::Var)
        .write_payload(b"some data");

    fixture.partition(Partition::Var).deactivate();

    // Overwrite the key
    fs::write(fixture.generated_key_path(), "wrong key").unwrap();

    fixture
        .var_partition()
        .open()
        .expect_err("Expected setup_disk_encryption to fail due to wrong key");
}

/// Tests that the store partition survives many upgrades, each re-keying the copied
/// detached header, while always keeping exactly one keyslot. The last upgrade re-keys
/// with the same key (same launch measurement), which must be equally harmless.
#[test]
fn test_open_store_multiple_times_with_different_keys() {
    init_logging();
    let mut fixture = TestFixture::new_sev();

    fixture.store_partition().format().unwrap();
    // Corrupt the area where an attached header would live so only the detached header is used.
    fixture.store_partition().corrupt_attached_header();

    for iteration in 0..6 {
        fixture
            .upgrade_sev_guestos_to([iteration as u8; 48])
            .unwrap_or_else(|e| {
                panic!("Failed to open store partition on iteration {iteration}: {e:#}")
            });
        assert!(
            fixture.store_partition().mapper_path().exists(),
            "store mapper device should exist on iteration {iteration}"
        );
        fixture.store_partition().deactivate();
    }

    // An upgrade to a GuestOS with the same launch measurement re-keys the header with
    // the same key.
    fixture
        .upgrade_sev_guestos_to([5_u8; 48])
        .expect("Failed to open store partition when re-keying with the same key");
    fixture.store_partition().deactivate();

    // Each re-key replaces the old key in place: the single keyslot (always the first)
    // and the single metadata token (always the first) carry the newest GuestOS's key
    // and launch measurement.
    let token = fixture.store_partition().read_keyslot_token();
    assert_eq!(
        token.sev_metadata.launch_measurement_hex,
        hex::encode([5_u8; 48])
    );
    assert_eq!(fixture.store_partition().active_keyslot_count(), 1);
}

/// A legacy header carrying an extra (stale) keyslot converges back to the single first
/// keyslot on the next upgrade.
// TODO: remove when we clean up destroy_keyslots_except_first (see comment on that function)
#[test]
fn test_upgrade_removes_stale_keyslots() {
    const STALE_KEY: &[u8] = b"stale previous key";

    let mut fixture = TestFixture::new_sev();

    // Build the legacy layout: the previous GuestOS's key in the first keyslot, the
    // current GuestOS's (served) key in a later one.
    let served_key = fixture.derive_sev_key(Partition::Store);
    let mut crypt_device = format_crypt_device(
        fixture.store_device_path(),
        LuksHeaderLocation::Detached(&fixture.store_header_path()),
        STALE_KEY,
    )
    .unwrap();
    crypt_device
        .keyslot_handle()
        .add_by_passphrase(None, STALE_KEY, &served_key)
        .expect("Failed to add the current GuestOS's keyslot");
    drop(crypt_device);
    assert_eq!(fixture.store_partition().active_keyslot_count(), 2);

    fixture
        .upgrade_sev_guestos_to([0x22; 48])
        .expect("opening Store after the upgrade should succeed");

    assert_eq!(fixture.store_partition().active_keyslot_count(), 1);
    // The re-key converges the legacy header back to the single token in the first
    // position, assigned to the single keyslot.
    fixture.store_partition().read_keyslot_token();
}

/// A legacy header carrying its keyslot at a non-zero index and its IC key metadata
/// token at a non-zero index migrates on the next upgrade: the re-key succeeds and
/// converges to the canonical layout with a single keyslot at index 0 and a single
/// token at index 0.
// TODO: remove this test once all nodes only use a single key slot + token per device
#[test]
fn test_rekey_migrates_legacy_keyslot_and_token_positions() {
    const LEGACY_KEYSLOT_INDEX: u32 = 2;
    const LEGACY_TOKEN_INDEX: u32 = 3;
    const STALE_KEY: &[u8] = b"stale previous key";

    let mut fixture = TestFixture::new_sev();

    // Build the legacy layout: the current GuestOS's (served) key in keyslot 2, keyslot
    // 0 unused, and the IC key metadata token in token position 3.
    let served_key = fixture.derive_sev_key(Partition::Store);
    let mut crypt_device = format_crypt_device(
        fixture.store_device_path(),
        LuksHeaderLocation::Detached(&fixture.store_header_path()),
        STALE_KEY,
    )
    .unwrap();
    crypt_device
        .keyslot_handle()
        .add_by_passphrase(Some(LEGACY_KEYSLOT_INDEX), STALE_KEY, &served_key)
        .expect("Failed to add the served key's keyslot at the legacy position");
    crypt_device
        .keyslot_handle()
        .destroy(SINGLE_KEYSLOT_INDEX)
        .expect("Failed to remove the format key's keyslot");
    let mut legacy_token = KeyslotToken::new_sev(SevMetadata {
        launch_measurement_hex: default_launch_measurement_as_hex(),
        tcb_version: default_launch_tcb_as_u64(),
    });
    legacy_token.keyslots = vec![LEGACY_KEYSLOT_INDEX.to_string()];
    crypt_device
        .token_handle()
        .json_set(TokenInput::ReplaceToken(
            LEGACY_TOKEN_INDEX,
            &serde_json::to_value(legacy_token).unwrap(),
        ))
        .expect("Failed to write the legacy IC key metadata token at position 3");
    drop(crypt_device);

    // Sanity-check the legacy layout before the migration: exactly one active keyslot
    // (in position 2) and the IC key token in position 3.
    assert_eq!(fixture.store_partition().active_keyslot_count(), 1);
    assert!(matches!(
        fixture
            .store_partition()
            .open_crypt_device()
            .token_handle()
            .status(LEGACY_TOKEN_INDEX)
            .unwrap(),
        CryptTokenInfo::ExternalUnknown(ref token_type) if token_type == IC_KEY_TOKEN_TYPE
    ));

    fixture
        .upgrade_sev_guestos_to([0x33; 48])
        .expect("re-keying a legacy header with non-zero keyslot/token positions should succeed");

    // The migrated header carries exactly one active keyslot, and it is at index 0.
    assert_eq!(fixture.store_partition().active_keyslot_count(), 1);
    assert!(matches!(
        fixture
            .store_partition()
            .open_crypt_device()
            .keyslot_handle()
            .status(SINGLE_KEYSLOT_INDEX)
            .unwrap(),
        KeyslotInfo::Active | KeyslotInfo::ActiveLast
    ));
    // The single token moved to position 0 referencing keyslot 0 (asserted by
    // read_keyslot_token) and carries the new GuestOS's launch measurement.
    let token = fixture.store_partition().read_keyslot_token();
    assert_eq!(
        token.sev_metadata.launch_measurement_hex,
        hex::encode([0x33_u8; 48])
    );
}

#[test]
fn test_can_open_store_with_detached_header_after_attached_header_is_corrupted() {
    let fixture = TestFixture::new_sev();

    fixture.store_partition().format().unwrap();
    // The store partition is formatted with a detached header only, so corrupting the area
    // where an attached header would be must not affect the result.
    fixture.store_partition().corrupt_attached_header();

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
    let fixture = TestFixture::new_sev();

    // Device is unformatted (no LUKS header), so no key can open it
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
    let fixture = TestFixture::new_sev();

    fixture.store_partition().format().unwrap();

    let store_header_path = fixture.store_header_path();
    assert!(store_header_path.exists());
    let metadata = store_header_path.metadata().unwrap();
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
    let fixture = TestFixture::new_sev();

    fixture.store_partition().format().unwrap();

    assert!(fixture.store_header_path().exists());
    // The store partition is formatted with a detached header only; there is no attached
    // LUKS header on the data device.
    assert!(!fixture.store_partition().has_attached_luks2_header());

    // Corrupting the area on the data device where an attached header would have been must
    // not affect opening because only the detached header is used.
    fixture.store_partition().corrupt_attached_header();

    fixture
        .store_partition().open()
        .expect("opening Store should succeed with the detached header even if the attached header is corrupted");

    assert!(
        fixture.store_partition().mapper_path().exists(),
        "store mapper device should exist after open"
    );
}

#[test]
fn test_cannot_open_with_generated_key_if_sev_is_enabled() {
    for partition in [Partition::Store, Partition::Var] {
        let mut fixture = TestFixture::new_with_generated_key();
        fixture.partition(partition).format().unwrap();
        fixture.partition(partition).open().unwrap();
        fixture.sev_enabled = true;
        fixture
            .partition(partition)
            .open()
            .expect_err("opening with generated key should fail when SEV is enabled");
    }
}

/// SEV: opening the var partition must fail with `expected_error` when the on-disk LUKS
/// parameters were tampered with, because the SEV path verifies them before activating.
fn assert_sev_rejects_tampered_luks_parameters(
    cipher: &str,
    cipher_mode: &str,
    volume_key_size: usize,
    pbkdf_type: CryptKdf,
    pbkdf_iterations: u32,
    expected_error: &str,
) {
    let fixture = TestFixture::new_sev();
    let device_path = fixture
        .partition(Partition::Var)
        .device_path()
        .to_path_buf();
    let passphrase = fixture.derive_sev_key(Partition::Var);

    create_crypt_device_luks_parameters(
        &device_path,
        &passphrase,
        cipher,
        cipher_mode,
        volume_key_size,
        pbkdf_type,
        pbkdf_iterations,
    );

    let open_err = fixture
        .var_partition()
        .open()
        .expect_err("Open should fail because LUKS parameters are invalid");
    assert!(
        format!("{open_err:#}").contains(expected_error),
        "Unexpected error message: {open_err:#}"
    );
}

/// Generated-key path: opening the var partition succeeds even with tampered LUKS
/// parameters, because the generated-key path does not verify them.
fn assert_generated_key_accepts_tampered_luks_parameters(
    cipher: &str,
    cipher_mode: &str,
    volume_key_size: usize,
    pbkdf_type: CryptKdf,
    pbkdf_iterations: u32,
) {
    let fixture = TestFixture::new_with_generated_key();
    let device_path = fixture
        .partition(Partition::Var)
        .device_path()
        .to_path_buf();
    // Let the implementation format the device so it generates and persists the key, then
    // reuse that key for the tampered formatting below.
    fixture
        .var_partition()
        .format()
        .expect("Failed to format var partition to generate key");
    let passphrase = fs::read(fixture.generated_key_path()).expect("Failed to read generated key");

    create_crypt_device_luks_parameters(
        &device_path,
        &passphrase,
        cipher,
        cipher_mode,
        volume_key_size,
        pbkdf_type,
        pbkdf_iterations,
    );

    fixture
        .var_partition()
        .open()
        .expect("Failed to open var partition");
}

#[test]
fn test_verification_cipher_tampered() {
    // SEV rejects the tampered cipher; the generated-key path ignores LUKS parameters.
    assert_sev_rejects_tampered_luks_parameters(
        "cipher_null",
        "ecb",
        TEST_VOLUME_KEY_BYTES,
        CryptKdf::Pbkdf2,
        TEST_PBKDF_ITERATIONS,
        "Unexpected cipher",
    );
    assert_generated_key_accepts_tampered_luks_parameters(
        "cipher_null",
        "ecb",
        TEST_VOLUME_KEY_BYTES,
        CryptKdf::Pbkdf2,
        TEST_PBKDF_ITERATIONS,
    );
}

#[test]
fn test_verification_volume_key_size_tampered() {
    assert_sev_rejects_tampered_luks_parameters(
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
    assert_sev_rejects_tampered_luks_parameters(
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
    let fixture = TestFixture::new_with_generated_key();

    // Format the device
    fixture
        .var_partition()
        .format()
        .expect("Failed to format device");

    // Open the device which will export metrics
    fixture
        .var_partition()
        .open()
        .expect("Failed to open device");

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
        metrics_content.contains("num_tokens=\"0\""),
        "Missing or incorrect num_tokens label: {metrics_content}"
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
fn test_run_returns_sev_firmware_factory_error() {
    let temp_dir = tempdir().unwrap();
    let device_path = temp_dir.path().join("dummy_device");

    let err = run(
        Args::CryptOpen {
            partition: Partition::Store,
            device_path,
        },
        true,
        || Err(anyhow!("boom")),
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
