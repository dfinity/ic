use anyhow::{Context, Result, bail, ensure};
use devicemapper::{Bytes, DM, DevId, DmName, DmOptions, Sectors};
use ic_device::device_mapping::{BaseDevice, LinearSegment, MappedDevice, TempDevice};
use std::path::Path;
use std::sync::Arc;

const UPGRADE_DM_NAME: &str = "upgrade-guestos";
const DATA_PARTITION_DM_NAME: &str = "guestos-data";
const DATA_PARTITION_SNAPSHOT_DM_NAME: &str = "guestos-data-snapshot";

const ALL_DM_NAMES_IN_CLEANUP_ORDER: [&str; 3] = [
    // The cleanup order is the reverse of creation order in create_device_for_upgrade.
    UPGRADE_DM_NAME,
    DATA_PARTITION_SNAPSHOT_DM_NAME,
    DATA_PARTITION_DM_NAME,
];

/// Creates a mapped device for the Upgrade VM which does not persist writes to the data partition.
/// This is done to protect the data partition in case the Upgrade Guest VM wants to write to it.
/// The mapped device has the following structure:
/// 1. GPT + first 9 partitions of base device
/// 2. Data partition that stores writes in a temporary file
/// 3. Backup GPT
///
/// The created device lives as long as the returned [MappedDevice] is in scope.
pub fn create_mapped_device_for_upgrade(base_device: &Path) -> Result<MappedDevice> {
    if !base_device.exists() {
        bail!(
            "Base device does not exist at path: {}",
            base_device.display()
        );
    }

    let gpt = gpt::disk::read_disk(base_device).context("Could not read GPT from device")?;
    ensure!(
        gpt.partitions().len() == 10,
        "Expected guest device to have 10 partitions but found {}",
        gpt.partitions().len()
    );

    let data_partition = gpt
        .partitions()
        .get(&10)
        .context("Could not find partition 10")?;

    let dev_mapper = Arc::new(DM::new().context("Failed to create device mapper instance")?);
    // In case the devices were not cleaned up properly before, we clean them up now.
    cleanup_devices(&dev_mapper);

    create_device_for_upgrade(
        dev_mapper,
        BaseDevice::from_path(base_device)?,
        Sectors(data_partition.first_lba),
        Sectors(
            data_partition
                .sectors_len()
                .context("Could not query data_partition len")?,
        ),
    )
}

/// Creates the mapped device chain.
///
/// We create 3 devices (device mapper tables are somewhat primitive, so we stack them):
///   - data partition device: maps just the data partition of the base device.
///   - data partition device with snapshot: writes are persisted to the snapshot instead of the original device.
///   - upgrade device: the merger of the base device and the newly created data partition device.
fn create_device_for_upgrade(
    dev_mapper: Arc<DM>,
    base_device: BaseDevice,
    data_partition_start: Sectors,
    data_partition_len: Sectors,
) -> Result<MappedDevice> {
    // Create device for data partition
    let readonly_data_partition_device = MappedDevice::create_linear(
        dev_mapper.clone(),
        DATA_PARTITION_DM_NAME,
        vec![LinearSegment::slice(
            Box::new(base_device.clone()),
            data_partition_start,
            data_partition_len,
        )?],
    )
    .context("Failed to create data partition device")?;

    // Create data partition snapshot that writes to the temporary device
    let data_partition_snapshot_device = MappedDevice::create_snapshot(
        dev_mapper.clone(),
        DATA_PARTITION_SNAPSHOT_DM_NAME,
        Box::new(readonly_data_partition_device),
        Box::new(
            // TODO: Is 512MB a good size for the snapshot?
            TempDevice::new(Bytes(512 * 1024 * 1024).sectors())
                .context("Failed to create temporary device for copy-on-write")?,
        ),
    )
    .context("Failed to create data snapshotpartition device")?;

    // Create final upgrade VM device with all segments
    MappedDevice::create_linear(
        dev_mapper,
        UPGRADE_DM_NAME,
        vec![
            // Read-write section: GPT + first 9 partitions
            LinearSegment::prefix(Box::new(base_device.clone()), data_partition_start)?,
            // Read-only section: data partition
            LinearSegment::full(Box::new(data_partition_snapshot_device)),
            // Read-write section: whatever is left at the end of the device (backup GPT)
            LinearSegment::suffix(
                Box::new(base_device),
                data_partition_start + data_partition_len,
            )?,
        ],
    )
    .context("Failed to create upgrade device")
}

/// Cleans up the device mapper devices to ensure that the upgrade device can be created without
/// conflicts.
fn cleanup_devices(dev_mapper: &DM) {
    let devices = match dev_mapper.list_devices() {
        Ok(devices) => devices,
        Err(err) => {
            eprintln!("Failed to list devices: {err}");
            return;
        }
    };

    for &name in &ALL_DM_NAMES_IN_CLEANUP_ORDER {
        for existing_device in &devices {
            if existing_device.0.as_bytes() == name.as_bytes() {
                try_remove_device(dev_mapper, &existing_device.0);
            }
        }
    }
}

fn try_remove_device(dev_mapper: &DM, name: &DmName) {
    const MAX_RETRIES: u32 = 10;
    const RETRY_DELAY_SECS: u64 = 2;

    for retry in 1..=MAX_RETRIES {
        match dev_mapper.device_remove(&DevId::Name(name), DmOptions::default()) {
            Ok(_) => return,
            Err(err) => {
                eprintln!("Failed to remove device {name} (attempt {retry}/{MAX_RETRIES}): {err}");
                std::thread::sleep(std::time::Duration::from_secs(RETRY_DELAY_SECS));
            }
        }
    }
}

#[cfg(all(test, feature = "upgrade_device_mapper_test"))]
mod tests {
    use super::*;
    use gpt::{GptConfig, GptDisk};
    use ic_device::device_mapping::LoopDeviceWrapper;
    use std::fs::File;
    use std::os::unix::fs::FileExt;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use tempfile::{NamedTempFile, TempPath};

    // The tests use the same global device mapper instance, so we need to ensure that
    // they do not interfere with each other. Each test that interacts with the device mapper
    // must hold the lock for the duration of the test.
    static DM_MUTEX: Mutex<()> = Mutex::new(());

    struct TestSetup {
        device: MappedDevice,
        gpt: GptDisk<File>,
        _loop_device: LoopDeviceWrapper,
        backing_file: TempPath,
    }

    fn create_test_setup() -> TestSetup {
        let backing_file = NamedTempFile::new().expect("Failed to create temporary file");
        backing_file
            .as_file()
            .set_len(1024 * 1024)
            .expect("Failed to set file length");

        let backing_file = backing_file.into_temp_path();

        let loop_device = LoopDeviceWrapper::attach_to_next_free(&backing_file, 0).unwrap();
        let loop_device_path = loop_device.path().expect("Failed to get loop device path");

        let mut gpt = GptConfig::new()
            .writable(true)
            .create(&loop_device_path)
            .expect("Failed to open GPT disk");
        for partition in 1..=10 {
            gpt.add_partition(
                &format!("part{partition}"),
                2048,
                gpt::partition_types::LINUX_FS,
                0,
                None,
            )
            .expect("Failed to add partition");
        }
        gpt.write_inplace().expect("Could not write GPT to device");

        let device = create_mapped_device_for_upgrade(&loop_device_path)
            .expect("Failed to create mapped device");
        TestSetup {
            device,
            gpt,
            _loop_device: loop_device,
            backing_file,
        }
    }

    fn get_mapped_devices() -> Vec<PathBuf> {
        std::fs::read_dir("/dev/mapper")
            .expect("Failed to read /dev/mapper")
            .map(|entry| entry.unwrap().path())
            .collect()
    }

    fn assert_mapped_devices_are_cleaned_up() {
        let mapped_devices = get_mapped_devices();
        for device in ALL_DM_NAMES_IN_CLEANUP_ORDER {
            assert!(
                !mapped_devices
                    .iter()
                    .any(|p| p.file_name() == Some(device.as_ref())),
                "Device {device} should be cleaned up"
            );
        }
    }

    /// Tests the creation of a mapped device for the upgrade VM.
    ///
    /// - Creates a temporary backing file and attaches it to a loop device.
    /// - Initializes a partition table with 10 partitions on the loop device.
    /// - Calls `create_mapped_device` to create the upgrade device.
    /// - Writes to both a read-write and the read-only (10th) partition via the upgrade device.
    /// - Verifies that data written to the read-write partition is persisted to the backing file.
    /// - Verifies that data written to the read-only partition is not persisted to the backing file.
    #[test]
    fn test_create_mapped_device_for_upgrade() {
        let _lock = DM_MUTEX.lock().unwrap();

        let setup = create_test_setup();

        let partition3_start_bytes = setup.gpt.partitions().get(&3).unwrap().first_lba * 512;
        let partition10_start_bytes = setup.gpt.partitions().get(&10).unwrap().first_lba * 512;

        let upgrade_device = File::options()
            .write(true)
            .read(true)
            .open(setup.device.path())
            .expect("Failed to open device file");
        upgrade_device
            .write_at(b"foo", partition3_start_bytes)
            .expect("Failed to write to device file");
        upgrade_device
            .write_at(b"bar", partition10_start_bytes)
            .expect("Failed to write to device file");
        drop(upgrade_device);

        let upgrade_device =
            File::open(setup.device.path()).expect("Failed to open device file after write");
        let mut read_buf = vec![0; 3];
        upgrade_device
            .read_at(&mut read_buf, partition3_start_bytes)
            .expect("Failed to read from device file");
        assert_eq!(read_buf, b"foo");

        upgrade_device
            .read_at(&mut read_buf, partition10_start_bytes)
            .expect("Failed to read from device file");
        assert_eq!(read_buf, b"bar");
        drop(upgrade_device);

        let file = File::open(&setup.backing_file).expect("Failed to open backing file");
        let mut read_buf = vec![0; 3];
        file.read_at(&mut read_buf, partition3_start_bytes)
            .expect("Failed to read from backing file");
        // Check that the read-write partition is written to the backing file
        assert_eq!(read_buf, b"foo");

        file.read_at(&mut read_buf, partition10_start_bytes)
            .expect("Failed to read from backing file");
        // Check that the read-only partition is not written to the backing file
        assert_eq!(read_buf, &[0, 0, 0]);

        let device_path = setup.device.path().to_path_buf();
        drop(setup.device);

        assert!(
            !device_path.exists(),
            "Device file should be removed after drop"
        );

        assert_mapped_devices_are_cleaned_up();
    }

    #[test]
    fn test_device_missing() {
        let missing_path = Path::new("/nonexistent/device/path");
        let result = create_mapped_device_for_upgrade(missing_path);
        let err = result
            .expect_err("Expected error on missing base device")
            .to_string();
        assert!(err.contains("Base device does not exist"));
    }

    #[test]
    fn test_clean_up_before_creation() {
        let _lock = DM_MUTEX.lock().unwrap();

        let device = create_test_setup().device;
        let device_path = device.path().to_path_buf();
        // Forget the device so it doesn't get cleaned up automatically
        #[allow(clippy::mem_forget)] // This is intentional to test cleanup
        std::mem::forget(device);
        assert!(device_path.exists());

        // Create another device to verify that it cleans up the previous one
        let device = create_test_setup();
        drop(device);
        assert!(
            !device_path.exists(),
            "Previous device should be cleaned up"
        );

        assert_mapped_devices_are_cleaned_up();
    }
}
