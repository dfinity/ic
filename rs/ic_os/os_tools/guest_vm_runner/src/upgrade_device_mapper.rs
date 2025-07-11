use crate::device_mapping::{BaseDevice, LinearSegment, MappedDevice, TempDevice};
use anyhow::{bail, ensure, Context, Result};
use devicemapper::{DevId, DmName, DmOptions, Sectors, DM};
use std::path::Path;
use std::sync::Arc;

const UPGRADE_DM_NAME: &'static str = "upgrade-guestos";
const DATA_PARTITION_DM_NAME: &'static str = "guestos-data";
const DATA_PARTITION_WRITETHROUGH_DM_NAME: &'static str = "guestos-data-writethrough";

const ALL_DM_NAMES_IN_CLEANUP_ORDER: [&'static str; 3] = [
    // Cleanup order is the reverse of creation order in create_device_for_upgrade.
    UPGRADE_DM_NAME,
    DATA_PARTITION_WRITETHROUGH_DM_NAME,
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
pub fn create_mapped_device(base_device: &Path) -> Result<MappedDevice> {
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
///   - data partition device:
///         Maps just the data partition of the base device.
///   - data partition device with snapshot:
///         Writes are persisted to the snapshot instead of the original device.
///   - upgrade device:
///         The merger of the base device and the newly created data partition device.
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
            Box::new(base_device),
            data_partition_start,
            data_partition_len,
        )],
    )
    .context("Failed to create data partition device")?;

    // Create cached data partition that writes to the temporary device
    let cached_data_partition_device = MappedDevice::create_snapshot_table(
        dev_mapper.clone(),
        DATA_PARTITION_WRITETHROUGH_DM_NAME,
        Box::new(readonly_data_partition_device),
        Box::new(
            TempDevice::new(Sectors(1024 * 1024))
                .context("Failed to create temporary device for copy-on-write")?,
        ),
    )
    .context("Failed to create cached data partition device")?;

    // Create final upgrade VM device with all segments
    MappedDevice::create_linear(
        dev_mapper,
        UPGRADE_DM_NAME,
        vec![
            // Read-write section: GPT + first 9 partitions
            LinearSegment::prefix(Box::new(base_device), data_partition_start),
            // Read-only section: data partition
            LinearSegment::full(Box::new(cached_data_partition_device)),
            // Read-write section: whatever is left at the end of the device (backup GPT)
            LinearSegment::suffix(
                Box::new(base_device),
                data_partition_start + data_partition_len,
            ),
        ],
        /*readonly=*/ false,
    )
    .context("Failed to create upgrade device")
}

fn cleanup_devices(dev_mapper: &DM) {
    let devices = match dev_mapper.list_devices() {
        Ok(devices) => devices,
        Err(err) => {
            eprintln!("Failed to list devices: {}", err);
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
                if retry < MAX_RETRIES {
                    std::thread::sleep(std::time::Duration::from_secs(RETRY_DELAY_SECS));
                }
            }
        }
    }
}

#[cfg(all(test, feature = "upgrade_device_mapper_test"))]
mod tests {
    use super::*;
    use crate::device_mapping::LoopDeviceWrapper;
    use gpt::GptConfig;
    use loopdev::LoopControl;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::unix::fs::FileExt;
    use tempfile::NamedTempFile;

    #[test]
    fn test_create_mapped_device() {
        let backing_file = NamedTempFile::new().expect("Failed to create temporary file");
        backing_file
            .as_file()
            .set_len(1024 * 1024)
            .expect("Failed to set file length");

        let backing_file = backing_file.into_temp_path();

        let base = LoopDeviceWrapper(
            LoopControl::open()
                .expect("Failed to open loop control")
                .next_free()
                .expect("Failed to find free loop device"),
        );

        base.attach_file(&backing_file)
            .expect("Failed to attach file to loop device");
        let base_path = base.path().expect("Failed to get loop device path");

        let mut gpt = GptConfig::new()
            .writable(true)
            .create(&base_path)
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

        let device = create_mapped_device(&base_path).expect("Failed to create mapped device");

        let partition3_start_bytes = gpt.partitions().get(&3).unwrap().first_lba * 512;
        let partition10_start_bytes = gpt.partitions().get(&10).unwrap().first_lba * 512;

        let mut upgrade_device = File::options()
            .write(true)
            .read(true)
            .open(device.path())
            .expect("Failed to open device file");
        upgrade_device
            .write_at(b"foo", partition3_start_bytes)
            .expect("Failed to write to device file");
        upgrade_device
            .write_at(b"bar", partition10_start_bytes)
            .expect("Failed to write to device file");
        drop(upgrade_device);

        let mut upgrade_device =
            File::open(device.path()).expect("Failed to open device file after write");
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

        let mut file = File::open(backing_file).expect("Failed to open backing file");
        let mut read_buf = vec![0; 3];
        file.read_at(&mut read_buf, partition3_start_bytes)
            .expect("Failed to read from backing file");
        // Check that the read-write partition is written to the backing file
        assert_eq!(read_buf, b"foo");

        file.read_at(&mut read_buf, partition10_start_bytes)
            .expect("Failed to read from backing file");
        // Check that the read-only partition is not written to the backing file
        assert_eq!(read_buf, &[0, 0, 0]);
    }
}
