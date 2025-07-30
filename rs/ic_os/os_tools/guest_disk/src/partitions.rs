use grub::BootAlternative;
use std::path::PathBuf;

pub fn partition_setup(boot_alternative: BootAlternative) -> PartitionSetup {
    let mut setup = PartitionSetup {
        efi_partition_device: PathBuf::from("/dev/vda1"),
        grub_partition_device: PathBuf::from("/dev/vda2"),
        config_partition_device: PathBuf::from("/dev/vda3"),
        my_boot_partition_device: PathBuf::from("/dev/vda4"),
        my_root_partition_device: PathBuf::from("/dev/vda5"),
        my_var_partition_device: PathBuf::from("/dev/vda6"),
        alternative_boot_partition_device: PathBuf::from("/dev/vda7"),
        alternative_root_partition_device: PathBuf::from("/dev/vda8"),
        alternative_var_partition_device: PathBuf::from("/dev/vda9"),
        store_partition_device: PathBuf::from("/dev/vda10"),
    };

    match boot_alternative {
        BootAlternative::A => { /* default */ }
        BootAlternative::B => {
            std::mem::swap(
                &mut setup.my_boot_partition_device,
                &mut setup.alternative_boot_partition_device,
            );
            std::mem::swap(
                &mut setup.my_root_partition_device,
                &mut setup.alternative_root_partition_device,
            );
            std::mem::swap(
                &mut setup.my_var_partition_device,
                &mut setup.alternative_var_partition_device,
            );
        }
    }

    setup
}

pub struct PartitionSetup {
    pub efi_partition_device: PathBuf,
    pub grub_partition_device: PathBuf,
    pub config_partition_device: PathBuf,
    pub my_boot_partition_device: PathBuf,
    pub my_root_partition_device: PathBuf,
    pub my_var_partition_device: PathBuf,
    pub alternative_boot_partition_device: PathBuf,
    pub alternative_root_partition_device: PathBuf,
    pub alternative_var_partition_device: PathBuf,
    pub store_partition_device: PathBuf,
}
