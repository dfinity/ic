use anyhow::Context;
use config_types::{GuestOSConfig, GuestVMType};
use grub::{BootAlternative, GrubEnv};
use std::path::{Path, PathBuf};

pub fn partition_setup() -> PartitionSetup {
    // let mut boot_alternative = grub_env.boot_alternative?;
    //
    // let boot_alternative = match guestos_config.guest_vm_type {
    //     GuestVMType::Default => boot_alternative,
    //     GuestVMType::Upgrade => boot_alternative.get_opposite()
    // };
    //
    // let path = match boot_alternative {
    //     BootAlternative::A => PathBuf::from("/dev/vda6"),
    //     BootAlternative::B => PathBuf::from("/dev/vda9")
    // };

    PartitionSetup {
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
    }
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
