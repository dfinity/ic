use super::resource::AllocatedVm;
use super::test_env::TestEnv;
use crate::prod_tests::driver_setup::mk_logger;
use crate::prod_tests::driver_setup::{FARM_BASE_URL, FARM_GROUP_NAME};
use crate::prod_tests::farm::Farm;
use crate::prod_tests::ic::VmResources;
use crate::prod_tests::resource::{
    allocate_resources, get_resource_request_for_universal_vm, DiskImage,
};
use anyhow::{bail, Result};
use slog::info;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

/// A builder for the initial configuration of a universal VM.
/// See: https://github.com/dfinity-lab/infra/tree/master/farm/universal-vm
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct UniversalVm {
    pub name: String,
    pub vm_resources: VmResources,
    pub has_ipv4: bool,
    pub primary_image: Option<DiskImage>,
    pub config_dir: Option<PathBuf>,
}

const UNIVERSAL_VMS_DIR: &str = "universal_vms";
const CONF_IMG_FNAME: &str = "config_disk.img.zst";

impl UniversalVm {
    pub fn new(name: String) -> Self {
        UniversalVm {
            name,
            vm_resources: Default::default(),
            has_ipv4: true,
            primary_image: Default::default(),
            config_dir: Default::default(),
        }
    }

    pub fn with_vm_resources(mut self, vm_resources: VmResources) -> Self {
        self.vm_resources = vm_resources;
        self
    }

    pub fn disable_ipv4(mut self) -> Self {
        self.has_ipv4 = false;
        self
    }

    pub fn with_primary_image(mut self, primary_image: DiskImage) -> Self {
        self.primary_image = Some(primary_image);
        self
    }

    pub fn with_config_dir(mut self, config_dir: PathBuf) -> Self {
        self.config_dir = Some(config_dir);
        self
    }

    pub fn start(&self, env: &TestEnv) -> Result<()> {
        let group_name: String = env.read_object(FARM_GROUP_NAME)?;
        let logger = mk_logger();
        let farm = Farm::new(env.read_object(FARM_BASE_URL)?, logger.clone());
        let res_request = get_resource_request_for_universal_vm(self, &group_name)?;
        let resource_group = allocate_resources(&farm, &res_request)?;
        let vm = resource_group
            .vms
            .get(&self.name)
            .expect("Expected {self.name} to be allocated!");

        let univm_path: PathBuf = [UNIVERSAL_VMS_DIR, &self.name].iter().collect();
        env.write_object(univm_path.join("vm.json"), vm)?;

        if let Some(config_dir) = self.config_dir.clone() {
            let universal_vm_dir = env.get_path(univm_path);
            let config_img = universal_vm_dir.join(CONF_IMG_FNAME);
            std::fs::create_dir_all(universal_vm_dir)?;

            let mut cmd = Command::new("create-universal-vm-config-image.sh");
            cmd.arg("--input")
                .arg(config_dir)
                .arg("--output")
                .arg(config_img.clone());

            let output = cmd.output()?;
            std::io::stdout().write_all(&output.stdout)?;
            std::io::stderr().write_all(&output.stderr)?;
            if !output.status.success() {
                bail!("could not spawn config image creation process");
            }

            let image_id =
                farm.upload_image(&group_name, config_img, String::from(CONF_IMG_FNAME))?;
            info!(logger, "Uploaded image: {}", image_id);

            farm.attach_disk_image(&group_name, &self.name, "usb-storage", image_id)?;
        }

        farm.start_vm(&group_name, &self.name)?;
        Ok(())
    }
}

pub trait UniversalVms {
    fn universal_vm(&self, name: &str) -> Result<AllocatedVm>;
}

impl UniversalVms for TestEnv {
    fn universal_vm(&self, name: &str) -> Result<AllocatedVm> {
        let p: PathBuf = [UNIVERSAL_VMS_DIR, name].iter().collect();
        self.read_object(p.join("vm.json"))
    }
}
