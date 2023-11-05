use crate::driver::resource::AllocatedVm;
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::*;

use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Result};

pub const NESTED_VMS_DIR: &str = "nested_vms";
pub const NESTED_VM_PATH: &str = "vm.json";
pub const NESTED_CONFIGURED_IMAGE_PATH: &str = "config.img.gz";

pub struct NestedNode {
    pub name: String,
}

impl NestedNode {
    pub fn new(name: String) -> Self {
        NestedNode { name }
    }
}

pub struct NestedVm {
    env: TestEnv,
    name: String,
}

impl NestedVm {
    pub fn get_vm(&self) -> Result<AllocatedVm> {
        let rel_dir: PathBuf = [NESTED_VMS_DIR, &self.name].iter().collect();
        let vm_path = rel_dir.join(NESTED_VM_PATH);

        self.env.read_json_object(vm_path)
    }

    pub fn get_configured_setupos_image_path(&self) -> Result<PathBuf> {
        let rel_dir: PathBuf = [NESTED_VMS_DIR, &self.name].iter().collect();
        let image_path = rel_dir.join(NESTED_CONFIGURED_IMAGE_PATH);

        Ok(self.env.get_path(image_path))
    }
}

impl HasTestEnv for NestedVm {
    fn test_env(&self) -> TestEnv {
        self.env.clone()
    }
}

impl HasVmName for NestedVm {
    fn vm_name(&self) -> String {
        self.name.clone()
    }
}

pub trait NestedVms {
    fn get_nested_vm(&self, name: &str) -> Result<NestedVm>;

    fn get_all_nested_vms(&self) -> Result<Vec<NestedVm>>;

    fn write_nested_vm(&self, name: &str, vm: &AllocatedVm) -> Result<()>;
}

impl NestedVms for TestEnv {
    fn get_nested_vm(&self, name: &str) -> Result<NestedVm> {
        let rel_dir: PathBuf = [NESTED_VMS_DIR, name].iter().collect();
        let abs_dir = self.get_path(rel_dir);

        if abs_dir.is_dir() {
            Ok(NestedVm {
                env: self.clone(),
                name: name.to_string(),
            })
        } else {
            bail!("Did not find nested VM '{name}'!")
        }
    }

    fn get_all_nested_vms(&self) -> Result<Vec<NestedVm>> {
        let mut vms = Vec::new();

        let abs_dir = self.get_path(NESTED_VMS_DIR);
        for file in fs::read_dir(abs_dir)? {
            let file = file?;

            if file.file_type()?.is_dir() {
                vms.push(NestedVm {
                    env: self.clone(),
                    name: file.file_name().to_string_lossy().into_owned(),
                });
            }
        }

        Ok(vms)
    }

    fn write_nested_vm(&self, name: &str, vm: &AllocatedVm) -> Result<()> {
        let vm_path: PathBuf = [NESTED_VMS_DIR, name].iter().collect();

        self.write_json_object(vm_path.join(NESTED_VM_PATH), &vm)
    }
}
