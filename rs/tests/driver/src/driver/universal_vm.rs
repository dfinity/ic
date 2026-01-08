use crate::driver::driver_setup::SSH_AUTHORIZED_PUB_KEYS_DIR;
use crate::driver::farm::AttachImageSpec;
use crate::driver::farm::ClaimResult;
use crate::driver::farm::Farm;
use crate::driver::farm::HostFeature;
use crate::driver::farm::id_of_file;
use crate::driver::ic::VmAllocationStrategy;
use crate::driver::ic::VmResources;
use crate::driver::resource::AllocatedVm;
use crate::driver::resource::{
    DiskImage, allocate_resources, get_resource_request_for_universal_vm,
};
use crate::driver::test_env::SshKeyGen;
use crate::driver::test_env::{TestEnv, TestEnvAttribute};
use crate::driver::test_env_api::{HasTestEnv, HasVmName, RetrieveIpv4Addr, SshSession};
use crate::driver::test_setup::{GroupSetup, InfraProvider};
use anyhow::{Result, bail};
use chrono::Duration;
use chrono::Utc;
use slog::info;
use std::fs::{self, File};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::prelude::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

use crate::driver::constants::SSH_USERNAME;

/// A builder for the initial configuration of a universal VM.
/// See: https://github.com/dfinity-lab/farm/tree/master/universal-vm
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct UniversalVm {
    pub name: String,
    pub vm_resources: VmResources,
    pub vm_allocation: Option<VmAllocationStrategy>,
    pub required_host_features: Vec<HostFeature>,
    pub has_ipv4: bool,
    pub primary_image: Option<DiskImage>,
    pub config: Option<UniversalVmConfig>,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub enum UniversalVmConfig {
    Dir(PathBuf),
    Img(PathBuf),
}

pub const UNIVERSAL_VMS_DIR: &str = "universal_vms";
const CONF_IMG_FNAME: &str = "config_disk.img.zst";
const CONF_SSH_IMG_FNAME: &str = "config_ssh_disk.img.zst";

const CONFIG_DIR_NAME: &str = "config";
const CONFIG_SSH_DIR_NAME: &str = "config-ssh";
const CONFIG_DIR_SSH_AUTHORIZED_KEYS_DIR: &str = "ssh-authorized-keys";

const CREATE_UVM_CONFIG_IMAGE_SH: &[u8] =
    include_bytes!("../../assets/create-universal-vm-config-image.sh");

impl UniversalVm {
    pub fn new(name: String) -> Self {
        UniversalVm {
            name,
            vm_resources: Default::default(),
            vm_allocation: Default::default(),
            required_host_features: Default::default(),
            has_ipv4: false,
            primary_image: Default::default(),
            config: Default::default(),
        }
    }

    pub fn with_vm_resources(mut self, vm_resources: VmResources) -> Self {
        self.vm_resources = vm_resources;
        self
    }

    pub fn with_vm_allocation(mut self, vm_allocation: VmAllocationStrategy) -> Self {
        self.vm_allocation = Some(vm_allocation);
        self
    }

    pub fn with_required_host_features(mut self, required_host_features: Vec<HostFeature>) -> Self {
        self.required_host_features = required_host_features;
        self
    }

    pub fn enable_ipv4(mut self) -> Self {
        self.has_ipv4 = true;
        self
    }

    pub fn with_primary_image(mut self, primary_image: DiskImage) -> Self {
        self.primary_image = Some(primary_image);
        self
    }

    pub fn with_config_dir(mut self, config_dir: PathBuf) -> Self {
        self.config = Some(UniversalVmConfig::Dir(config_dir));
        self
    }

    pub fn with_config_img(mut self, config_img: PathBuf) -> Self {
        self.config = Some(UniversalVmConfig::Img(config_img));
        self
    }

    pub fn start(&self, env: &TestEnv) -> Result<()> {
        let farm = Farm::from_test_env(env, "universal VM");
        let pot_setup = GroupSetup::read_attribute(env);

        env.ssh_keygen()?;
        let res_request =
            get_resource_request_for_universal_vm(self, &pot_setup, &pot_setup.infra_group_name)?;
        let resource_group = allocate_resources(&farm, &res_request, env)?;
        let vm = resource_group
            .vms
            .get(&self.name)
            .expect("Expected {self.name} to be allocated!");

        let univm_path: PathBuf = [UNIVERSAL_VMS_DIR, &self.name].iter().collect();
        env.write_json_object(univm_path.join("vm.json"), vm)?;
        let universal_vm_dir = env.get_path(univm_path);

        let mut image_specs = vec![];
        if InfraProvider::read_attribute(env) == InfraProvider::Farm {
            // Setup SSH image
            let config_ssh_dir = env.get_universal_vm_config_ssh_dir(&self.name);
            setup_ssh(env, config_ssh_dir.clone())?;
            let config_ssh_img = universal_vm_dir.join(CONF_SSH_IMG_FNAME);
            create_universal_vm_config_image(&config_ssh_dir, &config_ssh_img, "SSH")?;

            let ssh_config_img_file_spec = AttachImageSpec::new(farm.upload_file(
                &pot_setup.infra_group_name,
                config_ssh_img,
                CONF_SSH_IMG_FNAME,
            )?);
            image_specs.push(ssh_config_img_file_spec);
        }

        // Setup config image
        if let Some(config) = &self.config {
            let config_img = match config {
                UniversalVmConfig::Dir(config_dir) => {
                    let config_img = universal_vm_dir.join(CONF_IMG_FNAME);
                    std::fs::create_dir_all(universal_vm_dir)?;
                    create_universal_vm_config_image(config_dir, &config_img, "CONFIG")?;
                    config_img
                }
                UniversalVmConfig::Img(config_img) => config_img.to_path_buf(),
            };

            if InfraProvider::read_attribute(env) == InfraProvider::Farm {
                let file_id = id_of_file(config_img.clone())?;
                let mut file_spec = AttachImageSpec::new(file_id.clone());

                let upload = match farm.claim_file(&pot_setup.infra_group_name, &file_id)? {
                    ClaimResult::FileClaimed(file_expiration) => {
                        if let Some(expiration) = file_expiration.expiration {
                            let now = Utc::now();
                            let ttl = expiration - now;
                            // If the file expires within a day we upload it again
                            // to ensure it exists for at least a month.
                            ttl < Duration::days(1)
                        } else {
                            // If there's no expiration time we assume the file never expires
                            // so we don't need to upload it again.
                            false
                        }
                    }
                    ClaimResult::FileNotFound => true,
                };

                if upload {
                    file_spec = AttachImageSpec::new(farm.upload_file(
                        &pot_setup.infra_group_name,
                        config_img,
                        CONF_IMG_FNAME,
                    )?);
                    info!(env.logger(), "Uploaded image: {}", file_id);
                } else {
                    info!(
                        env.logger(),
                        "Image: {} was already uploaded, no need to upload it again", file_id,
                    );
                }
                image_specs.push(file_spec);
            }
        }

        if InfraProvider::read_attribute(env) == InfraProvider::Farm {
            farm.attach_disk_images(
                &pot_setup.infra_group_name,
                &self.name,
                "usb-storage",
                image_specs,
            )?;
            farm.start_vm(&pot_setup.infra_group_name, &self.name)?;
        }

        Ok(())
    }
}

fn create_universal_vm_config_image(
    input_dir: &PathBuf,
    output_img: &Path,
    label: &str,
) -> Result<()> {
    // pipe the uvm creation script into bash
    let mut cmd = Command::new("/bin/bash")
        .stdin(Stdio::piped())
        // with .spawn() the parent's stdout & stderr are inherited
        .arg("-s")
        .arg("--") // run script from stdin
        .arg("--input")
        .arg(input_dir)
        .arg("--output")
        .arg(output_img)
        .arg("--label")
        .arg(label)
        .spawn()?;

    cmd.stdin
        .take()
        .expect("could not open stdin")
        .write_all(CREATE_UVM_CONFIG_IMAGE_SH)?;

    if !cmd.wait_with_output()?.status.success() {
        bail!("could not spawn config image creation process");
    }
    Ok(())
}

pub trait UniversalVms {
    fn get_deployed_universal_vm_dir(&self, name: &str) -> PathBuf;

    fn get_deployed_universal_vm(&self, name: &str) -> Result<DeployedUniversalVm>;

    fn get_universal_vm_config_dir(&self, universal_vm_name: &str) -> PathBuf;

    fn get_universal_vm_config_ssh_dir(&self, universal_vm_name: &str) -> PathBuf;

    fn single_activate_script_config_dir(
        &self,
        universal_vm_name: &str,
        activate_script: &str,
    ) -> Result<PathBuf>;
}

impl UniversalVms for TestEnv {
    fn get_deployed_universal_vm_dir(&self, name: &str) -> PathBuf {
        let rel_universal_vm_dir: PathBuf = [UNIVERSAL_VMS_DIR, name].iter().collect();
        self.get_path(rel_universal_vm_dir)
    }

    fn get_deployed_universal_vm(&self, name: &str) -> Result<DeployedUniversalVm> {
        let universal_vm_dir = self.get_deployed_universal_vm_dir(name);
        if universal_vm_dir.is_dir() {
            Ok(DeployedUniversalVm {
                env: self.clone(),
                name: name.to_string(),
            })
        } else {
            bail!("Did not find deployed universal VM '{name}'!")
        }
    }

    fn get_universal_vm_config_dir(&self, universal_vm_name: &str) -> PathBuf {
        let p: PathBuf = [UNIVERSAL_VMS_DIR, universal_vm_name, CONFIG_DIR_NAME]
            .iter()
            .collect();
        self.get_path(p)
    }

    fn get_universal_vm_config_ssh_dir(&self, universal_vm_name: &str) -> PathBuf {
        let p: PathBuf = [UNIVERSAL_VMS_DIR, universal_vm_name, CONFIG_SSH_DIR_NAME]
            .iter()
            .collect();
        self.get_path(p)
    }

    fn single_activate_script_config_dir(
        &self,
        universal_vm_name: &str,
        activate_script: &str,
    ) -> Result<PathBuf> {
        let config_dir = self.get_universal_vm_config_dir(universal_vm_name);
        fs::create_dir_all(config_dir.clone())?;
        // copy activate script to Universal VM
        let _ = insert_file_to_config(config_dir.clone(), "activate", activate_script.as_bytes());
        Ok(config_dir)
    }
}

pub fn insert_file_to_config(config_dir: PathBuf, file_name: &str, content: &[u8]) -> Result<()> {
    let activate_path = config_dir.join(file_name);

    let mut activate_file = File::create(&activate_path)?;
    activate_file.write_all(content)?;
    let metadata = activate_file.metadata()?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(activate_path, permissions)?;
    activate_file.sync_all()?;
    Ok(())
}

fn setup_ssh(env: &TestEnv, config_dir: PathBuf) -> Result<()> {
    let ssh_authorized_pub_keys_dir = env.get_path(SSH_AUTHORIZED_PUB_KEYS_DIR);
    let config_dir_ssh_dir = config_dir.join(CONFIG_DIR_SSH_AUTHORIZED_KEYS_DIR);
    fs::create_dir_all(config_dir_ssh_dir.clone())?;
    fs::copy(
        ssh_authorized_pub_keys_dir.join(SSH_USERNAME),
        config_dir_ssh_dir.join(SSH_USERNAME),
    )?;
    Ok(())
}

#[derive(Debug)]
pub struct DeployedUniversalVm {
    env: TestEnv,
    name: String,
}

impl HasTestEnv for DeployedUniversalVm {
    fn test_env(&self) -> TestEnv {
        self.env.clone()
    }
}

impl HasVmName for DeployedUniversalVm {
    fn vm_name(&self) -> String {
        self.name.clone()
    }
}

impl DeployedUniversalVm {
    pub fn get_vm(&self) -> Result<AllocatedVm> {
        let p: PathBuf = [UNIVERSAL_VMS_DIR, &self.name].iter().collect();
        self.env.read_json_object(p.join("vm.json"))
    }
}

impl SshSession for DeployedUniversalVm {
    fn get_host_ip(&self) -> Result<IpAddr> {
        Ok(self.get_vm()?.ipv6.into())
    }
}

const IPV4_RETRIEVE_SH_SCRIPT: &str = r#"set -e -o pipefail
count=0
until ipv4=$(ip -j address show dev enp2s0 \
            | jq -r -e \
            '.[0].addr_info | map(select(.scope == "global")) | .[0].local'); \
do
  if [ "$count" -ge 120 ]; then
    echo "Timed out waiting for IPv4 address!" >&2
    exit 1
  fi
  sleep 1
  count=$((count+1))
done
echo "$ipv4"
"#;

impl RetrieveIpv4Addr for DeployedUniversalVm {
    fn block_on_ipv4(&self) -> Result<Ipv4Addr> {
        use anyhow::Context;
        let ipv4_string = self.block_on_bash_script(IPV4_RETRIEVE_SH_SCRIPT)?;
        ipv4_string
            .trim()
            .parse::<Ipv4Addr>()
            .context("ipv4 retrieval")
    }
}
