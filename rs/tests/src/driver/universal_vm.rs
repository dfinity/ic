use super::driver_setup::IcSetup;
use super::driver_setup::SSH_AUTHORIZED_PUB_KEYS_DIR;
use super::farm::Farm;
use super::ic::VmResources;
use super::resource::AllocatedVm;
use super::resource::{allocate_resources, get_resource_request_for_universal_vm, DiskImage};
use super::test_env::{TestEnv, TestEnvAttribute};
use super::test_env_api::{
    get_ssh_session_from_env, retry, HasTestEnv, HasVmName, RetrieveIpv4Addr, SshSession, ADMIN,
    RETRY_BACKOFF, RETRY_TIMEOUT,
};
use crate::driver::test_setup::PotSetup;
use anyhow::{bail, Result};
use slog::info;
use ssh2::Session;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::prelude::PermissionsExt;
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

const CONFIG_DIR_NAME: &str = "config";
const CONFIG_DIR_SSH_AUTHORIZED_KEYS_DIR: &str = "ssh-authorized-keys";

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
        let ic_setup = IcSetup::read_attribute(env);
        let pot_setup = PotSetup::read_attribute(env);
        let logger = env.logger();
        let farm = Farm::new(ic_setup.farm_base_url, logger.clone());
        let res_request = get_resource_request_for_universal_vm(self, &pot_setup.farm_group_name)?;
        let resource_group = allocate_resources(&farm, &res_request)?;
        let vm = resource_group
            .vms
            .get(&self.name)
            .expect("Expected {self.name} to be allocated!");

        let univm_path: PathBuf = [UNIVERSAL_VMS_DIR, &self.name].iter().collect();
        env.write_json_object(univm_path.join("vm.json"), vm)?;

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

            let image_id = farm.upload_file(config_img, CONF_IMG_FNAME)?;
            info!(logger, "Uploaded image: {}", image_id);

            farm.attach_disk_image(
                &pot_setup.farm_group_name,
                &self.name,
                "usb-storage",
                image_id,
            )?;
        }

        farm.start_vm(&pot_setup.farm_group_name, &self.name)?;
        Ok(())
    }
}

pub trait UniversalVms {
    fn get_deployed_universal_vm(&self, name: &str) -> Result<DeployedUniversalVm>;

    fn single_activate_script_config_dir(
        &self,
        universal_vm_name: &str,
        activate_script: &str,
    ) -> Result<PathBuf>;
}

impl UniversalVms for TestEnv {
    fn get_deployed_universal_vm(&self, name: &str) -> Result<DeployedUniversalVm> {
        let rel_universal_vm_dir: PathBuf = [UNIVERSAL_VMS_DIR, name].iter().collect();
        let abs_universal_vm_dir = self.get_path(rel_universal_vm_dir);
        if abs_universal_vm_dir.is_dir() {
            Ok(DeployedUniversalVm {
                env: self.clone(),
                name: name.to_string(),
            })
        } else {
            bail!("Did not find deployed universal VM '{name}'!")
        }
    }

    fn single_activate_script_config_dir(
        &self,
        universal_vm_name: &str,
        activate_script: &str,
    ) -> Result<PathBuf> {
        let p: PathBuf = ["universal_vms", universal_vm_name, CONFIG_DIR_NAME]
            .iter()
            .collect();
        let config_dir = self.get_path(p);
        fs::create_dir_all(config_dir.clone())?;

        setup_ssh(self, config_dir.clone())?;

        let activate_path = config_dir.join("activate");

        let mut activate_file = File::create(&activate_path)?;
        activate_file.write_all(activate_script.as_bytes())?;
        let metadata = activate_file.metadata()?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(activate_path, permissions)?;
        activate_file.sync_all()?;
        Ok(config_dir)
    }
}

fn setup_ssh(env: &TestEnv, config_dir: PathBuf) -> Result<()> {
    let ssh_authorized_pub_keys_dir = env.get_path(SSH_AUTHORIZED_PUB_KEYS_DIR);
    let config_dir_ssh_dir = config_dir.join(CONFIG_DIR_SSH_AUTHORIZED_KEYS_DIR);
    fs::create_dir_all(config_dir_ssh_dir.clone())?;
    fs::copy(
        ssh_authorized_pub_keys_dir.join(ADMIN),
        config_dir_ssh_dir.join(ADMIN),
    )?;
    Ok(())
}

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
    fn get_ssh_session(&self, user: &str) -> Result<Session> {
        let vm = self.get_vm()?;
        get_ssh_session_from_env(&self.env, user, IpAddr::V6(vm.ipv6))
    }

    fn block_on_ssh_session(&self, user: &str) -> Result<Session> {
        retry(self.env.logger(), RETRY_TIMEOUT, RETRY_BACKOFF, || {
            self.get_ssh_session(user)
        })
    }
}

impl RetrieveIpv4Addr for DeployedUniversalVm {
    fn block_on_ipv4(&self) -> Result<Ipv4Addr> {
        let sess = self.block_on_ssh_session(ADMIN)?;
        let mut channel = sess.channel_session()?;
        channel.exec("bash").unwrap();

        let get_ipv4_script = r#"set -e -o pipefail
until ipv4=$(ip -j address show dev enp2s0 \
            | jq -r -e \
            '.[0].addr_info | map(select(.scope == "global")) | .[0].local'); \
do
  sleep 1
done
echo "$ipv4"
"#;
        channel.write_all(get_ipv4_script.as_bytes())?;
        channel.flush()?;
        channel.send_eof()?;
        let mut out = String::new();
        channel.read_to_string(&mut out)?;
        let ipv4 = out.trim().parse::<Ipv4Addr>()?;
        Ok(ipv4)
    }
}
