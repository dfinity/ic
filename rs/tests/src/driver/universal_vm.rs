use super::driver_setup::{
    FARM_BASE_URL, FARM_GROUP_NAME, SSH_AUTHORIZED_PRIV_KEYS_DIR, SSH_AUTHORIZED_PUB_KEYS_DIR,
};
use super::farm::Farm;
use super::ic::VmResources;
use super::resource::AllocatedVm;
use super::resource::{allocate_resources, get_resource_request_for_universal_vm, DiskImage};
use super::test_env::TestEnv;
use super::test_env_api::{retry, RETRY_BACKOFF, RETRY_TIMEOUT};
use anyhow::{bail, Result};
use slog::info;
use ssh2::Session;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
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
const ADMIN_USER: &str = "admin";

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
        let logger = env.logger();
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

            let image_id = farm.upload_file(config_img, CONF_IMG_FNAME)?;
            info!(logger, "Uploaded image: {}", image_id);

            farm.attach_disk_image(&group_name, &self.name, "usb-storage", image_id)?;
        }

        farm.start_vm(&group_name, &self.name)?;
        Ok(())
    }
}

pub trait UniversalVms {
    fn universal_vm(&self, universal_vm_name: &str) -> Result<AllocatedVm>;

    fn universal_vm_path(&self, universal_vm_name: &str) -> PathBuf;

    fn universal_vm_ssh_session(&self, universal_vm_name: &str) -> Result<Session>;

    fn await_universal_vm_ssh_session(&self, universal_vm_name: &str) -> Result<Session>;

    fn await_universal_vm_ipv4(&self, universal_vm_name: &str) -> Result<Ipv4Addr>;

    fn single_activate_script_config_dir(
        &self,
        universal_vm_name: &str,
        activate_script: &str,
    ) -> Result<PathBuf>;
}

impl UniversalVms for TestEnv {
    fn universal_vm(&self, universal_vm_name: &str) -> Result<AllocatedVm> {
        let p: PathBuf = [UNIVERSAL_VMS_DIR, universal_vm_name].iter().collect();
        self.read_object(p.join("vm.json"))
    }
    fn universal_vm_path(&self, universal_vm_name: &str) -> PathBuf {
        let p: PathBuf = [UNIVERSAL_VMS_DIR, universal_vm_name].iter().collect();
        self.get_path(p)
    }

    fn universal_vm_ssh_session(&self, universal_vm_name: &str) -> Result<Session> {
        let vm = self.universal_vm(universal_vm_name)?;
        let tcp = TcpStream::connect((vm.ipv6, 22))?;
        let mut sess = Session::new().unwrap();
        sess.set_tcp_stream(tcp);
        sess.handshake().unwrap();
        let admin_priv_key_path = self.get_path(SSH_AUTHORIZED_PRIV_KEYS_DIR).join(ADMIN_USER);
        sess.userauth_pubkey_file(ADMIN_USER, None, admin_priv_key_path.as_path(), None)?;
        Ok(sess)
    }

    fn await_universal_vm_ssh_session(&self, universal_vm_name: &str) -> Result<Session> {
        retry(self.logger(), RETRY_TIMEOUT, RETRY_BACKOFF, || {
            self.universal_vm_ssh_session(universal_vm_name)
        })
    }

    fn await_universal_vm_ipv4(&self, universal_vm_name: &str) -> Result<Ipv4Addr> {
        let sess = self.await_universal_vm_ssh_session(universal_vm_name)?;
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
        ssh_authorized_pub_keys_dir.join(ADMIN_USER),
        config_dir_ssh_dir.join(ADMIN_USER),
    )?;
    Ok(())
}
