use crate::driver::port_allocator::AddrType;
use crate::driver::resource::AllocatedVm;
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::get_ssh_session_from_env;
use crate::driver::test_env_api::*;
use crate::retry_with_msg;
use crate::util::create_agent;
use ic_agent::{Agent, AgentError};

use std::fs;
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;

use anyhow::{bail, Result};
use async_trait::async_trait;
use deterministic_ips::{calculate_deterministic_mac, Deployment, HwAddr, IpVariant};
use serde::{Deserialize, Serialize};
use ssh2::Session;
use url::Url;

pub const NESTED_VMS_DIR: &str = "nested_vms";
pub const NESTED_VM_PATH: &str = "vm.json";
pub const NESTED_CONFIGURED_IMAGE_PATH: &str = "config.img.zst";
pub const NESTED_NETWORK_PATH: &str = "ips.json";

pub struct NestedNode {
    pub name: String,
}

impl NestedNode {
    pub fn new(name: String) -> Self {
        NestedNode { name }
    }
}

#[derive(Serialize, Deserialize)]
pub struct NestedNetwork {
    pub guest_ip: Ipv6Addr,
    pub host_ip: Ipv6Addr,
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

    pub fn get_nested_network(&self) -> Result<NestedNetwork> {
        let rel_dir: PathBuf = [NESTED_VMS_DIR, &self.name].iter().collect();
        let ip_path = rel_dir.join(NESTED_NETWORK_PATH);

        self.env.read_json_object(ip_path)
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
        // Remap the IPv6 addresses based on their deterministic IPs
        let seed_mac = vm.mac6.parse::<HwAddr>().unwrap();
        let old_ip = vm.ipv6;

        // TODO: We transform the IPv6 to get this information, but it could be
        // passed natively.
        let segments = old_ip.segments();
        let prefix = format!(
            "{:04x}:{:04x}:{:04x}:{:04x}",
            segments[0], segments[1], segments[2], segments[3]
        );

        let host_mac =
            calculate_deterministic_mac(seed_mac, Deployment::Mainnet, IpVariant::V6, 0).unwrap();
        let guest_mac =
            calculate_deterministic_mac(seed_mac, Deployment::Mainnet, IpVariant::V6, 1).unwrap();

        let host_ip = host_mac.calculate_slaac(&prefix).unwrap();
        let guest_ip = guest_mac.calculate_slaac(&prefix).unwrap();

        let nested_network = NestedNetwork { guest_ip, host_ip };
        let mapped_vm = AllocatedVm {
            ipv6: host_ip,
            ..vm.clone()
        };

        let vm_path: PathBuf = [NESTED_VMS_DIR, name].iter().collect();
        self.write_json_object(vm_path.join(NESTED_VM_PATH), &mapped_vm)?;
        self.write_json_object(vm_path.join(NESTED_NETWORK_PATH), &nested_network)?;

        Ok(())
    }
}

impl SshSession for NestedVm {
    fn get_ssh_session(&self) -> Result<Session> {
        let vm = self.get_vm()?;
        get_ssh_session_from_env(&self.env, IpAddr::V6(vm.ipv6))
    }

    fn block_on_ssh_session(&self) -> Result<Session> {
        let vm = self.get_vm()?;
        retry_with_msg!(
            format!("get_ssh_session to {}", vm.ipv6.to_string()),
            self.env.logger(),
            SSH_RETRY_TIMEOUT,
            RETRY_BACKOFF,
            || { self.get_ssh_session() }
        )
    }
}

#[async_trait]
impl HasPublicApiUrl for NestedVm {
    fn get_public_url(&self) -> Url {
        let NestedNetwork { guest_ip, .. } = self.get_nested_network().unwrap();

        let url = format!("http://[{}]:{}/", guest_ip, u16::from(AddrType::PublicApi));
        Url::parse(&url).expect("Could not parse Url")
    }

    fn get_public_addr(&self) -> SocketAddr {
        let NestedNetwork { guest_ip, .. } = self.get_nested_network().unwrap();
        SocketAddr::new(IpAddr::V6(guest_ip), AddrType::PublicApi.into())
    }

    async fn try_build_default_agent_async(&self) -> Result<Agent, AgentError> {
        let url = self.get_public_url().to_string();
        create_agent(&url).await
    }
}
