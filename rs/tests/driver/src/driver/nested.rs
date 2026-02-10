use crate::driver::farm::VmSpec;
use crate::driver::ic::VmResources;
use crate::driver::port_allocator::AddrType;
use crate::driver::resource::{AllocatedVm, BootImage};
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::*;
use crate::driver::{
    bootstrap::setup_and_start_nested_vms,
    farm::Farm,
    resource::{allocate_resources, get_resource_request_for_nested_nodes},
    test_env::TestEnvAttribute,
    test_setup::GroupSetup,
};
use crate::util::create_agent;
use ic_agent::{Agent, AgentError};

use std::fs;
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;

use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use config_types::DeploymentEnvironment;
use deterministic_ips::node_type::NodeType;
use deterministic_ips::{MacAddr6Ext, calculate_deterministic_mac};
use macaddr::MacAddr6;
use serde::{Deserialize, Serialize};
use slog::info;
use url::Url;

pub const NESTED_VMS_DIR: &str = "nested_vms";
pub const NESTED_VM_PATH: &str = "vm.json";
pub const NESTED_VM_SPEC_PATH: &str = "vm_spec.json";
pub const NESTED_CONFIG_IMAGE_PATH: &str = "config.img.zst";
pub const NESTED_NETWORK_PATH: &str = "ips.json";
pub const NESTED_VM_CONFIG: &str = "nested_vm_config.json";

#[derive(Default)]
pub struct NestedNodes {
    pub nodes: Vec<NestedNode>,
}

impl NestedNodes {
    pub fn new(names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        NestedNodes::new_with_resources(names, VmResources::default())
    }

    pub fn new_with_resources(
        names: impl IntoIterator<Item = impl Into<String>>,
        vm_resources: VmResources,
    ) -> Self {
        NestedNodes {
            nodes: names
                .into_iter()
                .map(|v| NestedNode::new_farm(v.into(), vm_resources))
                .collect(),
        }
    }

    pub fn single_bare_metal(
        name: impl Into<String>,
        host_address: Ipv6Addr,
        mgmt_mac: MacAddr6,
        enable_trusted_execution_environment: bool,
    ) -> Self {
        NestedNodes {
            nodes: vec![NestedNode::new_bare_metal(
                name.into(),
                host_address,
                mgmt_mac,
                enable_trusted_execution_environment,
            )],
        }
    }

    pub fn setup_and_start(&mut self, env: &TestEnv) -> Result<()> {
        let farm = Farm::from_test_env(env, "Internet Computer");

        let group_setup = GroupSetup::read_attribute(env);
        let group_name: String = group_setup.infra_group_name;

        let (bare_metal_nodes, virtual_nodes) =
            self.nodes.iter().cloned().partition::<Vec<_>, _>(|node| {
                matches!(node.node_spec, NestedNodeSpec::BareMetal { .. })
            });

        ensure!(
            bare_metal_nodes.len() <= 1,
            "Maximum one bare metal node is supported"
        );

        if !virtual_nodes.is_empty() {
            let res_request =
                get_resource_request_for_nested_nodes(&virtual_nodes[..], env, &group_name)?;
            let res_group = allocate_resources(&farm, &res_request, env)?;

            for (node, vm_spec) in self.nodes.iter().zip(&res_request.vm_configs) {
                let vm_spec = VmSpec {
                    v_cpus: vm_spec.vcpus.get(),
                    memory_ki_b: vm_spec.memory_kibibytes.get(),
                };
                env.write_nested_vm(
                    &node.name,
                    &vm_spec,
                    &res_group.vms[&node.name],
                    &NestedVmConfig {
                        // TEE not supported in virtual nodes
                        enable_trusted_execution_environment: false,
                    },
                )?;
            }
        }

        if bare_metal_nodes.len() == 1 {
            let NestedNodeSpec::BareMetal {
                enable_trusted_execution_environment,
                ..
            } = bare_metal_nodes[0].node_spec
            else {
                unreachable!();
            };
            let vm = allocated_vm_for_bare_metal_instance(&bare_metal_nodes[0], &group_name)?;
            env.write_nested_vm(
                &bare_metal_nodes[0].name,
                &bare_metal_vm_spec(),
                &vm,
                &NestedVmConfig {
                    enable_trusted_execution_environment,
                },
            )?;
        }

        setup_and_start_nested_vms(env, &farm, &group_name)?;

        Ok(())
    }
}

fn allocated_vm_for_bare_metal_instance(
    node: &NestedNode,
    group_name: &str,
) -> Result<AllocatedVm> {
    let (host_address, mgmt_mac) = match &node.node_spec {
        NestedNodeSpec::BareMetal {
            host_address,
            mgmt_mac,
            ..
        } => (*host_address, *mgmt_mac),
        _ => bail!("Expected bare metal node"),
    };
    Ok(AllocatedVm {
        name: node.name.clone(),
        group_name: group_name.to_string(),
        hostname: "".to_string(),
        ipv6: host_address,
        mac6: mgmt_mac.to_string(),
        ipv4: None,
        bare_metal: true,
    })
}

#[derive(Clone, PartialEq, Eq)]
pub enum NestedNodeSpec {
    Vm(VmResources),
    BareMetal {
        host_address: Ipv6Addr,
        mgmt_mac: MacAddr6,
        enable_trusted_execution_environment: bool,
    },
}

#[derive(Clone)]
pub struct NestedNode {
    pub name: String,
    pub node_spec: NestedNodeSpec,
    pub boot_image: BootImage,
}

impl NestedNode {
    pub fn new_farm(name: String, vm_resources: VmResources) -> Self {
        NestedNode {
            name,
            node_spec: NestedNodeSpec::Vm(vm_resources),
        }
    }

    pub fn new_bare_metal(
        name: String,
        host_address: Ipv6Addr,
        mgmt_mac: MacAddr6,
        enable_trusted_execution_environment: bool,
    ) -> Self {
        NestedNode {
            name,
            node_spec: NestedNodeSpec::BareMetal {
                host_address,
                mgmt_mac,
                enable_trusted_execution_environment,
            },
        }
    }

    pub fn with_boot_image(mut self, boot_image: BootImage) -> Self {
        self.boot_image = boot_image;
        self
    }
}

#[derive(Deserialize, Serialize)]
pub struct NestedNetwork {
    pub guest_ip: Ipv6Addr,
    pub host_ip: Ipv6Addr,
}

#[derive(Clone)]
pub struct NestedVm {
    env: TestEnv,
    name: String,
}

#[derive(Deserialize, Serialize)]
pub struct NestedVmConfig {
    pub enable_trusted_execution_environment: bool,
}

impl NestedVm {
    pub fn get_vm(&self) -> Result<AllocatedVm> {
        let vm_path: PathBuf = [NESTED_VMS_DIR, &self.name, NESTED_VM_PATH]
            .iter()
            .collect();

        self.env.read_json_object(vm_path)
    }

    pub fn get_vm_spec(&self) -> Result<VmSpec> {
        let resources_path: PathBuf = [NESTED_VMS_DIR, &self.name, NESTED_VM_SPEC_PATH]
            .iter()
            .collect();

        self.env.read_json_object(resources_path)
    }

    pub fn get_setupos_config_image_path(&self) -> Result<PathBuf> {
        let image_path: PathBuf = [NESTED_VMS_DIR, &self.name, NESTED_CONFIG_IMAGE_PATH]
            .iter()
            .collect();

        Ok(self.env.get_path(image_path))
    }

    pub fn get_nested_network(&self) -> Result<NestedNetwork> {
        let ip_path: PathBuf = [NESTED_VMS_DIR, &self.name, NESTED_NETWORK_PATH]
            .iter()
            .collect();

        self.env.read_json_object(ip_path)
    }

    pub fn get_nested_vm_config(&self) -> Result<NestedVmConfig> {
        let path: PathBuf = [NESTED_VMS_DIR, &self.name, NESTED_VM_CONFIG]
            .iter()
            .collect();

        self.env.read_json_object(path)
    }

    /// Returns a handle that allows to SSH into the guest OS of the nested VM.
    pub fn get_guest_ssh(&self) -> Result<GuestSsh> {
        let guest_ip = self
            .get_nested_network()
            .context("Failed to get nested network")?
            .guest_ip;
        Ok(GuestSsh {
            env: self.env.clone(),
            ip: guest_ip,
        })
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

pub trait HasNestedVms {
    fn get_nested_vm(&self, name: &str) -> Result<NestedVm>;

    fn get_all_nested_vms(&self) -> Result<Vec<NestedVm>>;

    fn write_nested_vm(
        &self,
        name: &str,
        vm_spec: &VmSpec,
        vm: &AllocatedVm,
        nested_vm_config: &NestedVmConfig,
    ) -> Result<()>;
}

impl HasNestedVms for TestEnv {
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
        if abs_dir.exists() {
            for file in fs::read_dir(abs_dir)? {
                let file = file?;

                if file.file_type()?.is_dir() {
                    vms.push(NestedVm {
                        env: self.clone(),
                        name: file.file_name().to_string_lossy().into_owned(),
                    });
                }
            }
        }

        Ok(vms)
    }

    fn write_nested_vm(
        &self,
        name: &str,
        vm_spec: &VmSpec,
        vm: &AllocatedVm,
        nested_vm_config: &NestedVmConfig,
    ) -> Result<()> {
        // Remap the IPv6 addresses based on their deterministic IPs
        let seed_mac = vm.mac6.parse::<MacAddr6>().unwrap();
        let old_ip = vm.ipv6;

        // TODO: We transform the IPv6 to get this information, but it could be
        // passed natively.
        let segments = old_ip.segments();
        let prefix = format!(
            "{:04x}:{:04x}:{:04x}:{:04x}",
            segments[0], segments[1], segments[2], segments[3]
        );

        let host_mac = calculate_deterministic_mac(
            &seed_mac,
            DeploymentEnvironment::Testnet,
            NodeType::HostOS,
        );
        let guest_mac = calculate_deterministic_mac(
            &seed_mac,
            DeploymentEnvironment::Testnet,
            NodeType::GuestOS,
        );

        let host_ip = host_mac.calculate_slaac(&prefix).unwrap();
        let guest_ip = guest_mac.calculate_slaac(&prefix).unwrap();

        let nested_network = NestedNetwork { guest_ip, host_ip };
        info!(
            self.logger(),
            "Nested network for VM '{name}': Host IP: {host_ip}, Guest IP: {guest_ip}"
        );
        let mapped_vm = AllocatedVm {
            ipv6: host_ip,
            ..vm.clone()
        };

        let vm_path: PathBuf = [NESTED_VMS_DIR, name].iter().collect();
        self.write_json_object(vm_path.join(NESTED_VM_PATH), &mapped_vm)?;
        self.write_json_object(vm_path.join(NESTED_VM_SPEC_PATH), &vm_spec)?;
        self.write_json_object(vm_path.join(NESTED_NETWORK_PATH), &nested_network)?;
        self.write_json_object(vm_path.join(NESTED_VM_CONFIG), &nested_vm_config)?;

        Ok(())
    }
}

impl SshSession for NestedVm {
    fn get_host_ip(&self) -> Result<IpAddr> {
        Ok(self.get_vm()?.ipv6.into())
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

pub struct GuestSsh {
    env: TestEnv,
    ip: Ipv6Addr,
}

impl HasTestEnv for GuestSsh {
    fn test_env(&self) -> TestEnv {
        self.env.clone()
    }
}

impl SshSession for GuestSsh {
    fn get_host_ip(&self) -> Result<IpAddr> {
        Ok(self.ip.into())
    }
}

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub enum UnassignedRecordConfig {
    /// Do not create an UnassignedNodesConfigRecord
    Skip,
    /// Create an UnassignedNodesConfigRecord, ignore version mismatch
    /// between initial GuestOS and SetupOS
    Ignore,
}

impl TestEnvAttribute for UnassignedRecordConfig {
    fn attribute_name() -> String {
        "unassigned_record_config".to_string()
    }
}

pub fn bare_metal_vm_spec() -> VmSpec {
    VmSpec {
        v_cpus: 64,
        memory_ki_b: 490 * 1024 * 1024,
    }
}
