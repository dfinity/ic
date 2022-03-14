use crate::prod_tests::ic::{AmountOfMemoryKiB, InternetComputer, Node, NrOfVCPUs};
use slog::info;
use std::collections::BTreeMap;
use std::net::IpAddr;
use url::Url;

use super::driver_setup::DriverContext;
use super::farm::{CreateVmRequest, PrimaryImage};
use crate::prod_tests::farm::FarmResult;

const DEFAULT_VCPUS_PER_VM: NrOfVCPUs = NrOfVCPUs::new(4);
const DEFAULT_MEMORY_KIB_PER_VM: AmountOfMemoryKiB = AmountOfMemoryKiB::new(25165824); // 24GiB

/// A declaration of resources needed to instantiate a InternetComputer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResourceRequest {
    pub group_name: String,
    pub primary_image: DiskImage,
    /// By internal contract, for the initial allocation of resources, the
    /// position of the AllocatedVm reflects the node index.
    pub vm_configs: Vec<VmSpec>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiskImage {
    url: Url,
    sha256: String,
}

impl ResourceRequest {
    pub fn new(primary_image_url: Url, primary_image_sha256: String) -> Self {
        Self {
            group_name: Default::default(),
            primary_image: DiskImage {
                url: primary_image_url,
                sha256: primary_image_sha256,
            },
            vm_configs: Default::default(),
        }
    }

    /// For the initial resource request, this function should be called in the
    /// order of the node index.
    fn add_vm_request(&mut self, vm_config: VmSpec) {
        self.vm_configs.push(vm_config)
    }
}

/// Virtual machine configuration as to be requested.
/// At first, the set of possible configurations is just a singleton: We assume
/// that there is only one possible VM configuration available.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VmSpec {
    pub name: String,
    pub vcpus: NrOfVCPUs,
    pub memory_kibibytes: AmountOfMemoryKiB,
    pub boot_image: BootImage,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum BootImage {
    GroupDefault,
    Image(DiskImage),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResourceGroup {
    pub group_name: String,
    pub vms: BTreeMap<String, AllocatedVm>,
}

impl ResourceGroup {
    pub fn new<S: ToString>(group_name: S) -> Self {
        Self {
            group_name: group_name.to_string(),
            vms: Default::default(),
        }
    }

    pub fn add_vm(&mut self, allocated_vm: AllocatedVm) {
        self.vms.insert(allocated_vm.name.clone(), allocated_vm);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AllocatedVm {
    pub name: String,
    pub group_name: String,
    pub ip_addr: IpAddr,
}

/// This translates the configuration structure from InternetComputer to a
/// request for resources (vms)
pub fn get_resource_request(
    ctx: &DriverContext,
    config: &InternetComputer,
    group_name: &str,
) -> ResourceRequest {
    let url = ctx.base_img_url.clone();
    let primary_image_sha256 = ctx.base_img_sha256.clone();
    let mut res_req = ResourceRequest::new(url, primary_image_sha256);
    res_req.group_name = group_name.to_string();
    for s in &config.subnets {
        for n in &s.nodes {
            res_req.add_vm_request(vm_spec_from_node(n));
        }
    }
    for n in &config.unassigned_nodes {
        res_req.add_vm_request(vm_spec_from_node(n));
    }
    res_req
}

pub fn allocate_resources(ctx: &DriverContext, req: &ResourceRequest) -> FarmResult<ResourceGroup> {
    let group_name = &req.group_name;
    let mut res_group = ResourceGroup::new(group_name.clone());
    for vm_config in req.vm_configs.iter() {
        let name = vm_config.name.clone();
        let create_vm_request = CreateVmRequest::new(
            name.clone(),
            vm_config.vcpus,
            vm_config.memory_kibibytes,
            match &vm_config.boot_image {
                BootImage::GroupDefault => PrimaryImage::new(
                    req.primary_image.url.clone(),
                    req.primary_image.sha256.clone(),
                ),
                BootImage::Image(DiskImage { url, sha256 }) => {
                    PrimaryImage::new(url.clone(), sha256.clone())
                }
            },
        );

        let ip_addr = ctx.farm.create_vm(group_name, create_vm_request)?;
        info!(ctx.logger, "VM({}) IP-Addr: {}", name, ip_addr);
        res_group.add_vm(AllocatedVm {
            name,
            group_name: group_name.clone(),
            ip_addr,
        });
    }
    Ok(res_group)
}

fn vm_spec_from_node(n: &Node) -> VmSpec {
    let vm_resources = &n.vm_resources;
    VmSpec {
        name: n.id().to_string(),
        vcpus: vm_resources.vcpus.unwrap_or(DEFAULT_VCPUS_PER_VM),
        memory_kibibytes: vm_resources
            .memory_kibibytes
            .unwrap_or(DEFAULT_MEMORY_KIB_PER_VM),
        boot_image: BootImage::GroupDefault,
    }
}
