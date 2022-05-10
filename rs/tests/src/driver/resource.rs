use crate::driver::ic::{AmountOfMemoryKiB, InternetComputer, Node, NrOfVCPUs};
use crate::driver::universal_vm::UniversalVm;
use anyhow;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use url::Url;

use super::farm::Farm;
use super::farm::FarmResult;
use super::farm::ImageLocation;
use super::farm::ImageLocation::{IcOsImageViaUrl, ImageViaUrl};
use super::farm::{CreateVmRequest, HostFeature};
use super::ic::VmAllocationStrategy;
use super::test_env::{TestEnv, TestEnvAttribute};
use crate::driver::driver_setup::IcSetup;

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
    pub image_type: ImageType,
    pub url: Url,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ImageType {
    IcOsImage,
    RawImage,
}

impl From<DiskImage> for ImageLocation {
    fn from(src: DiskImage) -> ImageLocation {
        match src.image_type {
            ImageType::IcOsImage => IcOsImageViaUrl {
                url: src.url.clone(),
                sha256: src.sha256,
            },
            ImageType::RawImage => ImageViaUrl {
                url: src.url.clone(),
                sha256: src.sha256,
            },
        }
    }
}

impl ResourceRequest {
    pub fn new(
        image_type: ImageType,
        primary_image_url: Url,
        primary_image_sha256: String,
    ) -> Self {
        Self {
            group_name: Default::default(),
            primary_image: DiskImage {
                image_type,
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
    pub has_ipv4: bool,
    pub vm_allocation: Option<VmAllocationStrategy>,
    pub required_host_features: Vec<HostFeature>,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct AllocatedVm {
    pub name: String,
    pub group_name: String,
    pub ipv6: Ipv6Addr,
}

/// This translates the configuration structure from InternetComputer to a
/// request for resources (vms)
pub fn get_resource_request(
    config: &InternetComputer,
    test_env: &TestEnv,
    group_name: &str,
) -> anyhow::Result<ResourceRequest> {
    let ic_setup = IcSetup::read_attribute(test_env);
    let url = ic_setup.ic_os_img_url;
    let primary_image_sha256 = ic_setup.ic_os_img_sha256;
    let mut res_req = ResourceRequest::new(ImageType::IcOsImage, url, primary_image_sha256);
    res_req.group_name = group_name.to_string();
    for s in &config.subnets {
        for n in &s.nodes {
            res_req.add_vm_request(vm_spec_from_node(n));
        }
    }
    for n in &config.unassigned_nodes {
        res_req.add_vm_request(vm_spec_from_node(n));
    }
    Ok(res_req)
}

/// The SHA-256 hash of the Universal VM disk image.
/// The latest hash can be retrieved by downloading the SHA256SUMS file from:
/// https://hydra.dfinity.systems/job/dfinity-ci-build/infra/infra.farm.universal-vm.img.x86_64-linux/latest
const DEFAULT_UNIVERSAL_VM_IMG_SHA256: &str =
    "58711b2e9f2760e90237ccf43fbcdc24caa2118220cdd33ea05fd4dcffa32aca";

pub fn get_resource_request_for_universal_vm(
    universal_vm: &UniversalVm,
    group_name: &str,
) -> anyhow::Result<ResourceRequest> {
    let primary_image = universal_vm.primary_image.clone().unwrap_or(DiskImage {
        image_type: ImageType::RawImage,
        url: Url::parse(&format!("https://download.dfinity.systems/farm/universal-vm/{DEFAULT_UNIVERSAL_VM_IMG_SHA256}/x86_64-linux/universal-vm.img.zst")).expect("should not fail!"),
        sha256: String::from(DEFAULT_UNIVERSAL_VM_IMG_SHA256),
    });
    let mut res_req = ResourceRequest::new(
        primary_image.image_type.clone(),
        primary_image.url.clone(),
        primary_image.sha256,
    );
    res_req.group_name = group_name.to_string();
    let vm_resources = universal_vm.vm_resources;
    res_req.add_vm_request(VmSpec {
        name: universal_vm.name.clone(),
        vcpus: vm_resources.vcpus.unwrap_or(DEFAULT_VCPUS_PER_VM),
        memory_kibibytes: vm_resources
            .memory_kibibytes
            .unwrap_or(DEFAULT_MEMORY_KIB_PER_VM),
        boot_image: BootImage::GroupDefault,
        has_ipv4: universal_vm.has_ipv4,
        vm_allocation: universal_vm.vm_allocation.clone(),
        required_host_features: universal_vm.required_host_features.clone(),
    });
    Ok(res_req)
}

pub fn allocate_resources(farm: &Farm, req: &ResourceRequest) -> FarmResult<ResourceGroup> {
    let group_name = &req.group_name;
    let mut res_group = ResourceGroup::new(group_name.clone());
    for vm_config in req.vm_configs.iter() {
        let name = vm_config.name.clone();
        let create_vm_request = CreateVmRequest::new(
            name.clone(),
            vm_config.vcpus,
            vm_config.memory_kibibytes,
            match &vm_config.boot_image {
                BootImage::GroupDefault => From::from(req.primary_image.clone()),
                BootImage::Image(disk_image) => From::from(disk_image.clone()),
            },
            vm_config.has_ipv4,
            vm_config.vm_allocation.clone(),
            vm_config.required_host_features.clone(),
        );

        let created_vm = farm.create_vm(group_name, create_vm_request)?;
        res_group.add_vm(AllocatedVm {
            name,
            group_name: group_name.clone(),
            ipv6: created_vm.ipv6,
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
        has_ipv4: false,
        vm_allocation: n.vm_allocation.clone(),
        required_host_features: n.required_host_features.clone(),
    }
}
