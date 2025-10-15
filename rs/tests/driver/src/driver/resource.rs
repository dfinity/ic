use crate::driver::farm::FarmResult;
use crate::driver::farm::FileId;
use crate::driver::farm::ImageLocation;
use crate::driver::farm::ImageLocation::{IcOsImageViaUrl, ImageViaUrl};
use crate::driver::farm::VMCreateResponse;
use crate::driver::farm::{CreateVmRequest, HostFeature};
use crate::driver::farm::{Farm, VmType};
use crate::driver::ic::{AmountOfMemoryKiB, InternetComputer, Node, NrOfVCPUs};
use crate::driver::ic::{ImageSizeGiB, VmAllocationStrategy, VmResources};
use crate::driver::nested::NestedNode;
use crate::driver::test_env::{TestEnv, TestEnvAttribute};
use crate::driver::test_env_api::{
    get_empty_disk_img_sha256, get_empty_disk_img_url, get_guestos_img_sha256, get_guestos_img_url,
};
use crate::driver::test_setup::{GroupSetup, InfraProvider};
use crate::driver::universal_vm::UniversalVm;
use anyhow;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use url::Url;

const DEFAULT_VCPUS_PER_VM: NrOfVCPUs = NrOfVCPUs::new(6);
const DEFAULT_MEMORY_KIB_PER_VM: AmountOfMemoryKiB = AmountOfMemoryKiB::new(25165824); // 24GiB

pub const HOSTOS_VCPUS_PER_VM: NrOfVCPUs = NrOfVCPUs::new(32);
pub const HOSTOS_MEMORY_KIB_PER_VM: AmountOfMemoryKiB = AmountOfMemoryKiB::new(33554432); // 32GiB

/// A declaration of resources needed to instantiate a InternetComputer.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct ResourceRequest {
    pub group_name: String,
    pub primary_image: DiskImage,
    /// By internal contract, for the initial allocation of resources, the
    /// position of the AllocatedVm reflects the node index.
    pub vm_configs: Vec<VmSpec>,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize)]
pub struct DiskImage {
    pub image_type: ImageType,
    pub url: Url,
    pub sha256: String,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize)]
pub enum ImageType {
    IcOsImage,
    PrometheusImage,
    UniversalImage,
}

impl From<DiskImage> for ImageLocation {
    fn from(src: DiskImage) -> ImageLocation {
        match src.image_type {
            ImageType::IcOsImage => IcOsImageViaUrl {
                url: src.url.clone(),
                sha256: src.sha256,
            },
            _ => ImageViaUrl {
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
/// At first, the set of possible configurations is just a singleton:
/// We assume that there is only one possible VM configuration available.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct VmSpec {
    pub name: String,
    pub vcpus: NrOfVCPUs,
    pub memory_kibibytes: AmountOfMemoryKiB,
    pub boot_image: BootImage,
    pub boot_image_minimal_size_gibibytes: Option<ImageSizeGiB>,
    pub has_ipv4: bool,
    pub vm_allocation: Option<VmAllocationStrategy>,
    pub required_host_features: Vec<HostFeature>,
    pub alternate_template: Option<VmType>,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub enum BootImage {
    GroupDefault,
    Image(DiskImage),
    File(FileId),
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
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

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize)]
pub struct AllocatedVm {
    pub name: String,
    pub group_name: String,
    pub hostname: String,
    pub ipv6: Ipv6Addr,
    pub mac6: String,
    pub ipv4: Option<Ipv4Addr>,
}

/// This translates the configuration structure from InternetComputer to a
/// request for resources (vms)
pub fn get_resource_request(
    config: &InternetComputer,
    test_env: &TestEnv,
    group_name: &str,
) -> anyhow::Result<ResourceRequest> {
    let (ic_os_img_sha256, ic_os_img_url) = (get_guestos_img_sha256(), get_guestos_img_url());

    let mut res_req = ResourceRequest::new(ImageType::IcOsImage, ic_os_img_url, ic_os_img_sha256);
    let group_setup = GroupSetup::read_attribute(test_env);
    let default_vm_resources = group_setup.default_vm_resources;
    res_req.group_name = group_name.to_string();
    for s in &config.subnets {
        for n in &s.nodes {
            res_req.add_vm_request(vm_spec_from_node(n, default_vm_resources));
        }
    }
    for n in &config.unassigned_nodes {
        res_req.add_vm_request(vm_spec_from_node(n, default_vm_resources));
    }
    for n in &config.api_boundary_nodes {
        res_req.add_vm_request(vm_spec_from_node(n, default_vm_resources));
    }
    Ok(res_req)
}

/// Create a `ResourceRequest` for a set of nested nodes.
pub fn get_resource_request_for_nested_nodes(
    nodes: &[NestedNode],
    test_env: &TestEnv,
    group_name: &str,
) -> anyhow::Result<ResourceRequest> {
    let empty_disk_img_url = get_empty_disk_img_url()?;
    let empty_disk_img_sha256 = get_empty_disk_img_sha256()?;

    // Add a VM request for each node.
    let mut res_req = ResourceRequest::new(
        ImageType::IcOsImage,
        empty_disk_img_url,
        empty_disk_img_sha256,
    );
    let group_setup = GroupSetup::read_attribute(test_env);
    let default_vm_resources = group_setup.default_vm_resources;
    res_req.group_name = group_name.to_string();
    for node in nodes {
        res_req.add_vm_request(vm_spec_from_nested_node(node, default_vm_resources));
    }

    Ok(res_req)
}

/// The SHA-256 hash of the Universal VM disk image.
/// The latest hash can be retrieved by downloading the SHA256SUMS file from:
/// https://hydra-int.dfinity.systems/job/dfinity-ci-build/farm/universal-vm.img.x86_64-linux/latest
const DEFAULT_UNIVERSAL_VM_IMG_SHA256: &str =
    "36977fe6e829631376dd0bc4b1a8e05b53a7e3a0248a6373f1d7fbdae4bc00ed";

pub fn get_resource_request_for_universal_vm(
    universal_vm: &UniversalVm,
    group_setup: &GroupSetup,
    group_name: &str,
) -> anyhow::Result<ResourceRequest> {
    let primary_image = universal_vm.primary_image.clone().unwrap_or_else(|| DiskImage {
        image_type: ImageType::UniversalImage,
        url: Url::parse(&format!("http://download.proxy-global.dfinity.network:8080/farm/universal-vm/{DEFAULT_UNIVERSAL_VM_IMG_SHA256}/x86_64-linux/universal-vm.img.zst")).expect("should not fail!"),
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
        vcpus: vm_resources.vcpus.unwrap_or_else(|| {
            group_setup
                .default_vm_resources
                .and_then(|vm_resources| vm_resources.vcpus)
                .unwrap_or(DEFAULT_VCPUS_PER_VM)
        }),
        memory_kibibytes: vm_resources.memory_kibibytes.unwrap_or_else(|| {
            group_setup
                .default_vm_resources
                .and_then(|vm_resources| vm_resources.memory_kibibytes)
                .unwrap_or(DEFAULT_MEMORY_KIB_PER_VM)
        }),
        boot_image: BootImage::GroupDefault,
        boot_image_minimal_size_gibibytes: vm_resources.boot_image_minimal_size_gibibytes.or_else(
            || {
                group_setup
                    .default_vm_resources
                    .and_then(|vm_resources| vm_resources.boot_image_minimal_size_gibibytes)
            },
        ),
        has_ipv4: universal_vm.has_ipv4,
        vm_allocation: universal_vm.vm_allocation.clone(),
        required_host_features: universal_vm.required_host_features.clone(),
        alternate_template: None,
    });
    Ok(res_req)
}

pub fn allocate_resources(
    farm: &Farm,
    req: &ResourceRequest,
    env: &TestEnv,
) -> FarmResult<ResourceGroup> {
    let group_name = req.group_name.clone();

    let mut threads = vec![];
    for vm_config in req.vm_configs.iter() {
        let farm_cloned = farm.clone();
        let vm_name = vm_config.name.clone();
        let create_vm_request = CreateVmRequest::new(
            vm_name.clone(),
            vm_config
                .alternate_template
                .clone()
                .unwrap_or(VmType::Production),
            vm_config.vcpus,
            vm_config.memory_kibibytes,
            vec![],
            match &vm_config.boot_image {
                BootImage::GroupDefault => From::from(req.primary_image.clone()),
                BootImage::Image(disk_image) => From::from(disk_image.clone()),
                BootImage::File(id) => ImageLocation::IcOsImageViaId { id: id.clone() },
            },
            vm_config.boot_image_minimal_size_gibibytes,
            vm_config.has_ipv4,
            vm_config.vm_allocation.clone(),
            vm_config.required_host_features.clone(),
        );
        let group_name = group_name.clone();

        match InfraProvider::read_attribute(env) {
            InfraProvider::Farm => {
                threads.push(std::thread::spawn(move || {
                    (
                        vm_name,
                        farm_cloned.create_vm(&group_name, create_vm_request),
                    )
                }));
            }
        }
    }
    let mut res_group = ResourceGroup::new(group_name.clone());
    match InfraProvider::read_attribute(env) {
        InfraProvider::Farm => {
            for thread in threads {
                let (vm_name, created_vm) = thread
                    .join()
                    .expect("Couldn't join on the associated thread");
                let VMCreateResponse {
                    hostname,
                    ipv6,
                    mac6,
                    ..
                } = created_vm?;
                res_group.add_vm(AllocatedVm {
                    name: vm_name,
                    group_name: group_name.clone(),
                    hostname,
                    ipv4: None,
                    ipv6,
                    mac6,
                })
            }
        }
    }
    Ok(res_group)
}

fn vm_spec_from_node(n: &Node, default_vm_resources: Option<VmResources>) -> VmSpec {
    let vm_resources = &n.vm_resources;
    VmSpec {
        name: n.id().to_string(),
        vcpus: vm_resources.vcpus.unwrap_or_else(|| {
            default_vm_resources
                .and_then(|vm_resources| vm_resources.vcpus)
                .unwrap_or(DEFAULT_VCPUS_PER_VM)
        }),
        memory_kibibytes: vm_resources.memory_kibibytes.unwrap_or_else(|| {
            default_vm_resources
                .and_then(|vm_resources| vm_resources.memory_kibibytes)
                .unwrap_or(DEFAULT_MEMORY_KIB_PER_VM)
        }),
        boot_image: BootImage::GroupDefault,
        boot_image_minimal_size_gibibytes: vm_resources.boot_image_minimal_size_gibibytes.or_else(
            || {
                default_vm_resources
                    .and_then(|vm_resources| vm_resources.boot_image_minimal_size_gibibytes)
            },
        ),
        has_ipv4: false,
        vm_allocation: n.vm_allocation.clone(),
        required_host_features: n.required_host_features.clone(),
        alternate_template: None,
    }
}

/// Create a `VmSpec` for a given Nested VM, using the specified image file.
fn vm_spec_from_nested_node(
    node: &NestedNode,
    default_vm_resources: Option<VmResources>,
) -> VmSpec {
    let vm_resources = &node.vm_resources;
    VmSpec {
        name: node.name.clone(),
        // Note that the nested GuestOS VM uses half the vCPUs and memory of this host VM.
        vcpus: vm_resources.vcpus.unwrap_or_else(|| {
            default_vm_resources
                .and_then(|vm_resources| vm_resources.vcpus)
                .unwrap_or(HOSTOS_VCPUS_PER_VM)
        }),
        memory_kibibytes: vm_resources.memory_kibibytes.unwrap_or_else(|| {
            default_vm_resources
                .and_then(|vm_resources| vm_resources.memory_kibibytes)
                .unwrap_or(HOSTOS_MEMORY_KIB_PER_VM)
        }),
        boot_image: BootImage::GroupDefault,
        boot_image_minimal_size_gibibytes: vm_resources.boot_image_minimal_size_gibibytes.or_else(
            || {
                default_vm_resources
                    .and_then(|vm_resources| vm_resources.boot_image_minimal_size_gibibytes)
            },
        ),
        has_ipv4: false,
        vm_allocation: None,
        required_host_features: Vec::new(),
        alternate_template: None,
    }
}
