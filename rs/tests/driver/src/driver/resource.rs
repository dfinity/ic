use crate::driver::farm::FarmResult;
use crate::driver::farm::FileId;
use crate::driver::farm::ImageLocation;
use crate::driver::farm::ImageLocation::{IcOsImageViaUrl, ImageViaUrl};
use crate::driver::farm::VMCreateResponse;
use crate::driver::farm::VmAllocationMode;
use crate::driver::farm::{CreateVmRequest, HostFeature};
use crate::driver::farm::{Farm, VmType};
use crate::driver::ic::VmResources;
use crate::driver::ic::{AmountOfMemoryKiB, InternetComputer, Node, NrOfVCPUs};
use crate::driver::ic::{ImageSizeGiB, VmResourceOverrides};
use crate::driver::nested::{NestedNode, NestedNodeSpec};
use crate::driver::test_env::{TestEnv, TestEnvAttribute};
use crate::driver::test_env_api::{
    get_empty_disk_img_sha256, get_empty_disk_img_url, get_guestos_img_sha256, get_guestos_img_url,
};
use crate::driver::test_setup::{GroupSetup, SystemTestBackend};
use crate::driver::universal_vm::UniversalVm;
use anyhow;
use anyhow::bail;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use std::path::PathBuf;
use url::Url;

const DEFAULT_VCPUS_PER_VM: NrOfVCPUs = NrOfVCPUs::new(6);
const DEFAULT_MEMORY_KIB_PER_VM: AmountOfMemoryKiB = AmountOfMemoryKiB::new(25165824); // 24GiB
const DEFAULT_VM_RESOURCES: VmResources = VmResources {
    vcpus: DEFAULT_VCPUS_PER_VM,
    memory_kibibytes: DEFAULT_MEMORY_KIB_PER_VM,
    boot_image_minimal_size_gibibytes: None,
};

pub const HOSTOS_VCPUS_PER_VM: NrOfVCPUs = NrOfVCPUs::new(8);
pub const HOSTOS_MEMORY_KIB_PER_VM: AmountOfMemoryKiB = AmountOfMemoryKiB::new(33554432); // 32GiB
const DEFAULT_NESTED_VM_RESOURCES: VmResources = VmResources {
    vcpus: HOSTOS_VCPUS_PER_VM,
    memory_kibibytes: HOSTOS_MEMORY_KIB_PER_VM,
    boot_image_minimal_size_gibibytes: None,
};

pub const HOSTOS_VCPUS_RESERVED: u64 = 4;
pub const HOSTOS_MEMORY_RESERVED_GIB: u64 = 8;

/// A declaration of resources needed to instantiate a InternetComputer.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct ResourceRequest {
    pub group_name: String,
    pub primary_image: DiskImage,
    /// By internal contract, for the initial allocation of resources, the
    /// position of the AllocatedVm reflects the node index.
    pub vm_configs: Vec<VmSpec>,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Serialize, Deserialize)]
pub enum DiskImage {
    /// Image downloaded by a Farm host via URL with sha256 verification.
    Url {
        image_type: ImageType,
        url: Url,
        sha256: String,
    },
    /// Image already present locally on disk. Used by the Local backend.
    Local {
        image_type: ImageType,
        path: PathBuf,
    },
}

impl DiskImage {
    pub fn image_type(&self) -> &ImageType {
        match self {
            DiskImage::Url { image_type, .. } => image_type,
            DiskImage::Local { image_type, .. } => image_type,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Serialize, Deserialize)]
pub enum ImageType {
    IcOsImage,
    PrometheusImage,
    UniversalImage,
}

impl From<DiskImage> for ImageLocation {
    fn from(src: DiskImage) -> ImageLocation {
        match src {
            DiskImage::Url {
                image_type: ImageType::IcOsImage,
                url,
                sha256,
            } => IcOsImageViaUrl { url, sha256 },
            DiskImage::Url { url, sha256, .. } => ImageViaUrl { url, sha256 },
            DiskImage::Local { .. } => {
                panic!("Local DiskImage cannot be converted to Farm ImageLocation")
            }
        }
    }
}

impl ResourceRequest {
    pub fn new(primary_image: DiskImage) -> Self {
        Self {
            group_name: Default::default(),
            primary_image,
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
    name: String,
    vcpus: NrOfVCPUs,
    memory_kibibytes: AmountOfMemoryKiB,
    boot_image: BootImage,
    boot_image_minimal_size_gibibytes: Option<ImageSizeGiB>,
    has_ipv4: bool,
    vm_allocation_mode: Option<VmAllocationMode>,
    required_host_features: Vec<HostFeature>,
    alternate_template: Option<VmType>,
}

impl VmSpec {
    pub fn vcpus(&self) -> NrOfVCPUs {
        self.vcpus
    }

    pub fn memory_kibibytes(&self) -> AmountOfMemoryKiB {
        self.memory_kibibytes
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Default, Serialize, Deserialize)]
pub enum BootImage {
    #[default]
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
    pub bare_metal: bool,
}

/// This translates the configuration structure from InternetComputer to a
/// request for resources (vms)
pub fn get_resource_request(
    config: &InternetComputer,
    test_env: &TestEnv,
    group_name: &str,
) -> anyhow::Result<ResourceRequest> {
    // The GuestOS image URL/hash environment variables are only populated for
    // the Farm backend. Under the Local backend they are unset (the image is
    // provided as a local path via `ENV_DEPS__GUESTOS_DISK_IMG_PATH`), so we
    // must not call `get_guestos_img_url`/`get_guestos_img_sha256` there.
    let primary_image = match SystemTestBackend::read_attribute(test_env) {
        SystemTestBackend::Farm => DiskImage::Url {
            image_type: ImageType::IcOsImage,
            url: get_guestos_img_url(test_env),
            sha256: get_guestos_img_sha256(),
        },
        SystemTestBackend::Local => {
            let var = local_path_env_var(&ImageType::IcOsImage);
            DiskImage::Local {
                image_type: ImageType::IcOsImage,
                path: PathBuf::from(
                    std::env::var(var)
                        .unwrap_or_else(|_| panic!("Failed to read '{var}' for Local backend")),
                ),
            }
        }
    };
    let mut res_req = ResourceRequest::new(primary_image);
    let group_setup = GroupSetup::read_attribute(test_env);
    let group_resource_overrides = group_setup.vm_resource_overrides;
    let ic_resource_overrides = config.vm_resource_overrides;
    res_req.group_name = group_name.to_string();
    for s in &config.subnets {
        let subnet_resource_overrides = Some(s.vm_resource_overrides);
        for n in &s.nodes {
            res_req.add_vm_request(vm_spec_from_node(
                n,
                subnet_resource_overrides,
                ic_resource_overrides,
                group_resource_overrides,
            ));
        }
    }
    for n in &config.unassigned_nodes {
        res_req.add_vm_request(vm_spec_from_node(
            n,
            None,
            ic_resource_overrides,
            group_resource_overrides,
        ));
    }
    for n in &config.api_boundary_nodes {
        res_req.add_vm_request(vm_spec_from_node(
            n,
            None,
            ic_resource_overrides,
            group_resource_overrides,
        ));
    }
    Ok(res_req)
}

/// Create a `ResourceRequest` for a set of nested nodes.
/// This function only supports virtual (non-bare metal) nodes.
pub fn get_resource_request_for_nested_nodes(
    nodes: &[NestedNode],
    test_env: &TestEnv,
    group_name: &str,
) -> anyhow::Result<ResourceRequest> {
    let empty_disk_img_url = get_empty_disk_img_url()?;
    let empty_disk_img_sha256 = get_empty_disk_img_sha256()?;

    // Add a VM request for each node.
    let mut res_req = ResourceRequest::new(DiskImage::Url {
        image_type: ImageType::IcOsImage,
        url: empty_disk_img_url,
        sha256: empty_disk_img_sha256,
    });
    let group_setup = GroupSetup::read_attribute(test_env);
    let group_resource_overrides = group_setup.vm_resource_overrides;
    res_req.group_name = group_name.to_string();
    for node in nodes {
        res_req.add_vm_request(vm_spec_from_nested_node(node, group_resource_overrides)?);
    }

    Ok(res_req)
}

/// The SHA-256 hash of the Universal VM disk image.
/// The latest hash can be retrieved by checking the latest successful test of the farm repo on the master branch:
/// https://github.com/dfinity-lab/farm/actions?query=branch%3Amaster+is%3Asuccess
/// Following through to the "Upload UVM images to S3" job and copying the <SHA256-HASH> from the line:
/// upload: ../../../../../nix/store/...-nixos-disk-image-out-refs-discarded/nixos.img.zst to s3://dfinity-download/farm/universal-vm/<SHA256-HASH>/x86_64-linux/universal-vm.img.zst
pub const DEFAULT_UNIVERSAL_VM_IMG_SHA256: &str =
    "ae94e672589c8cb47231976f8d0a4abaac4b8fde9ded1a664de6d7c32f0eac25";

/// Returns the default Universal VM disk image as a Farm-style URL.
/// Under the Local backend, callers should pipe this through [`maybe_localize`]
/// so the URL is replaced with the local path supplied by bazel.
pub fn default_universal_vm_disk_image() -> DiskImage {
    DiskImage::Url {
        image_type: ImageType::UniversalImage,
        url: Url::parse(&format!("http://download.proxy-global.dfinity.network:8080/farm/universal-vm/{DEFAULT_UNIVERSAL_VM_IMG_SHA256}/x86_64-linux/universal-vm.img.zst")).expect("should not fail!"),
        sha256: String::from(DEFAULT_UNIVERSAL_VM_IMG_SHA256),
    }
}

/// Environment variable name carrying the local path for a given image type.
fn local_path_env_var(image_type: &ImageType) -> &'static str {
    match image_type {
        ImageType::IcOsImage => "ENV_DEPS__GUESTOS_DISK_IMG_PATH",
        ImageType::PrometheusImage => "ENV_DEPS__PROMETHEUS_VM_DISK_IMG_PATH",
        ImageType::UniversalImage => "ENV_DEPS__UNIVERSAL_VM_DISK_IMG_PATH",
    }
}

/// Convert a `DiskImage::Url` into a `DiskImage::Local` when running under the
/// Local backend, preserving its `image_type`. The local path is looked up via
/// the appropriate `ENV_DEPS__*_DISK_IMG_PATH` environment variable provided by
/// the bazel `system_test(local = True, ...)` macro.
pub fn maybe_localize(primary_image: DiskImage, env: &TestEnv) -> DiskImage {
    match SystemTestBackend::read_attribute(env) {
        SystemTestBackend::Farm => primary_image,
        SystemTestBackend::Local => match primary_image {
            DiskImage::Local { .. } => primary_image,
            DiskImage::Url { image_type, .. } => {
                let var = local_path_env_var(&image_type);
                let path = PathBuf::from(
                    std::env::var(var)
                        .unwrap_or_else(|_| panic!("Failed to read '{var}' for Local backend")),
                );
                DiskImage::Local { image_type, path }
            }
        },
    }
}

pub fn get_resource_request_for_universal_vm(
    universal_vm: &UniversalVm,
    group_setup: &GroupSetup,
    group_name: &str,
    env: &TestEnv,
) -> anyhow::Result<ResourceRequest> {
    let primary_image = match universal_vm.primary_image.clone() {
        Some(image) => maybe_localize(image, env),
        None => match SystemTestBackend::read_attribute(env) {
            SystemTestBackend::Farm => default_universal_vm_disk_image(),
            SystemTestBackend::Local => {
                let var = local_path_env_var(&ImageType::UniversalImage);
                DiskImage::Local {
                    image_type: ImageType::UniversalImage,
                    path: PathBuf::from(
                        std::env::var(var)
                            .unwrap_or_else(|_| panic!("Failed to read '{var}' for Local backend")),
                    ),
                }
            }
        },
    };
    let mut res_req = ResourceRequest::new(primary_image);
    res_req.group_name = group_name.to_string();

    let resolved_vm_resources = universal_vm
        .vm_resource_overrides
        .layer(&group_setup.vm_resource_overrides)
        .base(&DEFAULT_VM_RESOURCES);

    res_req.add_vm_request(VmSpec {
        name: universal_vm.name.clone(),
        vcpus: resolved_vm_resources.vcpus,
        memory_kibibytes: resolved_vm_resources.memory_kibibytes,
        boot_image: BootImage::GroupDefault,
        boot_image_minimal_size_gibibytes: resolved_vm_resources.boot_image_minimal_size_gibibytes,
        has_ipv4: universal_vm.has_ipv4,
        vm_allocation_mode: None,
        required_host_features: universal_vm.required_host_features.clone(),
        alternate_template: None,
    });
    Ok(res_req)
}

pub fn allocate_resources(req: &ResourceRequest, env: &TestEnv) -> FarmResult<ResourceGroup> {
    let group_name = req.group_name.clone();
    let backend = SystemTestBackend::read_attribute(env);

    let mut res_group = ResourceGroup::new(group_name.clone());

    match backend {
        SystemTestBackend::Farm => {
            let farm = Farm::from_test_env(env, "allocate_resources");
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
                    None,
                    vm_config.required_host_features.clone(),
                );
                let group_name = group_name.clone();
                threads.push(std::thread::spawn(move || {
                    (
                        vm_name,
                        farm_cloned.create_vm(&group_name, create_vm_request),
                    )
                }));
            }
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
                    ipv6,
                    mac6,
                    bare_metal: false,
                });
            }
        }
        SystemTestBackend::Local => {
            let backend = crate::driver::local_backend::LocalBackend::from_test_env(env)
                .expect("LocalBackend::from_test_env failed");
            for vm_config in req.vm_configs.iter() {
                let vm_name = vm_config.name.clone();
                let primary_image: DiskImage = match &vm_config.boot_image {
                    BootImage::GroupDefault => req.primary_image.clone(),
                    BootImage::Image(disk_image) => disk_image.clone(),
                    BootImage::File(_) => {
                        panic!("BootImage::File is not supported by the Local backend")
                    }
                };
                let created = backend
                    .create_vm(
                        &group_name,
                        &vm_name,
                        vm_config.vcpus.get(),
                        vm_config.memory_kibibytes.get(),
                        primary_image,
                        vm_config.boot_image_minimal_size_gibibytes.map(|s| s.get()),
                        vm_config.has_ipv4,
                    )
                    .expect("LocalBackend::create_vm failed");
                let VMCreateResponse {
                    hostname,
                    ipv6,
                    mac6,
                    ..
                } = created;
                res_group.add_vm(AllocatedVm {
                    name: vm_name,
                    group_name: group_name.clone(),
                    hostname,
                    ipv6,
                    mac6,
                    bare_metal: false,
                });
            }
        }
    }
    Ok(res_group)
}

fn vm_spec_from_node(
    n: &Node,
    subnet_vm_resource_overrides: Option<VmResourceOverrides>,
    ic_vm_resource_overrides: VmResourceOverrides,
    group_vm_resource_overrides: VmResourceOverrides,
) -> VmSpec {
    let mut vm_resources = n.vm_resource_overrides;
    if let Some(subnet_vm_resource_overrides) = subnet_vm_resource_overrides {
        vm_resources = vm_resources.layer(&subnet_vm_resource_overrides);
    }
    let resolved_vm_resources = vm_resources
        .layer(&ic_vm_resource_overrides)
        .layer(&group_vm_resource_overrides)
        .base(&DEFAULT_VM_RESOURCES);

    VmSpec {
        name: n.id().to_string(),
        vcpus: resolved_vm_resources.vcpus,
        memory_kibibytes: resolved_vm_resources.memory_kibibytes,
        boot_image: n.boot_image.clone(),
        boot_image_minimal_size_gibibytes: resolved_vm_resources.boot_image_minimal_size_gibibytes,
        has_ipv4: false,
        vm_allocation_mode: None,
        required_host_features: n.required_host_features.clone(),
        alternate_template: None,
    }
}

/// Create a `VmSpec` for a given Nested VM, using the specified image file.
///
/// Note: There must be enough vCPUs and memory for the HostOS VM and nested
/// GuestOS VM.
fn vm_spec_from_nested_node(
    node: &NestedNode,
    group_vm_resource_overrides: VmResourceOverrides,
) -> anyhow::Result<VmSpec> {
    let (node_vm_resource_overrides, required_host_features) = match &node.node_spec {
        NestedNodeSpec::Vm {
            vm_resource_overrides,
            required_host_features,
        } => (*vm_resource_overrides, required_host_features.clone()),
        NestedNodeSpec::BareMetal { .. } => {
            bail!("Bare metal nodes are not supported by get_resource_request_for_nested_nodes")
        }
    };

    let resolved_vm_resources = node_vm_resource_overrides
        .layer(&group_vm_resource_overrides)
        .base(&DEFAULT_NESTED_VM_RESOURCES);

    Ok(VmSpec {
        name: node.name.clone(),
        vcpus: resolved_vm_resources.vcpus,
        memory_kibibytes: resolved_vm_resources.memory_kibibytes,
        boot_image: node.boot_image.clone(),
        boot_image_minimal_size_gibibytes: resolved_vm_resources.boot_image_minimal_size_gibibytes,
        has_ipv4: false,
        vm_allocation_mode: None,
        required_host_features,
        alternate_template: None,
    })
}
