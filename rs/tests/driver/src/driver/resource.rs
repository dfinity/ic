use super::constants::SSH_USERNAME;
use super::driver_setup::SSH_AUTHORIZED_PUB_KEYS_DIR;
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
    get_ic_os_img_sha256, get_ic_os_img_url, get_mainnet_ic_os_img_url,
    get_malicious_ic_os_img_sha256, get_malicious_ic_os_img_url, HasIcDependencies,
};
use crate::driver::test_setup::{GroupSetup, InfraProvider};
use crate::driver::universal_vm::UniversalVm;
use crate::k8s::tnet::TNet;
use crate::util::block_on;
use anyhow::{self, bail};
use kube::ResourceExt;
use serde::{Deserialize, Serialize};
use slog::{info, warn};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Command;
use url::Url;
use zstd::stream::write::Encoder;

const DEFAULT_VCPUS_PER_VM: NrOfVCPUs = NrOfVCPUs::new(6);
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
pub struct DiskImage {
    pub image_type: ImageType,
    pub url: Url,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
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
            ImageType::PrometheusImage | ImageType::UniversalImage => ImageViaUrl {
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum BootImage {
    GroupDefault,
    Image(DiskImage),
    File(FileId),
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
    let (ic_os_img_sha256, ic_os_img_url) = {
        if config.has_malicious_behaviours() {
            warn!(
                test_env.logger(),
                "Using malicious guestos image for IC config."
            );
            (
                get_malicious_ic_os_img_sha256()?,
                get_malicious_ic_os_img_url()?,
            )
        } else if config.with_mainnet_config {
            warn!(
                test_env.logger(),
                "Using mainnet guestos image for IC config."
            );
            (
                test_env.get_mainnet_ic_os_img_sha256()?,
                get_mainnet_ic_os_img_url()?,
            )
        } else {
            info!(
                test_env.logger(),
                "Using tip-of-branch guestos image for IC config."
            );
            (get_ic_os_img_sha256()?, get_ic_os_img_url()?)
        }
    };
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
    Ok(res_req)
}

/// Create a `ResourceRequest` for a set of nested nodes.
pub fn get_resource_request_for_nested_nodes(
    nodes: &[NestedNode],
    test_env: &TestEnv,
    group_name: &str,
    farm: &Farm,
) -> anyhow::Result<ResourceRequest> {
    // TODO: We always supply an image for VMs in this group, so these are not
    // being used. Ideally, we will replace the group default with an empty
    // image, and collapse this logic.
    let default_url = Url::parse("https://www.dfinity.org")?;
    let default_image_sha256 = "na".to_string();

    // Build and upload an empty image.
    // TODO: This is temporary until farm can do this natively.
    let empty_image_name = "empty.img.tar.zst";
    let tmp_dir = tempfile::tempdir().unwrap();
    let empty_image = build_empty_image(tmp_dir.path(), empty_image_name)?;
    let image_id = farm.upload_file(group_name, empty_image, empty_image_name)?;

    // Add a VM request for each node.
    let mut res_req = ResourceRequest::new(ImageType::IcOsImage, default_url, default_image_sha256);
    let group_setup = GroupSetup::read_attribute(test_env);
    let default_vm_resources = group_setup.default_vm_resources;
    res_req.group_name = group_name.to_string();
    for node in nodes {
        res_req.add_vm_request(vm_spec_from_nested_node(
            node,
            default_vm_resources,
            image_id.clone(),
        ));
    }

    Ok(res_req)
}

/// The SHA-256 hash of the Universal VM disk image.
/// The latest hash can be retrieved by downloading the SHA256SUMS file from:
/// https://hydra.dfinity.systems/job/dfinity-ci-build/farm/universal-vm.img.x86_64-linux/latest
const DEFAULT_UNIVERSAL_VM_IMG_SHA256: &str =
    "e9676384fdbff9713c543ea4e913782e7ef120282c3c7a491b63cb48f9f0748d";

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
    let mut vm_responses = vec![];
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
            InfraProvider::K8s => {
                let mut tnet = TNet::read_attribute(env);
                tnet.access_key = fs::read_to_string(
                    env.get_path(SSH_AUTHORIZED_PUB_KEYS_DIR).join(SSH_USERNAME),
                )
                .expect("failed to read ssh authorized pub key")
                .into();
                vm_responses.push((
                    vm_name,
                    block_on(tnet.vm_create(
                        CreateVmRequest {
                            primary_image: ImageLocation::PersistentVolumeClaim {
                                name: match req.primary_image.image_type {
                                    ImageType::IcOsImage => {
                                        format!("{}-image-guestos", tnet.owner.name_any())
                                    }
                                    ImageType::PrometheusImage => "img-prometheus-vm".into(),
                                    ImageType::UniversalImage => "img-universal-vm".into(),
                                },
                            },
                            ..create_vm_request
                        },
                        req.primary_image.image_type.clone(),
                    ))
                    .expect("failed to create vm"),
                ));
                tnet.write_attribute(env);
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
                let VMCreateResponse { ipv6, mac6, .. } = created_vm?;
                res_group.add_vm(AllocatedVm {
                    name: vm_name,
                    group_name: group_name.clone(),
                    ipv4: None,
                    ipv6,
                    mac6,
                })
            }
        }
        InfraProvider::K8s => {
            for (vm_name, created_vm) in vm_responses {
                let VMCreateResponse {
                    ipv6, mac6, ipv4, ..
                } = created_vm;
                res_group.add_vm(AllocatedVm {
                    name: vm_name,
                    group_name: group_name.clone(),
                    ipv4,
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
    image: FileId,
) -> VmSpec {
    VmSpec {
        name: node.name.clone(),
        vcpus: default_vm_resources
            .and_then(|vm_resources| vm_resources.vcpus)
            .unwrap_or(DEFAULT_VCPUS_PER_VM),
        memory_kibibytes: default_vm_resources
            .and_then(|vm_resources| vm_resources.memory_kibibytes)
            .unwrap_or(DEFAULT_MEMORY_KIB_PER_VM),
        boot_image: BootImage::File(image),
        boot_image_minimal_size_gibibytes: default_vm_resources
            .and_then(|vm_resources| vm_resources.boot_image_minimal_size_gibibytes),
        has_ipv4: false,
        vm_allocation: None,
        required_host_features: Vec::new(),
        alternate_template: Some(VmType::Nested),
    }
}

pub fn build_empty_image(tmp_dir: &Path, out_file_name: &str) -> anyhow::Result<PathBuf> {
    // Truncate large empty file
    let img_name = "disk.img";

    let img_path = PathBuf::from(tmp_dir).join(img_name);
    let mut cmd = Command::new("truncate");
    cmd.arg("-s").arg("101G").arg(img_path);
    let output = cmd.output()?;
    std::io::stdout().write_all(&output.stdout)?;
    std::io::stderr().write_all(&output.stderr)?;
    if !output.status.success() {
        bail!("could not create empty image");
    }

    // Compress it like we would a config image
    let tar_path = PathBuf::from(tmp_dir).join("empty.img.tar");
    let mut cmd = Command::new("tar");
    cmd.arg("Scf")
        .arg(&tar_path)
        .arg("-C")
        .arg(tmp_dir)
        .arg(img_name);
    let output = cmd.output()?;
    std::io::stdout().write_all(&output.stdout)?;
    std::io::stderr().write_all(&output.stderr)?;
    if !output.status.success() {
        bail!("could not archive empty image");
    }

    let compressed_img_path = PathBuf::from(&tmp_dir).join(out_file_name);

    let mut tar_file = File::open(tar_path)?;
    let compressed_img_file = File::create(&compressed_img_path)?;
    let mut encoder = Encoder::new(compressed_img_file, 0)?;
    let _ = io::copy(&mut tar_file, &mut encoder)?;
    let mut write_stream = encoder.finish()?;
    write_stream.flush()?;

    Ok(compressed_img_path)
}
