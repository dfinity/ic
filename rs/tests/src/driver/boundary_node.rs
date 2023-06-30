use std::{
    fmt::Write as FmtWrite,
    fs::{self, File},
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    process::Command,
};

use crate::{
    driver::{
        driver_setup::SSH_AUTHORIZED_PUB_KEYS_DIR,
        farm::{
            CreateVmRequest, DnsRecord, DnsRecordType, Farm, HostFeature, ImageLocation,
            VMCreateResponse, VmType,
        },
        ic::{AmountOfMemoryKiB, NrOfVCPUs, VmAllocationStrategy, VmResources},
        resource::{DiskImage, ImageType},
        test_env::{HasIcPrepDir, TestEnv, TestEnvAttribute},
        test_env_api::{
            get_ssh_session_from_env, retry, AcquirePlaynetCertificate, CreatePlaynetDnsRecords,
            HasDependencies, HasPublicApiUrl, HasTestEnv, HasTopologySnapshot, HasVmName,
            IcNodeContainer, RetrieveIpv4Addr, SshSession, RETRY_BACKOFF, SSH_RETRY_TIMEOUT,
        },
        test_setup::GroupSetup,
    },
    util::{create_agent, create_agent_mapping},
};

use anyhow::{bail, Result};
use async_trait::async_trait;
use flate2::{write::GzEncoder, Compression};
use ic_agent::{Agent, AgentError};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use slog::info;
use ssh2::Session;

use crate::driver::{
    farm::{FileId, PlaynetCertificate},
    test_env_api::HasIcDependencies,
};

// The following default values are the same as for replica nodes
const DEFAULT_VCPUS_PER_VM: NrOfVCPUs = NrOfVCPUs::new(6);
const DEFAULT_MEMORY_KIB_PER_VM: AmountOfMemoryKiB = AmountOfMemoryKiB::new(25165824); // 24GiB

const BOUNDARY_NODE_VMS_DIR: &str = "boundary_node_vms";
const BOUNDARY_NODE_VM_PATH: &str = "vm.json";
const BOUNDARY_NODE_PLAYNET_PATH: &str = "playnet.json";
const CONF_IMG_FNAME: &str = "config_disk.img";
const CERT_DIR: &str = "certificate";
const PLAYNET_PATH: &str = "playnet.json";

fn mk_compressed_img_path() -> std::string::String {
    format!("{}.gz", CONF_IMG_FNAME)
}
/// A builder for the initial configuration of an IC boundary node.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BoundaryNode {
    pub name: String,
    pub is_sev: bool,
    pub vm_resources: VmResources,
    pub qemu_cli_args: Vec<String>,
    pub vm_allocation: Option<VmAllocationStrategy>,
    pub required_host_features: Vec<HostFeature>,
    pub has_ipv4: bool,
    pub boot_image: Option<DiskImage>,
}

pub struct BoundaryNodeWithVm {
    pub name: String,
    pub allocated_vm: VMCreateResponse,
    pub use_real_certs_and_dns: bool,
    pub nns_node_urls: Vec<Url>,
    pub nns_public_key: Option<PathBuf>,
    pub replica_ipv6_rule: String,
    pub has_ipv4: bool,
}

impl BoundaryNodeWithVm {
    pub fn ipv6(&self) -> Ipv6Addr {
        self.allocated_vm.ipv6
    }
    /// Acquire a playnet certificate (or fail if all have been acquired already)
    /// for the domain `ic{ix}.farm.dfinity.systems`
    /// where `ix` is the index of the acquired playnet.
    ///
    /// Then create an AAAA record pointing
    /// `ic{ix}.farm.dfinity.systems` to the IPv6 address of this BN.
    ///
    /// Also add CNAME records for
    /// `*.ic{ix}.farm.dfinity.systems` and
    /// `*.raw.ic{ix}.farm.dfinity.systems`
    /// pointing to `ic{ix}.farm.dfinity.systems`.
    ///
    /// If IPv4 has been enabled (`has_ipv4`), also add a corresponding A record
    /// pointing to the IPv4 address of this BN.
    ///
    /// Finally configure the BN with the playnet certificate.
    ///
    /// Note that if multiple BNs are created within the same
    /// farm-group, they will share the same certificate and
    /// domain name.
    /// Also all their IPv6 addresses will be added to the AAAA record
    /// and all their IPv4 addresses will be added to the A record.
    pub fn use_real_certs_and_dns(mut self) -> Self {
        self.use_real_certs_and_dns = true;
        self
    }
    pub fn with_nns_urls(mut self, nns_node_urls: Vec<Url>) -> Self {
        self.nns_node_urls = nns_node_urls;
        self
    }

    pub fn with_nns_public_key(mut self, nns_public_key: PathBuf) -> Self {
        self.nns_public_key = Some(nns_public_key);
        self
    }

    pub fn with_replica_ipv6_rule(mut self, replica_ipv6_rule: String) -> Self {
        self.replica_ipv6_rule = replica_ipv6_rule;
        self
    }
    pub fn for_ic(self, env: &TestEnv, name: &str) -> Self {
        let replica_ipv6_rule = env
            .topology_snapshot_by_name(name)
            .subnets()
            .flat_map(|subnet| subnet.nodes())
            .filter_map(|node| {
                if let IpAddr::V6(addr) = node.get_ip_addr() {
                    Some(addr)
                } else {
                    None
                }
            })
            .try_fold(String::new(), |mut s, ip| {
                write!(&mut s, "{ip}/32,").map(|_| s)
            })
            .unwrap();

        let nns_urls: Vec<_> = env
            .topology_snapshot_by_name(name)
            .root_subnet()
            .nodes()
            .map(|ep| ep.get_public_url())
            .collect();

        self.with_replica_ipv6_rule(replica_ipv6_rule)
            .with_nns_public_key(env.prep_dir(name).unwrap().root_public_key_path())
            .with_nns_urls(nns_urls)
    }
    pub fn start(&self, env: &TestEnv) -> Result<()> {
        let logger = env.logger();
        let pot_setup = GroupSetup::read_attribute(env);
        let farm_url = env.get_farm_url()?;
        let farm = Farm::new(farm_url, logger.clone());
        // Acquire a playnet certificate and provision an AAAA record pointing
        // ic{ix}.farm.dfinity.systems to the IPv6 address of the BN.
        let opt_existing_playnet = if self.use_real_certs_and_dns {
            let playnet_domain_path = env.get_json_path(PLAYNET_PATH);
            let mut existing_playnet: Playnet = if playnet_domain_path.exists() {
                env.read_json_object(PLAYNET_PATH)?
            } else {
                let playnet_cert = env.acquire_playnet_certificate();
                Playnet {
                    playnet_cert,
                    aaaa_records: vec![],
                    a_records: vec![],
                }
            };

            existing_playnet
                .aaaa_records
                .push(self.allocated_vm.ipv6.to_string());
            let bn_fqdn = existing_playnet.playnet_cert.playnet.clone();
            env.create_playnet_dns_records(vec![
                DnsRecord {
                    name: "".to_string(),
                    record_type: DnsRecordType::AAAA,
                    records: existing_playnet.aaaa_records.clone(),
                },
                DnsRecord {
                    name: "*".to_string(),
                    record_type: DnsRecordType::CNAME,
                    records: vec![bn_fqdn.clone()],
                },
                DnsRecord {
                    name: "*.raw".to_string(),
                    record_type: DnsRecordType::CNAME,
                    records: vec![bn_fqdn.clone()],
                },
            ]);

            info!(
                &logger,
                "Created AAAA records {} to {:?}", bn_fqdn, existing_playnet.aaaa_records
            );
            Some(existing_playnet)
        } else {
            None
        };

        let opt_existing_playnet_cert: Option<PlaynetCertificate> = opt_existing_playnet
            .as_ref()
            .map(|existing_playnet| existing_playnet.playnet_cert.clone());

        env.write_boundary_node_vm(
            &self.name,
            &self.allocated_vm,
            opt_existing_playnet_cert
                .as_ref()
                .map(|existing_playnet_cert| existing_playnet_cert.playnet.clone()),
        )?;

        let image_id = create_and_upload_config_disk_image(
            self,
            env,
            &pot_setup.farm_group_name,
            &farm,
            opt_existing_playnet_cert,
        )?;

        farm.attach_disk_images(
            &pot_setup.farm_group_name,
            &self.name,
            "usb-storage",
            vec![image_id],
        )?;

        farm.start_vm(&pot_setup.farm_group_name, &self.name)?;

        if self.has_ipv4 {
            // Provision an A record pointing ic{ix}.farm.dfinity.systems
            // to the IPv4 address of the BN.
            if let Some(mut existing_playnet) = opt_existing_playnet.clone() {
                let boundary_node_vm = env
                    .get_deployed_boundary_node(&self.name.clone())
                    .unwrap()
                    .get_snapshot()
                    .unwrap();
                let ipv4_address = boundary_node_vm.block_on_ipv4().unwrap().to_string();

                existing_playnet.a_records.push(ipv4_address);

                let bn_fqdn = env.create_playnet_dns_records(vec![DnsRecord {
                    name: "".to_string(),
                    record_type: DnsRecordType::A,
                    records: existing_playnet.a_records.clone(),
                }]);
                info!(
                    &logger,
                    "Created A record {} to {:?}", bn_fqdn, existing_playnet.a_records
                );
            }
        }

        if let Some(existing_playnet) = opt_existing_playnet {
            env.write_json_object(PLAYNET_PATH, &existing_playnet)?;
        }

        Ok(())
    }
}

impl BoundaryNode {
    pub fn new(name: String) -> Self {
        Self {
            name,
            is_sev: false,
            vm_resources: Default::default(),
            qemu_cli_args: Default::default(),
            vm_allocation: Default::default(),
            required_host_features: Default::default(),
            has_ipv4: true,
            boot_image: Default::default(),
        }
    }

    pub fn enable_sev(mut self) -> Self {
        self.is_sev = true;
        self.with_required_host_features(vec![HostFeature::AmdSevSnp])
            .with_qemu_cli_args(
                vec![
            "-cpu",
            "EPYC-v4",
            "-machine",
            "memory-encryption=sev0,vmport=off",
            "-object",
            "sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1",
            "-append",
            "root=/dev/vda5 console=ttyS0 dfinity.system=A dfinity.boot_state=stable swiotlb=2621"
        ]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            )
    }

    pub fn with_vm_resources(mut self, vm_resources: VmResources) -> Self {
        self.vm_resources = vm_resources;
        self
    }

    pub fn with_qemu_cli_args(mut self, qemu_cli_args: Vec<String>) -> Self {
        self.qemu_cli_args = qemu_cli_args;
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

    pub fn allocate_vm(self, env: &TestEnv) -> Result<BoundaryNodeWithVm> {
        let farm = Farm::from_test_env(env, "boundary node");
        let pot_setup = GroupSetup::read_attribute(env);
        let boundary_node_img_url = env.get_boundary_node_img_url()?;
        let boundary_node_img_sha256 = env.get_boundary_node_img_sha256()?;

        let create_vm_req = CreateVmRequest::new(
            self.name.clone(),
            if self.is_sev {
                VmType::Sev
            } else {
                VmType::Production
            },
            self.vm_resources.vcpus.unwrap_or_else(|| {
                pot_setup
                    .default_vm_resources
                    .and_then(|vm_resources| vm_resources.vcpus)
                    .unwrap_or(DEFAULT_VCPUS_PER_VM)
            }),
            self.vm_resources.memory_kibibytes.unwrap_or_else(|| {
                pot_setup
                    .default_vm_resources
                    .and_then(|vm_resources| vm_resources.memory_kibibytes)
                    .unwrap_or(DEFAULT_MEMORY_KIB_PER_VM)
            }),
            self.qemu_cli_args.clone(),
            match &self.boot_image {
                None => {
                    let url = boundary_node_img_url;
                    let sha256 = boundary_node_img_sha256;
                    ImageLocation::IcOsImageViaUrl { url, sha256 }
                }
                Some(disk_image) => From::from(disk_image.clone()),
            },
            self.vm_resources
                .boot_image_minimal_size_gibibytes
                .or_else(|| {
                    pot_setup
                        .default_vm_resources
                        .and_then(|vm_resources| vm_resources.boot_image_minimal_size_gibibytes)
                }),
            self.has_ipv4,
            self.vm_allocation.clone(),
            self.required_host_features.clone(),
        );
        let allocated_vm = farm.create_vm(&pot_setup.farm_group_name, create_vm_req)?;

        Ok(BoundaryNodeWithVm {
            name: self.name,
            allocated_vm,
            nns_node_urls: Default::default(),
            nns_public_key: Default::default(),
            replica_ipv6_rule: Default::default(),
            use_real_certs_and_dns: false,
            has_ipv4: self.has_ipv4,
        })
    }

    pub fn with_snp_boot_img(mut self, env: &TestEnv) -> Self {
        let boundary_node_snp_img_url = env.get_boundary_node_snp_img_url().unwrap();
        let boundary_node_snp_img_sha256 = env.get_boundary_node_snp_img_sha256().unwrap();
        let snp_image = DiskImage {
            image_type: ImageType::IcOsImage,
            url: boundary_node_snp_img_url,
            sha256: boundary_node_snp_img_sha256,
        };

        self.boot_image = Some(snp_image);
        self
    }
}

/// side-effectful function that creates the config disk images
/// in the boundary node directories.
fn create_and_upload_config_disk_image(
    boundary_node: &BoundaryNodeWithVm,
    env: &TestEnv,
    group_name: &str,
    farm: &Farm,
    opt_playnet_cert: Option<PlaynetCertificate>,
) -> anyhow::Result<FileId> {
    let boundary_node_dir = env
        .base_path()
        .join(BOUNDARY_NODE_VMS_DIR)
        .join(boundary_node.name.clone());
    let img_path = boundary_node_dir.join(CONF_IMG_FNAME);
    let script_path =
        env.get_dependency_path("ic-os/boundary-guestos/scripts/build-bootstrap-config-image.sh");
    let mut cmd = Command::new(script_path);
    let ssh_authorized_pub_keys_dir: PathBuf = env.get_path(SSH_AUTHORIZED_PUB_KEYS_DIR);

    cmd.arg(img_path.clone())
        .arg("--hostname")
        .arg(boundary_node.name.clone())
        .arg("--accounts_ssh_authorized_keys")
        .arg(ssh_authorized_pub_keys_dir)
        .arg("--elasticsearch_tags")
        .arg(format!("system_test, {}", group_name))
        .arg("--ipv6_replica_ips")
        .arg(&boundary_node.replica_ipv6_rule)
        .arg("--ipv4_http_ips")
        .arg("0.0.0.0/0")
        .arg("--ipv6_http_ips")
        .arg("::/0")
        .arg("--ipv6_debug_ips")
        .arg("::/0")
        .arg("--ipv6_monitoring_ips")
        .arg("::/0")
        .arg("--elasticsearch_url")
        .arg("https://elasticsearch.testnet.dfinity.systems")
        .arg("--name_servers")
        .arg("2606:4700:4700::1111 2606:4700:4700::1001");

    if !boundary_node.nns_node_urls.is_empty() {
        cmd.arg("--nns_url").arg({
            let urls: Vec<&str> = boundary_node
                .nns_node_urls
                .iter()
                .map(|url| url.as_str())
                .collect();
            urls.join(",")
        });
    }

    if let Some(nns_public_key) = boundary_node.nns_public_key.clone() {
        cmd.arg("--nns_public_key").arg(nns_public_key);
    }

    if let Some(playnet_cert) = opt_playnet_cert {
        let cert_dir = boundary_node_dir.join(CERT_DIR);
        fs::create_dir_all(cert_dir.clone())?;
        let cert = playnet_cert.cert;
        fs::write(cert_dir.join("privkey.pem"), cert.priv_key_pem)?;
        fs::write(cert_dir.join("chain.pem"), cert.chain_pem.clone())?;
        fs::write(
            cert_dir.join("fullchain.pem"),
            cert.cert_pem + &cert.chain_pem,
        )?;
        let bn_fqdn = playnet_cert.playnet;
        cmd.arg("--system-domains")
            .arg(bn_fqdn.clone())
            .arg("--application-domains")
            .arg(bn_fqdn)
            .arg("--certdir")
            .arg(cert_dir);
    }

    let key = "PATH";
    let old_path = match std::env::var(key) {
        Ok(val) => val,
        Err(e) => {
            bail!("couldn't interpret {}: {}", key, e)
        }
    };
    cmd.env("PATH", format!("{}:{}", "/usr/sbin", old_path));

    let output = cmd.output()?;

    std::io::stdout().write_all(&output.stdout)?;
    std::io::stderr().write_all(&output.stderr)?;

    if !output.status.success() {
        bail!("could not spawn image creation process");
    }

    let mut img_file = File::open(img_path)?;

    let compressed_img_path = boundary_node_dir.join(mk_compressed_img_path());
    let compressed_img_file = File::create(compressed_img_path.clone())?;

    let mut encoder = GzEncoder::new(compressed_img_file, Compression::default());
    let _ = io::copy(&mut img_file, &mut encoder)?;
    let mut write_stream = encoder.finish()?;
    write_stream.flush()?;

    let mut cmd = Command::new("sha256sum");
    cmd.arg(compressed_img_path.clone());
    let output = cmd.output()?;
    if !output.status.success() {
        bail!("could not create sha256 of image");
    }

    std::io::stdout().write_all(&output.stdout)?;
    std::io::stderr().write_all(&output.stderr)?;

    let image_id = farm.upload_file(compressed_img_path, &mk_compressed_img_path())?;
    info!(farm.logger, "Uploaded image: {}", image_id);

    Ok(image_id)
}

pub trait BoundaryNodeVm {
    fn get_deployed_boundary_node(&self, name: &str) -> Result<DeployedBoundaryNode>;

    fn write_boundary_node_vm(
        &self,
        name: &str,
        vm: &VMCreateResponse,
        opt_playnet: Option<String>,
    ) -> Result<()>;
}

impl BoundaryNodeVm for TestEnv {
    fn get_deployed_boundary_node(&self, name: &str) -> Result<DeployedBoundaryNode> {
        let rel_boundary_node_dir: PathBuf = [BOUNDARY_NODE_VMS_DIR, name].iter().collect();
        let abs_boundary_node_dir = self.get_path(rel_boundary_node_dir.clone());
        let playnet =
            self.read_json_object(rel_boundary_node_dir.join(BOUNDARY_NODE_PLAYNET_PATH))?;
        if abs_boundary_node_dir.is_dir() {
            Ok(DeployedBoundaryNode {
                env: self.clone(),
                name: name.to_string(),
                playnet,
            })
        } else {
            bail!("Did not find deployed boundary node '{name}'!")
        }
    }

    fn write_boundary_node_vm(
        &self,
        name: &str,
        vm: &VMCreateResponse,
        opt_playnet: Option<String>,
    ) -> Result<()> {
        let rel_boundary_node_dir: PathBuf = [BOUNDARY_NODE_VMS_DIR, name].iter().collect();
        self.write_json_object(rel_boundary_node_dir.join(BOUNDARY_NODE_VM_PATH), &vm)?;
        self.write_json_object(
            rel_boundary_node_dir.join(BOUNDARY_NODE_PLAYNET_PATH),
            &opt_playnet,
        )
    }
}

pub struct DeployedBoundaryNode {
    env: TestEnv,
    name: String,
    playnet: Option<String>,
}

impl HasTestEnv for DeployedBoundaryNode {
    fn test_env(&self) -> TestEnv {
        self.env.clone()
    }
}

impl HasVmName for DeployedBoundaryNode {
    fn vm_name(&self) -> String {
        self.name.clone()
    }
}

impl DeployedBoundaryNode {
    fn get_vm(&self) -> Result<VMCreateResponse> {
        let vm_path: PathBuf = [BOUNDARY_NODE_VMS_DIR, &self.name].iter().collect();
        self.env
            .read_json_object(vm_path.join(BOUNDARY_NODE_VM_PATH))
    }
    pub fn get_snapshot(self) -> Result<BoundaryNodeSnapshot> {
        Ok(BoundaryNodeSnapshot {
            vm: self.get_vm()?,
            env: self.env,
            name: self.name,
            playnet: self.playnet,
        })
    }
}

pub struct BoundaryNodeSnapshot {
    env: TestEnv,
    name: String,
    pub playnet: Option<String>,
    vm: VMCreateResponse,
}

impl BoundaryNodeSnapshot {
    pub fn ipv6(&self) -> Ipv6Addr {
        self.vm.ipv6
    }

    pub fn get_playnet(&self) -> Option<String> {
        self.playnet.clone()
    }
}

impl HasTestEnv for BoundaryNodeSnapshot {
    fn test_env(&self) -> TestEnv {
        self.env.clone()
    }
}

impl HasVmName for BoundaryNodeSnapshot {
    fn vm_name(&self) -> String {
        self.name.clone()
    }
}

impl SshSession for BoundaryNodeSnapshot {
    fn get_ssh_session(&self) -> Result<Session> {
        get_ssh_session_from_env(&self.env, IpAddr::V6(self.vm.ipv6))
    }

    fn block_on_ssh_session(&self) -> Result<Session> {
        retry(self.env.logger(), SSH_RETRY_TIMEOUT, RETRY_BACKOFF, || {
            self.get_ssh_session()
        })
    }
}

#[async_trait]
impl HasPublicApiUrl for BoundaryNodeSnapshot {
    fn get_public_url(&self) -> Url {
        let url_str = self
            .playnet
            .clone()
            .map_or("https://ic0.app".to_string(), |playnet| {
                format!("https://{playnet}")
            });
        Url::parse(&url_str).expect("failed to parse url")
    }

    fn get_public_addr(&self) -> SocketAddr {
        SocketAddr::new(self.ipv6().into(), 443)
    }

    fn uses_snake_oil_certs(&self) -> bool {
        self.playnet.is_none()
    }

    fn uses_dns(&self) -> bool {
        self.playnet.is_some()
    }

    async fn try_build_default_agent_async(&self) -> Result<Agent, AgentError> {
        if self.uses_dns() {
            create_agent(self.get_public_url().as_ref()).await
        } else {
            create_agent_mapping(self.get_public_url().as_ref(), self.ipv6().into()).await
        }
    }
}

/// while this script is very similar to the one used for UniversalVm, the two
/// vm images have different dependencies. thus, we want to differentiate the
/// two scripts to make sure that they can be changed in isolation without
/// potentially causing incompatibilities with the other type of vm.
const IPV4_RETRIEVE_SH_SCRIPT: &str = r#"set -e -o pipefail
count=0
until ipv4=$(ip address show dev enp2s0 | grep 'inet.*scope global' | awk '{print $2}' | cut -d/ -f1); \
do
  if [ "$count" -ge 120 ]; then
    exit 1
  fi
  sleep 1
  count=$((count+1))
done
echo "$ipv4"
"#;

impl RetrieveIpv4Addr for BoundaryNodeSnapshot {
    fn block_on_ipv4(&self) -> Result<Ipv4Addr> {
        use anyhow::Context;
        let ipv4_string = self.block_on_bash_script(IPV4_RETRIEVE_SH_SCRIPT)?;
        ipv4_string
            .trim()
            .parse::<Ipv4Addr>()
            .context("ipv4 retrieval")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Playnet {
    playnet_cert: PlaynetCertificate,
    aaaa_records: Vec<String>,
    a_records: Vec<String>,
}
