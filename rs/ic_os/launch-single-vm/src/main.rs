use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::Command;

use clap::Parser;
use reqwest::blocking::{Client, Response};
use serde::Serialize;
use slog::{o, Drain};
use tempfile::tempdir;
use url::Url;

use ic_prep_lib::{
    internet_computer::{IcConfig, TopologyConfig},
    node::NodeConfiguration,
    subnet_configuration::SubnetConfig,
};
use ic_registry_subnet_type::SubnetType;
use ic_tests::driver::{
    farm::{CreateVmRequest, Farm, GroupSpec, ImageLocation, VmType},
    ic::{Subnet, VmAllocationStrategy},
};
use ic_types::ReplicaVersion;

const FARM_BASE_URL: &str = "https://farm.dfinity.systems";

/// Deploy a single ICOS VM to Farm
#[derive(Parser)]
struct Args {
    /// Version to deploy
    #[clap(long)]
    version: String,
    /// Image URL
    #[clap(long)]
    url: Url,
    /// Image SHA256SUM
    #[clap(long)]
    sha256: String,
    /// Path to `build-bootstrap-config-image.sh` script
    #[clap(long)]
    build_bootstrap_script: PathBuf,
    /// Key to be used for `admin` SSH
    #[clap(long)]
    ssh_key_path: Option<PathBuf>,
}

fn main() {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let logger = slog::Logger::root(drain, o!());

    let tempdir = tempdir().unwrap();

    let farm = Farm::new(Url::parse(FARM_BASE_URL).unwrap(), logger.clone());

    // Arguments
    let args = Args::parse();
    let version = ReplicaVersion::try_from(args.version).unwrap();
    let url = args.url;
    let sha256 = args.sha256;
    let build_bootstrap_script = args.build_bootstrap_script;
    let ssh_key_path = args.ssh_key_path;

    let group_name = if let Ok(user) = std::env::var("USER") {
        format!("testvm-{user}-{version}")
    } else {
        format!("testvm-{version}")
    };

    // Delete any old groups
    let _res = delete_group(&group_name);

    // Create a new group
    create_group(
        &group_name,
        CreateGroupRequest {
            ttl: 3600,
            spec: GroupSpec {
                vm_allocation: Some(VmAllocationStrategy::DistributeAcrossDcs),
                required_host_features: Vec::new(),
                preferred_network: None,
                metadata: None,
            },
        },
    );

    // Allocate new VM on Farm
    let vm_name = "main";
    let request = CreateVmRequest::new(
        vm_name.to_string(),
        VmType::Production,
        2.into(),        // 2 vCPUs
        25165824.into(), // 24 GibiBytes RAM
        Vec::new(),
        ImageLocation::IcOsImageViaUrl { url, sha256 },
        Some(100.into()), // 100 GibiByte image
        false,
        None,
        Vec::new(),
    );
    let created_vm = farm.create_vm(&group_name, request).unwrap();
    let ipv6_addr = IpAddr::V6(created_vm.ipv6);

    // Build Initial IC State
    let prep_dir = tempdir.as_ref().join("prep");
    std::fs::create_dir(&prep_dir).unwrap();

    let nodes = BTreeMap::from([(
        0,
        NodeConfiguration {
            xnet_api: SocketAddr::new(ipv6_addr, 2497),
            public_api: SocketAddr::new(ipv6_addr, 8080),
            p2p_addr: SocketAddr::new(ipv6_addr, 4100),
            node_operator_principal_id: None,
            secret_key_store: None,
            chip_id: vec![],
        },
    )]);

    let mut ic_topology = TopologyConfig::default();
    // Build a "Farm" subnet for the convenient defaults
    let subnet = Subnet::fast_single_node(SubnetType::System);
    ic_topology.insert_subnet(0, subnet_to_subnet_config(subnet, version.clone(), nodes));

    let ic_config = IcConfig::new(
        &prep_dir,
        ic_topology,
        Some(version),
        true,
        Some(0),
        None,
        None,
        None,
        None,
        None,
        Vec::new(),
        None,
    );
    let initialized_ic = ic_config.initialize().unwrap();
    // The first node from the first subnet will be our only node.
    let node = initialized_ic
        .initialized_topology
        .values()
        .next()
        .unwrap()
        .initialized_nodes
        .values()
        .next()
        .unwrap();

    // Construct SSH Key Directory
    let keys_dir = tempdir.as_ref().join("ssh_authorized_keys");
    std::fs::create_dir(&keys_dir).unwrap();
    if let Some(key) = ssh_key_path {
        std::fs::copy(key, keys_dir.join("admin")).unwrap();
    }

    // Build config image
    let filename = "config.tar.gz";
    let config_path = tempdir.as_ref().join(filename);
    let local_store = prep_dir.join("ic_registry_local_store");
    Command::new(build_bootstrap_script)
        .arg(&config_path)
        .arg("--nns_url")
        .arg(ipv6_addr.to_string())
        .arg("--ic_crypto")
        .arg(node.crypto_path())
        .arg("--ic_registry_local_store")
        .arg(&local_store)
        .arg("--accounts_ssh_authorized_keys")
        .arg(&keys_dir)
        .status()
        .unwrap();

    // Upload config image
    let image_id = farm.upload_file(&config_path, filename).unwrap();

    // Attatch image
    farm.attach_disk_images(&group_name, vm_name, "usb-storage", vec![image_id])
        .unwrap();

    // Start VM
    farm.start_vm(&group_name, vm_name).unwrap();
}

/// Convert from a Farm `Subnet` to the prep `SubnetConfig`
fn subnet_to_subnet_config(
    subnet: Subnet,
    version: ReplicaVersion,
    nodes: BTreeMap<u64, NodeConfiguration>,
) -> SubnetConfig {
    SubnetConfig::new(
        0,
        nodes,
        Some(version),
        subnet.ingress_bytes_per_block_soft_cap,
        subnet.max_ingress_bytes_per_message,
        subnet.max_ingress_messages_per_block,
        subnet.max_block_payload_size,
        subnet.unit_delay,
        subnet.initial_notary_delay,
        subnet.dkg_interval_length,
        subnet.dkg_dealings_per_block,
        subnet.subnet_type,
        subnet.max_instructions_per_message,
        subnet.max_instructions_per_round,
        subnet.max_instructions_per_install_code,
        subnet.features.map(|f| f.into()),
        None,
        subnet.max_number_of_canisters,
        subnet.ssh_readonly_access,
        subnet.ssh_backup_access,
    )
}

/// Delete a group from Farm, without retries
fn delete_group(group_name: &str) -> Response {
    let client = Client::new();

    client
        .delete(format!("{FARM_BASE_URL}/group/{group_name}"))
        .send()
        .unwrap()
}

// Need to create our own, as the one from Farm is private
#[derive(Serialize)]
struct CreateGroupRequest {
    ttl: u32,
    spec: GroupSpec,
}

/// Create a new group in farm, without needing a `TestEnv`
fn create_group(group_name: &str, body: CreateGroupRequest) {
    let client = Client::new();

    client
        .post(format!("{FARM_BASE_URL}/group/{group_name}"))
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .unwrap();
}
