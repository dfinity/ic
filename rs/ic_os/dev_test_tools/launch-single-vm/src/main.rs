use clap::Parser;
use config::generate_testnet_config::{
    generate_testnet_config, GenerateTestnetConfigArgs, Ipv6ConfigType,
};
use config::hostos::guestos_bootstrap_image::BootstrapOptions;
use config_types::DeploymentEnvironment;
use ic_prep_lib::{
    internet_computer::{IcConfig, TopologyConfig},
    node::NodeConfiguration,
    subnet_configuration::SubnetConfig,
};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::{
    farm::{
        AttachImageSpec, CreateVmRequest, Farm, GroupMetadata, GroupSpec, ImageLocation, VmType,
    },
    ic::{Subnet, VmAllocationStrategy},
    test_env_api::{get_empty_disk_img_sha256, get_empty_disk_img_url},
};
use ic_types::ReplicaVersion;
use reqwest::blocking::Client;
use serde::Serialize;
use slog::{o, Drain};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use tempfile::tempdir;
use url::Url;

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
    /// Key to be used for `admin` SSH
    #[clap(long)]
    ssh_key_path: Option<PathBuf>,
    /// Should a nested VM configuration be used
    #[clap(long)]
    nested: bool,
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
    let ssh_key_path = args.ssh_key_path;

    let test_name = "test_single_vm";

    let metadata = GroupMetadata {
        user: std::env::var("HOSTUSER").unwrap_or("unknown".to_string()),
        job_schedule: std::env::var("CI_JOB_NAME").unwrap_or("manual".to_string()),
        test_name: test_name.to_string(),
    };

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Falied to retrieve unix epoch")
        .as_millis();
    // Group name is now unique, so not deleting old ones
    let group_name = format!("{}--{:?}", test_name, timestamp);

    // Create a new group
    create_group(
        &group_name,
        CreateGroupRequest {
            ttl: 3600,
            spec: GroupSpec {
                vm_allocation: Some(VmAllocationStrategy::DistributeAcrossDcs),
                required_host_features: Vec::new(),
                preferred_network: None,
                metadata: Some(metadata),
            },
        },
    );

    // Adjust VM configuration for nested setup
    let (image_location, vm_type, vm_size) = if args.nested {
        let empty_disk_img_url = get_empty_disk_img_url().unwrap();
        let empty_disk_img_sha256 = get_empty_disk_img_sha256().unwrap();
        (
            ImageLocation::IcOsImageViaUrl {
                url: empty_disk_img_url,
                sha256: empty_disk_img_sha256,
            },
            VmType::Production,
            Some(101.into()), // 101 GibiByte image
        )
    } else {
        (
            ImageLocation::IcOsImageViaUrl {
                url: url.clone(),
                sha256: sha256.clone(),
            },
            VmType::Production,
            None, // Do not expand image
        )
    };

    // Allocate new VM on Farm
    let vm_name = "main";
    let request = CreateVmRequest::new(
        vm_name.to_string(),
        vm_type,
        2.into(),        // 2 vCPUs
        25165824.into(), // 24 GibiBytes RAM
        Vec::new(),
        image_location,
        vm_size,
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
            node_operator_principal_id: None,
            secret_key_store: None,
            domain: None,
            node_reward_type: None,
        },
    )]);

    let mut ic_topology = TopologyConfig::default();
    // Build a "Farm" subnet for the convenient defaults
    let subnet = Subnet::fast_single_node(SubnetType::System);
    ic_topology.insert_subnet(0, subnet_to_subnet_config(subnet, version.clone(), nodes));

    let ic_config = IcConfig::new(
        &prep_dir,
        ic_topology,
        version,
        true,
        Some(0),
        None,
        None,
        None,
        None,
        None,
        Vec::new(),
    );
    let initialized_ic = ic_config.initialize().unwrap();

    // Create initial guest configuration directly, when not nested, otherwise, attach the SetupOS installer
    if !args.nested {
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

        // Build GuestOS config object
        let config = GenerateTestnetConfigArgs {
            ipv6_config_type: Some(Ipv6ConfigType::RouterAdvertisement),
            deterministic_prefix: None,
            deterministic_prefix_length: None,
            deterministic_gateway: None,
            fixed_address: None,
            fixed_gateway: None,
            ipv4_address: None,
            ipv4_gateway: None,
            ipv4_prefix_length: None,
            node_reward_type: None,
            domain_name: None,
            mgmt_mac: None,
            deployment_environment: Some(DeploymentEnvironment::Testnet),
            elasticsearch_hosts: None,
            elasticsearch_tags: None,
            use_nns_public_key: Some(true),
            nns_urls: Some(vec![format!("http://[{}]", ipv6_addr)]),
            enable_trusted_execution_environment: None,
            use_node_operator_private_key: Some(true),
            use_ssh_authorized_keys: Some(true),
            inject_ic_crypto: Some(false),
            inject_ic_state: Some(false),
            inject_ic_registry_local_store: Some(false),
            backup_retention_time_seconds: None,
            backup_purging_interval_seconds: None,
            malicious_behavior: None,
            query_stats_epoch_length: None,
            bitcoind_addr: None,
            jaeger_addr: None,
            socks_proxy: None,
            hostname: None,
            generate_ic_boundary_tls_cert: None,
        };

        let guestos_config = generate_testnet_config(config).unwrap();

        // Build config image
        let filename = "config.tar.gz";
        let config_path = tempdir.as_ref().join(filename);
        let local_store = prep_dir.join("ic_registry_local_store");

        let bootstrap_options = BootstrapOptions {
            guestos_config: Some(guestos_config),
            ic_crypto: Some(node.crypto_path()),
            ic_registry_local_store: Some(local_store),
            accounts_ssh_authorized_keys: Some(keys_dir),
            ..Default::default()
        };
        bootstrap_options
            .build_bootstrap_config_image(&config_path)
            .unwrap();

        // Upload config image
        let image_id = farm
            .upload_file(&group_name, &config_path, filename)
            .unwrap();

        // Attach image
        farm.attach_disk_images(
            &group_name,
            vm_name,
            "usb-storage",
            vec![AttachImageSpec::new(image_id)],
        )
        .unwrap();
    } else {
        farm.attach_disk_images(
            &group_name,
            vm_name,
            "usb-storage",
            vec![AttachImageSpec::via_url(url, sha256)],
        )
        .unwrap();
    }

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
        version,
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
        subnet.features,
        None,
        subnet.max_number_of_canisters,
        subnet.ssh_readonly_access,
        subnet.ssh_backup_access,
        subnet.running_state,
        Some(subnet.initial_height),
    )
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
