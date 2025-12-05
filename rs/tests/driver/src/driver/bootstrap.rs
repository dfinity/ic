use crate::driver::ic_gateway_vm::HasIcGatewayVm;
use crate::driver::ic_gateway_vm::IC_GATEWAY_VM_NAME;
use crate::driver::test_env_api::get_guestos_initial_launch_measurements;
use crate::driver::{
    config::NODES_INFO,
    driver_setup::SSH_AUTHORIZED_PUB_KEYS_DIR,
    farm::{AttachImageSpec, Farm, FarmResult, FileId},
    ic::{InternetComputer, Node},
    nested::{HasNestedVms, NESTED_CONFIG_IMAGE_PATH, UnassignedRecordConfig},
    node_software_version::NodeSoftwareVersion,
    port_allocator::AddrType,
    resource::AllocatedVm,
    test_env::{HasIcPrepDir, TestEnv, TestEnvAttribute},
    test_env_api::{
        HasTopologySnapshot, HasVmName, IcNodeContainer, NodesInfo,
        get_build_setupos_config_image_tool, get_guestos_img_version,
        get_guestos_initial_update_img_sha256, get_guestos_initial_update_img_url,
        get_setupos_img_sha256, get_setupos_img_url, get_setupos_img_version,
        try_get_guestos_img_version,
    },
    test_setup::InfraProvider,
};
use anyhow::{Context, Result, bail};
use config::hostos::guestos_bootstrap_image::BootstrapOptions;
use config::setupos::{
    config_ini::ConfigIniSettings,
    deployment_json::{self, CompatDeploymentSettings},
};
use config_types::{
    CONFIG_VERSION, DeploymentEnvironment, GuestOSConfig, GuestOSDevSettings, GuestOSSettings,
    GuestOSUpgradeConfig, GuestVMType, ICOSDevSettings, ICOSSettings, Ipv4Config, Ipv6Config,
    NetworkSettings, RecoveryConfig,
};
use ic_base_types::NodeId;
use ic_prep_lib::{
    internet_computer::{IcConfig, InitializedIc, TopologyConfig},
    node::{InitializedNode, NodeConfiguration, NodeIndex},
    subnet_configuration::SubnetConfig,
};
use ic_registry_canister_api::IPv4Config;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_subnet_type::SubnetType;
use ic_types::malicious_behavior::MaliciousBehavior;
use slog::{Logger, debug, info, warn};
use std::{
    collections::BTreeMap,
    convert::Into,
    fs,
    fs::File,
    io,
    io::Write,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    process::Command,
    thread::{self, JoinHandle},
};
use url::Url;
use zstd::stream::write::Encoder;

pub type UnassignedNodes = BTreeMap<NodeIndex, NodeConfiguration>;
pub type NodeVms = BTreeMap<NodeId, AllocatedVm>;

const CONF_IMG_FNAME: &str = "config_disk.img";
const BITCOIND_ADDR_PATH: &str = "bitcoind_addr";
const DOGECOIND_ADDR_PATH: &str = "dogecoind_addr";
const JAEGER_ADDR_PATH: &str = "jaeger_addr";
const SOCKS_PROXY_PATH: &str = "socks_proxy";

fn mk_compressed_img_path() -> std::string::String {
    format!("{CONF_IMG_FNAME}.zst")
}

pub fn init_ic(
    ic: &InternetComputer,
    test_env: &TestEnv,
    logger: &Logger,
    specific_ids: bool,
) -> Result<InitializedIc> {
    let mut next_node_index = 0u64;
    let ic_name = ic.name();
    let working_dir = test_env.create_prep_dir(&ic_name)?;

    if let Some(bitcoind_addr) = &ic.bitcoind_addr {
        test_env.write_json_object(BITCOIND_ADDR_PATH, &bitcoind_addr)?;
    }

    if let Some(dogecoind_addr) = &ic.dogecoind_addr {
        test_env.write_json_object(DOGECOIND_ADDR_PATH, &dogecoind_addr)?;
    }

    if let Some(jaeger_addr) = &ic.jaeger_addr {
        test_env.write_json_object(JAEGER_ADDR_PATH, &jaeger_addr)?;
    }

    if let Some(socks_proxy) = &ic.socks_proxy {
        test_env.write_json_object(SOCKS_PROXY_PATH, &socks_proxy)?;
    }

    // In production, this dummy hash is not actually checked and exists
    // only as a placeholder: Updating individual binaries (replica/orchestrator)
    // is not supported anymore.
    let dummy_hash = "60958ccac3e5dfa6ae74aa4f8d6206fd33a5fc9546b8abaad65e3f1c4023c5bf".to_string();

    let replica_version = get_guestos_img_version();
    info!(
        logger,
        "Replica Version that is passed is: {:?}", &replica_version
    );
    let initial_replica = ic
        .initial_version
        .clone()
        .unwrap_or_else(|| NodeSoftwareVersion {
            replica_version,
            // the following are dummy values, these are not used in production
            replica_url: Url::parse("file:///opt/replica").unwrap(),
            replica_hash: dummy_hash.clone(),
            orchestrator_url: Url::parse("file:///opt/replica").unwrap(),
            orchestrator_hash: dummy_hash,
        });
    info!(logger, "Initial_replica: {:?}", initial_replica);

    // Note: NNS subnet should be selected from among the system subnets.
    // If there is no system subnet, fall back on choosing the first one.
    let mut nns_subnet_idx = None;
    // TopologyConfig is a structure provided by ic-prep. We translate from the
    // builder (InternetComputer) to TopologyConfig. While doing so, we allocate tcp
    // ports for the http handler, p2p and xnet. The corresponding sockets are
    // closed when the port-allocator is dropped—which happens before we start the
    // nodes.
    let mut ic_topology = TopologyConfig::default();
    for (subnet_idx, subnet) in ic.subnets.iter().enumerate() {
        if subnet.subnet_type == SubnetType::System && nns_subnet_idx.is_none() {
            nns_subnet_idx = Some(subnet_idx as u64);
        }
        let subnet_index = subnet_idx as u64;
        let mut nodes: BTreeMap<NodeIndex, NodeConfiguration> = BTreeMap::new();

        for node in &subnet.nodes {
            let node_index = next_node_index;
            next_node_index += 1;
            nodes.insert(node_index, node_to_config(node));
        }

        ic_topology.insert_subnet(
            subnet_index,
            SubnetConfig::new(
                subnet_index,
                nodes,
                initial_replica.replica_version.clone(),
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
                subnet.chain_key_config.clone().map(|c| c.into()),
                subnet.max_number_of_canisters,
                subnet.ssh_readonly_access.clone(),
                subnet.ssh_backup_access.clone(),
                subnet.running_state,
                Some(subnet.initial_height),
            ),
        );
    }

    for node in &ic.unassigned_nodes {
        let node_index = next_node_index;
        next_node_index += 1;
        ic_topology.insert_unassigned_node(node_index as NodeIndex, node_to_config(node));
    }

    for node in &ic.api_boundary_nodes {
        let node_index = next_node_index;
        next_node_index += 1;
        ic_topology.insert_api_boundary_node(node_index as NodeIndex, node_to_config(node))?;
    }

    let whitelist = ProvisionalWhitelist::All;
    let (ic_os_update_img_sha256, ic_os_update_img_url, ic_os_launch_measurements) = (
        get_guestos_initial_update_img_sha256(),
        get_guestos_initial_update_img_url(),
        get_guestos_initial_launch_measurements(),
    );
    let mut ic_config = IcConfig::new(
        working_dir.path(),
        ic_topology,
        initial_replica.replica_version,
        // To maintain backwards compatibility, pass true here.
        // False is used only when nodes need to be deployed without
        // them joining any subnet initially

        /* generate_subnet_records= */
        true,
        Some(nns_subnet_idx.unwrap_or(0)),
        Some(ic_os_update_img_url),
        Some(ic_os_update_img_sha256),
        Some(ic_os_launch_measurements),
        Some(whitelist),
        ic.node_operator,
        ic.node_provider,
        ic.ssh_readonly_access_to_unassigned_nodes.clone(),
    );

    ic_config.set_use_specified_ids_allocation_range(specific_ids);

    if let Some(UnassignedRecordConfig::Skip) = ic.unassigned_record_config {
        ic_config.skip_unassigned_record();
    }

    debug!(test_env.logger(), "Initializing via {:?}", &ic_config);

    Ok(ic_config.initialize()?)
}

pub fn setup_and_start_vms(
    initialized_ic: &InitializedIc,
    ic: &InternetComputer,
    env: &TestEnv,
    farm: &Farm,
    group_name: &str,
) -> anyhow::Result<()> {
    let mut nodes = vec![];
    for subnet in initialized_ic.initialized_topology.values() {
        for node in subnet.initialized_nodes.values() {
            nodes.push(node.clone());
        }
    }
    for node in initialized_ic.unassigned_nodes.values() {
        nodes.push(node.clone());
    }
    for node in initialized_ic.api_boundary_nodes.values() {
        nodes.push(node.clone());
    }
    let mut join_handles: Vec<JoinHandle<anyhow::Result<()>>> = vec![];
    let mut nodes_info = NodesInfo::new();
    for node in nodes {
        let group_name = group_name.to_string();
        let vm_name = node.node_id.to_string();
        let t_farm = farm.clone();
        let t_env = env.clone();
        let ic_name = ic.name();
        let malicious_behavior = ic.get_malicious_behavior_of_node(node.node_id);
        let query_stats_epoch_length = ic.get_query_stats_epoch_length_of_node(node.node_id);
        let ipv4_config = ic.get_ipv4_config_of_node(node.node_id);
        let domain = ic.get_domain_of_node(node.node_id);
        let recovery_hash: Option<String> = ic.get_recovery_hash_of_node(node.node_id);
        nodes_info.insert(node.node_id, malicious_behavior.clone());
        join_handles.push(thread::spawn(move || {
            create_config_disk_image(
                &ic_name,
                &node,
                malicious_behavior,
                query_stats_epoch_length,
                ipv4_config,
                domain,
                recovery_hash,
                &t_env,
            )?;

            let conf_img_path = PathBuf::from(&node.node_path).join(mk_compressed_img_path());
            match InfraProvider::read_attribute(&t_env) {
                InfraProvider::Farm => {
                    let image_spec = AttachImageSpec::new(upload_config_disk_image(
                        &group_name,
                        &node,
                        &t_farm,
                    )?);
                    t_farm.attach_disk_images(
                        &group_name,
                        &vm_name,
                        "usb-storage",
                        vec![image_spec],
                    )?;
                    t_farm.start_vm(&group_name, &vm_name)?;
                }
            }
            std::fs::remove_file(conf_img_path)?;
            Ok(())
        }));
    }
    // In the tests we may need to identify, which node/s have malicious behavior.
    // We dump this info into a file.
    env.write_json_object(NODES_INFO, &nodes_info)?;

    let mut result = Ok(());
    // Wait for all threads to finish and return an error if any of them fails.
    for jh in join_handles {
        if let Err(e) = jh.join().expect("Waiting for a thread failed") {
            warn!(farm.logger, "Starting VM failed with: {:?}", e);
            result = Err(anyhow::anyhow!(
                "Failed to set up and start a VM pool: {:?}",
                e
            ));
        }
    }
    result
}

// Setup and start nested VMs. NOTE: This is different from
// `setup_and_start_vms` in that we need to configure and push SetupOS config
// for each node.
pub fn setup_and_start_nested_vms(
    env: &TestEnv,
    farm: &Farm,
    group_name: &str,
) -> anyhow::Result<()> {
    // Check that versions are in line, or configured properly
    validate_version_config(env);

    let logger = env.logger();
    info!(logger, "Setting up nested VM(s) ...");

    let ic_gateway_url = env
        .get_deployed_ic_gateway(IC_GATEWAY_VM_NAME)
        .map(|v| v.get_public_url())
        .unwrap_or_else(|_| {
            info!(logger, "No gateway found, using dummy URL");
            url::Url::parse("http://localhost:8080").unwrap()
        });
    let nns_public_key_override = env.prep_dir("").map(|v| v.root_public_key_path());

    let setupos_url = get_setupos_img_url();
    let setupos_hash = get_setupos_img_sha256();
    let setupos_image_spec = AttachImageSpec::via_url(setupos_url, setupos_hash);

    let mut join_handles: Vec<JoinHandle<anyhow::Result<()>>> = vec![];
    for node in env.get_all_nested_vms()? {
        let t_env = env.clone();
        let t_farm = farm.clone();
        let t_group_name = group_name.to_string();
        let t_ic_gateway_url = ic_gateway_url.clone();
        let t_nns_public_key_override = nns_public_key_override.clone();
        let t_setupos_image_spec = setupos_image_spec.clone();
        join_handles.push(thread::spawn(move || {
            let vm_name = node.vm_name();

            let config_image = create_setupos_config_image(
                &t_env,
                &vm_name,
                &t_ic_gateway_url,
                t_nns_public_key_override.as_deref(),
            )?;
            let config_image_spec = AttachImageSpec::new(t_farm.upload_file(
                &t_group_name,
                config_image,
                NESTED_CONFIG_IMAGE_PATH,
            )?);

            t_farm.attach_disk_images(
                &t_group_name,
                &vm_name,
                "usb-storage",
                vec![t_setupos_image_spec, config_image_spec],
            )?;
            t_farm.start_vm(&t_group_name, &vm_name)?;

            Ok(())
        }));
    }

    // Wait for all threads to finish and return an error if any of them fails.
    info!(
        farm.logger,
        "Waiting for {} VM setup threads to complete",
        join_handles.len()
    );

    let mut result = Ok(());
    for jh in join_handles {
        if let Err(e) = jh.join().expect("Waiting for a thread failed") {
            warn!(farm.logger, "Setting up VM failed with: {:?}", e);
            result = Err(anyhow::anyhow!("Failed to set up a VM pool"));
        }
    }

    info!(logger, "Nested VM(s) setup complete!");

    result
}

fn validate_version_config(env: &TestEnv) {
    // When a GuestOS image is also in use...
    if let Ok(guestos_version) = try_get_guestos_img_version() {
        // ...and the versions do not match...
        if guestos_version != get_setupos_img_version() {
            // ...panic, unless an appropriate UnassignedRecordConfig is set.
            if let Ok(config) = UnassignedRecordConfig::try_read_attribute(env) {
                info!(
                    env.logger(),
                    "Version mismatch allowed by UnassignedRecordConfig: '{config:?}'"
                );
            } else {
                panic!(
                    "Initial GuestOS and SetupOS versions do not match! \
                    If this is intended, set `without_unassigned_config` (avoid) \
                    or `with_unassigned_config` (ignore) on your IC."
                );
            }
        }
    }
}

pub fn upload_config_disk_image(
    group_name: &str,
    node: &InitializedNode,
    farm: &Farm,
) -> FarmResult<FileId> {
    let compressed_img_path = mk_compressed_img_path();
    let target_file = PathBuf::from(&node.node_path).join(compressed_img_path.clone());
    let image_id = farm.upload_file(group_name, target_file, &compressed_img_path)?;
    info!(farm.logger, "Uploaded image: {}", image_id);
    Ok(image_id)
}

/// side-effectful function that creates the config disk images in the node
/// directories.
fn create_config_disk_image(
    ic_name: &str,
    node: &InitializedNode,
    malicious_behavior: Option<MaliciousBehavior>,
    query_stats_epoch_length: Option<u64>,
    ipv4_config: Option<IPv4Config>,
    domain_name: Option<String>,
    recovery_hash: Option<String>,
    test_env: &TestEnv,
) -> anyhow::Result<()> {
    let mut bootstrap_options = BootstrapOptions {
        ic_registry_local_store: Some(
            test_env
                .prep_dir(ic_name)
                .expect("No no-name IC")
                .registry_local_store_path(),
        ),
        ic_state: Some(node.state_path()),
        ic_crypto: Some(node.crypto_path()),
        ..Default::default()
    };

    let guestos_config = create_guestos_config_for_node(
        node,
        malicious_behavior,
        query_stats_epoch_length,
        ipv4_config,
        domain_name,
        recovery_hash,
        test_env,
        ic_name,
    )?;

    bootstrap_options.guestos_config = Some(guestos_config);

    let ssh_authorized_pub_keys_dir = test_env.get_path(SSH_AUTHORIZED_PUB_KEYS_DIR);
    if ssh_authorized_pub_keys_dir.exists() {
        bootstrap_options.accounts_ssh_authorized_keys = Some(ssh_authorized_pub_keys_dir);
    }

    let img_path = PathBuf::from(&node.node_path).join(CONF_IMG_FNAME);

    bootstrap_options
        .build_bootstrap_config_image(&img_path)
        .context("Could not create bootstrap config image")?;

    let mut img_file = File::open(img_path)?;
    let compressed_img_path = PathBuf::from(&node.node_path).join(mk_compressed_img_path());
    let compressed_img_file = File::create(compressed_img_path.clone())?;
    let mut encoder = Encoder::new(compressed_img_file, 0)?;
    let _ = io::copy(&mut img_file, &mut encoder)?;
    let mut write_stream = encoder.finish()?;
    write_stream.flush()?;
    let mut cmd = Command::new("sha256sum");
    cmd.arg(compressed_img_path);
    let output = cmd.output()?;
    std::io::stdout().write_all(&output.stdout)?;
    std::io::stderr().write_all(&output.stderr)?;
    if !output.status.success() {
        bail!("Could not create sha256 of image");
    }
    Ok(())
}

/// Creates a GuestOSConfig for a node based on the provided parameters.
fn create_guestos_config_for_node(
    node: &InitializedNode,
    malicious_behavior: Option<MaliciousBehavior>,
    query_stats_epoch_length: Option<u64>,
    ipv4_config: Option<IPv4Config>,
    domain_name: Option<String>,
    recovery_hash: Option<String>,
    test_env: &TestEnv,
    ic_name: &str,
) -> anyhow::Result<GuestOSConfig> {
    // Build NetworkSettings
    let ipv6_config = Ipv6Config::RouterAdvertisement;

    let ipv4_config = match ipv4_config {
        Some(config) => Some(Ipv4Config {
            address: config.ip_addr().parse::<std::net::Ipv4Addr>()?,
            gateway: config.gateway_ip_addr().parse::<std::net::Ipv4Addr>()?,
            prefix_length: config.prefix_length().try_into().unwrap(),
        }),
        None => None,
    };

    let network_settings = NetworkSettings {
        ipv6_config,
        ipv4_config,
        domain_name,
    };

    // Build ICOS settings
    let mgmt_mac = "00:00:00:00:00:00".parse()?;
    let deployment_environment = DeploymentEnvironment::Testnet;

    let nns_urls = if let Some(node) = test_env
        .topology_snapshot_by_name(ic_name)
        .root_subnet()
        .nodes()
        .next()
    {
        let nns_url = format!("http://[{}]:8080", node.get_ip_addr());
        vec![Url::parse(&nns_url)?]
    } else {
        vec![Url::parse("https://cloudflare.com/cdn-cgi/trace")?]
    };

    let icos_settings = ICOSSettings {
        node_reward_type: None,
        mgmt_mac,
        deployment_environment,
        nns_urls,
        use_node_operator_private_key: true,
        enable_trusted_execution_environment: false,
        use_ssh_authorized_keys: true,
        icos_dev_settings: ICOSDevSettings::default(),
    };

    // Build GuestOSDevSettings
    let guestos_dev_settings = GuestOSDevSettings {
        backup_spool: None,
        malicious_behavior,
        query_stats_epoch_length,
        bitcoind_addr: test_env
            .read_json_object::<String, _>(BITCOIND_ADDR_PATH)
            .ok(),
        dogecoind_addr: test_env
            .read_json_object::<String, _>(DOGECOIND_ADDR_PATH)
            .ok(),
        jaeger_addr: test_env
            .read_json_object::<String, _>(JAEGER_ADDR_PATH)
            .ok(),
        socks_proxy: test_env
            .read_json_object::<String, _>(SOCKS_PROXY_PATH)
            .ok(),
        hostname: Some(node.node_id.to_string()),
        generate_ic_boundary_tls_cert: node.node_config.domain.clone(),
    };

    let guestos_settings = GuestOSSettings {
        inject_ic_crypto: false,
        inject_ic_state: false,
        inject_ic_registry_local_store: false,
        guestos_dev_settings,
    };

    // Assemble GuestOSConfig
    Ok(GuestOSConfig {
        config_version: CONFIG_VERSION.to_string(),
        network_settings,
        icos_settings,
        guestos_settings,
        guest_vm_type: GuestVMType::Default,
        upgrade_config: GuestOSUpgradeConfig::default(),
        trusted_execution_environment_config: None,
        recovery_config: recovery_hash.map(|hash| RecoveryConfig {
            recovery_hash: hash,
        }),
    })
}

fn node_to_config(node: &Node) -> NodeConfiguration {
    let ipv6_addr = IpAddr::V6(node.ipv6.expect("Missing ip_addr"));
    let public_api = SocketAddr::new(ipv6_addr, AddrType::PublicApi.into());
    let xnet_api = SocketAddr::new(ipv6_addr, AddrType::Xnet.into());
    NodeConfiguration {
        xnet_api,
        public_api,
        // this value will be overridden by IcConfig::with_node_operator()
        node_operator_principal_id: None,
        secret_key_store: node.secret_key_store.clone(),
        domain: node.domain.clone(),
        node_reward_type: None,
    }
}

fn create_setupos_config_image(
    env: &TestEnv,
    name: &str,
    nns_url: &Url,
    nns_public_key_override: Option<&Path>,
) -> anyhow::Result<PathBuf> {
    info!(
        env.logger(),
        "[{}] Starting create_setupos_config_image", name
    );

    // Create a unique temporary directory for this thread to avoid conflicts
    let tmp_dir = env.get_path(format!("setupos_config_{name}"));
    fs::create_dir_all(&tmp_dir)?;

    let build_setupos_config_image = get_build_setupos_config_image_tool();

    let nested_vm = env.get_nested_vm(name)?;

    let mac = nested_vm.get_vm()?.mac6;
    let cpu = "kvm";

    let ssh_authorized_pub_keys_dir = env.get_path(SSH_AUTHORIZED_PUB_KEYS_DIR);

    // TODO: We transform the IPv6 to get this information, but it could be
    // passed natively.
    let old_ip = nested_vm.get_vm()?.ipv6;
    info!(env.logger(), "[{}] Got VM with IPv6: {}", name, old_ip);
    let segments = old_ip.segments();
    let prefix = format!(
        "{:04x}:{:04x}:{:04x}:{:04x}",
        segments[0], segments[1], segments[2], segments[3]
    );
    let gateway = format!(
        "{:04x}:{:04x}:{:04x}:{:04x}::1",
        segments[0], segments[1], segments[2], segments[3]
    );

    // Prep config dir
    let config_dir = tmp_dir.join("config");
    std::fs::create_dir_all(config_dir.join("ssh_authorized_keys"))?;

    // Prep data dir
    let data_dir = tmp_dir.join("data");
    std::fs::create_dir_all(&data_dir)?;

    let node_operator_private_key = std::env::var("NODE_OPERATOR_PRIV_KEY_PATH")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from);

    let vm_spec = nested_vm.get_vm_spec()?;

    setupos_image_config::create_setupos_config(
        &config_dir,
        &data_dir,
        ConfigIniSettings {
            ipv6_prefix: prefix,
            ipv6_prefix_length: Default::default(),
            ipv6_gateway: gateway.parse().context("Failed to parse ipv6 gateway")?,
            ipv4_address: Default::default(),
            ipv4_gateway: Default::default(),
            ipv4_prefix_length: Default::default(),
            domain_name: Default::default(),
            verbose: Default::default(),
            node_reward_type: Some("type3.1".to_string()),
            enable_trusted_execution_environment: Default::default(),
        },
        node_operator_private_key.as_deref(),
        nns_public_key_override,
        Some(&ssh_authorized_pub_keys_dir.join("admin")),
        CompatDeploymentSettings {
            deployment: deployment_json::Deployment {
                deployment_environment: DeploymentEnvironment::Testnet,
                mgmt_mac: Some(mac.to_string()),
            },
            logging: deployment_json::Logging::default(),
            nns: deployment_json::Nns {
                urls: vec![nns_url.clone()],
            },
            vm_resources: Some(deployment_json::VmResources {
                memory: (vm_spec.memory_ki_b / 2 / 1024 / 1024) as u32,
                cpu: cpu.to_string(),
                nr_of_vcpus: (vm_spec.v_cpus / 2) as u32,
            }),
            dev_vm_resources: Some(deployment_json::VmResources {
                memory: (vm_spec.memory_ki_b / 2 / 1024 / 1024) as u32,
                cpu: cpu.to_string(),
                nr_of_vcpus: (vm_spec.v_cpus / 2) as u32,
            }),
        },
    )
    .context("Could not create SetupOS config")?;

    // Pack dirs into config image
    let config_image = nested_vm.get_setupos_config_image_path()?;
    let status = Command::new(build_setupos_config_image)
        .arg(config_dir)
        .arg(data_dir)
        .arg(&config_image)
        .status()?;

    if !status.success() {
        bail!("Could not inject configs into image");
    }

    info!(
        env.logger(),
        "[{}] Successfully created config image at: {:?}", name, config_image
    );
    Ok(config_image)
}
