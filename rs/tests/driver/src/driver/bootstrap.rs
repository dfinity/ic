use crate::k8s::config::LOGS_URL;
use crate::k8s::images::*;
use crate::k8s::tnet::{TNet, TNode};
use crate::util::block_on;
use crate::{
    driver::{
        config::NODES_INFO,
        driver_setup::SSH_AUTHORIZED_PUB_KEYS_DIR,
        farm::{AttachImageSpec, Farm, FarmResult, FileId},
        ic::{InternetComputer, Node},
        nested::{NestedNode, NestedVms, NESTED_CONFIG_IMAGE_PATH},
        node_software_version::NodeSoftwareVersion,
        port_allocator::AddrType,
        resource::{AllocatedVm, HOSTOS_MEMORY_KIB_PER_VM, HOSTOS_VCPUS_PER_VM},
        test_env::{HasIcPrepDir, TestEnv, TestEnvAttribute},
        test_env_api::{
            get_dependency_path_from_env, get_elasticsearch_hosts, get_guestos_img_version,
            get_guestos_initial_update_img_sha256, get_guestos_initial_update_img_url,
            get_setupos_img_sha256, get_setupos_img_url, HasTopologySnapshot, HasVmName,
            IcNodeContainer, InitialReplicaVersion, NodesInfo,
        },
        test_setup::InfraProvider,
    },
    k8s::job::wait_for_job_completion,
};
use anyhow::{bail, Context, Result};
use config::generate_testnet_config::{
    generate_testnet_config, GenerateTestnetConfigArgs, Ipv6ConfigType,
};
use config::hostos::guestos_bootstrap_image::BootstrapOptions;
use config_types::DeploymentEnvironment;
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
use ic_types::ReplicaVersion;
use slog::{info, warn, Logger};
use std::{
    collections::BTreeMap,
    convert::Into,
    fs,
    fs::File,
    io,
    io::Write,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    process::Command,
    thread::{self, JoinHandle, ScopedJoinHandle},
};
use url::Url;
use zstd::stream::write::Encoder;

pub type UnassignedNodes = BTreeMap<NodeIndex, NodeConfiguration>;
pub type NodeVms = BTreeMap<NodeId, AllocatedVm>;

const CONF_IMG_FNAME: &str = "config_disk.img";
const BITCOIND_ADDR_PATH: &str = "bitcoind_addr";
const JAEGER_ADDR_PATH: &str = "jaeger_addr";
const SOCKS_PROXY_PATH: &str = "socks_proxy";

fn mk_compressed_img_path() -> std::string::String {
    format!("{}.zst", CONF_IMG_FNAME)
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

    let replica_version = get_guestos_img_version()?;
    let replica_version = ReplicaVersion::try_from(replica_version.clone())?;
    let initial_replica_version = InitialReplicaVersion {
        version: replica_version.clone(),
    };
    initial_replica_version.write_attribute(test_env);
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
    let (ic_os_update_img_sha256, ic_os_update_img_url) = (
        get_guestos_initial_update_img_sha256()?,
        get_guestos_initial_update_img_url()?,
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
        Some(whitelist),
        ic.node_operator,
        ic.node_provider,
        ic.ssh_readonly_access_to_unassigned_nodes.clone(),
    );

    ic_config.set_use_specified_ids_allocation_range(specific_ids);

    info!(test_env.logger(), "Initializing via {:?}", &ic_config);

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

    let tnet = match InfraProvider::read_attribute(env) {
        InfraProvider::K8s => TNet::read_attribute(env),
        InfraProvider::Farm => TNet::new("dummy")?,
    };

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
        nodes_info.insert(node.node_id, malicious_behavior.clone());
        let tnet_node = match InfraProvider::read_attribute(env) {
            InfraProvider::K8s => tnet
                .nodes
                .iter()
                .find(|n| n.node_id.clone().expect("node_id missing") == vm_name.clone())
                .expect("tnet doesn't have this node")
                .clone(),
            InfraProvider::Farm => TNode::default(),
        };
        join_handles.push(thread::spawn(move || {
            create_config_disk_image(
                &ic_name,
                &node,
                malicious_behavior,
                query_stats_epoch_length,
                ipv4_config,
                domain,
                &t_env,
                &group_name,
            )?;

            let conf_img_path = PathBuf::from(&node.node_path).join(mk_compressed_img_path());
            match InfraProvider::read_attribute(&t_env) {
                InfraProvider::K8s => {
                    let url = format!(
                        "{}/{}",
                        tnet_node.config_url.clone().expect("Missing config_url"),
                        mk_compressed_img_path()
                    );
                    info!(
                        t_env.logger(),
                        "Uploading image {} to {}",
                        conf_img_path.clone().display().to_string(),
                        url.clone()
                    );
                    block_on(upload_image(conf_img_path.as_path(), &url))
                        .expect("Failed to upload config image");
                    // wait for job pulling the disk to complete
                    block_on(wait_for_job_completion(&tnet_node.name.clone().unwrap()))
                        .expect("Waiting for job failed");
                    block_on(tnet_node.start()).expect("Starting vm failed");
                    let node_name = tnet_node.name.unwrap();
                    info!(t_farm.logger, "Starting k8s vm: {}", node_name);
                    info!(
                        t_farm.logger,
                        "VM {} console logs: {}",
                        node_name.clone(),
                        LOGS_URL.replace("{job}", &node_name)
                    );
                }
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
    test_env: &TestEnv,
    group_name: &str,
) -> anyhow::Result<()> {
    // Build GuestOS config object
    let mut config = GenerateTestnetConfigArgs {
        ipv6_config_type: Some(Ipv6ConfigType::RouterAdvertisement),
        deterministic_prefix: None,
        deterministic_prefix_length: None,
        deterministic_gateway: None,
        fixed_address: None,
        fixed_gateway: None,
        ipv4_address: None,
        ipv4_gateway: None,
        ipv4_prefix_length: None,
        domain_name: None,
        node_reward_type: None,
        mgmt_mac: None,
        deployment_environment: Some(DeploymentEnvironment::Testnet),
        elasticsearch_hosts: None,
        elasticsearch_tags: Some(format!("system_test {}", group_name)),
        use_nns_public_key: Some(true),
        nns_urls: None,
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

    // We've seen k8s nodes fail to pick up RA correctly, so we specify their
    // addresses directly. Ideally, all nodes should do this, to match mainnet.
    if InfraProvider::read_attribute(test_env) == InfraProvider::K8s {
        let ip = format!("{}/64", node.node_config.public_api.ip());
        let gateway = "fe80::ecee:eeff:feee:eeee".to_string();

        config.ipv6_config_type = Some(Ipv6ConfigType::Fixed);
        config.fixed_address = Some(ip.clone());
        config.fixed_gateway = Some(gateway.clone());
    }

    // If we have a root subnet, specify the correct NNS url.
    if let Some(node) = test_env
        .topology_snapshot_by_name(ic_name)
        .root_subnet()
        .nodes()
        .next()
    {
        let nns_url = format!("http://[{}]:8080", node.get_ip_addr());
        config.nns_urls = Some(vec![nns_url.clone()]);
    }

    if let Some(malicious_behavior) = malicious_behavior {
        info!(
            test_env.logger(),
            "Node with id={} has malicious behavior={:?}", node.node_id, malicious_behavior
        );
        config.malicious_behavior = Some(serde_json::to_string(&malicious_behavior)?);
    }

    if let Some(query_stats_epoch_length) = query_stats_epoch_length {
        info!(
            test_env.logger(),
            "Node with id={} has query_stats_epoch_length={:?}",
            node.node_id,
            query_stats_epoch_length
        );
        config.query_stats_epoch_length = Some(query_stats_epoch_length);
    }

    if let Some(ref ipv4_config) = ipv4_config {
        info!(
            test_env.logger(),
            "Node with id={} is IPv4-enabled: {:?}", node.node_id, ipv4_config
        );
        config.ipv4_address = Some(ipv4_config.ip_addr().to_string());
        config.ipv4_gateway = Some(ipv4_config.gateway_ip_addr().to_string());
        config.ipv4_prefix_length = Some(ipv4_config.prefix_length().try_into().unwrap());
    }

    // if the node has a domain name, generate a certificate to be used
    // when the node is an API boundary node.
    if let Some(domain_name) = &node.node_config.domain {
        config.generate_ic_boundary_tls_cert = Some(domain_name.to_string());
    }

    if let Some(ref domain_name) = domain_name {
        info!(
            test_env.logger(),
            "Node with id={} has domain_name {}", node.node_id, domain_name,
        );
        config.domain_name = Some(domain_name.to_string());
    }

    let elasticsearch_hosts: Vec<String> = get_elasticsearch_hosts()?;
    info!(
        test_env.logger(),
        "ElasticSearch hosts are {:?}", elasticsearch_hosts
    );
    if !elasticsearch_hosts.is_empty() {
        config.elasticsearch_hosts = Some(elasticsearch_hosts.join(" "));
    }

    // The bitcoin_addr specifies the local bitcoin node that the bitcoin adapter should connect to in the system test environment.
    if let Ok(bitcoind_addr) = test_env.read_json_object::<String, _>(BITCOIND_ADDR_PATH) {
        config.bitcoind_addr = Some(bitcoind_addr.clone());
    }

    // The jaeger_addr specifies the local Jaeger node that the nodes should connect to in the system test environment.
    if let Ok(jaeger_addr) = test_env.read_json_object::<String, _>(JAEGER_ADDR_PATH) {
        config.jaeger_addr = Some(jaeger_addr.clone());
    }

    // The socks_proxy configuration indicates that a socks proxy is available to the system test environment.
    if let Ok(socks_proxy) = test_env.read_json_object::<String, _>(SOCKS_PROXY_PATH) {
        config.socks_proxy = Some(socks_proxy.clone());
    }

    let hostname = node.node_id.to_string();
    config.hostname = Some(hostname.clone());

    // Generate the GuestOS config and set it in bootstrap_options
    bootstrap_options.guestos_config = Some(generate_testnet_config(config)?);

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

// Setup nested VMs. NOTE: This is different from `setup_and_start_vms` in that
// we need to configure and push a SetupOS image for each node.
pub fn setup_nested_vms(
    nodes: &[NestedNode],
    env: &TestEnv,
    farm: &Farm,
    group_name: &str,
    nns_url: &Url,
    nns_public_key: &str,
) -> anyhow::Result<()> {
    let mut result = Ok(());

    thread::scope(|s| {
        let mut join_handles: Vec<ScopedJoinHandle<anyhow::Result<()>>> = vec![];
        for node in nodes {
            join_handles.push(s.spawn(|| {
                let vm_name = &node.name;
                let url = get_setupos_img_url()?;
                let hash = get_setupos_img_sha256()?;
                let setupos_image_spec = AttachImageSpec::via_url(url, hash);

                let config_image =
                    create_setupos_config_image(env, group_name, vm_name, nns_url, nns_public_key)?;
                let config_image_spec = AttachImageSpec::new(farm.upload_file(
                    group_name,
                    config_image,
                    NESTED_CONFIG_IMAGE_PATH,
                )?);

                farm.attach_disk_images(
                    group_name,
                    vm_name,
                    "usb-storage",
                    vec![setupos_image_spec, config_image_spec],
                )
                .map_err(|e| e.into())
            }));
        }

        // Wait for all threads to finish and return an error if any of them fails.
        for jh in join_handles {
            if let Err(e) = jh.join().expect("Waiting for a thread failed") {
                warn!(farm.logger, "Setting up VM failed with: {:?}", e);
                result = Err(anyhow::anyhow!("Failed to set up a VM pool"));
            }
        }
    });

    result
}

pub fn start_nested_vms(env: &TestEnv, farm: &Farm, group_name: &str) -> anyhow::Result<()> {
    for node in env.get_all_nested_vms()? {
        farm.start_vm(group_name, &node.vm_name())?;
    }

    Ok(())
}

fn create_setupos_config_image(
    env: &TestEnv,
    group_name: &str,
    name: &str,
    nns_url: &Url,
    nns_public_key: &str,
) -> anyhow::Result<PathBuf> {
    let tmp_dir = env.get_path("setupos");
    fs::create_dir_all(&tmp_dir)?;

    let build_setupos_config_image = get_dependency_path_from_env("ENV_DEPS__SETUPOS_BUILD_CONFIG");
    let create_setupos_config = get_dependency_path_from_env("ENV_DEPS__SETUPOS_CREATE_CONFIG");

    let nested_vm = env.get_nested_vm(name)?;

    let mac = nested_vm.get_vm()?.mac6;
    let cpu = "kvm";

    let ssh_authorized_pub_keys_dir = env.get_path(SSH_AUTHORIZED_PUB_KEYS_DIR);

    // TODO: We transform the IPv6 to get this information, but it could be
    // passed natively.
    let old_ip = nested_vm.get_vm()?.ipv6;
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
    std::fs::create_dir(&data_dir)?;

    // Prep config contents
    let mut cmd = Command::new(create_setupos_config);
    cmd.arg("--config-dir")
        .arg(&config_dir)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("--deployment-environment")
        .arg("testnet")
        .arg("--mgmt-mac")
        .arg(&mac)
        .arg("--ipv6-prefix")
        .arg(&prefix)
        .arg("--ipv6-gateway")
        .arg(&gateway)
        .arg("--memory-gb")
        .arg((HOSTOS_MEMORY_KIB_PER_VM / 2 / 1024 / 1024).to_string())
        .arg("--cpu")
        .arg(cpu)
        .arg("--nr-of-vcpus")
        .arg((HOSTOS_VCPUS_PER_VM / 2).to_string())
        .arg("--nns-urls")
        .arg(nns_url.to_string())
        .arg("--nns-public-key")
        .arg(nns_public_key)
        .arg("--node-reward-type")
        .arg("type3.1")
        .arg("--admin-keys")
        .arg(ssh_authorized_pub_keys_dir.join("admin"))
        .arg("--elasticsearch-tags")
        .arg(format!("system_test {}", group_name));

    let elasticsearch_hosts: Vec<String> = get_elasticsearch_hosts()?;
    if !elasticsearch_hosts.is_empty() {
        cmd.arg("--elasticsearch-hosts")
            .arg(elasticsearch_hosts.join(" "));
    }

    if let Ok(node_key) = std::env::var("NODE_OPERATOR_PRIV_KEY_PATH") {
        if !node_key.trim().is_empty() {
            cmd.arg("--node-operator-private-key").arg(node_key);
        }
    }

    if !cmd.status()?.success() {
        bail!("Could not create SetupOS config");
    }

    // Pack dirs into config image
    let config_image = nested_vm.get_setupos_config_image_path()?;
    let path_key = "PATH";
    let new_path = format!("{}:{}", "/usr/sbin", std::env::var(path_key)?);
    let status = Command::new(build_setupos_config_image)
        .arg(config_dir)
        .arg(data_dir)
        .arg(&config_image)
        .env(path_key, &new_path)
        .status()?;

    if !status.success() {
        bail!("Could not inject configs into image");
    }

    Ok(config_image)
}
