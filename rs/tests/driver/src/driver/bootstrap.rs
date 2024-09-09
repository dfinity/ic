use crate::driver::{
    config::NODES_INFO,
    driver_setup::SSH_AUTHORIZED_PUB_KEYS_DIR,
    farm::{AttachImageSpec, Farm, FarmResult, FileId},
    ic::{InternetComputer, Node},
    nested::{NestedNode, NestedVms, NESTED_CONFIGURED_IMAGE_PATH},
    node_software_version::NodeSoftwareVersion,
    port_allocator::AddrType,
    resource::AllocatedVm,
    test_env::{HasIcPrepDir, TestEnv, TestEnvAttribute},
    test_env_api::{
        get_dependency_path, get_elasticsearch_hosts, get_ic_os_update_img_sha256,
        get_ic_os_update_img_url, get_mainnet_ic_os_update_img_url,
        get_malicious_ic_os_update_img_sha256, get_malicious_ic_os_update_img_url,
        read_dependency_from_env_to_string, read_dependency_to_string, HasIcDependencies,
        HasTopologySnapshot, IcNodeContainer, InitialReplicaVersion, NodesInfo,
    },
    test_setup::InfraProvider,
};
use crate::k8s::datavolume::DataVolumeContentType;
use crate::k8s::images::*;
use crate::k8s::tnet::{TNet, TNode};
use crate::util::block_on;
use anyhow::{bail, Result};
use ic_base_types::NodeId;
use ic_prep_lib::{
    internet_computer::{IcConfig, InitializedIc, TopologyConfig},
    node::{InitializedNode, NodeConfiguration, NodeIndex},
    subnet_configuration::SubnetConfig,
};
use ic_registry_canister_api::IPv4Config;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_subnet_type::SubnetType;
use ic_types::malicious_behaviour::MaliciousBehaviour;
use ic_types::ReplicaVersion;
use slog::{info, warn, Logger};
use std::{
    collections::BTreeMap,
    convert::Into,
    fs::File,
    io,
    io::Write,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    process::Command,
    thread::{self, JoinHandle},
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

    let replica_version = if ic.with_mainnet_config {
        let mainnet_nns_revisions_path = "testnet/mainnet_nns_revision.txt".to_string();
        read_dependency_to_string(mainnet_nns_revisions_path.clone())?
    } else {
        read_dependency_from_env_to_string("ENV_DEPS__IC_VERSION_FILE")?
    };

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
    info!(logger, "initial_replica: {:?}", initial_replica);

    // Note: NNS subnet should be selected from among the system subnets.
    // If there is no system subnet, fall back on choosing the first one.
    let mut nns_subnet_idx = Some(0);
    // TopologyConfig is a structure provided by ic-prep. We translate from the
    // builder (InternetComputer) to TopologyConfig. While doing so, we allocate tcp
    // ports for the http handler, p2p and xnet. The corresponding sockets are
    // closed when the port-allocator is dropped—which happens before we start the
    // nodes.
    let mut ic_topology = TopologyConfig::default();
    for (subnet_idx, subnet) in ic.subnets.iter().enumerate() {
        if subnet.subnet_type == SubnetType::System {
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

    let whitelist = ProvisionalWhitelist::All;
    let (ic_os_update_img_sha256, ic_os_update_img_url) = {
        if ic.has_malicious_behaviours() {
            warn!(
                logger,
                "Using malicious guestos update image for IC config."
            );
            (
                get_malicious_ic_os_update_img_sha256()?,
                get_malicious_ic_os_update_img_url()?,
            )
        } else if ic.with_mainnet_config {
            (
                test_env.get_mainnet_ic_os_update_img_sha256()?,
                get_mainnet_ic_os_update_img_url()?,
            )
        } else {
            (get_ic_os_update_img_sha256()?, get_ic_os_update_img_url()?)
        }
    };
    let mut ic_config = IcConfig::new(
        working_dir.path(),
        ic_topology,
        initial_replica.replica_version,
        // To maintain backwards compatibility, pass true here.
        // False is used only when nodes need to be deployed without
        // them joining any subnet initially

        /* generate_subnet_records= */
        true,
        nns_subnet_idx,
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
        let malicious_behaviour = ic.get_malicious_behavior_of_node(node.node_id);
        let query_stats_epoch_length = ic.get_query_stats_epoch_length_of_node(node.node_id);
        let ipv4_config = ic.get_ipv4_config_of_node(node.node_id);
        let domain = ic.get_domain_of_node(node.node_id);
        nodes_info.insert(node.node_id, malicious_behaviour.clone());
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
                malicious_behaviour,
                query_stats_epoch_length,
                ipv4_config,
                domain,
                &t_env,
                &group_name,
            )?;

            let conf_img_path = PathBuf::from(&node.node_path).join(CONF_IMG_FNAME);
            match InfraProvider::read_attribute(&t_env) {
                InfraProvider::K8s => {
                    let url = format!(
                        "{}/{}",
                        tnet_node.config_url.clone().expect("missing config_url"),
                        CONF_IMG_FNAME
                    );
                    info!(
                        t_env.logger(),
                        "Uploading image {} to {}",
                        conf_img_path.clone().display().to_string(),
                        url.clone()
                    );
                    block_on(upload_image(conf_img_path.as_path(), &url))
                        .expect("Failed to upload config image");
                    block_on(tnet_node.deploy_config_image(
                        CONF_IMG_FNAME,
                        "config",
                        DataVolumeContentType::Kubevirt,
                    ))
                    .expect("deploying config image failed");
                    block_on(tnet_node.start()).expect("starting vm failed");
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
        if let Err(e) = jh.join().expect("waiting for a thread failed") {
            warn!(farm.logger, "starting VM failed with: {:?}", e);
            result = Err(anyhow::anyhow!(
                "failed to set up and start a VM pool: {:?}",
                e
            ));
        }
    }
    result
}

// Startup nested VMs. NOTE: This is different from `setup_and_start_vms` in
// that we need to configure and push a SetupOS image for each node.
pub fn setup_and_start_nested_vms(
    nodes: &[NestedNode],
    env: &TestEnv,
    farm: &Farm,
    group_name: &str,
    nns_url: &Url,
    nns_public_key: &str,
) -> anyhow::Result<()> {
    let mut join_handles: Vec<JoinHandle<anyhow::Result<()>>> = vec![];
    for node in nodes {
        let t_farm = farm.to_owned();
        let t_env = env.to_owned();
        let t_group_name = group_name.to_owned();
        let t_vm_name = node.name.to_owned();
        let t_nns_url = nns_url.to_owned();
        let t_nns_public_key = nns_public_key.to_owned();
        join_handles.push(thread::spawn(move || {
            let configured_image =
                configure_setupos_image(&t_env, &t_vm_name, &t_nns_url, &t_nns_public_key)?;

            let configured_image_spec = AttachImageSpec::new(t_farm.upload_file(
                &t_group_name,
                configured_image,
                NESTED_CONFIGURED_IMAGE_PATH,
            )?);
            t_farm.attach_disk_images(
                &t_group_name,
                &t_vm_name,
                "usb-storage",
                vec![configured_image_spec],
            )?;
            t_farm.start_vm(&t_group_name, &t_vm_name)?;

            Ok(())
        }));
    }

    let mut result = Ok(());
    // Wait for all threads to finish and return an error if any of them fails.
    for jh in join_handles {
        if let Err(e) = jh.join().expect("waiting for a thread failed") {
            warn!(farm.logger, "starting VM failed with: {:?}", e);
            result = Err(anyhow::anyhow!("failed to set up and start a VM pool"));
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
    malicious_behavior: Option<MaliciousBehaviour>,
    query_stats_epoch_length: Option<u64>,
    ipv4_config: Option<IPv4Config>,
    domain: Option<String>,
    test_env: &TestEnv,
    group_name: &str,
) -> anyhow::Result<()> {
    let img_path = PathBuf::from(&node.node_path).join(CONF_IMG_FNAME);
    let script_path =
        get_dependency_path("ic-os/components/hostos-scripts/build-bootstrap-config-image.sh");
    let mut cmd = Command::new(script_path);
    let local_store_path = test_env
        .prep_dir(ic_name)
        .expect("no no-name IC")
        .registry_local_store_path();
    cmd.arg(img_path.clone())
        .arg("--hostname")
        .arg(node.node_id.to_string())
        .arg("--ic_registry_local_store")
        .arg(local_store_path)
        .arg("--ic_state")
        .arg(node.state_path())
        .arg("--ic_crypto")
        .arg(node.crypto_path())
        .arg("--elasticsearch_tags")
        .arg(format!("system_test {}", group_name));

    // We've seen k8s nodes fail to pick up RA correctly, so we specify their
    // addresses directly. Ideally, all nodes should do this, to match mainnet.
    if InfraProvider::read_attribute(test_env) == InfraProvider::K8s {
        cmd.arg("--ipv6_address")
            .arg(format!("{}/64", node.node_config.public_api.ip()))
            .arg("--ipv6_gateway")
            .arg("fe80::ecee:eeff:feee:eeee");
    }

    // If we have a root subnet, specify the correct NNS url.
    if let Some(node) = test_env
        .topology_snapshot_by_name(ic_name)
        .root_subnet()
        .nodes()
        .next()
    {
        cmd.arg("--nns_url")
            .arg(format!("http://[{}]:8080", node.get_ip_addr()));
    }

    if let Some(malicious_behavior) = malicious_behavior {
        info!(
            test_env.logger(),
            "Node with id={} has malicious behavior={:?}", node.node_id, malicious_behavior
        );
        cmd.arg("--malicious_behavior")
            .arg(serde_json::to_string(&malicious_behavior)?);
    }

    if let Some(query_stats_epoch_length) = query_stats_epoch_length {
        info!(
            test_env.logger(),
            "Node with id={} has query_stats_epoch_length={:?}",
            node.node_id,
            query_stats_epoch_length
        );
        cmd.arg("--query_stats_epoch_length")
            .arg(format!("{}", query_stats_epoch_length));
    }

    if let Some(ipv4_config) = ipv4_config {
        info!(
            test_env.logger(),
            "Node with id={} is IPv4-enabled: {:?}", node.node_id, ipv4_config
        );
        cmd.arg("--ipv4_address").arg(format!(
            "{}/{:?}",
            ipv4_config.ip_addr(),
            ipv4_config.prefix_length()
        ));
        cmd.arg("--ipv4_gateway").arg(ipv4_config.gateway_ip_addr());
    }

    if let Some(domain) = domain {
        info!(
            test_env.logger(),
            "Node with id={} has domain_name {}", node.node_id, domain,
        );
        cmd.arg("--domain").arg(domain);
    }

    let ssh_authorized_pub_keys_dir: PathBuf = test_env.get_path(SSH_AUTHORIZED_PUB_KEYS_DIR);
    if ssh_authorized_pub_keys_dir.exists() {
        cmd.arg("--accounts_ssh_authorized_keys")
            .arg(ssh_authorized_pub_keys_dir);
    }

    let elasticsearch_hosts: Vec<String> = get_elasticsearch_hosts()?;
    info!(
        test_env.logger(),
        "ElasticSearch hosts are {:?}", elasticsearch_hosts
    );
    if !elasticsearch_hosts.is_empty() {
        cmd.arg("--elasticsearch_hosts")
            .arg(elasticsearch_hosts.join(" "));
    }

    // --bitcoind_addr indicates the local bitcoin node that the bitcoin adapter should be connected to in the system test environment.
    if let Ok(arg) = test_env.read_json_object::<String, _>(BITCOIND_ADDR_PATH) {
        cmd.arg("--bitcoind_addr").arg(arg);
    }
    // --jaeger_addr indicates the local Jaeger node that the nodes should be connected to in the system test environment.
    if let Ok(arg) = test_env.read_json_object::<String, _>(JAEGER_ADDR_PATH) {
        cmd.arg("--jaeger_addr").arg(arg);
    }
    // --socks_proxy indicates that a socks proxy is available to the system test environment.
    if let Ok(arg) = test_env.read_json_object::<String, _>(SOCKS_PROXY_PATH) {
        cmd.arg("--socks_proxy").arg(arg);
    }
    let key = "PATH";
    let old_path = match std::env::var(key) {
        Ok(val) => {
            println!("{}: {:?}", key, val);
            val
        }
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
        bail!("could not create sha256 of image");
    }
    Ok(())
}

fn node_to_config(node: &Node) -> NodeConfiguration {
    let ipv6_addr = IpAddr::V6(node.ipv6.expect("missing ip_addr"));
    let public_api = SocketAddr::new(ipv6_addr, AddrType::PublicApi.into());
    let xnet_api = SocketAddr::new(ipv6_addr, AddrType::Xnet.into());
    NodeConfiguration {
        xnet_api,
        public_api,
        // this value will be overridden by IcConfig::with_node_operator()
        node_operator_principal_id: None,
        secret_key_store: node.secret_key_store.clone(),
    }
}

fn configure_setupos_image(
    env: &TestEnv,
    name: &str,
    nns_url: &Url,
    nns_public_key: &str,
) -> anyhow::Result<PathBuf> {
    let setupos_image = get_dependency_path("ic-os/setupos/envs/dev/disk-img.tar.zst");
    let setupos_inject_configs = get_dependency_path(
        "rs/ic_os/dev_test_tools/setupos-inject-configuration/setupos-inject-configuration",
    );
    let setupos_disable_checks = get_dependency_path(
        "rs/ic_os/dev_test_tools/setupos-disable-checks/setupos-disable-checks",
    );

    let nested_vm = env.get_nested_vm(name)?;

    let mac = nested_vm.get_vm()?.mac6;
    let memory = "16";
    let cpu = "qemu";

    let ssh_authorized_pub_keys_dir = env.get_path(SSH_AUTHORIZED_PUB_KEYS_DIR);
    let admin_keys: Vec<_> = std::fs::read_to_string(ssh_authorized_pub_keys_dir.join("admin"))
        .map(|v| v.lines().map(|v| v.to_owned()).collect())
        .unwrap_or_default();

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

    let tmp_dir = tempfile::tempdir().unwrap();
    let uncompressed_image = tmp_dir.path().join("disk.img");

    let output = Command::new("tar")
        .arg("xaf")
        .arg(&setupos_image)
        .arg("-C")
        .arg(tmp_dir.path())
        .output()?;
    std::io::stdout().write_all(&output.stdout)?;
    std::io::stderr().write_all(&output.stderr)?;
    if !output.status.success() {
        bail!("could not extract image");
    }

    let path_key = "PATH";
    let new_path = format!("{}:{}", "/usr/sbin", std::env::var(path_key)?);

    let output = Command::new(setupos_disable_checks)
        .arg("--image-path")
        .arg(&uncompressed_image)
        .env(path_key, &new_path)
        .output()?;
    std::io::stdout().write_all(&output.stdout)?;
    std::io::stderr().write_all(&output.stderr)?;
    if !output.status.success() {
        bail!("could not disable checks on image");
    }

    let mut cmd = Command::new(setupos_inject_configs);
    cmd.arg("--image-path")
        .arg(&uncompressed_image)
        .arg("--mgmt-mac")
        .arg(&mac)
        .arg("--ipv6-prefix")
        .arg(&prefix)
        .arg("--ipv6-gateway")
        .arg(&gateway)
        .arg("--memory-gb")
        .arg(memory)
        .arg("--cpu")
        .arg(cpu)
        .arg("--nns-url")
        .arg(nns_url.to_string())
        .arg("--nns-public-key")
        .arg(nns_public_key)
        .env(path_key, &new_path);

    if !admin_keys.is_empty() {
        cmd.arg("--public-keys");
        for key in admin_keys {
            cmd.arg(key);
        }
    }

    let output = cmd.output()?;
    std::io::stdout().write_all(&output.stdout)?;
    std::io::stderr().write_all(&output.stderr)?;
    if !output.status.success() {
        bail!("could not inject configs into image");
    }

    let configured_image = nested_vm.get_configured_setupos_image_path().unwrap();

    let mut img_file = File::open(&uncompressed_image)?;
    let configured_image_file = File::create(configured_image.clone())?;
    let mut encoder = Encoder::new(configured_image_file, 0)?;
    let _ = io::copy(&mut img_file, &mut encoder)?;
    let mut write_stream = encoder.finish()?;
    write_stream.flush()?;

    Ok(configured_image)
}
