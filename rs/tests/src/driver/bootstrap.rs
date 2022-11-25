use anyhow::{bail, Result};
use flate2::{write::GzEncoder, Compression};
use std::convert::Into;
use std::net::IpAddr;
use std::{collections::BTreeMap, fs::File, io, net::SocketAddr, path::PathBuf, process::Command};

use crate::driver::farm::FarmResult;
use crate::driver::ic::{InternetComputer, Node};
use crate::driver::test_env::{HasIcPrepDir, TestEnv};
use crate::driver::test_env_api::{HasDependencies, HasIcDependencies, NodesInfo};
use ic_base_types::NodeId;
use ic_fondue::ic_instance::{
    node_software_version::NodeSoftwareVersion, port_allocator::AddrType,
};
use ic_prep_lib::{
    internet_computer::{IcConfig, InitializedIc, TopologyConfig},
    node::{InitializedNode, NodeConfiguration, NodeIndex},
    subnet_configuration::SubnetConfig,
};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_subnet_type::SubnetType;
use ic_types::malicious_behaviour::MaliciousBehaviour;
use slog::{info, warn, Logger};
use std::io::Write;
use std::thread::{self, JoinHandle};
use url::Url;

use super::config::NODES_INFO;
use super::driver_setup::SSH_AUTHORIZED_PUB_KEYS_DIR;
use super::resource::AllocatedVm;

pub type UnassignedNodes = BTreeMap<NodeIndex, NodeConfiguration>;
pub type NodeVms = BTreeMap<NodeId, AllocatedVm>;

const CONF_IMG_FNAME: &str = "config_disk.img";
const BITCOIND_ADDR_PATH: &str = "bitcoind_addr";

fn mk_compressed_img_path() -> std::string::String {
    return format!("{}.gz", CONF_IMG_FNAME);
}

pub fn init_ic(
    ic: &InternetComputer,
    test_env: &TestEnv,
    logger: &Logger,
) -> Result<InitializedIc> {
    let mut next_node_index = 0u64;
    let ic_name = ic.name();
    let working_dir = test_env.create_prep_dir(&ic_name)?;

    if let Some(bitcoind_addr) = &ic.bitcoind_addr {
        test_env.write_json_object(BITCOIND_ADDR_PATH, &bitcoind_addr)?;
    }

    // In production, this dummy hash is not actually checked and exists
    // only as a placeholder: Updating individual binaries (replica/orchestrator)
    // is not supported anymore.
    let dummy_hash = "60958ccac3e5dfa6ae74aa4f8d6206fd33a5fc9546b8abaad65e3f1c4023c5bf".to_string();
    let initial_replica_version = test_env.get_initial_replica_version()?;
    info!(
        logger,
        "Replica Version that is passed in: {:?}", &initial_replica_version
    );
    let initial_replica = ic
        .initial_version
        .clone()
        .unwrap_or_else(|| NodeSoftwareVersion {
            replica_version: initial_replica_version,
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
                Some(initial_replica.replica_version.clone()),
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
                subnet.ssh_readonly_access.clone(),
                subnet.ssh_backup_access.clone(),
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
                test_env.get_malicious_ic_os_update_img_sha256()?,
                test_env.get_malicious_ic_os_update_img_url()?,
            )
        } else {
            (
                test_env.get_ic_os_update_img_sha256()?,
                test_env.get_ic_os_update_img_url()?,
            )
        }
    };
    let ic_config = IcConfig::new(
        working_dir.path(),
        ic_topology,
        Some(initial_replica.replica_version),
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

    Ok(ic_config.initialize()?)
}

use crate::driver::farm::Farm;

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

    let mut join_handles: Vec<JoinHandle<anyhow::Result<()>>> = vec![];
    let mut nodes_info = NodesInfo::new();
    for node in nodes {
        let group_name = group_name.to_string();
        let vm_name = node.node_id.to_string();
        let t_farm = farm.clone();
        let t_env = env.clone();
        let ic_name = ic.name();
        let malicious_behaviour = ic.get_malicious_behavior_of_node(node.node_id);
        nodes_info.insert(node.node_id, malicious_behaviour.clone());
        join_handles.push(thread::spawn(move || {
            create_config_disk_image(&ic_name, &node, malicious_behaviour, &t_env, &group_name)?;
            let image_id = upload_config_disk_image(&node, &t_farm)?;
            // delete uncompressed file
            let conf_img_path = PathBuf::from(&node.node_path).join(CONF_IMG_FNAME);
            std::fs::remove_file(conf_img_path)?;
            t_farm.attach_disk_image(&group_name, &vm_name, "usb-storage", image_id)?;
            t_farm.start_vm(&group_name, &vm_name)?;
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

pub fn upload_config_disk_image(node: &InitializedNode, farm: &Farm) -> FarmResult<String> {
    let compressed_img_path = mk_compressed_img_path();
    let target_file = PathBuf::from(&node.node_path).join(compressed_img_path.clone());
    let image_id = farm.upload_file(target_file, &compressed_img_path)?;
    info!(farm.logger, "Uploaded image: {}", image_id);
    Ok(image_id)
}

/// side-effectful function that creates the config disk images in the node
/// directories.
pub fn create_config_disk_image(
    ic_name: &str,
    node: &InitializedNode,
    malicious_behavior: Option<MaliciousBehaviour>,
    test_env: &TestEnv,
    group_name: &str,
) -> anyhow::Result<()> {
    let img_path = PathBuf::from(&node.node_path).join(CONF_IMG_FNAME);
    let script_path =
        test_env.get_dependency_path("ic-os/guestos/scripts/build-bootstrap-config-image.sh");
    let mut cmd = Command::new(script_path);
    let local_store_path = test_env
        .prep_dir(ic_name)
        .expect("no no name IC")
        .registry_local_store_path();
    cmd.arg(img_path.clone())
        .arg("--hostname")
        .arg(node.node_id.to_string())
        .arg("--ic_registry_local_store")
        .arg(local_store_path)
        .arg("--ic_crypto")
        .arg(node.crypto_path())
        .arg("--journalbeat_tags")
        .arg(format!("system_test {}", group_name));

    if let Some(malicious_behavior) = malicious_behavior {
        info!(
            test_env.logger(),
            "Node with id={} has malicious behavior={:?}", node.node_id, malicious_behavior
        );
        cmd.arg("--malicious_behavior")
            .arg(serde_json::to_string(&malicious_behavior)?);
    }

    let ssh_authorized_pub_keys_dir: PathBuf = test_env.get_path(SSH_AUTHORIZED_PUB_KEYS_DIR);
    if ssh_authorized_pub_keys_dir.exists() {
        cmd.arg("--accounts_ssh_authorized_keys")
            .arg(ssh_authorized_pub_keys_dir);
    }

    let journalbeat_hosts: Vec<String> = test_env.get_journalbeat_hosts()?;
    info!(
        test_env.logger(),
        "journal beat hosts are {:?}", journalbeat_hosts
    );
    if !journalbeat_hosts.is_empty() {
        cmd.arg("--journalbeat_hosts")
            .arg(journalbeat_hosts.join(" "));
    }

    let replica_log_debug_overrides: Vec<String> = test_env.get_replica_log_debug_overrides()?;

    info!(
        test_env.logger(),
        "replica-log-debug-overrides args are {:?}", replica_log_debug_overrides
    );

    if !replica_log_debug_overrides.is_empty() {
        let replica_log_debug_overrides_val = format!(
            "[{}]",
            replica_log_debug_overrides
                .iter()
                .map(|component_unquoted| format!("\"{}\"", component_unquoted))
                .collect::<Vec<_>>()
                .join(",")
        );
        cmd.arg("--replica_log_debug_overrides")
            .arg(replica_log_debug_overrides_val);
    }
    // --bitcoind_addr indicates the local bitcoin node that the bitcoin adapter should be connected to in the system test environment.
    if let Ok(arg) = test_env.read_json_object::<String, _>(BITCOIND_ADDR_PATH) {
        cmd.arg("--bitcoind_addr").arg(arg);
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
    let mut encoder = GzEncoder::new(compressed_img_file, Compression::default());
    let _ = io::copy(&mut img_file, &mut encoder)?;
    let mut write_stream = encoder.finish()?;
    write_stream.flush()?;
    let mut cmd = Command::new("sha256sum");
    cmd.arg(compressed_img_path);
    let output = cmd.output()?;
    if !output.status.success() {
        bail!("could not create sha256 of image");
    }
    std::io::stdout().write_all(&output.stdout)?;
    std::io::stderr().write_all(&output.stderr)?;
    Ok(())
}

fn node_to_config(node: &Node) -> NodeConfiguration {
    let ipv6_addr = IpAddr::V6(node.ipv6.expect("missing ip_addr"));
    let public_api = SocketAddr::new(ipv6_addr, AddrType::PublicApi.into());
    let xnet_api = SocketAddr::new(ipv6_addr, AddrType::Xnet.into());
    let p2p_addr = SocketAddr::new(ipv6_addr, AddrType::P2P.into());
    let prometheus_addr = SocketAddr::new(ipv6_addr, AddrType::Prometheus.into());
    NodeConfiguration {
        xnet_api: vec![xnet_api.into()],
        public_api: vec![public_api.into()],
        private_api: vec![],
        p2p_addr: format!("org.internetcomputer.p2p1://{}", p2p_addr)
            .parse()
            .expect("can't fail"),
        p2p_num_flows: 1,
        p2p_start_flow_tag: 1234,
        prometheus_metrics: vec![prometheus_addr.into()],
        // this value will be overridden by IcConfig::with_node_operator()
        node_operator_principal_id: None,
        secret_key_store: node.secret_key_store.clone(),
    }
}
