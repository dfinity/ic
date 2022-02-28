use anyhow::bail;
use flate2::{write::GzEncoder, Compression};
use std::{
    collections::BTreeMap,
    fs::File,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Command,
};

use crate::ic_instance::{
    node_software_version::NodeSoftwareVersion, port_allocator::AddrType, InternetComputer,
};
use crate::prod_tests::farm::FarmResult;
use ic_base_types::NodeId;

use ic_prep_lib::{
    internet_computer::{IcConfig, InitializedIc, TopologyConfig},
    node::{InitializedNode, NodeConfiguration, NodeIndex},
    subnet_configuration::SubnetConfig,
};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_subnet_type::SubnetType;
use ic_types::malicious_behaviour::MaliciousBehaviour;
use slog::{info, warn};
use std::io::Write;
use std::thread::{self, JoinHandle};
use url::Url;

use super::{
    driver_setup::DriverContext,
    resource::{AllocatedVm, ResourceGroup},
};

pub type MaliciousNodes = BTreeMap<NodeId, MaliciousBehaviour>;
pub type UnassignedNodes = BTreeMap<NodeIndex, NodeConfiguration>;
pub type NodeVms = BTreeMap<NodeId, AllocatedVm>;

const CONF_IMG_FNAME: &str = "config_disk.img";

fn mk_compressed_img_path() -> std::string::String {
    return format!("{}.gz", CONF_IMG_FNAME);
}

pub fn init_ic<P: AsRef<Path>>(
    ctx: &DriverContext,
    prep_dir: P,
    ic: InternetComputer,
    res_group: &ResourceGroup,
) -> (InitializedIc, MaliciousNodes, NodeVms) {
    let mut next_node_index = 0u64;
    let working_dir = PathBuf::from(prep_dir.as_ref());
    let mut malicious_nodes: BTreeMap<NodeIndex, MaliciousBehaviour> = Default::default();
    let mut node_idx_to_vm: BTreeMap<NodeIndex, AllocatedVm> = Default::default();

    // In production, this dummy hash is not actually checked and exists
    // only as a placeholder: Updating individual binaries (replica/orchestrator)
    // is not supported anymore.
    let dummy_hash = "60958ccac3e5dfa6ae74aa4f8d6206fd33a5fc9546b8abaad65e3f1c4023c5bf".to_string();
    info!(
        ctx.logger,
        "Replica Version that is passed in: {:?}", ctx.initial_replica_version
    );
    let initial_replica = ic
        .initial_version
        .clone()
        .unwrap_or_else(|| NodeSoftwareVersion {
            replica_version: ctx.initial_replica_version.clone(),
            // the following are dummy values, these are not used in production
            replica_url: Url::parse("file:///opt/replica").unwrap(),
            replica_hash: dummy_hash.clone(),
            orchestrator_url: Url::parse("file:///opt/replica").unwrap(),
            orchestrator_hash: dummy_hash,
        });
    info!(ctx.logger, "initial_replica: {:?}", initial_replica);

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

        for node in subnet.nodes.iter() {
            let node_index = next_node_index;
            next_node_index += 1;
            let vm = res_group
                .get_vm(node_index)
                .expect("Could not find allocated vm for given node index.");
            node_idx_to_vm.insert(node_index, vm);
            nodes.insert(node_index, node_to_config(node_index, res_group));
            if let Some(malicious_behaviour) = &node.malicious_behaviour {
                malicious_nodes.insert(node_index, malicious_behaviour.clone());
            }
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
                subnet.features.clone(),
                subnet.max_number_of_canisters,
                subnet.ssh_readonly_access.clone(),
                subnet.ssh_backup_access.clone(),
            ),
        );
    }

    for node in ic.unassigned_nodes {
        let node_index = next_node_index;
        next_node_index += 1;
        let vm = res_group
            .get_vm(node_index)
            .expect("Could not find allocated vm for given node index.");
        node_idx_to_vm.insert(node_index, vm);
        ic_topology.insert_unassigned_node(
            node_index as NodeIndex,
            node_to_config(node_index, res_group),
        );
        if let Some(malicious_behaviour) = &node.malicious_behaviour {
            malicious_nodes.insert(node_index, malicious_behaviour.clone());
        }
    }

    let whitelist = ProvisionalWhitelist::All;
    let ic_config = IcConfig::new(
        working_dir.as_path(),
        ic_topology,
        Some(initial_replica.replica_version),
        // To maintain backwards compatibility, pass true here.
        // False is used only when nodes need to be deployed without
        // them joining any subnet initially

        /* generate_subnet_records= */
        true,
        nns_subnet_idx,
        None,
        None,
        Some(whitelist),
        ic.node_operator,
        ic.node_provider,
        ic.ssh_readonly_access_to_unassigned_nodes,
    );

    let init_ic = ic_config.initialize().expect("can't fail");

    let malicious_nodes: MaliciousNodes = init_ic
        .initialized_topology
        .values()
        .flat_map(|s| s.initialized_nodes.iter())
        .filter_map(|(node_index, n)| {
            malicious_nodes
                .get(node_index)
                .map(|mal_beh| (n.node_id, mal_beh.clone()))
        })
        .collect();

    let mut node_vms = BTreeMap::new();
    init_ic
        .initialized_topology
        .values()
        .flat_map(|s| s.initialized_nodes.iter())
        .for_each(|(idx, n)| {
            node_vms.insert(n.node_id, node_idx_to_vm.get(idx).cloned().unwrap());
        });

    let delta_idx = node_vms.len();
    init_ic
        .unassigned_nodes
        .values()
        .enumerate()
        .for_each(|(idx, n)| {
            let node_idx = (delta_idx + idx) as u64;
            node_vms.insert(n.node_id, node_idx_to_vm.get(&node_idx).cloned().unwrap());
        });

    (init_ic, malicious_nodes, node_vms)
}

pub fn setup_and_start_vms(
    ctx: &DriverContext,
    initialized_ic: &InitializedIc,
    vms: &NodeVms,
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
    for node in nodes {
        let t_ctx = ctx.clone();
        let local_store_path = initialized_ic.target_dir.join("ic_registry_local_store");
        let vm = vms
            .get(&node.node_id)
            .expect("internal error: vm for given node id not found")
            .clone();
        join_handles.push(thread::spawn(move || {
            create_config_disk_image(&t_ctx, &node, &vm.group_name, &local_store_path)?;
            let image_id = upload_config_disk_image(&t_ctx, &node, &vm.group_name)?;
            t_ctx
                .farm
                .attach_disk_image(&vm.group_name, &vm.name, "usb-storage", image_id)?;
            t_ctx.farm.start_vm(&vm.group_name, &vm.name)?;
            Ok(())
        }));
    }

    let mut result = Ok(());
    // Wait for all threads to finish and return an error if any of them fails.
    for jh in join_handles {
        if let Err(e) = jh.join().expect("waiting for a thread failed") {
            warn!(ctx.logger, "starting VM failed with: {:?}", e);
            result = Err(anyhow::anyhow!("failed to set up and start a VM pool"));
        }
    }
    result
}

pub fn upload_config_disk_image(
    ctx: &DriverContext,
    node: &InitializedNode,
    group_name: &str,
) -> FarmResult<String> {
    let compressed_img_path = mk_compressed_img_path();
    let target_file = PathBuf::from(&node.node_path).join(compressed_img_path.clone());
    let image_id = ctx
        .farm
        .upload_image(group_name, target_file, compressed_img_path)?;
    info!(ctx.logger, "Uploaded image: {}", image_id);
    Ok(image_id)
}

/// side-effectful function that creates the config disk images in the node
/// directories.
pub fn create_config_disk_image(
    ctx: &DriverContext,
    node: &InitializedNode,
    group_name: &str,
    local_store_path: &Path,
) -> anyhow::Result<()> {
    let img_path = PathBuf::from(&node.node_path).join(CONF_IMG_FNAME);
    let mut cmd = Command::new("build-bootstrap-config-image.sh");
    cmd.arg(img_path.clone())
        .arg("--ic_registry_local_store")
        .arg(&local_store_path)
        .arg("--ic_crypto")
        .arg(node.crypto_path())
        .arg("--accounts_ssh_authorized_keys")
        .arg(ctx.authorized_ssh_accounts_dir.path())
        .arg("--journalbeat_tags")
        .arg(format!("system_test {}", group_name));

    if !ctx.journalbeat_hosts.is_empty() {
        cmd.arg("--journalbeat_hosts")
            .arg(ctx.journalbeat_hosts.join(" "));
    }

    if !ctx.log_debug_overrides.is_empty() {
        let log_debug_overrides_val = format!(
            "[{}]",
            ctx.log_debug_overrides
                .iter()
                .map(|component_unquoted| format!("\"{}\"", component_unquoted))
                .collect::<Vec<_>>()
                .join(",")
        );
        cmd.arg("--log_debug_overrides")
            .arg(log_debug_overrides_val);
    }

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

fn node_to_config(node_index: NodeIndex, res_group: &ResourceGroup) -> NodeConfiguration {
    let vm = res_group
        .get_vm(node_index)
        .expect("Could not find allocated vm for given node index.");
    let ipv6_addr = vm.ip_addr;
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
        secret_key_store: None,
    }
}
