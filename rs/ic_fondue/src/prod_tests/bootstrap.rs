use std::{
    collections::BTreeMap,
    fs::File,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Command,
};

use crate::internet_computer::InternetComputer;
use crate::node_software_version::NodeSoftwareVersion;
use crate::port_allocator::AddrType;
use crate::prod_tests::farm::FarmResult;
use ic_base_types::NodeId;

use ic_prep_lib::{
    internet_computer::{IcConfig, InitializedIc, TopologyConfig},
    node::{InitializedNode, NodeConfiguration, NodeIndex},
    subnet_configuration::SubnetConfig,
};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_types::malicious_behaviour::MaliciousBehaviour;
use slog::{info, Logger};
use std::io::Write;
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
    return format!("{}.zst", CONF_IMG_FNAME);
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
    // only as a placeholder: Updating individual binaries (replica/nodemanager)
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
            nodemanager_url: Url::parse("file:///opt/replica").unwrap(),
            nodemanager_hash: dummy_hash,
        });
    info!(ctx.logger, "initial_replica: {:?}", initial_replica);

    // TopologyConfig is a structure provided by ic-prep. We translate from the
    // builder (InternetComputer) to TopologyConfig. While doing so, we allocate tcp
    // ports for the http handler, p2p and xnet. The corresponding sockets are
    // closed when the port-allocator is dropped—which happens before we start the
    // nodes.
    let mut ic_topology = TopologyConfig::default();
    for (subnet_idx, subnet) in ic.subnets.iter().enumerate() {
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

    // ic-prep allows a declaring any of the subnets to be the NNS subnet. In our
    // case, however, it's always the first subnet.
    let nns_subnet_idx = Some(0);

    let whitelist = ProvisionalWhitelist::All;
    let ic_config = IcConfig::new(
        working_dir.as_path(),
        ic_topology,
        Some(initial_replica.replica_version),
        Some(initial_replica.replica_url),
        Some(initial_replica.replica_hash),
        // To maintain backwards compatibility, pass true here.
        // False is used only when nodes need to be deployed without
        // them joining any subnet initially

        /* generate_subnet_records= */
        true,
        // We assume by default that the subnet with index 0 is the NNS subnet.
        /* nns_subnet_index= */
        nns_subnet_idx,
        Some(initial_replica.nodemanager_url),
        Some(initial_replica.nodemanager_hash),
        None, // release_package_url
        None, // release_package_sha256_hex
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

    let delta_idx = init_ic.initialized_topology.len();
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

pub fn upload_config_disk_images(
    ctx: &DriverContext,
    initialized_ic: &InitializedIc,
    group_name: &str,
) -> FarmResult<Vec<String>> {
    let upload_for_node = |node: &InitializedNode| -> FarmResult<String> {
        let compressed_img_path = mk_compressed_img_path();
        let target_file = PathBuf::from(&node.node_path).join(compressed_img_path.clone());
        let image_id = ctx
            .farm
            .upload_image(group_name, target_file, compressed_img_path)?;
        info!(ctx.logger, "Uploaded image: {}", image_id);
        Ok(image_id)
    };

    let mut res = vec![];
    // TODO(VER-1261): upload all images in one batch.
    for subnet in initialized_ic.initialized_topology.values() {
        for node in subnet.initialized_nodes.values() {
            res.push(upload_for_node(node)?);
        }
    }
    for node in initialized_ic.unassigned_nodes.values() {
        res.push(upload_for_node(node)?);
    }
    Ok(res)
}

/// side-effectful function that creates the config disk images in the node
/// directories.
pub fn create_config_disk_images(
    ctx: &DriverContext,
    logger: &Logger,
    initialized_ic: &InitializedIc,
) {
    let ic_registry_local_store_path = initialized_ic.target_dir.join("ic_registry_local_store");
    let cfg_for_node = |node: &InitializedNode| {
        let img_path = PathBuf::from(&node.node_path).join(CONF_IMG_FNAME);

        let mut cmd = Command::new("build-bootstrap-config-image.sh");
        cmd.arg(img_path.clone())
            .arg("--ic_registry_local_store")
            .arg(&ic_registry_local_store_path)
            .arg("--ic_crypto")
            .arg(node.crypto_path())
            .arg("--accounts_ssh_authorized_keys")
            .arg(ctx.authorized_ssh_accounts_dir.path());

        if !ctx.journalbeat_hosts.is_empty() {
            cmd.arg("--journalbeat_hosts")
                .arg(ctx.journalbeat_hosts.join(" "));
        }

        let output = cmd
            .output()
            .expect("could not spawn image creation process");

        info!(logger, "status: {}", output.status);
        std::io::stdout().write_all(&output.stdout).unwrap();
        std::io::stderr().write_all(&output.stderr).unwrap();

        let img_file = File::open(img_path).unwrap();
        let compressed_img_path = PathBuf::from(&node.node_path).join(mk_compressed_img_path());
        let compressed_img_file = File::create(compressed_img_path.clone()).unwrap();
        zstd::stream::copy_encode(img_file, compressed_img_file, 0).unwrap();

        let mut cmd = Command::new("sha256sum");
        cmd.arg(compressed_img_path);

        let output = cmd
            .output()
            .expect("could not spawn image creation process");

        info!(logger, "status: {}", output.status);
        assert!(
            output.status.success(),
            "Could not create config disk image for IC node."
        );
        std::io::stdout().write_all(&output.stdout).unwrap();
        std::io::stderr().write_all(&output.stderr).unwrap();
    };

    for subnet in initialized_ic.initialized_topology.values() {
        for node in subnet.initialized_nodes.values() {
            cfg_for_node(node);
        }
    }
    for node in initialized_ic.unassigned_nodes.values() {
        cfg_for_node(node);
    }
}

pub fn attach_config_disk_images(
    ctx: &DriverContext,
    res_group: &ResourceGroup,
    cfg_disk_image_ids: Vec<String>,
) -> FarmResult<()> {
    assert_eq!(res_group.vms.len(), cfg_disk_image_ids.len());
    res_group
        .vms
        .iter()
        .zip(cfg_disk_image_ids.iter())
        .try_for_each(|(vm, image_id)| {
            ctx.farm.attach_disk_image(
                &res_group.group_name,
                &vm.name,
                "usb-storage",
                image_id.clone(),
            )
        })?;

    res_group
        .vms
        .iter()
        .try_for_each(|alloc_vm| ctx.farm.start_vm(&res_group.group_name, &alloc_vm.name))?;
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
    }
}
