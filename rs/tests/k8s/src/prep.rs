use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::process::Command;
use std::{net::IpAddr, path::Path};

use tempfile::tempdir;
use tracing::*;

use ic_prep_lib::{
    internet_computer::{IcConfig, TopologyConfig},
    node::NodeConfiguration,
    subnet_configuration::{SubnetConfig, SubnetRunningState},
};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_subnet_type::SubnetType;
use ic_types::ReplicaVersion;

use crate::tnet::{TNode, TNET_IPV6};

const BOOTSTRAP_SCRIPT_PATH: &str = "../../../ic-os/scripts/build-bootstrap-config-image.sh";
const SSH_AUTHORIZED_KEYS_PATH: &str = "../../../testnet/config/ssh_authorized_keys/";
const RCLONE_CONFIG_PATH: &str = "../../../.rclone-anon.conf";

pub(crate) fn generate_config(
    version: &str,
    use_zero_version: bool,
    nns_nodes: &[TNode],
    app_nodes: &[TNode],
) -> anyhow::Result<()> {
    info!("Building node config");

    let version = ReplicaVersion::try_from(version)?;

    let subnet_version = if use_zero_version {
        ReplicaVersion::try_from("0000000000000000000000000000000000000000")?
    } else {
        version.clone()
    };

    let tempdir = tempdir()?;
    let out_dir = Path::new("out");
    std::fs::create_dir(out_dir)?;

    let nns_nodes: BTreeMap<u64, _> = nns_nodes
        .iter()
        .map(|v| IpAddr::V6(v.ipv6_addr.expect("IPv6 has not been assigned.")))
        .map(|v| NodeConfiguration {
            xnet_api: SocketAddr::new(v, 2497),
            public_api: SocketAddr::new(v, 8080),
            p2p_addr: SocketAddr::new(v, 4100),
            node_operator_principal_id: None,
            secret_key_store: None,
            chip_id: Vec::new().into(),
        })
        .enumerate()
        .map(|(k, v)| {
            (
                k.try_into()
                    .expect("More than u64::MAX NNS nodes requested!"),
                v,
            )
        })
        .collect();

    let app_nodes: BTreeMap<u64, _> = app_nodes
        .iter()
        .map(|v| IpAddr::V6(v.ipv6_addr.expect("IPv6 has not been assigned.")))
        .map(|v| NodeConfiguration {
            xnet_api: SocketAddr::new(v, 2497),
            public_api: SocketAddr::new(v, 8080),
            p2p_addr: SocketAddr::new(v, 4100),
            node_operator_principal_id: None,
            secret_key_store: None,
            chip_id: Vec::new().into(),
        })
        .enumerate()
        .map(|(k, v)| (k + nns_nodes.len(), v))
        .map(|(k, v)| {
            (
                k.try_into()
                    .expect("More than u64::MAX app nodes requested!"),
                v,
            )
        })
        .collect();

    let mut ic_topology = TopologyConfig::default();

    if !nns_nodes.is_empty() {
        // Use defaults for all unset fields
        let nns_subnet = SubnetConfig::new(
            0,
            nns_nodes,
            Some(subnet_version.clone()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            SubnetType::System,
            None,
            None,
            None,
            None,
            None,
            None,
            Vec::new(),
            Vec::new(),
            SubnetRunningState::Active,
        );

        ic_topology.insert_subnet(0, nns_subnet);
    }

    if !app_nodes.is_empty() {
        // Use defaults for all unset fields
        let app_subnet = SubnetConfig::new(
            1,
            app_nodes,
            Some(subnet_version.clone()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            SubnetType::Application,
            None,
            None,
            None,
            None,
            None,
            None,
            Vec::new(),
            Vec::new(),
            SubnetRunningState::Active,
        );

        ic_topology.insert_subnet(1, app_subnet);
    }

    let mut ic_config = IcConfig::new(
        &tempdir,                        // target_dir
        ic_topology,                     // topology_config
        Some(subnet_version.clone()),    // replica_version_id
        true,                            // generate_subnet_records
        Some(0),                         // nns_subnet_index
        None,                            // release_package_url
        None,                            // release_package_sha256_hex
        Some(ProvisionalWhitelist::All), // provisional_whitelist
        None,                            // initial_node_operator
        None,                            // initial_node_provider
        Vec::new(),                      // ssh_readonly_access_to_unassigned_nodes
        None,                            // initial_guest_launch_measurement_sha256_hex
    );

    let wider_prefix = format!("{}::/48", &TNET_IPV6[0..(TNET_IPV6.len() - 5)]);
    ic_config.set_whitelisted_prefixes(Some(wider_prefix));

    let initialized_ic = ic_config.initialize()?;

    let local_store = tempdir.path().join("ic_registry_local_store");
    for subnet in initialized_ic.initialized_topology.values() {
        for (node_index, node) in subnet.initialized_nodes.iter() {
            // Build config image
            let filename = format!("bootstrap-{node_index}.img");
            let config_path = out_dir.join(filename);
            Command::new(BOOTSTRAP_SCRIPT_PATH)
                .arg(&config_path)
                .arg("--ic_registry_local_store")
                .arg(&local_store)
                .arg("--ic_crypto")
                .arg(node.crypto_path())
                .arg("--hostname")
                .arg(&format!("vm-{node_index}"))
                // TODO: parameterize this
                .arg("--ipv6_address")
                .arg(node.node_config.public_api.ip().to_string())
                .arg("--ipv6_gateway")
                .arg("fe80::ecee:eeff:feee:eeee")
                .arg("--elasticsearch_hosts")
                .arg("elasticsearch.testnet.dfinity.network:443")
                .arg("--accounts_ssh_authorized_keys")
                .arg(SSH_AUTHORIZED_KEYS_PATH)
                .status()?;
        }
    }

    build_init_package(&local_store, &version, out_dir)?;

    Ok(())
}

fn build_init_package(
    local_store_path: &Path,
    version: &ReplicaVersion,
    destination: &Path,
) -> anyhow::Result<()> {
    let tempdir = tempdir()?;

    // Download init
    Command::new("rclone")
        .arg(format!("--config={}", RCLONE_CONFIG_PATH))
        .arg("copy")
        .arg(format!(
            "public-s3:dfinity-download-public/ic/{}/release/ic-nns-init.gz",
            version
        ))
        .arg(tempdir.path())
        .status()?;

    // Download canisters
    Command::new("rclone")
        .arg(format!("--config={}", RCLONE_CONFIG_PATH))
        .arg("--include")
        .arg("*")
        .arg("copyto")
        .arg(format!(
            "public-s3:dfinity-download-public/ic/{}/canisters",
            version
        ))
        .arg(tempdir.path().join("canisters"))
        .status()?;

    // Copy local store into place
    Command::new("cp")
        .arg("-r")
        .arg(local_store_path)
        .arg(tempdir.path())
        .status()?;

    // Pack up into destination
    Command::new("tar")
        .arg("-C")
        .arg(tempdir.path())
        .arg("-cf")
        .arg(destination.join("init.tar"))
        .arg(".")
        .status()?;

    Ok(())
}
