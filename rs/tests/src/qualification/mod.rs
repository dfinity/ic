use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::{
    boundary_node::BoundaryNode,
    ic::{InternetComputer, Node, Subnet},
    node_software_version::NodeSoftwareVersion,
    prometheus_vm::{HasPrometheus, PrometheusVm},
    test_env::TestEnv,
    test_env_api::{get_dependency_path, HasTopologySnapshot, NnsCustomizations},
};
use serde::Deserialize;
use slog::info;
use url::Url;

pub mod defs;
pub mod steps;

const IC_VERSION_FILE: &str = "ENV_DEPS__IC_VERSION_FILE";
const CUSTOM_REVISION: &str = "custom_revision";

const CUSTOM_DISK_IMG_TAR_URL: &str = "custom_disk_img_tar_url";
const DEV_DISK_IMG_TAR_ZST_CAS_URL: &str = "ENV_DEPS__DEV_DISK_IMG_TAR_ZST_CAS_URL";

const CUSTOM_DISK_IMG_SHA: &str = "custom_disk_img_sha";
const DEV_DISK_IMG_TAR_ZST_SHA256: &str = "ENV_DEPS__DEV_DISK_IMG_TAR_ZST_SHA256";

pub const IC_CONFIG: &str = "IC_CONFIG";

const TAR_EXTENSION: &str = ".tar.zst";

pub fn setup(env: TestEnv, config: IcConfig) {
    let mut ic = InternetComputer::new();
    if let Some(v) = config.initial_version {
        ic = ic.with_initial_replica(NodeSoftwareVersion {
            replica_version: v.clone().try_into().unwrap(),
            replica_url: Url::parse("https://unimportant.com").unwrap(),
            replica_hash: "".to_string(),
            orchestrator_url: Url::parse("https://unimportant.com").unwrap(),
            orchestrator_hash: "".to_string(),
        });
        write_file_and_update_env_variable(
            &env,
            vec![
                (
                    CUSTOM_REVISION,
                    v.to_string(),
                    IC_VERSION_FILE,
                ),
                (
                    CUSTOM_DISK_IMG_TAR_URL,
                    format!("http://download.proxy-global.dfinity.network:8080/ic/{}/guest-os/disk-img/disk-img.tar.zst", v),
                    DEV_DISK_IMG_TAR_ZST_CAS_URL,
                ),
                (
                    CUSTOM_DISK_IMG_SHA,
                    fetch_shasum_for_disk_img(v.to_string()),
                    DEV_DISK_IMG_TAR_ZST_SHA256,
                ),
            ],
        );
    }
    if let Some(subnets) = config.subnets {
        subnets.iter().for_each(|s| {
            let su = match s {
                ConfigurableSubnet::Simple(s) => Subnet::new(s.subnet_type).add_nodes(s.num_nodes),
                ConfigurableSubnet::Complex(s) => *s.to_owned(),
            };
            ic = ic.clone().add_subnet(su)
        })
    }
    if let Some(u) = config.unassigned_nodes {
        match u {
            ConfigurableUnassignedNodes::Simple(un) => ic = ic.clone().with_unassigned_nodes(un),
            ConfigurableUnassignedNodes::Complex(uns) => uns
                .into_iter()
                .for_each(|un| ic = ic.clone().with_unassigned_node(un)),
        }
    }

    PrometheusVm::default()
        .start(&env)
        .expect("Failed to start prometheus VM");
    ic.setup_and_start(&env)
        .expect("Failed to setup IC under test");

    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        NnsCustomizations::default(),
    );

    if let Some(boundary_nodes) = config.boundary_nodes {
        boundary_nodes.iter().for_each(|bn| {
            match bn {
                ConfigurableBoundaryNode::Simple(bn) => BoundaryNode::new(bn.name.clone()),
                ConfigurableBoundaryNode::Complex(b) => *b.to_owned(),
            }
            .allocate_vm(&env)
            .expect("Allocation of BoundaryNode failed.")
            .for_ic(&env, "")
            .use_real_certs_and_dns()
            .start(&env)
            .expect("Failed to setup BoundaryNode VM")
        })
    }

    env.sync_with_prometheus();
}

fn write_file_and_update_env_variable(env: &TestEnv, pairs: Vec<(&str, String, &str)>) {
    for (file_name, value_in_file, env_variable) in pairs {
        let path = get_dependency_path(file_name);
        std::fs::write(&path, value_in_file)
            .unwrap_or_else(|_| panic!("Failed to write to path: {}", path.display()));
        std::env::set_var(env_variable, file_name);
        info!(
            env.logger(),
            "Overriden env variable `{}` to value: {}",
            env_variable,
            path.display()
        )
    }
}

fn fetch_shasum_for_disk_img(version: String) -> String {
    let url = format!(
        "http://download.proxy-global.dfinity.network:8080/ic/{}/guest-os/disk-img/SHA256SUMS",
        version
    );
    let response = reqwest::blocking::get(&url)
        .unwrap_or_else(|e| panic!("Failed to fetch url `{}` with err: {:?}", &url, e));
    if !response.status().is_success() {
        panic!(
            "Received non-success response status: {:?}",
            response.status()
        )
    }

    String::from_utf8(
        response
            .bytes()
            .expect("Failed to deserialize bytes")
            .to_vec(),
    )
    .expect("Failed to convert to UTF8")
    .lines()
    .find(|l| l.ends_with(TAR_EXTENSION))
    .unwrap_or_else(|| {
        panic!(
            "Failed to find a hash ending with `{}` from: {}",
            &url, TAR_EXTENSION
        )
    })
    .split_whitespace()
    .next()
    .expect("The format of hash should contain whitespace")
    .to_string()
}

#[derive(Deserialize, Debug)]
pub struct IcConfig {
    pub subnets: Option<Vec<ConfigurableSubnet>>,
    pub unassigned_nodes: Option<ConfigurableUnassignedNodes>,
    pub boundary_nodes: Option<Vec<ConfigurableBoundaryNode>>,
    pub initial_version: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum ConfigurableSubnet {
    Simple(SubnetSimple),
    Complex(Box<Subnet>),
}

#[derive(Deserialize, Debug)]
pub struct SubnetSimple {
    pub subnet_type: SubnetType,
    pub num_nodes: usize,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum ConfigurableBoundaryNode {
    Simple(BoundaryNodeSimple),
    Complex(Box<BoundaryNode>),
}

#[derive(Deserialize, Debug)]
pub struct BoundaryNodeSimple {
    pub name: String,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum ConfigurableUnassignedNodes {
    Simple(usize),
    Complex(Vec<Node>),
}
