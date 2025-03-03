use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::{
    boundary_node::BoundaryNode,
    ic::{InternetComputer, Node, Subnet},
    node_software_version::NodeSoftwareVersion,
    prometheus_vm::{HasPrometheus, PrometheusVm},
    test_env::TestEnv,
    test_env_api::{HasTopologySnapshot, NnsCustomizations},
};
use serde::Deserialize;
use slog::info;
use url::Url;

pub mod defs;
pub mod steps;

const IC_VERSION_FILE: &str = "ENV_DEPS__IC_VERSION_FILE";
const GUESTOS_DISK_IMG_URL: &str = "ENV_DEPS__GUESTOS_DISK_IMG_URL";
const GUESTOS_UPDATE_IMG_URL: &str = "ENV_DEPS__GUESTOS_UPDATE_IMG_URL";

pub const IC_CONFIG: &str = "IC_CONFIG";

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
        update_env_variables(
            &env,
            vec![
                (
                    v.to_string(),
                    IC_VERSION_FILE,
                ),
                (
                    format!("http://download.proxy-global.dfinity.network:8080/ic/{}/guest-os/disk-img/disk-img.tar.zst", v),
                    GUESTOS_DISK_IMG_URL,
                ),
                (
                    format!("http://download.proxy-global.dfinity.network:8080/ic/{}/guest-os/update-img/update-img.tar.zst", v),
                    GUESTOS_UPDATE_IMG_URL,
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

fn update_env_variables(env: &TestEnv, pairs: Vec<(String, &str)>) {
    for (value, env_variable) in pairs {
        std::env::set_var(env_variable, &value);
        info!(
            env.logger(),
            "Overriden env variable `{}` to value: {}", env_variable, value
        )
    }
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
