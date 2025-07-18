use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::{
    ic::{InternetComputer, Node, Subnet},
    node_software_version::NodeSoftwareVersion,
    prometheus_vm::{HasPrometheus, PrometheusVm},
    test_env::TestEnv,
    test_env_api::{HasTopologySnapshot, NnsCustomizations},
    vector_vm::VectorVm,
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
    let mut vector_vm = VectorVm::new();
    vector_vm.start(&env).expect("Failed to start Vector VM");

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
    if let Some(u) = config.api_boundary_nodes {
        match u {
            ConfigurableApiBoundaryNodes::Simple(un) => ic = ic.clone().with_api_boundary_nodes(un),
            ConfigurableApiBoundaryNodes::Complex(uns) => uns
                .into_iter()
                .for_each(|un| ic = ic.clone().with_api_boundary_node(un)),
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

    env.sync_with_prometheus();
    vector_vm
        .sync_targets(&env)
        .expect("Failed to sync Vector targets");
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
    pub api_boundary_nodes: Option<ConfigurableApiBoundaryNodes>,
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
pub enum ConfigurableApiBoundaryNodes {
    Simple(usize),
    Complex(Vec<Node>),
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum ConfigurableUnassignedNodes {
    Simple(usize),
    Complex(Vec<Node>),
}
