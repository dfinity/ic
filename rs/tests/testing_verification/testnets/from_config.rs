use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::{
    boundary_node::BoundaryNode,
    group::SystemTestGroup,
    ic::{InternetComputer, Node, Subnet},
    node_software_version::NodeSoftwareVersion,
    prometheus_vm::{HasPrometheus, PrometheusVm},
    test_env::TestEnv,
    test_env_api::{
        HasDependencies, HasTopologySnapshot, NnsCanisterWasmStrategy, NnsCustomizations,
    },
};
use ic_tests::orchestrator::utils::rw_message::install_nns_with_customizations_and_check_progress;
use serde::Deserialize;
use slog::info;

fn main() -> anyhow::Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .execute_from_args()?;
    Ok(())
}

const IC_VERSION_FILE: &str = "ENV_DEPS__IC_VERSION_FILE";
const CUSTOM_REVISION: &str = "custom_revision";
const IC_CONFIG: &str = "IC_CONFIG";

pub fn setup(env: TestEnv) {
    let mut config = std::env::var(IC_CONFIG)
        .unwrap_or_else(|_| panic!("Failed to fetch `{}` from env", IC_CONFIG));

    if config.starts_with('\'') {
        config = config[1..config.len() - 1].to_string();
    }

    let parsed: IcConfig = serde_json::from_str(&config)
        .unwrap_or_else(|_| panic!("Failed to parse json from envrionment: \n{}", config));

    let mut ic = InternetComputer::new();
    if let Some(v) = parsed.initial_version {
        ic = ic.with_initial_replica(v.clone());
        let path = env.get_dependency_path(CUSTOM_REVISION);
        std::fs::write(&path, v.replica_version.to_string())
            .unwrap_or_else(|_| panic!("Failed to write to path: {}", path.display()));
        std::env::set_var(IC_VERSION_FILE, CUSTOM_REVISION);
        info!(
            env.logger(),
            "Overriden env variable `{}` to value: {}",
            IC_VERSION_FILE,
            path.display()
        )
    }
    if let Some(subnets) = parsed.subnets {
        subnets.iter().for_each(|s| {
            let su = match s {
                ConfigurableSubnet::Simple(s) => Subnet::new(s.subnet_type).add_nodes(s.num_nodes),
                ConfigurableSubnet::Complex(s) => *s.to_owned(),
            };
            ic = ic.clone().add_subnet(su)
        })
    }
    if let Some(u) = parsed.unassigned_nodes {
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
        NnsCanisterWasmStrategy::TakeBuiltFromSources,
        NnsCustomizations::default(),
    );

    if let Some(boundary_nodes) = parsed.boundary_nodes {
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

#[derive(Deserialize, Debug)]
struct IcConfig {
    subnets: Option<Vec<ConfigurableSubnet>>,
    unassigned_nodes: Option<ConfigurableUnassignedNodes>,
    boundary_nodes: Option<Vec<ConfigurableBoundaryNode>>,
    initial_version: Option<NodeSoftwareVersion>,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum ConfigurableSubnet {
    Simple(SubnetSimple),
    Complex(Box<Subnet>),
}

#[derive(Deserialize, Debug)]
struct SubnetSimple {
    subnet_type: SubnetType,
    num_nodes: usize,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum ConfigurableBoundaryNode {
    Simple(BoundaryNodeSimple),
    Complex(Box<BoundaryNode>),
}

#[derive(Deserialize, Debug)]
struct BoundaryNodeSimple {
    name: String,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum ConfigurableUnassignedNodes {
    Simple(usize),
    Complex(Vec<Node>),
}
