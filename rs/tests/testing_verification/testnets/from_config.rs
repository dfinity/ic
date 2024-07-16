use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::{
    boundary_node::BoundaryNode,
    group::SystemTestGroup,
    ic::{InternetComputer, Subnet},
    prometheus_vm::{HasPrometheus, PrometheusVm},
    test_env::TestEnv,
    test_env_api::{HasTopologySnapshot, NnsCanisterWasmStrategy, NnsCustomizations},
};
use ic_tests::orchestrator::utils::rw_message::install_nns_with_customizations_and_check_progress;
use serde::Deserialize;

fn main() -> anyhow::Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .execute_from_args()?;
    Ok(())
}

const IC_CONFIG: &str = "IC_CONFIG";

pub fn setup(env: TestEnv) {
    let mut config = std::env::var(IC_CONFIG)
        .unwrap_or_else(|_| panic!("Failed to fetch `{}` from env", IC_CONFIG));

    if config.starts_with('\'') {
        config = config[1..config.len() - 2].to_string();
    }

    let parsed: IcConfig =
        serde_json::from_str(&config).expect("Failed to parse json from envrionment");

    let mut ic = InternetComputer::new();
    if let Some(subnets) = parsed.subnets {
        for s in subnets {
            ic = ic.add_subnet(Subnet::new(s.subnet_type).add_nodes(s.num_nodes));
        }
    }

    ic = ic.with_unassigned_nodes(parsed.num_unassigned_nodes.unwrap_or_default());

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
        for bn in boundary_nodes {
            BoundaryNode::new(bn.name)
                .allocate_vm(&env)
                .expect("Allocation of BoundaryNode failed.")
                .for_ic(&env, "")
                .use_real_certs_and_dns()
                .start(&env)
                .expect("Failed to setup BoundaryNode VM");
        }
    }

    env.sync_with_prometheus();
}

#[derive(Deserialize, Debug)]
struct IcConfig {
    subnets: Option<Vec<ConfigurableSubnet>>,
    num_unassigned_nodes: Option<usize>,
    boundary_nodes: Option<Vec<ConfigurableBoundaryNode>>,
}

#[derive(Deserialize, Debug)]
struct ConfigurableSubnet {
    subnet_type: SubnetType,
    num_nodes: usize,
}

#[derive(Deserialize, Debug)]
struct ConfigurableBoundaryNode {
    name: String,
}
