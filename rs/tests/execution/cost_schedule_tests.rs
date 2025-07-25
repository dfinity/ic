use anyhow::Result;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::{SystemTestGroup, SystemTestSubGroup},
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl},
    },
    systest,
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_parallel(SystemTestSubGroup::new().add_test(systest!(execute_without_cycles)))
        .execute_from_args()
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(Subnet::fast_single_node(SubnetType::Application))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

pub fn execute_without_cycles(env: TestEnv) {
    let _logger = env.logger();
    let nns_node = env.get_first_healthy_nns_node_snapshot();
    let _nns_agent = nns_node.build_default_agent();
    // TODO
}
