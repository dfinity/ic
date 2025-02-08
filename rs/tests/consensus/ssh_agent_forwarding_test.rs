use anyhow::Result;
use ic_consensus_system_test_utils::rw_message::install_nns_and_check_progress;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::{
    group::SystemTestGroup,
    ic::{InternetComputer, Subnet},
    test_env::TestEnv,
    test_env_api::{HasTopologySnapshot, IcNodeContainer, SshSession},
};
use ic_system_test_driver::systest;
use slog::info;

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(2))
        .setup_and_start(&env)
        .expect("Should be able to set up IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
}

fn test(env: TestEnv) {
    let logger = env.logger();
    let mut nns_nodes = env.topology_snapshot().root_subnet().nodes();
    let (node1, node2) = (nns_nodes.next().unwrap(), nns_nodes.next().unwrap());

    info!(logger, "Running local test");
    let result = node1.block_on_bash_script("echo test").unwrap();
    info!(logger, "Result: {result}");

    info!(logger, "Running remote test");
    let result = node1
        .block_on_bash_script(&format!(
            "ssh -vvv -A -o StrictHostKeyChecking=no admin@{} echo test2",
            node2.get_ip_addr()
        ))
        .unwrap();
    info!(logger, "Results: {result}");
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()
}
