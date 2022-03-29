//! This module tests the system tests API itself.

use ic_fondue::prod_tests::{ic::InternetComputer, test_env::TestEnv, test_setup::DefaultIC};
use ic_registry_subnet_type::SubnetType;
use slog::Logger;

/// Create two ICs, a no-name IC and a named one which differ in their topology.
pub fn two_ics(test_env: TestEnv) {
    let mut ic = InternetComputer::new().add_fast_single_node_subnet(SubnetType::System);
    ic.setup_and_start(&test_env)
        .expect("Could not start no-name IC");

    let mut ic2 = InternetComputer::new()
        .with_name("two_subnets")
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::Application);
    ic2.setup_and_start(&test_env)
        .expect("Could not start second IC");
}

pub fn ics_have_correct_subnet_count(test_env: TestEnv, _logger: Logger) {
    let topo_snapshot = test_env.topology_snapshot();
    assert_eq!(topo_snapshot.subnets().count(), 1);

    let topo_snapshot2 = test_env.topology_snapshot_by_name("two_subnets");
    assert_eq!(topo_snapshot2.subnets().count(), 2);
}
