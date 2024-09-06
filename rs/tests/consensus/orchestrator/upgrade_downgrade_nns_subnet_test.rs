use std::time::Duration;

use anyhow::Result;

use ic_consensus_system_test_upgrade_common::{
    bless_branch_version, get_chain_key_canister_and_public_key, upgrade,
};
use ic_consensus_system_test_utils::rw_message::{
    can_read_msg_with_retries, install_nns_and_check_progress,
};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::HasPublicApiUrl;
use ic_system_test_driver::driver::test_env_api::{
    read_dependency_to_string, GetFirstHealthyNodeSnapshot, HasTopologySnapshot,
};
use ic_system_test_driver::systest;
use ic_types::Height;

const DKG_INTERVAL: u64 = 9;
const ALLOWED_FAILURES: usize = 1;
const SUBNET_SIZE: usize = 3 * ALLOWED_FAILURES + 1; // 4 nodes
const UP_DOWNGRADE_OVERALL_TIMEOUT: Duration = Duration::from_secs(25 * 60);
const UP_DOWNGRADE_PER_TEST_TIMEOUT: Duration = Duration::from_secs(20 * 60);

fn setup(env: TestEnv) {
    let subnet_under_test = Subnet::new(SubnetType::System)
        .add_nodes(SUBNET_SIZE)
        .with_dkg_interval_length(Height::from(DKG_INTERVAL));

    InternetComputer::new()
        .with_mainnet_config()
        .add_subnet(subnet_under_test)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
}

// Tests an upgrade of the NNS subnet to the branch version and a downgrade back to the mainnet version
fn upgrade_downgrade_nns_subnet(env: TestEnv) {
    let nns_node = env.get_first_healthy_system_node_snapshot();
    let branch_version = bless_branch_version(&env, &nns_node);
    let (faulty_node, can_id, msg) =
        upgrade(&env, &nns_node, &branch_version, SubnetType::System, None);
    let mainnet_version = read_dependency_to_string("testnet/mainnet_nns_revision.txt").unwrap();
    upgrade(&env, &nns_node, &mainnet_version, SubnetType::System, None);
    // Make sure we can still read the message stored before the first upgrade
    assert!(can_read_msg_with_retries(
        &env.logger(),
        &faulty_node.get_public_url(),
        can_id,
        &msg,
        /*retries=*/ 3
    ));
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_overall_timeout(UP_DOWNGRADE_OVERALL_TIMEOUT)
        .with_timeout_per_test(UP_DOWNGRADE_PER_TEST_TIMEOUT)
        .with_setup(setup)
        .add_test(systest!(upgrade_downgrade_nns_subnet))
        .execute_from_args()?;

    Ok(())
}
