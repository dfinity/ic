use ic_consensus_system_test_utils::rw_message::install_nns_and_check_progress;
use ic_consensus_system_test_utils::upgrade::{
    assert_assigned_replica_hash, assert_assigned_replica_version, bless_replica_version,
    deploy_guestos_to_all_subnet_nodes, deploy_slow_to_subnet_node,
};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env_api::{
    GetFirstHealthyNodeSnapshot, HasTopologySnapshot,
};
use ic_system_test_driver::{
    driver::{test_env::TestEnv, test_env_api::*},
    systest,
    util::block_on,
};
use ic_types::ReplicaVersion;

use anyhow::Result;
use slog::info;

use std::time::Duration;

const ALLOWED_FAILURES: usize = 1;
const SUBNET_SIZE: usize = 3 * ALLOWED_FAILURES + 1; // 4 nodes
const UP_DOWNGRADE_OVERALL_TIMEOUT: Duration = Duration::from_secs(25 * 60);
const UP_DOWNGRADE_PER_TEST_TIMEOUT: Duration = Duration::from_secs(20 * 60);

fn setup(env: TestEnv) {
    let subnet_under_test = Subnet::new(SubnetType::Application).add_nodes(SUBNET_SIZE);

    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(subnet_under_test)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
}

fn demo_quick_upgrade(env: TestEnv) {
    let logger = env.logger();

    let nns_node = env.get_first_healthy_system_node_snapshot();

    let target_version = bless_target_version(&env, &nns_node, true);
    let target_replica_hash = get_replica_update_sha256();

    let subnet = env
        .topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("there is no application subnet");
    let subnet_id = subnet.subnet_id;
    let subnet_nodes = subnet.nodes().collect::<Vec<_>>();

    info!(logger, "Upgrade to hash {}", target_replica_hash);
    info!(
        logger,
        "Upgrading subnet {} to {}", subnet_id, target_replica_hash
    );
    block_on(deploy_guestos_to_all_subnet_nodes(
        &nns_node,
        &target_version,
        subnet_id,
    ));

    for node in &subnet_nodes {
        assert_assigned_replica_hash(&node, &target_replica_hash, logger.clone());
    }
    info!(
        logger,
        "Successfully upgraded subnet {} to {}", subnet_id, target_replica_hash
    );

    info!(
        logger,
        "Slowly rolling subnet {} to {}", subnet_id, target_version
    );
    for node in &subnet_nodes {
        block_on(deploy_slow_to_subnet_node(
            &nns_node,
            &target_version,
            node.node_id,
        ));
    }
    for node in &subnet_nodes {
        assert_assigned_replica_version(&node, &target_version, logger.clone());
    }
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_overall_timeout(UP_DOWNGRADE_OVERALL_TIMEOUT)
        .with_timeout_per_test(UP_DOWNGRADE_PER_TEST_TIMEOUT)
        .without_assert_no_replica_restarts()
        .remove_metrics_to_check("consensus_invalidated_artifacts")
        .with_setup(setup)
        .add_test(systest!(demo_quick_upgrade))
        .execute_from_args()?;
    Ok(())
}

pub fn bless_target_version(
    env: &TestEnv,
    nns_node: &IcNodeSnapshot,
    fast_upgrade: bool,
) -> ReplicaVersion {
    let logger = env.logger();

    let target_version = get_guestos_update_img_version();

    // Bless target version
    let upgrade_url = get_guestos_update_img_url();
    let sha256 = get_guestos_update_img_sha256();
    let guest_launch_measurements = get_guestos_launch_measurements();
    let replica_url = get_replica_update_url();
    let replica_sha256 = get_replica_update_sha256();
    block_on(bless_replica_version(
        nns_node,
        &target_version,
        &logger,
        sha256,
        Some(guest_launch_measurements),
        vec![upgrade_url.to_string()],
        vec![replica_url.to_string()],
        Some(replica_sha256.to_string()),
        fast_upgrade,
    ));
    info!(&logger, "Blessed target version");

    target_version
}
