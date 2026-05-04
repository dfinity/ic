/* tag::catalog[]

Title:: Unassigned nodes configuration updates

Goal:: Ensure we can upgrade the unassigned nodes.

Description::
We deploy an IC with a set of unassigned nodes. Then we make a proposal to set the
replica version for unassigned nodes.
Then we make sure that unassigned nodes eventually upgrade to that version by
using SSH access.
Then repeat by downgrading the unassigned nodes to the initial version.

Runbook::
. Deploy an IC with unassigned nodes
. Deploy a config for the unassigned nodes with a replica version.
. Ssh into one of the unassigned nodes and read the version file.
. Repeat the previous two steps by downgrading to the initial version.

Success::
. At least one unassigned node runs the expected version.

end::catalog[] */

use anyhow::Result;
use anyhow::bail;
use ic_consensus_system_test_upgrade_common::bless_target_version;
use ic_consensus_system_test_utils::{
    rw_message::install_nns_and_check_progress,
    upgrade::{deploy_guestos_to_all_unassigned_nodes, fetch_unassigned_node_version},
};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_system_test_driver::{
    driver::{ic::InternetComputer, test_env::TestEnv, test_env_api::*},
    util::block_on,
};
use ic_types::ReplicaVersion;
use slog::Logger;
use slog::info;

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .with_unassigned_nodes(1)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
}

fn upgrade_unassigned_nodes(
    log: &Logger,
    nns_node: &IcNodeSnapshot,
    unassigned_node: &IcNodeSnapshot,
    target_version: &ReplicaVersion,
) {
    block_on(deploy_guestos_to_all_unassigned_nodes(
        nns_node,
        target_version,
    ));

    ic_system_test_driver::retry_with_msg!(
        format!(
            "check if unassigned node {} is at version {}",
            unassigned_node.node_id, &target_version
        ),
        log.clone(),
        secs(600),
        secs(10),
        || match fetch_unassigned_node_version(unassigned_node) {
            Ok(ver) if (ver == *target_version) => Ok(()),
            Ok(ver) => bail!("Unassigned node replica version: {}", ver),
            Err(_) => bail!("Waiting for the host to boot..."),
        }
    )
    .expect("Unassigned node was not updated!");
}

fn upgrade_downgrade_unassigned_nodes(env: TestEnv) {
    let log = env.logger();
    let nns_node = env.get_first_healthy_system_node_snapshot();
    let unassigned_node = env.topology_snapshot().unassigned_nodes().next().unwrap();

    let target_version = bless_target_version(&env, &nns_node);
    info!(log, "Upgrading unassigned nodes to {} ...", target_version);
    upgrade_unassigned_nodes(&log, &nns_node, &unassigned_node, &target_version);
    let initial_version = get_guestos_img_version();
    info!(
        log,
        "Downgrading unassigned nodes to {} ...", initial_version
    );
    upgrade_unassigned_nodes(&log, &nns_node, &unassigned_node, &initial_version);
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(upgrade_downgrade_unassigned_nodes))
        .execute_from_args()?;
    Ok(())
}
