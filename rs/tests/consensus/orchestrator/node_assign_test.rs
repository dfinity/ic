/* tag::catalog[]
Title:: Assign free (unassigned) nodes to an existing application subnet.

Goals::
. Ensure that unassigned nodes can be added to an existing subnet.
. Ensure that the newly assigned nodes can be killed within the subnet.

Runbook::
. Setup:
    . Single-node Systems subnet with NNS canisters.
    . Single-node Application subnet (initially without canisters).
    . X unassigned nodes (X >= 3).
. Add all unassigned nodes to the Application subnet (via governance canister proposal). Total number of nodes is N=X+1.
. Install a new canister in the Application subnet.
. Assert that `update` messages can be sent to this canister (this proves that nodes have been added successfully).
. Kill floor(X/3) nodes in the Application subnet.
. Assert that `update` messages can still be sent to the canister (as the consensus rule holds: N>=3*f+1, f=floor(X/3)).
. Kill one more node in the Application subnet.
. Assert that `update` messages can no longer be sent (as the consensus rule breaks: N<3*f+1, f=floor(X/3)+1).
. Restart the last node again.
. Assert that `update` messages can be sent to the canister again.

Success:: nodes can be added/killed to/within the existing subnet.

end::catalog[] */

use anyhow::Result;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use canister_test;
use ic_base_types::NodeId;
use ic_consensus_system_test_utils::{
    node::{await_node_certified_height, get_node_certified_height},
    rw_message::install_nns_and_check_progress,
};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance_api::pb::v1::NnsFunction;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, HasTopologySnapshot, HasVm},
    },
    nns::{submit_external_proposal_with_test_id, vote_execute_proposal_assert_executed},
    util::{
        assert_create_agent, block_on, get_app_subnet_and_node, get_nns_node, runtime_from_url,
        MessageCanister,
    },
};
use ic_types::Height;
use registry_canister::mutations::do_add_nodes_to_subnet::AddNodesToSubnetPayload;
use slog::info;

const UPDATE_MSG_1: &str = "This beautiful prose should be persisted for future generations";
const UPDATE_MSG_2: &str = "And this beautiful prose should be persisted for future generations";
const UPDATE_MSG_3: &str = "However this prose will NOT be persisted for future generations";
const UPDATE_MSG_4: &str = "UPDATE_MSG_4";
const UNASSIGNED_NODES_COUNT: usize = 3; // must be >= 3, currently tested for X=3, f=1 and N=4
const DKG_INTERVAL_LENGTH: u64 = 14;

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL_LENGTH))
                .add_nodes(1),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL_LENGTH))
                .add_nodes(1),
        )
        .with_unassigned_nodes(UNASSIGNED_NODES_COUNT)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
}

fn test(env: TestEnv) {
    let topo_snapshot = env.topology_snapshot();
    let logger = env.logger();
    let nns_node = get_nns_node(&topo_snapshot);

    let unassigned_node_ids: Vec<NodeId> = topo_snapshot
        .unassigned_nodes()
        .map(|n| n.node_id)
        .collect();
    assert_eq!(unassigned_node_ids.len(), UNASSIGNED_NODES_COUNT);
    let unassigned_nodes = topo_snapshot.unassigned_nodes();

    // get application node
    info!(logger, "Getting application node");
    let (app_subnet, app_node) = get_app_subnet_and_node(&topo_snapshot);
    info!(
        logger,
        "Continuing with app node: {}",
        app_node.get_ip_addr()
    );

    // Create NNS runtime.
    info!(logger, "Creating NNS runtime");
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());

    // Send a proposal for the nodes to join a subnet via the governance canister.
    let governance_canister = canister_test::Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);
    let proposal_payload = AddNodesToSubnetPayload {
        subnet_id: app_subnet.subnet_id.get(),
        node_ids: unassigned_node_ids,
    };

    info!(
        logger,
        "Submitting AddNodeToSubnet proposal: {:#?}", proposal_payload
    );
    let proposal_id = block_on(submit_external_proposal_with_test_id(
        &governance_canister,
        NnsFunction::AddNodeToSubnet,
        proposal_payload,
    ));

    // Explicitly vote for the proposal to add nodes to subnet.
    info!(logger, "Voting on proposal");
    block_on(vote_execute_proposal_assert_executed(
        &governance_canister,
        proposal_id,
    ));

    // Set unassigned nodes to the Application subnet.
    let newly_assigned_nodes: Vec<_> = unassigned_nodes.collect();

    // Wait for registry update
    info!(logger, "Waiting for registry update");
    block_on(topo_snapshot.block_for_newer_registry_version())
        .expect("Could not block for newer registry version");

    // Assert that new nodes are reachable (via http call).
    info!(logger, "Assert that new nodes are reachable");
    for n in newly_assigned_nodes.iter() {
        n.await_status_is_healthy().unwrap();
    }

    // Wait for 3 DKG intervals to ensure that added nodes have actually joined consensus.
    let target_height =
        get_node_certified_height(&app_node, logger.clone()).get() + DKG_INTERVAL_LENGTH * 3;
    for n in newly_assigned_nodes.iter() {
        await_node_certified_height(n, Height::from(target_height), logger.clone());
    }

    // Install a canister in the Application subnet for testing consensus (sending
    // `update` messages).
    let last_assigned = newly_assigned_nodes.last().unwrap();
    info!(logger, "Creating a canister using selected app node");
    let agent = block_on(assert_create_agent(last_assigned.get_public_url().as_str()));
    let message_canister = block_on(MessageCanister::new(
        &agent,
        app_node.effective_canister_id(),
    ));

    // Assert that `update` call to the canister succeeds.
    info!(logger, "Assert that update call to the canister succeeds");
    block_on(message_canister.try_store_msg(UPDATE_MSG_1)).expect("Update canister call failed.");
    assert_eq!(
        block_on(message_canister.try_read_msg()),
        Ok(Some(UPDATE_MSG_1.to_string()))
    );

    // Kill floor(X/3) nodes.
    let kill_nodes_count = UNASSIGNED_NODES_COUNT / 3;
    info!(logger, "Kill {} of the new nodes", kill_nodes_count);
    for n in newly_assigned_nodes.iter().take(kill_nodes_count) {
        n.vm().kill();
    }

    // Second loop to paralelize the effects of the previous one
    info!(logger, "Wait for killed nodes to become unavailable");
    for n in newly_assigned_nodes.iter().take(kill_nodes_count) {
        n.await_status_is_unavailable().expect("Node still healthy");
    }

    // Assert that `update` call to the canister succeeds.
    info!(
        logger,
        "Assert that update call to the canister still succeeds"
    );
    block_on(message_canister.try_store_msg(UPDATE_MSG_2)).expect("Update canister call failed.");
    assert_eq!(
        block_on(message_canister.try_read_msg()),
        Ok(Some(UPDATE_MSG_2.to_string()))
    );

    // Kill one more node and break consensus.
    info!(logger, "Kill one more node and break consensus");
    newly_assigned_nodes[kill_nodes_count].vm().kill();
    info!(logger, "Wait for it to become unavailable");
    newly_assigned_nodes[kill_nodes_count]
        .await_status_is_unavailable()
        .expect("Node still healthy");

    // Assert that `update` call to the canister now fails.
    info!(logger, "Assert that update call to the canister now fails");
    if let Ok(Ok(result)) = block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            message_canister.try_store_msg(UPDATE_MSG_3),
        )
        .await
    }) {
        panic!("expected the update to fail, got {:?}", result);
    };

    // Restart node to start consensus.
    info!(logger, "Restart node to start consensus");
    newly_assigned_nodes[kill_nodes_count].vm().start();
    info!(logger, "Wait for subnet to restart");
    // Wait for 1 DKG interval to ensure that subnet makes progress again.
    let target_height =
        get_node_certified_height(&app_node, logger.clone()).get() + DKG_INTERVAL_LENGTH;
    await_node_certified_height(&app_node, Height::from(target_height), logger.clone());

    // Assert that `update` call to the canister succeeds again.
    info!(
        logger,
        "Assert that update call to the canister succeeds again"
    );
    block_on(message_canister.try_store_msg(UPDATE_MSG_4)).expect("Update canister call failed.");
    assert_eq!(
        block_on(message_canister.try_read_msg()),
        Ok(Some(UPDATE_MSG_4.to_string()))
    );
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}
