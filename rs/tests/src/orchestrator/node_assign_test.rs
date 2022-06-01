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

Success:: nodes can be added/killed to/within the existing subnet.

end::catalog[] */

use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::{test_env::TestEnv, test_env_api::*};
use crate::nns::{submit_external_proposal_with_test_id, vote_execute_proposal_assert_executed};
use crate::orchestrator::upgrade_downgrade::wait_node_unreachable;
use crate::util::*;
use canister_test;
use ic_base_types::NodeId;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance::pb::v1::NnsFunction;
use ic_registry_subnet_type::SubnetType;
use ic_types::Height;
use registry_canister::mutations::do_add_nodes_to_subnet::AddNodesToSubnetPayload;

const UPDATE_MSG_1: &[u8] = b"This beautiful prose should be persisted for future generations";
const UPDATE_MSG_2: &[u8] = b"And this beautiful prose should be persisted for future generations";
const UPDATE_MSG_3: &[u8] = b"However this prose will NOT be persisted for future generations";
const UNASSIGNED_NODES_COUNT: usize = 3; // must be >= 3, currently tested for X=3, f=1 and N=4

pub fn config(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(19))
                .add_nodes(1),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(19))
                .add_nodes(1),
        )
        .with_unassigned_nodes(UNASSIGNED_NODES_COUNT as i32)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

pub fn test(env: TestEnv) {
    let topo_snapshot = env.topology_snapshot();

    // Install all necessary NNS canisters.
    let nns_node = topo_snapshot
        .root_subnet()
        .nodes()
        .next()
        .expect("there is no NNS node");
    nns_node.await_status_is_healthy().unwrap();
    nns_node
        .install_nns_canisters()
        .expect("NNS canisters not installed");

    let unassigned_node_ids: Vec<NodeId> = topo_snapshot
        .unassigned_nodes()
        .map(|n| n.node_id)
        .collect();
    assert_eq!(unassigned_node_ids.len(), UNASSIGNED_NODES_COUNT);

    topo_snapshot.unassigned_nodes().for_each(|n| {
        n.await_can_login_as_admin_via_ssh().unwrap();
    });
    let unassigned_nodes = topo_snapshot.unassigned_nodes();

    // get application node
    let app_subnet = topo_snapshot
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("there is no application subnet");
    let app_node = app_subnet
        .nodes()
        .next()
        .expect("there is no application node");
    app_node.await_status_is_healthy().unwrap();

    // Create NNS runtime.
    let nns_runtime = runtime_from_url(nns_node.get_public_url());

    // Send a proposal for the nodes to join a subnet via the governance canister.
    let governance_canister = canister_test::Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);
    let proposal_payload = AddNodesToSubnetPayload {
        subnet_id: app_subnet.subnet_id.get(),
        node_ids: unassigned_node_ids,
    };
    let proposal_id = block_on(submit_external_proposal_with_test_id(
        &governance_canister,
        NnsFunction::AddNodeToSubnet,
        proposal_payload,
    ));

    // Explicitly vote for the proposal to add nodes to subnet.
    block_on(vote_execute_proposal_assert_executed(
        &governance_canister,
        proposal_id,
    ));

    // Set unassigned nodes to the Application subnet.
    let newly_assigned_nodes: Vec<_> = unassigned_nodes.collect();

    // Wait for registry update
    topo_snapshot
        .block_for_newer_registry_version()
        .expect("Could not block for newer registry version");

    // Assert that new nodes are reachable (via http call).
    for n in newly_assigned_nodes.iter() {
        n.await_status_is_healthy().unwrap();
    }

    // Install a canister in the Application subnet for testing consensus (sending
    // `update` messages).
    let agent = block_on(assert_create_agent(app_node.get_public_url().as_str()));
    let universal_canister = block_on(UniversalCanister::new(&agent));

    // Assert that `update` call to the canister succeeds.
    let delay = create_delay(500, 60);
    block_on(universal_canister.try_store_to_stable(0, UPDATE_MSG_1, delay.clone()))
        .expect("Update canister call failed.");
    assert_eq!(
        block_on(universal_canister.try_read_stable(0, UPDATE_MSG_1.len() as u32)),
        UPDATE_MSG_1.to_vec()
    );

    // Kill floor(X/3) nodes.
    let kill_nodes_count = UNASSIGNED_NODES_COUNT / 3;
    for n in newly_assigned_nodes.iter().take(kill_nodes_count) {
        n.vm().kill();
    }
    // Second loop to paralelize the effects of the previous one
    for n in newly_assigned_nodes.iter().take(kill_nodes_count) {
        wait_node_unreachable(&env.logger(), n);
    }

    // Assert that `update` call to the canister succeeds.
    block_on(universal_canister.try_store_to_stable(0, UPDATE_MSG_2, delay.clone()))
        .expect("Update canister call failed.");
    assert_eq!(
        block_on(universal_canister.try_read_stable(0, UPDATE_MSG_2.len() as u32)),
        UPDATE_MSG_2.to_vec()
    );

    // Kill one more node and break consensus.
    newly_assigned_nodes[kill_nodes_count].vm().kill();
    wait_node_unreachable(&env.logger(), &newly_assigned_nodes[kill_nodes_count]);

    // Assert that `update` call to the canister now fails.
    assert!(block_on(universal_canister.try_store_to_stable(0, UPDATE_MSG_3, delay)).is_err());
}
