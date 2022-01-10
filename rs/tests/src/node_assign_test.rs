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

use crate::nns::{
    submit_external_proposal_with_test_id, vote_execute_proposal_assert_executed, NnsExt,
};
use crate::util;
use canister_test;
use ic_base_types::NodeId;
use ic_fondue::{
    ic_instance::InternetComputer,
    ic_instance::Subnet,
    ic_manager::{IcControl, IcHandle},
    iterator::PermOf,
};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance::pb::v1::NnsFunction;
use ic_registry_subnet_type::SubnetType;
use ic_types::Height;
use registry_canister::mutations::do_add_nodes_to_subnet::AddNodesToSubnetPayload;
use std::time::{Duration, Instant};

const UPDATE_MSG_1: &[u8] = b"This beautiful prose should be persisted for future generations";
const UPDATE_MSG_2: &[u8] = b"And this beautiful prose should be persisted for future generations";
const UPDATE_MSG_3: &[u8] = b"However this prose will NOT be persisted for future generations";
const UNASSIGNED_NODES_COUNT: i32 = 3; // >= 3, tested for [3-9] nodes; beware that for many nodes, sleep time might
                                       // need adjustment for nodes to come up

pub fn config() -> InternetComputer {
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
        .with_unassigned_nodes(UNASSIGNED_NODES_COUNT)
}

pub fn test(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    // Install all necessary NNS canisters.
    ctx.install_nns_canisters(&handle, true);
    // Create a runtime, necessary to run async tasks.
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    let unassigned_nodes_endpoints = util::get_unassinged_nodes_endpoints(&handle);
    assert_eq!(
        unassigned_nodes_endpoints.len(),
        UNASSIGNED_NODES_COUNT as usize
    );

    let unassigned_node_ids: Vec<NodeId> = unassigned_nodes_endpoints
        .iter()
        .map(|ep| ep.node_id)
        .collect();

    // Check via internal ssh_open call.
    rt.block_on(util::assert_all_ready(
        unassigned_nodes_endpoints.as_slice(),
        ctx,
    ));

    // Get application and NNS endpoints and assert their readiness.
    let mut rng = ctx.rng.clone();
    let app_endpoint = util::get_random_application_node_endpoint(&handle, &mut rng);
    let nns_endpoint = util::get_random_nns_node_endpoint(&handle, &mut rng);
    rt.block_on(app_endpoint.assert_ready(ctx));
    rt.block_on(nns_endpoint.assert_ready(ctx));

    // Create runtime.
    let nns_runtime = util::runtime_from_url(nns_endpoint.url.clone());

    // Send a proposal for the nodes to join a subnet via the governance canister.
    let governance_canister = canister_test::Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);
    let proposal_payload = AddNodesToSubnetPayload {
        subnet_id: app_endpoint.subnet_id().unwrap().get(),
        node_ids: unassigned_node_ids,
    };
    let proposal_id = rt.block_on(submit_external_proposal_with_test_id(
        &governance_canister,
        NnsFunction::AddNodeToSubnet,
        proposal_payload,
    ));

    // Explicitly vote for the proposal to add nodes to subnet.
    rt.block_on(vote_execute_proposal_assert_executed(
        &governance_canister,
        proposal_id,
    ));

    // Set unassigned nodes to the Application subnet.
    let newly_assigned_nodes: Vec<_> = unassigned_nodes_endpoints
        .iter()
        .map(|ep| ep.recreate_with_subnet(app_endpoint.clone().subnet.unwrap()))
        .collect();

    // Sleep and assert that new nodes are reachable (via http call).
    rt.block_on(async {
        tokio::time::sleep(Duration::from_secs(80)).await;
        for ep in newly_assigned_nodes.iter() {
            ep.assert_ready_with_start(Instant::now(), ctx).await;
        }
    });

    // Install a canister in the Application subnet for testing consensus (sending
    // `update` messages).
    let agent = rt.block_on(util::assert_create_agent(app_endpoint.url.as_str()));
    let universal_canister = rt.block_on(util::UniversalCanister::new(&agent));

    // Assert that `update` call to the canister succeeds.
    let delay = util::create_delay(500, 60);
    rt.block_on(universal_canister.try_store_to_stable(0, UPDATE_MSG_1, delay.clone()))
        .expect("Update canister call failed.");
    assert_eq!(
        rt.block_on(universal_canister.try_read_stable(0, UPDATE_MSG_1.len() as u32)),
        UPDATE_MSG_1.to_vec()
    );

    // Kill random floor(X/3) nodes.
    let mut perm = PermOf::new(&newly_assigned_nodes, &mut rng);
    let kill_nodes_count = UNASSIGNED_NODES_COUNT / 3;
    for _ in 0..kill_nodes_count {
        perm.next().unwrap().kill_node(ctx.logger.clone());
    }

    // Assert that `update` call to the canister succeeds.
    rt.block_on(universal_canister.try_store_to_stable(0, UPDATE_MSG_2, delay.clone()))
        .expect("Update canister call failed.");
    assert_eq!(
        rt.block_on(universal_canister.try_read_stable(0, UPDATE_MSG_2.len() as u32)),
        UPDATE_MSG_2.to_vec()
    );

    // Kill one more node and break consensus.
    perm.next().unwrap().kill_node(ctx.logger.clone());

    // Assert that `update` call to the canister now fails.
    assert!(rt
        .block_on(universal_canister.try_store_to_stable(0, UPDATE_MSG_3, delay))
        .is_err());
}
