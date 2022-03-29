/* tag::catalog[]
Title:: Removal of the node record from the registry

Goal:: Confirm that removing unassigned/assigned node record from the registry succeeds/fails.

Runbook::
. Setup:
    . System subnet comprising two nodes and all necessary NNS canisters.
    . One unassigned node
. Try removing the registry record of a node belonging to system subnet (via proposal).
. Assert operation failure.
. Try removing the registry record of the unassigned node (via proposal).
. Assert operation success.
. Repeat the previous operation.
. Assert operation failure (node was already removed).

Success::
. Observe 'Failed' status for the proposal for the nns node removal.
. Observe 'Executed' status for the proposal for the unassigned node removal.
. Observe 'Failed' status for the proposal for the already removed node.

end::catalog[] */

use crate::nns::{
    submit_external_proposal_with_test_id, vote_execute_proposal_assert_executed, NnsExt,
};
use crate::{
    nns::vote_execute_proposal_assert_failed,
    util::{self, block_on},
};
use ic_base_types::PrincipalId;
use ic_fondue::{
    ic_manager::IcHandle,
    prod_tests::ic::{InternetComputer, Subnet},
};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance::pb::v1::NnsFunction;
use ic_registry_subnet_type::SubnetType;
use ic_types::Height;
use registry_canister::mutations::node_management::do_remove_nodes::RemoveNodesPayload;

pub fn config() -> InternetComputer {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(3))
                .add_nodes(1),
        )
        .with_node_provider(PrincipalId::new_user_test_id(1))
        .with_node_operator(PrincipalId::new_user_test_id(1))
        .with_unassigned_nodes(1)
}

pub fn test(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    // Install all necessary NNS canisters.
    ctx.install_nns_canisters(&handle, true);
    // Assert that necessary endpoints are reachable.
    let mut rng = ctx.rng.clone();
    let nns_endpoint = util::get_random_nns_node_endpoint(&handle, &mut rng);
    block_on(nns_endpoint.assert_ready(ctx));
    let unassigned_node_endpoint = util::get_random_unassigned_node_endpoint(&handle, &mut rng);
    block_on(unassigned_node_endpoint.assert_ready(ctx));

    // Get the governance canister for sending proposals to.
    let nns_runtime = util::runtime_from_url(nns_endpoint.url.clone());
    let governance_canister = canister_test::Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);

    block_on(async {
        // Send the proposal to remove a random NNS node from the registry and assert operation failure.
        let proposal_id = submit_external_proposal_with_test_id(
            &governance_canister,
            NnsFunction::RemoveNodes,
            RemoveNodesPayload {
                node_ids: vec![nns_endpoint.node_id],
            },
        )
        .await;
        vote_execute_proposal_assert_failed(
            &governance_canister,
            proposal_id,
            "Cannot remove a node that is a member of a subnet",
        )
        .await;
        // Send the proposal to remove the unassigned node from the registry and assert operation success.
        let proposal_id = submit_external_proposal_with_test_id(
            &governance_canister,
            NnsFunction::RemoveNodes,
            RemoveNodesPayload {
                node_ids: vec![unassigned_node_endpoint.node_id],
            },
        )
        .await;
        vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
        // Confirm that the node was indeed removed by sending the proposal again and asserting failure.
        let proposal_id = submit_external_proposal_with_test_id(
            &governance_canister,
            NnsFunction::RemoveNodes,
            RemoveNodesPayload {
                node_ids: vec![unassigned_node_endpoint.node_id],
            },
        )
        .await;
        vote_execute_proposal_assert_failed(
            &governance_canister,
            proposal_id,
            format!(
                "Aborting node removal: Node Id {} not found in the registry",
                unassigned_node_endpoint.node_id
            ),
        )
        .await;
    });
}
