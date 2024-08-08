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

use ic_base_types::PrincipalId;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance_api::pb::v1::NnsFunction;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder,
        },
    },
    nns::{
        submit_external_proposal_with_test_id, vote_execute_proposal_assert_executed,
        vote_execute_proposal_assert_failed,
    },
    util::{block_on, runtime_from_url},
};
use ic_types::Height;
use registry_canister::mutations::node_management::do_remove_nodes::RemoveNodesPayload;
use slog::info;

pub fn config(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(3))
                .add_nodes(1),
        )
        .with_node_provider(PrincipalId::new_user_test_id(1))
        .with_node_operator(PrincipalId::new_user_test_id(1))
        .with_unassigned_nodes(1)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    env.topology_snapshot()
        .unassigned_nodes()
        .for_each(|node| node.await_can_login_as_admin_via_ssh().unwrap());
}

pub fn test(env: TestEnv) {
    let logger = env.logger();
    let topology = env.topology_snapshot();
    let nns_node = topology.root_subnet().nodes().next().unwrap();
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    info!(logger, "Installing NNS canisters on the root subnet...");
    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("Could not install NNS canisters");
    info!(&logger, "NNS canisters installed successfully.");
    // get IDs of all unassigned nodes
    let unassigned_node_id = topology.unassigned_nodes().next().unwrap().node_id;
    let governance_canister = canister_test::Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);

    block_on(async {
        // Send the proposal to remove a random NNS node from the registry and assert operation failure.
        let proposal_id = submit_external_proposal_with_test_id(
            &governance_canister,
            NnsFunction::RemoveNodes,
            RemoveNodesPayload {
                node_ids: vec![nns_node.node_id],
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
                node_ids: vec![unassigned_node_id],
            },
        )
        .await;
        vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
        // Confirm that the node was indeed removed by sending the proposal again and asserting failure.
        let proposal_id = submit_external_proposal_with_test_id(
            &governance_canister,
            NnsFunction::RemoveNodes,
            RemoveNodesPayload {
                node_ids: vec![unassigned_node_id],
            },
        )
        .await;
        vote_execute_proposal_assert_failed(
            &governance_canister,
            proposal_id,
            format!(
                "Aborting node removal: Node Id {} not found in the registry",
                unassigned_node_id
            ),
        )
        .await;
    });
}
