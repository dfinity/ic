use crate::nns::NnsExt;
use crate::types::*;
use crate::util::*;
use canister_test::Canister;
use ic_canister_client::Sender;
use ic_fondue::{
    ic_manager::IcHandle,
    internet_computer::{InternetComputer, Subnet},
};
use ic_nns_common::types::NeuronId;
use ic_nns_constants::ids::TEST_NEURON_1_OWNER_KEYPAIR;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance::pb::v1::{NnsFunction, ProposalStatus};
use ic_nns_test_utils::governance::{
    get_pending_proposals, submit_external_update_proposal, wait_for_final_state,
};
use ic_nns_test_utils::ids::TEST_NEURON_1_ID;
use ic_registry_subnet_type::SubnetType;
use ic_utils::call::AsyncCall;
use ic_utils::interfaces::ManagementCanister;

pub fn config() -> InternetComputer {
    InternetComputer::new()
        .add_subnet(Subnet::fast(SubnetType::System))
        .add_subnet(Subnet::fast(SubnetType::Application))
}

/// Submits an `UninstallCode` proposal to the governance and verifies
/// that, when the proposal is executed, the canister is uninstalled.
pub fn test(handle: IcHandle, ctx: &fondue::pot::Context) {
    // Install NNS canisters
    ctx.install_nns_canisters(&handle, true);

    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on(async move {
        let endpoint = get_random_nns_node_endpoint(&handle, &mut rng);
        endpoint.assert_ready(ctx).await;
        let nns = runtime_from_url(endpoint.url.clone());
        let governance_canister = Canister::new(&nns, GOVERNANCE_CANISTER_ID);

        // Create a canister on an app subnet.
        let endpoint = get_random_nns_node_endpoint(&handle, &mut rng);
        endpoint.assert_ready(ctx).await;
        let agent = assert_create_agent(endpoint.url.as_str()).await;
        let mgr = ManagementCanister::create(&agent);
        let canister_to_uninstall = create_and_install(&agent, EMPTY_WASM).await;

        // Verify that the canister has a wasm module.
        assert!(mgr
            .canister_status(&canister_to_uninstall)
            .call_and_wait(delay())
            .await
            .unwrap()
            .0
            .module_hash
            .is_some());

        let proposal_payload = CanisterIdRecord {
            canister_id: canister_to_uninstall,
        };

        // Submitting a proposal also implicitly records a vote from the proposer,
        // which with TEST_NEURON_1 is enough to trigger execution.
        let proposal_id = submit_external_update_proposal(
            &governance_canister,
            Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            NeuronId(TEST_NEURON_1_ID),
            NnsFunction::UninstallCode,
            proposal_payload,
            "<proposal created by uninstall_via_governance_proposal>".to_string(),
            "".to_string(),
        )
        .await;

        // Wait for the proposal to be accepted and executed.
        assert_eq!(
            wait_for_final_state(&governance_canister, proposal_id)
                .await
                .status(),
            ProposalStatus::Executed
        );

        // No proposals should be pending now.
        let pending_proposals = get_pending_proposals(&governance_canister).await;
        assert!(pending_proposals.is_empty());

        // The module of the canister should no longer exist.
        assert_eq!(
            mgr.canister_status(&canister_to_uninstall)
                .call_and_wait(delay())
                .await
                .unwrap()
                .0
                .module_hash,
            None
        );
    });
}
