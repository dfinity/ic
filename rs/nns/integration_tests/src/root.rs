use candid::Nat;
use canister_test::Runtime;
use ic_canister_client_sender::Sender;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_2_ID, TEST_NEURON_2_OWNER_KEYPAIR,
};
use ic_nervous_system_root::change_canister::AddCanisterRequest;
use ic_nns_governance_api::pb::v1::{ManageNeuronResponse, NnsFunction, ProposalStatus, Vote};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    governance::{
        get_pending_proposals, maybe_upgrade_root_controlled_canister_to_self,
        submit_external_update_proposal, wait_for_final_state,
    },
    itest_helpers::{NnsCanisters, UpgradeTestingScenario},
};
use ic_nns_test_utils_macros::parameterized_upgrades;
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM;

#[parameterized_upgrades]
async fn add_nns_canister(runtime: &Runtime, upgrade_scenario: UpgradeTestingScenario) {
    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .with_test_neurons()
        .build();
    let mut nns_canisters = NnsCanisters::set_up(runtime, nns_init_payload).await;

    let name = "new_mega_important_handler".to_string();

    // Test adding a new canister to the NNS.
    let add_canister_request = AddCanisterRequest {
        name: name.clone(),
        wasm_module: UNIVERSAL_CANISTER_WASM.to_vec(),
        arg: vec![],
        memory_allocation: Some(Nat::from(12345678_u32)),
        compute_allocation: Some(Nat::from(12_u8)),
        initial_cycles: 1 << 45,
    };

    let proposal_id = submit_external_update_proposal(
        &nns_canisters.governance,
        Sender::from_keypair(&TEST_NEURON_2_OWNER_KEYPAIR),
        ic_nns_common::types::NeuronId(TEST_NEURON_2_ID),
        NnsFunction::NnsCanisterInstall,
        add_canister_request,
        "<proposal created by add_nns_canister>".to_string(),
        "".to_string(),
    )
    .await;

    maybe_upgrade_root_controlled_canister_to_self(
        nns_canisters.clone(),
        &mut nns_canisters.governance,
        true,
        upgrade_scenario,
    )
    .await;

    // Should have 1 pending proposals
    let pending_proposals = get_pending_proposals(&nns_canisters.governance).await;
    assert_eq!(pending_proposals.len(), 1);

    // Cast votes.
    let input = (TEST_NEURON_1_ID, proposal_id, Vote::Yes);
    let _result: ManageNeuronResponse = nns_canisters
        .governance
        .update_from_sender(
            "forward_vote",
            dfn_candid::candid,
            input,
            &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        )
        .await
        .expect("Vote failed");

    // Wait for the proposal to be accepted and executed.
    assert_eq!(
        wait_for_final_state(&nns_canisters.governance, proposal_id)
            .await
            .status(),
        ProposalStatus::Executed
    );

    // No proposals should be pending now.
    let pending_proposals = get_pending_proposals(&nns_canisters.governance).await;
    assert_eq!(pending_proposals, vec![]);
}
