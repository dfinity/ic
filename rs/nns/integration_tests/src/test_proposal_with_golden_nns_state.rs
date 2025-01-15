use std::env;

use ic_base_types::PrincipalId;
use ic_ledger_core::tokens::Tokens;
use ic_nns_common::pb::v1::ProposalId;
use ic_nns_test_utils::{
    nns_canister_upgrade::NnsCanisterUpgrade,
    state_test_helpers::{
        adopt_proposal, nns_create_neuron_with_stake, nns_create_super_powerful_neuron,
        nns_get_network_economics_parameters, nns_propose_upgrade_nns_canister,
        nns_wait_for_proposal_execution, wait_for_canister_upgrade_to_succeed,
    },
};
use ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_nns_state_or_panic;

#[test]
fn test_proposal_with_golden_nns_state() {
    // Step 1: Prepare the world

    // Make sure we can get a test version of NNS Governance. This enables adopting open proposals.
    let mut nns_canister_upgrade = NnsCanisterUpgrade::new("governance-test");

    // Step 1.1: Load golden nns state into a StateMachine.
    let state_machine = new_state_machine_with_golden_nns_state_or_panic();

    // Save initial state for the ultimate assertion of this test.
    let network_economics = nns_get_network_economics_parameters(&state_machine);

    // Phase I. Upgrade NNS Governance to a test-only version (using a super powerful neuron) that
    // allows adopting any proposal by calling adopt_proposal.
    {
        let neuron_controller = PrincipalId::new_self_authenticating(&[1, 2, 3, 4]);
        let proposer_neuron_id =
            nns_create_super_powerful_neuron(&state_machine, neuron_controller);

        println!("Proposing to upgrade NNS Governance ...");

        let _proposal_id = nns_propose_upgrade_nns_canister(
            &state_machine,
            neuron_controller,
            proposer_neuron_id,
            nns_canister_upgrade.canister_id,
            nns_canister_upgrade.wasm_content.clone(),
            nns_canister_upgrade.module_arg.clone(),
            true,
        );

        // Step 3: Verify result(s): In a short while, the canister should be running the new code.
        wait_for_canister_upgrade_to_succeed(
            &state_machine,
            nns_canister_upgrade.canister_id,
            &nns_canister_upgrade.wasm_hash,
            nns_canister_upgrade.controller_principal_id(),
        );

        println!("Upgrading NNS Governance to a test version succeeded!");
    }

    // Phase II. Test that adopt_proposal now works for another proposal (so we no longer need the
    // super powerful neuron).
    {
        let neuron_controller = PrincipalId::new_self_authenticating(&[5, 6, 7, 8]);
        let proposer_neuron_id = nns_create_neuron_with_stake(
            &state_machine,
            neuron_controller,
            Tokens::from_e8s(network_economics.neuron_minimum_stake_e8s),
        );

        let proposal_id = if let Ok(proposal_id) = env::var("NNS_PROPOSAL_ID_TO_ADOPT") {
            let id = proposal_id
                .parse::<u64>()
                .expect("Proposal ID must be a u64");

            ProposalId { id }
        } else {
            nns_canister_upgrade.modify_wasm_but_preserve_behavior();

            nns_propose_upgrade_nns_canister(
                &state_machine,
                neuron_controller,
                proposer_neuron_id,
                nns_canister_upgrade.canister_id,
                nns_canister_upgrade.wasm_content.clone(),
                nns_canister_upgrade.module_arg.clone(),
                true,
            )
        };

        adopt_proposal(&state_machine, proposal_id).unwrap();

        nns_wait_for_proposal_execution(&state_machine, proposal_id.id);
    }

    // Phase III. Smoke test.
    //
    // Example use case for manual experimentation. Say we want to observe how the network economics
    // are being changed as a result of adopting the corresponding NNS proposal. The diff would be
    // pretty printed by the following (failing) assertion.
    //
    // The reason this assertion passes in CI is because we did not have `NNS_PROPOSAL_ID_TO_ADOPT`
    // defined, which is an environment variable for manual experimentation. Thus, the proposal was
    // an upgrade proposal, and the network economics are expected to be unchanged. This, however,
    // allows avoiding bit rot in the example code (which would likely happen if it were commented
    // out).
    let new_network_economics = nns_get_network_economics_parameters(&state_machine);
    assert_eq!(new_network_economics, network_economics);
}
