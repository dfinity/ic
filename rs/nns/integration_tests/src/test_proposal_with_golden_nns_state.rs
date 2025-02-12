use std::env;

use ic_base_types::PrincipalId;
use ic_ledger_core::tokens::Tokens;
use ic_nns_common::pb::v1::ProposalId;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID};
use ic_nns_test_utils::{
    nns_canister_upgrade::NnsCanisterUpgrade,
    state_test_helpers::{
        adopt_proposal, nns_create_neuron_with_stake, nns_create_super_powerful_neuron, nns_get_monthly_node_provider_rewards, nns_get_network_economics_parameters, nns_propose_upgrade_nns_canister, nns_update_node_operator_config, nns_wait_for_proposal_execution, wait_for_canister_upgrade_to_succeed, install_code,
    },
};
use ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_nns_state_or_panic;
use maplit::btreemap;
use registry_canister::mutations::do_update_node_operator_config::UpdateNodeOperatorConfigPayload;
use std::str::FromStr;

#[test]
fn test_proposal_with_golden_nns_state() {
    // Step 1: Prepare the world

    // Make sure we can get a test version of NNS Governance. This enables adopting open proposals.
    let mut nns_canister_upgrade = NnsCanisterUpgrade::new("governance-test");

    // Step 1.1: Load golden nns state into a StateMachine.
    let state_machine = new_state_machine_with_golden_nns_state_or_panic();

    // Phase I. Upgrade NNS Governance to a test-only version (using a super powerful neuron) that
    // allows adopting any proposal by calling adopt_proposal.

    /*
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
    */
    install_code(
        &state_machine,
        GOVERNANCE_CANISTER_ID.into(),
        &nns_canister_upgrade.wasm_content,
        &nns_canister_upgrade.module_arg,
    );

    // Step 3: Verify result(s): In a short while, the canister should be running the new code.
    wait_for_canister_upgrade_to_succeed(
        &state_machine,
        nns_canister_upgrade.canister_id,
        &nns_canister_upgrade.wasm_hash,
        nns_canister_upgrade.controller_principal_id(),
    );

    println!("Upgrading NNS Governance to a test version succeeded!");

    // Phase II. Test that adopt_proposal now works for another proposal (so we no longer need the
    // super powerful neuron).
    {
        /*
        let proposal_id = if let Ok(proposal_id) = env::var("NNS_PROPOSAL_ID_TO_ADOPT") {
            let id = proposal_id
                .parse::<u64>()
                .expect("Proposal ID must be a u64");

            ProposalId { id }
        } else {
            // TODO replace with Sasa's proposal
        };

        // adopt_proposal(&state_machine, proposal_id).unwrap();

        nns_wait_for_proposal_execution(&state_machine, proposal_id.id);
        */
    }

    // Data from https://dfinity.enterprise.slack.com/docs/T43F9UHS5/F08CRU7R0HL
    nns_update_node_operator_config(
        &state_machine,
        &UpdateNodeOperatorConfigPayload {
            node_operator_id: Some(PrincipalId::from_str("3nu7r-l6i5c-jlmhi-fmmhm-4wcw4-ndlwb-yovrx-o3wxh-suzew-hvbbo-7qe").unwrap()),
            rewardable_nodes: btreemap! {
                "type1".to_string() => 28,
            },
            ..Default::default()
        },
    );
    nns_update_node_operator_config(
        &state_machine,
        &UpdateNodeOperatorConfigPayload {
            node_operator_id: Some(PrincipalId::from_str("redpf-rrb5x-sa2it-zhbh7-q2fsp-bqlwz-4mf4y-tgxmj-g5y7p-ezjtj-5qe").unwrap()),
            rewardable_nodes: btreemap! {
                "type1".to_string() => 28,
            },
            ..Default::default()
        },
    );
    nns_update_node_operator_config(
        &state_machine,
        &UpdateNodeOperatorConfigPayload {
            node_operator_id: Some(PrincipalId::from_str("bmlhw-kinr6-7cyv5-3o3v6-ic6tw-pnzk3-jycod-6d7sw-owaft-3b6k3-kqe").unwrap()),
            rewardable_nodes: btreemap! {
                "type1".to_string() => 14,
            },
            ..Default::default()
        },
    );

    // Phase III. Assert that things are as expected.
    let nns_get_monthly_node_provider_rewards = nns_get_monthly_node_provider_rewards(
        &state_machine,
    ).unwrap();
    println!("nns_get_monthly_node_provider_rewards = {:#?}", nns_get_monthly_node_provider_rewards);

    panic!("see stuff printed above!");
}
