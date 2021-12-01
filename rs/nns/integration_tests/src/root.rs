use candid::{Encode, Nat};
use canister_test::Runtime;
use dfn_candid::candid_one;
use dfn_protobuf::protobuf;
use ic_canister_client::Sender;
use ic_nns_common::{pb::v1::NeuronId, types::ProposalId};
use ic_nns_constants::{
    ids::{TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_2_OWNER_KEYPAIR, TEST_USER1_KEYPAIR},
    ALL_NNS_CANISTER_IDS, GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID,
};
use ic_nns_governance::pb::v1::{
    manage_neuron::{Command, NeuronIdOrSubaccount},
    manage_neuron_response::Command as CommandResponse,
    proposal::Action,
    ExecuteNnsFunction, ManageNeuron, ManageNeuronResponse, NnsFunction, Proposal, ProposalStatus,
    Vote,
};
use ic_nns_handler_root::common::{
    AddNnsCanisterProposalPayload, CanisterAction, StopOrStartNnsCanisterProposalPayload,
};
use ic_nns_test_utils::ids::{TEST_NEURON_1_ID, TEST_NEURON_2_ID};
use ic_nns_test_utils::{
    governance::{
        get_pending_proposals, maybe_upgrade_root_controlled_canister_to_self,
        submit_external_update_proposal, wait_for_final_state,
    },
    itest_helpers::{
        local_test_on_nns_subnet, NnsCanisters, NnsInitPayloadsBuilder, UpgradeTestingScenario,
    },
};
use ic_nns_test_utils_macros::parameterized_upgrades;
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM;
use ledger_canister::{
    AccountBalanceArgs, AccountIdentifier, BlockHeight, LedgerCanisterInitPayload, Memo, SendArgs,
    Tokens, TRANSACTION_FEE,
};
use std::collections::HashMap;

#[parameterized_upgrades]
async fn add_nns_canister(runtime: &Runtime, upgrade_scenario: UpgradeTestingScenario) {
    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .with_test_neurons()
        .build();
    let mut nns_canisters = NnsCanisters::set_up(runtime, nns_init_payload).await;

    let name = "new_mega_important_handler".to_string();

    // Test adding a new canister to the NNS.
    let proposal_payload = AddNnsCanisterProposalPayload {
        name: name.clone(),
        wasm_module: UNIVERSAL_CANISTER_WASM.to_vec(),
        arg: vec![],
        query_allocation: Some(Nat::from(34)),
        memory_allocation: Some(Nat::from(2771786)),
        compute_allocation: Some(Nat::from(12)),
        initial_cycles: 1 << 45,
        authz_changes: vec![],
    };

    let proposal_id = submit_external_update_proposal(
        &nns_canisters.governance,
        Sender::from_keypair(&TEST_NEURON_2_OWNER_KEYPAIR),
        ic_nns_common::types::NeuronId(TEST_NEURON_2_ID),
        NnsFunction::NnsCanisterInstall,
        proposal_payload,
        "<proposal created by add_nns_canister_and_change_authz>".to_string(),
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

#[test]
fn test_stop_start_nns_canister() {
    local_test_on_nns_subnet(|runtime| {
        async move {
            // Initialize the ledger with an account for a user.
            let user1 = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);
            let user2 = Sender::from_keypair(&TEST_USER1_KEYPAIR);

            let alloc = Tokens::from_tokens(1000).unwrap();
            let mut ledger_init_state = HashMap::new();
            ledger_init_state.insert(user1.get_principal_id().into(), alloc);
            let init_args = LedgerCanisterInitPayload::new(
                GOVERNANCE_CANISTER_ID.into(),
                ledger_init_state,
                None,
                None,
                None,
                ALL_NNS_CANISTER_IDS.iter().map(|&x| *x).collect(),
            );

            let nns_init_payload = NnsInitPayloadsBuilder::new()
                .with_ledger_init_state(init_args)
                .with_test_neurons()
                .build();

            let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

            // Perform a transfer, should succeed.
            let _: BlockHeight = nns_canisters
                .ledger
                .update_from_sender(
                    "send_pb",
                    protobuf,
                    SendArgs {
                        memo: Memo(0),
                        amount: Tokens::from_tokens(100).unwrap(),
                        fee: TRANSACTION_FEE,
                        from_subaccount: None,
                        to: AccountIdentifier::new(user2.get_principal_id(), None),
                        created_at_time: None,
                    },
                    &user1,
                )
                .await
                .expect("Couldn't send funds.");

            // Submit a proposal to stop the ledger.
            let payload = StopOrStartNnsCanisterProposalPayload {
                canister_id: LEDGER_CANISTER_ID,
                action: CanisterAction::Stop,
            };

            // Make a proposal to stop the ledger canister.
            // Should be automatically accepted.
            let result: ManageNeuronResponse = nns_canisters
                .governance
                .update_from_sender(
                    "manage_neuron",
                    candid_one,
                    ManageNeuron {
                        neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId {
                            id: TEST_NEURON_1_ID,
                        })),
                        id: None,
                        command: Some(Command::MakeProposal(Box::new(Proposal {
                            title: Some("Stop the ledger!".to_string()),
                            summary: "".to_string(),
                            url: "".to_string(),
                            action: Some(Action::ExecuteNnsFunction(ExecuteNnsFunction {
                                nns_function: NnsFunction::StopOrStartNnsCanister as i32,
                                payload: Encode!(&payload).expect("Error encoding payload"),
                            })),
                        }))),
                    },
                    &user1,
                )
                .await
                .expect("Error calling the manage_neuron api.");

            let pid = match result.command.unwrap() {
                CommandResponse::MakeProposal(response) => response.proposal_id.unwrap(),
                _ => panic!("Wrong response"),
            };

            // Wait for the proposal to be executed.
            assert_eq!(
                wait_for_final_state(&nns_canisters.governance, ProposalId::from(pid))
                    .await
                    .status(),
                ProposalStatus::Executed
            );

            // Perform a transfer, should fail.
            let result: Result<BlockHeight, String> = nns_canisters
                .ledger
                .update_from_sender(
                    "send_pb",
                    protobuf,
                    SendArgs {
                        memo: Memo(0),
                        amount: Tokens::from_tokens(100).unwrap(),
                        fee: TRANSACTION_FEE,
                        from_subaccount: None,
                        to: AccountIdentifier::new(user2.get_principal_id(), None),
                        created_at_time: None,
                    },
                    &user1,
                )
                .await;

            assert!(result.unwrap_err().contains("is stopped"));

            let payload = StopOrStartNnsCanisterProposalPayload {
                canister_id: LEDGER_CANISTER_ID,
                action: CanisterAction::Start,
            };

            // Make another proposal, to start the canister.
            // Should be automatically accepted.
            let result: ManageNeuronResponse = nns_canisters
                .governance
                .update_from_sender(
                    "manage_neuron",
                    candid_one,
                    ManageNeuron {
                        neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId {
                            id: TEST_NEURON_1_ID,
                        })),
                        id: None,
                        command: Some(Command::MakeProposal(Box::new(Proposal {
                            title: Some("Start the ledger!".to_string()),
                            summary: "".to_string(),
                            url: "".to_string(),
                            action: Some(Action::ExecuteNnsFunction(ExecuteNnsFunction {
                                nns_function: NnsFunction::StopOrStartNnsCanister as i32,
                                payload: Encode!(&payload).expect("Error encoding payload"),
                            })),
                        }))),
                    },
                    &user1,
                )
                .await
                .expect("Error calling the manage_neuron api.");

            let pid = match result.command.unwrap() {
                CommandResponse::MakeProposal(response) => response.proposal_id.unwrap(),
                _ => panic!("Wrong response"),
            };

            // Wait for the proposal to be executed.
            assert_eq!(
                wait_for_final_state(&nns_canisters.governance, ProposalId::from(pid))
                    .await
                    .status(),
                ProposalStatus::Executed
            );

            // Perform another transfer, should succeed.
            let _: BlockHeight = nns_canisters
                .ledger
                .update_from_sender(
                    "send_pb",
                    protobuf,
                    SendArgs {
                        memo: Memo(0),
                        amount: Tokens::from_tokens(100).unwrap(),
                        fee: TRANSACTION_FEE,
                        from_subaccount: None,
                        to: AccountIdentifier::new(user2.get_principal_id(), None),
                        created_at_time: None,
                    },
                    &user1,
                )
                .await
                .expect("Couldn't send funds.");

            let user1_balance: Tokens = nns_canisters
                .ledger
                .update_from_sender(
                    "account_balance_pb",
                    protobuf,
                    AccountBalanceArgs {
                        account: user1.get_principal_id().into(),
                    },
                    &user1,
                )
                .await?;

            // The balance of the first user should have been deducted 200 ICPTs from both
            // transfers, minus 2 * the transaction fees.
            assert_eq!(
                user1_balance,
                Tokens::from_e8s(
                    Tokens::from_tokens(800).unwrap().get_e8s() - 2 * TRANSACTION_FEE.get_e8s()
                )
            );

            let user2_balance: Tokens = nns_canisters
                .ledger
                .update_from_sender(
                    "account_balance_pb",
                    protobuf,
                    AccountBalanceArgs {
                        account: user2.get_principal_id().into(),
                    },
                    &user2,
                )
                .await?;

            // The balance of the first user should have been deducted 200 ICPTs from both
            // transfers.
            assert_eq!(user2_balance, Tokens::from_tokens(200).unwrap());

            Ok(())
        }
    });
}
