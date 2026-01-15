use assert_matches::assert_matches;
use canister_test::Runtime;
use dfn_candid::candid_one;
use dfn_protobuf::protobuf;
use ic_base_types::PrincipalId;
use ic_canister_client_sender::Sender;
use ic_nervous_system_common::ledger;
use ic_nervous_system_common_test_keys::TEST_USER1_KEYPAIR;
use ic_nns_common::pb::v1::NeuronId as NeuronIdProto;
use ic_nns_constants::{ALL_NNS_CANISTER_IDS, GENESIS_TOKEN_CANISTER_ID, GOVERNANCE_CANISTER_ID};
use ic_nns_governance::governance::INITIAL_NEURON_DISSOLVE_DELAY;
use ic_nns_governance_api::{
    ClaimOrRefreshNeuronFromAccount, ClaimOrRefreshNeuronFromAccountResponse, GovernanceError,
    ManageNeuronCommandRequest, ManageNeuronRequest, ManageNeuronResponse, Neuron,
    claim_or_refresh_neuron_from_account_response::Result as ClaimOrRefreshResult,
    governance_error::ErrorType,
    manage_neuron::{
        ClaimOrRefresh, Disburse, NeuronIdOrSubaccount,
        claim_or_refresh::{By, MemoAndController},
    },
    manage_neuron_response::Command as CommandResponse,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    itest_helpers::{NnsCanisters, state_machine_test_on_nns_subnet},
    state_test_helpers::nns_start_dissolving,
};
use icp_ledger::{
    AccountBalanceArgs, AccountIdentifier, BlockIndex, DEFAULT_TRANSFER_FEE,
    LedgerCanisterInitPayload, Memo, SendArgs, Tokens, tokens_from_proto,
};
use std::{collections::HashMap, time::Duration};

// This tests the whole neuron lifecycle in integration with the ledger. Namely
// tests that the neuron can be staked from a ledger account. That the neuron
// can be claimed and ultimately disbursed to the same account.
#[test]
fn test_stake_and_disburse_neuron_with_notification() {
    state_machine_test_on_nns_subnet(|runtime| {
        async move {
            let state_machine = match runtime {
                Runtime::StateMachine(ref state_machine) => state_machine,
                _ => panic!("This test must run on a state machine."),
            };
            // Initialize the ledger with an account for a user.
            let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);

            let alloc = Tokens::from_tokens(1000).unwrap();
            let mut ledger_init_state = HashMap::new();
            ledger_init_state.insert(user.get_principal_id().into(), alloc);
            let init_args = LedgerCanisterInitPayload::builder()
                .minting_account(GOVERNANCE_CANISTER_ID.into())
                .initial_values(ledger_init_state)
                .send_whitelist(ALL_NNS_CANISTER_IDS.iter().map(|&x| *x).collect())
                .build()
                .unwrap();

            let nns_init_payload = NnsInitPayloadsBuilder::new()
                .with_ledger_init_state(init_args)
                .build();

            let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

            let user_balance: Tokens = nns_canisters
                .ledger
                .query_(
                    "account_balance_pb",
                    protobuf,
                    AccountBalanceArgs {
                        account: user.get_principal_id().into(),
                    },
                )
                .await
                .map(tokens_from_proto)?;
            assert_eq!(alloc, user_balance);

            // Stake a neuron by transferring to a subaccount of the neurons
            // canister and claiming the neuron on the governance canister..
            let nonce = 12345u64;
            let to_subaccount =
                ledger::compute_neuron_staking_subaccount(user.get_principal_id(), nonce);

            // Stake the neuron.
            let stake = Tokens::from_tokens(100).unwrap();
            let _block_height: u64 = nns_canisters
                .ledger
                .update_from_sender(
                    "send_pb",
                    protobuf,
                    SendArgs {
                        memo: Memo(nonce),
                        amount: stake,
                        fee: DEFAULT_TRANSFER_FEE,
                        from_subaccount: None,
                        to: AccountIdentifier::new(
                            PrincipalId::from(GOVERNANCE_CANISTER_ID),
                            Some(to_subaccount),
                        ),
                        created_at_time: None,
                    },
                    &user,
                )
                .await
                .expect("Couldn't send funds.");

            // Claim the neuron on the governance canister.
            let manage_neuron_response: ManageNeuronResponse = nns_canisters
                .governance
                .update_from_sender(
                    "manage_neuron",
                    candid_one,
                    ManageNeuronRequest {
                        neuron_id_or_subaccount: None,
                        id: None,
                        command: Some(ManageNeuronCommandRequest::ClaimOrRefresh(ClaimOrRefresh {
                            by: Some(By::MemoAndController(MemoAndController {
                                memo: nonce,
                                controller: None,
                            })),
                        })),
                    },
                    &user,
                )
                .await
                .expect("Error calling the manage_neuron api.");

            let neuron_id = match manage_neuron_response.command.unwrap() {
                CommandResponse::Error(error) => panic!("Unexpected error: {error}"),
                CommandResponse::ClaimOrRefresh(claim_or_refresh_response) => {
                    claim_or_refresh_response.refreshed_neuron_id.unwrap()
                }
                _ => panic!("Unexpected command response."),
            };

            // The balance now should have been deducted the stake.
            let user_balance: Tokens = nns_canisters
                .ledger
                .query_(
                    "account_balance_pb",
                    protobuf,
                    AccountBalanceArgs {
                        account: user.get_principal_id().into(),
                    },
                )
                .await
                .map(tokens_from_proto)?;
            // The balance should now be: initial allocation - stake - fee
            assert_eq!(
                Tokens::from_e8s(
                    user_balance.get_e8s() + stake.get_e8s() + DEFAULT_TRANSFER_FEE.get_e8s()
                ),
                alloc
            );

            nns_start_dissolving(state_machine, user.get_principal_id(), neuron_id)
                .expect("Failed to start dissolving neuron");

            state_machine.advance_time(Duration::from_secs(INITIAL_NEURON_DISSOLVE_DELAY + 1));
            state_machine.tick();

            // Disburse the neuron.
            let result: ManageNeuronResponse = nns_canisters
                .governance
                .update_from_sender(
                    "manage_neuron",
                    candid_one,
                    ManageNeuronRequest {
                        neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(neuron_id)),
                        id: None,
                        command: Some(ManageNeuronCommandRequest::Disburse(Disburse {
                            amount: None,
                            to_account: Some(
                                AccountIdentifier::new(user.get_principal_id(), None).into(),
                            ),
                        })),
                    },
                    &user,
                )
                .await
                .expect("Error calling the manage_neuron api.");
            result.panic_if_error("Error disbursing the neuron.");

            // Check the balance again.
            //
            // Use an "update" instead of a query to make sure that the transfer
            // was executed first.
            let user_balance: Tokens = nns_canisters
                .ledger
                .update_from_sender(
                    "account_balance_pb",
                    protobuf,
                    AccountBalanceArgs {
                        account: user.get_principal_id().into(),
                    },
                    &user,
                )
                .await
                .map(tokens_from_proto)?;

            // The balance should now be: initial allocation - fee * 2 (one fee for the
            // stake and one for the disburse).
            assert_eq!(
                Tokens::from_e8s(user_balance.get_e8s() + 2 * DEFAULT_TRANSFER_FEE.get_e8s()),
                alloc
            );

            Ok(())
        }
    });
}

// Like the above but tests staking/refreshing the neuron by checking the
// ledger account.
#[test]
fn test_stake_and_disburse_neuron_with_account() {
    state_machine_test_on_nns_subnet(|runtime| {
        async move {
            let state_machine = match runtime {
                Runtime::StateMachine(ref state_machine) => state_machine,
                _ => panic!("This test must run on a state machine."),
            };
            // Initialize the ledger with an account for a user.
            let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);

            let alloc = Tokens::from_tokens(1000).unwrap();
            let mut ledger_init_state = HashMap::new();
            ledger_init_state.insert(user.get_principal_id().into(), alloc);
            let init_args = LedgerCanisterInitPayload::builder()
                .minting_account(GOVERNANCE_CANISTER_ID.into())
                .initial_values(ledger_init_state)
                .send_whitelist(ALL_NNS_CANISTER_IDS.iter().map(|&x| *x).collect())
                .build()
                .unwrap();

            let nns_init_payload = NnsInitPayloadsBuilder::new()
                .with_ledger_init_state(init_args)
                .build();

            let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

            let user_balance: Tokens = nns_canisters
                .ledger
                .query_(
                    "account_balance_pb",
                    protobuf,
                    AccountBalanceArgs {
                        account: user.get_principal_id().into(),
                    },
                )
                .await
                .map(tokens_from_proto)?;
            assert_eq!(alloc, user_balance);

            // Stake a neuron by transferring to a subaccount of the neurons
            // canister and notifying the canister of the transfer.
            let nonce = 12345u64;
            let to_subaccount =
                ledger::compute_neuron_staking_subaccount(user.get_principal_id(), nonce);

            let stake = Tokens::from_tokens(100).unwrap();
            let _block_height: BlockIndex = nns_canisters
                .ledger
                .update_from_sender(
                    "send_pb",
                    protobuf,
                    SendArgs {
                        memo: Memo(nonce),
                        amount: stake,
                        fee: DEFAULT_TRANSFER_FEE,
                        from_subaccount: None,
                        to: AccountIdentifier::new(
                            PrincipalId::from(GOVERNANCE_CANISTER_ID),
                            Some(to_subaccount),
                        ),
                        created_at_time: None,
                    },
                    &user,
                )
                .await
                .expect("Couldn't send funds.");

            // The balance now should have been deducted the stake.
            let user_balance: Tokens = nns_canisters
                .ledger
                .query_(
                    "account_balance_pb",
                    protobuf,
                    AccountBalanceArgs {
                        account: user.get_principal_id().into(),
                    },
                )
                .await
                .map(tokens_from_proto)?;
            // The balance should now be: initial allocation - stake - fee
            assert_eq!(
                Tokens::from_e8s(
                    user_balance.get_e8s() + stake.get_e8s() + DEFAULT_TRANSFER_FEE.get_e8s()
                ),
                alloc
            );

            let result: ClaimOrRefreshNeuronFromAccountResponse = nns_canisters
                .governance
                .update_from_sender(
                    "claim_or_refresh_neuron_from_account",
                    candid_one,
                    ClaimOrRefreshNeuronFromAccount {
                        controller: Some(user.get_principal_id()),
                        memo: nonce,
                    },
                    &user,
                )
                .await
                .unwrap();

            let neuron_id: NeuronIdProto = match result.result.unwrap() {
                ClaimOrRefreshResult::Error(_) => panic!("Error claiming neuron."),
                ClaimOrRefreshResult::NeuronId(nid) => nid,
            };

            // Someone else than 'user' should not have access to that new neuron
            let neuron_data_res_wrong_caller: Result<Neuron, GovernanceError> = nns_canisters
                .governance
                .update_("get_full_neuron", candid_one, neuron_id.id)
                .await
                .unwrap();
            assert_matches!(neuron_data_res_wrong_caller,
            Err(e) if e.error_type == ErrorType::NotAuthorized as i32);

            // Let's verify that the neuron state is as expected.
            let full_neuron_res: Result<Neuron, GovernanceError> = nns_canisters
                .governance
                .update_from_sender("get_full_neuron", candid_one, neuron_id.id, &user)
                .await
                .unwrap();
            let full_neuron = full_neuron_res.unwrap();
            assert_eq!(
                full_neuron.id.as_ref().unwrap(),
                &neuron_id,
                "Neuron: {full_neuron:?}"
            );
            assert_eq!(
                full_neuron.cached_neuron_stake_e8s,
                stake.get_e8s(),
                "Neuron: {full_neuron:?}"
            );
            assert_eq!(full_neuron.neuron_fees_e8s, 0, "Neuron: {full_neuron:?}");
            assert_eq!(
                full_neuron.controller.as_ref().unwrap(),
                &user.get_principal_id(),
                "Neuron: {full_neuron:?}"
            );
            nns_start_dissolving(state_machine, user.get_principal_id(), neuron_id)
                .expect("Failed to start dissolving neuron");

            state_machine.advance_time(Duration::from_secs(INITIAL_NEURON_DISSOLVE_DELAY + 1));
            state_machine.tick();
            // Disburse the neuron.
            let result: ManageNeuronResponse = nns_canisters
                .governance
                .update_from_sender(
                    "manage_neuron",
                    candid_one,
                    ManageNeuronRequest {
                        neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(neuron_id)),
                        id: None,
                        command: Some(ManageNeuronCommandRequest::Disburse(Disburse {
                            amount: None,
                            to_account: Some(
                                AccountIdentifier::new(user.get_principal_id(), None).into(),
                            ),
                        })),
                    },
                    &user,
                )
                .await
                .expect("Error calling the manage_neuron api.");
            result.panic_if_error("Error disbursing the neuron.");

            // Check the balance again.
            //
            // Use an "update" instead of a query to make sure that the transfer
            // was executed first.
            let user_balance: Tokens = nns_canisters
                .ledger
                .update_from_sender(
                    "account_balance_pb",
                    protobuf,
                    AccountBalanceArgs {
                        account: user.get_principal_id().into(),
                    },
                    &user,
                )
                .await
                .map(tokens_from_proto)?;

            // The balance should now be: initial allocation - fee * 2;
            assert_eq!(
                Tokens::from_e8s(user_balance.get_e8s() + 2 * DEFAULT_TRANSFER_FEE.get_e8s()),
                alloc
            );

            Ok(())
        }
    });
}

#[test]
fn test_ledger_gtc_sync() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        let gtc_user_id = GENESIS_TOKEN_CANISTER_ID.get();

        let mut ledger_init_state = HashMap::new();
        let alloc = Tokens::from_tokens(100).unwrap();
        ledger_init_state.insert(gtc_user_id.into(), alloc);

        let init_args = LedgerCanisterInitPayload::builder()
            .minting_account(GOVERNANCE_CANISTER_ID.into())
            .initial_values(ledger_init_state)
            .send_whitelist(ALL_NNS_CANISTER_IDS.iter().map(|&x| *x).collect())
            .build()
            .unwrap();

        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_ledger_init_state(init_args)
            .build();

        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        let gtc_icpt_amt: Tokens = nns_canisters
            .ledger
            .query_(
                "account_balance_pb",
                protobuf,
                AccountBalanceArgs::new(gtc_user_id.into()),
            )
            .await
            .map(tokens_from_proto)
            .unwrap();

        assert_eq!(gtc_icpt_amt, alloc);

        Ok(())
    });
}
