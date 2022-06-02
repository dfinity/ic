use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use assert_matches::assert_matches;
use canister_test::{Canister, Project};
use dfn_candid::candid_one;
use dfn_protobuf::protobuf;
use ic_base_types::{CanisterId, PrincipalId};
use ic_canister_client::Sender;
use ic_ledger_core::{block::BlockType, timestamp::TimeStamp};
use ic_nervous_system_common::ledger;
use ic_nervous_system_common_test_keys::TEST_USER1_KEYPAIR;
use ic_nns_common::pb::v1::NeuronId as NeuronIdProto;
use ic_nns_constants::{
    ALL_NNS_CANISTER_IDS, GENESIS_TOKEN_CANISTER_ID, GOVERNANCE_CANISTER_ID, ROOT_CANISTER_ID,
};
use ic_nns_governance::pb::v1::governance_error::ErrorType;
use ic_nns_governance::pb::v1::manage_neuron::claim_or_refresh::{By, MemoAndController};
use ic_nns_governance::pb::v1::manage_neuron::Disburse;
use ic_nns_governance::pb::v1::manage_neuron::NeuronIdOrSubaccount;
use ic_nns_governance::pb::v1::manage_neuron::{ClaimOrRefresh, Command};
use ic_nns_governance::pb::v1::manage_neuron_response::Command as CommandResponse;
use ic_nns_governance::pb::v1::{
    claim_or_refresh_neuron_from_account_response::Result as ClaimOrRefreshResult,
    ClaimOrRefreshNeuronFromAccount, ClaimOrRefreshNeuronFromAccountResponse, GovernanceError,
    ManageNeuron, ManageNeuronResponse, Neuron,
};
use ic_nns_test_utils::itest_helpers::{
    local_test_on_nns_subnet, maybe_upgrade_root_controlled_canister_to_self, NnsCanisters,
    NnsInitPayloadsBuilder, UpgradeTestingScenario,
};
use ledger_canister::{
    protobuf::TipOfChainRequest, AccountBalanceArgs, AccountIdentifier, ArchiveOptions, Block,
    BlockHeight, LedgerCanisterInitPayload, Memo, SendArgs, TipOfChainRes, Tokens, Transaction,
    DEFAULT_TRANSFER_FEE,
};
use tokio::time::{timeout_at, Instant};

fn example_block() -> Block {
    let transaction = Transaction::new(
        AccountIdentifier::new(CanisterId::from_u64(1).get(), None),
        AccountIdentifier::new(CanisterId::from_u64(2).get(), None),
        Tokens::new(10000, 50).unwrap(),
        DEFAULT_TRANSFER_FEE,
        Memo(456),
        TimeStamp::new(2_000_000_000, 123_456_789),
    );
    Block::new_from_transaction(None, transaction, TimeStamp::new(1, 1))
}

async fn perform_transfers(
    nns_canisters: Arc<NnsCanisters<'static>>,
    user: Sender,
    blocks_per_archive_node: usize,
) {
    let mut join_handles = Vec::new();
    // Do `num_blocks_to_archive' transfers in parallel
    for idx in 0..blocks_per_archive_node {
        let nns_canisters = nns_canisters.clone();
        let user = user.clone();
        join_handles.push(tokio::runtime::Handle::current().spawn(async move {
            let result: Result<BlockHeight, String> = timeout_at(
                Instant::now() + Duration::from_secs(10u64),
                nns_canisters.ledger.update_from_sender(
                    "send_pb",
                    protobuf,
                    SendArgs {
                        memo: Memo(idx as u64),
                        amount: Tokens::from_tokens(1).unwrap(),
                        fee: DEFAULT_TRANSFER_FEE,
                        from_subaccount: None,
                        to: AccountIdentifier::new(user.get_principal_id(), None),
                        created_at_time: None,
                    },
                    &user,
                ),
            )
            .await
            .unwrap_or_else(|_| Err(format!("Operation {} (transfer) timed out.", idx)));
            result
        }));
    }

    let results = futures::future::join_all(join_handles.into_iter()).await;
    for result in results {
        result
            .as_ref()
            .expect("Error waiting for ledger transfer.")
            .as_ref()
            .expect("Error doing ledger transfer");
    }
}

#[test]
fn test_rosetta1_92() {
    local_test_on_nns_subnet(|runtime| async move {
        let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let alloc = Tokens::from_tokens(10000).unwrap();
        let blocks_per_archive_node = 8usize;
        let blocks_per_archive_call = 3usize;
        let (node_max_memory_size_bytes, max_message_size_bytes): (usize, usize) = {
            let e = example_block().encode();
            println!("[test] encoded block size: {}", e.size_bytes());
            (
                e.size_bytes() * blocks_per_archive_node,
                e.size_bytes() * blocks_per_archive_call,
            )
        };

        let mut ledger_init_state = HashMap::new();
        ledger_init_state.insert(AccountIdentifier::new(user.get_principal_id(), None), alloc);
        let init_args = LedgerCanisterInitPayload::builder()
            .minting_account(GOVERNANCE_CANISTER_ID.into())
            .initial_values(ledger_init_state)
            .archive_options(ArchiveOptions {
                node_max_memory_size_bytes: Some(node_max_memory_size_bytes),
                max_message_size_bytes: Some(max_message_size_bytes),
                controller_id: ROOT_CANISTER_ID,
                trigger_threshold: blocks_per_archive_node,
                num_blocks_to_archive: blocks_per_archive_call,
                cycles_for_archive_creation: Some(0),
            })
            .send_whitelist(ALL_NNS_CANISTER_IDS.iter().map(|&x| *x).collect())
            .build()
            .unwrap();

        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_test_neurons()
            .with_ledger_init_state(init_args)
            .build();

        // Get a static reference to the runtime that we can pass around.
        let runtime = Box::new(runtime);
        let runtime: &'static canister_test::Runtime = Box::leak(runtime);
        let mut nns_canisters = Arc::new(NnsCanisters::set_up(runtime, nns_init_payload).await);

        perform_transfers(nns_canisters.clone(), user.clone(), blocks_per_archive_node).await;

        let tip_of_chain_before: Result<TipOfChainRes, String> = nns_canisters
            .ledger
            .query_("tip_of_chain_pb", protobuf, TipOfChainRequest {})
            .await;

        assert_eq!(
            tip_of_chain_before
                .expect("Couldn't get the tip of the chain")
                .tip_index,
            // Tip of chain should be 4 initial transfers + 8 transfers - 1
            11u64
        );
        // All should be good by now, the tip should report the right number and we
        // should have archived the operations above.

        // Make sure there is exactly one archive canister
        let result: Result<Vec<CanisterId>, String> = nns_canisters
            .ledger
            .query_("get_nodes", dfn_candid::candid, ())
            .await;

        assert_eq!(
            result
                .as_ref()
                .expect("Failed to get archive canisters")
                .len(),
            1
        );
        let archive_canister_id = result.unwrap()[0];
        let mut archive_canister = Canister::new(runtime, archive_canister_id);

        let archive_canister_wasm = Project::cargo_bin_maybe_use_path_relative_to_rs(
            "rosetta-api/ledger_canister",
            "ledger-archive-node-canister",
            &[],
        );

        archive_canister.set_wasm(archive_canister_wasm.bytes());
        // Now upgrade the archive to self, it should stop taking blocks from the ledger
        maybe_upgrade_root_controlled_canister_to_self(
            Arc::get_mut(&mut nns_canisters).unwrap().clone(),
            &mut archive_canister,
            true,
            UpgradeTestingScenario::Always,
        )
        .await;

        // Perform some more transfers, this should create another archive canister but
        // because of ROSETTA1-92 it doesn't.
        // Perform the transfers in single transfer batches so that we give archiving
        // some oportunity to catch up.
        for _i in 0..blocks_per_archive_node {
            perform_transfers(nns_canisters.clone(), user.clone(), 1).await;
        }

        let tip_of_chain_after: Result<TipOfChainRes, String> = nns_canisters
            .ledger
            .query_("tip_of_chain_pb", protobuf, TipOfChainRequest {})
            .await;

        assert_eq!(
            tip_of_chain_after
                .expect("Couldn't get the tip of the chain")
                .tip_index,
            // Tip of chain should be 4 initial transfers + 16 transfers - 1
            19u64
        );

        // Assert that we have the right number of archive canisters.
        let archive_canisters: Vec<CanisterId> = nns_canisters
            .ledger
            .query_("get_nodes", dfn_candid::candid, ())
            .await
            .expect("Couldn't get archive canisters");
        assert!(archive_canisters.len() >= 2);

        runtime.stop();
        Ok(())
    });
}

// This tests the whole neuron lifecycle in integration with the ledger. Namely
// tests that the neuron can be staked from a ledger account. That the neuron
// can be claimed and ultimately disbursed to the same account.
#[test]
fn test_stake_and_disburse_neuron_with_notification() {
    local_test_on_nns_subnet(|runtime| {
        async move {
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
                .await?;
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
                    ManageNeuron {
                        neuron_id_or_subaccount: None,
                        id: None,
                        command: Some(Command::ClaimOrRefresh(ClaimOrRefresh {
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
                CommandResponse::Error(error) => panic!("Unexpected error: {}", error),
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
                .await?;
            // The balance should now be: initial allocation - stake - fee
            assert_eq!(
                Tokens::from_e8s(
                    user_balance.get_e8s() + stake.get_e8s() + DEFAULT_TRANSFER_FEE.get_e8s()
                ),
                alloc
            );

            // Disburse the neuron.
            let result: ManageNeuronResponse = nns_canisters
                .governance
                .update_from_sender(
                    "manage_neuron",
                    candid_one,
                    ManageNeuron {
                        neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(neuron_id)),
                        id: None,
                        command: Some(Command::Disburse(Disburse {
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
            result.expect("Error disbursing the neuron.");

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
                .await?;

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
    local_test_on_nns_subnet(|runtime| {
        async move {
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
                .await?;
            assert_eq!(alloc, user_balance);

            // Stake a neuron by transferring to a subaccount of the neurons
            // canister and notifying the canister of the transfer.
            let nonce = 12345u64;
            let to_subaccount =
                ledger::compute_neuron_staking_subaccount(user.get_principal_id(), nonce);

            let stake = Tokens::from_tokens(100).unwrap();
            let _block_height: BlockHeight = nns_canisters
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
                .await?;
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
                "Neuron: {:?}",
                full_neuron
            );
            assert_eq!(
                full_neuron.cached_neuron_stake_e8s,
                stake.get_e8s(),
                "Neuron: {:?}",
                full_neuron
            );
            assert_eq!(full_neuron.neuron_fees_e8s, 0, "Neuron: {:?}", full_neuron);
            assert_eq!(
                full_neuron.controller.as_ref().unwrap(),
                &user.get_principal_id(),
                "Neuron: {:?}",
                full_neuron
            );

            // Disburse the neuron.
            let result: ManageNeuronResponse = nns_canisters
                .governance
                .update_from_sender(
                    "manage_neuron",
                    candid_one,
                    ManageNeuron {
                        neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(neuron_id)),
                        id: None,
                        command: Some(Command::Disburse(Disburse {
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
            result.expect("Error disbursing the neuron.");

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
                .await?;

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
    local_test_on_nns_subnet(|runtime| async move {
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
            .unwrap();

        assert_eq!(gtc_icpt_amt, alloc);

        Ok(())
    });
}
