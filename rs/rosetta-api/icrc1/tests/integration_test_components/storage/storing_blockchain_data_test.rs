#![allow(clippy::disallowed_types)]
use crate::common::local_replica;
use crate::common::local_replica::create_and_install_custom_icrc_ledger;
use crate::common::local_replica::test_identity;
use crate::common::local_replica::{create_and_install_icrc_ledger, get_custom_agent};
use candid::{Decode, Encode, Nat};
use ic_agent::Identity;
use ic_agent::identity::BasicIdentity;
use ic_base_types::PrincipalId;
use ic_icrc_rosetta::common::storage::storage_client::StorageClient;
use ic_icrc_rosetta::ledger_blocks_synchronization::blocks_synchronizer::{self, RecurrencyMode};
use ic_icrc1_ledger::FeatureFlags;
use ic_icrc1_ledger::InitArgsBuilder;
use ic_icrc1_ledger::Tokens;
use ic_icrc1_test_utils::ArgWithCaller;
use ic_icrc1_test_utils::DEFAULT_TRANSFER_FEE;
use ic_icrc1_test_utils::LedgerEndpointArg;
use ic_icrc1_test_utils::icrc3::BlockBuilder;
use ic_icrc1_test_utils::minter_identity;
use ic_icrc1_test_utils::valid_transactions_strategy;
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_core::tokens::Zero;
use icrc_ledger_agent::CallMode;
use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::icrc::generic_value::ICRC3Value;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg;
use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use pocket_ic::PocketIcBuilder;
use proptest::prelude::*;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::runtime::Runtime;
use tokio::sync::Mutex as AsyncMutex;

lazy_static! {
    pub static ref TEST_ACCOUNT: Account = test_identity().sender().unwrap().into();
    pub static ref MAX_NUM_GENERATED_BLOCKS: usize = 50;
    pub static ref NUM_TEST_CASES: u32 = 2;
    pub static ref MINTER_IDENTITY: Arc<BasicIdentity> = Arc::new(minter_identity());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(*NUM_TEST_CASES))]
    #[test]
    fn test_updating_account_balances(args_with_caller in valid_transactions_strategy(
        MINTER_IDENTITY.clone(),
        DEFAULT_TRANSFER_FEE,
        *MAX_NUM_GENERATED_BLOCKS,
        SystemTime::now(),
    ).no_shrink()) {
        // Create a tokio environment to conduct async calls
        let rt = Runtime::new().unwrap();
        let mut pocket_ic = PocketIcBuilder::new().with_nns_subnet().with_sns_subnet().build();
        let init_args = InitArgsBuilder::for_tests()
            .with_minting_account(MINTER_IDENTITY.clone().sender().unwrap())
            .with_transfer_fee(DEFAULT_TRANSFER_FEE)
            .with_feature_flags(FeatureFlags {icrc2:true})
            .with_archive_options(ArchiveOptions {
                // Create archive after every ten blocks
                trigger_threshold: 10,
                num_blocks_to_archive: 5,
                node_max_memory_size_bytes: None,
                max_message_size_bytes: None,
                controller_id: PrincipalId::new_user_test_id(100),
                more_controller_ids: None,
                cycles_for_archive_creation: None,
                max_transactions_per_response: None,
            })
            .build();
        let icrc_ledger_canister_id = create_and_install_icrc_ledger(&pocket_ic, init_args, None);
        let endpoint = pocket_ic.make_live(None);
        let port = endpoint.port().unwrap();

        // Wrap async calls in a blocking Block
        rt.block_on(async {
            // Create a testing agent
            let agent = Arc::new(Icrc1Agent {
                agent: local_replica::get_testing_agent(port).await,
                ledger_canister_id: icrc_ledger_canister_id,
            });

            // Create the storage client where blocks will be stored
            let storage_client = Arc::new(StorageClient::new_in_memory().unwrap());

            // No blocks have been synched. The update should succeed with no accounts being updated
            storage_client.update_account_balances().unwrap();

            // A mapping between accounts, block indices and their respective balances
            let mut account_balance_at_block_idx = HashMap::new();

            // Keep track of all the accounts that will be created by the strategy
            let mut accounts = HashSet::new();
            let mut block_indices = HashSet::new();

            // Create some blocks to be fetched later
            // An archive is created after 10 blocks
            for ArgWithCaller {
                caller,
                arg,
                principal_to_basic_identity:_
            } in args_with_caller.iter() {
                let caller_agent = Icrc1Agent {
                    agent: get_custom_agent(caller.clone(), port).await,
                    ledger_canister_id: icrc_ledger_canister_id
                };
                let (block_idx,account1,account2) = match arg {
                    LedgerEndpointArg::ApproveArg(approve_arg) => {
                        let block_idx = caller_agent.approve(approve_arg.clone()).await.unwrap().unwrap().0.to_u64().unwrap();
                        let from_account = Account{owner:caller.clone().sender().unwrap(),subaccount: approve_arg.from_subaccount};
                        (block_idx,from_account,approve_arg.spender)
                    }
                    LedgerEndpointArg::TransferArg(transfer_arg) => {
                        let block_idx = caller_agent.transfer(transfer_arg.clone()).await.unwrap().unwrap().0.to_u64().unwrap();
                        let from_account = Account{owner:caller.clone().sender().unwrap(),subaccount: transfer_arg.from_subaccount};
                        (block_idx,from_account,transfer_arg.to)
                    }
                    LedgerEndpointArg::TransferFromArg(transfer_from_arg) => {
                        let block_idx = caller_agent.transfer_from(transfer_from_arg.clone()).await.unwrap().unwrap().0.to_u64().unwrap();
                        (block_idx,transfer_from_arg.from,transfer_from_arg.to)
                    }
                };

                // Store the current balance of the involved accounts and add them to the list of accounts if not already present
                let balance_acc1 = agent.balance_of(account1,CallMode::Query).await.unwrap();
                let balance_acc2 = agent.balance_of(account2,CallMode::Query).await.unwrap();
                account_balance_at_block_idx.insert((account1,block_idx),balance_acc1);
                account_balance_at_block_idx.insert((account2,block_idx),balance_acc2);
                accounts.insert(account1);
                accounts.insert(account2);
                block_indices.insert(block_idx);
            }

            let mut current_balances = HashMap::new();
            for account in accounts.clone().into_iter(){
                current_balances.insert(account,Nat(BigUint::zero()));
            }

            blocks_synchronizer::start_synching_blocks(agent.clone(), storage_client.clone(), 10,Arc::new(AsyncMutex::new(vec![])), RecurrencyMode::OneShot, Box::new(|| {})).await.unwrap();
            storage_client.update_account_balances().unwrap();

            let mut block_indices_iter = block_indices.into_iter().collect::<Vec<u64>>();
            block_indices_iter.sort();

            // Iterate over every account at every block index and make sure the balances of the balances of the ledger match the balances of the rosetta storage
            for idx in block_indices_iter.into_iter(){
                for account in accounts.clone().into_iter(){
                    account_balance_at_block_idx.contains_key(&(account,idx)).then(|| current_balances.entry(account).and_modify(|balance| *balance = account_balance_at_block_idx.get(&(account,idx)).unwrap().clone()));
                    assert_eq!(*current_balances.get(&account).unwrap(),storage_client.get_account_balance_at_block_idx(&account,idx).unwrap().unwrap_or(Nat(BigUint::zero())));
                }
            }

            // Check that the current balances of the ledger and rosetta storage match up
            for account  in accounts.clone().into_iter(){
                let balance_ledger = agent.balance_of(account,CallMode::Query).await.unwrap();
                let balance_rosetta = storage_client.get_account_balance(&account).unwrap().unwrap_or(Nat(BigUint::zero()));
                assert_eq!(balance_ledger,balance_rosetta);
            }
        });
    }
}

#[test]
fn test_self_transfer() {
    // Create a tokio environment to conduct async calls
    let rt = Runtime::new().unwrap();
    let account = Account::from(test_identity().sender().unwrap());

    let mut pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .build();
    let init_args = InitArgsBuilder::for_tests()
        .with_minting_account(MINTER_IDENTITY.clone().sender().unwrap())
        .with_transfer_fee(DEFAULT_TRANSFER_FEE)
        .with_feature_flags(FeatureFlags { icrc2: true })
        .with_initial_balance(account, Nat::from(100_000_000_u64))
        .build();

    let icrc_ledger_canister_id = create_and_install_icrc_ledger(&pocket_ic, init_args, None);
    let endpoint = pocket_ic.make_live(None);
    let port = endpoint.port().unwrap();

    rt.block_on(async {
        let agent = Arc::new(Icrc1Agent {
            agent: local_replica::get_testing_agent(port).await,
            ledger_canister_id: icrc_ledger_canister_id,
        });
        let storage_client = Arc::new(StorageClient::new_in_memory().unwrap());

        blocks_synchronizer::start_synching_blocks(
            agent.clone(),
            storage_client.clone(),
            10,
            Arc::new(AsyncMutex::new(vec![])),
            RecurrencyMode::OneShot,
            Box::new(|| {}),
        )
        .await
        .unwrap();
        storage_client.update_account_balances().unwrap();

        let balance = agent.balance_of(account, CallMode::Query).await.unwrap();
        assert_eq!(balance, Nat::from(100_000_000_u64));
        assert_eq!(
            storage_client
                .get_account_balance(&account)
                .unwrap()
                .unwrap(),
            Nat::from(100_000_000_u64)
        );

        agent
            .transfer(TransferArg {
                to: account,
                amount: 1000u64.into(),
                fee: Some(DEFAULT_TRANSFER_FEE.into()),
                from_subaccount: None,
                created_at_time: None,
                memo: None,
            })
            .await
            .unwrap()
            .unwrap();

        blocks_synchronizer::start_synching_blocks(
            agent.clone(),
            storage_client.clone(),
            10,
            Arc::new(AsyncMutex::new(vec![])),
            RecurrencyMode::OneShot,
            Box::new(|| {}),
        )
        .await
        .unwrap();
        storage_client.update_account_balances().unwrap();

        let balance = agent.balance_of(account, CallMode::Query).await.unwrap();
        assert_eq!(balance, Nat::from(100_000_000 - DEFAULT_TRANSFER_FEE));
        assert_eq!(
            storage_client
                .get_account_balance(&account)
                .unwrap()
                .unwrap(),
            Nat::from(100_000_000 - DEFAULT_TRANSFER_FEE)
        );
    });
}

fn icrc3_test_ledger() -> Vec<u8> {
    std::fs::read(std::env::var("ICRC3_TEST_LEDGER_CANISTER_WASM_PATH").unwrap()).unwrap()
}

/// Adds the block to the ledger
pub async fn add_block(agent: &Arc<Icrc1Agent>, block: &ICRC3Value) -> Result<Nat, String> {
    let result = agent
        .agent
        .update(&agent.ledger_canister_id, "add_block")
        .with_arg(Encode!(block).expect("failed to encode arg"))
        .call_and_wait()
        .await
        .expect("failed to add block");
    Decode!(&result, Result<Nat, String>).unwrap()
}

#[test]
fn test_burn_and_mint_fee() {
    // Create a tokio environment to conduct async calls
    let rt = Runtime::new().unwrap();

    let mut pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .build();

    let init_args = InitArgsBuilder::for_tests().build();

    let icrc_ledger_canister_id =
        create_and_install_custom_icrc_ledger(&pocket_ic, init_args, icrc3_test_ledger(), None);
    let endpoint = pocket_ic.make_live(None);
    let port = endpoint.port().unwrap();

    rt.block_on(async {
        let agent = Arc::new(Icrc1Agent {
            agent: local_replica::get_testing_agent(port).await,
            ledger_canister_id: icrc_ledger_canister_id,
        });
        let storage_client = Arc::new(StorageClient::new_in_memory().unwrap());

        const FEE_COLLECTOR: Account = Account {
            owner: PrincipalId::new_user_test_id(2).0,
            subaccount: None,
        };

        // Create mint and burn blocks with fees, and add them to the ledger
        let block0 = BlockBuilder::new(0, 1000)
            .with_fee(Tokens::from(50u64))
            .mint(*TEST_ACCOUNT, Tokens::from(1_000u64))
            .build();
        let block1 = BlockBuilder::new(1, 2000)
            .with_parent_hash(block0.clone().hash().to_vec())
            .with_fee(Tokens::from(50u64))
            .burn(*TEST_ACCOUNT, Tokens::from(50u64))
            .build();
        let result0 = add_block(&agent, &block0).await.unwrap();
        assert_eq!(result0, Nat::from(0u64));
        let result1 = add_block(&agent, &block1).await.unwrap();
        assert_eq!(result1, Nat::from(1u64));

        blocks_synchronizer::start_synching_blocks(
            agent.clone(),
            storage_client.clone(),
            10,
            Arc::new(AsyncMutex::new(vec![])),
            RecurrencyMode::OneShot,
            Box::new(|| {}),
        )
        .await
        .unwrap();
        storage_client.update_account_balances().unwrap();

        assert_eq!(
            storage_client
                .get_account_balance(&TEST_ACCOUNT)
                .unwrap()
                .unwrap(),
            Nat::from(850u64) // mint 1000 - mint fee 50 - burn 50 - burn fee 50
        );
        assert!(
            storage_client
                .get_account_balance(&FEE_COLLECTOR)
                .unwrap()
                .is_none()
        ); // no fee collector in the first 2 blocks

        // Create mint and burn blocks with fees and fee collector, and add them to the ledger
        let block2 = BlockBuilder::new(2, 3000)
            .with_parent_hash(block1.clone().hash().to_vec())
            .with_fee(Tokens::from(50u64))
            .with_fee_collector(FEE_COLLECTOR)
            .mint(*TEST_ACCOUNT, Tokens::from(100u64))
            .build();
        let block3 = BlockBuilder::new(3, 4000)
            .with_parent_hash(block2.clone().hash().to_vec())
            .with_fee_collector_block(2)
            .with_fee(Tokens::from(50u64))
            .burn(*TEST_ACCOUNT, Tokens::from(50u64))
            .build();
        let result2 = add_block(&agent, &block2).await.unwrap();
        assert_eq!(result2, Nat::from(2u64));
        let result3 = add_block(&agent, &block3).await.unwrap();
        assert_eq!(result3, Nat::from(3u64));

        blocks_synchronizer::start_synching_blocks(
            agent.clone(),
            storage_client.clone(),
            10,
            Arc::new(AsyncMutex::new(vec![])),
            RecurrencyMode::OneShot,
            Box::new(|| {}),
        )
        .await
        .unwrap();
        storage_client.update_account_balances().unwrap();

        assert_eq!(
            storage_client
                .get_account_balance(&TEST_ACCOUNT)
                .unwrap()
                .unwrap(),
            Nat::from(800u64) // 850 + mint 100 - mint fee 50 - burn 50 - burn fee 50
        );
        assert_eq!(
            storage_client
                .get_account_balance(&FEE_COLLECTOR)
                .unwrap()
                .unwrap(),
            Nat::from(100u64) // mint fee 50 + burn fee 50
        );
    });
}
