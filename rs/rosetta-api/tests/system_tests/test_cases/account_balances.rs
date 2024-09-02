use crate::common::system_test_environment::RosettaTestingEnvironment;
use crate::common::utils::get_test_agent;
use crate::common::utils::query_blocks;
use crate::common::utils::test_identity;
use candid::Nat;
use ic_agent::identity::BasicIdentity;
use ic_agent::Identity;
use ic_base_types::PrincipalId;
use ic_icrc1_test_utils::ArgWithCaller;
use ic_icrc1_test_utils::LedgerEndpointArg;
use ic_icrc1_test_utils::{minter_identity, valid_transactions_strategy, DEFAULT_TRANSFER_FEE};
use ic_ledger_core::block::BlockType;
use ic_nns_constants::LEDGER_CANISTER_ID;
use ic_rosetta_api::models::AccountBalanceRequest;
use icp_ledger::AccountIdentifier;
use icp_ledger::Subaccount;
use icrc_ledger_agent::CallMode;
use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::icrc1::account::Account;
use lazy_static::lazy_static;
use proptest::strategy::Strategy;
use proptest::test_runner::Config as TestRunnerConfig;
use proptest::test_runner::TestRunner;
use rosetta_core::identifiers::TransactionIdentifier;
use rosetta_core::request_types::SearchTransactionsRequest;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::runtime::Runtime;

lazy_static! {
    pub static ref TEST_ACCOUNT: Account = test_identity().sender().unwrap().into();
    pub static ref MAX_NUM_GENERATED_BLOCKS: usize = 50;
    pub static ref NUM_TEST_CASES: u32 = 1;
    pub static ref MINTING_IDENTITY: Arc<BasicIdentity> = Arc::new(minter_identity());
}

#[test]
fn test_account_balances() {
    let mut runner = TestRunner::new(TestRunnerConfig {
        max_shrink_iters: 0,
        cases: *NUM_TEST_CASES,
        ..Default::default()
    });

    runner
        .run(
            &(valid_transactions_strategy(
                (*MINTING_IDENTITY).clone(),
                DEFAULT_TRANSFER_FEE,
                *MAX_NUM_GENERATED_BLOCKS,
                SystemTime::now(),
            )
            .no_shrink()),
            |args_with_caller| {
                let rt = Runtime::new().unwrap();
                rt.block_on(async {
                    let rosetta_testing_environment = RosettaTestingEnvironment::builder()
                        .with_minting_account(MINTING_IDENTITY.sender().unwrap().into())
                        .build()
                        .await;
                    let icrc1_agent = Icrc1Agent {
                        agent: get_test_agent(
                            rosetta_testing_environment
                                .pocket_ic
                                .url()
                                .unwrap()
                                .port()
                                .unwrap(),
                        )
                        .await,
                        ledger_canister_id: LEDGER_CANISTER_ID.into(),
                    };

                    let mut balance_at_block_index = HashMap::new();
                    let mut involved_accounts = HashSet::new();
                    let mut block_indices = HashSet::new();
                    for ArgWithCaller { caller, arg, .. } in args_with_caller {
                        let mut accounts = HashSet::new();
                        let block_index = match arg {
                            LedgerEndpointArg::TransferArg(transfer_arg) => {
                                accounts.insert(Account {
                                    owner: caller.sender().unwrap(),
                                    subaccount: transfer_arg.from_subaccount,
                                });
                                accounts.insert(transfer_arg.to);
                                icrc1_agent
                                    .transfer(transfer_arg.clone())
                                    .await
                                    .unwrap()
                                    .unwrap()
                            }
                            LedgerEndpointArg::ApproveArg(approve_arg) => {
                                accounts.insert(Account {
                                    owner: caller.sender().unwrap(),
                                    subaccount: approve_arg.from_subaccount,
                                });
                                accounts.insert(approve_arg.spender);
                                icrc1_agent
                                    .approve(approve_arg.clone())
                                    .await
                                    .unwrap()
                                    .unwrap()
                            }
                        };
                        for account_id in accounts.into_iter() {
                            let balance = icrc1_agent
                                .balance_of(account_id.clone(), CallMode::Query)
                                .await
                                .unwrap();
                            balance_at_block_index
                                .insert((account_id, block_index.clone()), balance);
                            involved_accounts.insert(account_id.clone());
                        }
                        block_indices.insert(block_index);
                    }
                    for block_index in block_indices.into_iter() {
                        for account in involved_accounts.into_iter() {
                            let balance_ledger = icrc1_agent
                                .balance_of(account.clone(), CallMode::Query)
                                .await
                                .unwrap();
                            let balance_rosetta: Nat = Nat::try_from(
                                rosetta_testing_environment
                                    .rosetta_client
                                    .account_balance(
                                        AccountBalanceRequest::builder(
                                            rosetta_testing_environment.network_identifier.clone(),
                                            account.into(),
                                        )
                                        .with_block_index(block_index)
                                        .build(),
                                    )
                                    .await
                                    .unwrap()
                                    .balances
                                    .first()
                                    .unwrap()
                                    .clone(),
                            )
                            .unwrap();
                            assert_eq!(balance_ledger, balance_rosetta);
                        }
                    }
                });
                Ok(())
            },
        )
        .unwrap();
}
