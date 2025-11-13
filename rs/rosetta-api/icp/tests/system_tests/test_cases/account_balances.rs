use crate::common::system_test_environment::RosettaTestingEnvironment;
use crate::common::utils::get_custom_agent;
use crate::common::utils::get_test_agent;
use crate::common::utils::test_identity;
use crate::common::utils::wait_for_rosetta_to_sync_up_to_block;
use candid::Nat;
use ic_agent::Identity;
use ic_agent::identity::BasicIdentity;
use ic_icrc1_test_utils::ArgWithCaller;
use ic_icrc1_test_utils::LedgerEndpointArg;
use ic_icrc1_test_utils::{DEFAULT_TRANSFER_FEE, minter_identity, valid_transactions_strategy};
use ic_nns_constants::LEDGER_CANISTER_ID;
use ic_rosetta_api::models::AccountBalanceRequest;
use icrc_ledger_agent::CallMode;
use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::icrc1::account::Account;
use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use num_traits::Zero;
use proptest::strategy::Strategy;
use proptest::test_runner::Config as TestRunnerConfig;
use proptest::test_runner::TestRunner;
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

                    let mut account_balance_at_block_idx = HashMap::new();
                    let mut involved_accounts = HashSet::new();
                    let mut block_indices = HashSet::new();
                    let replica_port = rosetta_testing_environment
                        .pocket_ic
                        .url()
                        .unwrap()
                        .port()
                        .unwrap();
                    let agent = Icrc1Agent {
                        agent: get_test_agent(replica_port).await,
                        ledger_canister_id: LEDGER_CANISTER_ID.into(),
                    };
                    for ArgWithCaller { caller, arg, .. } in args_with_caller {
                        let caller_agent = Icrc1Agent {
                            agent: get_custom_agent(caller.clone(), replica_port).await,
                            ledger_canister_id: LEDGER_CANISTER_ID.into(),
                        };
                        let (block_idx, account1, account2) = match arg {
                            LedgerEndpointArg::ApproveArg(approve_arg) => {
                                let block_idx = caller_agent
                                    .approve(approve_arg.clone())
                                    .await
                                    .unwrap()
                                    .unwrap()
                                    .0
                                    .to_u64()
                                    .unwrap();
                                let from_account = Account {
                                    owner: caller.clone().sender().unwrap(),
                                    subaccount: approve_arg.from_subaccount,
                                };
                                (block_idx, from_account, approve_arg.spender)
                            }
                            LedgerEndpointArg::TransferArg(transfer_arg) => {
                                let block_idx = caller_agent
                                    .transfer(transfer_arg.clone())
                                    .await
                                    .unwrap()
                                    .unwrap()
                                    .0
                                    .to_u64()
                                    .unwrap();
                                let from_account = Account {
                                    owner: caller.clone().sender().unwrap(),
                                    subaccount: transfer_arg.from_subaccount,
                                };
                                (block_idx, from_account, transfer_arg.to)
                            }
                            LedgerEndpointArg::TransferFromArg(transfer_from_arg) => {
                                let block_idx = caller_agent
                                    .transfer_from(transfer_from_arg.clone())
                                    .await
                                    .unwrap()
                                    .unwrap()
                                    .0
                                    .to_u64()
                                    .unwrap();
                                (block_idx, transfer_from_arg.from, transfer_from_arg.to)
                            }
                        };

                        // Store the current balance of the involved accounts and add them to the list of accounts if not already present
                        let balance_acc1 = caller_agent
                            .balance_of(account1, CallMode::Query)
                            .await
                            .unwrap();
                        let balance_acc2 = caller_agent
                            .balance_of(account2, CallMode::Query)
                            .await
                            .unwrap();
                        account_balance_at_block_idx.insert((account1, block_idx), balance_acc1);
                        account_balance_at_block_idx.insert((account2, block_idx), balance_acc2);
                        involved_accounts.insert(account1);
                        involved_accounts.insert(account2);
                        block_indices.insert(block_idx);
                    }

                    let mut current_balances = HashMap::new();
                    for account in involved_accounts.clone().into_iter() {
                        current_balances.insert(account, Nat(BigUint::zero()));
                    }

                    let mut block_indices_iter = block_indices.into_iter().collect::<Vec<u64>>();
                    block_indices_iter.sort();

                    wait_for_rosetta_to_sync_up_to_block(
                        &rosetta_testing_environment.rosetta_client,
                        rosetta_testing_environment.network_identifier.clone(),
                        *block_indices_iter.iter().last().unwrap(),
                    )
                    .await
                    .unwrap();

                    // Iterate over every account at every block index and make sure the balances of the ledger match the balances of the rosetta storage
                    for idx in block_indices_iter.into_iter() {
                        for account in involved_accounts.clone().into_iter() {
                            account_balance_at_block_idx
                                .contains_key(&(account, idx))
                                .then(|| {
                                    current_balances.entry(account).and_modify(|balance| {
                                        *balance = account_balance_at_block_idx
                                            .get(&(account, idx))
                                            .unwrap()
                                            .clone()
                                    })
                                });
                            let account_id: icp_ledger::AccountIdentifier = account.into();
                            assert_eq!(
                                current_balances
                                    .get(&account)
                                    .unwrap()
                                    .0
                                    .to_u64()
                                    .unwrap()
                                    .to_string(),
                                rosetta_testing_environment
                                    .rosetta_client
                                    .account_balance(
                                        AccountBalanceRequest::builder(
                                            rosetta_testing_environment.network_identifier.clone(),
                                            account_id.into()
                                        )
                                        .with_block_index(idx)
                                        .build()
                                    )
                                    .await
                                    .unwrap()
                                    .balances[0]
                                    .clone()
                                    .value
                            );
                        }
                    }

                    // Check that the current balances of the ledger and rosetta storage match up
                    for account in involved_accounts.into_iter() {
                        let balance_ledger = agent
                            .balance_of(account, CallMode::Query)
                            .await
                            .unwrap()
                            .0
                            .to_u64()
                            .unwrap()
                            .to_string();
                        let account_id: icp_ledger::AccountIdentifier = account.into();
                        let balance_rosetta = rosetta_testing_environment
                            .rosetta_client
                            .account_balance(
                                AccountBalanceRequest::builder(
                                    rosetta_testing_environment.network_identifier.clone(),
                                    account_id.into(),
                                )
                                .build(),
                            )
                            .await
                            .unwrap()
                            .balances[0]
                            .clone()
                            .value;
                        assert_eq!(balance_ledger, balance_rosetta);
                    }
                });
                Ok(())
            },
        )
        .unwrap();
}
