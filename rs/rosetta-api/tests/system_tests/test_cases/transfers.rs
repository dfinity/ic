use crate::common::system_test_environment::RosettaTestingEnvironment;
use crate::common::utils::bytebuf_to_u64;
use crate::common::utils::get_custom_agent;
use crate::common::utils::test_identity;
use ic_agent::identity::BasicIdentity;
use ic_agent::Identity;
use ic_icrc1_test_utils::{minter_identity, valid_transactions_strategy, DEFAULT_TRANSFER_FEE};
use ic_icrc1_test_utils::{ArgWithCaller, LedgerEndpointArg};
use ic_icrc1_tokens_u256::U256;
use ic_nns_constants::LEDGER_CANISTER_ID;
use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::icrc1::account::Account;
use lazy_static::lazy_static;
use proptest::strategy::Strategy;
use proptest::test_runner::Config as TestRunnerConfig;
use proptest::test_runner::TestRunner;
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
fn test_icp_transfer() {
    let mut runner = TestRunner::new(TestRunnerConfig {
        max_shrink_iters: 0,
        cases: *NUM_TEST_CASES,
        ..Default::default()
    });

    runner
        .run(
            &(valid_transactions_strategy(
                MINTING_IDENTITY.clone(),
                DEFAULT_TRANSFER_FEE,
                *MAX_NUM_GENERATED_BLOCKS,
                SystemTime::now(),
            ),)
                .prop_filter_map("Only transfer transactions", |(args_with_caller,)| {
                    let filtered_args_with_caller: Vec<ArgWithCaller> = args_with_caller
                        .into_iter()
                        .filter(|arg_with_caller| {
                            matches!(arg_with_caller.arg, LedgerEndpointArg::TransferArg(_))
                        })
                        .collect();
                    if filtered_args_with_caller.is_empty() {
                        None
                    } else {
                        Some((filtered_args_with_caller,))
                    }
                })
                .no_shrink(),
            |(args_with_caller,)| {
                let rt = Runtime::new().unwrap();
                rt.block_on(async {
                    let rosetta_testing_environment = RosettaTestingEnvironment::builder()
                        .with_minting_account(MINTING_IDENTITY.sender().unwrap().into())
                        .build()
                        .await;

                    for arg_with_caller in args_with_caller.into_iter() {
                        let icrc1_transaction: ic_icrc1::Transaction<U256> = arg_with_caller
                            .to_transaction(Account::from(MINTING_IDENTITY.sender().unwrap()));

                        // Rosetta does not support mint and burn operations
                        // To keep the balances in sync we need to call the ledger agent directly and then go to the next iteration of args with caller
                        if matches!(
                            icrc1_transaction.operation,
                            ic_icrc1::Operation::Mint { .. }
                        ) || matches!(
                            icrc1_transaction.operation,
                            ic_icrc1::Operation::Burn { .. }
                        ) {
                            let caller_agent = Icrc1Agent {
                                agent: get_custom_agent(
                                    arg_with_caller.caller.clone(),
                                    rosetta_testing_environment
                                        ._pocket_ic
                                        .url()
                                        .unwrap()
                                        .port()
                                        .unwrap(),
                                )
                                .await,
                                ledger_canister_id: LEDGER_CANISTER_ID.into(),
                            };
                            match arg_with_caller.arg {
                                LedgerEndpointArg::TransferArg(mut transfer_arg) => {
                                    // ICP Rosetta cannot handle subaccounts, so we have to eliminate them
                                    transfer_arg.from_subaccount = None;
                                    transfer_arg.to.subaccount = None;
                                    caller_agent
                                        .transfer(transfer_arg.clone())
                                        .await
                                        .unwrap()
                                        .unwrap()
                                }
                                _ => panic!("Expected TransferArg for Mint and Burns"),
                            };
                            continue;
                        }

                        let transfer_args = match arg_with_caller.arg {
                            LedgerEndpointArg::TransferArg(mut transfer_args) => {
                                transfer_args.from_subaccount = None;
                                transfer_args.to.subaccount = None;
                                transfer_args
                            }
                            _ => panic!("Expected TransferArg"),
                        };

                        let transfer_operations = rosetta_testing_environment
                            .rosetta_client
                            .build_transfer_operations(
                                arg_with_caller.caller.sender().unwrap(),
                                transfer_args.from_subaccount,
                                transfer_args.to,
                                transfer_args.amount,
                                rosetta_testing_environment.network_identifier.clone(),
                            )
                            .await
                            .unwrap();

                        // This submit wrapper will also wait for the transaction to be finalized
                        rosetta_testing_environment
                            .rosetta_client
                            .make_submit_and_wait_for_transaction(
                                &arg_with_caller.caller,
                                rosetta_testing_environment.network_identifier.clone(),
                                transfer_operations,
                                // We don't care about the specific memo, only that there exists a memo
                                transfer_args
                                    .memo
                                    .map(|memo| bytebuf_to_u64(memo.0.as_slice()).unwrap_or(0)),
                                transfer_args.created_at_time,
                            )
                            .await
                            .unwrap();
                    }
                });
                Ok(())
            },
        )
        .unwrap();
}
