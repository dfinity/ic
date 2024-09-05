use crate::common::system_test_environment::RosettaTestingEnvironment;
use crate::common::utils::get_custom_agent;
use crate::common::utils::memo_bytebuf_to_u64;
use crate::common::utils::test_identity;
use ic_agent::identity::BasicIdentity;
use ic_agent::Identity;
use ic_icp_rosetta_client::RosettaTransferArgs;
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
                            rosetta_testing_environment
                                .generate_blocks(vec![arg_with_caller])
                                .await;
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
                        let mut args_builder =
                            RosettaTransferArgs::builder(transfer_args.to, transfer_args.amount);
                        if let Some(from_subaccount) = transfer_args.from_subaccount {
                            args_builder = args_builder.with_from_subaccount(from_subaccount);
                        }
                        if let Some(memo) = transfer_args.memo {
                            args_builder =
                                args_builder.with_memo(memo_bytebuf_to_u64(&memo.0).unwrap());
                        }
                        if let Some(created_at_time) = transfer_args.created_at_time {
                            args_builder = args_builder.with_created_at_time(created_at_time);
                        }

                        rosetta_testing_environment
                            .rosetta_client
                            .transfer(
                                args_builder.build(),
                                rosetta_testing_environment.network_identifier.clone(),
                                arg_with_caller.caller,
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
