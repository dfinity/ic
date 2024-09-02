use crate::common::system_test_environment::RosettaTestingEnvironment;
use crate::common::utils::test_identity;
use ic_agent::identity::BasicIdentity;
use ic_agent::Identity;
use ic_icrc1_test_utils::{minter_identity, valid_transactions_strategy, DEFAULT_TRANSFER_FEE};
use icrc_ledger_types::icrc1::account::Account;
use lazy_static::lazy_static;
use proptest::strategy::Strategy;
use proptest::test_runner::Config as TestRunnerConfig;
use proptest::test_runner::TestRunner;
use rosetta_core::identifiers::TransactionIdentifier;
use rosetta_core::request_types::SearchTransactionsRequest;
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
fn test_search_transactions_by_hash() {
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
                        .with_transfer_args_for_block_generating(args_with_caller.clone())
                        .with_minting_account(MINTING_IDENTITY.sender().unwrap().into())
                        .build()
                        .await;
                    let tip_block_indentifier = rosetta_testing_environment
                        .rosetta_client
                        .network_status(rosetta_testing_environment.network_identifier.clone())
                        .await
                        .unwrap()
                        .current_block_identifier;

                    let tip_block = rosetta_testing_environment
                        .rosetta_client
                        .block(
                            rosetta_testing_environment.network_identifier.clone(),
                            tip_block_indentifier.clone().into(),
                        )
                        .await
                        .unwrap()
                        .block
                        .unwrap();
                    let tx_hash = tip_block.transactions[0]
                        .transaction_identifier
                        .hash
                        .clone();

                    let transaction = rosetta_testing_environment
                        .rosetta_client
                        .search_transactions(
                            &SearchTransactionsRequest::builder(
                                rosetta_testing_environment.network_identifier.clone(),
                            )
                            .with_transaction_identifier(TransactionIdentifier { hash: tx_hash })
                            .build(),
                        )
                        .await
                        .unwrap();

                    assert_eq!(
                        transaction.transactions[0].block_identifier,
                        tip_block_indentifier
                    );
                });
                Ok(())
            },
        )
        .unwrap();
}
