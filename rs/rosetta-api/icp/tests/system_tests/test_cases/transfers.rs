use crate::common::system_test_environment::RosettaTestingEnvironment;
use crate::common::utils::assert_rosetta_blockchain_is_valid;
use crate::common::utils::get_test_agent;
use crate::common::utils::test_identity;
use crate::common::utils::wait_for_rosetta_to_sync_up_to_block;
use ic_agent::Identity;
use ic_agent::identity::BasicIdentity;
use ic_icrc1_test_utils::LedgerEndpointArg;
use ic_icrc1_test_utils::{
    DEFAULT_TRANSFER_FEE, TransactionTypes, minter_identity,
    valid_transactions_strategy_with_excluded_transaction_types,
};
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
            &(valid_transactions_strategy_with_excluded_transaction_types(
                MINTING_IDENTITY.clone(),
                DEFAULT_TRANSFER_FEE,
                *MAX_NUM_GENERATED_BLOCKS,
                SystemTime::now(),
                vec![TransactionTypes::TransferFrom, TransactionTypes::Approve],
            ),)
                .no_shrink(),
            |(args_with_caller,)| {
                for arg_with_caller in args_with_caller.iter() {
                    assert!(
                        matches!(arg_with_caller.arg, LedgerEndpointArg::TransferArg(_)),
                        "Strategy should only generate transactions with TransferArg, but got: {arg_with_caller:?}"
                    );
                }
                let rt = Runtime::new().unwrap();
                rt.block_on(async {
                    let rosetta_testing_environment = RosettaTestingEnvironment::builder()
                        .with_minting_account(MINTING_IDENTITY.sender().unwrap().into())
                        .build()
                        .await;

                    rosetta_testing_environment
                        .generate_blocks(args_with_caller.clone())
                        .await;

                    wait_for_rosetta_to_sync_up_to_block(
                        &rosetta_testing_environment.rosetta_client,
                        rosetta_testing_environment.network_identifier.clone(),
                        args_with_caller.len() as u64,
                    )
                    .await
                    .unwrap();
                    // Let's check that rosetta has a valid blockchain when compared to the ledger
                    assert_rosetta_blockchain_is_valid(
                        &rosetta_testing_environment.rosetta_client,
                        rosetta_testing_environment.network_identifier.clone(),
                        &get_test_agent(
                            rosetta_testing_environment
                                .pocket_ic
                                .url()
                                .unwrap()
                                .port()
                                .unwrap(),
                        )
                        .await,
                    )
                    .await;
                });
                Ok(())
            },
        )
        .unwrap();
}
