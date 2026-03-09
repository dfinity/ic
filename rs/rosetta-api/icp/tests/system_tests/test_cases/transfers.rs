use crate::common::system_test_environment::RosettaTestingEnvironment;
use crate::common::utils::assert_rosetta_blockchain_is_valid;
use crate::common::utils::get_test_agent;
use crate::common::utils::test_identity;
use crate::common::utils::wait_for_rosetta_to_sync_up_to_block;
use candid::Nat;
use ic_agent::Identity;
use ic_agent::identity::BasicIdentity;
use ic_icp_rosetta_client::RosettaTransferArgs;
use ic_icrc1_test_utils::{
    DEFAULT_TRANSFER_FEE, TransactionTypes, minter_identity,
    valid_transactions_strategy_with_options,
};
use ic_icrc1_test_utils::{LedgerEndpointArg, TransactionStrategyOptions};
use icrc_ledger_types::icrc1::account::Account;
use lazy_static::lazy_static;
use proptest::strategy::Strategy;
use proptest::test_runner::Config as TestRunnerConfig;
use proptest::test_runner::TestRunner;
use std::sync::Arc;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
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
            &(valid_transactions_strategy_with_options(
                MINTING_IDENTITY.clone(),
                DEFAULT_TRANSFER_FEE,
                *MAX_NUM_GENERATED_BLOCKS,
                SystemTime::now(),
                TransactionStrategyOptions{
                    excluded_transaction_types: vec![
                        TransactionTypes::TransferFrom,
                        TransactionTypes::Approve
                    ],
                    require_created_at_time: true,
                    require_memo: true
                },
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

#[test]
fn test_duplicate_transfer_is_rejected() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let env = RosettaTestingEnvironment::builder()
            .with_minting_account(MINTING_IDENTITY.sender().unwrap().into())
            .build()
            .await;

        let caller = Arc::new(test_identity());
        // Transfer to a different (non-minter) account
        let to = Account {
            owner: candid::Principal::anonymous(),
            subaccount: None,
        };
        let amount = Nat::from(100_000u64);
        let created_at_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let memo = 12345u64;

        let transfer_args = RosettaTransferArgs::builder(to, amount)
            .with_memo(memo)
            .with_created_at_time(created_at_time)
            .build();

        // First transfer should succeed
        let first_response = env
            .rosetta_client
            .transfer(
                transfer_args.clone(),
                env.network_identifier.clone(),
                &caller,
            )
            .await;
        assert!(
            first_response.is_ok(),
            "First transfer should succeed, got: {first_response:?}"
        );

        // Second transfer with same args (same dedup key) should be rejected
        let second_response = env
            .rosetta_client
            .transfer(transfer_args, env.network_identifier.clone(), &caller)
            .await;
        let err =
            second_response.expect_err("Second transfer with same dedup key should be rejected");
        let err_msg = format!("{err:?}");
        eprintln!("Duplicate transfer error: {err_msg}");
        assert!(
            err_msg.contains("transaction is a duplicate of another transaction"),
            "Expected a duplicate transaction error, got: {err_msg}"
        );
    });
}
