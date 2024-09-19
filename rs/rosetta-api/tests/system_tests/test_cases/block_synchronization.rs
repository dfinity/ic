use crate::common::system_test_environment::RosettaTestingEnvironment;
use crate::common::utils::assert_rosetta_blockchain_is_valid;
use crate::common::utils::get_test_agent;
use crate::common::utils::test_identity;
use crate::common::utils::wait_for_rosetta_to_sync_up_to_block;
use candid::Encode;
use candid::Principal;
use ic_agent::identity::BasicIdentity;
use ic_agent::Identity;
use ic_icp_rosetta_runner::RosettaOptions;
use ic_icrc1_test_utils::{minter_identity, valid_transactions_strategy, DEFAULT_TRANSFER_FEE};
use ic_nns_constants::LEDGER_CANISTER_ID;
use icp_ledger::LedgerCanisterPayload;
use icp_ledger::LedgerCanisterUpgradePayload;
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
fn test_block_synchronization() {
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
fn test_ledger_upgrade_synchronization() {
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
                *MAX_NUM_GENERATED_BLOCKS * 2,
                SystemTime::now(),
            )
            .no_shrink()),
            |args_with_caller| {
                let rt = Runtime::new().unwrap();
                rt.block_on(async {
                    let mut env = RosettaTestingEnvironment::builder()
                        .with_minting_account(MINTING_IDENTITY.sender().unwrap().into())
                        .build()
                        .await;

                    // Currently, the ledger canister version is that of this branch
                    // We need to reinstall it to the mainnet version
                    let ledger_canister_id = Principal::from(LEDGER_CANISTER_ID);

                    let ledger_wasm_mainnet = std::fs::read(
                        std::env::var("ICP_LEDGER_DEPLOYED_VERSION_WASM_PATH").unwrap(),
                    )
                    .unwrap();
                    env.pocket_ic
                        .reinstall_canister(
                            ledger_canister_id,
                            ledger_wasm_mainnet,
                            Encode!(&icp_ledger::LedgerCanisterInitPayload::builder()
                                .minting_account(MINTING_IDENTITY.sender().unwrap().into())
                                // We need some initial values otherwise the install fails
                                .initial_values(
                                    [(
                                        icp_ledger::AccountIdentifier::new(
                                            test_identity().sender().unwrap().into(),
                                            None
                                        ),
                                        icp_ledger::Tokens::from_tokens(1_000_000_000).unwrap(),
                                    )]
                                    .into()
                                )
                                .build()
                                .unwrap())
                            .unwrap(),
                            None,
                        )
                        .await
                        .unwrap();

                    wait_for_rosetta_to_sync_up_to_block(
                        &env.rosetta_client,
                        env.network_identifier.clone(),
                        0,
                    )
                    .await
                    .unwrap();

                    let pockt_ic_url = env.pocket_ic.url().unwrap();

                    // Let's restart rosetta to make sure it can handle the mainnet ledger version
                    env = env
                        .restart_rosetta_node(
                            RosettaOptions::builder(pockt_ic_url.to_string()).build(),
                        )
                        .await;

                    // We split up the transactions into two batches to make sure we have a valid blockchain
                    let (first_block_batch, second_block_batch) =
                        args_with_caller.split_at(args_with_caller.len() / 2);

                    // Let's create a few transactions to make sure rosetta is working with the mainnet ledger version
                    env.generate_blocks(first_block_batch.to_owned()).await;

                    wait_for_rosetta_to_sync_up_to_block(
                        &env.rosetta_client,
                        env.network_identifier.clone(),
                        first_block_batch.len() as u64,
                    )
                    .await
                    .unwrap();

                    // Let's check that rosetta has a valid blockchain when compared to the ledger
                    assert_rosetta_blockchain_is_valid(
                        &env.rosetta_client,
                        env.network_identifier.clone(),
                        &get_test_agent(env.pocket_ic.url().unwrap().port().unwrap()).await,
                    )
                    .await;

                    // Now we upgrade the ledger canister to the latest version of the current branch
                    let ledger_wasm_current_branch = std::fs::read(
                        std::env::var("LEDGER_CANISTER_NOTIFY_METHOD_WASM_PATH").unwrap(),
                    )
                    .unwrap();
                    env.pocket_ic
                        .upgrade_canister(
                            ledger_canister_id,
                            ledger_wasm_current_branch,
                            Encode!(&LedgerCanisterUpgradePayload(
                                LedgerCanisterPayload::Upgrade(None)
                            ))
                            .unwrap(),
                            None,
                        )
                        .await
                        .unwrap();

                    // Let's create a few transactions on the new ledger version
                    env.generate_blocks(second_block_batch.to_owned()).await;

                    wait_for_rosetta_to_sync_up_to_block(
                        &env.rosetta_client,
                        env.network_identifier.clone(),
                        args_with_caller.len() as u64,
                    )
                    .await
                    .unwrap();

                    // Let's check that rosetta has a valid blockchain when compared to the ledger
                    assert_rosetta_blockchain_is_valid(
                        &env.rosetta_client,
                        env.network_identifier.clone(),
                        &get_test_agent(env.pocket_ic.url().unwrap().port().unwrap()).await,
                    )
                    .await;
                });

                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn test_load_from_storage() {
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
                *MAX_NUM_GENERATED_BLOCKS * 2,
                SystemTime::now(),
            )
            .no_shrink()),
            |args_with_caller| {
                let rt = Runtime::new().unwrap();
                rt.block_on(async {
                    let mut env = RosettaTestingEnvironment::builder()
                        .with_minting_account(MINTING_IDENTITY.sender().unwrap().into())
                        .with_persistent_storage(true)
                        .build()
                        .await;
                    let replica_url = env.pocket_ic.url();
                    env = env.restart_rosetta_node(
                        RosettaOptions::builder(replica_url.clone().unwrap().to_string())
                            .with_persistent_storage()
                            .offline()
                            .build(),
                    )
                    .await;

                    wait_for_rosetta_to_sync_up_to_block(
                        &env.rosetta_client,
                        env.network_identifier.clone(),
                        args_with_caller.len() as u64,
                    )
                    .await
                    .unwrap();

                    assert_rosetta_blockchain_is_valid(
                        &env.rosetta_client,
                        env.network_identifier.clone(),
                        &get_test_agent(replica_url.clone().unwrap().port().unwrap()).await,
                    ).await
                });

                Ok(())
            },
        )
        .unwrap();
}
