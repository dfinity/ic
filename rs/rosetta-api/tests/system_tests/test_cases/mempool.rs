use crate::common::system_test_environment::RosettaTestingEnvironment;
use crate::common::utils::get_test_agent;
use crate::common::utils::query_blocks;
use crate::common::utils::test_identity;
use ic_agent::identity::BasicIdentity;
use ic_agent::Identity;
use ic_icrc1_test_utils::{minter_identity, valid_transactions_strategy, DEFAULT_TRANSFER_FEE};
use ic_ledger_core::block::BlockType;
use ic_rosetta_api::API_VERSION;
use ic_rosetta_api::NODE_VERSION;
use icrc_ledger_types::icrc1::account::Account;
use lazy_static::lazy_static;
use proptest::strategy::Strategy;
use proptest::test_runner::Config as TestRunnerConfig;
use proptest::test_runner::TestRunner;
use rosetta_core::identifiers::TransactionIdentifier;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::runtime::Runtime;

#[test]
fn test_mempool() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let rosetta_testing_environment = RosettaTestingEnvironment::builder().build().await;
        let mempool = rosetta_testing_environment
            .rosetta_client
            .mempool(rosetta_testing_environment.network_identifier.clone())
            .await
            .unwrap();

        assert!(mempool.transaction_identifiers.is_empty());
    });
}

#[test]
fn test_mempool_transaction() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let rosetta_testing_environment = RosettaTestingEnvironment::builder().build().await;
        let mempool_transaction = rosetta_testing_environment
            .rosetta_client
            .mempool_transaction(
                rosetta_testing_environment.network_identifier.clone(),
                TransactionIdentifier {
                    hash: "ARBITRARY TRANSACTION HASH".to_string(),
                },
            )
            .await
            .unwrap_err()
            .to_string();

        assert!(
            mempool_transaction
                .clone()
                .contains("Transaction not in the mempool"),
            "Error does not contain expected message: {:?}",
            mempool_transaction
        );
    });
}
