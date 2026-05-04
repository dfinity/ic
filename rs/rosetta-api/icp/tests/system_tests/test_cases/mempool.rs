use crate::common::system_test_environment::RosettaTestingEnvironment;
use rosetta_core::identifiers::TransactionIdentifier;
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
            "Error does not contain expected message: {mempool_transaction:?}"
        );
    });
}
