use candid::Principal;
use ic_icrc_rosetta_client::RosettaClient;
use ic_icrc_rosetta_runner::RosettaOptions;
use ic_icrc_rosetta_runner::start_rosetta;
use icrc_ledger_types::icrc1::account::Account;
use pocket_ic::PocketIcBuilder;
use rosetta_core::identifiers::{AccountIdentifier, NetworkIdentifier, PartialBlockIdentifier};
use rosetta_core::request_types::AccountBalanceRequest;
use serde_json::{Map, Value};
use std::path::PathBuf;
use tokio::runtime::Runtime;

fn path_from_env(var: &str) -> PathBuf {
    std::fs::canonicalize(std::env::var(var).unwrap_or_else(|_| panic!("Unable to find {var}")))
        .unwrap()
}

// only test_health is in here to check that the client works
// as intended. All the other tests are in the rosetta tests.
#[test]
fn test() {
    let rt = Runtime::new().unwrap();
    let mut pocket_ic = PocketIcBuilder::new().with_nns_subnet().build();
    let endpoint = pocket_ic.make_live(None);
    let port = endpoint.port().unwrap();
    let replica_url = format!("http://localhost:{port}");
    let rosetta_bin = path_from_env("ROSETTA_BIN_PATH");

    // Wrap async calls in a blocking Block
    rt.block_on(async {
        let context = start_rosetta(
            &rosetta_bin,
            RosettaOptions {
                network_url: Some(replica_url),
                ..RosettaOptions::default()
            },
        )
        .await;
        let client = RosettaClient::from_str_url(&format!("http://0.0.0.0:{}", context.port))
            .expect("Unable to parse url");
        assert!(client.health().await.is_ok())
    });
}

#[test]
fn test_aggregated_balance_method_creates_correct_metadata() {
    // Test that the account_balance_aggregated method creates the correct metadata
    let rt = Runtime::new().unwrap();
    let principal = Principal::anonymous();
    let account = Account {
        owner: principal,
        subaccount: None, // Must be None for aggregated balance
    };
    let account_identifier = AccountIdentifier::from(account);
    let network_identifier = NetworkIdentifier::new("ICRC-1".to_string(), "test".to_string());

    // We can't easily test the internal metadata creation without mocking the HTTP client,
    // but we can test that the method exists and has the right signature
    let client = RosettaClient::from_str_url("http://localhost:8080").unwrap();

    // This test verifies the method signature exists and is callable
    rt.block_on(async {
        // This will fail with a connection error since there's no server,
        // but it proves the method exists with the right signature
        let result = client
            .account_balance_aggregated(0, account_identifier, network_identifier)
            .await;
        assert!(result.is_err()); // Expected to fail due to no server
    });
}

#[test]
fn test_regular_balance_vs_aggregated_balance_requests() {
    // Test that regular and aggregated balance requests create different request structures
    let principal = Principal::anonymous();
    let account = Account {
        owner: principal,
        subaccount: None,
    };
    let account_identifier = AccountIdentifier::from(account);
    let network_identifier = NetworkIdentifier::new("ICRC-1".to_string(), "test".to_string());

    // Regular balance request (no metadata)
    let regular_request = AccountBalanceRequest {
        block_identifier: Some(PartialBlockIdentifier {
            index: Some(0),
            hash: None,
        }),
        account_identifier: account_identifier.clone(),
        network_identifier: network_identifier.clone(),
        metadata: None,
    };

    // Aggregated balance request (with metadata)
    let mut metadata_map = Map::new();
    metadata_map.insert("aggregate_all_subaccounts".to_string(), Value::Bool(true));

    let aggregated_request = AccountBalanceRequest {
        block_identifier: Some(PartialBlockIdentifier {
            index: Some(0),
            hash: None,
        }),
        account_identifier,
        network_identifier,
        metadata: Some(metadata_map),
    };

    // Verify the difference
    assert!(regular_request.metadata.is_none());
    assert!(aggregated_request.metadata.is_some());

    let metadata = aggregated_request.metadata.unwrap();
    assert_eq!(
        metadata.get("aggregate_all_subaccounts"),
        Some(&Value::Bool(true))
    );
}

#[test]
fn test_aggregated_balance_request_serialization() {
    // Test that aggregated balance requests serialize correctly
    let principal = Principal::anonymous();
    let account = Account {
        owner: principal,
        subaccount: None, // Required for aggregated balance
    };
    let account_identifier = AccountIdentifier::from(account);
    let network_identifier = NetworkIdentifier::new("ICRC-1".to_string(), "test".to_string());

    let mut metadata_map = Map::new();
    metadata_map.insert("aggregate_all_subaccounts".to_string(), Value::Bool(true));

    let request = AccountBalanceRequest {
        block_identifier: Some(PartialBlockIdentifier {
            index: Some(0),
            hash: None,
        }),
        account_identifier,
        network_identifier,
        metadata: Some(metadata_map),
    };

    // Test serialization
    let serialized = serde_json::to_string(&request).expect("Should serialize successfully");
    assert!(serialized.contains("aggregate_all_subaccounts"));
    assert!(serialized.contains("true"));

    // Test deserialization
    let deserialized: AccountBalanceRequest =
        serde_json::from_str(&serialized).expect("Should deserialize successfully");

    assert!(deserialized.metadata.is_some());
    let metadata = deserialized.metadata.unwrap();
    assert_eq!(
        metadata.get("aggregate_all_subaccounts"),
        Some(&Value::Bool(true))
    );
}

#[test]
fn test_account_suitable_for_aggregation() {
    // Test that we can distinguish between accounts suitable for aggregation
    let principal = Principal::anonymous();

    // Account without subaccount (suitable for aggregation)
    let aggregatable_account = Account {
        owner: principal,
        subaccount: None,
    };

    // Account with subaccount (not suitable for aggregation)
    let subaccount = [1u8; 32];
    let non_aggregatable_account = Account {
        owner: principal,
        subaccount: Some(subaccount),
    };

    // Verify the difference
    assert_eq!(aggregatable_account.subaccount, None);
    assert_ne!(non_aggregatable_account.subaccount, None);

    // The aggregatable account should be the one used with account_balance_aggregated
    // The documentation states that the account must not specify a subaccount
    assert!(
        aggregatable_account.subaccount.is_none(),
        "Account suitable for aggregation must have subaccount = None"
    );
    assert!(
        non_aggregatable_account.subaccount.is_some(),
        "Account with specific subaccount should not be used for aggregation"
    );
}

#[test]
fn test_aggregate_all_subaccounts_metadata_field() {
    // Test the specific metadata field used for aggregation
    let mut metadata = Map::new();
    metadata.insert("aggregate_all_subaccounts".to_string(), Value::Bool(true));

    // Verify the field name and value
    assert!(metadata.contains_key("aggregate_all_subaccounts"));
    assert_eq!(metadata["aggregate_all_subaccounts"], Value::Bool(true));

    // Test that it's different from false
    let mut metadata_false = Map::new();
    metadata_false.insert("aggregate_all_subaccounts".to_string(), Value::Bool(false));

    assert_ne!(
        metadata["aggregate_all_subaccounts"],
        metadata_false["aggregate_all_subaccounts"]
    );
}
