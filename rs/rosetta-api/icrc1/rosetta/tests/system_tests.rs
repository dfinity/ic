use candid::Principal;
use ic_base_types::CanisterId;
use ic_icrc_rosetta::common::types::NetworkIdentifier;
use ic_icrc_rosetta_client::RosettaClient;
use ic_icrc_rosetta_runner::{start_rosetta, RosettaOptions};
use ic_starter_tests::{start_replica, ReplicaBins, ReplicaStarterConfig};
use std::path::PathBuf;

fn path_from_env(var: &str) -> PathBuf {
    std::fs::canonicalize(
        std::env::var(var).unwrap_or_else(|_| panic!("Environment variable {} is not set", var)),
    )
    .unwrap()
}

fn replica_bins() -> ReplicaBins {
    let canister_launcher = path_from_env("CANISTER_LAUNCHER");
    let replica_bin = path_from_env("REPLICA_BIN");
    let sandbox_launcher = path_from_env("SANDBOX_LAUNCHER");
    let starter_bin = path_from_env("STARTER_BIN");
    ReplicaBins {
        canister_launcher,
        replica_bin,
        sandbox_launcher,
        starter_bin,
    }
}

fn rosetta_bin() -> PathBuf {
    path_from_env("ROSETTA_BIN_PATH")
}

#[tokio::test]
async fn test_network_list() {
    let context = start_replica(&replica_bins(), &ReplicaStarterConfig::default())
        .await
        .expect("Unable to start the replica");
    let replica_url = format!("http://localhost:{}", context.port);

    let context = start_rosetta(
        &rosetta_bin(),
        RosettaOptions {
            network_url: Some(replica_url),
            ..RosettaOptions::default()
        },
    )
    .await;
    let client = RosettaClient::from_str_url(&format!("http://0.0.0.0:{}", context.port))
        .expect("Unable to parse url");
    let network_list = client
        .network_list()
        .await
        .expect("Unable to call network_list")
        .network_identifiers;
    let expected = NetworkIdentifier::for_ledger_id(
        CanisterId::try_from(Principal::anonymous().as_slice()).unwrap(),
    );
    assert_eq!(network_list, vec![expected]);
}
