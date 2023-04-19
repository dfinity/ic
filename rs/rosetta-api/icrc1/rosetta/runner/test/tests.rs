use candid::Principal;
use ic_icrc_rosetta_runner::start_rosetta;
use ic_starter_tests::{start_replica, ReplicaBins, ReplicaStarterConfig};
use reqwest::StatusCode;
use std::path::PathBuf;

fn path_from_env(var: &str) -> PathBuf {
    std::fs::canonicalize(std::env::var(var).unwrap_or_else(|_| panic!("Unable to find {}", var)))
        .unwrap()
}

#[tokio::test]
async fn test() {
    let canister_launcher = path_from_env("CANISTER_LAUNCHER");
    let replica_bin = path_from_env("REPLICA_BIN");
    let sandbox_launcher = path_from_env("SANDBOX_LAUNCHER");
    let starter_bin = path_from_env("STARTER_BIN");
    let replica_bins = ReplicaBins {
        canister_launcher,
        replica_bin,
        sandbox_launcher,
        starter_bin,
    };
    let context = start_replica(&replica_bins, &ReplicaStarterConfig::default())
        .await
        .expect("Unable to start the replica");
    let replica_url = format!("http://localhost:{}", context.port);

    let rosetta_bin = path_from_env("ROSETTA_BIN_PATH");
    let context = start_rosetta(&rosetta_bin, Principal::anonymous(), replica_url).await;
    let res = reqwest::get(format!("http://localhost:{}/health", context.port))
        .await
        .expect("Unable to GET /health");
    assert_eq!(res.status(), StatusCode::OK);
}
