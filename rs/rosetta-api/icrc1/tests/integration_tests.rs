pub mod common;
pub mod integration_test_components;

use std::path::PathBuf;
use std::process::Command;

fn get_rosetta_path() -> PathBuf {
    std::fs::canonicalize(
        std::env::var("ROSETTA_BIN_PATH").unwrap_or_else(|_| panic!("Environment variable ROSETTA_BIN_PATH is not set")),
    )
    .unwrap()
}

#[test]
fn test_environment_and_network_type_flags_conflict() {
    let output = Command::new(get_rosetta_path())
        .args(["--environment", "production", "--network-type", "mainnet"])
        .output()
        .expect("Failed to execute binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Cannot specify both --network-type and --environment flags"));
}
