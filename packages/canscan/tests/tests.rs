use assert_cmd::Command;
use predicates::str::contains;
use std::env;
use std::path::PathBuf;

#[test]
fn should_succeed() {
    Command::new(get_runfile_path("canscan"))
        .args([
            "--wasm",
            &get_runfile_path("test_canister/test_canister.wasm.gz"),
            "--candid",
            &get_runfile_path("test_canister/test_canister.did"),
            "--hidden",
            "update:setApiKey",
        ])
        .assert()
        .success()
        .stdout(contains("Canister WASM and Candid interface match!"));
}

#[test]
fn should_fail_with_incorrect_path() {
    Command::new(get_runfile_path("canscan"))
        .args([
            "--wasm",
            &get_runfile_path("test_canister/test_canister.wasm.gz"),
            "--candid",
            "test_canister/test_canister.did",
            "--hidden",
            "query:setApiKey",
        ])
        .assert()
        .failure()
        .stderr(contains("ERROR: Failed to parse Candid file: Cannot open"));
}

#[test]
fn should_fail_without_hidden_argument() {
    Command::new(get_runfile_path("canscan"))
        .args([
            "--wasm",
            &get_runfile_path("test_canister/test_canister.wasm.gz"),
            "--candid",
            &get_runfile_path("test_canister/test_canister.did"),
        ])
        .assert()
        .failure()
        .stderr(contains("ERROR: The following endpoint is unexpected in the WASM exports section: update:setApiKey"));
}

#[test]
fn should_fail_with_incorrect_hidden_argument() {
    Command::new(get_runfile_path("canscan"))
        .args([
            "--wasm",
            &get_runfile_path("test_canister/test_canister.wasm.gz"),
            "--candid",
            &get_runfile_path("test_canister/test_canister.did"),
            "--hidden",
            "query:setApiKey"
        ])
        .assert()
        .failure()
        .stderr(contains("ERROR: The following endpoint is unexpected in the WASM exports section: update:setApiKey"));
}

pub fn get_runfile_path(path: &str) -> String {
    [
        env::var("RUNFILES_DIR").unwrap().as_str(),
        "_main/packages/canscan/",
        path,
    ]
    .iter()
    .collect::<PathBuf>()
    .to_str()
    .unwrap()
    .to_string()
}
