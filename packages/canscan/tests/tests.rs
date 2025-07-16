use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn should_succeed() {
    Command::cargo_bin("canscan")
        .unwrap()
        .args(&[
            "--wasm",
            "../target/wasm32-unknown-unknown/canister-release/test_canister.wasm",
            "--candid",
            "../test_canister/canister.did",
            "--hidden",
            "update:setApiKey",
        ])
        .assert()
        .success()
        .stdout(contains("Canister WASM and Candid interface match!"));
}

#[test]
fn should_fail_with_incorrect_path() {
    Command::cargo_bin("canscan")
        .unwrap()
        .args(&[
            "--wasm",
            "test_canister.wasm",
            "--candid",
            "../test_canister/canister.did",
            "--hidden",
            "query:setApiKey",
        ])
        .assert()
        .failure()
        .stderr(contains("Failed to parse WASM: No such file or directory"));
}

#[test]
fn should_fail_without_hidden_argument() {
    Command::cargo_bin("canscan")
        .unwrap()
        .args(&[
            "--wasm",
            "../target/wasm32-unknown-unknown/canister-release/test_canister.wasm",
            "--candid",
            "../test_canister/canister.did",
        ])
        .assert()
        .failure()
        .stderr(contains("ERROR: The following endpoint is unexpected in the WASM exports section: update:setApiKey"));
}

#[test]
fn should_fail_with_incorrect_hidden_argument() {
    Command::cargo_bin("canscan")
        .unwrap()
        .args(&[
            "--wasm",
            "../target/wasm32-unknown-unknown/canister-release/test_canister.wasm",
            "--candid",
            "../test_canister/canister.did",
            "--hidden",
            "query:setApiKey"
        ])
        .assert()
        .failure()
        .stderr(contains("ERROR: The following endpoint is unexpected in the WASM exports section: update:setApiKey"));
}
