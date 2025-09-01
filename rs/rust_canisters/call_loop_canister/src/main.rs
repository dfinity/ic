#![allow(deprecated)]
use ic_cdk::{api::call, update};
use ic_principal::Principal;

const MB: usize = 1024 * 1024;

/// Takes the total number of bytes to send in a single message (in megabytes).
#[update]
async fn send_calls(megabytes_to_send: u32) {
    let calls = (0..megabytes_to_send)
        .map(|i| {
            let mut slice = [0; 29];
            slice[..4].copy_from_slice(&i.to_le_bytes());
            let canister = Principal::from_slice(&slice);
            call::call_raw(canister, "", &[5; MB], 0)
        })
        .collect::<Vec<_>>();
    let _ = futures::future::join_all(calls).await;
}

// When run on native this prints the candid service definition of this
// canister, from the methods annotated with `candid_method` above.
//
// Note that `cargo test` calls `main`, and `export_service` (which defines
// `__export_service` in the current scope) needs to be called exactly once. So
// in addition to `not(target_family = "wasm")` we have a `not(test)` guard here
// to avoid calling `export_service`, which we need to call in the test below.
#[cfg(not(any(target_family = "wasm", test)))]
fn main() {
    // The line below generates did types and service definition from the
    // methods annotated with `candid_method` above. The definition is then
    // obtained with `__export_service()`.
    candid::export_service!();
    std::print!("{}", __export_service());
}

#[cfg(any(target_family = "wasm", test))]
fn main() {}

#[test]
fn check_candid_file() {
    let did_path = match std::env::var("DID_PATH") {
        Ok(v) => v,
        Err(_e) => "call_loop_canister.did".to_string(),
    };
    let candid = String::from_utf8(std::fs::read(did_path).unwrap()).unwrap();

    // See comments in main above
    candid::export_service!();
    let expected = __export_service();

    if candid != expected {
        panic!(
            "Generated candid definition does not match call_loop_canister.did. Run `bazel \
            run //rs/rust_canisters/call_loop_canister:call-loop-canister-binary > \
            rs/rust_canisters/call_loop_canister/call_loop_canister.did` to update \
            the candid file."
        )
    }
}
