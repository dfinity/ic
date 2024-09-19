use candid::candid_method;
use ic_cdk_macros::update;

#[candid_method(update)]
#[update]
fn unreachable() {
    #[cfg(target_arch = "wasm32")]
    core::arch::wasm32::unreachable();
    #[cfg(not(target_arch = "wasm32"))]
    panic!("uh oh");
}

#[candid_method(update)]
#[update]
fn oob() {
    let address = (u32::MAX - 10) as *const usize; // In the last page of Wasm memory.
    let _count = unsafe { core::ptr::read_volatile(address) };
}

#[candid_method(update)]
#[update]
fn ic0_trap() {
    panic!("uh oh");
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
        Err(_e) => "backtrace_canister.did".to_string(),
    };
    let candid = String::from_utf8(std::fs::read(did_path).unwrap()).unwrap();

    // See comments in main above
    candid::export_service!();
    let expected = __export_service();

    if candid != expected {
        panic!(
            "Generated candid definition does not match backtrace_canister.did. Run `bazel \
            run //rs/rust_canisters/backtrace_canister:backtrace-canister-binary > \
            rs/rust_canisters/backtrace_canister/backtrace_canister.did` to update \
            the candid file."
        )
    }
}
