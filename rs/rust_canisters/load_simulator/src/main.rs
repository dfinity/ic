#![allow(deprecated)]
use ic_cdk::api::stable;
use std::cell::RefCell;
use std::time::Duration;

thread_local! {
    static COUNTER: RefCell<i32> = const { RefCell::new(0) };
}

async fn timer_handler() {
    COUNTER.with(|counter| {
        let mut counter = counter.borrow_mut();
        *counter += 1;

        // Write to stable memory every 50 timer calls.
        if *counter % 50 == 0 {
            if stable::stable_size() < 5 {
                let _ = stable::stable_grow(1);
            }
            if stable::stable_size() > 0 {
                stable::stable_write(0, &[1, 2, 3]);
            }
        }
    });
}

#[ic_cdk::init]
fn set_up_timer() {
    // Set up a canister timer to call a function every N seconds.
    ic_cdk_timers::set_timer_interval(Duration::from_secs(1), async || timer_handler().await);
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
        Err(_e) => "load_simulator.did".to_string(),
    };
    let candid = String::from_utf8(std::fs::read(did_path).unwrap()).unwrap();

    // See comments in main above
    candid::export_service!();
    let expected = __export_service();

    if candid != expected {
        panic!(
            "Generated candid definition does not match load_simulator.did. Run \
            `bazel run //rs/rust_canisters/load_simulator:load_simulator_binary > \
            rs/rust_canisters/load_simulator/load_simulator.did` to update \
            the candid file."
        )
    }
}
