use candid::candid_method;
use ic_cdk::update;

/// Macro to create a chain of function calls resulting in the provided
/// expression and expose it via an update with the provided name.
///
/// This just allows us to make a non-trivial backtrace without needed to write
/// out several functions each time.
macro_rules! make_call_chain {
    ( $name:ident, $x:expr_2021 ) => {
        mod $name {
            #[inline(never)]
            pub(super) fn outer() {
                inner();
            }

            #[inline(never)]
            fn inner() {
                inner_2();
            }

            #[inline(never)]
            fn inner_2() {
                $x;
            }
        }

        #[candid_method(update)]
        #[update]
        fn $name() {
            $name::outer();
        }
    };
}

make_call_chain!(unreachable, {
    #[cfg(target_arch = "wasm32")]
    core::arch::wasm32::unreachable();
});

make_call_chain!(oob, {
    let address = (u32::MAX - 10) as *const usize; // In the last page of Wasm memory.
    let _count = unsafe { core::ptr::read_volatile(address) };
});

make_call_chain!(ic0_trap, {
    panic!("uh oh");
});

make_call_chain!(stable_oob, {
    ic_cdk::stable::stable_write(1_000 * 1_000, "foo".as_bytes());
});

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
