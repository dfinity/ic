//! A test canister designed to exercise the panic hooks.
//! Its content is tied to the `hooks.rs` test.

fn main() {}

#[export_name = "canister_update test_panic_hook"]
fn test_panic_hook() {
    dfn_core::printer::hook();
    // This is a trap WITHOUT an explicit to the API to verify that the
    // trap hooks works
    panic!("This message should be passed as trap message thanks to the hook");
}

#[export_name = "canister_update set_hooks"]
fn set_hooks() {
    dfn_core::printer::hook();
    dfn_core::api::reply(&[]);
}

#[export_name = "canister_update panic"]
fn panic() {
    // This is a trap WITHOUT an explicit to the API to verify that the
    // trap hooks set in a previous update call works
    panic!("A panic message in a function that does not set the hook");
}
