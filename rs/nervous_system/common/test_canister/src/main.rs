#[macro_use]
extern crate ic_nervous_system_common;

expose_build_metadata! {}

// Prints Candid interface definition, which should only contain get_build_metadata method.
#[cfg(not(test))]
fn main() {
    candid::export_service!();
    std::print!("{}", __export_service());
}

#[test]
fn matches_candid_file() {
    let expected = String::from_utf8(std::fs::read("interface.did").unwrap()).unwrap();

    candid::export_service!();
    let actual = __export_service();

    assert_eq!(
        actual, expected,
        "Generated candid definition does not match interface.did. \
         Run `cargo run --bin ic-nns-common-test-canister > interface.did` in \
         rs/nns/common/test_canister to update interface.did."
    );
}
