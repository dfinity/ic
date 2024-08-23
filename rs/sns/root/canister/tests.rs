use super::*;

/// A test that fails if the API was updated but the candid definition was not.
#[test]
fn check_candid_interface_definition_file() {
    let did_path = std::path::PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR env var undefined"),
    )
    .join("canister/root.did");

    let did_contents = String::from_utf8(std::fs::read(did_path).unwrap()).unwrap();

    // See comments in main above
    candid::export_service!();
    let expected = __export_service();

    if did_contents != expected {
        panic!(
            "Generated candid definition does not match canister/root.did. \
             Run `bazel run :generate_did > canister/root.did` (no nix and/or direnv) or \
             `cargo run --bin sns-root-canister > canister/root.did` in \
             rs/sns/root to update canister/root.did."
        )
    }
}
