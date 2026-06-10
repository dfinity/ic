use super::*;
use candid_parser::utils::{CandidSource, service_equal};

/// This is NOT affected by
///
///   1. comments (in ./engine_controller.did)
///   2. whitespace
///   3. order of type definitions
///   4. names of types
///   5. etc.
///
/// Whereas, this test fails in the following cases
///
///   1. extra (or missing) fields
///   2. differences in field names
///   3. etc.
///
/// If this test passes, that does NOT mean that the API has evolved safely;
/// it only checks that the canister's currently-implemented interface
/// matches the contents of `engine_controller.did`.
#[test]
fn test_implemented_interface_matches_declared_interface_exactly() {
    let declared_interface = CandidSource::Text(include_str!("../engine_controller.did"));

    // The line below generates did types and the service definition from the
    // methods exported by this canister. The definition is then obtained with
    // `__export_service()`.
    candid::export_service!();
    let implemented_interface_str = __export_service();
    let implemented_interface = CandidSource::Text(&implemented_interface_str);

    let result = service_equal(declared_interface, implemented_interface);
    assert!(result.is_ok(), "{:?}\n\n", result.unwrap_err());
}
