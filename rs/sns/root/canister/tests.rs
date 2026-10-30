use super::*;
use candid_parser::utils::{CandidSource, service_equal};

/// This is NOT affected by
///
///   1. comments (in ./registry.did)
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
/// there is a different test for that (namely,
/// candid_changes_are_backwards_compatible). This test does not compare the
/// current working copy against master. Rather, it only compares ./canister.rs
/// to root.did.
#[test]
fn test_implemented_interface_matches_declared_interface_exactly() {
    let declared_interface = CandidSource::Text(include_str!("root.did"));

    // The line below generates did types and service definition from the
    // methods annotated with `candid_method` above. The definition is then
    // obtained with `__export_service()`.
    candid::export_service!();
    let implemented_interface_str = __export_service();
    let implemented_interface = CandidSource::Text(&implemented_interface_str);

    let result = service_equal(declared_interface, implemented_interface);
    assert!(result.is_ok(), "{:?}\n\n", result.unwrap_err());
}

fn set_state_for_governance_gate_tests() -> PrincipalId {
    let governance_canister_id = PrincipalId::new_user_test_id(42);
    STATE.with(|state| {
        *state.borrow_mut() = SnsRootCanister {
            governance_canister_id: Some(governance_canister_id),
            ..Default::default()
        };
    });
    governance_canister_id
}

/// take_canister_snapshot and load_canister_snapshot, like change_canister,
/// start with assert_eq_governance_canister_id.
#[test]
fn test_assert_eq_governance_canister_id_accepts_governance() {
    let governance_canister_id = set_state_for_governance_gate_tests();

    // This must not panic.
    assert_eq_governance_canister_id(governance_canister_id);
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")]
fn test_assert_eq_governance_canister_id_rejects_other_principals() {
    let _governance_canister_id = set_state_for_governance_gate_tests();

    assert_eq_governance_canister_id(PrincipalId::new_user_test_id(43));
}
