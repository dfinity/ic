use ic_base_types::{PrincipalId, PrincipalIdClass};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    state_test_helpers::{
        registry_get_changes_since, setup_nns_canisters, state_machine_builder_for_nns_tests,
    },
};
use ic_registry_transport::pb::v1::{
    registry_error, RegistryError, RegistryGetChangesSinceResponse,
};
use std::str::FromStr;

#[test]
fn test_disallow_opaque_callers() {
    // Step 1: Prepare the world.
    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    // Step 2: Call the code under test.
    let sender = PrincipalId::new_user_test_id(42);
    assert_eq!(sender.class(), Ok(PrincipalIdClass::Opaque));
    let response = registry_get_changes_since(&state_machine, sender, 1);

    // Step 3: Inspect results.
    let RegistryGetChangesSinceResponse {
        error,
        version,
        deltas,
    } = response;

    assert_eq!(version, 0);
    assert_eq!(deltas, vec![]);

    let error = error.unwrap();
    let RegistryError { code, reason, key } = error;

    assert_eq!(key, Vec::<u8>::new());

    assert_eq!(
        registry_error::Code::try_from(code),
        Ok(registry_error::Code::Authorization)
    );
    let reason = reason.to_lowercase();
    for key_word in ["caller", "opaque"] {
        assert!(
            reason.contains(key_word),
            "{} not in {:?}",
            key_word,
            reason
        );
    }
}

#[test]
fn test_allow_non_opaque_callers() {
    // Step 1: Prepare the world. (Same as previous test.)
    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    // Step 2: Call the code under test. Unlike the previous test, the sender is a
    // self-authenticatying principal, not an opaque principal.
    let sender =
        PrincipalId::from_str("ubktz-haghv-fqsdh-23fhi-3urex-bykoz-pvpfd-5rs6w-qpo3t-nf2dv-oae")
            .unwrap();
    assert_eq!(sender.class(), Ok(PrincipalIdClass::SelfAuthenticating));
    let response = registry_get_changes_since(&state_machine, sender, 1);

    // Step 3: Inspect results.
    let RegistryGetChangesSinceResponse {
        error,
        version: _,
        deltas: _,
    } = response;

    assert_eq!(error, None);
}
