use super::*;
use candid_parser::utils::{CandidSource, service_equal};
use ic_base_types::{PrincipalId, SubnetId};

/// Builds an `UpdateSubnetPayload` where every optional field is `None` and
/// every non-optional knob has its default. The given `subnet_id` identifies
/// the target; the caller can flip individual fields on the returned struct
/// to set up a specific test case.
fn empty_update_payload() -> UpdateSubnetPayload {
    UpdateSubnetPayload {
        subnet_id: SubnetId::new(PrincipalId::new_user_test_id(1)),
        max_ingress_bytes_per_message: None,
        max_ingress_bytes_per_block: None,
        max_ingress_messages_per_block: None,
        max_block_payload_size: None,
        unit_delay_millis: None,
        initial_notary_delay_millis: None,
        dkg_interval_length: None,
        dkg_dealings_per_block: None,
        start_as_nns: None,
        subnet_type: None,
        is_halted: None,
        halt_at_cup_height: None,
        features: None,
        resource_limits: None,
        chain_key_config: None,
        chain_key_signing_enable: None,
        chain_key_signing_disable: None,
        max_number_of_canisters: None,
        ssh_readonly_access: None,
        ssh_backup_access: None,
        subnet_admins: None,
        max_artifact_streams_per_peer: None,
        max_chunk_wait_ms: None,
        max_duplicity: None,
        max_chunk_size: None,
        receive_check_cache_size: None,
        pfn_evaluation_period_ms: None,
        registry_poll_period_ms: None,
        retransmission_request_ms: None,
        set_gossip_config_to_default: false,
    }
}

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

#[test]
fn ensure_only_allowed_fields_set_accepts_empty_payload() {
    // Pure no-op: no fields set at all. We don't actually want to allow this
    // in practice (the call would be useless), but the validator's job is
    // purely structural — it must accept any payload where the only mutated
    // fields are the allowed ones.
    ensure_only_allowed_fields_set(&empty_update_payload())
        .expect("an empty payload must pass the structural check");
}

#[test]
fn ensure_only_allowed_fields_set_accepts_subnet_admins_only() {
    let mut payload = empty_update_payload();
    payload.subnet_admins = Some(vec![PrincipalId::new_user_test_id(42)]);
    ensure_only_allowed_fields_set(&payload).expect("subnet_admins-only payload must be allowed");
}

#[test]
fn ensure_only_allowed_fields_set_accepts_is_halted() {
    for is_halted in [true, false] {
        let mut payload = empty_update_payload();
        payload.is_halted = Some(is_halted);
        ensure_only_allowed_fields_set(&payload)
            .unwrap_or_else(|e| panic!("is_halted={is_halted} payload must be allowed: {e}"));
    }
}

#[test]
fn ensure_only_allowed_fields_set_accepts_subnet_admins_and_is_halted() {
    let mut payload = empty_update_payload();
    payload.subnet_admins = Some(vec![PrincipalId::new_user_test_id(42)]);
    payload.is_halted = Some(true);
    ensure_only_allowed_fields_set(&payload)
        .expect("subnet_admins + is_halted payload must be allowed");
}

#[test]
fn ensure_only_allowed_fields_set_rejects_other_fields() {
    let mut payload = empty_update_payload();
    payload.max_number_of_canisters = Some(100);
    // `halt_at_cup_height` is intentionally *not* part of the allowed surface,
    // even though it is halting-adjacent: only `is_halted` is.
    payload.halt_at_cup_height = Some(true);
    let err = ensure_only_allowed_fields_set(&payload).expect_err("should reject");
    assert!(
        err.contains("max_number_of_canisters"),
        "error must mention disallowed field: {err}"
    );
    assert!(
        err.contains("halt_at_cup_height"),
        "error must mention disallowed field: {err}"
    );
}

#[test]
fn ensure_only_allowed_fields_set_rejects_non_default_gossip_flag() {
    let mut payload = empty_update_payload();
    payload.set_gossip_config_to_default = true;
    let err = ensure_only_allowed_fields_set(&payload).expect_err("should reject");
    assert!(
        err.contains("set_gossip_config_to_default"),
        "error must mention the non-default bool: {err}"
    );
}
