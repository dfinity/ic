use super::*;
use candid_parser::utils::{service_equal, CandidSource};

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
/// to registry.did.
#[test]
fn test_implemented_interface_matches_declared_interface_exactly() {
    #[cfg(feature = "test")]
    let declared_interface = include_str!("governance_test.did");
    #[cfg(not(feature = "test"))]
    let declared_interface = include_str!("governance.did");
    let declared_interface = CandidSource::Text(declared_interface);

    // The line below generates did types and service definition from the
    // methods annotated with `candid_method` above. The definition is then
    // obtained with `__export_service()`.
    candid::export_service!();
    let implemented_interface_str = __export_service();
    let implemented_interface = CandidSource::Text(&implemented_interface_str);

    let result = service_equal(declared_interface, implemented_interface);
    assert!(result.is_ok(), "{:?}\n\n", result.unwrap_err());
}

#[test]
fn test_set_time_warp() {
    let mut environment = CanisterEnv::new();

    let start = environment.now();
    environment.set_time_warp(GovTimeWarp { delta_s: 1_000 });
    let delta_s = environment.now() - start;

    assert!(delta_s >= 1000, "delta_s = {}", delta_s);
    assert!(delta_s < 1005, "delta_s = {}", delta_s);
}

#[test]
fn test_get_effective_payload_sets_proposal_id_for_add_wasm() {
    let mt = gov_pb::NnsFunction::AddSnsWasm;
    let proposal_id = 42;
    let wasm = vec![1, 2, 3];
    let canister_type = 3;
    let hash = vec![1, 2, 3, 4];
    let payload = Encode!(&AddWasmRequest {
        wasm: Some(SnsWasm {
            proposal_id: None,
            wasm: wasm.clone(),
            canister_type,
        }),
        hash: hash.clone(),
    })
    .unwrap();

    let effective_payload = get_effective_payload(mt, &payload, proposal_id, 0).unwrap();

    let decoded = Decode!(&effective_payload, AddWasmRequest).unwrap();
    assert_eq!(
        decoded,
        AddWasmRequest {
            wasm: Some(SnsWasm {
                proposal_id: Some(proposal_id), // The proposal_id should be set
                wasm,
                canister_type
            }),
            hash
        }
    );
}

#[test]
fn test_get_effective_payload_overrides_proposal_id_for_add_wasm() {
    let mt = gov_pb::NnsFunction::AddSnsWasm;
    let proposal_id = 42;
    let payload = Encode!(&AddWasmRequest {
        wasm: Some(SnsWasm {
            proposal_id: Some(proposal_id - 1),
            ..SnsWasm::default()
        }),
        ..AddWasmRequest::default()
    })
    .unwrap();

    let effective_payload = get_effective_payload(mt, &payload, proposal_id, 0).unwrap();

    let decoded = Decode!(&effective_payload, AddWasmRequest).unwrap();
    assert_eq!(decoded.wasm.unwrap().proposal_id.unwrap(), proposal_id);
}
