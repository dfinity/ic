use super::*;
use candid_parser::utils::{service_equal, CandidSource};
use ic_sns_governance::pb::v1::{DisburseMaturityInProgress, Neuron};
use maplit::btreemap;

/// See analogous comments in registry/canister/canister/tests.rs (yes, canister occurs twice).
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

/// A test that checks that set_time_warp advances time correctly.
#[test]
fn test_set_time_warp() {
    let mut environment = CanisterEnv::new();

    let start = environment.now();
    environment.set_time_warp(TimeWarp { delta_s: 1_000 });
    let delta_s = environment.now() - start;

    assert!(delta_s >= 1000, "delta_s = {}", delta_s);
    assert!(delta_s < 1005, "delta_s = {}", delta_s);
}

#[test]
fn test_populate_finalize_disbursement_timestamp_seconds() {
    // Step 1: prepare a neuron with 2 in progress disbursement, one with
    // finalize_disbursement_timestamp_seconds as None, and the other has incorrect timestamp.
    let mut governance_proto = GovernanceProto {
        neurons: btreemap! {
            "1".to_string() => Neuron {
                disburse_maturity_in_progress: vec![
                    DisburseMaturityInProgress {
                        timestamp_of_disbursement_seconds: 1,
                        finalize_disbursement_timestamp_seconds: None,
                        ..Default::default()
                    },
                    DisburseMaturityInProgress {
                        timestamp_of_disbursement_seconds: 2,
                        finalize_disbursement_timestamp_seconds: Some(3),
                        ..Default::default()
                    }
                ],
                ..Default::default()
            },
        },
        ..Default::default()
    };

    // Step 2: populates the timestamps.
    populate_finalize_disbursement_timestamp_seconds(&mut governance_proto);

    // Step 3: verifies that both disbursements have the correct finalization timestamps.
    let expected_governance_proto = GovernanceProto {
        neurons: btreemap! {
            "1".to_string() => Neuron {
                disburse_maturity_in_progress: vec![
                    DisburseMaturityInProgress {
                        timestamp_of_disbursement_seconds: 1,
                        finalize_disbursement_timestamp_seconds: Some(1 + MATURITY_DISBURSEMENT_DELAY_SECONDS),
                        ..Default::default()
                    },
                    DisburseMaturityInProgress {
                        timestamp_of_disbursement_seconds: 2,
                        finalize_disbursement_timestamp_seconds: Some(2 + MATURITY_DISBURSEMENT_DELAY_SECONDS),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
        },
        ..Default::default()
    };
    assert_eq!(governance_proto, expected_governance_proto);
}
