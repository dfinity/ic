use super::*;
use ic_sns_governance::pb::v1::{DisburseMaturityInProgress, Neuron};
use maplit::btreemap;

/// A test that fails if the API was updated but the candid definition was not.
#[cfg(not(feature = "test"))]
#[test]
fn check_governance_candid_file() {
    let did_path = format!(
        "{}/canister/governance.did",
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set")
    );
    let did_contents = String::from_utf8(std::fs::read(did_path).unwrap()).unwrap();

    // See comments in main above
    candid::export_service!();
    let expected = __export_service();

    if did_contents != expected {
        panic!(
            "Generated candid definition does not match canister/governance.did. \
            Run `bazel run :generate_did > canister/governance.did` (no nix and/or direnv) or \
            `cargo run --bin sns-governance-canister > canister/governance.did` in \
            rs/sns/governance to update canister/governance.did."
        )
    }
}

#[cfg(feature = "test")]
#[test]
fn check_governance_candid_file() {
    let did_path = format!(
        "{}/canister/governance_test.did",
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set")
    );
    let did_contents = String::from_utf8(std::fs::read(did_path).unwrap()).unwrap();

    // See comments in main above
    candid::export_service!();
    let expected = __export_service();

    if did_contents != expected {
        panic!(
            "Generated candid definition does not match canister/governance_test.did. \
            Run `bazel run :generate_test_did > canister/governance_test.did` (no nix and/or direnv) in \
            rs/sns/governance to update canister/governance_test.did."
        )
    }
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
