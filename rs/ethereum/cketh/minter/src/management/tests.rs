use super::Reason;
use ic_cdk::call::{CallFailed, CallPerformFailed, CallRejected, InsufficientLiquidCycleBalance};

#[test]
fn from_call_failed_maps_insufficient_liquid_cycle_balance_to_out_of_cycles() {
    // The ic-cdk 0.19 `Call` builder does a pre-flight check comparing
    // `canister_liquid_cycle_balance` against `Call::get_cost` and surfaces
    // `InsufficientLiquidCycleBalance` *before* `ic0.call_perform`. The old
    // `call_with_payment128` surface had no such check, so this is a new code
    // path; we map it to `Reason::OutOfCycles` so the error message is accurate.
    let err = CallFailed::InsufficientLiquidCycleBalance(InsufficientLiquidCycleBalance {
        available: 100,
        required: 1_000,
    });
    assert_eq!(Reason::from_call_failed(err), Reason::OutOfCycles);
}

#[test]
fn from_call_failed_includes_underlying_error_on_call_perform_failed() {
    match Reason::from_call_failed(CallFailed::CallPerformFailed(CallPerformFailed)) {
        Reason::InternalError(msg) => {
            assert!(msg.starts_with("call_perform failed: "), "got {msg}")
        }
        other => panic!("expected InternalError, got {other:?}"),
    }
}

#[test]
fn from_call_failed_maps_known_reject_codes_to_expected_reasons() {
    let cases = [
        (2_u32, Reason::TransientInternalError("msg".to_string())),
        (5_u32, Reason::CanisterError("msg".to_string())),
        (4_u32, Reason::Rejected("msg".to_string())),
    ];
    for (raw_code, expected) in cases {
        let err =
            CallFailed::CallRejected(CallRejected::with_rejection(raw_code, "msg".to_string()));
        assert_eq!(
            Reason::from_call_failed(err),
            expected,
            "raw_code={raw_code}"
        );
    }
}

#[test]
fn from_call_failed_maps_unrecognized_reject_code_to_internal_error() {
    let err = CallFailed::CallRejected(CallRejected::with_rejection(99, "huh".to_string()));
    match Reason::from_call_failed(err) {
        Reason::InternalError(msg) => {
            assert!(msg.contains("99") && msg.contains("huh"), "got {msg}");
        }
        other => panic!("expected InternalError, got {other:?}"),
    }
}
