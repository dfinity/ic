use super::Reason;
use ic_cdk::call::{
    CallFailed, CallPerformFailed, CallRejected, Error as CallError,
    InsufficientLiquidCycleBalance, OnewayError,
};

#[test]
fn from_call_error_maps_insufficient_liquid_cycle_balance_to_out_of_cycles() {
    // `Reason::OutOfCycles` had no producer before the ic-cdk 0.18 migration:
    // the cdk's pre-flight check inside `Call::await` is what surfaces this
    // variant when `canister_liquid_cycle_balance` < `Call::get_cost`. We
    // intentionally route it to `Reason::OutOfCycles` rather than fall through
    // to `InternalError` so the error message reflects the real cause.
    let err = CallError::InsufficientLiquidCycleBalance(InsufficientLiquidCycleBalance {
        available: 100,
        required: 1_000,
    });
    assert_eq!(Reason::from_call_error(err), Reason::OutOfCycles);
}

#[test]
fn from_call_failed_maps_insufficient_liquid_cycle_balance_to_out_of_cycles() {
    let err = CallFailed::InsufficientLiquidCycleBalance(InsufficientLiquidCycleBalance {
        available: 100,
        required: 1_000,
    });
    assert_eq!(Reason::from_call_failed(err), Reason::OutOfCycles);
}

#[test]
fn from_oneway_error_maps_insufficient_liquid_cycle_balance_to_out_of_cycles() {
    let err = OnewayError::InsufficientLiquidCycleBalance(InsufficientLiquidCycleBalance {
        available: 100,
        required: 1_000,
    });
    assert_eq!(Reason::from_oneway_error(err), Reason::OutOfCycles);
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

#[test]
fn from_call_failed_includes_underlying_error_on_call_perform_failed() {
    match Reason::from_call_failed(CallFailed::CallPerformFailed(CallPerformFailed)) {
        Reason::InternalError(msg) => {
            assert_eq!(msg, "call_perform failed");
        }
        other => panic!("expected InternalError, got {other:?}"),
    }
}
