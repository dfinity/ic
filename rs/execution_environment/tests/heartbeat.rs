use assert_matches::assert_matches;
use ic_execution_environment::CanisterHeartbeatError;
use ic_ic00_types::CanisterStatusType;
use ic_interfaces::execution_environment::{HypervisorError, TrapCode};
use ic_replicated_state::{page_map::PAGE_SIZE, CanisterStatus};
use ic_test_utilities::execution_environment::ExecutionTestBuilder;
use ic_types::{NumBytes, NumInstructions};

#[test]
fn heartbeat_is_executed() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_heartbeat") unreachable)
            (memory (export "memory") 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.heartbeat(canister_id).unwrap_err();
    assert_eq!(
        err,
        CanisterHeartbeatError::CanisterExecutionFailed(HypervisorError::Trapped(
            TrapCode::Unreachable
        ))
    );
}

#[test]
fn heartbeat_produces_heap_delta() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_heartbeat")
                (i32.store (i32.const 10) (i32.const 10))
            )
            (memory (export "memory") 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    assert_eq!(NumBytes::from(0), test.state().metadata.heap_delta_estimate);
    test.heartbeat(canister_id).unwrap();
    assert_eq!(
        NumBytes::from((PAGE_SIZE) as u64),
        test.state().metadata.heap_delta_estimate
    );
}

#[test]
fn heartbeat_fails_gracefully_if_not_exported() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = "(module)";
    let canister_id = test.canister_from_wat(wat).unwrap();
    test.heartbeat(canister_id).unwrap();
    assert_eq!(NumBytes::from(0), test.state().metadata.heap_delta_estimate);
    assert_eq!(NumInstructions::from(0), test.executed_instructions());
}

#[test]
fn heartbeat_doesnt_run_if_canister_is_stopped() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_heartbeat") unreachable)
            (memory (export "memory") 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    test.stop_canister(canister_id);
    test.process_stopping_canisters();
    assert_eq!(
        CanisterStatus::Stopped,
        test.canister_state(canister_id).system_state.status
    );
    let err = test.heartbeat(canister_id).unwrap_err();
    assert_eq!(
        err,
        CanisterHeartbeatError::CanisterNotRunning {
            status: CanisterStatusType::Stopped,
        }
    );
}

#[test]
fn heartbeat_doesnt_run_if_canister_is_stopping() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_heartbeat") unreachable)
            (memory (export "memory") 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    test.stop_canister(canister_id);
    assert_matches!(
        test.canister_state(canister_id).system_state.status,
        CanisterStatus::Stopping {
            call_context_manager: _,
            stop_contexts: _
        }
    );
    let err = test.heartbeat(canister_id).unwrap_err();
    assert_eq!(
        err,
        CanisterHeartbeatError::CanisterNotRunning {
            status: CanisterStatusType::Stopping,
        }
    );
}
