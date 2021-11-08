use super::*;
use ic_test_utilities::types::ids::canister_test_id;
use ic_types::methods::WasmClosure;

#[test]
fn call_context_origin() {
    let mut ccm = CallContextManager::default();
    let id = canister_test_id(42);
    let cb_id = CallbackId::from(1);
    let cc_id = ccm.new_call_context(CallOrigin::CanisterUpdate(id, cb_id), Cycles::from(10));
    assert_eq!(
        ccm.call_contexts().get(&cc_id).unwrap().call_origin,
        CallOrigin::CanisterUpdate(id, cb_id)
    );
}

#[test]
// This test is close to the minimal one and I don't want to delete comments
#[allow(clippy::cognitive_complexity)]
fn call_context_handling() {
    let mut ccm = CallContextManager::default();

    // On two incoming calls
    let cc_id = ccm.new_call_context(
        CallOrigin::CanisterUpdate(canister_test_id(123), CallbackId::from(1)),
        Cycles::from(0),
    );
    let cc_id2 = ccm.new_call_context(
        CallOrigin::CanisterUpdate(canister_test_id(123), CallbackId::from(2)),
        Cycles::from(0),
    );

    let cc_id3 = ccm.new_call_context(
        CallOrigin::CanisterUpdate(canister_test_id(123), CallbackId::from(3)),
        Cycles::from(0),
    );

    // Call context 3 was not responded and does not have outstanding calls,
    // so we should generate the response ourselves.
    assert_eq!(
        ccm.on_canister_result(cc_id3, Ok(None)),
        CallContextAction::NoResponse {
            refund: Cycles::from(0),
        }
    );

    // First they're unanswered
    assert!(!ccm.call_contexts().get(&cc_id).unwrap().responded);
    assert!(!ccm.call_contexts().get(&cc_id2).unwrap().responded);

    // First call (CallContext 1) makes two outgoing calls
    let cb_id = ccm.register_callback(Callback::new(
        cc_id,
        Cycles::from(0),
        WasmClosure::new(0, 1),
        WasmClosure::new(2, 3),
        None,
    ));
    let cb_id2 = ccm.register_callback(Callback::new(
        cc_id,
        Cycles::from(0),
        WasmClosure::new(4, 5),
        WasmClosure::new(6, 7),
        None,
    ));

    // There are 2 ougoing calls
    assert_eq!(ccm.outstanding_calls(cc_id), 2);

    // Second one (CallContext 2) has one outgoing call
    let cb_id3 = ccm.register_callback(Callback::new(
        cc_id2,
        Cycles::from(0),
        WasmClosure::new(8, 9),
        WasmClosure::new(10, 11),
        None,
    ));
    // There is 1 outgoing call
    assert_eq!(ccm.outstanding_calls(cc_id2), 1);

    assert_eq!(ccm.callbacks().len(), 3);

    // Still unanswered
    assert!(!ccm.call_contexts().get(&cc_id).unwrap().responded);
    assert!(!ccm.call_contexts().get(&cc_id2).unwrap().responded);

    // One outstanding call is closed
    let callback = ccm.unregister_callback(cb_id).unwrap();
    assert_eq!(
        callback.on_reply,
        WasmClosure {
            func_idx: 0,
            env: 1
        }
    );
    assert_eq!(
        callback.on_reject,
        WasmClosure {
            func_idx: 2,
            env: 3
        }
    );
    assert_eq!(ccm.callbacks().len(), 2);
    // There is 1 outstanding call left
    assert_eq!(ccm.outstanding_calls(cc_id), 1);

    assert_eq!(
        ccm.on_canister_result(cc_id, Ok(Some(WasmResult::Reply(vec![1])))),
        CallContextAction::Reply {
            payload: vec![1],
            refund: Cycles::from(0),
        }
    );

    // CallContext 1 is answered, CallContext 2 is not
    assert!(ccm.call_contexts().get(&cc_id).unwrap().responded);
    assert!(!ccm.call_contexts().get(&cc_id2).unwrap().responded);

    // The outstanding call of CallContext 2 is back
    let callback = ccm.unregister_callback(cb_id3).unwrap();
    assert_eq!(
        callback.on_reply,
        WasmClosure {
            func_idx: 8,
            env: 9
        }
    );
    assert_eq!(
        callback.on_reject,
        WasmClosure {
            func_idx: 10,
            env: 11
        }
    );

    // Only one outstanding call left
    assert_eq!(ccm.callbacks().len(), 1);

    // Since we didn't mark CallContext 2 as answered we still have two
    assert_eq!(ccm.call_contexts().len(), 2);

    // We mark the CallContext 2 as responded and it is deleted as it has no
    // outstanding calls
    assert_eq!(
        ccm.on_canister_result(cc_id2, Ok(Some(WasmResult::Reply(vec![])))),
        CallContextAction::Reply {
            payload: vec![],
            refund: Cycles::from(0),
        }
    );
    assert_eq!(ccm.call_contexts().len(), 1);

    // the last outstanding call of CallContext 1 is finished
    let callback = ccm.unregister_callback(cb_id2).unwrap();
    assert_eq!(
        callback.on_reply,
        WasmClosure {
            func_idx: 4,
            env: 5
        }
    );
    assert_eq!(
        callback.on_reject,
        WasmClosure {
            func_idx: 6,
            env: 7
        }
    );
    assert_eq!(
        ccm.on_canister_result(cc_id, Ok(None)),
        CallContextAction::AlreadyResponded
    );

    // Since CallContext 1 was already responded, make sure we're in a clean state
    assert_eq!(ccm.callbacks().len(), 0);
    assert_eq!(ccm.call_contexts().len(), 0);
}

#[test]
fn withdraw_cycles_fails_when_not_enough_available_cycles() {
    let mut ccm = CallContextManager::default();
    let id = canister_test_id(42);
    let cb_id = CallbackId::from(1);
    let cc_id = ccm.new_call_context(CallOrigin::CanisterUpdate(id, cb_id), Cycles::from(30));

    assert_eq!(
        ccm.call_context_mut(cc_id)
            .unwrap()
            .withdraw_cycles(Cycles::from(40)),
        Err(CallContextError::InsufficientCyclesInCall {
            available: Cycles::from(30),
            requested: Cycles::from(40),
        })
    );
}

#[test]
fn withdraw_cycles_succeeds_when_enough_available_cycles() {
    let mut ccm = CallContextManager::default();
    let id = canister_test_id(42);
    let cb_id = CallbackId::from(1);
    let cc_id = ccm.new_call_context(CallOrigin::CanisterUpdate(id, cb_id), Cycles::from(30));

    assert_eq!(
        ccm.call_context_mut(cc_id)
            .unwrap()
            .withdraw_cycles(Cycles::from(25)),
        Ok(())
    );
}
