use super::*;
use ic_test_utilities_types::{
    ids::{canister_test_id, message_test_id, user_test_id},
    messages::{RequestBuilder, ResponseBuilder},
};
use ic_types::{messages::RequestMetadata, methods::WasmClosure, time::UNIX_EPOCH};
use maplit::btreemap;

#[test]
fn call_context_origin() {
    let mut ccm = CallContextManager::default();
    let id = canister_test_id(42);
    let cb_id = CallbackId::from(1);
    let cc_id = ccm.new_call_context(
        CallOrigin::CanisterUpdate(id, cb_id, NO_DEADLINE),
        Cycles::new(10),
        Time::from_nanos_since_unix_epoch(0),
        Default::default(),
    );
    assert_eq!(
        ccm.call_contexts().get(&cc_id).unwrap().call_origin,
        CallOrigin::CanisterUpdate(id, cb_id, NO_DEADLINE)
    );
}

#[test]
// This test is close to the minimal one and I don't want to delete comments
#[allow(clippy::cognitive_complexity)]
fn call_context_handling() {
    let mut call_context_manager = CallContextManager::default();

    // On two incoming calls
    let call_context_id1 = call_context_manager.new_call_context(
        CallOrigin::CanisterUpdate(canister_test_id(123), CallbackId::from(1), NO_DEADLINE),
        Cycles::zero(),
        Time::from_nanos_since_unix_epoch(0),
        Default::default(),
    );
    let call_context_id2 = call_context_manager.new_call_context(
        CallOrigin::CanisterUpdate(canister_test_id(123), CallbackId::from(2), NO_DEADLINE),
        Cycles::zero(),
        Time::from_nanos_since_unix_epoch(0),
        Default::default(),
    );

    let call_context_id3 = call_context_manager.new_call_context(
        CallOrigin::CanisterUpdate(canister_test_id(123), CallbackId::from(3), NO_DEADLINE),
        Cycles::zero(),
        Time::from_nanos_since_unix_epoch(0),
        Default::default(),
    );

    // Call context 3 was not responded and does not have outstanding calls,
    // so we should generate the response ourselves.
    assert_eq!(
        (
            CallContextAction::NoResponse {
                refund: Cycles::zero(),
            },
            call_context_manager.call_context(call_context_id3).cloned()
        ),
        call_context_manager.on_canister_result(call_context_id3, None, Ok(None), 0.into())
    );

    // First they're unanswered
    assert!(
        !call_context_manager
            .call_contexts()
            .get(&call_context_id1)
            .unwrap()
            .responded
    );
    assert!(
        !call_context_manager
            .call_contexts()
            .get(&call_context_id2)
            .unwrap()
            .responded
    );

    // First call (CallContext 1) makes two outgoing calls
    let callback_id1 = call_context_manager.register_callback(Callback::new(
        call_context_id1,
        canister_test_id(1),
        canister_test_id(2),
        Cycles::zero(),
        Cycles::new(42),
        Cycles::new(84),
        WasmClosure::new(0, 1),
        WasmClosure::new(2, 3),
        None,
        NO_DEADLINE,
    ));
    let callback_id2 = call_context_manager.register_callback(Callback::new(
        call_context_id1,
        canister_test_id(1),
        canister_test_id(2),
        Cycles::zero(),
        Cycles::new(43),
        Cycles::new(85),
        WasmClosure::new(4, 5),
        WasmClosure::new(6, 7),
        None,
        NO_DEADLINE,
    ));

    // There are 2 ougoing calls
    assert_eq!(call_context_manager.outstanding_calls(call_context_id1), 2);

    // Second one (CallContext 2) has one outgoing call
    let callback_id3 = call_context_manager.register_callback(Callback::new(
        call_context_id2,
        canister_test_id(1),
        canister_test_id(2),
        Cycles::zero(),
        Cycles::new(44),
        Cycles::new(86),
        WasmClosure::new(8, 9),
        WasmClosure::new(10, 11),
        None,
        NO_DEADLINE,
    ));
    // There is 1 outgoing call
    assert_eq!(call_context_manager.outstanding_calls(call_context_id2), 1);

    assert_eq!(call_context_manager.callbacks().len(), 3);

    // Still unanswered
    assert!(
        !call_context_manager
            .call_contexts()
            .get(&call_context_id1)
            .unwrap()
            .responded
    );
    assert!(
        !call_context_manager
            .call_contexts()
            .get(&call_context_id2)
            .unwrap()
            .responded
    );

    // One outstanding call is closed
    let callback = call_context_manager.callback(callback_id1).unwrap().clone();
    assert_eq!(callback.on_reply, WasmClosure::new(0, 1));
    assert_eq!(callback.on_reject, WasmClosure::new(2, 3));
    assert_eq!(call_context_manager.callbacks().len(), 3);

    assert_eq!(
        call_context_manager.on_canister_result(
            call_context_id1,
            Some(callback_id1),
            Ok(Some(WasmResult::Reply(vec![1]))),
            0.into()
        ),
        (
            CallContextAction::Reply {
                payload: vec![1],
                refund: Cycles::zero(),
            },
            None
        )
    );

    assert_eq!(call_context_manager.callbacks().len(), 2);
    // There is 1 outstanding call left
    assert_eq!(call_context_manager.outstanding_calls(call_context_id1), 1);

    // CallContext 1 is answered, CallContext 2 is not
    assert!(
        call_context_manager
            .call_contexts()
            .get(&call_context_id1)
            .unwrap()
            .responded
    );
    assert!(
        !call_context_manager
            .call_contexts()
            .get(&call_context_id2)
            .unwrap()
            .responded
    );

    // The outstanding call of CallContext 2 is back
    let callback = call_context_manager.callback(callback_id3).unwrap().clone();
    assert_eq!(callback.on_reply, WasmClosure::new(8, 9));
    assert_eq!(callback.on_reject, WasmClosure::new(10, 11));

    // Since we didn't mark CallContext 2 as answered we still have two
    assert_eq!(call_context_manager.call_contexts().len(), 2);

    // We mark the CallContext 2 as responded and it is deleted as it has no
    // outstanding calls
    assert_eq!(
        (
            CallContextAction::Reply {
                payload: vec![],
                refund: Cycles::zero(),
            },
            call_context_manager.call_context(call_context_id2).cloned()
        ),
        call_context_manager.on_canister_result(
            call_context_id2,
            Some(callback_id3),
            Ok(Some(WasmResult::Reply(vec![]))),
            0.into()
        )
    );
    assert_eq!(call_context_manager.callbacks().len(), 1);
    assert_eq!(call_context_manager.call_contexts().len(), 1);

    // the last outstanding call of CallContext 1 is finished
    let callback = call_context_manager.callback(callback_id2).unwrap().clone();
    assert_eq!(callback.on_reply, WasmClosure::new(4, 5));
    assert_eq!(callback.on_reject, WasmClosure::new(6, 7));
    assert_eq!(
        (
            CallContextAction::AlreadyResponded,
            call_context_manager.call_context(call_context_id1).cloned()
        ),
        call_context_manager.on_canister_result(
            call_context_id1,
            Some(callback_id2),
            Ok(None),
            0.into()
        )
    );

    // Since CallContext 1 was already responded, make sure we're in a clean state
    assert_eq!(call_context_manager.callbacks().len(), 0);
    assert_eq!(call_context_manager.call_contexts().len(), 0);
}

#[test]
fn withdraw_cycles_fails_when_not_enough_available_cycles() {
    let mut ccm = CallContextManager::default();
    let id = canister_test_id(42);
    let cb_id = CallbackId::from(1);
    let cc_id = ccm.new_call_context(
        CallOrigin::CanisterUpdate(id, cb_id, NO_DEADLINE),
        Cycles::new(30),
        Time::from_nanos_since_unix_epoch(0),
        Default::default(),
    );

    assert_eq!(
        Err("Canister accepted more cycles than available from call context"),
        ccm.withdraw_cycles(cc_id, Cycles::new(40))
    );
}

#[test]
fn withdraw_cycles_succeeds_when_enough_available_cycles() {
    let mut ccm = CallContextManager::default();
    let id = canister_test_id(42);
    let cb_id = CallbackId::from(1);
    let cc_id = ccm.new_call_context(
        CallOrigin::CanisterUpdate(id, cb_id, NO_DEADLINE),
        Cycles::new(30),
        Time::from_nanos_since_unix_epoch(0),
        Default::default(),
    );

    let cc = ccm.withdraw_cycles(cc_id, Cycles::new(25)).unwrap().clone();
    assert_eq!(ccm.call_contexts().get(&cc_id).unwrap(), &cc);
    assert_eq!(Cycles::new(5), cc.available_cycles());
}

#[test]
fn test_call_context_instructions_executed_is_updated() {
    let mut call_context_manager = CallContextManager::default();
    let call_context_id = call_context_manager.new_call_context(
        CallOrigin::CanisterUpdate(canister_test_id(123), CallbackId::from(1), NO_DEADLINE),
        Cycles::zero(),
        Time::from_nanos_since_unix_epoch(0),
        Default::default(),
    );
    // Register a callback, so the call context is not deleted in `on_canister_result()` later.
    let _callback_id = call_context_manager.register_callback(Callback::new(
        call_context_id,
        canister_test_id(1),
        canister_test_id(2),
        Cycles::zero(),
        Cycles::new(42),
        Cycles::new(84),
        WasmClosure::new(0, 1),
        WasmClosure::new(2, 3),
        None,
        NO_DEADLINE,
    ));

    // Finish a successful execution with 1K instructions.
    assert_eq!(
        call_context_manager.on_canister_result(call_context_id, None, Ok(None), 1_000.into()),
        (CallContextAction::NotYetResponded, None)
    );
    assert_eq!(
        call_context_manager
            .call_contexts()
            .get(&call_context_id)
            .unwrap()
            .instructions_executed,
        1_000.into()
    );

    // Finish an unsuccessful execution with 2K instructions.
    assert_eq!(
        call_context_manager.on_canister_result(
            call_context_id,
            None,
            Err(HypervisorError::InstructionLimitExceeded(2_000.into())),
            2_000.into()
        ),
        (CallContextAction::NotYetResponded, None)
    );

    // Now there should be 1K + 2K instructions_executed in the call context.
    assert_eq!(
        call_context_manager
            .call_contexts()
            .get(&call_context_id)
            .unwrap()
            .instructions_executed,
        (1_000 + 2_000).into()
    );
}

#[test]
fn call_context_roundtrip_encoding() {
    use ic_protobuf::state::canister_state_bits::v1 as pb;

    let minimal_call_context = CallContext::new(
        CallOrigin::Ingress(user_test_id(1), message_test_id(2)),
        false,
        false,
        Cycles::zero(),
        UNIX_EPOCH,
        Default::default(),
    );
    let maximal_call_context = CallContext::new(
        CallOrigin::Ingress(user_test_id(1), message_test_id(2)),
        true,
        false,
        Cycles::new(3),
        Time::from_nanos_since_unix_epoch(4),
        RequestMetadata::new(5, Time::from_nanos_since_unix_epoch(6)),
    );

    for call_context in [minimal_call_context, maximal_call_context] {
        let encoded = pb::CallContext::from(&call_context);
        let decoded = CallContext::try_from(encoded).unwrap();

        assert_eq!(call_context, decoded);
    }
}

#[test]
fn callback_stats() {
    let mut ccm = CallContextManager::default();
    let call_context_id = CallContextId::from(1);
    let originator = canister_test_id(1);
    let respondent = canister_test_id(2);
    let best_effort_callback = Callback::new(
        call_context_id,
        originator,
        respondent,
        Cycles::zero(),
        Cycles::new(42),
        Cycles::new(84),
        WasmClosure::new(0, 1),
        WasmClosure::new(2, 3),
        None,
        CoarseTime::from_secs_since_unix_epoch(13),
    );
    let guaranteed_response_callback = Callback::new(
        call_context_id,
        originator,
        respondent,
        Cycles::zero(),
        Cycles::new(42),
        Cycles::new(84),
        WasmClosure::new(0, 1),
        WasmClosure::new(2, 3),
        None,
        NO_DEADLINE,
    );

    fn calculate_callback_counts(
        ccm: &CallContextManager,
        aborted_or_paused_response: Option<&Response>,
    ) -> BTreeMap<CanisterId, usize> {
        CallContextManagerStats::calculate_unresponded_callbacks_per_respondent(
            ccm.callbacks(),
            aborted_or_paused_response,
        )
    }

    assert_eq!(0, ccm.unresponded_callback_count(None));
    assert_eq!(btreemap! {}, calculate_callback_counts(&ccm, None));
    assert_eq!(0, ccm.unresponded_guaranteed_response_callback_count(None));

    //
    // Register a best-effort callback.
    //
    let best_effort_callback_id = ccm.register_callback(best_effort_callback);
    let best_effort_callback_response = ResponseBuilder::new()
        .originator(originator)
        .respondent(respondent)
        .originator_reply_callback(best_effort_callback_id)
        .deadline(CoarseTime::from_secs_since_unix_epoch(14))
        .build();
    assert_eq!(1, ccm.unresponded_callback_count(None));
    assert_eq!(
        btreemap! { respondent => 1 },
        calculate_callback_counts(&ccm, None)
    );
    assert_eq!(0, ccm.unresponded_guaranteed_response_callback_count(None));

    //
    // Register a guaranteed response callback.
    //
    let guaranteed_response_callback_id = ccm.register_callback(guaranteed_response_callback);
    let guaranteed_response_callback_response = ResponseBuilder::new()
        .originator(originator)
        .respondent(respondent)
        .originator_reply_callback(guaranteed_response_callback_id)
        .deadline(NO_DEADLINE)
        .build();
    // 2 pending callbacks, one guaranteed response.
    assert_eq!(2, ccm.unresponded_callback_count(None));
    assert_eq!(
        btreemap! { respondent => 2 },
        calculate_callback_counts(&ccm, None)
    );
    assert_eq!(1, ccm.unresponded_guaranteed_response_callback_count(None));

    // But only 1 if either response is in DTS execution.
    assert_eq!(
        1,
        ccm.unresponded_callback_count(Some(&guaranteed_response_callback_response))
    );
    assert_eq!(
        btreemap! { respondent => 1 },
        calculate_callback_counts(&ccm, Some(&guaranteed_response_callback_response))
    );
    assert_eq!(
        0,
        ccm.unresponded_guaranteed_response_callback_count(Some(
            &guaranteed_response_callback_response
        ))
    );
    assert_eq!(
        1,
        ccm.unresponded_callback_count(Some(&best_effort_callback_response))
    );
    assert_eq!(
        btreemap! { respondent => 1 },
        calculate_callback_counts(&ccm, Some(&best_effort_callback_response))
    );
    assert_eq!(
        1,
        ccm.unresponded_guaranteed_response_callback_count(Some(&best_effort_callback_response))
    );

    // Also test an encode-decode roundtrip, to ensure that the count is preserved.
    let call_context_manager_proto: pb::CallContextManager = (&ccm).into();
    assert_eq!(
        ccm,
        CallContextManager::try_from(call_context_manager_proto).unwrap(),
    );

    //
    // Unreguster the best-effort callback.
    //
    ccm.unregister_callback(best_effort_callback_id);
    assert_eq!(1, ccm.unresponded_callback_count(None));
    assert_eq!(
        btreemap! { respondent => 1 },
        calculate_callback_counts(&ccm, None)
    );
    assert_eq!(1, ccm.unresponded_guaranteed_response_callback_count(None));

    //
    // Unregister the guaranteed response callback.
    //
    ccm.unregister_callback(guaranteed_response_callback_id);
    assert_eq!(0, ccm.unresponded_callback_count(None));
    assert_eq!(btreemap! {}, calculate_callback_counts(&ccm, None));
    assert_eq!(0, ccm.unresponded_guaranteed_response_callback_count(None));
}

#[test]
fn test_expire_callbacks() {
    fn callback_with_deadline(deadline: CoarseTime) -> Callback {
        Callback::new(
            CallContextId::from(1),
            canister_test_id(1),
            canister_test_id(2),
            Cycles::zero(),
            Cycles::new(42),
            Cycles::new(84),
            WasmClosure::new(0, 1),
            WasmClosure::new(2, 3),
            None,
            deadline,
        )
    }

    let mut ccm = CallContextManager::default();

    let deadline_1 = CoarseTime::from_secs_since_unix_epoch(1);
    let deadline_2 = CoarseTime::from_secs_since_unix_epoch(2);
    let deadline_3 = CoarseTime::from_secs_since_unix_epoch(3);
    let deadline_4 = CoarseTime::from_secs_since_unix_epoch(4);
    let deadline_5 = CoarseTime::from_secs_since_unix_epoch(5);

    let callback_1 = ccm.register_callback(callback_with_deadline(deadline_1));
    let callback_1b = ccm.register_callback(callback_with_deadline(deadline_1));
    let _callback_n = ccm.register_callback(callback_with_deadline(NO_DEADLINE));
    let callback_3 = ccm.register_callback(callback_with_deadline(deadline_3));
    let callback_4 = ccm.register_callback(callback_with_deadline(deadline_4));
    assert_eq!(5, ccm.callbacks().len());

    // No callbacks expire at deadline 1.
    assert_eq!(0, ccm.expire_callbacks(deadline_1).count());

    // Expire all callbacks with deadlines before 3.
    assert_eq!(
        vec![callback_1, callback_1b],
        ccm.expire_callbacks(deadline_3).collect::<Vec<_>>()
    );
    // The callbacks are still in place, expiration doesn't actually touch them.
    assert_eq!(5, ccm.callbacks().len());
    // And making the same call is a no-op.
    assert_eq!(0, ccm.expire_callbacks(deadline_3).count());

    // Unregister one of the expired callbacks.
    ccm.unregister_callback(callback_1);
    // And one of the unexpired ones.
    ccm.unregister_callback(callback_3);
    // 3 callbacks left.
    assert_eq!(3, ccm.callbacks().len());

    // Register a callback with a deadline in the past. Technically, this cannot
    // happen on a subnet, but we also don't have an explicit check against it.
    let callback_2 = ccm.register_callback(callback_with_deadline(deadline_2));

    // Expire the remaining callbacks (callback 4 and the newly registered callback
    // 2; in order of their expiration times).
    assert_eq!(
        vec![callback_2, callback_4],
        ccm.expire_callbacks(deadline_5).collect::<Vec<_>>()
    );
    // 3 + 1 callbacks left.
    assert_eq!(4, ccm.callbacks().len());
}

#[test]
fn call_context_stats() {
    fn new_call_context(ccm: &mut CallContextManager, origin: CallOrigin) -> CallContextId {
        ccm.new_call_context(
            origin,
            Cycles::zero(),
            Time::from_nanos_since_unix_epoch(1),
            RequestMetadata::new(2, UNIX_EPOCH),
        )
    }

    let mut ccm = CallContextManager::default();

    fn calculate_call_context_counts(
        ccm: &CallContextManager,
        aborted_or_paused_request: Option<&Request>,
    ) -> BTreeMap<CanisterId, usize> {
        CallContextManagerStats::calculate_unresponded_call_contexts_per_originator(
            ccm.call_contexts(),
            aborted_or_paused_request,
        )
    }

    assert_eq!(0, ccm.unresponded_canister_update_call_contexts(None));
    assert_eq!(btreemap! {}, calculate_call_context_counts(&ccm, None));
    assert_eq!(0, ccm.unresponded_guaranteed_response_call_contexts(None));

    //
    // Create a new call context with ingress origin.
    //
    let ingress_id = new_call_context(
        &mut ccm,
        CallOrigin::Ingress(user_test_id(1), message_test_id(2)),
    );

    // Not a canister update, no stats updated.
    assert_eq!(0, ccm.unresponded_canister_update_call_contexts(None));
    assert_eq!(btreemap! {}, calculate_call_context_counts(&ccm, None));
    assert_eq!(0, ccm.unresponded_guaranteed_response_call_contexts(None));

    //
    // Create a new best-effort call context.
    //
    let be_originator = canister_test_id(3);
    let be_deadline = CoarseTime::from_secs_since_unix_epoch(5);
    let best_effort_id = new_call_context(
        &mut ccm,
        CallOrigin::CanisterUpdate(be_originator, CallbackId::from(4), be_deadline),
    );

    // One unresponded call context, but not a guaranteed response one.
    assert_eq!(1, ccm.unresponded_canister_update_call_contexts(None));
    assert_eq!(
        btreemap! { be_originator => 1 },
        calculate_call_context_counts(&ccm, None)
    );
    assert_eq!(0, ccm.unresponded_guaranteed_response_call_contexts(None));

    //
    // Create a new guaranteed response call context.
    //
    let gr_originator = canister_test_id(6);
    let guaranteed_response_id = new_call_context(
        &mut ccm,
        CallOrigin::CanisterUpdate(gr_originator, CallbackId::from(7), NO_DEADLINE),
    );

    // Two unresponded call contexts, a best-effort one and a guaranteed response
    // one.
    assert_eq!(2, ccm.unresponded_canister_update_call_contexts(None));
    assert_eq!(
        btreemap! { be_originator => 1, gr_originator => 1 },
        calculate_call_context_counts(&ccm, None)
    );
    assert_eq!(1, ccm.unresponded_guaranteed_response_call_contexts(None));

    // But one more call context if we have another request in DTS execution.
    let other_be_request = RequestBuilder::new()
        .sender(be_originator)
        .sender_reply_callback(CallbackId::from(8))
        .deadline(be_deadline)
        .build();
    assert_eq!(
        3,
        ccm.unresponded_canister_update_call_contexts(Some(&other_be_request))
    );
    assert_eq!(
        btreemap! { be_originator => 2, gr_originator => 1 },
        calculate_call_context_counts(&ccm, Some(&other_be_request))
    );
    assert_eq!(
        1,
        ccm.unresponded_guaranteed_response_call_contexts(Some(&other_be_request))
    );

    // Same with a guaranteed response request in DTS execution.
    let other_gr_request = RequestBuilder::new()
        .sender(gr_originator)
        .sender_reply_callback(CallbackId::from(9))
        .deadline(NO_DEADLINE)
        .build();
    assert_eq!(
        3,
        ccm.unresponded_canister_update_call_contexts(Some(&other_gr_request))
    );
    assert_eq!(
        btreemap! { be_originator => 1, gr_originator => 2 },
        calculate_call_context_counts(&ccm, Some(&other_gr_request))
    );
    assert_eq!(
        2,
        ccm.unresponded_guaranteed_response_call_contexts(Some(&other_gr_request))
    );

    //
    // Respond to the ingress call context. No effect on the stats.
    //
    ccm.mark_responded(ingress_id).unwrap();
    assert_eq!(3, ccm.call_contexts.len());
    assert_eq!(2, ccm.unresponded_canister_update_call_contexts(None));
    assert_eq!(
        btreemap! { be_originator => 1, gr_originator => 1 },
        calculate_call_context_counts(&ccm, None)
    );
    assert_eq!(1, ccm.unresponded_guaranteed_response_call_contexts(None));

    //
    // Mark the best effort call context as responded.
    //
    ccm.mark_responded(best_effort_id).unwrap();
    assert_eq!(3, ccm.call_contexts.len());
    assert_eq!(1, ccm.unresponded_canister_update_call_contexts(None));
    assert_eq!(
        btreemap! { gr_originator => 1 },
        calculate_call_context_counts(&ccm, None)
    );
    assert_eq!(1, ccm.unresponded_guaranteed_response_call_contexts(None));

    //
    // Non-response result on the best effort call context. Call context is
    // consumed, but no effect on the stats.
    //
    ccm.on_canister_result(best_effort_id, None, Ok(None), 0.into());
    assert_eq!(2, ccm.call_contexts.len());
    assert_eq!(1, ccm.unresponded_canister_update_call_contexts(None));
    assert_eq!(
        btreemap! { gr_originator => 1 },
        calculate_call_context_counts(&ccm, None)
    );
    assert_eq!(1, ccm.unresponded_guaranteed_response_call_contexts(None));

    //
    // A no response result to the guaranteed response call context.
    //
    ccm.on_canister_result(guaranteed_response_id, None, Ok(None), 1.into());
    assert_eq!(1, ccm.call_contexts.len());
    // No more unresponded call contexts.
    assert_eq!(0, ccm.unresponded_canister_update_call_contexts(None));
    assert_eq!(btreemap! {}, calculate_call_context_counts(&ccm, None));
    assert_eq!(0, ccm.unresponded_guaranteed_response_call_contexts(None));
}

/// Tests that an encode-decode roundtrip yields a result equal to the original.
#[test]
fn roundtrip_encode() {
    let mut ccm = CallContextManager::default();

    let this = canister_test_id(13);
    let other = canister_test_id(14);
    let deadline_1 = CoarseTime::from_secs_since_unix_epoch(1);
    let deadline_2 = CoarseTime::from_secs_since_unix_epoch(2);

    // Create a new call context.
    let call_context_id = ccm.new_call_context(
        CallOrigin::CanisterUpdate(other, CallbackId::new(13), NO_DEADLINE),
        Cycles::new(30),
        Time::from_nanos_since_unix_epoch(0),
        Default::default(),
    );

    // Register two best-effort and one guaranteed response callbacks.
    let callback_1 = ccm.register_callback(Callback::new(
        call_context_id,
        this,
        other,
        Cycles::new(21),
        Cycles::new(42),
        Cycles::new(84),
        WasmClosure::new(0, 1),
        WasmClosure::new(2, 3),
        None,
        deadline_1,
    ));
    ccm.register_callback(Callback::new(
        call_context_id,
        this,
        other,
        Cycles::zero(),
        Cycles::new(43),
        Cycles::new(85),
        WasmClosure::new(4, 5),
        WasmClosure::new(6, 7),
        Some(WasmClosure::new(8, 9)),
        deadline_2,
    ));
    ccm.register_callback(Callback::new(
        call_context_id,
        this,
        other,
        Cycles::zero(),
        Cycles::new(44),
        Cycles::new(86),
        WasmClosure::new(10, 11),
        WasmClosure::new(12, 13),
        None,
        NO_DEADLINE,
    ));

    // Expire the first callback.
    assert_eq!(
        vec![callback_1],
        ccm.expire_callbacks(deadline_2).collect::<Vec<_>>()
    );

    let encoded: pb::CallContextManager = (&ccm).into();
    let decoded = encoded.try_into().unwrap();

    assert_eq!(ccm, decoded);
}
