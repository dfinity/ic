//! `StateMachine` analogue of the system test
//! `rs/tests/message_routing/xnet/subnet_delete_test.rs`.
//!
//! It verifies that deleting a subnet correctly handles in-flight XNet messages:
//! requests towards the deleted subnet are rejected, responses towards the
//! deleted subnet are silently dropped (a response is never turned into a
//! reject), and messages from the deleted subnet that are still in its stream
//! are not pulled after subnet deletion. The scenario is run as a matrix over
//! the type of the deleted subnet: it must behave the same whether the deleted
//! subnet is a CloudEngine subnet or a regular application subnet (subnet
//! deletion is handled by the routing/topology layer, which is subnet-type
//! agnostic).
//!
//! The scenario wires together three `StateMachine`s sharing a single registry
//! (see `rs/state_machine_tests/tests/multi_subnet.rs` for the basic wiring):
//!   - two application subnets `S` and `T`, and
//!   - one subnet `C` (the one being deleted), whose type is either
//!     `CloudEngine` or `Application` depending on the matrix entry.
//!
//! A subnet is "halted" simply by not executing rounds on it (a halted subnet
//! makes no progress), and `C` is "deleted" by removing it from the shared pool
//! of subnets and tombstoning its registry records (matching how PocketIC
//! implements subnet deletion).
//!
//! Runbook:
//! ```text
//! 1.  Install universal canisters US on S, UT on T, UC on C, plus two more
//!     canisters US2 and US3 on S (for the response-dropping part).
//! 2.  Halt T (stop executing rounds on it).
//! 3.  From UC fire a bounded-wait call to UT that would set UT's global data to
//!     a fixed blob. The call is fire-and-forget (UC replies to its ingress
//!     immediately) and remains stuck in the C -> T stream. Also from UC fire two
//!     bounded-wait calls to US2 and US3 on S. Each callee loops (making
//!     `canister_status` calls) holding its reply back until its global data is
//!     set. Both calls are fire-and-forget.
//! 4.  Halt C.
//! 5.  Release US2's reply (set its global data). Its response is destined for UC
//!     on the halted subnet C; C does not consume it and, since the S -> C stream
//!     is still empty, it is inducted into that stream.
//! 6.  From US submit 10 bounded-wait calls to UC with a 2 MB payload each
//!     (generated at runtime, so the ingress stays small). Each call's on_reject
//!     handler replies with the reject code as a 4-byte LE integer. The 2 MB
//!     payloads fill the S -> C stream (TARGET_STREAM_SIZE_BYTES), so some calls
//!     reach the stream while the rest stay in US's output queue.
//! 7.  Drive S until all 10 calls are in flight; at this point the S -> C stream
//!     is full (TARGET_STREAM_SIZE_BYTES) and the remaining calls stay in US's
//!     output queue.
//! 8.  Release US3's reply. As the S -> C stream is now full, its response cannot
//!     be inducted and stays in US3's output queue.
//! 9.  Delete C, unhalt T, check UT's global data is still empty (T must not pull
//!     messages from the deleted C's stream), and wait for all 10 calls from US to
//!     complete. (Unlike the system test, T observes the post-deletion registry
//!     version synchronously — applied in Step 9a — so there is no separate wait
//!     for it.)
//! 10. Assert at least one call from US was rejected with DestinationInvalid
//!     (call did not reach the stream: no route after deletion) and at least one
//!     with CanisterReject (call reached the stream, so its callback was still
//!     open when C was deleted; generate_reject_responses_for_deleted_subnets
//!     then synthesizes an immediate reject for it, rather than waiting for the
//!     bounded-wait callback to time out).
//! 11. Assert both responses towards C were silently dropped: the one that sat in
//!     US3's output queue is dropped by the stream builder (counted by
//!     mr_routed_message_count{type="response",status="canister_not_found"}), and
//!     the one that sat in the S -> C stream is dropped together with the whole
//!     stream (metric-silent, asserted by the stream being gone).
//! ```
//!
//! Bounded-wait (best-effort) calls with no cycles are used throughout because
//! they are the only cross-subnet calls allowed to/from a CloudEngine subnet;
//! they are equally valid for an application subnet, which keeps the scenario
//! identical across both matrix entries.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_registry_routing_table::{RoutingTable, routing_table_insert_subnet};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{
    StateMachine, StateMachineBuilder, Subnets, add_global_registry_records,
    add_initial_registry_records, remove_subnet_local_registry_records,
    update_global_registry_records,
};
use ic_test_utilities_metrics::fetch_int_counter_vec;
use ic_types::ingress::{IngressState, IngressStatus, WasmResult};
use ic_types::messages::{MessageId, StreamMessage};
use ic_types::{CanisterId, PrincipalId, RegistryVersion, SubnetId};
use ic_types_cycles::Cycles;
use ic_universal_canister::{UNIVERSAL_CANISTER_WASM, call_args, wasm};

const INITIAL_CYCLES_BALANCE: Cycles = Cycles::new(100_000_000_000_000);
const NUM_CALLS: usize = 10;
/// Payload size per `US -> UC` call. `2 MB` is below `MAX_INTER_CANISTER_PAYLOAD_IN_BYTES`
/// (`2 MiB`) and `6` such payloads exceed `TARGET_STREAM_SIZE_BYTES` (`10 MiB`),
/// so the `S -> C` stream fills up and only some of the calls reach it.
const PAYLOAD_SIZE: u32 = 2 * 1000 * 1000;
/// Best-effort call timeout. `with_execute_round_time_increment` advances each
/// subnet's clock by 1s per round, so a best-effort call/response times out after
/// this many rounds. It is chosen comfortably larger than the number of rounds
/// executed while any best-effort call or response is still pending (in
/// particular the two responses towards `C`, which are produced early yet must
/// survive until `C` is deleted), so that nothing times out prematurely; it is
/// still smaller than the post-deletion round budget, so a regression that fails
/// to reject/drop in-flight messages lets them time out within that budget: the
/// calls complete (via a timeout reject) and the failure surfaces as a mismatched
/// reject code in the Step 10 assertions, rather than as the (bounded)
/// completion-wait loop exhausting its rounds with calls still pending.
const CALL_TIMEOUT_SECS: u32 = 120;
const FIXED_BLOB: &[u8] = b"cloud-engine-test-fixed-blob";
/// Blobs used by the response-dropping scenario. A looping canister on `S` holds
/// its reply back until its global data is set to `RESPONSE_TRIGGER_BLOB`, then
/// replies with the given reply blob (the payload of the response that must be
/// silently dropped once `C` is deleted). Two responses are produced: one that
/// ends up in `S`'s stream towards `C`, and one that stays in the sender
/// canister's output queue (because the stream is already full).
const RESPONSE_TRIGGER_BLOB: &[u8] = b"subnet-delete-response-trigger";
const RESPONSE_STREAM_REPLY_BLOB: &[u8] = b"subnet-delete-response-in-stream";
const RESPONSE_QUEUE_REPLY_BLOB: &[u8] = b"subnet-delete-response-in-queue";

/// Reject codes (see `ic_error_types::RejectCode`).
const DESTINATION_INVALID: u32 = 3;
const CANISTER_REJECT: u32 = 4;

/// Shared pool of `StateMachine`s used to mock the XNet layer. Removing a subnet
/// from this pool makes it unreachable for the other subnets (i.e. "deleted").
#[derive(Clone)]
struct SubnetsImpl {
    subnets: Arc<RwLock<BTreeMap<SubnetId, Arc<StateMachine>>>>,
}

impl SubnetsImpl {
    fn new() -> Self {
        Self {
            subnets: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    fn remove(&self, subnet_id: SubnetId) {
        self.subnets.write().unwrap().remove(&subnet_id);
    }
}

impl Subnets for SubnetsImpl {
    fn insert(&self, state_machine: Arc<StateMachine>) {
        self.subnets
            .write()
            .unwrap()
            .insert(state_machine.get_subnet_id(), state_machine);
    }
    fn get(&self, subnet_id: SubnetId) -> Option<Arc<StateMachine>> {
        self.subnets.read().unwrap().get(&subnet_id).cloned()
    }
}

fn build_subnet(
    subnets: Arc<SubnetsImpl>,
    subnet_seed: u8,
    subnet_type: SubnetType,
    registry_data_provider: Arc<ProtoRegistryDataProvider>,
) -> Arc<StateMachine> {
    StateMachineBuilder::new()
        .with_subnet_seed([subnet_seed; 32])
        .with_subnet_type(subnet_type)
        .with_registry_data_provider(registry_data_provider)
        // Advance time by 1 second between rounds so that bounded-wait calls can
        // eventually expire.
        .with_execute_round_time_increment(Duration::from_secs(1))
        .build_with_subnets(subnets)
}

fn install_universal_canister(sm: &StateMachine) -> CanisterId {
    sm.install_canister_with_cycles(
        UNIVERSAL_CANISTER_WASM.to_vec(),
        vec![],
        None,
        INITIAL_CYCLES_BALANCE,
    )
    .unwrap()
}

fn ingress_result(sm: &StateMachine, msg_id: &MessageId) -> Option<WasmResult> {
    match sm.ingress_status(msg_id) {
        IngressStatus::Known {
            state: IngressState::Completed(result),
            ..
        } => Some(result),
        _ => None,
    }
}

/// Fires a fire-and-forget bounded-wait call from `uc` on subnet `c` to
/// `callee`'s `update` method running the looping op: `callee` holds its reply
/// back (looping on `canister_status` calls) until its global data equals
/// `RESPONSE_TRIGGER_BLOB`, then replies with `reply_blob`. `uc` replies to its
/// own ingress immediately; `c` is driven until that ingress completes, so the
/// resulting request is placed in `c`'s outgoing stream towards `callee`'s subnet.
fn fire_looping_call(
    c: &StateMachine,
    uc: CanisterId,
    callee: CanisterId,
    user_id: PrincipalId,
    reply_blob: &[u8],
) {
    let payload = wasm()
        .call_simple_with_cycles_and_best_effort_response(
            callee,
            "update",
            call_args()
                .other_side(wasm().loop_until_global_data_set(RESPONSE_TRIGGER_BLOB, reply_blob))
                .on_reply(wasm().noop())
                .on_reject(wasm().noop()),
            0_u128,
            CALL_TIMEOUT_SECS,
        )
        .reply_data(&[])
        .build();
    let msg_id = c.submit_ingress_as(user_id, uc, "update", payload).unwrap();
    let mut completed = false;
    for _ in 0..10 {
        c.execute_round();
        if ingress_result(c, &msg_id).is_some() {
            completed = true;
            break;
        }
    }
    assert!(
        completed,
        "UC fire-and-forget looping ingress did not complete"
    );
}

/// Releases a looping canister's held-back reply by setting its global data to
/// `RESPONSE_TRIGGER_BLOB` (fire-and-forget; the canister's loop then replies on
/// its next iteration).
fn release_looping_reply(sm: &StateMachine, canister: CanisterId, user_id: PrincipalId) {
    let payload = wasm()
        .set_global_data(RESPONSE_TRIGGER_BLOB)
        .reply_data(&[])
        .build();
    sm.submit_ingress_as(user_id, canister, "update", payload)
        .unwrap();
}

/// Counts the `Response` messages in `sm`'s stream towards `remote` (0 if there
/// is no such stream).
fn stream_response_count(sm: &StateMachine, remote: SubnetId) -> usize {
    sm.get_latest_state()
        .get_stream(&remote)
        .map(|stream| {
            stream
                .messages()
                .iter()
                .filter(|(_, m)| matches!(m, StreamMessage::Response(_)))
                .count()
        })
        .unwrap_or(0)
}

/// Returns the number of responses that the stream builder on `sm` has silently
/// dropped because their destination canister had no known route, i.e. the value
/// of `mr_routed_message_count{type="response",status="canister_not_found"}`.
fn dropped_no_route_response_count(sm: &StateMachine) -> u64 {
    fetch_int_counter_vec(sm.metrics_registry(), "mr_routed_message_count")
        .into_iter()
        .filter(|(labels, _)| {
            labels.get("type").map(String::as_str) == Some("response")
                && labels.get("status").map(String::as_str) == Some("canister_not_found")
        })
        .map(|(_, value)| value)
        .sum()
}

// The subnet-deletion scenario is run once per supported type of the deleted
// subnet `C`; the observable behavior must be identical. Each type gets its own
// test so they run in parallel and failures are easy to attribute.

#[test]
fn xnet_messages_rejected_after_cloud_engine_subnet_deletion() {
    xnet_messages_rejected_after_subnet_deletion_impl(SubnetType::CloudEngine);
}

#[test]
fn xnet_messages_rejected_after_application_subnet_deletion() {
    xnet_messages_rejected_after_subnet_deletion_impl(SubnetType::Application);
}

fn xnet_messages_rejected_after_subnet_deletion_impl(deleted_subnet_type: SubnetType) {
    let user_id = PrincipalId::new_anonymous();

    // Set up a shared registry and three subnets: two application subnets S, T
    // and one subnet C (the one to be deleted), whose type is `deleted_subnet_type`.
    let registry_data_provider = Arc::new(ProtoRegistryDataProvider::new());
    let subnets = Arc::new(SubnetsImpl::new());
    let s = build_subnet(
        subnets.clone(),
        1,
        SubnetType::Application,
        registry_data_provider.clone(),
    );
    let t = build_subnet(
        subnets.clone(),
        2,
        SubnetType::Application,
        registry_data_provider.clone(),
    );
    let c = build_subnet(
        subnets.clone(),
        3,
        deleted_subnet_type,
        registry_data_provider.clone(),
    );

    let s_id = s.get_subnet_id();
    let t_id = t.get_subnet_id();
    let c_id = c.get_subnet_id();

    // Set up the routing table and global registry records for all three subnets.
    let mut routing_table = RoutingTable::new();
    routing_table_insert_subnet(&mut routing_table, s_id).unwrap();
    routing_table_insert_subnet(&mut routing_table, t_id).unwrap();
    routing_table_insert_subnet(&mut routing_table, c_id).unwrap();

    add_initial_registry_records(registry_data_provider.clone());
    add_global_registry_records(
        s_id,
        routing_table.clone(),
        vec![s_id, t_id, c_id],
        BTreeMap::new(),
        registry_data_provider.clone(),
    );

    // Make all three subnets agree on the registry.
    s.reload_registry();
    t.reload_registry();
    c.reload_registry();

    // Step 1: Install universal canisters US on S, UT on T, UC on C, plus two
    // more canisters US2 and US3 on S dedicated to the response-dropping
    // scenario: US2 produces the response that ends up in S's stream towards C,
    // US3 the response that stays in US3's output queue.
    let us = install_universal_canister(&s);
    let us2 = install_universal_canister(&s);
    let us3 = install_universal_canister(&s);
    let ut = install_universal_canister(&t);
    let uc = install_universal_canister(&c);

    // Step 2: Halt subnet T by simply not executing any rounds on it from now on.

    // Step 3: Fire a fire-and-forget bounded-wait call from UC to UT that would
    // set UT's global data to FIXED_BLOB. UC replies to its ingress immediately,
    // and the call remains stuck in the C -> T stream (T is halted).
    let payload = wasm()
        .call_simple_with_cycles_and_best_effort_response(
            ut,
            "update",
            call_args()
                .other_side(wasm().set_global_data(FIXED_BLOB).reply_data(&[]))
                .on_reply(wasm().noop())
                .on_reject(wasm().noop()),
            0_u128,
            CALL_TIMEOUT_SECS,
        )
        .reply_data(&[])
        .build();
    let msg_id = c.submit_ingress_as(user_id, uc, "update", payload).unwrap();
    // UC replies to its ingress immediately after performing the call.
    let mut completed = false;
    for _ in 0..10 {
        c.execute_round();
        if ingress_result(&c, &msg_id).is_some() {
            completed = true;
            break;
        }
    }
    assert!(completed, "UC fire-and-forget ingress did not complete");

    // The UC -> UT request must be sitting in the C -> T stream (T is halted, so
    // it is never pulled), which is the state under test after C is deleted.
    let c_state = c.get_latest_state();
    let stream = c_state
        .get_stream(&t_id)
        .expect("expected a C -> T stream holding the UC -> UT request");
    let stream_messages: Vec<&StreamMessage> = stream.messages().iter().map(|(_, m)| m).collect();
    assert_eq!(
        stream_messages.len(),
        1,
        "expected exactly the UC -> UT request in the C -> T stream, got {} messages",
        stream_messages.len()
    );
    match stream_messages[0] {
        StreamMessage::Request(req) => {
            assert_eq!(req.sender, uc, "unexpected sender of the C -> T request");
            assert_eq!(
                req.receiver, ut,
                "unexpected receiver of the C -> T request"
            );
            assert_eq!(
                req.method_name, "update",
                "unexpected method of the C -> T request"
            );
        }
        other => panic!("expected a Request in the C -> T stream, got {other:?}"),
    }
    drop(c_state);

    // Also fire two more fire-and-forget bounded-wait calls from UC to US2
    // and US3 on the surviving subnet S. Each callee loops (making
    // `canister_status` calls) holding its reply back until its global data is
    // set (Steps 5, 8).
    // Both requests are placed in the C -> S stream while C is still running, so
    // S can induct them (and start the loops) before C is deleted. Their eventual
    // replies are *responses* destined for UC on the deleted subnet C.
    fire_looping_call(&c, uc, us2, user_id, RESPONSE_STREAM_REPLY_BLOB);
    fire_looping_call(&c, uc, us3, user_id, RESPONSE_QUEUE_REPLY_BLOB);

    // Step 4: Halt subnet C by not executing any more rounds on it.

    // Step 5: Release US2's reply by setting its global data, and drive S until
    // the resulting response reaches the S -> C stream. This is the first time S
    // runs since Step 3, so the drive inducts the two C -> S requests and starts
    // US2's and US3's loops, letting US2 observe its global data and reply. C is
    // halted, so it does not consume the response; and the S -> C stream is still
    // empty (Step 6 has not run yet), so the response is inducted into it.
    release_looping_reply(&s, us2, user_id);
    let mut response_in_stream = false;
    for _ in 0..50 {
        s.execute_round();
        if stream_response_count(&s, c_id) >= 1 {
            response_in_stream = true;
            break;
        }
    }
    assert!(
        response_in_stream,
        "US2's response did not reach the S -> C stream"
    );
    // The S -> C stream must hold exactly US2's response and nothing else yet.
    let state = s.get_latest_state();
    let stream = state
        .get_stream(&c_id)
        .expect("expected an S -> C stream holding US2's response");
    let stream_messages: Vec<&StreamMessage> = stream.messages().iter().map(|(_, m)| m).collect();
    assert_eq!(
        stream_messages.len(),
        1,
        "expected exactly US2's response in the S -> C stream, got {} messages",
        stream_messages.len()
    );
    match stream_messages[0] {
        StreamMessage::Response(resp) => {
            assert_eq!(
                resp.respondent, us2,
                "unexpected respondent of the streamed response"
            );
            assert_eq!(
                resp.originator, uc,
                "unexpected originator of the streamed response"
            );
        }
        other => panic!("expected a Response in the S -> C stream, got {other:?}"),
    }
    drop(state);

    // Step 6: Submit 10 bounded-wait calls from US to UC, each producing a 2 MB
    // payload at runtime (the ingress itself stays small). The on_reject handler
    // replies with the reject code as a 4-byte LE integer.
    let us_uc_payload = wasm()
        .call_simple_with_cycles_and_best_effort_response(
            uc,
            "update",
            call_args()
                .eval_other_side(wasm().push_equal_bytes(0, PAYLOAD_SIZE).build())
                .on_reply(wasm().reply_data(&[]))
                .on_reject(
                    wasm()
                        .reject_code()
                        .int_to_blob()
                        .reply_data_append()
                        .reply(),
                ),
            0_u128,
            CALL_TIMEOUT_SECS,
        )
        .build();
    let us_msg_ids: Vec<MessageId> = (0..NUM_CALLS)
        .map(|_| {
            s.submit_ingress_as(user_id, us, "update", us_uc_payload.clone())
                .unwrap()
        })
        .collect();

    // Step 7: Execute rounds on S until all calls have been performed by US (i.e.
    // all ingress messages are being processed, waiting for their callbacks). Each
    // round the stream builder moves queued messages into the S -> C stream but
    // stops adding to it once its byte size reaches the soft limit
    // TARGET_STREAM_SIZE_BYTES (the check is `count_bytes() >=
    // TARGET_STREAM_SIZE_BYTES`, evaluated before each message, so the last one may
    // push it slightly over). By the time all calls are processing the stream is
    // full to that target, so the remaining calls stay in US's output queue.
    let mut all_processing = false;
    for _ in 0..50 {
        s.execute_round();
        if us_msg_ids.iter().all(|msg_id| {
            matches!(
                s.ingress_status(msg_id),
                IngressStatus::Known {
                    state: IngressState::Processing,
                    ..
                }
            )
        }) {
            all_processing = true;
            break;
        }
    }
    assert!(
        all_processing,
        "US did not perform all calls before deleting C"
    );

    // Assert that the S -> C stream is partially filled: some (but not all)
    // US -> UC calls reached the stream and the rest are still in US's output
    // queue. This partition is what yields both reject codes in step 10 (streamed
    // calls -> CanisterReject, queued calls -> DestinationInvalid). The stream
    // also still holds the single US2 response from Step 5.
    let state = s.get_latest_state();
    let stream = state
        .get_stream(&c_id)
        .expect("expected an S -> C stream partially filled with US -> UC requests");
    let stream_request_count = stream
        .messages()
        .iter()
        .filter(|(_, m)| {
            matches!(
                m,
                StreamMessage::Request(req)
                    if req.sender == us && req.receiver == uc && req.method_name == "update"
            )
        })
        .count();
    let response_count = stream
        .messages()
        .iter()
        .filter(|(_, m)| matches!(m, StreamMessage::Response(_)))
        .count();
    assert_eq!(
        response_count, 1,
        "expected exactly US2's response among the S -> C stream messages"
    );
    assert_eq!(
        stream_request_count + response_count,
        stream.messages().len(),
        "expected only US -> UC requests and US2's response in the S -> C stream"
    );
    assert!(
        (1..NUM_CALLS).contains(&stream_request_count),
        "expected some but not all US -> UC calls in the S -> C stream, \
         got {stream_request_count} of {NUM_CALLS}"
    );
    assert!(
        state.canister_state(&us).unwrap().has_output(),
        "expected the remaining US -> UC calls in US's output queue before deleting C"
    );
    drop(state);

    // Step 8: Release US3's reply, now that the S -> C stream is full. US3's
    // response towards UC on C therefore cannot be inducted into the stream and
    // stays in US3's output queue. We drive S enough rounds for US3's loop to
    // reply, then assert the stream is unchanged (still exactly one response, the
    // US2 one from Step 5), confirming US3's response did not enter the stream.
    release_looping_reply(&s, us3, user_id);
    for _ in 0..20 {
        s.execute_round();
    }
    assert_eq!(
        stream_response_count(&s, c_id),
        1,
        "US3's response must stay in US3's output queue, not enter the full S -> C stream"
    );
    assert!(
        s.get_latest_state()
            .canister_state(&us3)
            .unwrap()
            .has_output(),
        "expected US3's response in US3's output queue before deleting C"
    );

    // Step 9a: Delete subnet C. We remove it from the shared pool of subnets
    // (making it unreachable for S and T) and tombstone its registry records,
    // matching how PocketIC implements subnet deletion.
    let next_version = RegistryVersion::new(registry_data_provider.latest_version().get() + 1);
    routing_table.remove_subnet(c_id);
    update_global_registry_records(
        next_version,
        routing_table.clone(),
        vec![s_id, t_id],
        BTreeMap::new(),
        registry_data_provider.clone(),
    );
    remove_subnet_local_registry_records(
        c_id,
        &c.nodes,
        registry_data_provider.clone(),
        next_version,
    );
    subnets.remove(c_id);
    s.reload_registry();
    t.reload_registry();

    // Step 9b: Unhalt subnet T by resuming round execution on it.
    //
    // Step 9c: No analog here. The system test waits for T to observe the registry
    // version at which C was deleted; in this test `reload_registry()` in Step 9a
    // applied that version to T synchronously, so T already sees C as deleted by
    // the time it runs.
    for _ in 0..5 {
        t.execute_round();
    }

    // Step 9d: Verify T does not pull the messages from the deleted subnet C:
    // UT's global data must stay empty.
    let global_data = t
        .query(
            ut,
            "query",
            wasm().get_global_data().reply_data_append().reply().build(),
        )
        .unwrap();
    match global_data {
        WasmResult::Reply(bytes) => assert!(
            bytes.is_empty(),
            "UT global data should be empty but got {} bytes",
            bytes.len()
        ),
        WasmResult::Reject(reject) => panic!("unexpected reject querying UT: {reject}"),
    }

    // Step 9e: Drive S until all 10 calls from US complete. The calls still in
    // US's output queue are rejected with DestinationInvalid (no route to C),
    // while the calls already in the S -> C stream (whose callback is still
    // open) get an immediate synthetic CanisterReject once C disappears from
    // the network topology (see `generate_reject_responses_for_deleted_subnets`).
    let mut results: Vec<Option<WasmResult>> = vec![None; NUM_CALLS];
    let mut done = false;
    for _ in 0..200 {
        for (i, msg_id) in us_msg_ids.iter().enumerate() {
            if results[i].is_none() {
                results[i] = ingress_result(&s, msg_id);
            }
        }
        if results.iter().all(Option::is_some) {
            done = true;
            break;
        }
        s.execute_round();
    }
    assert!(done, "not all US -> UC calls completed");

    // Step 10: Assert that all calls were rejected and that both reject codes occur.
    let mut destination_invalid_count = 0_usize;
    let mut canister_reject_count = 0_usize;
    for result in results {
        match result.unwrap() {
            WasmResult::Reply(bytes) => {
                assert_eq!(
                    bytes.len(),
                    4,
                    "expected exactly 4 bytes (reject code), got {} bytes",
                    bytes.len()
                );
                let code = u32::from_le_bytes(bytes.try_into().unwrap());
                match code {
                    DESTINATION_INVALID => destination_invalid_count += 1,
                    CANISTER_REJECT => canister_reject_count += 1,
                    other => panic!("unexpected reject code {other} from US -> UC call"),
                }
            }
            WasmResult::Reject(reject) => panic!("unexpected reject from US -> UC call: {reject}"),
        }
    }
    assert!(
        destination_invalid_count >= 1,
        "expected at least one DestinationInvalid rejection, got {destination_invalid_count} \
         (deleted subnet type: {deleted_subnet_type:?})"
    );
    assert!(
        canister_reject_count >= 1,
        "expected at least one CanisterReject rejection, got {canister_reject_count} \
         (deleted subnet type: {deleted_subnet_type:?})"
    );

    // Step 11: Verify the two responses towards C were silently dropped.
    //
    // The response that sat in US3's output queue (Step 8) is dropped by the
    // stream builder when it finds no route to C, incrementing
    // `mr_routed_message_count{type="response",status="canister_not_found"}`.
    // (The queued US -> UC requests increment the same counter with
    // `type="request"` and are additionally rejected, see Step 10.) Unlike a
    // request, a response is never turned into a reject.
    assert_eq!(
        dropped_no_route_response_count(&s),
        1,
        "expected exactly the queued US3 response to be silently dropped as no_route \
         (deleted subnet type: {deleted_subnet_type:?})"
    );

    // The response that sat in the S -> C stream (Step 5) is dropped together
    // with the whole stream when C is deleted; that bulk discard is intentionally
    // metric-silent, so we assert it directly: S no longer has a stream towards
    // the deleted subnet C.
    assert!(
        s.get_latest_state().get_stream(&c_id).is_none(),
        "expected S's stream towards the deleted subnet C to be discarded \
         (deleted subnet type: {deleted_subnet_type:?})"
    );
}
