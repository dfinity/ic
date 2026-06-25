//! `StateMachine` analogue of the system test
//! `rs/tests/message_routing/xnet/cloud_engine_subnet_delete_test.rs`.
//!
//! It verifies that deleting a CloudEngine subnet correctly causes in-flight
//! XNet messages to be rejected, and that messages from the deleted CloudEngine
//! subnet that are still in the engine's stream are not pulled after subnet
//! deletion.
//!
//! The scenario wires together three `StateMachine`s sharing a single registry
//! (see `rs/state_machine_tests/tests/multi_subnet.rs` for the basic wiring):
//!   - two application subnets `S` and `T`, and
//!   - one CloudEngine subnet `C`.
//!
//! A subnet is "halted" simply by not executing rounds on it (a halted subnet
//! makes no progress), and `C` is "deleted" by removing it from the shared pool
//! of subnets and tombstoning its registry records (matching how PocketIC
//! implements subnet deletion).
//!
//! Runbook:
//!   1. Install universal canisters `US` on `S`, `UT` on `T`, `UC` on `C`.
//!   2. Halt `T` (stop executing rounds on it).
//!   3. From `UC` fire two best-effort calls to `UT` that would set `UT`'s
//!      global data to a fixed blob. The calls are fire-and-forget (`UC` replies
//!      to its ingress immediately) and remain stuck in the `C -> T` stream.
//!   4. Halt `C`.
//!   5. From `US` submit 10 best-effort calls to `UC` with a 2 MB payload each
//!      (generated at runtime, so the ingress stays small). Each call's
//!      `on_reject` handler replies with the reject code as a 4-byte LE integer.
//!      The 2 MB payloads fill the `S -> C` stream (`TARGET_STREAM_SIZE_BYTES`),
//!      so some calls reach the stream while the rest stay in `US`'s output queue.
//!   6. Delete `C`, unhalt `T`, check `UT`'s global data is still empty, and wait
//!      for all 10 calls from `US` to complete.
//!   7. Assert at least one call from `US` was rejected with `DestinationInvalid`
//!      (call did not reach the stream: no route after deletion) and at least one
//!      with `SysUnknown` (call reached the stream but `C` is gone, so the
//!      best-effort callback times out).

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
use ic_types::ingress::{IngressState, IngressStatus, WasmResult};
use ic_types::messages::MessageId;
use ic_types::{CanisterId, PrincipalId, RegistryVersion, SubnetId};
use ic_types_cycles::Cycles;
use ic_universal_canister::{UNIVERSAL_CANISTER_WASM, call_args, wasm};

const INITIAL_CYCLES_BALANCE: Cycles = Cycles::new(100_000_000_000_000);
const NUM_CALLS: usize = 10;
/// Payload size per `US -> UC` call. `2 MB` is below `MAX_INTER_CANISTER_PAYLOAD_IN_BYTES`
/// (`2 MiB`) and `5` such payloads exceed `TARGET_STREAM_SIZE_BYTES` (`10 MiB`),
/// so the `S -> C` stream fills up and only some of the calls reach it.
const PAYLOAD_SIZE: u32 = 2 * 1000 * 1000;
/// Best-effort call timeout. Chosen comfortably larger than the number of rounds
/// executed before deleting `C`, so that calls do not time out prematurely, yet
/// small enough to keep the post-deletion round count modest.
const CALL_TIMEOUT_SECS: u32 = 30;
const FIXED_BLOB: &[u8] = b"cloud-engine-test-fixed-blob";

/// Reject codes (see `ic_error_types::RejectCode`).
const DESTINATION_INVALID: u32 = 3;
const SYS_UNKNOWN: u32 = 6;

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

#[test]
fn xnet_messages_rejected_after_cloud_engine_subnet_deletion() {
    let user_id = PrincipalId::new_anonymous();

    // Set up a shared registry and three subnets: two application subnets S, T
    // and one CloudEngine subnet C.
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
        SubnetType::CloudEngine,
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

    // Step 1: Install universal canisters US on S, UT on T, UC on C.
    let us = install_universal_canister(&s);
    let ut = install_universal_canister(&t);
    let uc = install_universal_canister(&c);

    // Step 2: Halt subnet T by simply not executing any rounds on it from now on.

    // Step 3: Fire two fire-and-forget best-effort calls from UC to UT that would
    // set UT's global data to FIXED_BLOB. UC replies to its ingress immediately,
    // and the calls remain stuck in the C -> T stream (T is halted).
    for _ in 0..2 {
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
    }

    // Step 4: Halt subnet C by not executing any more rounds on it.

    // Step 5: Submit 10 best-effort calls from US to UC, each producing a 2 MB
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

    // Execute rounds on S until all calls have been performed by US (i.e. all
    // ingress messages are being processed, waiting for their callbacks). At this
    // point the S -> C stream has filled up to TARGET_STREAM_SIZE_BYTES and the
    // remaining calls stay in US's output queue.
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

    // Step 6a: Delete subnet C. We remove it from the shared pool of subnets
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

    // Step 6b: Unhalt subnet T and verify that it does not pull the messages from
    // the deleted CloudEngine subnet C: UT's global data must stay empty.
    for _ in 0..5 {
        t.execute_round();
    }
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

    // Step 6c: Drive S until all 10 calls from US complete. The calls still in
    // US's output queue are rejected with DestinationInvalid (no route to C),
    // while the calls already in the S -> C stream eventually time out with
    // SysUnknown (C is gone, so no response ever arrives).
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

    // Step 7: Assert that all calls were rejected and that both reject codes occur.
    let mut destination_invalid_count = 0_usize;
    let mut sys_unknown_count = 0_usize;
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
                    SYS_UNKNOWN => sys_unknown_count += 1,
                    other => panic!("unexpected reject code {other} from US -> UC call"),
                }
            }
            WasmResult::Reject(reject) => panic!("unexpected reject from US -> UC call: {reject}"),
        }
    }
    assert!(
        destination_invalid_count >= 1,
        "expected at least one DestinationInvalid rejection, got {destination_invalid_count}"
    );
    assert!(
        sys_unknown_count >= 1,
        "expected at least one SysUnknown rejection, got {sys_unknown_count}"
    );
}
