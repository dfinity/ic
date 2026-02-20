use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_management_canister_types_private::{CanisterIdRecord, Payload};
use ic_registry_routing_table::{CANISTER_IDS_PER_SUBNET, CanisterIdRange, RoutingTable};
use ic_state_machine_tests::{StateMachine, StateMachineBuilder};
use ic_types::Cycles;
use ic_types::ingress::{IngressState, IngressStatus, WasmResult};
use ic_types::messages::MessageId;
use ic_universal_canister::{CallArgs, UNIVERSAL_CANISTER_WASM, wasm};

const INITIAL_CYCLES_BALANCE: Cycles = Cycles::new(100_000_000_000_000);

struct Env {
    sm: StateMachine,
    canister_id: CanisterId,
    remote_canister_id: CanisterId,
}

fn setup() -> Env {
    // Create a `StateMachine` with a routing table of the form:
    // - "local" (the `StateMachine`): (0, CANISTER_IDS_PER_SUBNET - 1),
    // - "remote" (in this test non-existent): (CANISTER_IDS_PER_SUBNET, 2 * CANISTER_IDS_PER_SUBNET - 1).
    let mut routing_table = RoutingTable::new();
    // use a subnet ID of length 29 (as in production)
    // so that it does not resemble a canister ID
    let subnet_id_slice: &[u8] = &[42; 29];
    let subnet_id_principal: PrincipalId = subnet_id_slice.try_into().unwrap();
    let subnet_id = SubnetId::from(subnet_id_principal);
    let canister_id_range = CanisterIdRange {
        start: CanisterId::from_u64(0),
        end: CanisterId::from_u64(CANISTER_IDS_PER_SUBNET - 1),
    };
    routing_table.insert(canister_id_range, subnet_id).unwrap();
    // use a subnet ID of length 29 (as in production)
    // so that it does not resemble a canister ID
    let remote_subnet_id_slice: &[u8] = &[64; 29];
    let remote_subnet_id_principal: PrincipalId = remote_subnet_id_slice.try_into().unwrap();
    let remote_subnet_id = SubnetId::from(remote_subnet_id_principal);
    let remote_canister_id_range = CanisterIdRange {
        start: CanisterId::from_u64(CANISTER_IDS_PER_SUBNET),
        end: CanisterId::from_u64(2 * CANISTER_IDS_PER_SUBNET - 1),
    };
    let remote_canister_id = remote_canister_id_range.start;
    routing_table
        .insert(remote_canister_id_range, remote_subnet_id)
        .unwrap();
    let sm = StateMachineBuilder::new()
        .with_routing_table(routing_table)
        .with_subnet_id(subnet_id)
        .build();

    // Deploy a universal canister to the `StateMachine` acting as the main canister under test.
    let canister_id = sm
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();

    Env {
        sm,
        canister_id,
        remote_canister_id,
    }
}

fn assert_processing(sm: &StateMachine, msg_id: &MessageId) {
    let ingress_status = sm.ingress_status(msg_id);
    assert!(matches!(
        ingress_status,
        IngressStatus::Known {
            state: IngressState::Processing,
            ..
        }
    ));
}

fn wasm_result(sm: &StateMachine, msg_id: &MessageId) -> WasmResult {
    let ingress_status = sm.ingress_status(msg_id);
    match ingress_status {
        IngressStatus::Known {
            state: IngressState::Completed(res),
            ..
        } => res,
        _ => panic!("Unexpected ingress status: {:?}", ingress_status),
    }
}

#[test]
fn reject_remote_callbacks() {
    let Env {
        sm,
        canister_id,
        remote_canister_id,
    } = setup();

    // Send an ingress message to the main canister
    // that calls a "remote" (in this test non-existent) canister.
    let remote_payload = wasm()
        .inter_update(
            remote_canister_id,
            CallArgs::default().on_reject(
                wasm()
                    .reject_code()
                    .int_to_blob()
                    .reject_message()
                    .concat()
                    .reject()
                    .build(),
            ),
        )
        .build();
    let remote_msg_id = sm.send_ingress(
        PrincipalId::new_anonymous(),
        canister_id,
        "update",
        remote_payload,
    );

    // Send an ingress message to stop the main canister.
    let stop_msg_id = sm.send_ingress(
        PrincipalId::new_anonymous(),
        CanisterId::ic_00(),
        "stop_canister",
        (CanisterIdRecord::from(canister_id)).encode(),
    );

    for _ in 0..100 {
        sm.tick();
    }

    // The main canister could not be stopped yet due to the outstanding callback.
    for msg_id in [&stop_msg_id, &remote_msg_id] {
        assert_processing(&sm, msg_id);
    }

    // Now we reject remote callbacks and confirm that the expected reject was observed by the main canister.
    sm.reject_remote_callbacks();
    // We reject remote callbacks twice in a row to confirm that this operation is idempotent.
    sm.reject_remote_callbacks();
    sm.tick();

    let mut expected_reject = 2_u32.to_le_bytes().to_vec();
    expected_reject.extend_from_slice("Remote callback rejected by StateMachine test.".as_bytes());
    assert!(
        matches!(wasm_result(&sm, &remote_msg_id), WasmResult::Reject(reject) if reject == String::from_utf8(expected_reject).unwrap())
    );

    // The main canister should be stopped by now.
    assert!(matches!(
        wasm_result(&sm, &stop_msg_id),
        WasmResult::Reply(_)
    ));
}

#[test]
fn reject_remote_callbacks_preserves_local_calls() {
    let Env {
        sm,
        canister_id,
        remote_canister_id: _,
    } = setup();

    // Deploy another universal canister acting as a "local" callee for the main canister under test.
    let callee_canister_id = sm
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();

    // Send an ingress message to the main canister
    // that calls a "local" canister.
    // The "local" canister performs heavy computation so that
    // the "local" call is "hanging" for many rounds.
    let local_payload = wasm()
        .inter_update(
            callee_canister_id,
            CallArgs::default().other_side(
                wasm()
                    .instruction_counter_is_at_least(38_000_000_000)
                    .reply_data("Made it!".as_bytes())
                    .build(),
            ),
        )
        .build();
    let local_msg_id = sm.send_ingress(
        PrincipalId::new_anonymous(),
        canister_id,
        "update",
        local_payload,
    );

    for _ in 0..5 {
        sm.tick();
    }

    // The "local" call should be still processing.
    assert_processing(&sm, &local_msg_id);

    // Now we reject remote callbacks and confirm that the "local" call is still processing.
    sm.reject_remote_callbacks();
    sm.tick();

    assert_processing(&sm, &local_msg_id);

    // Eventually the local callback should return.
    for _ in 0..100 {
        sm.tick();
    }

    assert!(
        matches!(wasm_result(&sm, &local_msg_id), WasmResult::Reply(reply) if reply == "Made it!".as_bytes())
    );
}

#[test]
fn reject_remote_callbacks_preserves_local_mgmt_canister_calls() {
    let Env {
        sm,
        canister_id,
        remote_canister_id: _,
    } = setup();

    // Send an ingress message to the main canister
    // that calls the "local" management canister.
    let mgmt_payload: CanisterIdRecord = canister_id.into();
    let local_payload = wasm()
        .call_simple(
            CanisterId::ic_00(),
            "canister_status",
            CallArgs::default().other_side(mgmt_payload.encode()),
        )
        .build();
    let local_msg_id = sm.send_ingress(
        PrincipalId::new_anonymous(),
        canister_id,
        "update",
        local_payload,
    );

    // The "local" call should be still processing.
    assert_processing(&sm, &local_msg_id);

    // Now we reject remote callbacks and confirm that the "local" call is still processing.
    sm.reject_remote_callbacks();
    sm.tick();

    assert_processing(&sm, &local_msg_id);

    // Eventually the local callback should return.
    for _ in 0..100 {
        sm.tick();
    }

    assert!(matches!(
        wasm_result(&sm, &local_msg_id),
        WasmResult::Reply(_)
    ));
}
