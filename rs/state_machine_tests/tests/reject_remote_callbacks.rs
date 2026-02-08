use ic_base_types::{CanisterId, PrincipalId};
use ic_management_canister_types_private::{CanisterIdRecord, Payload};
use ic_registry_routing_table::{CANISTER_IDS_PER_SUBNET, CanisterIdRange, RoutingTable};
use ic_state_machine_tests::StateMachineBuilder;
use ic_test_utilities_types::ids::subnet_test_id;
use ic_types::Cycles;
use ic_types::ingress::{IngressState, IngressStatus, WasmResult};
use ic_universal_canister::{CallArgs, UNIVERSAL_CANISTER_WASM, wasm};

const INITIAL_CYCLES_BALANCE: Cycles = Cycles::new(100_000_000_000_000);

#[test]
fn reject_remote_callbacks() {
    // Create a `StateMachine` with a routing table of the form:
    // - "local" (the `StateMachine`): (0, CANISTER_IDS_PER_SUBNET - 1),
    // - "remote" (in this test non-existent): (CANISTER_IDS_PER_SUBNET, 2 * CANISTER_IDS_PER_SUBNET - 1).
    let mut routing_table = RoutingTable::new();
    let subnet_id = subnet_test_id(0);
    let canister_id_range = CanisterIdRange {
        start: CanisterId::from_u64(0),
        end: CanisterId::from_u64(CANISTER_IDS_PER_SUBNET - 1),
    };
    routing_table.insert(canister_id_range, subnet_id).unwrap();
    let remote_subnet_id = subnet_test_id(1);
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

    // Deploy two universal canisters to the `StateMachine`:
    // - one acting as the main canister under test;
    // - another one acting as a "local" callee for the main canister under test.
    let canister_id = sm
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();
    let callee_canister_id = sm
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();

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

    // Send an ingress message to stop the main canister.
    let stop_msg_id = sm.send_ingress(
        PrincipalId::new_anonymous(),
        CanisterId::ic_00(),
        "stop_canister",
        (CanisterIdRecord::from(canister_id)).encode(),
    );

    for _ in 0..5 {
        sm.tick();
    }

    // The main canister could not be stopped due to the outstanding (local and remote) callbacks.
    let assert_processing = |msg_id| {
        let ingress_status = sm.ingress_status(msg_id);
        assert!(matches!(
            ingress_status,
            IngressStatus::Known {
                state: IngressState::Processing,
                ..
            }
        ));
    };

    for msg_id in [&stop_msg_id, &local_msg_id, &remote_msg_id] {
        assert_processing(msg_id);
    }

    // Now we reject remote callbacks and confirm that the expected reject was observed by the main canister.
    sm.reject_remote_callbacks();
    sm.tick();

    let wasm_result = |msg_id| {
        let ingress_status = sm.ingress_status(msg_id);
        match ingress_status {
            IngressStatus::Known {
                state: IngressState::Completed(res),
                ..
            } => res,
            _ => panic!("Unexpected ingress status: {:?}", ingress_status),
        }
    };

    let mut expected_reject = 2_u32.to_le_bytes().to_vec();
    expected_reject.extend_from_slice("Remote callback rejected by StateMachine test.".as_bytes());
    assert!(
        matches!(wasm_result(&remote_msg_id), WasmResult::Reject(reject) if reject == String::from_utf8(expected_reject).unwrap())
    );

    // The local callback should still be pending.
    for msg_id in [&stop_msg_id, &local_msg_id] {
        assert_processing(msg_id);
    }

    // Eventually the local callback should return and the main canister should stop.
    for _ in 0..100 {
        sm.tick();
    }

    for msg_id in [&stop_msg_id, &local_msg_id] {
        assert!(matches!(wasm_result(msg_id), WasmResult::Reply(_)));
    }
    assert!(
        matches!(wasm_result(&local_msg_id), WasmResult::Reply(reply) if reply == "Made it!".as_bytes())
    );
}
