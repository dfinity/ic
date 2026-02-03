use ic_state_machine_tests::two_subnets_simple;
use ic_test_utilities_types::ids::user_test_id;
use ic_types::{
    Cycles,
    ingress::{IngressStatus, WasmResult},
};
use ic_universal_canister::{CallArgs, UNIVERSAL_CANISTER_WASM, wasm};

const INITIAL_CYCLES_BALANCE: Cycles = Cycles::new(100_000_000_000_000);

#[test]
fn counter_canister_call_test() {
    const MAX_TICKS: usize = 100;
    let user_id = user_test_id(1).get();

    let (env1, env2) = two_subnets_simple();

    // Create a canister on each of the two subnets.
    let canister_id1 = env1
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();
    let canister_id2 = env2
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();

    // Make a self-call with a large argument.
    let msg_id = env1
        .submit_ingress_as(
            user_id,
            canister_id1,
            "update",
            wasm()
                .inter_update(
                    canister_id1,
                    CallArgs::default().eval_other_side(
                        wasm()
                            .push_bytes_wasm_push_bytes_and_reply(10_000_000)
                            .build(),
                    ),
                )
                .build(),
        )
        .unwrap();
    env1.execute_round();
    let wasm_result = env1.await_ingress(msg_id, MAX_TICKS).unwrap();
    match wasm_result {
        WasmResult::Reply(bytes) => assert_eq!(bytes, 10_000_000_u32.to_le_bytes()),
        _ => panic!("unreachable"),
    };

    // Make a xnet-call with too large argument.
    let msg_id = env1
        .submit_ingress_as(
            user_id,
            canister_id1,
            "update",
            wasm()
                .inter_update(
                    canister_id2,
                    CallArgs::default().eval_other_side(
                        wasm()
                            .push_bytes_wasm_push_bytes_and_reply(10_000_000)
                            .build(),
                    ),
                )
                .build(),
        )
        .unwrap();
    env1.execute_round();
    let wasm_result = env1.await_ingress(msg_id, MAX_TICKS).unwrap();
    match wasm_result {
        // The call fails with CANISTER_ERROR reject code (5).
        WasmResult::Reject(reject) => assert_eq!(reject.as_bytes(), 5_u32.to_le_bytes().to_vec()),
        _ => panic!("unreachable"),
    };

    // Set global data on the 1st subnet.
    let msg1_id = env1
        .submit_ingress_as(
            user_id,
            canister_id1,
            "update",
            wasm()
                .set_global_data(&vec![42; 2000000])
                .get_global_data()
                .append_and_reply()
                .build(),
        )
        .unwrap();
    env1.execute_round();
    let wasm_result = env1.await_ingress(msg1_id, MAX_TICKS).unwrap();
    match wasm_result {
        WasmResult::Reply(bytes) => assert_eq!(bytes, vec![42; 2000000]),
        _ => panic!("unreachable"),
    };

    // Set global data on the 2nd subnet.
    let msg2_id = env2
        .submit_ingress_as(
            user_id,
            canister_id2,
            "update",
            wasm()
                .set_global_data(&vec![123; 2000000])
                .get_global_data()
                .append_and_reply()
                .build(),
        )
        .unwrap();
    env2.execute_round();
    let wasm_result = env2.await_ingress(msg2_id, MAX_TICKS).unwrap();
    match wasm_result {
        WasmResult::Reply(bytes) => assert_eq!(bytes, vec![123; 2000000]),
        _ => panic!("unreachable"),
    };

    // Invoke a method on the 1st subnet calling into the 2nd subnet.
    let msg3_id = env1
        .submit_ingress_as(
            user_id,
            canister_id1,
            "update",
            wasm()
                .inter_update(
                    canister_id2,
                    CallArgs::default().other_side(wasm().get_global_data().append_and_reply()),
                )
                .build(),
        )
        .unwrap();

    // We execute a round on the 1st subnet to start processing the ingress message,
    // then we execute a round on the 2nd subnet to process the downstream
    // inter-canister call, and finally we execute a round on the 1st subnet
    // to process the callback of the inter-canister call and finish processing
    // the ingress message.
    env1.execute_round();
    env2.execute_round();
    env1.execute_round();

    let wasm_result = env1.await_ingress(msg3_id, MAX_TICKS).unwrap();
    match wasm_result {
        WasmResult::Reply(bytes) => assert_eq!(bytes, vec![123; 2000000]),
        _ => panic!("unreachable"),
    };

    // Invoke a method on the 1st subnet calling into the 2nd subnet multiple times.
    let msg10_id = env1
        .submit_ingress_as(
            user_id,
            canister_id1,
            "update",
            wasm()
                .inter_update(
                    canister_id2,
                    CallArgs::default().other_side(
                        wasm()
                            .set_global_data(&vec![0; 2000000])
                            .get_global_data()
                            .append_and_reply(),
                    ),
                )
                .build(),
        )
        .unwrap();
    let msg11_id = env1
        .submit_ingress_as(
            user_id,
            canister_id1,
            "update",
            wasm()
                .inter_update(
                    canister_id2,
                    CallArgs::default().other_side(
                        wasm()
                            .set_global_data(&vec![1; 2000000])
                            .get_global_data()
                            .append_and_reply(),
                    ),
                )
                .build(),
        )
        .unwrap();
    let msg12_id = env1
        .submit_ingress_as(
            user_id,
            canister_id1,
            "update",
            wasm()
                .inter_update(
                    canister_id2,
                    CallArgs::default().other_side(
                        wasm()
                            .set_global_data(&vec![2; 2000000])
                            .get_global_data()
                            .append_and_reply(),
                    ),
                )
                .build(),
        )
        .unwrap();

    // Invoke a method on the 2nd subnet calling into the 1st subnet.
    let msg20_id = env2
        .submit_ingress_as(
            user_id,
            canister_id2,
            "update",
            wasm()
                .inter_update(
                    canister_id1,
                    CallArgs::default().other_side(
                        wasm()
                            .set_global_data(&vec![3; 2000000])
                            .get_global_data()
                            .append_and_reply(),
                    ),
                )
                .build(),
        )
        .unwrap();

    // This time we need to execute multiple rounds on the 1st subnet
    // to induct all ingress messages with large payloads.
    env1.execute_round();
    let known_count = [&msg10_id, &msg11_id, &msg12_id]
        .into_iter()
        .filter(|&msg_id| matches!(env1.ingress_status(msg_id), IngressStatus::Known { .. }))
        .count();
    assert_eq!(2, known_count);

    // The third ingress message is only inducted after a repeated
    // call to execute a round.
    env1.execute_round();
    assert!(matches!(
        (
            env1.ingress_status(&msg10_id),
            env1.ingress_status(&msg11_id),
            env1.ingress_status(&msg12_id)
        ),
        (
            IngressStatus::Known { .. },
            IngressStatus::Known { .. },
            IngressStatus::Known { .. }
        )
    ));

    // We also need execute to multiple rounds on the 2nd subnet
    // to induct the ingress message with large payload
    // and all three inter-canister calls with large arguments
    // from the 1st subnet.
    env2.execute_round();
    assert!(matches!(
        env2.ingress_status(&msg20_id),
        IngressStatus::Known { .. }
    ));
    env2.execute_round();
    env2.execute_round();
    // Finally, we need to execute multiple rounds on the 1st subnet
    // to induct all (large) responses from the 2nd subnet
    // and an inter-canister call from the 2nd into the 1st subnet
    // with large argument.
    env1.execute_round();
    env1.execute_round();
    env1.execute_round();
    env1.execute_round();

    let wasm_result = env1.await_ingress(msg10_id, MAX_TICKS).unwrap();
    match wasm_result {
        WasmResult::Reply(bytes) => assert_eq!(bytes, vec![0; 2000000]),
        _ => panic!("unreachable"),
    };
    let wasm_result = env1.await_ingress(msg11_id, MAX_TICKS).unwrap();
    match wasm_result {
        WasmResult::Reply(bytes) => assert_eq!(bytes, vec![1; 2000000]),
        _ => panic!("unreachable"),
    };
    let wasm_result = env1.await_ingress(msg12_id, MAX_TICKS).unwrap();
    match wasm_result {
        WasmResult::Reply(bytes) => assert_eq!(bytes, vec![2; 2000000]),
        _ => panic!("unreachable"),
    };

    // This time, we also need to execute one more round on the 2nd subnet
    // to process the response callback of the inter-canister call
    // to the 1st subnet.
    env2.execute_round();

    let wasm_result = env2.await_ingress(msg20_id, MAX_TICKS).unwrap();
    match wasm_result {
        WasmResult::Reply(bytes) => assert_eq!(bytes, vec![3; 2000000]),
        _ => panic!("unreachable"),
    };
}
