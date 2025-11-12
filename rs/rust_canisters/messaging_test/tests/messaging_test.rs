use assert_matches::assert_matches;
use canister_test::{Cycles, PrincipalId, Project};
use ic_state_machine_tests::two_subnets_simple;
use ic_types::{
    CanisterId,
    ingress::{IngressState, IngressStatus, WasmResult},
};
use ic_types_test_utils::ids::canister_test_id;
use messaging_test::{Call, CallMessage, Reply, decode, encode};
use messaging_test_utils::{CallConfig, arb_call, from_blob, to_encoded_ingress};
use proptest::prop_assert_eq;

// Tests payloads can be encoded and decoded into the same message again while producing
/// payloads of the requested size (or larger where the target is too small).
#[test_strategy::proptest]
fn test_message_roundtrip_with_payload_size(
    #[strategy(arb_call(
        canister_test_id(13),
        CallConfig {
            receivers: vec![canister_test_id(13), canister_test_id(17), canister_test_id(19)],
            ..CallConfig::default()
        }
    ))]
    call: Call,
) {
    let test_message = CallMessage {
        call_index: 23,
        reply_bytes: call.reply_bytes,
        downstream_calls: call.downstream_calls,
    };

    let (blob, payload_size_bytes) = encode(&test_message, call.call_bytes as usize);

    // A payload has this structure [u32 ; candid ; padding] where the u32 is the number of
    // bytes in the contained candid encoded payload.
    if call.call_bytes > payload_size_bytes + 4 {
        // The requested size bytes should be met exactly with an added padding.
        prop_assert_eq!(call.call_bytes, blob.len() as u32);
    } else {
        // For a requested size bytes below what is possible, there should be no padding.
        prop_assert_eq!(payload_size_bytes + 4, blob.len() as u32);
    }

    // Check the roundtrip yields the same message and size bytes information.
    let blob_size_bytes = blob.len();
    let (decoded_test_message, blob_size_bytes_, payload_size_bytes_) = decode::<CallMessage>(blob);
    prop_assert_eq!(test_message, decoded_test_message);
    prop_assert_eq!(blob_size_bytes as u32, blob_size_bytes_);
    prop_assert_eq!(payload_size_bytes, payload_size_bytes_);
}

/// Tests traffic between canisters works as intended without triggering any traps and that
/// the instructions are adhered to faithfully.
#[test]
fn smoke_test() {
    let (env1, env2) = two_subnets_simple();
    let wasm = Project::cargo_bin_maybe_from_env("messaging-test-canister", &[]).bytes();

    let canister1 = env1
        .install_canister_with_cycles(wasm.clone(), Vec::new(), None, Cycles::new(u128::MAX / 2))
        .expect("Installing messaging-test-canister failed");
    let canister2 = env1
        .install_canister_with_cycles(wasm.clone(), Vec::new(), None, Cycles::new(u128::MAX / 2))
        .expect("Installing messaging-test-canister failed");
    let canister3 = env2
        .install_canister_with_cycles(wasm.clone(), Vec::new(), None, Cycles::new(u128::MAX / 2))
        .expect("Installing messaging-test-canister failed");

    // A call to be sent to `canister1` as an ingress that then calls `canister3`
    // as a XNet inter canister call; that then makes a call to self.
    let (receiver, payload) = to_encoded_ingress(Call {
        receiver: canister1.into(),
        call_bytes: 456,
        reply_bytes: 789,
        cycles: 1_000_000_000_000,
        timeout_secs: None,
        downstream_calls: vec![Call {
            receiver: canister3.into(),
            call_bytes: 654,
            reply_bytes: 987,
            cycles: 1_000_000_000,
            timeout_secs: Some(10),
            downstream_calls: vec![Call {
                receiver: canister3.into(),
                call_bytes: 123_456,
                reply_bytes: 654_321,
                cycles: 0,
                timeout_secs: None,
                downstream_calls: vec![],
            }],
        }],
    });
    let msg_id1 = env1
        .submit_ingress_as(
            PrincipalId::new_anonymous(),
            receiver,
            "handle_call",
            payload,
        )
        .unwrap();

    // A call to be sent to `canister2` as an ingress that then calls `canister1`
    // on the same subnet.
    let (receiver, payload) = to_encoded_ingress(Call {
        receiver: canister2.into(),
        call_bytes: 312,
        reply_bytes: 546,
        cycles: 500_000_000,
        timeout_secs: Some(20),
        downstream_calls: vec![Call {
            receiver: canister1.into(),
            call_bytes: 385_212,
            reply_bytes: 2,
            cycles: 0,
            timeout_secs: None,
            downstream_calls: vec![],
        }],
    });
    let msg_id2 = env1
        .submit_ingress_as(
            PrincipalId::new_anonymous(),
            receiver,
            "handle_call",
            payload,
        )
        .unwrap();

    // Executing 20 rounds should plenty for these two calls to conclude.
    for _ in 0..20 {
        env1.execute_round();
        env1.advance_time(std::time::Duration::from_secs(1));
        env2.execute_round();
        env2.advance_time(std::time::Duration::from_secs(1));
    }

    // Check the reply to the first call.
    match env1.ingress_status(&msg_id1) {
        IngressStatus::Known {
            receiver,
            state: IngressState::Completed(WasmResult::Reply(blob)),
            ..
        } => {
            from_blob(CanisterId::unchecked_from_principal(receiver), blob).for_each_depth_first(
                &|reply, _| {
                    assert_matches!(reply, Reply::Success { .. });
                },
            );
        }
        _ => unreachable!("the first call did not conclude successfully"),
    }

    // Check the reply to the second call.
    match env1.ingress_status(&msg_id2) {
        IngressStatus::Known {
            receiver,
            state: IngressState::Completed(WasmResult::Reply(blob)),
            ..
        } => {
            from_blob(CanisterId::unchecked_from_principal(receiver), blob).for_each_depth_first(
                &|reply, _| {
                    assert_matches!(reply, Reply::Success { .. });
                },
            );
        }
        _ => unreachable!("the second call did not conclude successfully"),
    }
}
