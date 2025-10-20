use canister_test::{Cycles, PrincipalId, Project};
use ic_state_machine_tests::two_subnets_simple;
use ic_types::ingress::{IngressState, IngressStatus, WasmResult};
use ic_types_test_utils::ids::canister_test_id;
use messaging_test::{Call, Message, decode, encode};
use messaging_test_utils::{arb_call, from_blob, to_encoded_ingress};
use proptest::prop_assert_eq;
use std::collections::{BTreeMap, VecDeque};

// Tests payloads can be encoded and decoded into the same message again while producing
/// payloads of the requested size (or larger where the target is too small).
#[test_strategy::proptest]
fn test_message_roundtrip_with_payload_size(
    #[strategy(arb_call(vec![canister_test_id(13), canister_test_id(17), canister_test_id(19)]))]
    call: Call,
) {
    let test_message = Message {
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
    let (decoded_test_message, blob_size_bytes_, payload_size_bytes_) = decode::<Message>(blob);
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

    let mut msg_ids = VecDeque::new();

    // A call to be sent to `canister1` as an ingress that then calls `canister3`
    // as a XNet inter canister call; that then makes a call to self.
    let (receiver, payload) = to_encoded_ingress(Call {
        receiver: canister1,
        call_bytes: 456,
        reply_bytes: 789,
        timeout_secs: None,
        downstream_calls: vec![Call {
            receiver: canister3,
            call_bytes: 654,
            reply_bytes: 987,
            timeout_secs: Some(10),
            downstream_calls: vec![Call {
                receiver: canister3,
                call_bytes: 123_456,
                reply_bytes: 654_321,
                timeout_secs: None,
                downstream_calls: vec![],
            }],
        }],
    });
    msg_ids.push_back(
        env1.submit_ingress_as(PrincipalId::new_anonymous(), receiver, "pulse", payload)
            .unwrap(),
    );

    // A call to be sent to `canister2` as an ingress that then calls `canister1`
    // on the same subnet.
    let (receiver, payload) = to_encoded_ingress(Call {
        receiver: canister2,
        call_bytes: 312,
        reply_bytes: 546,
        timeout_secs: Some(20),
        downstream_calls: vec![Call {
            receiver: canister1,
            call_bytes: 385_212,
            reply_bytes: 2,
            timeout_secs: None,
            downstream_calls: vec![],
        }],
    });
    msg_ids.push_back(
        env1.submit_ingress_as(PrincipalId::new_anonymous(), receiver, "pulse", payload)
            .unwrap(),
    );

    // Execute rounds and advance time until the results of both calls are in the ingress history.
    let mut responses = BTreeMap::new();
    for _ in 0..100 {
        env1.execute_round();
        env1.advance_time(std::time::Duration::from_secs(1));
        env2.execute_round();
        env2.advance_time(std::time::Duration::from_secs(1));

        let len = msg_ids.len();
        if len == 0 {
            break;
        }

        for _ in 0..len {
            let msg_id = msg_ids.pop_front().unwrap();
            match env1.ingress_status(&msg_id) {
                IngressStatus::Known {
                    state: IngressState::Completed(WasmResult::Reply(blob)),
                    ..
                } => assert!(responses.insert(msg_id, from_blob(blob)).is_none()),
                _ => msg_ids.push_back(msg_id),
            }
        }
    }

    // No hanging or unsuccessful calls after 100 rounds.
    assert_eq!(0, msg_ids.len());
}
