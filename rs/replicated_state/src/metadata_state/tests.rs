use super::*;
use crate::metadata_state::subnet_call_context_manager::SubnetCallContextManager;
use ic_base_types::HttpMethodType;
use ic_test_utilities::{
    mock_time,
    types::{
        ids::{canister_test_id, message_test_id, user_test_id, SUBNET_1},
        messages::RequestBuilder,
    },
    types::{
        ids::{SUBNET_0, SUBNET_2},
        messages::ResponseBuilder,
    },
};
use ic_types::{
    canister_http::CanisterHttpRequestContext,
    ingress::{WasmResult, MAX_INGRESS_TTL},
    messages::{CallbackId, Payload},
};

#[test]
fn can_prune_old_ingress_history_entries() {
    let mut ingress_history = IngressHistoryState::new();

    let message_id1 = MessageId::from([1_u8; 32]);
    let message_id2 = MessageId::from([2_u8; 32]);
    let message_id3 = MessageId::from([3_u8; 32]);

    let time = mock_time();
    ingress_history.insert(
        message_id1.clone(),
        IngressStatus::Completed {
            receiver: canister_test_id(1).get(),
            user_id: user_test_id(1),
            result: WasmResult::Reply(vec![]),
            time: mock_time(),
        },
        time,
    );
    ingress_history.insert(
        message_id2.clone(),
        IngressStatus::Completed {
            receiver: canister_test_id(2).get(),
            user_id: user_test_id(2),
            result: WasmResult::Reply(vec![]),
            time: mock_time(),
        },
        time,
    );
    ingress_history.insert(
        message_id3.clone(),
        IngressStatus::Completed {
            receiver: canister_test_id(1).get(),
            user_id: user_test_id(1),
            result: WasmResult::Reply(vec![]),
            time: mock_time(),
        },
        time + MAX_INGRESS_TTL / 2,
    );

    // Pretend that the time has advanced
    let time = time + MAX_INGRESS_TTL + std::time::Duration::from_secs(10);

    ingress_history.prune(time);
    assert!(ingress_history.get(&message_id1).is_none());
    assert!(ingress_history.get(&message_id2).is_none());
    assert!(ingress_history.get(&message_id3).is_some());
}

#[test]
fn entries_sorted_lexicographically() {
    let mut ingress_history = IngressHistoryState::new();
    let time = mock_time();

    for i in (0..10u64).rev() {
        ingress_history.insert(
            message_test_id(i),
            IngressStatus::Received {
                receiver: canister_test_id(1).get(),
                user_id: user_test_id(1),
                time,
            },
            time,
        );
    }
    let mut expected: Vec<_> = (0..10u64).map(message_test_id).collect();
    expected.sort();

    let actual: Vec<_> = ingress_history
        .statuses()
        .map(|(id, _)| id.clone())
        .collect();

    assert_eq!(actual, expected);
}

#[test]
fn streams_stats() {
    // Two local canisters, `local_a` and `local_b`.
    let local_a = canister_test_id(1);
    let local_b = canister_test_id(2);
    // Two remote canisters, `remote_1` on `SUBNET_1` and `remote_2` on `SUBNET_2`.
    let remote_1 = canister_test_id(3);
    let remote_2 = canister_test_id(4);

    fn request(sender: CanisterId, receiver: CanisterId) -> RequestOrResponse {
        RequestBuilder::default()
            .sender(sender)
            .receiver(receiver)
            .build()
            .into()
    }
    fn response(
        respondent: CanisterId,
        originator: CanisterId,
        payload: &str,
    ) -> (RequestOrResponse, usize) {
        let rep: RequestOrResponse = ResponseBuilder::default()
            .respondent(respondent)
            .originator(originator)
            .response_payload(Payload::Data(payload.as_bytes().to_vec()))
            .build()
            .into();
        let req_bytes = rep.count_bytes();
        (rep, req_bytes)
    }

    // A bunch of requests and responses from local canisters to remote ones.
    let req_a1 = request(local_a, remote_1);
    let (rep_a1, rep_a1_size) = response(local_a, remote_1, "a");
    let (rep_b1, rep_b1_size) = response(local_b, remote_1, "bb");
    let (rep_b2, rep_b2_size) = response(local_b, remote_2, "ccc");

    let mut streams = Streams::new();
    // Empty response size map.
    let mut expected_responses_size = Default::default();
    assert_eq!(streams.responses_size_bytes(), &expected_responses_size);

    streams.push(SUBNET_1, req_a1);
    // Pushed a request, response size stats are unchanged.
    assert_eq!(streams.responses_size_bytes(), &expected_responses_size);

    // Push response via `Streams::push()`.
    streams.push(SUBNET_1, rep_a1);
    // `rep_a1` is now accounted for against `local_a`.
    expected_responses_size.insert(local_a, rep_a1_size);
    assert_eq!(streams.responses_size_bytes(), &expected_responses_size);

    // Push response via `StreamHandle::push()`.
    streams.get_mut(&SUBNET_1).unwrap().push(rep_b1);
    // `rep_b1` is accounted for against `local_b`.
    expected_responses_size.insert(local_b, rep_b1_size);
    assert_eq!(streams.responses_size_bytes(), &expected_responses_size);

    // Push response via `StreamHandle::push()` after `get_mut_or_insert()`.
    streams.get_mut_or_insert(SUBNET_2).push(rep_b2);
    // `rep_b2` is accounted for against `local_b`.
    *expected_responses_size.get_mut(&local_b).unwrap() += rep_b2_size;
    assert_eq!(streams.responses_size_bytes(), &expected_responses_size);

    // Discard `req_a1` and `rep_a1` from the stream for `SUBNET_1`.
    streams.get_mut(&SUBNET_1).unwrap().discard_before(2.into());
    // No more responses from `local_a` in `streams`.
    expected_responses_size.remove(&local_a);
    assert_eq!(streams.responses_size_bytes(), &expected_responses_size);

    // Discard `rep_b2` from the stream for `SUBNET_2`.
    streams.get_mut(&SUBNET_2).unwrap().discard_before(1.into());
    // `rep_b2` is gone.
    *expected_responses_size.get_mut(&local_b).unwrap() -= rep_b2_size;
    assert_eq!(streams.responses_size_bytes(), &expected_responses_size);
}

#[test]
fn streams_stats_after_deserialization() {
    let mut system_metadata = SystemMetadata::new(SUBNET_0, SubnetType::Application);
    let streams = Arc::make_mut(&mut system_metadata.streams);

    streams.push(
        SUBNET_1,
        ResponseBuilder::default()
            .respondent(canister_test_id(1))
            .originator(canister_test_id(2))
            .build()
            .into(),
    );

    let system_metadata_proto: ic_protobuf::state::system_metadata::v1::SystemMetadata =
        (&system_metadata).into();
    let deserialized_system_metadata = system_metadata_proto.try_into().unwrap();

    // Ensure that the deserialized `SystemMetadata` is equal to the original.
    assert_eq!(system_metadata, deserialized_system_metadata);
    // Double-check that the stats match.
    assert_eq!(
        system_metadata.streams.responses_size_bytes(),
        deserialized_system_metadata.streams.responses_size_bytes()
    );
}

#[test]
fn subnet_call_contexts_deserialization() {
    let url = "https://".to_string();
    let transform_method_name = Some("transform".to_string());
    let mut system_call_context_manager = SubnetCallContextManager::default();

    let canister_http_request = CanisterHttpRequestContext {
        request: RequestBuilder::default()
            .sender(canister_test_id(1))
            .receiver(canister_test_id(2))
            .build(),
        url: url.clone(),
        body: None,
        http_method: HttpMethodType::GET,
        transform_method_name: transform_method_name.clone(),
        time: mock_time(),
    };
    system_call_context_manager.push_http_request(canister_http_request);

    let system_call_context_manager_proto: ic_protobuf::state::system_metadata::v1::SubnetCallContextManager = (&system_call_context_manager).into();
    let deserialized_system_call_context_manager: SubnetCallContextManager =
        system_call_context_manager_proto.try_into().unwrap();

    assert_eq!(
        deserialized_system_call_context_manager
            .canister_http_request_contexts
            .len(),
        1
    );

    let deserialized_http_request_context = deserialized_system_call_context_manager
        .canister_http_request_contexts
        .get(&CallbackId::from(0))
        .unwrap();
    assert_eq!(deserialized_http_request_context.url, url);
    assert_eq!(
        deserialized_http_request_context.http_method,
        HttpMethodType::GET
    );
    assert_eq!(
        deserialized_http_request_context.transform_method_name,
        transform_method_name
    );
}
