use super::*;
use crate::metadata_state::subnet_call_context_manager::SubnetCallContextManager;
use ic_constants::MAX_INGRESS_TTL;
use ic_error_types::{ErrorCode, UserError};
use ic_ic00_types::EcdsaCurve;
use ic_registry_routing_table::CanisterIdRange;
use ic_test_utilities::{
    mock_time,
    types::{
        ids::{
            canister_test_id, message_test_id, subnet_test_id, user_test_id, SUBNET_0, SUBNET_1,
            SUBNET_2,
        },
        messages::{RequestBuilder, ResponseBuilder},
        xnet::{StreamHeaderBuilder, StreamSliceBuilder},
    },
};
use ic_types::{
    canister_http::{CanisterHttpMethod, CanisterHttpRequestContext},
    ingress::WasmResult,
    messages::{CallbackId, Payload},
};
use lazy_static::lazy_static;
use maplit::btreemap;
use std::str::FromStr;

lazy_static! {
    static ref LOCAL_CANISTER: CanisterId = CanisterId::from(0x34);
    static ref REMOTE_CANISTER: CanisterId = CanisterId::from(0x134);
}

fn make_key_id() -> EcdsaKeyId {
    EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: "secp256k1".to_string(),
    }
}

#[test]
fn can_prune_old_ingress_history_entries() {
    let mut ingress_history = IngressHistoryState::new();

    let message_id1 = MessageId::from([1_u8; 32]);
    let message_id2 = MessageId::from([2_u8; 32]);
    let message_id3 = MessageId::from([3_u8; 32]);

    let time = mock_time();
    ingress_history.insert(
        message_id1.clone(),
        IngressStatus::Known {
            receiver: canister_test_id(1).get(),
            user_id: user_test_id(1),
            time: mock_time(),
            state: IngressState::Completed(WasmResult::Reply(vec![])),
        },
        time,
        NumBytes::from(u64::MAX),
    );
    ingress_history.insert(
        message_id2.clone(),
        IngressStatus::Known {
            receiver: canister_test_id(2).get(),
            user_id: user_test_id(2),
            time: mock_time(),
            state: IngressState::Completed(WasmResult::Reply(vec![])),
        },
        time,
        NumBytes::from(u64::MAX),
    );
    ingress_history.insert(
        message_id3.clone(),
        IngressStatus::Known {
            receiver: canister_test_id(1).get(),
            user_id: user_test_id(1),
            time: mock_time(),
            state: IngressState::Completed(WasmResult::Reply(vec![])),
        },
        time + MAX_INGRESS_TTL / 2,
        NumBytes::from(u64::MAX),
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
            IngressStatus::Known {
                receiver: canister_test_id(1).get(),
                user_id: user_test_id(1),
                time,
                state: IngressState::Received,
            },
            time,
            NumBytes::from(u64::MAX),
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
    streams
        .get_mut(&SUBNET_1)
        .unwrap()
        .discard_messages_before(2.into(), &Default::default());
    // No more responses from `local_a` in `streams`.
    expected_responses_size.remove(&local_a);
    assert_eq!(streams.responses_size_bytes(), &expected_responses_size);

    // Discard `rep_b2` from the stream for `SUBNET_2`.
    streams
        .get_mut(&SUBNET_2)
        .unwrap()
        .discard_messages_before(1.into(), &Default::default());
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
fn init_allocation_ranges_if_empty() {
    let own_subnet_id = SUBNET_0;
    let routing_table = Arc::new(
        RoutingTable::try_from(btreemap! {
            // Valid range, but not last one.
            CanisterIdRange{ start: CanisterId::from(CANISTER_IDS_PER_SUBNET), end: CanisterId::from(2 * CANISTER_IDS_PER_SUBNET - 1) } => own_subnet_id,
            // Valid range, this is what we're looking for.
            CanisterIdRange{ start: CanisterId::from(3 * CANISTER_IDS_PER_SUBNET), end: CanisterId::from(4 * CANISTER_IDS_PER_SUBNET - 1) } => own_subnet_id,
            // Doesn't start at boundary.
            CanisterIdRange{ start: CanisterId::from(5 * CANISTER_IDS_PER_SUBNET + 1), end: CanisterId::from(6 * CANISTER_IDS_PER_SUBNET - 1) } => own_subnet_id,
            // Doesn't end at boundary.
            CanisterIdRange{ start: CanisterId::from(7 * CANISTER_IDS_PER_SUBNET), end: CanisterId::from(8 * CANISTER_IDS_PER_SUBNET) } => own_subnet_id,
            // Spans 2 * CANISTER_IDS_PER_SUBNET.
            CanisterIdRange{ start: CanisterId::from(9 * CANISTER_IDS_PER_SUBNET), end: CanisterId::from(11 * CANISTER_IDS_PER_SUBNET - 1) } => own_subnet_id,
        })
        .unwrap(),
    );
    let network_topology = NetworkTopology {
        subnets: BTreeMap::new(),
        routing_table,
        canister_migrations: Arc::new(CanisterMigrations::default()),
        nns_subnet_id: subnet_test_id(42),
        ecdsa_signing_subnets: Default::default(),
    };

    let mut system_metadata = SystemMetadata::new(own_subnet_id, SubnetType::Application);
    system_metadata.network_topology = network_topology;

    assert_eq!(
        CanisterIdRanges::try_from(vec![]).unwrap(),
        system_metadata.canister_allocation_ranges
    );
    assert_eq!(None, system_metadata.last_generated_canister_id);

    // Pretend we've fully consumed the first routing table range and generated
    // 13 canister IDs from the second routing table range already.
    system_metadata.generated_id_counter = CANISTER_IDS_PER_SUBNET + 13;

    system_metadata.init_allocation_ranges_if_empty().unwrap();

    assert_eq!(
        CanisterIdRanges::try_from(vec![CanisterIdRange {
            start: CanisterId::from(3 * CANISTER_IDS_PER_SUBNET),
            end: CanisterId::from(4 * CANISTER_IDS_PER_SUBNET - 1)
        }])
        .unwrap(),
        system_metadata.canister_allocation_ranges
    );
    assert_eq!(
        Some(CanisterId::from(3 * CANISTER_IDS_PER_SUBNET + 12)),
        system_metadata.last_generated_canister_id
    );
}

#[test]
fn generate_new_canister_id_no_allocation_ranges() {
    let mut system_metadata = SystemMetadata::new(SUBNET_0, SubnetType::Application);

    assert_eq!(
        Err("Canister ID allocation was consumed".into()),
        system_metadata.generate_new_canister_id()
    );
    assert_eq!(None, system_metadata.last_generated_canister_id);
}

/// Tests that canister IDs are actually generated from the ranges:
/// ```
///     (canister_allocation_ranges
///          ∩ routing_table.ranges(own_subnet_id))
///          \ canister_migrations.ranges()
/// ```
#[test]
fn generate_new_canister_id() {
    fn range(start: u64, end: u64) -> CanisterIdRange {
        CanisterIdRange {
            start: start.into(),
            end: end.into(),
        }
    }

    // `canister_allocation_ranges = [[10, 19], [30, 30]]`
    let canister_allocation_ranges = vec![range(10, 19), range(30, 30)];

    // `routing_table.ranges(own_subnet_id) = [[10, 12], [17, 39]]`
    let own_subnet_id = SUBNET_0;
    let other_subnet_id = subnet_test_id(42);
    let routing_table = Arc::new(
        RoutingTable::try_from(btreemap! {
            range(10, 12) => own_subnet_id,
            range(13, 15) => other_subnet_id,
            range(17, 39) => own_subnet_id,
        })
        .unwrap(),
    );

    // `canister_migration.ranges() = [[12, 13], [18, 18]]`
    let canister_migrations = Arc::new(
        CanisterMigrations::try_from(btreemap! {
            range(12, 13) => vec![own_subnet_id, other_subnet_id],
            range(18, 18) => vec![own_subnet_id, other_subnet_id],
        })
        .unwrap(),
    );

    let mut system_metadata = SystemMetadata::new(own_subnet_id, SubnetType::Application);

    system_metadata.canister_allocation_ranges = canister_allocation_ranges.try_into().unwrap();
    let network_topology = NetworkTopology {
        subnets: BTreeMap::new(),
        routing_table,
        canister_migrations,
        nns_subnet_id: other_subnet_id,
        ecdsa_signing_subnets: Default::default(),
    };
    system_metadata.network_topology = network_topology;

    assert_eq!(None, system_metadata.last_generated_canister_id);
    assert_eq!(2, system_metadata.canister_allocation_ranges.len());

    /// Asserts that the next generated canister ID is the expected one.
    /// And that `last_generated_canister_id` is updated accordingly.
    fn assert_next_generated(expected: u64, system_metadata: &mut SystemMetadata) {
        assert_eq!(
            Ok(expected.into()),
            system_metadata.generate_new_canister_id()
        );
        assert_eq!(
            Some(expected.into()),
            system_metadata.last_generated_canister_id
        );
    }

    assert_next_generated(10, &mut system_metadata);
    assert_next_generated(11, &mut system_metadata);
    // 12 is being migrated, 13-16 are hosted by a different subnet.
    assert_next_generated(17, &mut system_metadata);

    // Same outcome if last generated canister ID had been within the allocation
    // range, but being migrated.
    system_metadata.last_generated_canister_id = Some(12.into());
    assert_next_generated(17, &mut system_metadata);

    assert_next_generated(19, &mut system_metadata);
    // Still have both allocation ranges.
    assert_eq!(2, system_metadata.canister_allocation_ranges.len());

    // Once we've generated 30, the first allocation range should have been dropped.
    assert_next_generated(30, &mut system_metadata);
    assert_eq!(1, system_metadata.canister_allocation_ranges.len());

    // Ensure backwards compatibility: we've generated 6 canister IDs so far.
    assert_eq!(6, system_metadata.generated_id_counter);

    // No more canister IDs can be generated.
    assert_eq!(
        Err("Canister ID allocation was consumed".into()),
        system_metadata.generate_new_canister_id()
    );
    // But last generated is the same.
    assert_eq!(Some(30.into()), system_metadata.last_generated_canister_id);
    // The last allocation range is still there.
    assert_eq!(1, system_metadata.canister_allocation_ranges.len());
    // And we're still at 6 generated canister IDs.
    assert_eq!(6, system_metadata.generated_id_counter);
}

#[test]
fn roundtrip_encoding() {
    use ic_protobuf::state::system_metadata::v1 as pb;

    fn range(start: u64, end: u64) -> CanisterIdRange {
        CanisterIdRange {
            start: start.into(),
            end: end.into(),
        }
    }

    // `canister_allocation_ranges = [[10, 19], [30, 30]]`
    let canister_allocation_ranges = vec![range(10, 19), range(30, 30)];

    // `routing_table.ranges(own_subnet_id) = [[10, 12]]`
    let own_subnet_id = SUBNET_0;
    let other_subnet_id = subnet_test_id(42);
    let routing_table = Arc::new(
        RoutingTable::try_from(btreemap! {
            range(10, 12) => own_subnet_id,
        })
        .unwrap(),
    );

    // `canister_migration.ranges() = [[12, 13]]`
    let canister_migrations = Arc::new(
        CanisterMigrations::try_from(btreemap! {
            range(12, 13) => vec![own_subnet_id, other_subnet_id],
        })
        .unwrap(),
    );

    let mut system_metadata = SystemMetadata::new(own_subnet_id, SubnetType::Application);

    let network_topology = NetworkTopology {
        subnets: BTreeMap::new(),
        routing_table,
        canister_migrations,
        nns_subnet_id: other_subnet_id,
        ecdsa_signing_subnets: Default::default(),
    };
    system_metadata.network_topology = network_topology;

    // Decoding a `SystemMetadata` with no `canister_allocation_ranges` succeeds.
    let mut proto = pb::SystemMetadata::from(&system_metadata);
    proto.canister_allocation_ranges = None;
    assert_eq!(system_metadata, proto.try_into().unwrap());

    // Validates that a roundtrip encode-decode results in the same `SystemMetadata`.
    fn validate_roundtrip_encoding(system_metadata: &SystemMetadata) {
        let proto = pb::SystemMetadata::from(system_metadata);
        assert_eq!(*system_metadata, proto.try_into().unwrap());
    }

    // Set `canister_allocation_ranges`, but not `last_generated_canister_id`.
    system_metadata.canister_allocation_ranges = canister_allocation_ranges.try_into().unwrap();
    validate_roundtrip_encoding(&system_metadata);

    // Set `last_generated_canister_id` to valid canister ID.
    system_metadata.last_generated_canister_id = Some(11.into());
    validate_roundtrip_encoding(&system_metadata);

    // Set `last_generated_canister_id` to valid, but migrated canister ID.
    system_metadata.last_generated_canister_id = Some(15.into());
    validate_roundtrip_encoding(&system_metadata);
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
        max_response_bytes: None,
        headers: Vec::new(),
        body: None,
        http_method: CanisterHttpMethod::GET,
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
        CanisterHttpMethod::GET
    );
    assert_eq!(
        deserialized_http_request_context.transform_method_name,
        transform_method_name
    );
}

#[test]
fn empty_network_topology() {
    let network_topology = NetworkTopology {
        subnets: BTreeMap::new(),
        routing_table: Arc::new(RoutingTable::default()),
        canister_migrations: Arc::new(CanisterMigrations::default()),
        nns_subnet_id: subnet_test_id(42),
        ecdsa_signing_subnets: Default::default(),
    };

    assert_eq!(network_topology.bitcoin_testnet_subnets(), vec![]);
    assert_eq!(
        network_topology.ecdsa_signing_subnets(&make_key_id()),
        vec![]
    );
}

#[test]
fn network_topology_bitcoin_testnet_subnets() {
    let network_topology = NetworkTopology {
        subnets: btreemap![
            // A subnet with the bitcoin testnet feature enabled.
            subnet_test_id(0) => SubnetTopology {
                public_key: vec![],
                nodes: BTreeMap::new(),
                subnet_type: SubnetType::Application,
                subnet_features: SubnetFeatures::from_str("bitcoin_testnet").unwrap(),
                ecdsa_keys_held: BTreeSet::new(),
            },

            // A subnet with the bitcoin testnet feature paused.
            subnet_test_id(1) => SubnetTopology {
                public_key: vec![],
                nodes: BTreeMap::new(),
                subnet_type: SubnetType::Application,
                subnet_features: SubnetFeatures::from_str("bitcoin_testnet_paused").unwrap(),
                ecdsa_keys_held: BTreeSet::new(),
            },

            // A subnet without the bitcoin feature enabled.
            subnet_test_id(3) => SubnetTopology {
                public_key: vec![],
                nodes: BTreeMap::new(),
                subnet_type: SubnetType::Application,
                subnet_features: SubnetFeatures::default(),
                ecdsa_keys_held: BTreeSet::new(),
            }
        ],
        routing_table: Arc::new(RoutingTable::default()),
        canister_migrations: Arc::new(CanisterMigrations::default()),
        nns_subnet_id: subnet_test_id(42),
        ecdsa_signing_subnets: Default::default(),
    };

    assert_eq!(
        network_topology.bitcoin_testnet_subnets(),
        vec![subnet_test_id(0)]
    );
}

#[test]
fn network_topology_ecdsa_subnets() {
    let key = make_key_id();
    let network_topology = NetworkTopology {
        subnets: Default::default(),
        routing_table: Arc::new(RoutingTable::default()),
        canister_migrations: Arc::new(CanisterMigrations::default()),
        nns_subnet_id: subnet_test_id(42),
        ecdsa_signing_subnets: btreemap! {
            key.clone() => vec![subnet_test_id(1)],
        },
    };

    assert_eq!(
        network_topology.ecdsa_signing_subnets(&key),
        &[subnet_test_id(1)]
    );
}

/// Test fixture that will produce an ingress status of type completed or failed,
/// depending on whether `i % 2 == 0` (completed) or not (failed). Both statuses
/// will have the same payload size.
fn test_status_terminal(i: u64) -> IngressStatus {
    let test_status_completed = |i| IngressStatus::Known {
        receiver: canister_test_id(i).get(),
        user_id: user_test_id(i),
        time: Time::from_nanos_since_unix_epoch(i),
        state: IngressState::Completed(WasmResult::Reply(vec![0, 1, 2, 3, 4])),
    };
    let test_status_failed = |i| IngressStatus::Known {
        receiver: canister_test_id(i).get(),
        user_id: user_test_id(i),
        time: Time::from_nanos_since_unix_epoch(i),
        state: IngressState::Failed(UserError::new(ErrorCode::SubnetOversubscribed, "Error")),
    };

    if i % 2 == 0 {
        test_status_completed(i)
    } else {
        test_status_failed(i)
    }
}

/// Test fixture to generate an ingress status of type done.
fn test_status_done(i: u64) -> IngressStatus {
    IngressStatus::Known {
        receiver: canister_test_id(i).get(),
        user_id: user_test_id(i),
        time: Time::from_nanos_since_unix_epoch(i),
        state: IngressState::Done,
    }
}

#[test]
fn ingress_history_insert_beyond_limit_will_succeed() {
    let mut ingress_history = IngressHistoryState::default();

    let insert_status = |ingress_history: &mut IngressHistoryState, i, max_num_entries| {
        let message_id = message_test_id(i);
        let status = test_status_terminal(i);
        let limit = NumBytes::from(max_num_entries * status.payload_bytes() as u64);
        ingress_history.insert(
            message_id.clone(),
            status.clone(),
            Time::from_nanos_since_unix_epoch(i),
            limit,
        );
        (message_id, status)
    };

    // Inserting with enough space for exactly one entry will always leave the
    // most recently inserted status there while setting everything else to
    // done.
    for i in 1..=100 {
        let (inserted_message_id, inserted_status) = insert_status(&mut ingress_history, i, 1);

        assert_eq!(ingress_history.statuses().count(), i as usize);
        if CURRENT_CERTIFICATION_VERSION >= CertificationVersion::V8 {
            assert_eq!(
                ingress_history.get(&inserted_message_id).unwrap(),
                &inserted_status
            );
            assert_eq!(
                ingress_history
                    .statuses()
                    .filter(|(_, status)| matches!(
                        status,
                        IngressStatus::Known {
                            state: IngressState::Completed(_),
                            ..
                        } | IngressStatus::Known {
                            state: IngressState::Failed(_),
                            ..
                        }
                    ))
                    .count(),
                1
            );
        } else {
            assert_eq!(
                ingress_history
                    .statuses()
                    .filter(|(_, status)| matches!(
                        status,
                        IngressStatus::Known {
                            state: IngressState::Completed(_),
                            ..
                        } | IngressStatus::Known {
                            state: IngressState::Failed(_),
                            ..
                        }
                    ))
                    .count(),
                i as usize
            );
            assert!(!ingress_history.statuses().any(|(_, status)| matches!(
                status,
                IngressStatus::Known {
                    state: IngressState::Done,
                    ..
                }
            )));
        }
    }

    // Inserting without available space will directly transition inserted status
    // to done.
    for i in 101..=200 {
        let (inserted_message_id, _) = insert_status(&mut ingress_history, i, 0);

        assert_eq!(ingress_history.statuses().count(), i as usize);
        if CURRENT_CERTIFICATION_VERSION >= CertificationVersion::V8 {
            assert_eq!(
                ingress_history.get(&inserted_message_id).unwrap(),
                &test_status_done(i),
            );

            assert_eq!(
                ingress_history
                    .statuses()
                    .filter(|(_, status)| matches!(
                        status,
                        IngressStatus::Known {
                            state: IngressState::Completed(_),
                            ..
                        } | IngressStatus::Known {
                            state: IngressState::Failed(_),
                            ..
                        }
                    ))
                    .count(),
                0
            );
        } else {
            assert_eq!(
                ingress_history
                    .statuses()
                    .filter(|(_, status)| matches!(
                        status,
                        IngressStatus::Known {
                            state: IngressState::Completed(_),
                            ..
                        } | IngressStatus::Known {
                            state: IngressState::Failed(_),
                            ..
                        }
                    ))
                    .count(),
                i as usize
            );
            assert!(!ingress_history.statuses().any(|(_, status)| matches!(
                status,
                IngressStatus::Known {
                    state: IngressState::Done,
                    ..
                }
            )));
        }
    }
}

#[test]
fn ingress_history_forget_completed_does_not_touch_other_statuses() {
    // Set up two ingress history states. In one we will later insert with a limit
    // of `0` whereas we will insert in the other with a limit of `u64::MAX`. Given
    // that we only insert non-terminal statuses this should lead to the same
    // ingress history state.
    let mut ingress_history_limit = IngressHistoryState::default();
    let mut ingress_history_no_limit = IngressHistoryState::default();

    let statuses = vec![
        IngressStatus::Known {
            receiver: canister_test_id(2).get(),
            user_id: user_test_id(2),
            time: Time::from_nanos_since_unix_epoch(2),
            state: IngressState::Processing,
        },
        IngressStatus::Known {
            receiver: canister_test_id(3).get(),
            user_id: user_test_id(3),
            time: Time::from_nanos_since_unix_epoch(3),
            state: IngressState::Received,
        },
        test_status_done(4),
        IngressStatus::Unknown,
    ];
    statuses.into_iter().enumerate().for_each(|(i, status)| {
        ingress_history_limit.insert(
            message_test_id(i as u64),
            status.clone(),
            Time::from_nanos_since_unix_epoch(0),
            NumBytes::from(0),
        );
        ingress_history_no_limit.insert(
            message_test_id(i as u64),
            status,
            Time::from_nanos_since_unix_epoch(0),
            NumBytes::from(u64::MAX),
        );
    });

    assert_eq!(ingress_history_limit, ingress_history_no_limit);

    let mut ingress_history_before = ingress_history_limit.clone();

    // Forgetting terminal statuses when the ingress history only contains non-terminal
    // statuses should be a no-op.
    ingress_history_limit.forget_terminal_statuses(NumBytes::from(0));
    // ... except that if current certification version >= 8, the next_terminal_time
    // is updated to the first key in the pruning_times map
    if CURRENT_CERTIFICATION_VERSION >= CertificationVersion::V8 {
        ingress_history_before.next_terminal_time =
            *ingress_history_limit.pruning_times().next().unwrap().0;
    }

    assert_eq!(ingress_history_before, ingress_history_limit);
}

#[test]
fn ingress_history_respects_limits() {
    let run_test = |num_statuses, max_num_terminal| {
        let mut ingress_history = IngressHistoryState::default();

        assert_eq!(ingress_history.memory_usage, 0);

        let terminal_size = NumBytes::from(
            max_num_terminal as u64 * test_status_terminal(0).payload_bytes() as u64,
        );

        for i in 1..=num_statuses {
            ingress_history.insert(
                message_test_id(i),
                test_status_terminal(i),
                Time::from_nanos_since_unix_epoch(i),
                terminal_size,
            );

            let terminal_count = ingress_history
                .statuses()
                .filter(|(_, status)| {
                    matches!(
                        status,
                        IngressStatus::Known {
                            state: IngressState::Completed(_),
                            ..
                        } | IngressStatus::Known {
                            state: IngressState::Failed(_),
                            ..
                        }
                    )
                })
                .count();

            let done_count = ingress_history
                .statuses()
                .filter(|(_, status)| {
                    matches!(
                        status,
                        IngressStatus::Known {
                            state: IngressState::Done,
                            ..
                        }
                    )
                })
                .count();

            if CURRENT_CERTIFICATION_VERSION >= CertificationVersion::V8 {
                assert_eq!(terminal_count, i.min(max_num_terminal) as usize);
                assert_eq!(done_count, i.saturating_sub(max_num_terminal) as usize);
            } else {
                assert_eq!(terminal_count, i as usize);
                assert_eq!(done_count, 0);
            }

            assert_eq!(
                terminal_count + done_count,
                ingress_history.statuses().count()
            )
        }
    };

    run_test(10, 1);
    run_test(10, 6);
    run_test(10, 6);
    run_test(10, 0);
}

#[test]
fn ingress_history_insert_before_next_complete_time_resets_it() {
    if CURRENT_CERTIFICATION_VERSION < CertificationVersion::V8 {
        return;
    }

    let mut ingress_history = IngressHistoryState::new();

    // Fill the ingress history with 10 terminal entries...
    for i in 1..=10 {
        ingress_history.insert(
            message_test_id(i),
            test_status_terminal(i),
            Time::from_nanos_since_unix_epoch(i),
            NumBytes::from(u64::MAX),
        );
    }

    // ... and trigger forgetting terminal statuses with a limit sufficient
    // for 5 non-terminal entries
    let status_size = NumBytes::from(5 * test_status_terminal(0).payload_bytes() as u64);
    ingress_history.forget_terminal_statuses(status_size);

    // ... which should lead to the next_terminal_time pointing to 6 + TTL.
    assert_eq!(
        ingress_history.next_terminal_time,
        Time::from_nanos_since_unix_epoch(6 + MAX_INGRESS_TTL.as_nanos() as u64)
    );

    // Insert another status with a time of `3` ...
    ingress_history.insert(
        message_test_id(11),
        test_status_terminal(11),
        Time::from_nanos_since_unix_epoch(3),
        NumBytes::from(u64::MAX),
    );

    // ... should lead to resetting the next_terminal_time to 3 + TTL.
    assert_eq!(
        ingress_history.next_terminal_time,
        Time::from_nanos_since_unix_epoch(3 + MAX_INGRESS_TTL.as_nanos() as u64)
    );

    // At this point forgetting terminal statuses with a limit sufficient
    // for 5 statuses should lead to "forgetting" the terminal status
    // we just inserted above.
    ingress_history.forget_terminal_statuses(status_size);

    let expected_fogotten = ingress_history.get(&message_test_id(11)).unwrap();

    if let IngressStatus::Known {
        receiver,
        user_id,
        time,
        state: IngressState::Done,
    } = expected_fogotten
    {
        assert_eq!(receiver, &canister_test_id(11).get());
        assert_eq!(user_id, &user_test_id(11));
        assert_eq!(time, &Time::from_nanos_since_unix_epoch(11));
    } else {
        panic!("Expected a done status");
    }
}

#[test]
fn ingress_history_forget_behaves_the_same_with_reset_next_complete_time() {
    if CURRENT_CERTIFICATION_VERSION < CertificationVersion::V8 {
        return;
    }

    let mut ingress_history = IngressHistoryState::new();

    // Fill the ingress history with 10 terminal entries...
    for i in 1..=10 {
        ingress_history.insert(
            message_test_id(i),
            test_status_terminal(i),
            Time::from_nanos_since_unix_epoch(i),
            NumBytes::from(u64::MAX),
        );
    }

    // ... and trigger forgetting terminal statuses with a limit sufficient
    // for 5 non-terminal entries
    let status_size = NumBytes::from(5 * test_status_terminal(0).payload_bytes() as u64);
    ingress_history.forget_terminal_statuses(status_size);

    // ... which should lead to the next_terminal_time pointing to 6 + TTL.
    assert_eq!(
        ingress_history.next_terminal_time,
        Time::from_nanos_since_unix_epoch(6 + MAX_INGRESS_TTL.as_nanos() as u64)
    );

    // Make a clone of the ingress history that has the `next_terminal_time` reset to
    // 0, i.e., the way it is after deserialization.
    let mut ingress_history_reset = {
        let mut hist = ingress_history.clone();
        hist.next_terminal_time = Time::from_nanos_since_unix_epoch(0);
        hist
    };

    // Insert two more entries with a time of 3 (i.e., before next_terminal_time of
    // the initial ingress history)
    ingress_history.insert(
        message_test_id(11),
        test_status_terminal(11),
        Time::from_nanos_since_unix_epoch(3),
        NumBytes::from(u64::MAX),
    );
    ingress_history_reset.insert(
        message_test_id(11),
        test_status_terminal(11),
        Time::from_nanos_since_unix_epoch(3),
        NumBytes::from(u64::MAX),
    );

    // ... and trigger forgetting terminal statuses with a limit sufficient
    // for 5 non-terminal entries
    ingress_history.forget_terminal_statuses(status_size);
    ingress_history_reset.forget_terminal_statuses(status_size);

    // ... which should bring both versions of the ingress history in the
    // same state.
    assert_eq!(ingress_history, ingress_history_reset);
}

#[derive(Clone)]
struct SignalConfig {
    end: u64,
}

#[derive(Clone)]
struct MessageConfig {
    begin: u64,
    count: u64,
}

fn generate_stream(msg_config: MessageConfig, signal_config: SignalConfig) -> Stream {
    let stream_header_builder = StreamHeaderBuilder::new()
        .begin(StreamIndex::from(msg_config.begin))
        .end(StreamIndex::from(msg_config.begin + msg_config.count))
        .signals_end(StreamIndex::from(signal_config.end));

    let msg_begin = StreamIndex::from(msg_config.begin);

    let slice = StreamSliceBuilder::new()
        .header(stream_header_builder.build())
        .generate_messages(
            msg_begin,
            msg_config.count,
            *LOCAL_CANISTER,
            *REMOTE_CANISTER,
        )
        .build();

    Stream::new(
        slice
            .messages()
            .cloned()
            .unwrap_or_else(|| StreamIndexedQueue::with_begin(msg_begin)),
        slice.header().signals_end,
    )
}

#[test]
fn stream_discard_messages_before() {
    let mut stream = generate_stream(
        MessageConfig {
            begin: 30,
            count: 20,
        },
        SignalConfig { end: 43 },
    );

    let expected_stream = generate_stream(
        MessageConfig {
            begin: 40,
            count: 10,
        },
        SignalConfig { end: 43 },
    );

    let expected_rejected_messages = vec![
        stream.messages().get(32.into()).unwrap().clone(),
        stream.messages().get(35.into()).unwrap().clone(),
    ];

    let slice_signals_end = 40.into();
    let slice_reject_signals: VecDeque<StreamIndex> =
        vec![28.into(), 29.into(), 32.into(), 35.into()].into();

    // Note that the `generate_stream` testing fixture only generates requests
    // while in the normal case reject signals are not expected to be generated for requests.
    // It does not matter here for the purpose of testing `discard_messages_before`.
    let (rejected_messages, _) =
        stream.discard_messages_before(slice_signals_end, &slice_reject_signals);

    assert_eq!(rejected_messages, expected_rejected_messages);
    assert_eq!(expected_stream, stream);
}

#[test]
fn stream_discard_signals_before() {
    let mut stream = generate_stream(
        MessageConfig {
            begin: 30,
            count: 5,
        },
        SignalConfig { end: 153 },
    );

    stream.reject_signals = vec![138.into(), 139.into(), 142.into(), 145.into()].into();

    let new_signals_begin = 140.into();
    stream.discard_signals_before(new_signals_begin);
    let expected_reject_signals: VecDeque<StreamIndex> = vec![142.into(), 145.into()].into();
    assert_eq!(stream.reject_signals, expected_reject_signals);

    let new_signals_begin = 145.into();
    stream.discard_signals_before(new_signals_begin);
    let expected_reject_signals: VecDeque<StreamIndex> = vec![145.into()].into();
    assert_eq!(stream.reject_signals, expected_reject_signals);
}
