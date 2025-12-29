use super::subnet_call_context_manager::{
    EcdsaArguments, EcdsaMatchedPreSignature, InstallCodeCall, PreSignatureStash, RawRandContext,
    SchnorrArguments, SchnorrMatchedPreSignature, SignWithThresholdContext, StopCanisterCall,
    SubnetCallContext, SubnetCallContextManager, ThresholdArguments,
};
use super::*;
use crate::InputQueueType;
use crate::testing::CanisterQueuesTesting;
use assert_matches::assert_matches;
use ic_crypto_test_utils_canister_threshold_sigs::{
    CanisterThresholdSigTestEnvironment, IDkgParticipants, generate_ecdsa_presig_quadruple,
    generate_key_transcript, setup_unmasked_random_params,
};
use ic_crypto_test_utils_reproducible_rng::{ReproducibleRng, reproducible_rng};
use ic_error_types::{ErrorCode, UserError};
use ic_limits::MAX_INGRESS_TTL;
use ic_management_canister_types_private::{
    EcdsaCurve, EcdsaKeyId, IC_00, MasterPublicKeyId, SchnorrAlgorithm, SchnorrKeyId,
};
use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::state::queues::v1 as pb_queues;
use ic_protobuf::state::system_metadata::v1 as pb_metadata;
use ic_registry_routing_table::CanisterIdRange;
use ic_test_utilities_types::ids::{
    SUBNET_0, SUBNET_1, SUBNET_2, canister_test_id, message_test_id, node_test_id, subnet_test_id,
    user_test_id,
};
use ic_test_utilities_types::messages::{RequestBuilder, ResponseBuilder};
use ic_test_utilities_types::xnet::{StreamHeaderBuilder, StreamSliceBuilder};
use ic_types::batch::BlockmakerMetrics;
use ic_types::canister_http::{
    CanisterHttpMethod, CanisterHttpRequestContext, PricingVersion, Replication, Transform,
};
use ic_types::consensus::idkg::{IDkgMasterPublicKeyId, PreSigId, common::PreSignature};
use ic_types::crypto::AlgorithmId;
use ic_types::crypto::canister_threshold_sig::SchnorrPreSignatureTranscript;
use ic_types::crypto::canister_threshold_sig::idkg::{IDkgDealers, IDkgReceivers, IDkgTranscript};
use ic_types::ingress::WasmResult;
use ic_types::messages::{CallbackId, CanisterCall, Payload, Refund, Request, RequestMetadata};
use ic_types::time::{CoarseTime, current_time};
use ic_types::{Cycles, ExecutionRound, Height};
use lazy_static::lazy_static;
use maplit::btreemap;
use proptest::prelude::*;
use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;
use strum::IntoEnumIterator;

struct DummyMetrics;
impl CheckpointLoadingMetrics for DummyMetrics {
    fn observe_broken_soft_invariant(&self, _: String) {
        // Do nothing.
    }
}

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

    let time = UNIX_EPOCH;
    ingress_history.insert(
        message_id1.clone(),
        IngressStatus::Known {
            receiver: canister_test_id(1).get(),
            user_id: user_test_id(1),
            time: UNIX_EPOCH,
            state: IngressState::Completed(WasmResult::Reply(vec![])),
        },
        time,
        NumBytes::from(u64::MAX),
        |_| {},
    );
    ingress_history.insert(
        message_id2.clone(),
        IngressStatus::Known {
            receiver: canister_test_id(2).get(),
            user_id: user_test_id(2),
            time: UNIX_EPOCH,
            state: IngressState::Completed(WasmResult::Reply(vec![])),
        },
        time,
        NumBytes::from(u64::MAX),
        |_| {},
    );
    ingress_history.insert(
        message_id3.clone(),
        IngressStatus::Known {
            receiver: canister_test_id(1).get(),
            user_id: user_test_id(1),
            time: UNIX_EPOCH,
            state: IngressState::Completed(WasmResult::Reply(vec![])),
        },
        time + MAX_INGRESS_TTL / 2,
        NumBytes::from(u64::MAX),
        |_| {},
    );

    // Pretend that the time has advanced
    let time = time + MAX_INGRESS_TTL + Duration::from_secs(10);

    ingress_history.prune(time);
    assert!(ingress_history.get(&message_id1).is_none());
    assert!(ingress_history.get(&message_id2).is_none());
    assert!(ingress_history.get(&message_id3).is_some());
}

#[test]
fn entries_sorted_lexicographically() {
    let mut ingress_history = IngressHistoryState::new();
    let time = UNIX_EPOCH;

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
            |_| {},
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
        ..Default::default()
    };

    let mut system_metadata = SystemMetadata::new(own_subnet_id, SubnetType::Application);
    system_metadata.network_topology = network_topology;

    assert_eq!(
        CanisterIdRanges::try_from(vec![]).unwrap(),
        system_metadata.canister_allocation_ranges
    );
    assert_eq!(None, system_metadata.last_generated_canister_id);

    system_metadata.init_allocation_ranges_if_empty().unwrap();

    assert_eq!(
        CanisterIdRanges::try_from(vec![CanisterIdRange {
            start: CanisterId::from(3 * CANISTER_IDS_PER_SUBNET),
            end: CanisterId::from(4 * CANISTER_IDS_PER_SUBNET - 1)
        }])
        .unwrap(),
        system_metadata.canister_allocation_ranges
    );
    assert!(system_metadata.last_generated_canister_id.is_none());
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
        ..Default::default()
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

    // No more canister IDs can be generated.
    assert_eq!(
        Err("Canister ID allocation was consumed".into()),
        system_metadata.generate_new_canister_id()
    );
    // But last generated is the same.
    assert_eq!(Some(30.into()), system_metadata.last_generated_canister_id);
    // The last allocation range is still there.
    assert_eq!(1, system_metadata.canister_allocation_ranges.len());
}

#[test]
fn system_metadata_roundtrip_encoding() {
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
        ..Default::default()
    };
    system_metadata.network_topology = network_topology;

    use ic_crypto_test_utils_keys::public_keys::valid_node_signing_public_key;
    let pk_der = ic_ed25519::PublicKey::deserialize_raw(&valid_node_signing_public_key().key_value)
        .unwrap()
        .serialize_rfc8410_der();

    system_metadata.node_public_keys = btreemap! {
        node_test_id(1) => pk_der,
    };
    system_metadata.api_boundary_nodes = btreemap! {
        node_test_id(1) => ApiBoundaryNodeEntry {
            domain: "api-example.com".to_string(),
            ipv4_address: Some("127.0.0.1".to_string()),
            ipv6_address: "2001:0db8:85a3:0000:0000:8a2e:0370:7334".to_string(),
            pubkey: None,
        },
    };
    system_metadata.bitcoin_get_successors_follow_up_responses =
        btreemap! { 10.into() => vec![vec![1], vec![2]] };

    // Decoding a `SystemMetadata` with no `canister_allocation_ranges` succeeds.
    let mut proto = pb::SystemMetadata::from(&system_metadata);
    proto.canister_allocation_ranges = None;
    assert_eq!(
        system_metadata,
        (proto, &DummyMetrics as &dyn CheckpointLoadingMetrics)
            .try_into()
            .unwrap()
    );

    // Validates that a roundtrip encode-decode results in the same `SystemMetadata`.
    fn validate_roundtrip_encoding(system_metadata: &SystemMetadata) {
        let proto = pb::SystemMetadata::from(system_metadata);
        assert_eq!(
            *system_metadata,
            (proto, &DummyMetrics as &dyn CheckpointLoadingMetrics)
                .try_into()
                .unwrap()
        );
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

    // Observe two `BlockmakerMetrics` on successive days.
    system_metadata.blockmaker_metrics_time_series.observe(
        Time::from_nanos_since_unix_epoch(0),
        &BlockmakerMetrics {
            blockmaker: node_test_id(1),
            failed_blockmakers: vec![node_test_id(2)],
        },
    );
    system_metadata.blockmaker_metrics_time_series.observe(
        Time::from_nanos_since_unix_epoch(0) + Duration::from_secs(24 * 3600),
        &BlockmakerMetrics {
            blockmaker: node_test_id(3),
            failed_blockmakers: vec![node_test_id(4)],
        },
    );
    validate_roundtrip_encoding(&system_metadata);
}

#[test]
fn system_metadata_split() {
    // We will be splitting subnet A into A' and B. C is a third-party subnet.
    const SUBNET_A: SubnetId = SUBNET_0;
    const SUBNET_B: SubnetId = SUBNET_1;
    const SUBNET_C: SubnetId = SUBNET_2;

    // 2 canisters: we will retain `CANISTER_1` on `SUBNET_A` and split off
    // `CANISTER_2` to `SUBNET_B`.
    const CANISTER_1: CanisterId = CanisterId::from_u64(1);
    const CANISTER_2: CanisterId = CanisterId::from_u64(2);

    // Ingress history with 3 Received messages, addressed to canisters 1 and 2;
    // and `IC_00` (i.e., `SUBNET_A`).
    let mut ingress_history = IngressHistoryState::new();
    let time = UNIX_EPOCH;
    let receivers = [CANISTER_1.get(), CANISTER_2.get(), IC_00.get()];
    for (i, receiver) in receivers.into_iter().enumerate().rev() {
        ingress_history.insert(
            message_test_id(i as u64),
            IngressStatus::Known {
                receiver,
                user_id: user_test_id(i as u64),
                time,
                state: IngressState::Received,
            },
            time,
            NumBytes::from(u64::MAX),
            |_| {},
        );
    }
    let mut subnet_queues = CanisterQueues::default();

    // `CANISTER_1` remains on `SUBNET_A`.
    let is_canister_on_subnet_a = |canister_id: CanisterId| canister_id == CANISTER_1;
    // All ingress messages except the one addressed to `CANISTER_2` (including the
    // ones for `IC_00`, i.e., `SUBNET_A`) should remain on `SUBNET_A` after the split.
    let is_receiver_on_subnet_a = |canister_id: CanisterId| canister_id != CANISTER_2;
    // Only ingress messages for `CANISTER_2` should be retained on `SUBNET_B`.
    let is_canister_on_subnet_b = |canister_id: CanisterId| canister_id == CANISTER_2;

    let streams =
        btreemap! { SUBNET_C => Stream::new(StreamIndexedQueue::with_begin(13.into()), 14.into()) };

    // Use uncommon `SubnetType::VerifiedApplication` to make it more likely to
    // detect a regression in the subnet type assigned to subnet B.
    let mut system_metadata = SystemMetadata::new(SUBNET_A, SubnetType::VerifiedApplication);
    system_metadata.ingress_history = ingress_history;
    system_metadata.streams = streams.into();
    system_metadata.prev_state_hash = Some(CryptoHash(vec![1, 2, 3]).into());
    system_metadata.batch_time = current_time();
    system_metadata.subnet_metrics = SubnetMetrics {
        consumed_cycles_by_deleted_canisters: 2197.into(),
        ..Default::default()
    };

    // Split off subnet A', phase 1.
    let mut metadata_a = system_metadata.clone().split(SUBNET_A, None).unwrap();

    // Metadata should be identical, plus a split marker pointing to subnet A.
    let mut expected = system_metadata.clone();
    expected.split_from = Some(SUBNET_A);
    assert_eq!(expected, metadata_a);

    // Split off subnet A', phase 2.
    //
    // Technically some parts of the `SystemMetadata` (such as `prev_state_hash` and
    // `own_subnet_type`) would be replaced during loading. However, we only care
    // that `after_split()` does not touch them.
    metadata_a.after_split(is_canister_on_subnet_a, &mut subnet_queues);

    // Expect same metadata, but with pruned ingress history and no split marker.
    expected.ingress_history.split(is_receiver_on_subnet_a);
    expected.split_from = None;
    assert_eq!(expected, metadata_a);

    // Split off subnet B, phase 1.
    let mut metadata_b = system_metadata.clone().split(SUBNET_B, None).unwrap();

    // Should only retain ingress history and batch time; and a split marker
    // pointing back to subnet A.
    let mut expected = SystemMetadata::new(SUBNET_B, SubnetType::VerifiedApplication);
    expected.ingress_history = system_metadata.ingress_history;
    expected.split_from = Some(SUBNET_A);
    expected.batch_time = system_metadata.batch_time;
    assert_eq!(expected, metadata_b);

    // Split off subnet B, phase 2.
    //
    // Technically some parts of the `SystemMetadata` (such as `prev_state_hash` and
    // `own_subnet_type`) would be replaced during loading. However, we only care
    // that `after_split()` does not touch them.
    metadata_b.after_split(is_canister_on_subnet_b, &mut subnet_queues);

    // Expect pruned ingress history and no split marker.
    expected.split_from = None;
    expected.ingress_history.split(is_canister_on_subnet_b);
    assert_eq!(expected, metadata_b);
}

#[test]
fn system_metadata_split_with_batch_time() {
    // We will be splitting subnet A into A' and B. C is a third-party subnet.
    const SUBNET_A: SubnetId = SUBNET_0;
    const SUBNET_B: SubnetId = SUBNET_1;

    let mut system_metadata = SystemMetadata::new(SUBNET_A, SubnetType::Application);
    system_metadata.prev_state_hash = Some(CryptoHash(vec![1, 2, 3]).into());
    system_metadata.batch_time = current_time();
    system_metadata.subnet_metrics = SubnetMetrics {
        consumed_cycles_by_deleted_canisters: 2197.into(),
        ..Default::default()
    };

    // Try splitting off subnet A' with an explicit batch time. It should fail, even
    // though it is the exact same batch time.
    assert_matches!(
        system_metadata
            .clone()
            .split(SUBNET_A, Some(system_metadata.batch_time)),
        Err(_)
    );

    let assert_valid_subnet_b_split = |batch_time: Time| {
        let split_metadata = system_metadata
            .clone()
            .split(SUBNET_B, Some(batch_time))
            .unwrap();

        let mut expected = SystemMetadata::new(SUBNET_B, SubnetType::Application);
        expected.split_from = Some(SUBNET_A);
        expected.batch_time = batch_time;
        assert_eq!(expected, split_metadata);
    };

    // Providing an equal batch time when splitting `SUBNET_B` should work.
    assert_valid_subnet_b_split(system_metadata.batch_time);
    // As should a later batch time.
    assert_valid_subnet_b_split(Time::from_nanos_since_unix_epoch(
        system_metadata.batch_time.as_nanos_since_unix_epoch() + 1,
    ));
    // But an earlier batch time should fail.
    assert_matches!(
        system_metadata.clone().split(
            SUBNET_B,
            Some(Time::from_nanos_since_unix_epoch(
                system_metadata.batch_time.as_nanos_since_unix_epoch() - 1,
            ))
        ),
        Err(_)
    );
}

#[test]
fn system_metadata_online_split() {
    // We will be splitting subnet A into A' and B. C is a third-party subnet.
    const SUBNET_A: SubnetId = SUBNET_0;
    const SUBNET_B: SubnetId = SUBNET_1;
    const SUBNET_C: SubnetId = SUBNET_2;

    // 2 canisters: we will retain `CANISTER_1` on `SUBNET_A` and split off
    // `CANISTER_2` to `SUBNET_B`.
    const CANISTER_1: CanisterId = CanisterId::from_u64(1);
    const CANISTER_2_U64: u64 = 2;
    const CANISTER_2: CanisterId = CanisterId::from_u64(CANISTER_2_U64);
    let routing_table = RoutingTable::try_from(btreemap! {
        CanisterIdRange {start: CanisterId::from_u64(0), end: CanisterId::from_u64(CANISTER_2_U64 - 1)} => SUBNET_A,
        CanisterIdRange {start: CanisterId::from_u64(CANISTER_2_U64), end: CanisterId::from_u64(CANISTER_2_U64)} => SUBNET_B,
        CanisterIdRange {start: CanisterId::from_u64(CANISTER_2_U64 + 1), end: CanisterId::from_u64(CANISTER_IDS_PER_SUBNET - 1)} => SUBNET_A,
    })
    .unwrap();

    // Ingress history with 3 `Received` messages; one each to canisters 1 and 2;
    // and one to `IC_00` (i.e., the `SUBNET_A` management canister).
    let mut ingress_history = IngressHistoryState::new();
    let time = UNIX_EPOCH;
    let receivers = [CANISTER_1.get(), CANISTER_2.get(), IC_00.get()];
    for (i, receiver) in receivers.into_iter().enumerate().rev() {
        ingress_history.insert(
            message_test_id(i as u64),
            IngressStatus::Known {
                receiver,
                user_id: user_test_id(i as u64),
                time,
                state: IngressState::Received,
            },
            time,
            NumBytes::from(u64::MAX),
            |_| {},
        );
    }

    // A stream to subnet C.
    let streams =
        btreemap! { SUBNET_C => Stream::new(StreamIndexedQueue::with_begin(13.into()), 14.into()) };

    // Non-empty subnet queues.
    let mut subnet_queues = CanisterQueues::default();
    subnet_queues
        .push_input(
            RequestBuilder::default()
                .sender(CANISTER_1)
                .receiver(SUBNET_A.into())
                .build()
                .into(),
            InputQueueType::LocalSubnet,
        )
        .unwrap();

    // Use uncommon `SubnetType::VerifiedApplication` to make it more likely to
    // detect a regression in the subnet type assigned to subnet B.
    let mut system_metadata = SystemMetadata::new(SUBNET_A, SubnetType::VerifiedApplication);
    system_metadata.ingress_history = ingress_history;
    system_metadata.streams = streams.into();
    system_metadata.canister_allocation_ranges =
        CanisterIdRanges::try_from(vec![CanisterIdRange {
            start: CanisterId::from_u64(0),
            end: CanisterId::from_u64(CANISTER_IDS_PER_SUBNET - 1),
        }])
        .unwrap();
    system_metadata.last_generated_canister_id = Some(CANISTER_2);
    system_metadata.prev_state_hash = Some(CryptoHash(vec![1, 2, 3]).into());
    system_metadata.batch_time = current_time();
    system_metadata.network_topology.routing_table = Arc::new(routing_table);
    system_metadata.subnet_metrics = SubnetMetrics {
        consumed_cycles_by_deleted_canisters: 2197.into(),
        ..Default::default()
    };

    // In-flight `install_code` management canister calls for each of the canisters.
    const INSTALL_CODE_SENDER: CanisterId = CanisterId::from_u64(13);
    const INSTALL_CODE_CALLBACK_ID: CallbackId = CallbackId::new(17);
    let mut push_install_code_call = |canister_id: CanisterId| {
        let request = RequestBuilder::default()
            .sender(INSTALL_CODE_SENDER)
            .receiver(SUBNET_A.into())
            .sender_reply_callback(INSTALL_CODE_CALLBACK_ID)
            .build();
        subnet_queues
            .push_input(request.clone().into(), InputQueueType::LocalSubnet)
            .unwrap();
        subnet_queues.pop_input().unwrap();
        system_metadata
            .subnet_call_context_manager
            .push_install_code_call(InstallCodeCall {
                call: CanisterCall::Request(Arc::new(request)),
                effective_canister_id: canister_id,
                time: UNIX_EPOCH,
            })
    };
    let _canister_1_install_code_call = push_install_code_call(CANISTER_1);
    let canister_2_install_code_call = push_install_code_call(CANISTER_2);

    // Split off subnet A'.
    let metadata_a = system_metadata
        .clone()
        .online_split(SUBNET_A, &mut subnet_queues)
        .unwrap();

    // Expect a pruned ingress history.
    let mut expected = system_metadata.clone();
    expected
        .ingress_history
        .split(|canister_id| canister_id != CANISTER_2);
    // And the split marker should be set.
    expected.subnet_split_from = Some(SUBNET_A);
    expected.split_from = None;

    // The `install_code` call targeting `CANISTER_2` has been dropped and a reject
    // response was enqueued for it.
    expected
        .subnet_call_context_manager
        .remove_install_code_call(canister_2_install_code_call);
    subnet_queues.push_output_response(Arc::new(Response {
        originator: INSTALL_CODE_SENDER,
        respondent: SUBNET_A.into(),
        originator_reply_callback: INSTALL_CODE_CALLBACK_ID,
        refund: Default::default(),
        response_payload: Payload::Reject(RejectContext::new(
            RejectCode::SysTransient,
            format!("Canister {CANISTER_2} migrated during a subnet split"),
        )),
        deadline: CoarseTime::from_secs_since_unix_epoch(0),
    }));
    assert_eq!(expected, metadata_a);

    // Split off subnet B.
    let metadata_b = system_metadata
        .clone()
        .online_split(SUBNET_B, &mut subnet_queues)
        .unwrap();

    // Start off with the original metadata state.
    let mut expected = system_metadata;
    // New subnet ID.
    expected.own_subnet_id = SUBNET_B;

    // Ingress history should only contain the message to `CANISTER_2`.
    expected
        .ingress_history
        .split(|canister_id| canister_id == CANISTER_2);
    // No streams.
    expected.streams = Default::default();
    // No canister allocation ranges. Will be initialized in the next round.
    expected.canister_allocation_ranges = Default::default();
    expected.last_generated_canister_id = None;
    // And the split marker should be set.
    expected.subnet_split_from = Some(SUBNET_A);
    expected.split_from = None;
    // No management canister calls.
    expected.subnet_call_context_manager = Default::default();
    // Default subnet metrics.
    expected.subnet_metrics = Default::default();
    // Everything else should be unchanged.
    assert_eq!(expected, metadata_b);
}

#[test]
fn subnet_call_contexts_deserialization() {
    let url = "https://".to_string();
    let transform = Transform {
        method_name: "transform".to_string(),
        context: vec![0, 1, 2],
    };
    let mut subnet_call_context_manager: SubnetCallContextManager =
        SubnetCallContextManager::default();

    // Define HTTP request.
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
        transform: Some(transform.clone()),
        time: UNIX_EPOCH,
        replication: Replication::FullyReplicated,
        pricing_version: PricingVersion::Legacy,
    };
    subnet_call_context_manager.push_context(SubnetCallContext::CanisterHttpRequest(
        canister_http_request,
    ));

    // Define install code request.
    let request = RequestBuilder::default()
        .sender(canister_test_id(1))
        .receiver(canister_test_id(2))
        .build();
    let install_code_call = InstallCodeCall {
        call: CanisterCall::Request(Arc::new(request)),
        effective_canister_id: canister_test_id(3),
        time: UNIX_EPOCH,
    };
    let call_id = subnet_call_context_manager.push_install_code_call(install_code_call.clone());

    // Define stop canister request.
    let request = RequestBuilder::default()
        .sender(canister_test_id(1))
        .receiver(canister_test_id(2))
        .build();
    let stop_canister_call = StopCanisterCall {
        call: CanisterCall::Request(Arc::new(request)),
        effective_canister_id: canister_test_id(3),
        time: UNIX_EPOCH,
    };
    let stop_canister_call_id =
        subnet_call_context_manager.push_stop_canister_call(stop_canister_call.clone());

    // Define RawRand context.
    let raw_rand_request = RequestBuilder::default()
        .sender(canister_test_id(10))
        .receiver(canister_test_id(20))
        .build();
    subnet_call_context_manager.push_raw_rand_request(
        raw_rand_request.clone(),
        ExecutionRound::new(5),
        UNIX_EPOCH,
    );

    // Encode and decode.
    let subnet_call_context_manager_proto: ic_protobuf::state::system_metadata::v1::SubnetCallContextManager = (&subnet_call_context_manager).into();
    let mut deserialized_subnet_call_context_manager: SubnetCallContextManager =
        SubnetCallContextManager::try_from((UNIX_EPOCH, subnet_call_context_manager_proto))
            .unwrap();

    // Check HTTP request deserialization.
    assert_eq!(
        deserialized_subnet_call_context_manager
            .canister_http_request_contexts
            .len(),
        1
    );
    let deserialized_http_request_context = deserialized_subnet_call_context_manager
        .canister_http_request_contexts
        .get(&CallbackId::from(0))
        .unwrap();
    assert_eq!(deserialized_http_request_context.url, url);
    assert_eq!(
        deserialized_http_request_context.http_method,
        CanisterHttpMethod::GET
    );
    assert_eq!(deserialized_http_request_context.transform, Some(transform));

    // Check install code call deserialization.
    assert_eq!(
        deserialized_subnet_call_context_manager.install_code_calls_len(),
        1
    );
    let deserialized_install_code_call = deserialized_subnet_call_context_manager
        .remove_install_code_call(call_id)
        .expect("Did not find the install code call.");
    assert_eq!(deserialized_install_code_call, install_code_call);

    // Check stop canister request deserialization.
    assert_eq!(
        deserialized_subnet_call_context_manager.stop_canister_calls_len(),
        1
    );
    let deserialized_stop_canister_call = deserialized_subnet_call_context_manager
        .remove_stop_canister_call(stop_canister_call_id)
        .expect("Did not find the stop canister call.");
    assert_eq!(deserialized_stop_canister_call, stop_canister_call);

    // Check raw rand request deserialization.
    let deserialized_raw_rand_requests = deserialized_subnet_call_context_manager.raw_rand_contexts;
    assert_eq!(
        deserialized_raw_rand_requests,
        vec![RawRandContext {
            request: raw_rand_request,
            execution_round_id: ExecutionRound::new(5),
            time: UNIX_EPOCH,
        }]
    )
}

pub fn generate_pre_signature(
    env: &CanisterThresholdSigTestEnvironment,
    dealers: &IDkgDealers,
    receivers: &IDkgReceivers,
    key_transcript: &IDkgTranscript,
    rng: &mut ReproducibleRng,
) -> PreSignature {
    let alg = key_transcript.algorithm_id;
    match alg {
        AlgorithmId::ThresholdEcdsaSecp256k1 => {
            let pre_sig =
                generate_ecdsa_presig_quadruple(env, dealers, receivers, alg, key_transcript, rng);
            PreSignature::Ecdsa(Arc::new(pre_sig))
        }
        AlgorithmId::ThresholdEd25519 | AlgorithmId::ThresholdSchnorrBip340 => {
            let blinder_unmasked_params =
                setup_unmasked_random_params(env, alg, dealers, receivers, rng);
            let blinder_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&blinder_unmasked_params, rng);
            PreSignature::Schnorr(Arc::new(
                SchnorrPreSignatureTranscript::new(blinder_transcript).unwrap(),
            ))
        }
        _ => panic!("unsupported algorithm"),
    }
}

fn make_key_ids() -> Vec<IDkgMasterPublicKeyId> {
    [
        MasterPublicKeyId::Ecdsa(EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "key1".into(),
        }),
        MasterPublicKeyId::Schnorr(SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Ed25519,
            name: "key1".into(),
        }),
        MasterPublicKeyId::Schnorr(SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Bip340Secp256k1,
            name: "key1".into(),
        }),
    ]
    .into_iter()
    .map(|key_id| IDkgMasterPublicKeyId::try_from(key_id).unwrap())
    .collect()
}

#[test]
fn pre_signature_stash_roundtrip() {
    let rng = &mut reproducible_rng();
    let env = CanisterThresholdSigTestEnvironment::new(4, rng);
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
    let key_ids = make_key_ids();
    let mut stashes = BTreeMap::new();
    // create some stashes with pre-signatures
    for key_id in key_ids {
        let alg = AlgorithmId::from(key_id.inner());
        let key_transcript = generate_key_transcript(&env, &dealers, &receivers, alg, rng);
        let mut pre_signatures = BTreeMap::new();
        for i in 1..10 {
            pre_signatures.insert(
                PreSigId(i),
                generate_pre_signature(&env, &dealers, &receivers, &key_transcript, rng),
            );
        }
        stashes.insert(
            key_id,
            PreSignatureStash {
                pre_signatures,
                key_transcript: Arc::new(key_transcript),
            },
        );
    }
    // insert empty stash
    stashes.insert(
        MasterPublicKeyId::Ecdsa(make_key_id()).try_into().unwrap(),
        PreSignatureStash {
            pre_signatures: BTreeMap::new(),
            key_transcript: Arc::new(generate_key_transcript(
                &env,
                &dealers,
                &receivers,
                AlgorithmId::ThresholdEcdsaSecp256k1,
                rng,
            )),
        },
    );

    let mut subnet_call_context_manager: SubnetCallContextManager =
        SubnetCallContextManager::default();
    subnet_call_context_manager.pre_signature_stashes = stashes;

    // Encode and decode.
    let subnet_call_context_manager_proto: ic_protobuf::state::system_metadata::v1::SubnetCallContextManager = (&subnet_call_context_manager).into();
    let deserialized_subnet_call_context_manager: SubnetCallContextManager =
        SubnetCallContextManager::try_from((UNIX_EPOCH, subnet_call_context_manager_proto))
            .unwrap();

    assert_eq!(
        subnet_call_context_manager,
        deserialized_subnet_call_context_manager
    );
}

#[test]
fn sign_with_threshold_context_roundtrip() {
    let rng = &mut reproducible_rng();
    let env = CanisterThresholdSigTestEnvironment::new(4, rng);
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
    let transcripts = make_key_ids().into_iter().map(|key_id| {
        let alg = AlgorithmId::from(key_id.inner());
        let key_transcript = generate_key_transcript(&env, &dealers, &receivers, alg, rng);
        let pre_signature =
            generate_pre_signature(&env, &dealers, &receivers, &key_transcript, rng);
        (key_id, key_transcript, pre_signature)
    });
    let mut contexts = BTreeMap::new();
    let mut id = 1;

    // create some contexts with and without pre-signatures
    for (key_id, key_transcript, pre_signature) in transcripts {
        let arguments = match (key_id.inner(), pre_signature) {
            (MasterPublicKeyId::Ecdsa(key_id), PreSignature::Ecdsa(ecdsa)) => {
                let message_hash = [1; 32];
                let args_matched = ThresholdArguments::Ecdsa(EcdsaArguments {
                    key_id: key_id.clone(),
                    message_hash,
                    pre_signature: Some(EcdsaMatchedPreSignature {
                        id: PreSigId(id),
                        height: Height::new(id),
                        pre_signature: ecdsa,
                        key_transcript: Arc::new(key_transcript),
                    }),
                });
                let args_empty = ThresholdArguments::Ecdsa(EcdsaArguments {
                    key_id: key_id.clone(),
                    message_hash,
                    pre_signature: None,
                });
                [args_matched, args_empty]
            }
            (MasterPublicKeyId::Schnorr(key_id), PreSignature::Schnorr(schnorr)) => {
                let message = Arc::new(vec![1; 32]);
                let args_matched = ThresholdArguments::Schnorr(SchnorrArguments {
                    key_id: key_id.clone(),
                    message: message.clone(),
                    pre_signature: Some(SchnorrMatchedPreSignature {
                        id: PreSigId(id),
                        height: Height::new(id),
                        pre_signature: schnorr,
                        key_transcript: Arc::new(key_transcript),
                    }),
                    taproot_tree_root: Some(Arc::new(vec![2; 32])),
                });
                let args_empty = ThresholdArguments::Schnorr(SchnorrArguments {
                    key_id: key_id.clone(),
                    message,
                    pre_signature: None,
                    taproot_tree_root: None,
                });
                [args_matched, args_empty]
            }
            _ => panic!("unexpected combination"),
        };
        for args in arguments {
            id += 1;
            contexts.insert(
                CallbackId::new(id),
                SignWithThresholdContext {
                    request: RequestBuilder::new().build(),
                    args,
                    derivation_path: Arc::new(vec![]),
                    pseudo_random_id: [1; 32],
                    batch_time: UNIX_EPOCH,
                    matched_pre_signature: None,
                    nonce: Some([3; 32]),
                },
            );
        }
    }

    assert_eq!(contexts.len(), 6);
    let mut subnet_call_context_manager: SubnetCallContextManager =
        SubnetCallContextManager::default();
    subnet_call_context_manager.sign_with_threshold_contexts = contexts;

    // Encode and decode.
    let subnet_call_context_manager_proto: ic_protobuf::state::system_metadata::v1::SubnetCallContextManager = (&subnet_call_context_manager).into();
    let deserialized_subnet_call_context_manager: SubnetCallContextManager =
        SubnetCallContextManager::try_from((UNIX_EPOCH, subnet_call_context_manager_proto))
            .unwrap();

    assert_eq!(
        subnet_call_context_manager,
        deserialized_subnet_call_context_manager
    );
}

#[test]
fn empty_network_topology() {
    let network_topology = NetworkTopology {
        subnets: BTreeMap::new(),
        routing_table: Arc::new(RoutingTable::default()),
        canister_migrations: Arc::new(CanisterMigrations::default()),
        nns_subnet_id: subnet_test_id(42),
        ..Default::default()
    };

    assert_eq!(
        network_topology.chain_key_enabled_subnets(&MasterPublicKeyId::Ecdsa(make_key_id())),
        vec![]
    );
}

#[test]
fn network_topology_ecdsa_subnets() {
    let key = MasterPublicKeyId::Ecdsa(make_key_id());
    let network_topology = NetworkTopology {
        subnets: Default::default(),
        routing_table: Arc::new(RoutingTable::default()),
        canister_migrations: Arc::new(CanisterMigrations::default()),
        nns_subnet_id: subnet_test_id(42),
        chain_key_enabled_subnets: btreemap! {
            key.clone() => vec![subnet_test_id(1)],
        },
        ..Default::default()
    };

    assert_eq!(
        network_topology.chain_key_enabled_subnets(&key),
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

    if i.is_multiple_of(2) {
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
            |_| {},
        );
        (message_id, status)
    };

    // Inserting with enough space for exactly one entry will always leave the
    // most recently inserted status there while setting everything else to
    // done.
    for i in 1..=100 {
        let (inserted_message_id, inserted_status) = insert_status(&mut ingress_history, i, 1);

        assert_eq!(ingress_history.statuses().count(), i as usize);
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
    }

    // Inserting without available space will directly transition inserted status
    // to done.
    for i in 101..=200 {
        let (inserted_message_id, _) = insert_status(&mut ingress_history, i, 0);

        assert_eq!(ingress_history.statuses().count(), i as usize);
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
            |_| {},
        );
        ingress_history_no_limit.insert(
            message_test_id(i as u64),
            status,
            Time::from_nanos_since_unix_epoch(0),
            NumBytes::from(u64::MAX),
            |_| {},
        );
    });

    assert_eq!(ingress_history_limit, ingress_history_no_limit);

    let mut ingress_history_before = ingress_history_limit.clone();

    // Forgetting terminal statuses when the ingress history only contains non-terminal
    // statuses should be a no-op.
    ingress_history_limit.forget_terminal_statuses(
        NumBytes::from(0),
        Time::from_nanos_since_unix_epoch(0),
        |_| {},
    );
    // ... except the next_terminal_time is updated to the first key in the `pruning_times` map.
    ingress_history_before.next_terminal_time =
        *ingress_history_limit.pruning_times().next().unwrap().0;

    assert_eq!(ingress_history_before, ingress_history_limit);
}

#[test]
fn ingress_history_respects_limits() {
    let run_test = |num_statuses, max_num_terminal| {
        let mut ingress_history = IngressHistoryState::default();

        assert_eq!(ingress_history.memory_usage, 0);

        let terminal_size =
            NumBytes::from(max_num_terminal * test_status_terminal(0).payload_bytes() as u64);

        for i in 1..=num_statuses {
            ingress_history.insert(
                message_test_id(i),
                test_status_terminal(i),
                Time::from_nanos_since_unix_epoch(i),
                terminal_size,
                |_| {},
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

            assert_eq!(terminal_count, i.min(max_num_terminal) as usize);
            assert_eq!(done_count, i.saturating_sub(max_num_terminal) as usize);

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
    let mut ingress_history = IngressHistoryState::new();

    // Fill the ingress history with 10 terminal entries...
    for i in 1..=10 {
        ingress_history.insert(
            message_test_id(i),
            test_status_terminal(i),
            Time::from_nanos_since_unix_epoch(i),
            NumBytes::from(u64::MAX),
            |_| {},
        );
    }

    // ... and trigger forgetting terminal statuses with a limit sufficient
    // for 5 non-terminal entries
    let status_size = NumBytes::from(5 * test_status_terminal(0).payload_bytes() as u64);
    ingress_history.forget_terminal_statuses(
        status_size,
        Time::from_nanos_since_unix_epoch(0),
        |_| {},
    );

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
        |_| {},
    );

    // ... should lead to resetting the next_terminal_time to 3 + TTL.
    assert_eq!(
        ingress_history.next_terminal_time,
        Time::from_nanos_since_unix_epoch(3 + MAX_INGRESS_TTL.as_nanos() as u64)
    );

    // At this point forgetting terminal statuses with a limit sufficient
    // for 5 statuses should lead to "forgetting" the terminal status
    // we just inserted above.
    ingress_history.forget_terminal_statuses(
        status_size,
        Time::from_nanos_since_unix_epoch(0),
        |_| {},
    );

    let expected_forgotten = ingress_history.get(&message_test_id(11)).unwrap();

    if let IngressStatus::Known {
        receiver,
        user_id,
        time,
        state: IngressState::Done,
    } = expected_forgotten
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
    let mut ingress_history = IngressHistoryState::new();

    // Fill the ingress history with 10 terminal entries...
    for i in 1..=10 {
        ingress_history.insert(
            message_test_id(i),
            test_status_terminal(i),
            Time::from_nanos_since_unix_epoch(i),
            NumBytes::from(u64::MAX),
            |_| {},
        );
    }

    // ... and trigger forgetting terminal statuses with a limit sufficient
    // for 5 non-terminal entries
    let status_size = NumBytes::from(5 * test_status_terminal(0).payload_bytes() as u64);
    ingress_history.forget_terminal_statuses(
        status_size,
        Time::from_nanos_since_unix_epoch(0),
        |_| {},
    );

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
        |_| {},
    );
    ingress_history_reset.insert(
        message_test_id(11),
        test_status_terminal(11),
        Time::from_nanos_since_unix_epoch(3),
        NumBytes::from(u64::MAX),
        |_| {},
    );

    // ... and trigger forgetting terminal statuses with a limit sufficient
    // for 5 non-terminal entries
    ingress_history.forget_terminal_statuses(
        status_size,
        Time::from_nanos_since_unix_epoch(0),
        |_| {},
    );
    ingress_history_reset.forget_terminal_statuses(
        status_size,
        Time::from_nanos_since_unix_epoch(0),
        |_| {},
    );

    // ... which should bring both versions of the ingress history in the
    // same state.
    assert_eq!(ingress_history, ingress_history_reset);
}

#[test]
fn ingress_history_roundtrip_encode() {
    use ic_protobuf::state::ingress::v1 as pb;

    let mut ingress_history = IngressHistoryState::new();

    // Fill the ingress history with 10 terminal entries...
    for i in 1..=10 {
        ingress_history.insert(
            message_test_id(i),
            test_status_terminal(i),
            Time::from_nanos_since_unix_epoch(i),
            NumBytes::from(u64::MAX),
            |_| {},
        );
    }

    // ... and trigger forgetting terminal statuses with a limit sufficient
    // for 5 non-terminal entries
    let status_size = NumBytes::from(5 * test_status_terminal(0).payload_bytes() as u64);
    ingress_history.forget_terminal_statuses(
        status_size,
        Time::from_nanos_since_unix_epoch(0),
        |_| {},
    );

    let ingress_history_proto = pb::IngressHistoryState::from(&ingress_history);

    assert_eq!(ingress_history, ingress_history_proto.try_into().unwrap());
}

#[test]
fn ingress_history_split() {
    use IngressState::*;
    let canister_1 = canister_test_id(1);
    let canister_2 = canister_test_id(2);

    let mut ingress_history = IngressHistoryState::new();

    let states = &[
        Received,
        Processing,
        Completed(WasmResult::Reply(vec![1, 2, 3])),
        Failed(UserError::new(ErrorCode::CanisterTrapped, "Oops")),
        Done,
    ];

    // Populates the provided `ingress_history` with messages having each state in
    // `states` for `canister_1`; and messages having each state in `states` for
    // `canister_2`; if `filter` accepts them.
    let populate = |ingress_history: &mut IngressHistoryState,
                    filter: &dyn Fn(PrincipalId, &IngressState) -> bool| {
        let mut i = 169;
        for receiver in [canister_1.get(), canister_2.get()] {
            for state in states.iter().cloned() {
                i += 1;
                if !filter(receiver, &state) {
                    continue;
                }
                let time = Time::from_nanos_since_unix_epoch(i);
                ingress_history.insert(
                    message_test_id(i),
                    IngressStatus::Known {
                        receiver,
                        user_id: user_test_id(i),
                        time,
                        state,
                    },
                    time,
                    NumBytes::from(u64::MAX),
                    |_| {},
                );
            }
        }
    };

    populate(&mut ingress_history, &|_, _| true);
    // We should have 10 messages, 5 for each canister.
    assert_eq!(10, ingress_history.len());
    // Bump `next_terminal_time` to the time of the oldest terminal state (canister_1, Completed).
    ingress_history.forget_terminal_statuses(
        NumBytes::from(u64::MAX),
        Time::from_nanos_since_unix_epoch(0),
        |_| {},
    );
    assert_ne!(
        0,
        ingress_history
            .next_terminal_time
            .as_nanos_since_unix_epoch()
    );

    // Try a no-op split first.
    let is_local_canister = |_: CanisterId| true;
    let expected = ingress_history.clone();

    ingress_history.split(is_local_canister);

    // All messages should be retained.
    assert_eq!(expected, ingress_history);

    // Do an actual split, with only canister_2 hosted by own_subnet_id.
    let is_local_canister = |canister_id: CanisterId| canister_id == canister_2;

    // Expect all messages for canister_2; as well as all terminal statuses; to be retained.
    let mut expected = IngressHistoryState::new();
    populate(&mut expected, &|receiver, state| {
        receiver == canister_2.get() || state.is_terminal()
    });
    // We should only have 8 messages, 3 terminal ones for canister_1 and 5 for canister_2.
    assert_eq!(8, expected.len());
    // Bump `next_terminal_time` to the time of the oldest terminal state (canister_1, Completed).
    expected.forget_terminal_statuses(
        NumBytes::from(u64::MAX),
        Time::from_nanos_since_unix_epoch(0),
        |_| {},
    );

    ingress_history.split(is_local_canister);
    assert_eq!(expected, ingress_history);
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
    let stream_header = StreamHeaderBuilder::new()
        .begin(StreamIndex::from(msg_config.begin))
        .end(StreamIndex::from(msg_config.begin + msg_config.count))
        .signals_end(StreamIndex::from(signal_config.end))
        .build();

    let msg_begin = StreamIndex::from(msg_config.begin);

    let slice = StreamSliceBuilder::new()
        .header(stream_header)
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
        slice.header().signals_end(),
    )
}

#[test]
fn stream_discard_messages_before_returns_no_rejected_messages() {
    let mut stream = generate_stream(
        MessageConfig {
            begin: 30,
            count: 20,
        },
        SignalConfig { end: 43 },
    );

    // Check that `discard_messages_before()` returns no messages for an empty `reject_signals`.
    let slice_signals_end = 40.into();
    let slice_reject_signals = VecDeque::new();

    let rejected_messages =
        stream.discard_messages_before(slice_signals_end, &slice_reject_signals);
    assert!(rejected_messages.is_empty());
}

#[test]
fn stream_discard_messages_before_returns_expected_messages() {
    let mut stream = generate_stream(
        MessageConfig {
            begin: 30,
            count: 20,
        },
        SignalConfig { end: 43 },
    );
    let slice_signals_end = 40.into();
    let slice_reject_signals: VecDeque<RejectSignal> = vec![
        RejectSignal::new(RejectReason::CanisterMigrating, 28.into()), // before the stream
        RejectSignal::new(RejectReason::CanisterNotFound, 29.into()),  // before the stream
        RejectSignal::new(RejectReason::QueueFull, 32.into()),
        RejectSignal::new(RejectReason::Unknown, 35.into()),
    ]
    .into();

    let expected_stream = generate_stream(
        MessageConfig {
            begin: 40,
            count: 10,
        },
        SignalConfig { end: 43 },
    );
    let expected_rejected_messages = vec![
        (
            RejectReason::QueueFull,
            stream.messages().get(32.into()).unwrap().clone(),
        ),
        (
            RejectReason::Unknown,
            stream.messages().get(35.into()).unwrap().clone(),
        ),
    ];

    // Note that the `generate_stream` testing fixture only generates requests
    // while in the normal case reject signals are not expected to be generated for requests.
    // It does not matter here for the purpose of testing `discard_messages_before`.
    let rejected_messages =
        stream.discard_messages_before(slice_signals_end, &slice_reject_signals);

    assert_eq!(expected_stream, stream);
    assert_eq!(rejected_messages, expected_rejected_messages);
}

#[test]
fn stream_discard_messages_before_returns_expected_refunds() {
    // A stream with 3 refund messages at indices 30..=32.
    let mut messages = StreamIndexedQueue::with_begin(30.into());
    let refund30 = Arc::new(Refund::anonymous(*LOCAL_CANISTER, Cycles::new(1_000_000)));
    let refund31 = Arc::new(Refund::anonymous(*LOCAL_CANISTER, Cycles::new(2_000_000)));
    let refund32 = Arc::new(Refund::anonymous(*LOCAL_CANISTER, Cycles::new(3_000_000)));
    messages.push(StreamMessage::Refund(refund30.clone()));
    messages.push(StreamMessage::Refund(refund31.clone()));
    messages.push(StreamMessage::Refund(refund32.clone()));
    let mut stream = Stream::new(messages, 42.into());

    // Discard messages before index 32, rejecting refund @31.
    let reject_signal = RejectSignal::new(RejectReason::CanisterMigrating, 31.into());
    let slice_reject_signals: VecDeque<RejectSignal> = vec![reject_signal.clone()].into();
    let slice_signals_end = 32.into();

    let rejected_messages =
        stream.discard_messages_before(slice_signals_end, &slice_reject_signals);

    // Expect refund @32 to remain in the stream, refund @31 to be rejected.
    let mut expected_messages = StreamIndexedQueue::with_begin(32.into());
    expected_messages.push(StreamMessage::Refund(refund32.clone()));
    let expected_stream = Stream::new(expected_messages, 42.into());
    assert_eq!(expected_stream, stream);
    assert_eq!(
        vec![(
            RejectReason::CanisterMigrating,
            StreamMessage::Refund(refund31)
        )],
        rejected_messages
    );
}

#[test]
fn stream_discard_messages_before_removes_no_messages() {
    let mut stream = generate_stream(
        MessageConfig {
            begin: 30,
            count: 20,
        },
        SignalConfig { end: 43 },
    );
    let expected_stream = stream.clone();
    let slice_reject_signals = vec![
        RejectSignal::new(RejectReason::CanisterStopped, 28.into()), // before the stream
        RejectSignal::new(RejectReason::OutOfMemory, 29.into()),     // before the stream
    ]
    .into();
    let slice_signals_end = stream.messages_begin();

    let rejected_messages =
        stream.discard_messages_before(slice_signals_end, &slice_reject_signals);

    assert_eq!(expected_stream, stream);
    assert!(rejected_messages.is_empty());
}

#[test]
fn stream_discard_messages_before_removes_all_messages() {
    let mut stream = generate_stream(
        MessageConfig {
            begin: 30,
            count: 20,
        },
        SignalConfig { end: 43 },
    );
    let slice_reject_signals = VecDeque::new();
    let slice_signals_end = stream.messages_end();
    let expected_stream = generate_stream(
        MessageConfig {
            begin: 50,
            count: 0,
        },
        SignalConfig { end: 43 },
    );
    let rejected_messages =
        stream.discard_messages_before(slice_signals_end, &slice_reject_signals);

    assert_eq!(expected_stream, stream);
    assert!(rejected_messages.is_empty());
}

#[test]
fn stream_discard_signals_before_drops_no_reject_signals() {
    let mut stream = generate_stream(
        MessageConfig {
            begin: 30,
            count: 5,
        },
        SignalConfig { end: 153 },
    );
    stream.reject_signals = vec![
        RejectSignal::new(RejectReason::CanisterMigrating, 138.into()),
        RejectSignal::new(RejectReason::CanisterStopped, 139.into()),
        RejectSignal::new(RejectReason::CanisterNotFound, 142.into()),
        RejectSignal::new(RejectReason::Unknown, 145.into()),
    ]
    .into();

    // Check that `discard_signals_before()` drops no reject signals for
    // `new_signals_begin` == first reject signal.
    let new_signals_begin = stream.reject_signals().front().unwrap().index;
    let expected_reject_signals = stream.reject_signals().clone();
    stream.discard_signals_before(new_signals_begin);
    assert_eq!(stream.reject_signals(), &expected_reject_signals);
}

#[test]
fn stream_discard_signals_before_drops_expected_signals() {
    let mut stream = generate_stream(
        MessageConfig {
            begin: 30,
            count: 5,
        },
        SignalConfig { end: 153 },
    );
    stream.reject_signals = vec![
        RejectSignal::new(RejectReason::CanisterMigrating, 138.into()),
        RejectSignal::new(RejectReason::QueueFull, 139.into()),
        RejectSignal::new(RejectReason::CanisterMigrating, 142.into()),
        RejectSignal::new(RejectReason::CanisterNotFound, 145.into()),
    ]
    .into();

    // Check that `discard_signals_before()` drops the expected reject signals
    // for an in-between reject signals `new_signals_begin`.
    let new_signals_begin = 140.into();
    let expected_reject_signals: VecDeque<RejectSignal> = [
        RejectSignal::new(RejectReason::CanisterMigrating, 142.into()),
        RejectSignal::new(RejectReason::CanisterNotFound, 145.into()),
    ]
    .into();
    stream.discard_signals_before(new_signals_begin);
    assert_eq!(stream.reject_signals(), &expected_reject_signals);
}

#[test]
fn stream_discard_signals_before_drops_expected_signals_for_existing_reject_signal() {
    let mut stream = generate_stream(
        MessageConfig {
            begin: 30,
            count: 5,
        },
        SignalConfig { end: 153 },
    );
    stream.reject_signals = vec![
        RejectSignal::new(RejectReason::QueueFull, 138.into()),
        RejectSignal::new(RejectReason::CanisterNotFound, 139.into()),
        RejectSignal::new(RejectReason::Unknown, 142.into()),
        RejectSignal::new(RejectReason::OutOfMemory, 145.into()),
    ]
    .into();

    // Check that `discard_signals_before()` drops the expected reject signals
    // for an existing reject signal `new_signals_begin`.
    let new_signals_begin = 145.into();
    let expected_reject_signals: VecDeque<RejectSignal> =
        [RejectSignal::new(RejectReason::OutOfMemory, 145.into())].into();

    stream.discard_signals_before(new_signals_begin);
    assert_eq!(stream.reject_signals(), &expected_reject_signals);
}

#[test]
fn stream_discard_signals_before_drops_all_signals() {
    let mut stream = generate_stream(
        MessageConfig {
            begin: 30,
            count: 5,
        },
        SignalConfig { end: 153 },
    );
    stream.reject_signals = vec![
        RejectSignal::new(RejectReason::QueueFull, 138.into()),
        RejectSignal::new(RejectReason::CanisterMigrating, 139.into()),
        RejectSignal::new(RejectReason::CanisterStopped, 142.into()),
        RejectSignal::new(RejectReason::CanisterNotFound, 145.into()),
    ]
    .into();

    // Check that `discard_signals_before()` drops all reject signals for a
    // `new_signals_begin` past all the signals.
    let new_signals_begin = 150.into();
    stream.discard_signals_before(new_signals_begin);
    assert_eq!(stream.reject_signals(), &VecDeque::new());
}

#[test]
fn stream_pushing_signals_increments_signals_end() {
    let mut stream = generate_stream(
        MessageConfig {
            begin: 30,
            count: 0,
        },
        SignalConfig { end: 30 },
    );
    assert!(stream.reject_signals().is_empty());

    stream.push_accept_signal();
    assert_eq!(StreamIndex::new(31), stream.signals_end());
    stream.push_reject_signal(RejectReason::CanisterMigrating);
    assert_eq!(
        &VecDeque::from([RejectSignal::new(
            RejectReason::CanisterMigrating,
            31.into()
        )]),
        stream.reject_signals()
    );
    assert_eq!(StreamIndex::new(32), stream.signals_end());
}

#[test]
fn stream_roundtrip_encoding() {
    let mut messages = StreamIndexedQueue::with_begin(30.into());
    // Push a fully specified `Request`.
    messages.push(
        Request {
            sender: *LOCAL_CANISTER,
            receiver: *REMOTE_CANISTER,
            sender_reply_callback: CallbackId::from(1),
            payment: Cycles::from(123_456_789_u128),
            method_name: "method_1".into(),
            method_payload: [2_u8, 17_u8, 29_u8, 113_u8].into(),
            metadata: RequestMetadata::new(17, Time::from_nanos_since_unix_epoch(123)),
            deadline: CoarseTime::from_secs_since_unix_epoch(456),
        }
        .into(),
    );

    // Push a fully specified `Response`.
    messages.push(
        Response {
            originator: *LOCAL_CANISTER,
            respondent: *REMOTE_CANISTER,
            originator_reply_callback: CallbackId::from(2),
            refund: Cycles::from(234_567_u128),
            response_payload: Payload::Data([13_u8, 44_u8, 1_u8].into()),
            deadline: CoarseTime::from_secs_since_unix_epoch(7428),
        }
        .into(),
    );

    // Push an anonymous refund.
    messages.push(Refund::anonymous(*LOCAL_CANISTER, Cycles::from(3_456_789_u128)).into());

    let mut stream = Stream::with_signals(
        messages,
        153.into(),
        [RejectSignal::new(
            RejectReason::CanisterMigrating,
            138.into(),
        )]
        .into(),
    );
    stream.set_reverse_stream_flags(StreamFlags {
        deprecated_responses_only: true,
    });

    let proto_stream: pb_queues::Stream = (&stream).into();
    let deserialized_stream: Stream = proto_stream.try_into().expect("bad conversion");
    assert_eq!(stream, deserialized_stream);
}

#[test]
fn deserializing_stream_fails_for_bad_reject_signals() {
    let stream = pb_queues::Stream {
        messages_begin: 0,
        messages: Vec::new(),
        signals_end: 153,
        reject_signals: Vec::new(),
        reverse_stream_flags: None,
    };

    // Deserializing a stream with duplicate reject signals (by index) should fail.
    let bad_stream = pb_queues::Stream {
        reject_signals: vec![
            pb_queues::RejectSignal {
                reason: 1,
                index: 1,
            },
            pb_queues::RejectSignal {
                reason: 1,
                index: 1,
            },
        ],
        ..stream.clone()
    };
    let deserialized_result: Result<Stream, _> = bad_stream.try_into();
    assert_matches!(
        deserialized_result,
        Err(ProxyDecodeError::Other(err_msg)) if err_msg == "reject signals not strictly sorted, received [1, 1]"
    );

    // Deserializing a stream with descending reject signals (by index) should fail.
    let bad_stream = pb_queues::Stream {
        reject_signals: vec![
            pb_queues::RejectSignal {
                reason: 1,
                index: 1,
            },
            pb_queues::RejectSignal {
                reason: 1,
                index: 0,
            },
        ],
        ..stream
    };
    let deserialized_result: Result<Stream, _> = bad_stream.try_into();
    assert_matches!(
        deserialized_result,
        Err(ProxyDecodeError::Other(err_msg)) if err_msg == "reject signals not strictly sorted, received [1, 0]"
    );
}

#[test]
fn reject_reason_proto_roundtrip() {
    for initial in RejectReason::iter() {
        let encoded = pb_queues::RejectReason::from(initial);
        let round_trip = RejectReason::try_from(encoded).unwrap();

        assert_eq!(initial, round_trip);
    }
}

#[test]
fn compatibility_for_reject_reason() {
    assert_eq!(
        RejectReason::iter()
            .map(|reason| reason as i32)
            .collect::<Vec<i32>>(),
        [1, 2, 3, 4, 5, 6, 7]
    );
}

#[test]
fn refund_proto_roundtrip() {
    let initial = Refund::anonymous(*LOCAL_CANISTER, Cycles::new(1_000_000));
    let encoded = pb_queues::Refund::from(&initial);
    let round_trip = Refund::try_from(encoded).unwrap();

    assert_eq!(initial, round_trip);
}

#[test]
fn stream_responses_tracking() {
    let mut stream = Stream::new(StreamIndexedQueue::with_begin(0.into()), 0.into());
    assert!(stream.guaranteed_response_counts().is_empty());

    let response = ResponseBuilder::default()
        .respondent(*LOCAL_CANISTER)
        .originator(*REMOTE_CANISTER)
        .build();
    stream.push(response.into());
    assert_eq!(
        stream.guaranteed_response_counts(),
        &btreemap! { *LOCAL_CANISTER => 1 }
    );

    // Best-effort responses don't count.
    let response = ResponseBuilder::default()
        .respondent(*LOCAL_CANISTER)
        .originator(*REMOTE_CANISTER)
        .deadline(CoarseTime::from_secs_since_unix_epoch(1))
        .build();
    stream.push(response.into());
    assert_eq!(
        stream.guaranteed_response_counts(),
        &btreemap! { *LOCAL_CANISTER => 1 }
    );

    let response = ResponseBuilder::default()
        .respondent(*LOCAL_CANISTER)
        .originator(*REMOTE_CANISTER)
        .build();
    stream.push(response.into());
    assert_eq!(
        stream.guaranteed_response_counts(),
        &btreemap! { *LOCAL_CANISTER => 2 }
    );

    // Response from a different respondent.
    let response = ResponseBuilder::default()
        .respondent(*REMOTE_CANISTER)
        .originator(*LOCAL_CANISTER)
        .build();
    stream.push(response.into());
    assert_eq!(
        stream.guaranteed_response_counts(),
        &btreemap! { *LOCAL_CANISTER => 2, *REMOTE_CANISTER => 1 }
    );

    // Requests don't count.
    let request = RequestBuilder::default()
        .sender(*LOCAL_CANISTER)
        .receiver(*REMOTE_CANISTER)
        .build();
    stream.push(request.into());
    assert_eq!(
        stream.guaranteed_response_counts(),
        &btreemap! { *LOCAL_CANISTER => 2, *REMOTE_CANISTER => 1 }
    );

    // Discard everything in the same order.
    stream.discard_messages_before(StreamIndex::new(1), &vec![].into());
    assert_eq!(
        stream.guaranteed_response_counts(),
        &btreemap! { *LOCAL_CANISTER => 1, *REMOTE_CANISTER => 1 }
    );
    stream.discard_messages_before(StreamIndex::new(2), &vec![].into());
    assert_eq!(
        stream.guaranteed_response_counts(),
        &btreemap! { *LOCAL_CANISTER => 1, *REMOTE_CANISTER => 1 }
    );
    stream.discard_messages_before(StreamIndex::new(4), &vec![].into());
    assert!(stream.guaranteed_response_counts().is_empty());
    stream.discard_messages_before(StreamIndex::new(5), &vec![].into());
    assert!(stream.guaranteed_response_counts().is_empty());
}

#[test]
fn consumed_cycles_total_calculates_the_right_amount() {
    let mut consumed_cycles_by_use_case = BTreeMap::new();
    consumed_cycles_by_use_case.insert(CyclesUseCase::DeletedCanisters, NominalCycles::from(5));
    consumed_cycles_by_use_case.insert(CyclesUseCase::HTTPOutcalls, NominalCycles::from(12));
    consumed_cycles_by_use_case.insert(CyclesUseCase::ECDSAOutcalls, NominalCycles::from(30));
    consumed_cycles_by_use_case.insert(CyclesUseCase::Instructions, NominalCycles::from(100));
    consumed_cycles_by_use_case.insert(CyclesUseCase::Memory, NominalCycles::from(50));
    consumed_cycles_by_use_case.insert(CyclesUseCase::CanisterCreation, NominalCycles::from(40));
    consumed_cycles_by_use_case.insert(CyclesUseCase::NonConsumed, NominalCycles::from(10));

    let subnet_metrics = SubnetMetrics {
        consumed_cycles_by_deleted_canisters: NominalCycles::from(10),
        consumed_cycles_http_outcalls: NominalCycles::from(20),
        consumed_cycles_ecdsa_outcalls: NominalCycles::from(30),
        consumed_cycles_by_use_case,
        ..Default::default()
    };

    assert_eq!(
        subnet_metrics.consumed_cycles_total(),
        NominalCycles::from(250)
    );
}

impl From<(u64, u64)> for BlockmakerStats {
    fn from(item: (u64, u64)) -> Self {
        Self {
            blocks_proposed_total: item.0,
            blocks_not_proposed_total: item.1,
        }
    }
}

#[test]
fn blockmaker_metrics_time_series_check_observe_works() {
    let mut metrics = BlockmakerMetricsTimeSeries::default();
    let mut batch_time = Time::from_nanos_since_unix_epoch(0) + Duration::from_secs(10 * 24 * 3600);

    let test_id_1 = node_test_id(0);
    let test_id_2 = node_test_id(1);
    let test_id_3 = node_test_id(2);

    // Observe metrics twice on the same day, then check no snapshot is available yet.
    metrics.observe(
        batch_time,
        &BlockmakerMetrics {
            blockmaker: test_id_1,
            failed_blockmakers: vec![],
        },
    );
    batch_time += Duration::from_secs(3600);
    metrics.observe(
        batch_time,
        &BlockmakerMetrics {
            blockmaker: test_id_1,
            failed_blockmakers: vec![test_id_2],
        },
    );
    let snapshot = BlockmakerStatsMap {
        node_stats: btreemap! {
            test_id_1 => (2, 0).into(),
            test_id_2 => (0, 1).into(),
        },
        subnet_stats: (2, 1).into(),
    };
    assert_eq!(metrics.running_stats(), Some((&batch_time, &snapshot)),);
    assert_eq!(
        metrics.metrics_since(batch_time).collect::<Vec<_>>(),
        vec![],
    );

    // Observe more metrics a day later, then check the data of yesterday is available
    // and aggregated as a snapshot.
    let later_batch_time = batch_time + Duration::from_secs(3600 * 24);
    metrics.observe(
        later_batch_time,
        &BlockmakerMetrics {
            blockmaker: test_id_2,
            failed_blockmakers: vec![test_id_3],
        },
    );
    assert_eq!(
        metrics.metrics_since(batch_time).collect::<Vec<_>>(),
        vec![(&batch_time, &snapshot)],
    );
    // Check the running stats are still aggregating (i.e. are not reset after making a snapshot).
    assert_eq!(
        metrics.running_stats(),
        Some((
            &later_batch_time,
            &BlockmakerStatsMap {
                node_stats: btreemap! {
                    test_id_1 => (2, 0).into(),
                    test_id_2 => (1, 1).into(),
                    test_id_3 => (0, 1).into(),
                },
                subnet_stats: (3, 2).into(),
            },
        )),
    );

    // Check `metrics_since()` returns the same (all) snapshots for a UNIX_EPOCH,
    // compared to the exact time included in the snapshot.
    assert_eq!(
        metrics.metrics_since(batch_time).collect::<Vec<_>>(),
        metrics
            .metrics_since(Time::from_nanos_since_unix_epoch(0))
            .collect::<Vec<_>>(),
    );

    // Check `metrics_since()` returns nothing for a time after the last observation.
    assert!(
        metrics
            .metrics_since(later_batch_time + Duration::from_secs(365 * 24 * 3600))
            .next()
            .is_none()
    );

    // Check `observe()` does nothing with a batch time before the last obseration.
    let metrics_before = metrics.clone();
    metrics.observe(
        batch_time,
        &BlockmakerMetrics {
            blockmaker: test_id_2,
            failed_blockmakers: vec![test_id_3],
        },
    );
    assert_eq!(metrics, metrics_before);
}

#[test]
fn blockmaker_metrics_time_series_observe_prunes() {
    let mut metrics = BlockmakerMetricsTimeSeries::default();
    let batch_time = Time::from_nanos_since_unix_epoch(0);

    let test_id_1 = node_test_id(0);
    let test_id_2 = node_test_id(1);
    let test_id_3 = node_test_id(2);

    let mut expected_snapshots = BTreeMap::new();

    // Observe `test_id_1` as blockmaker.
    metrics.observe(
        batch_time,
        &BlockmakerMetrics {
            blockmaker: test_id_1,
            failed_blockmakers: vec![],
        },
    );
    // There are no snapshots yet.
    assert!(metrics.metrics_since(batch_time).next().is_none());
    // Check `test_id_1` was observed in the running stats.
    assert_eq!(
        metrics.running_stats(),
        Some((
            &batch_time,
            &BlockmakerStatsMap {
                node_stats: btreemap! {
                    test_id_1 => (1, 0).into(),
                },
                subnet_stats: (1, 0).into(),
            }
        )),
    );

    // Observe `test_id_2` as blockmaker 24 hours later.
    let later_batch_time_1 = batch_time + Duration::from_secs(3600 * 24);
    metrics.observe(
        later_batch_time_1,
        &BlockmakerMetrics {
            blockmaker: test_id_2,
            failed_blockmakers: vec![],
        },
    );
    // A new snapshot is generated including only the first observation.
    expected_snapshots.insert(
        batch_time,
        BlockmakerStatsMap {
            node_stats: btreemap! { test_id_1 => (1, 0).into() },
            subnet_stats: (1, 0).into(),
        },
    );
    assert!(
        metrics
            .metrics_since(batch_time)
            .eq(expected_snapshots.iter())
    );
    // Check `test_id_2` was observed in the running stats.
    assert_eq!(
        metrics.running_stats(),
        Some((
            &later_batch_time_1,
            &BlockmakerStatsMap {
                node_stats: btreemap! {
                    test_id_1 => (1, 0).into(),
                    test_id_2 => (1, 0).into(),
                },
                subnet_stats: (2, 0).into(),
            }
        )),
    );

    // There are now observations spanning more than 24 hours. If we observe `test_id_3`
    // as blockmaker another 24 hours later, `test_id_1` should get pruned from the
    // running stats.
    let later_batch_time_2 = later_batch_time_1 + Duration::from_secs(3600 * 24);
    metrics.observe(
        later_batch_time_2,
        &BlockmakerMetrics {
            blockmaker: test_id_3,
            failed_blockmakers: vec![],
        },
    );
    // `test_id_1` is pruned just before a new snapshot is generated, so it should
    // not include `test_id_1`.
    expected_snapshots.insert(
        later_batch_time_1,
        BlockmakerStatsMap {
            node_stats: btreemap! { test_id_2 => (1, 0).into() },
            subnet_stats: (2, 0).into(),
        },
    );
    assert!(
        metrics
            .metrics_since(batch_time)
            .eq(expected_snapshots.iter())
    );
    // `test_id_1` should be pruned from the running stats.
    assert_eq!(
        metrics.running_stats(),
        Some((
            &later_batch_time_2,
            &BlockmakerStatsMap {
                node_stats: btreemap! {
                    test_id_2 => (1, 0).into(),
                    test_id_3 => (1, 0).into(),
                },
                subnet_stats: (3, 0).into(),
            }
        )),
    );

    // If we observe `test_id_1` again, it should be reintroduced in the running stats,
    // but with its counters restarted.
    metrics.observe(
        later_batch_time_2,
        &BlockmakerMetrics {
            blockmaker: test_id_1,
            failed_blockmakers: vec![],
        },
    );
    assert_eq!(
        metrics.running_stats(),
        Some((
            &later_batch_time_2,
            &BlockmakerStatsMap {
                node_stats: btreemap! {
                    test_id_1 => (1, 0).into(),
                    test_id_2 => (1, 0).into(),
                    test_id_3 => (1, 0).into(),
                },
                subnet_stats: (4, 0).into(),
            },
        ))
    );

    // The presence of `test_id_1` before its pruning should not influence the restarted stats.
    // So if we observe it another 24 hours later, it should be still there with the new observations
    // aggregated.
    let later_batch_time_3 = later_batch_time_2 + Duration::from_secs(3600 * 24);
    metrics.observe(
        later_batch_time_3,
        &BlockmakerMetrics {
            blockmaker: test_id_1,
            failed_blockmakers: vec![],
        },
    );
    // A new snapshot is pushed (Note: `test_id_2` gets pruned just before).
    expected_snapshots.insert(
        later_batch_time_2,
        BlockmakerStatsMap {
            node_stats: btreemap! {
                test_id_1 => (1, 0).into(),
                test_id_3 => (1, 0).into(),
            },
            subnet_stats: (4, 0).into(),
        },
    );
    assert!(
        metrics
            .metrics_since(batch_time)
            .eq(expected_snapshots.iter())
    );
    assert_eq!(
        metrics.running_stats(),
        Some((
            &later_batch_time_3,
            &BlockmakerStatsMap {
                node_stats: btreemap! {
                    test_id_1 => (2, 0).into(),
                    test_id_3 => (1, 0).into(),
                },
                subnet_stats: (5, 0).into(),
            },
        ))
    );
}

struct BlockmakerMetricsFixture;
impl BlockmakerMetricsFixture {
    fn blockmaker_stats_map() -> BlockmakerStatsMap {
        BlockmakerStatsMap {
            node_stats: btreemap! {
                node_test_id(0) => (1, 0).into(),
                node_test_id(1) => (1, 0).into(),
            },
            subnet_stats: (2, 0).into(),
        }
    }

    fn new_with_multiple_samples_per_day() -> BlockmakerMetricsTimeSeries {
        let mut metrics = BlockmakerMetricsTimeSeries::default();
        let batch_time = Time::from_nanos_since_unix_epoch(0);

        // Insert two observations within 10 minutes violating the invariant.
        metrics.0.insert(batch_time, Self::blockmaker_stats_map());
        metrics.0.insert(
            batch_time + Duration::from_secs(10),
            Self::blockmaker_stats_map(),
        );
        metrics
    }

    fn new_with_too_many_observations() -> BlockmakerMetricsTimeSeries {
        let mut metrics = BlockmakerMetricsTimeSeries::default();
        let batch_time = Time::from_nanos_since_unix_epoch(0);

        for i in 0..BLOCKMAKER_METRICS_TIME_SERIES_NUM_SNAPSHOTS + 1 {
            metrics.0.insert(
                batch_time + Duration::from_secs(i as u64 * 24 * 3600),
                Self::blockmaker_stats_map(),
            );
        }
        metrics
    }

    fn new_with_multiple_samples_per_day_and_max_num_samples() -> BlockmakerMetricsTimeSeries {
        let mut metrics = BlockmakerMetricsFixture::new_with_multiple_samples_per_day();
        let batch_time = Time::from_nanos_since_unix_epoch(0);

        for i in 1..BLOCKMAKER_METRICS_TIME_SERIES_NUM_SNAPSHOTS - 1 {
            metrics.0.insert(
                batch_time + Duration::from_secs(i as u64 * 24 * 3600),
                Self::blockmaker_stats_map(),
            );
        }

        assert_eq!(
            metrics.0.len(),
            BLOCKMAKER_METRICS_TIME_SERIES_NUM_SNAPSHOTS
        );

        metrics
    }
}

fn check_invariant_self_heals(mut metrics: BlockmakerMetricsTimeSeries, error: &str) {
    let batch_time = Time::from_nanos_since_unix_epoch(0);

    // Make sure the invariant is broken
    assert_matches!(metrics.check_soft_invariants(), Err(err) if err.contains(error));

    // The next observation should restore the soft invariant.
    metrics.observe(
        batch_time + Duration::from_secs(u64::MAX / 2),
        &BlockmakerMetrics {
            blockmaker: node_test_id(0),
            failed_blockmakers: vec![],
        },
    );

    assert!(metrics.check_soft_invariants().is_ok());
}

#[test]
fn blockmaker_metrics_soft_invariant_multiple_samples_self_heals() {
    check_invariant_self_heals(
        BlockmakerMetricsFixture::new_with_multiple_samples_per_day_and_max_num_samples(),
        "Found two timestamps",
    );
}

#[test]
fn blockmaker_metrics_soft_invariant_size_limit_self_heals() {
    check_invariant_self_heals(
        BlockmakerMetricsFixture::new_with_too_many_observations(),
        "exceeds limit",
    );
}

fn do_roundtrip_and_check_error(metrics: &BlockmakerMetricsTimeSeries, expected_error: &str) {
    use std::sync::Mutex;

    struct TestMetrics(Arc<Mutex<String>>);
    impl CheckpointLoadingMetrics for TestMetrics {
        fn observe_broken_soft_invariant(&self, error: String) {
            *self.0.lock().unwrap() = error;
        }
    }

    let test_metrics = TestMetrics(Arc::new(Mutex::new("".to_string())));

    // Currently the String stored in `TestMetrics` is still empty
    assert!(test_metrics.0.lock().unwrap().is_empty());

    let pb_stats = pb_metadata::BlockmakerMetricsTimeSeries::from(metrics);
    let deserialized_stats = BlockmakerMetricsTimeSeries::try_from((
        pb_stats,
        &test_metrics as &dyn CheckpointLoadingMetrics,
    ))
    .unwrap();

    // But the invariant check done in deserialization will set the error message.
    assert!(test_metrics.0.lock().unwrap().contains(expected_error));

    // Assert the the (de)serialization roundtrip works as expected despite
    // the invariant violation.
    assert_eq!(metrics, &deserialized_stats);
}

#[test]
fn blockmaker_metrics_soft_invariant_multiple_samples_bumps_critical_error_counter() {
    let metrics = BlockmakerMetricsFixture::new_with_multiple_samples_per_day();
    assert_matches!(metrics.check_soft_invariants(), Err(err) if err.contains("Found two timestamps"));
    do_roundtrip_and_check_error(&metrics, "Found two timestamps");
}

#[test]
fn blockmaker_metrics_soft_invariant_size_limit_bumps_critical_error_counter() {
    let metrics = BlockmakerMetricsFixture::new_with_too_many_observations();
    assert_matches!(metrics.check_soft_invariants(), Err(err) if err.contains("exceeds limit"));
    do_roundtrip_and_check_error(&metrics, "exceeds limit");
}

#[test]
fn canister_state_bits_cycles_use_case_round_trip() {
    use ic_protobuf::state::canister_state_bits::v1 as pb;

    for initial in CyclesUseCase::iter() {
        let encoded = pb::CyclesUseCase::from(initial);
        let round_trip = CyclesUseCase::try_from(encoded).unwrap();

        assert_eq!(initial, round_trip);
    }
}

#[test]
fn compatibility_for_cycles_use_case() {
    // If this fails, you are making a potentially incompatible change to `CyclesUseCase`.
    // See note [Handling changes to Enums in Replicated State] for how to proceed.
    assert_eq!(
        CyclesUseCase::iter()
            .map(|x| x as i32)
            .collect::<Vec<i32>>(),
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    );
}

const MAX_NUM_DAYS: usize = BLOCKMAKER_METRICS_TIME_SERIES_NUM_SNAPSHOTS + 10;
const MAX_NUM_DAYS_NANOS: u64 = MAX_NUM_DAYS as u64 * 24 * 3600 * 1_000_000_000;
// The compiler doesn't see the use of these constants inside the `proptest!` macro.
// The range for `batch_time` is chosen such that random u64 have about a 50% chance to lie
// above or below it.
#[allow(dead_code)]
const BATCH_TIME_RANGE: Range<u64> = (u64::MAX / 2)..(u64::MAX / 2 + MAX_NUM_DAYS_NANOS);
#[allow(dead_code)]
const NODE_ID_RANGE: Range<u64> = 0..20;

/// Checks that `check_soft_invariants()` does not return an error when observing random
/// node IDs at random mostly sorted and slightly permuted timestamps.
/// Such invariants are checked indirectly at the bottom of `observe()` where
/// `check_soft_invariants()` is called. There is an additional call to
/// `check_soft_invariants()` at the end of the test to ensure the test doesn't
/// silently pass when the production code is changed.
/// Querying `metrics_since()` is also checked using completely random time stamps to
/// ensure there are no hidden panics.
#[test_strategy::proptest]
fn blockmaker_metrics_check_soft_invariants(
    #[strategy(0..MAX_NUM_DAYS)] _num_elements: usize,
    #[strategy(proptest::collection::vec(BATCH_TIME_RANGE, #_num_elements))] mut time_u64: Vec<u64>,
    #[strategy(proptest::collection::vec(any::<u64>(), #_num_elements))] random_time_u64: Vec<u64>,
    #[strategy(proptest::collection::vec(NODE_ID_RANGE, #_num_elements))] node_ids_u64: Vec<u64>,
) {
    // Sort timestamps, then slightly permute them by inserting some
    // duplicates and swapping elements in some places.
    time_u64.sort();
    if !time_u64.is_empty() {
        for index in 0..(time_u64.len() - 1) {
            if time_u64[index] % 23 == 0 {
                time_u64[index + 1] = time_u64[index];
            }
            if time_u64[index] % 27 == 0 {
                time_u64.swap(index, index + 1);
            }
        }
    }

    let mut metrics = BlockmakerMetricsTimeSeries::default();
    // Observe a unique node ID first to ensure the pruning process
    // is triggered once the metrics reach capacity.
    metrics.observe(
        Time::from_nanos_since_unix_epoch(0),
        &BlockmakerMetrics {
            blockmaker: node_test_id(NODE_ID_RANGE.end + 10),
            failed_blockmakers: vec![],
        },
    );
    // Observe random node IDs at random increasing timestamps; `check_runtime_invariants()`
    // will be triggered passively each time `observe()` is called.
    // Additionally, query snapshots at random times and consume the iterator to ensure
    // there are no hidden panics in `metrics_since()`.
    for ((batch_time_u64, query_time_u64), node_id_u64) in time_u64
        .into_iter()
        .zip(random_time_u64.into_iter())
        .zip(node_ids_u64.into_iter())
    {
        metrics.observe(
            Time::from_nanos_since_unix_epoch(batch_time_u64),
            &BlockmakerMetrics {
                blockmaker: node_test_id(node_id_u64),
                failed_blockmakers: vec![node_test_id(node_id_u64 + 1)],
            },
        );
        metrics
            .metrics_since(Time::from_nanos_since_unix_epoch(query_time_u64))
            .count();
    }

    prop_assert!(metrics.check_soft_invariants().is_ok());
}
