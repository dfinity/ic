use super::*;
use futures_util::FutureExt;
use ic_certification_test_utils::{CertificateBuilder, CertificateData};
use ic_crypto_sha2::Sha256;
use ic_crypto_tree_hash::{
    Digest, FlatMap, HashTreeBuilder, HashTreeBuilderImpl, Label, LabeledTree, WitnessGenerator,
    flatmap,
};
use ic_interfaces_registry::RegistryRecord;
use ic_registry_transport::{
    MockGetChunk, delete,
    pb::v1::{
        CertifiedResponse, HighCapacityRegistryMutation, LargeValueChunkKeys, RegistryMutation,
        high_capacity_registry_mutation, registry_mutation,
    },
    upsert,
};
use ic_types::{
    CanisterId, RegistryVersion, Time, crypto::CombinedThresholdSig,
    crypto::threshold_sig::ThresholdSigPublicKey,
};
use pretty_assertions::assert_eq;
use prost::Message;
use std::string::ToString;

const REPLICA_TIME: u64 = 1234567;

#[derive(Clone)]
enum GarbleResponse {
    LeaveAsIs,
    OverrideCertifiedData(Digest),
    OverrideSignature(CombinedThresholdSig),
    DropVersion(u64),
}

impl GarbleResponse {
    fn should_drop_version(&self, version: u64) -> bool {
        matches!(self, Self::DropVersion(v) if *v == version)
    }
}

type EncodedResponse = Vec<u8>;

fn decode_certified_deltas_no_chunks(
    since_version: u64,
    canister_id: &CanisterId,
    nns_pk: &ThresholdSigPublicKey,
    payload: &[u8],
) -> Result<(Vec<RegistryRecord>, RegistryVersion, Time), CertificationError> {
    decode_certified_deltas(
        since_version,
        canister_id,
        nns_pk,
        payload,
        &MockGetChunk::new(),
    )
    .now_or_never()
    .unwrap()
}

fn make_certified_delta(
    deltas: Vec<HighCapacityRegistryAtomicMutateRequest>,
    selection: impl std::ops::RangeBounds<u64>,
    garble_response: GarbleResponse,
) -> (CanisterId, ThresholdSigPublicKey, EncodedResponse) {
    let cid = CanisterId::from_u64(1);

    let mut encoded_version = vec![];

    let mut b = HashTreeBuilderImpl::new();

    let current_version_label = Label::from("current_version");
    b.start_subtree();

    b.new_edge(current_version_label.clone());
    b.start_leaf();
    leb128::write::unsigned(&mut encoded_version, deltas.len() as u64).unwrap();
    b.write_leaf(&encoded_version[..]);
    b.finish_leaf();

    let mut map: FlatMap<Label, LabeledTree<Vec<u8>>> = FlatMap::new();

    if !deltas.is_empty() {
        b.new_edge(Label::from("delta"));
        b.start_subtree();
        for (i, delta) in deltas.into_iter().enumerate() {
            let version = (i + 1) as u64;

            let mut buf = vec![];

            let label = Label::from(version.to_be_bytes());
            b.new_edge(label.clone());
            b.start_leaf();
            delta.encode(&mut buf).unwrap();
            b.write_leaf(&buf[..]);
            b.finish_leaf();

            if selection.contains(&version) && !garble_response.should_drop_version(version) {
                map.try_append(label, LabeledTree::Leaf(buf)).unwrap();
            }
        }
        b.finish_subtree();
    }
    b.finish_subtree();

    let witness_gen = b.witness_generator().unwrap();

    let digest = if let GarbleResponse::OverrideCertifiedData(digest) = &garble_response {
        digest.clone()
    } else {
        witness_gen.hash_tree().digest().clone()
    };

    let mut root = flatmap!(current_version_label => LabeledTree::Leaf(encoded_version));
    if !map.is_empty() {
        root.try_append(Label::from("delta"), LabeledTree::SubTree(map))
            .unwrap();
    }
    let data_tree = LabeledTree::SubTree(root);

    let mixed_hash_tree = witness_gen.mixed_hash_tree(&data_tree).unwrap();

    let mut builder = CertificateBuilder::new(CertificateData::CanisterData {
        canister_id: cid,
        certified_data: digest,
    });
    if let GarbleResponse::OverrideSignature(sig) = &garble_response {
        builder = builder.with_sig(sig.clone());
    }
    let (_, pk, cbor) = builder.build();

    let response = CertifiedResponse {
        hash_tree: Some(mixed_hash_tree.into()),
        certificate: cbor,
    };

    let mut encoded_response = vec![];
    response.encode(&mut encoded_response).unwrap();

    (cid, pk, encoded_response)
}

fn set_key(version: u64, k: impl ToString, v: impl AsRef<[u8]>) -> RegistryRecord {
    RegistryRecord {
        version: RegistryVersion::from(version),
        key: k.to_string(),
        value: Some(v.as_ref().to_vec()),
    }
}

fn rem_key(version: u64, k: impl ToString) -> RegistryRecord {
    RegistryRecord {
        version: RegistryVersion::from(version),
        key: k.to_string(),
        value: None,
    }
}

fn make_change(mutations: Vec<RegistryMutation>) -> HighCapacityRegistryAtomicMutateRequest {
    let mutations = mutations
        .into_iter()
        .map(HighCapacityRegistryMutation::from)
        .collect();
    HighCapacityRegistryAtomicMutateRequest {
        mutations,
        preconditions: vec![],
        timestamp_nanoseconds: 0,
    }
}

#[test]
fn test_decode_no_update() {
    let (cid, pk, payload) = make_certified_delta(
        vec![make_change(vec![upsert("key", "value")])],
        2..=2,
        GarbleResponse::LeaveAsIs,
    );
    assert_eq!(
        decode_certified_deltas_no_chunks(1, &cid, &pk, &payload[..]).unwrap(),
        (
            vec![],
            RegistryVersion::from(1u64),
            Time::from_nanos_since_unix_epoch(REPLICA_TIME)
        ),
    )
}

#[test]
fn test_decode_single_delta() {
    let (cid, pk, payload) = make_certified_delta(
        vec![make_change(vec![upsert("key", "value")])],
        1..=1,
        GarbleResponse::LeaveAsIs,
    );
    assert_eq!(
        decode_certified_deltas_no_chunks(0, &cid, &pk, &payload[..]).unwrap(),
        (
            vec![set_key(1, "key", "value")],
            RegistryVersion::from(1u64),
            Time::from_nanos_since_unix_epoch(REPLICA_TIME),
        ),
    )
}

#[test]
fn test_decode_prefix() {
    let (cid, pk, payload) = make_certified_delta(
        vec![
            make_change(vec![upsert("key1", "value1"), upsert("key2", "value2")]),
            make_change(vec![delete("key1"), upsert("key2", "value22")]),
            make_change(vec![upsert("key3", "value3")]),
        ],
        1..=2,
        GarbleResponse::LeaveAsIs,
    );

    assert_eq!(
        decode_certified_deltas_no_chunks(0, &cid, &pk, &payload[..]).unwrap(),
        (
            vec![
                set_key(1, "key1", "value1"),
                set_key(1, "key2", "value2"),
                rem_key(2, "key1"),
                set_key(2, "key2", "value22"),
            ],
            RegistryVersion::from(3u64),
            Time::from_nanos_since_unix_epoch(REPLICA_TIME),
        ),
    )
}

#[test]
fn test_decode_bad_root_hash() {
    let bad_digest = Digest([0u8; 32]);

    let (cid, pk, payload) = make_certified_delta(
        vec![make_change(vec![upsert("key", "value")])],
        1..=1,
        GarbleResponse::OverrideCertifiedData(bad_digest.clone()),
    );
    match decode_certified_deltas_no_chunks(0, &cid, &pk, &payload[..]) {
        Err(CertificationError::CertifiedDataMismatch { certified, .. })
            if &certified[..] == bad_digest.as_bytes() => {}
        other => panic!(
            "Expected CertifiedDataMismatch error containing the bad digest {bad_digest}, got {other:?}"
        ),
    }
}

#[test]
fn test_decode_bad_sig() {
    let bad_sig = CombinedThresholdSig(vec![0u8; 32]);

    let (cid, pk, payload) = make_certified_delta(
        vec![make_change(vec![upsert("key", "value")])],
        1..=1,
        GarbleResponse::OverrideSignature(bad_sig),
    );
    match decode_certified_deltas_no_chunks(0, &cid, &pk, &payload[..]) {
        Err(CertificationError::InvalidSignature(_)) => (),
        other => panic!("Expected InvalidSignature error, got {other:?}"),
    }
}

#[test]
fn test_missing_tail_is_ok() {
    let (cid, pk, payload) = make_certified_delta(
        vec![
            make_change(vec![upsert("key1", "value1")]),
            make_change(vec![upsert("key2", "value2")]),
            make_change(vec![upsert("key3", "value3")]),
            make_change(vec![upsert("key4", "value4")]),
        ],
        1..=4,
        GarbleResponse::DropVersion(4),
    );
    assert_eq!(
        decode_certified_deltas_no_chunks(0, &cid, &pk, &payload[..]).unwrap(),
        (
            vec![
                set_key(1, "key1", "value1"),
                set_key(2, "key2", "value2"),
                set_key(3, "key3", "value3"),
            ],
            RegistryVersion::from(4u64),
            Time::from_nanos_since_unix_epoch(REPLICA_TIME),
        ),
    )
}

#[test]
fn test_decode_missing_version() {
    let (cid, pk, payload) = make_certified_delta(
        vec![
            make_change(vec![upsert("key1", "value1")]),
            make_change(vec![upsert("key2", "value2")]),
        ],
        1..=2,
        GarbleResponse::DropVersion(1),
    );
    match decode_certified_deltas_no_chunks(0, &cid, &pk, &payload[..]) {
        Err(CertificationError::InvalidDeltas(_)) => (),
        other => panic!("Expected InvalidDeltas error, got {other:?}"),
    }
}

#[test]
fn test_decode_missing_middle_version() {
    let (cid, pk, payload) = make_certified_delta(
        vec![
            make_change(vec![upsert("key1", "value1")]),
            make_change(vec![upsert("key2", "value2")]),
            make_change(vec![upsert("key3", "value3")]),
        ],
        1..=3,
        GarbleResponse::DropVersion(2),
    );
    match decode_certified_deltas_no_chunks(0, &cid, &pk, &payload[..]) {
        Err(CertificationError::InvalidDeltas(_)) => (),
        other => panic!("Expected InvalidDeltas error, got {other:?}"),
    }
}

#[allow(clippy::reversed_empty_ranges)]
#[test]
fn test_decode_empty_prefix() {
    let (cid, pk, payload) = make_certified_delta(
        vec![
            make_change(vec![upsert("key1", "value1")]),
            make_change(vec![upsert("key2", "value2")]),
        ],
        1..1,
        GarbleResponse::LeaveAsIs,
    );
    match decode_certified_deltas_no_chunks(0, &cid, &pk, &payload[..]) {
        Err(CertificationError::InvalidDeltas(_)) => (),
        other => panic!("Expected InvalidDeltas error, got {other:?}"),
    }
}

#[test]
fn test_honest_chunked() {
    // Step 1: Prepare the world.

    let chunk_contents = vec![
        b"It was the best of times.\n".to_vec(),
        b"It was the worst of times.\n".to_vec(),
        b"It was the age of foolishness.\n".to_vec(),
        b"It was the epoch of belief.\n".to_vec(),
    ];

    let chunk_content_sha256s = chunk_contents
        .iter()
        .map(|chunk_content| Sha256::hash(chunk_content).to_vec())
        .collect::<Vec<Vec<u8>>>();

    let mut get_chunk = MockGetChunk::new();
    for (content, content_sha256) in chunk_contents.iter().zip(chunk_content_sha256s.iter()) {
        get_chunk
            .expect_get_chunk_without_validation()
            .with(mockall::predicate::eq(content_sha256.clone()))
            .times(1)
            .return_const(Ok(content.clone()));
    }

    let (cid, pk, payload) = make_certified_delta(
        vec![HighCapacityRegistryAtomicMutateRequest {
            mutations: vec![HighCapacityRegistryMutation {
                key: b"giant_blob".to_vec(),
                mutation_type: registry_mutation::Type::Insert as i32,
                content: Some(
                    high_capacity_registry_mutation::Content::LargeValueChunkKeys(
                        LargeValueChunkKeys {
                            chunk_content_sha256s,
                        },
                    ),
                ),
            }],
            preconditions: vec![],
            timestamp_nanoseconds: 1735689600000000000, // Jan 1, 2025 midnight UTC
        }],
        1..=1,
        GarbleResponse::LeaveAsIs,
    );

    // Step 2: Call the code under test.
    let result = decode_certified_deltas(0, &cid, &pk, &payload[..], &get_chunk)
        .now_or_never()
        .unwrap()
        .unwrap();

    // Step 3: Verify result(s).
    let monolithic_blob = chunk_contents
        .clone()
        .into_iter()
        .flatten()
        .collect::<Vec<u8>>();
    assert_eq!(
        result,
        (
            vec![set_key(1, "giant_blob", monolithic_blob)],
            RegistryVersion::from(1u64),
            Time::from_nanos_since_unix_epoch(REPLICA_TIME),
        ),
    );
}

#[test]
fn test_evil_chunked() {
    // Step 1: Prepare the world.

    let chunk_content = b"response from an honest node".to_vec();

    let chunk_content_sha256 = Sha256::hash(&chunk_content).to_vec();

    let mut get_chunk = MockGetChunk::new();
    get_chunk
        .expect_get_chunk_without_validation()
        .with(mockall::predicate::eq(chunk_content_sha256.clone()))
        .times(1)
        .return_const(Ok(b"DO NOT BELIEVE THE LIES OF THIS EVIL NODE".to_vec()));

    // Same as test_honest_chunked.
    let (cid, pk, payload) = make_certified_delta(
        vec![HighCapacityRegistryAtomicMutateRequest {
            mutations: vec![HighCapacityRegistryMutation {
                key: b"giant_blob".to_vec(),
                mutation_type: registry_mutation::Type::Insert as i32,
                content: Some(
                    high_capacity_registry_mutation::Content::LargeValueChunkKeys(
                        LargeValueChunkKeys {
                            chunk_content_sha256s: vec![chunk_content_sha256],
                        },
                    ),
                ),
            }],
            preconditions: vec![],
            timestamp_nanoseconds: 1735689600000000000, // Jan 1, 2025 midnight UTC
        }],
        1..=1,
        GarbleResponse::LeaveAsIs,
    );

    // Step 2: Call the code under test.
    let result = decode_certified_deltas(0, &cid, &pk, &payload[..], &get_chunk)
        .now_or_never()
        .unwrap();

    // Step 3: Verify result(s).
    match result {
        Err(CertificationError::DechunkifyingFailed(
            ic_registry_transport::Error::UnknownError(err),
        )) => {
            let message = err.to_lowercase();
            for key_word in ["chunk", "hash", "match"] {
                assert!(message.contains(key_word), "{key_word} not in {err}");
            }
        }

        _ => panic!("{result:?}"),
    }
}
