use super::{decode_certified_deltas, CertificationError};
use ic_crypto::combined_threshold_signature_and_public_key;
use ic_crypto_tree_hash::{
    flatmap, Digest, FlatMap, HashTreeBuilder, HashTreeBuilderImpl, Label, LabeledTree,
    MixedHashTree, WitnessGenerator,
};
use ic_interfaces::registry::RegistryTransportRecord;
use ic_registry_transport::{
    delete,
    pb::v1::{CertifiedResponse, RegistryAtomicMutateRequest, RegistryMutation},
    upsert,
};
use ic_types::{
    consensus::certification::CertificationContent,
    crypto::{threshold_sig::ThresholdSigPublicKey, CryptoHash},
    crypto::{CombinedThresholdSig, CombinedThresholdSigOf},
    CanisterId, CryptoHashOfPartialState, Randomness, RegistryVersion, Time,
};
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

fn make_certificate(
    cid: &CanisterId,
    certified_data: &Digest,
    fake_sig: Option<CombinedThresholdSig>,
) -> (ThresholdSigPublicKey, Vec<u8>) {
    #[derive(serde::Serialize)]
    struct Certificate {
        tree: MixedHashTree,
        signature: CombinedThresholdSigOf<CertificationContent>,
    }

    fn hash_full_tree(b: &mut HashTreeBuilderImpl, t: &LabeledTree<Vec<u8>>) {
        match t {
            LabeledTree::Leaf(bytes) => {
                b.start_leaf();
                b.write_leaf(&bytes[..]);
                b.finish_leaf();
            }
            LabeledTree::SubTree(map) => {
                b.start_subtree();
                for (l, child) in map.iter() {
                    b.new_edge(l.clone());
                    hash_full_tree(b, child);
                }
                b.finish_subtree();
            }
        }
    }
    let mut encoded_time = vec![];
    leb128::write::unsigned(&mut encoded_time, REPLICA_TIME).unwrap();

    let tree = LabeledTree::SubTree(flatmap![
        Label::from("canister") => LabeledTree::SubTree(flatmap![
            Label::from(cid.get_ref().to_vec()) => LabeledTree::SubTree(flatmap![
                Label::from("certified_data") => LabeledTree::Leaf(certified_data.to_vec()),
            ])
        ]),
        Label::from("time") => LabeledTree::Leaf(encoded_time)
    ]);

    let mut b = HashTreeBuilderImpl::new();
    hash_full_tree(&mut b, &tree);
    let witness_gen = b.witness_generator().unwrap();
    let hash_tree_digest = witness_gen.hash_tree().digest();
    let mixed_tree = witness_gen.mixed_hash_tree(&tree).unwrap();
    let root_hash = CryptoHashOfPartialState::from(CryptoHash(hash_tree_digest.to_vec()));

    let (sig, pk) = combined_threshold_signature_and_public_key(
        Randomness::from([0; 32]),
        &CertificationContent::new(root_hash),
    );

    let bytes = serde_cbor::to_vec(&Certificate {
        tree: mixed_tree,
        signature: fake_sig
            .map(CombinedThresholdSigOf::<CertificationContent>::from)
            .unwrap_or(sig),
    })
    .unwrap();

    (pk, bytes)
}

fn make_certified_delta(
    deltas: Vec<RegistryAtomicMutateRequest>,
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
    let fake_sig = if let GarbleResponse::OverrideSignature(sig) = &garble_response {
        Some(sig.clone())
    } else {
        None
    };
    let (pk, certificate) = make_certificate(&cid, &digest, fake_sig);

    let response = CertifiedResponse {
        hash_tree: Some(mixed_hash_tree.into()),
        certificate,
    };

    let mut encoded_response = vec![];
    response.encode(&mut encoded_response).unwrap();

    (cid, pk, encoded_response)
}

fn set_key(version: u64, k: impl ToString, v: impl AsRef<[u8]>) -> RegistryTransportRecord {
    RegistryTransportRecord {
        version: RegistryVersion::from(version),
        key: k.to_string(),
        value: Some(v.as_ref().to_vec()),
    }
}

fn rem_key(version: u64, k: impl ToString) -> RegistryTransportRecord {
    RegistryTransportRecord {
        version: RegistryVersion::from(version),
        key: k.to_string(),
        value: None,
    }
}

fn make_change(mutations: Vec<RegistryMutation>) -> RegistryAtomicMutateRequest {
    RegistryAtomicMutateRequest {
        mutations,
        preconditions: vec![],
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
        decode_certified_deltas(1, &cid, &pk, &payload[..]).unwrap(),
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
        decode_certified_deltas(0, &cid, &pk, &payload[..]).unwrap(),
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
        decode_certified_deltas(0, &cid, &pk, &payload[..]).unwrap(),
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
    match decode_certified_deltas(0, &cid, &pk, &payload[..]) {
        Err(CertificationError::CertifiedDataMismatch { certified, .. })
            if &certified[..] == bad_digest.as_bytes() => {}
        other => panic!(
            "Expected CertifiedDataMismatch error containing the bad digest {}, got {:?}",
            bad_digest, other
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
    match decode_certified_deltas(0, &cid, &pk, &payload[..]) {
        Err(CertificationError::InvalidSignature(_)) => (),
        other => panic!("Expected InvalidSignature error, got {:?}", other),
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
        decode_certified_deltas(0, &cid, &pk, &payload[..]).unwrap(),
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
    match decode_certified_deltas(0, &cid, &pk, &payload[..]) {
        Err(CertificationError::InvalidDeltas(_)) => (),
        other => panic!("Expected InvalidDeltas error, got {:?}", other),
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
    match decode_certified_deltas(0, &cid, &pk, &payload[..]) {
        Err(CertificationError::InvalidDeltas(_)) => (),
        other => panic!("Expected InvalidDeltas error, got {:?}", other),
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
    match decode_certified_deltas(0, &cid, &pk, &payload[..]) {
        Err(CertificationError::InvalidDeltas(_)) => (),
        other => panic!("Expected InvalidDeltas error, got {:?}", other),
    }
}
