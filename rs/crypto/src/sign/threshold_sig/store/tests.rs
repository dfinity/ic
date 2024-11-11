#![allow(clippy::unwrap_used)]

use super::*;
use crate::sign::threshold_sig::tests::{NI_DKG_ID_1, NI_DKG_ID_2};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::PublicCoefficientsBytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::CspThresholdSigPublicKey;
use ic_types::crypto::threshold_sig::ni_dkg::NiDkgId;
use ic_types::Height;
use ic_types_test_utils::ids::{node_test_id, SUBNET_1};

const NODE_1: u64 = 1;
const NODE_2: u64 = 2;
const NODE_1_INDEX: NodeIndex = 1;
const NODE_2_INDEX: NodeIndex = 2;

#[test]
fn should_contain_transcript_data_after_insertion_with_nidkg_id() {
    should_contain_transcript_data_after_insertion_with_dkg_id(NI_DKG_ID_1);
}

fn should_contain_transcript_data_after_insertion_with_dkg_id(dkg_id: NiDkgId) {
    let mut store = ThresholdSigDataStoreImpl::new();
    let indices = indices_with(vec![
        (node_test_id(NODE_1), NODE_1_INDEX),
        (node_test_id(NODE_2), NODE_2_INDEX),
    ]);
    let public_coeffs = public_coeffs();

    store.insert_transcript_data(dkg_id, public_coeffs.clone(), indices);

    let transcript_data = store.transcript_data(dkg_id).unwrap();
    assert_eq!(transcript_data.public_coefficients(), &public_coeffs);
    assert_eq!(
        transcript_data.index(node_test_id(NODE_1)),
        Some(&NODE_1_INDEX)
    );
    assert_eq!(
        transcript_data.index(node_test_id(NODE_2)),
        Some(&NODE_2_INDEX)
    );
}

#[test]
fn should_not_contain_nonexistent_transcript_data() {
    let store = ThresholdSigDataStoreImpl::new();

    assert!(store.transcript_data(NI_DKG_ID_1).is_none());
}

#[test]
fn should_contain_individual_public_keys_after_insertion_with_nidkg_id() {
    let dkg_id = NI_DKG_ID_1;
    let mut store = ThresholdSigDataStoreImpl::new();
    let csp_pubkey = csp_public_key();

    store.insert_individual_public_key(dkg_id, node_test_id(NODE_1), csp_pubkey);

    assert_eq!(
        store.individual_public_key(dkg_id, node_test_id(NODE_1)),
        Some(&csp_pubkey)
    );
}

#[test]
fn should_insert_multiple_individual_public_keys() {
    let mut store = ThresholdSigDataStoreImpl::new();
    let csp_pubkey_1 = csp_public_key();
    let csp_pubkey_2 = csp_public_key();

    assert_ne!(NI_DKG_ID_1, NI_DKG_ID_2);
    store.insert_individual_public_key(NI_DKG_ID_1, node_test_id(NODE_1), csp_pubkey_1);
    store.insert_individual_public_key(NI_DKG_ID_1, node_test_id(NODE_2), csp_pubkey_2);
    store.insert_individual_public_key(NI_DKG_ID_2, node_test_id(NODE_1), csp_pubkey_2);

    assert_eq!(
        store.individual_public_key(NI_DKG_ID_1, node_test_id(NODE_1)),
        Some(&csp_pubkey_1)
    );
    assert_eq!(
        store.individual_public_key(NI_DKG_ID_1, node_test_id(NODE_2)),
        Some(&csp_pubkey_2)
    );
    assert_eq!(
        store.individual_public_key(NI_DKG_ID_2, node_test_id(NODE_1)),
        Some(&csp_pubkey_2)
    );
}

#[test]
fn should_not_contain_nonexistent_individual_public_key() {
    let store = ThresholdSigDataStoreImpl::new();

    assert_eq!(
        store.individual_public_key(NI_DKG_ID_1, node_test_id(NODE_1)),
        None
    );
}

#[test]
fn should_overwrite_existing_public_coefficients() {
    let mut store = ThresholdSigDataStoreImpl::new();
    let (public_coeffs_1, public_coeffs_2) = (public_coeffs_1(), public_coeffs_2());
    assert_ne!(public_coeffs_1, public_coeffs_2);

    store.insert_transcript_data(NI_DKG_ID_1, public_coeffs_1, BTreeMap::new());
    store.insert_transcript_data(NI_DKG_ID_1, public_coeffs_2.clone(), BTreeMap::new());

    let transcript_data = store.transcript_data(NI_DKG_ID_1).unwrap();
    assert_eq!(transcript_data.public_coefficients(), &public_coeffs_2);
}

#[test]
fn should_overwrite_existing_indices() {
    let mut store = ThresholdSigDataStoreImpl::new();
    let indices_1 = indices_with(vec![(node_test_id(NODE_1), NODE_1_INDEX)]);
    let indices_2 = indices_with(vec![(node_test_id(NODE_2), NODE_2_INDEX)]);
    let public_coeffs = public_coeffs();

    store.insert_transcript_data(NI_DKG_ID_1, public_coeffs.clone(), indices_1);
    store.insert_transcript_data(NI_DKG_ID_1, public_coeffs, indices_2);

    let transcript_data = store.transcript_data(NI_DKG_ID_1).unwrap();
    assert_eq!(transcript_data.index(node_test_id(NODE_1)), None);
    assert_eq!(
        transcript_data.index(node_test_id(NODE_2)),
        Some(&NODE_2_INDEX)
    );
}

#[test]
fn should_overwrite_existing_individual_public_keys() {
    let mut store = ThresholdSigDataStoreImpl::new();
    let csp_pubkey_1 = csp_public_key();
    let csp_pubkey_2 = other_csp_public_key();
    assert_ne!(csp_pubkey_1, csp_pubkey_2);

    store.insert_individual_public_key(NI_DKG_ID_1, node_test_id(NODE_1), csp_pubkey_1);
    store.insert_individual_public_key(NI_DKG_ID_1, node_test_id(NODE_1), csp_pubkey_2);

    assert_eq!(
        store.individual_public_key(NI_DKG_ID_1, node_test_id(NODE_1)),
        Some(&csp_pubkey_2)
    );
}

#[test]
fn should_have_capacity_per_tag_of_9() {
    assert_eq!(ThresholdSigDataStoreImpl::CAPACITY_PER_TAG, 9)
}

#[test]
fn should_not_purge_data_on_inserting_coeffs_and_indices_if_capacity_not_exceeded() {
    let mut store = ThresholdSigDataStoreImpl::new();

    for i in 1..=ThresholdSigDataStoreImpl::CAPACITY_PER_TAG {
        store.insert_transcript_data(ni_dkg_id(i), public_coeffs(), BTreeMap::new());
    }

    assert_eq!(
        store.store.len(),
        ThresholdSigDataStoreImpl::CAPACITY_PER_TAG
    );
}

#[test]
fn should_not_purge_data_on_inserting_pubkeys_if_capacity_not_exceeded() {
    let mut store = ThresholdSigDataStoreImpl::new();

    for i in 1..=ThresholdSigDataStoreImpl::CAPACITY_PER_TAG {
        store.insert_individual_public_key(ni_dkg_id(i), node_test_id(NODE_1), csp_public_key());
    }

    assert_eq!(
        store.store.len(),
        ThresholdSigDataStoreImpl::CAPACITY_PER_TAG
    );
}

#[test]
fn should_purge_data_on_inserting_coeffs_and_indices_if_capacity_exceeded() {
    let mut store = ThresholdSigDataStoreImpl::new();
    let pub_coeffs = public_coeffs();

    for i in 1..=ThresholdSigDataStoreImpl::CAPACITY_PER_TAG + 1 {
        store.insert_transcript_data(ni_dkg_id(i), pub_coeffs.clone(), BTreeMap::new());
    }

    assert_eq!(
        store.store.len(),
        ThresholdSigDataStoreImpl::CAPACITY_PER_TAG
    );
    assert!(store.transcript_data(ni_dkg_id(1)).is_none());
    for i in 2..=ThresholdSigDataStoreImpl::CAPACITY_PER_TAG + 1 {
        assert_eq!(pub_coeffs_from_store(&store, ni_dkg_id(i)), pub_coeffs);
    }
}

#[test]
fn should_purge_data_in_insertion_order_on_inserting_coeffs_and_indices_if_capacity_exceeded() {
    let mut store = ThresholdSigDataStoreImpl::new();
    let pub_coeffs = public_coeffs();

    for i in (1..=ThresholdSigDataStoreImpl::CAPACITY_PER_TAG + 1).rev() {
        store.insert_transcript_data(ni_dkg_id(i), pub_coeffs.clone(), BTreeMap::new());
    }

    assert_eq!(
        store.store.len(),
        ThresholdSigDataStoreImpl::CAPACITY_PER_TAG
    );
    for i in 1..=ThresholdSigDataStoreImpl::CAPACITY_PER_TAG {
        assert_eq!(pub_coeffs_from_store(&store, ni_dkg_id(i)), pub_coeffs);
    }
    assert!(store
        .transcript_data(ni_dkg_id(ThresholdSigDataStoreImpl::CAPACITY_PER_TAG + 1))
        .is_none());
}

fn should_not_purge_all_transcripts_of_certain_threshold_if_capacity_exceeded(
    single_transcript_threshold: NiDkgTag,
    other_transcripts_threshold: NiDkgTag,
) {
    let mut store = ThresholdSigDataStoreImpl::new();
    let pub_coeffs = public_coeffs();

    store.insert_transcript_data(
        ni_dkg_id_with_tag(single_transcript_threshold, 1),
        pub_coeffs.clone(),
        BTreeMap::new(),
    );
    for i in 0..ThresholdSigDataStoreImpl::CAPACITY_PER_TAG + 1 {
        store.insert_transcript_data(
            ni_dkg_id_with_tag(other_transcripts_threshold, i),
            pub_coeffs.clone(),
            BTreeMap::new(),
        );
    }

    assert_eq!(
        store.store.len(),
        ThresholdSigDataStoreImpl::CAPACITY_PER_TAG + 1
    );
    assert_eq!(
        store.store.len(),
        store.low_threshold_dkg_id_insertion_order.len()
            + store.high_threshold_dkg_id_insertion_order.len(),
    );

    // verify there is at least one high threshold transcript and at least one low threshold transcript
    let mut found_single_threshold = false;
    let mut found_other_threshold = false;
    for (ni_dkg_id, _value) in store.store.iter() {
        if ni_dkg_id.dkg_tag == single_transcript_threshold {
            found_single_threshold = true;
        } else if ni_dkg_id.dkg_tag == other_transcripts_threshold {
            found_other_threshold = true;
        }
        if found_single_threshold && found_other_threshold {
            break;
        }
    }
    assert!(found_other_threshold);
    assert!(found_single_threshold);
}

#[test]
fn should_not_purge_only_low_threshold_transcript_if_capacity_exceeded() {
    should_not_purge_all_transcripts_of_certain_threshold_if_capacity_exceeded(
        NiDkgTag::LowThreshold,
        NiDkgTag::HighThreshold,
    );
}

#[test]
fn should_not_purge_only_high_threshold_transcript_if_capacity_exceeded() {
    should_not_purge_all_transcripts_of_certain_threshold_if_capacity_exceeded(
        NiDkgTag::HighThreshold,
        NiDkgTag::LowThreshold,
    );
}

#[test]
fn should_purge_data_on_inserting_pubkeys_if_capacity_exceeded() {
    let mut store = ThresholdSigDataStoreImpl::new();
    let csp_pubkey = csp_public_key();
    let node_id = node_test_id(NODE_1);

    for i in 1..=ThresholdSigDataStoreImpl::CAPACITY_PER_TAG + 1 {
        store.insert_individual_public_key(ni_dkg_id(i), node_id, csp_pubkey);
    }

    assert_eq!(
        store.store.len(),
        ThresholdSigDataStoreImpl::CAPACITY_PER_TAG
    );
    for i in 2..=ThresholdSigDataStoreImpl::CAPACITY_PER_TAG + 1 {
        assert_eq!(
            store.individual_public_key(ni_dkg_id(i), node_id),
            Some(&csp_pubkey)
        );
    }
    assert_eq!(store.individual_public_key(ni_dkg_id(1), node_id), None);
}

#[test]
fn should_purge_data_in_insertion_order_on_inserting_pubkeys_if_max_size_exceeded() {
    let mut store = ThresholdSigDataStoreImpl::new();
    let csp_pubkey = csp_public_key();
    let node_id = node_test_id(NODE_1);

    for i in (1..=ThresholdSigDataStoreImpl::CAPACITY_PER_TAG + 1).rev() {
        store.insert_individual_public_key(ni_dkg_id(i), node_id, csp_pubkey);
    }

    assert_eq!(
        store.store.len(),
        ThresholdSigDataStoreImpl::CAPACITY_PER_TAG
    );
    for i in 1..=ThresholdSigDataStoreImpl::CAPACITY_PER_TAG {
        assert_eq!(
            store.individual_public_key(ni_dkg_id(i), node_id),
            Some(&csp_pubkey)
        );
    }
    assert_eq!(
        store.individual_public_key(
            ni_dkg_id(ThresholdSigDataStoreImpl::CAPACITY_PER_TAG + 1),
            node_id
        ),
        None
    );
}

#[test]
fn should_store_up_to_capacity_per_tag_for_both_tags() {
    let mut store = ThresholdSigDataStoreImpl::new();
    let pub_coeffs = public_coeffs();

    for i in 0..ThresholdSigDataStoreImpl::CAPACITY_PER_TAG {
        store.insert_transcript_data(
            ni_dkg_id_with_tag(NiDkgTag::LowThreshold, i),
            pub_coeffs.clone(),
            BTreeMap::new(),
        );
        store.insert_transcript_data(
            ni_dkg_id_with_tag(NiDkgTag::HighThreshold, i),
            pub_coeffs.clone(),
            BTreeMap::new(),
        );
    }

    // Verify we have exactly the max capacity stored
    assert_eq!(
        store.store.len(),
        ThresholdSigDataStoreImpl::CAPACITY_PER_TAG * 2
    );
    assert_eq!(
        store.store.len(),
        store.low_threshold_dkg_id_insertion_order.len()
            + store.high_threshold_dkg_id_insertion_order.len(),
    );

    // Insert one more transcript per tag
    store.insert_transcript_data(
        ni_dkg_id_with_tag(
            NiDkgTag::LowThreshold,
            ThresholdSigDataStoreImpl::CAPACITY_PER_TAG,
        ),
        pub_coeffs.clone(),
        BTreeMap::new(),
    );
    store.insert_transcript_data(
        ni_dkg_id_with_tag(
            NiDkgTag::HighThreshold,
            ThresholdSigDataStoreImpl::CAPACITY_PER_TAG,
        ),
        pub_coeffs.clone(),
        BTreeMap::new(),
    );

    // Verify that we still have exactly the max capacity stored (since one of each tag was purged)
    assert_eq!(
        store.store.len(),
        ThresholdSigDataStoreImpl::CAPACITY_PER_TAG * 2
    );
    assert_eq!(
        store.store.len(),
        store.low_threshold_dkg_id_insertion_order.len()
            + store.high_threshold_dkg_id_insertion_order.len(),
    );
}

fn indices_with(mappings: Vec<(NodeId, NodeIndex)>) -> BTreeMap<NodeId, NodeIndex> {
    let mut indices = BTreeMap::new();
    for (node_id, index) in mappings {
        indices.insert(node_id, index);
    }
    indices
}

fn csp_public_key() -> CspThresholdSigPublicKey {
    CspThresholdSigPublicKey::ThresBls12_381(PublicKeyBytes([42; PublicKeyBytes::SIZE]))
}

fn other_csp_public_key() -> CspThresholdSigPublicKey {
    CspThresholdSigPublicKey::ThresBls12_381(PublicKeyBytes([43; PublicKeyBytes::SIZE]))
}

fn public_coeffs() -> CspPublicCoefficients {
    public_coeffs_1()
}

fn public_coeffs_1() -> CspPublicCoefficients {
    CspPublicCoefficients::Bls12_381(PublicCoefficientsBytes {
        coefficients: vec![PublicKeyBytes([1; PublicKeyBytes::SIZE])],
    })
}

fn public_coeffs_2() -> CspPublicCoefficients {
    CspPublicCoefficients::Bls12_381(PublicCoefficientsBytes {
        coefficients: vec![PublicKeyBytes([2; PublicKeyBytes::SIZE])],
    })
}

fn pub_coeffs_from_store(
    store: &ThresholdSigDataStoreImpl,
    dkg_id: NiDkgId,
) -> CspPublicCoefficients {
    store
        .transcript_data(dkg_id)
        .expect("Expecting transcript data to be present for dkg id")
        .public_coefficients()
        .clone()
}

fn ni_dkg_id(i: usize) -> NiDkgId {
    NiDkgId {
        start_block_height: Height::new(i as u64),
        dealer_subnet: SUBNET_1,
        dkg_tag: NiDkgTag::HighThreshold,
        target_subnet: NI_DKG_ID_1.target_subnet,
    }
}

fn ni_dkg_id_with_tag(ni_dkg_tag: NiDkgTag, height: usize) -> NiDkgId {
    NiDkgId {
        dkg_tag: ni_dkg_tag,
        ..ni_dkg_id(height)
    }
}
