#![allow(clippy::unwrap_used)]

use super::*;
use crate::sign::threshold_sig::tests::NI_DKG_ID;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::PublicCoefficientsBytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::CspThresholdSigPublicKey;
use ic_test_utilities::types::ids::{node_test_id, SUBNET_1};
use ic_types::Height;

const NODE_1: u64 = 1;
const NODE_2: u64 = 2;
const NODE_1_INDEX: NodeIndex = 1;
const NODE_2_INDEX: NodeIndex = 2;
const I_DKG_1: IDkgId = IDkgId {
    instance_id: Height::new(1),
    subnet_id: SUBNET_1,
};
const I_DKG_2: IDkgId = IDkgId {
    instance_id: Height::new(2),
    subnet_id: SUBNET_1,
};

#[test]
fn should_contain_transcript_data_after_insertion_with_idkg_id() {
    should_contain_transcript_data_after_insertion_with_dkg_id(DkgId::IDkgId(I_DKG_1));
}

#[test]
fn should_contain_transcript_data_after_insertion_with_nidkg_id() {
    should_contain_transcript_data_after_insertion_with_dkg_id(DkgId::NiDkgId(NI_DKG_ID));
}

fn should_contain_transcript_data_after_insertion_with_dkg_id(dkg_id: DkgId) {
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

    assert!(store.transcript_data(DkgId::IDkgId(I_DKG_1)).is_none());
}

#[test]
fn should_contain_individual_public_keys_after_insertion_with_idkg_id() {
    should_contain_individual_public_keys_after_insertion_with_dkg_id(DkgId::IDkgId(I_DKG_1));
}

#[test]
fn should_contain_individual_public_keys_after_insertion_with_nidkg_id() {
    should_contain_individual_public_keys_after_insertion_with_dkg_id(DkgId::NiDkgId(NI_DKG_ID));
}

fn should_contain_individual_public_keys_after_insertion_with_dkg_id(dkg_id: DkgId) {
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

    assert_ne!(I_DKG_1, I_DKG_2);
    store.insert_individual_public_key(DkgId::IDkgId(I_DKG_1), node_test_id(NODE_1), csp_pubkey_1);
    store.insert_individual_public_key(DkgId::IDkgId(I_DKG_1), node_test_id(NODE_2), csp_pubkey_2);
    store.insert_individual_public_key(DkgId::IDkgId(I_DKG_2), node_test_id(NODE_1), csp_pubkey_2);

    assert_eq!(
        store.individual_public_key(DkgId::IDkgId(I_DKG_1), node_test_id(NODE_1)),
        Some(&csp_pubkey_1)
    );
    assert_eq!(
        store.individual_public_key(DkgId::IDkgId(I_DKG_1), node_test_id(NODE_2)),
        Some(&csp_pubkey_2)
    );
    assert_eq!(
        store.individual_public_key(DkgId::IDkgId(I_DKG_2), node_test_id(NODE_1)),
        Some(&csp_pubkey_2)
    );
}

#[test]
fn should_not_contain_nonexistent_individual_public_key() {
    let store = ThresholdSigDataStoreImpl::new();

    assert_eq!(
        store.individual_public_key(DkgId::IDkgId(I_DKG_1), node_test_id(NODE_1)),
        None
    );
}

#[test]
fn should_overwrite_existing_public_coefficients() {
    let mut store = ThresholdSigDataStoreImpl::new();
    let (public_coeffs_1, public_coeffs_2) = (public_coeffs_1(), public_coeffs_2());
    assert_ne!(public_coeffs_1, public_coeffs_2);

    store.insert_transcript_data(DkgId::IDkgId(I_DKG_1), public_coeffs_1, BTreeMap::new());
    store.insert_transcript_data(
        DkgId::IDkgId(I_DKG_1),
        public_coeffs_2.clone(),
        BTreeMap::new(),
    );

    let transcript_data = store.transcript_data(DkgId::IDkgId(I_DKG_1)).unwrap();
    assert_eq!(transcript_data.public_coefficients(), &public_coeffs_2);
}

#[test]
fn should_overwrite_existing_indices() {
    let mut store = ThresholdSigDataStoreImpl::new();
    let indices_1 = indices_with(vec![(node_test_id(NODE_1), NODE_1_INDEX)]);
    let indices_2 = indices_with(vec![(node_test_id(NODE_2), NODE_2_INDEX)]);
    let public_coeffs = public_coeffs();

    store.insert_transcript_data(DkgId::IDkgId(I_DKG_1), public_coeffs.clone(), indices_1);
    store.insert_transcript_data(DkgId::IDkgId(I_DKG_1), public_coeffs, indices_2);

    let transcript_data = store.transcript_data(DkgId::IDkgId(I_DKG_1)).unwrap();
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

    store.insert_individual_public_key(DkgId::IDkgId(I_DKG_1), node_test_id(NODE_1), csp_pubkey_1);
    store.insert_individual_public_key(DkgId::IDkgId(I_DKG_1), node_test_id(NODE_1), csp_pubkey_2);

    assert_eq!(
        store.individual_public_key(DkgId::IDkgId(I_DKG_1), node_test_id(NODE_1)),
        Some(&csp_pubkey_2)
    );
}

#[test]
fn should_have_capacity_9() {
    assert_eq!(ThresholdSigDataStoreImpl::CAPACITY, 9)
}

#[test]
fn should_not_purge_data_on_inserting_coeffs_and_indices_if_capacity_not_exceeded() {
    let mut store = ThresholdSigDataStoreImpl::new();

    for i in 1..=ThresholdSigDataStoreImpl::CAPACITY {
        store.insert_transcript_data(dkg_id(i), public_coeffs(), BTreeMap::new());
    }

    assert_eq!(store.store.len(), ThresholdSigDataStoreImpl::CAPACITY);
}

#[test]
fn should_not_purge_data_on_inserting_pubkeys_if_capacity_not_exceeded() {
    let mut store = ThresholdSigDataStoreImpl::new();

    for i in 1..=ThresholdSigDataStoreImpl::CAPACITY {
        store.insert_individual_public_key(dkg_id(i), node_test_id(NODE_1), csp_public_key());
    }

    assert_eq!(store.store.len(), ThresholdSigDataStoreImpl::CAPACITY);
}

#[test]
fn should_purge_data_on_inserting_coeffs_and_indices_if_capacity_exceeded() {
    let mut store = ThresholdSigDataStoreImpl::new();
    let pub_coeffs = public_coeffs();

    for i in 1..=ThresholdSigDataStoreImpl::CAPACITY + 1 {
        store.insert_transcript_data(dkg_id(i), pub_coeffs.clone(), BTreeMap::new());
    }

    assert_eq!(store.store.len(), ThresholdSigDataStoreImpl::CAPACITY);
    assert!(store.transcript_data(dkg_id(1)).is_none());
    for i in 2..=ThresholdSigDataStoreImpl::CAPACITY + 1 {
        assert_eq!(pub_coeffs_from_store(&store, dkg_id(i)), pub_coeffs);
    }
}

#[test]
fn should_purge_data_in_insertion_order_on_inserting_coeffs_and_indices_if_capacity_exceeded() {
    let mut store = ThresholdSigDataStoreImpl::new();
    let pub_coeffs = public_coeffs();

    for i in (1..=ThresholdSigDataStoreImpl::CAPACITY + 1).rev() {
        store.insert_transcript_data(dkg_id(i), pub_coeffs.clone(), BTreeMap::new());
    }

    assert_eq!(store.store.len(), ThresholdSigDataStoreImpl::CAPACITY);
    for i in 1..=ThresholdSigDataStoreImpl::CAPACITY {
        assert_eq!(pub_coeffs_from_store(&store, dkg_id(i)), pub_coeffs);
    }
    assert!(store
        .transcript_data(dkg_id(ThresholdSigDataStoreImpl::CAPACITY + 1))
        .is_none());
}

#[test]
fn should_purge_data_on_inserting_pubkeys_if_capacity_exceeded() {
    let mut store = ThresholdSigDataStoreImpl::new();
    let csp_pubkey = csp_public_key();
    let node_id = node_test_id(NODE_1);

    for i in 1..=ThresholdSigDataStoreImpl::CAPACITY + 1 {
        store.insert_individual_public_key(dkg_id(i), node_id, csp_pubkey);
    }

    assert_eq!(store.store.len(), ThresholdSigDataStoreImpl::CAPACITY);
    for i in 2..=ThresholdSigDataStoreImpl::CAPACITY + 1 {
        assert_eq!(
            store.individual_public_key(dkg_id(i), node_id),
            Some(&csp_pubkey)
        );
    }
    assert_eq!(store.individual_public_key(dkg_id(1), node_id), None);
}

#[test]
fn should_purge_data_in_insertion_order_on_inserting_pubkeys_if_max_size_exceeded() {
    let mut store = ThresholdSigDataStoreImpl::new();
    let csp_pubkey = csp_public_key();
    let node_id = node_test_id(NODE_1);

    for i in (1..=ThresholdSigDataStoreImpl::CAPACITY + 1).rev() {
        store.insert_individual_public_key(dkg_id(i), node_id, csp_pubkey);
    }

    assert_eq!(store.store.len(), ThresholdSigDataStoreImpl::CAPACITY);
    for i in 1..=ThresholdSigDataStoreImpl::CAPACITY {
        assert_eq!(
            store.individual_public_key(dkg_id(i), node_id),
            Some(&csp_pubkey)
        );
    }
    assert_eq!(
        store.individual_public_key(dkg_id(ThresholdSigDataStoreImpl::CAPACITY + 1), node_id),
        None
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
    dkg_id: DkgId,
) -> CspPublicCoefficients {
    store
        .transcript_data(dkg_id)
        .expect("Expecting transcript data to be present for dkg id")
        .public_coefficients()
        .clone()
}

fn dkg_id(i: usize) -> DkgId {
    DkgId::IDkgId(IDkgId {
        instance_id: Height::new(i as u64),
        subnet_id: SUBNET_1,
    })
}
