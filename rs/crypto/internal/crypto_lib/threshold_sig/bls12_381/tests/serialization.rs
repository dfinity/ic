use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg::{
    Epoch,
    forward_secure::{PublicKeyWithPop, SecretKey},
};
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::groth20_bls12_381::{
    types::FsEncryptionSecretKey, *,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::{
    Dealing, FsEncryptionPop, FsEncryptionPublicKey,
};
use ic_types::NumberOfNodes;
use std::collections::BTreeMap;

#[test]
fn test_can_parse_deserialized_pk_and_pop() {
    let pk = serde_cbor::from_slice::<FsEncryptionPublicKey>(
        &hex::decode(include_bytes!("data/nidkg_pk.hex")).unwrap(),
    )
    .unwrap();

    let pop = serde_cbor::from_slice::<FsEncryptionPop>(
        &hex::decode(include_bytes!("data/nidkg_pop.hex")).unwrap(),
    )
    .unwrap();

    let pk = PublicKeyWithPop::deserialize(&pk, &pop).expect("Unable to decode PK/PoP");

    assert!(pk.verify(b"ic-crypto-kgen-assoc-data"));
}

#[test]
fn test_can_parse_deserialized_sk() {
    let sk = serde_cbor::from_slice::<FsEncryptionSecretKey>(
        &hex::decode(include_bytes!("data/nidkg_sk.hex")).unwrap(),
    )
    .unwrap();

    let _sk = SecretKey::deserialize(&sk);
}

#[test]
fn test_can_parse_deserialized_dealing() {
    let dealer_index = 0;
    let epoch = Epoch::from(5);
    let threshold = NumberOfNodes::from(2);

    let receiver_key0 = serde_cbor::from_slice::<FsEncryptionPublicKey>(
        &hex::decode(include_bytes!("data/nidkg_dealing_pk0.hex")).unwrap(),
    )
    .unwrap();
    let receiver_key1 = serde_cbor::from_slice::<FsEncryptionPublicKey>(
        &hex::decode(include_bytes!("data/nidkg_dealing_pk1.hex")).unwrap(),
    )
    .unwrap();
    let receiver_key2 = serde_cbor::from_slice::<FsEncryptionPublicKey>(
        &hex::decode(include_bytes!("data/nidkg_dealing_pk2.hex")).unwrap(),
    )
    .unwrap();
    let receiver_key3 = serde_cbor::from_slice::<FsEncryptionPublicKey>(
        &hex::decode(include_bytes!("data/nidkg_dealing_pk3.hex")).unwrap(),
    )
    .unwrap();

    let mut receiver_keys = BTreeMap::new();

    receiver_keys.insert(0, receiver_key0);
    receiver_keys.insert(1, receiver_key1);
    receiver_keys.insert(2, receiver_key2);
    receiver_keys.insert(3, receiver_key3);

    let dealing = serde_cbor::from_slice::<Dealing>(
        &hex::decode(include_bytes!("data/nidkg_dealing.hex")).unwrap(),
    )
    .unwrap();

    assert!(verify_dealing(dealer_index, threshold, epoch, &receiver_keys, &dealing).is_ok());
}
