use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg::Epoch;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::groth20_bls12_381::{
    types::FsEncryptionSecretKey, *,
};
use ic_crypto_internal_threshold_sig_bls12381::types::SecretKeyBytes;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::{
    Dealing, FsEncryptionPublicKey,
};
use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::bls12_381::PublicCoefficientsBytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_crypto_sha::Sha256;
use ic_types::{NodeIndex, NumberOfNodes};
use rand::RngCore;
use serde::Serialize;
use std::collections::BTreeMap;
use std::convert::TryInto;

/*
These tests generate artifacts using fixed input seeds and check that hashing
the serialization of the results does not change. These tests are sensitive to
any change in the output, even those which are not "important" (for instance,
variations in the CBOR encoding), but are also effective at noticing any
unintended modification.
*/

fn assert_sha256_cbor_is<T: Serialize>(val: &T, expected_sha256: &str) {
    let cbor = serde_cbor::to_vec(val).expect("Encoding to CBOR failed");
    let sha256_cbor = Sha256::hash(&cbor);
    assert_eq!(hex::encode(sha256_cbor), expected_sha256);
}

#[test]
fn test_generating_fs_key_pair_is_stable() {
    let seed = Seed::from_bytes(b"ic-crypto-kgen-seed");
    let key_and_pop = create_forward_secure_key_pair(seed, b"ic-crypto-kgen-assoc-data");

    assert_sha256_cbor_is(
        &key_and_pop.pop,
        "4eb54511de50d2c62ff86128c29d40530da7d3f20ffb843110effb0a0cf699f7",
    );
    assert_sha256_cbor_is(
        &key_and_pop.public_key,
        "34c78d27d4a7e20218b72d16d88e12973794d43f3f18c15dd80d73b3718eb67f",
    );
    assert_sha256_cbor_is(
        &key_and_pop.secret_key,
        "c635fc5a84d4934ff56662ddaf286d84550a3df31754085579ea0a5c2a9262a9",
    );
}

#[test]
fn test_updating_fs_secret_key_is_stable() {
    let seed = Seed::from_bytes(b"ic-crypto-kgen-seed");
    let key_and_pop = create_forward_secure_key_pair(seed, b"ic-crypto-kgen-assoc-data");

    let mut sk = trusted_secret_key_into_miracl(&key_and_pop.secret_key);

    let seed = Seed::from_bytes(b"ic-crypto-update-key-seed");
    update_key_inplace_to_epoch(&mut sk, Epoch::from(2), seed);

    assert_sha256_cbor_is(
        &secret_key_from_miracl(&sk),
        "bbecdf1c4e6999f3f1575ff5c3c80d0a7bef6790d140d0340ccedceec5c5c315",
    );
}

fn create_receiver_keys(
    count: usize,
) -> (
    BTreeMap<NodeIndex, FsEncryptionPublicKey>,
    BTreeMap<NodeIndex, FsEncryptionSecretKey>,
) {
    let mut pk = BTreeMap::new();
    let mut sk = BTreeMap::new();

    for node_index in 0..count {
        let node_key_seed =
            Seed::from_bytes(format!("ic-crypto-kgen-seed-node-{}", node_index).as_bytes());
        let key_and_pop =
            create_forward_secure_key_pair(node_key_seed, b"ic-crypto-kgen-assoc-data");
        pk.insert(node_index as u32, key_and_pop.public_key);
        sk.insert(node_index as u32, key_and_pop.secret_key);
    }

    (pk, sk)
}

fn create_and_verify_dealing(
    dealer_index: NodeIndex,
    receiver_keys: &BTreeMap<NodeIndex, FsEncryptionPublicKey>,
    threshold: NumberOfNodes,
    epoch: Epoch,
    resharing_secret: Option<SecretKeyBytes>,
) -> Dealing {
    let keygen_seed = Seed::from_bytes(
        format!("ic-crypto-create-dealing-keygen-seed-{}", dealer_index).as_bytes(),
    );
    let encryption_seed = Seed::from_bytes(
        format!("ic-crypto-create-dealing-encryption-seed-{}", dealer_index).as_bytes(),
    );

    let dealing = create_dealing(
        keygen_seed,
        encryption_seed,
        threshold,
        receiver_keys,
        epoch,
        dealer_index,
        resharing_secret,
    )
    .expect("Unable to create dealing");

    assert!(verify_dealing(dealer_index, threshold, epoch, receiver_keys, &dealing).is_ok());

    dealing
}

#[test]
fn test_create_dealings_and_transcript_without_resharing_secret_is_stable() {
    let nodes = 4u32;
    let threshold = NumberOfNodes::from(2);

    let (receiver_pk, receiver_sk) = create_receiver_keys(4);
    let epoch = Epoch::from(2);

    let expected_dealing_hashes = [
        "73bb46fb7a62cec33de090696b024d505ada195449732105f61bff2c46aef622",
        "0f2442116e08aacd5ce0066d0b4b23af6827e4b425ca1c7518cee8ee7342716e",
        "76f5048fad7d2ac737472ead8929c83129e129f60c7bfa020cc87fb4e7e81372",
        "d7f5da17a4612f23931d1dc536cb589e601ebf855edcd69b0d31036308732d1c",
    ];

    let mut dealings = BTreeMap::new();
    for dealer in 0..nodes {
        let dealing = create_and_verify_dealing(dealer, &receiver_pk, threshold, epoch, None);
        assert_sha256_cbor_is(&dealing, expected_dealing_hashes[dealer as usize]);
        dealings.insert(dealer as NodeIndex, dealing);
    }

    let transcript = create_transcript(
        threshold,
        NumberOfNodes::from(nodes),
        &dealings,
        NumberOfNodes::from(nodes),
    )
    .unwrap();

    assert_sha256_cbor_is(
        &transcript,
        "6decf1f731df063c425a3e764f82f22a6914ca8f464c47f7865f131f3faff79b",
    );

    let expected_threshold_key_hashes = [
        "2a0956d761e515e8f9987548d2edc30c21fbd130ce2989c45b2e78ead3cf3ed2",
        "389c61c89cc226833bdf261740ef802dded6f2eb5cf43ee1205f872959faba92",
        "56e03f7c276a9543217eaf4ac799b53753fc59dc6cafb16b377ba0808ff4a1e6",
        "192782c176a55d0ec5cfd437ea674a4b20900db7ee2ae6bd78955556be62668c",
    ];

    for receiver in 0..nodes {
        let sk = trusted_secret_key_into_miracl(receiver_sk.get(&receiver).unwrap());

        let key = compute_threshold_signing_key(&transcript, receiver, &sk, epoch)
            .expect("Unable to compute threshold key");

        assert_sha256_cbor_is(&key, expected_threshold_key_hashes[receiver as usize]);
    }
}

#[test]
fn test_create_dealings_and_transcript_with_resharing_secret_is_stable() {
    let nodes = 4u32;
    let threshold = NumberOfNodes::from(2);
    let (receiver_pk, receiver_sk) = create_receiver_keys(nodes as usize);
    let epoch = Epoch::from(2);

    let resharing_secret = SecretKeyBytes([42; SecretKeyBytes::SIZE]);

    let expected_dealing_hashes = [
        "2dbada74ed33f06040ecae2904da9a58d062d567da507371cc1556958f5e65f4",
        "6cec982367bdf5c4a06adb8a1948b92a77d0d54172f808554a9dffc4acdc3ca3",
        "840c4ffaabc1bd405ef76c988e27fc596a78726ab1bf9dd6d797e40c017ba713",
        "c62e9733883fa4180c4288fc292b31c72ba0c94ed4722b68cee38af5b377b177",
    ];

    let mut dealings = BTreeMap::new();
    for dealer in 0..nodes {
        let dealing = create_and_verify_dealing(
            dealer,
            &receiver_pk,
            threshold,
            epoch,
            Some(resharing_secret),
        );

        assert_sha256_cbor_is(&dealing, expected_dealing_hashes[dealer as usize]);
        dealings.insert(dealer as NodeIndex, dealing);
    }

    let mut coefficients = vec![];

    let mut rng = Seed::from_bytes(b"ic-crypto-generate-random-bls-coefficients").into_rng();

    let fixed0 = hex::decode("9772c16106e9c70b2073dfe17989225dd10f3adb675365fc6d833587ad4cbd3ae692ad1e20679003f676b0b089e83feb058b3e8b9fc9552e30787cb4a541a1c3bf67a02e91fc648b2c19f4bb333e14c5c73b9bfbc5ec56dadabb07ff15d45124").unwrap();
    coefficients.push(PublicKeyBytes(fixed0.try_into().expect("Size checked")));
    for _ in 1..nodes {
        let mut coefficient = [0u8; 96];
        rng.fill_bytes(&mut coefficient);
        coefficients.push(PublicKeyBytes(coefficient));
    }

    let public_coefficients = PublicCoefficientsBytes { coefficients };

    let transcript = create_resharing_transcript(
        threshold,
        NumberOfNodes::from(nodes),
        &dealings,
        &public_coefficients,
    )
    .unwrap();

    assert_sha256_cbor_is(
        &transcript,
        "c01bf050dd815ec6596f466b3874bef5e74f0f2591f5f7a26209317550d1b31f",
    );

    let expected_threshold_key_hashes = [
        "f5baeb5a2e9c0609cfa64d67872958588e5fac84a1f3480c94c0c4f316e684fc",
        "0bda41bd3f867951912680628fa41a78fd6a8b1474e51be7f02a91c83bb063f0",
        "54ddf1f715771d39f02250a6451d8d3e8f6d7a3f50ed67464ed0bd80204377fe",
        "66bb14d0789f5b9b1bbf8d08a067ad2b13a4e83a79aad6423e2afa2958a1cb2d",
    ];

    for receiver in 0..nodes {
        let sk = trusted_secret_key_into_miracl(receiver_sk.get(&receiver).unwrap());

        let key = compute_threshold_signing_key(&transcript, receiver, &sk, epoch)
            .expect("Unable to compute threshold key");

        assert_sha256_cbor_is(&key, expected_threshold_key_hashes[receiver as usize]);
    }
}
