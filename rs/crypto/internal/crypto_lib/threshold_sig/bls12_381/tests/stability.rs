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
    let sha256_cbor = hex::encode(Sha256::hash(&cbor));
    assert_eq!(sha256_cbor, expected_sha256);
    //println!("perl -pi -e s/{}/{}/g tests/stability.rs", expected_sha256, sha256_cbor);
}

#[test]
fn test_generating_fs_key_pair_is_stable() {
    let seed = Seed::from_bytes(b"ic-crypto-kgen-seed");
    let key_and_pop = create_forward_secure_key_pair(seed, b"ic-crypto-kgen-assoc-data");

    assert_sha256_cbor_is(
        &key_and_pop.pop,
        "6f05e05b030242083119968af870548287330c5033aab104c4806ac4044fd6d6",
    );
    assert_sha256_cbor_is(
        &key_and_pop.public_key,
        "ab72b5e55db7957f5f2c3d8091dd17553cadc673eebbb44198abfad795ff4af0",
    );
    assert_sha256_cbor_is(
        &key_and_pop.secret_key,
        "12c08d082d9e59db9ce46c39210046e77aae4c69f0ea0b46464ebc5db762af9b",
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
        "7e8e048bd7e903c271a66903223d80fe5c5c8e6c8876c5b1bc8abab373a893c5",
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
        "06783b96a9f5a04666762ac5d487491265d67e43ff1ad1d5b56d17d1379fecfe",
        "d5dc62607df766f41e65ba56baca52c0d73d16c6588c8731bd44e1b5c1578938",
        "8da68bebb1cd78f41090159d4bc6fd0be059bf2705b682e9c19f9b1f6e8efcac",
        "5fa524219379c790734115d42a4075faf29893e2d94f4de184bb2745f8a7e925",
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
        "4acbfe16fdfdb85ff0ea6868a9342b1bf4e9b0f211c36a7e2629c75b797f17ae",
    );

    let expected_threshold_key_hashes = [
        "c4b8e342aa39298e2334b45f166436ff4449a40d07df21185246b3bc3a22020f",
        "52ab8e1cc956a8340d37868cc5215bdad22c7a0d0844d01da1491f8aa6c624e5",
        "055324cbf3447071f139433f0c02cd8f27fbec19d9ba3cb9adeefd49f371b42a",
        "69affb46550951145cbd37b654c3ab74c6b4faa1d0dd35e9d6afd1d98e0ad02c",
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
        "cd96d170a464fc81d778966b432ae7176483aa7100d2d05347371fbfc846156f",
        "c5462ec22068bab3874e17f74f519bbf3723b210c7dd46c749b08dc766386caf",
        "4d60725ce5e9a4c973a47e2c7d7e2a5d69eccd236d4b9b65a7417f117ff81212",
        "bb0ed35288e29203b8f5b9b2f0857be304eb34ecfa9f715530f268fc9a2869f5",
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
        "be0280d6ca6148b82c6a9d802baf8a6e9ea4719648d90b73780c41cd950f71fa",
    );

    let expected_threshold_key_hashes = [
        "f547614d6f8a641d60d1b05604f5a3bd1ed72f4efedd3cb868b5aa5178212635",
        "c500c383f6aeaa279ee199ae054e1aa40aa3066b3982ca6b0b18194f73feb3be",
        "4d20146d965b47387e56682d2475c9713727bad7b198ef7861267937ab3997ca",
        "c85d81742072f2126094192374256c5c23d1e2c58208000bdb89816554dfd2c0",
    ];

    for receiver in 0..nodes {
        let sk = trusted_secret_key_into_miracl(receiver_sk.get(&receiver).unwrap());

        let key = compute_threshold_signing_key(&transcript, receiver, &sk, epoch)
            .expect("Unable to compute threshold key");

        assert_sha256_cbor_is(&key, expected_threshold_key_hashes[receiver as usize]);
    }
}
