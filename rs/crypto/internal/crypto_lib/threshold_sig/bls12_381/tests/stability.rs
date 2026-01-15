use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg::Epoch;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg::forward_secure::SecretKey;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::groth20_bls12_381::{
    types::FsEncryptionSecretKey, *,
};
use ic_crypto_internal_threshold_sig_bls12381::types::SecretKeyBytes;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::{
    Dealing, FsEncryptionPublicKey,
};
use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::bls12_381::PublicCoefficientsBytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_crypto_secrets_containers::SecretArray;
use ic_crypto_sha2::Sha256;
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
        "4d606b3e6a3b790c0e4b1fc4687fb3892fc5e8c4377684a25a7183f0c2a74d91",
    );
    assert_sha256_cbor_is(
        &key_and_pop.public_key,
        "707ca0f3e366812cb3f8efc734a9eff1e7aff21427082467d034f54d525327d2",
    );
    assert_sha256_cbor_is(
        &key_and_pop.secret_key,
        "25cfe9b7b5c95d6d8cab1f8f5b205470909ce1dc27612b17e987e57ea0443864",
    );
}

#[test]
fn test_updating_fs_secret_key_is_stable() {
    let seed = Seed::from_bytes(b"ic-crypto-kgen-seed");
    let key_and_pop = create_forward_secure_key_pair(seed, b"ic-crypto-kgen-assoc-data");

    let mut sk = SecretKey::deserialize(&key_and_pop.secret_key);

    let seed = Seed::from_bytes(b"ic-crypto-update-key-seed");
    update_key_inplace_to_epoch(&mut sk, Epoch::from(2), seed);

    assert_sha256_cbor_is(
        &sk.serialize(),
        "f70143bdd1fad70ac7d24cda1f5141b6e730841361fc4c8e5059ddc0a1514e15",
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
            Seed::from_bytes(format!("ic-crypto-kgen-seed-node-{node_index}").as_bytes());
        let key_and_pop =
            create_forward_secure_key_pair(node_key_seed, b"ic-crypto-kgen-assoc-data");
        pk.insert(node_index as u32, key_and_pop.public_key);
        sk.insert(node_index as u32, key_and_pop.secret_key.clone());
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
    let keygen_seed =
        Seed::from_bytes(format!("ic-crypto-create-dealing-keygen-seed-{dealer_index}").as_bytes());
    let encryption_seed = Seed::from_bytes(
        format!("ic-crypto-create-dealing-encryption-seed-{dealer_index}").as_bytes(),
    );

    let dealing = match resharing_secret {
        Some(secret) => create_resharing_dealing(
            keygen_seed,
            encryption_seed,
            threshold,
            receiver_keys,
            epoch,
            dealer_index,
            secret,
        )
        .expect("Unable to create resharing dealing"),
        None => create_dealing(
            keygen_seed,
            encryption_seed,
            threshold,
            receiver_keys,
            epoch,
            dealer_index,
        )
        .expect("Unable to create dealing"),
    };

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
        "800d77d0b316a24c89f874813a104071a9a5e2f462df1b7615cb5697d0410424",
        "c31e537350f2faf43b3d684dee343a16077fd317f7bf9046f036c26b796d9329",
        "8e7dba35d9e74c595135bee8cd842b407b18ff80d5e725da750cef3b960efba1",
        "e37e1de43df69200e6959f44564023b32593213ffa7854ffcf71a70229926ba2",
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
        "fa6e9825d6e4bed18061832d4b302267d1827e86f885ce5f0be2ff6137f076af",
    );

    let expected_threshold_key_hashes = [
        "c4b8e342aa39298e2334b45f166436ff4449a40d07df21185246b3bc3a22020f",
        "52ab8e1cc956a8340d37868cc5215bdad22c7a0d0844d01da1491f8aa6c624e5",
        "055324cbf3447071f139433f0c02cd8f27fbec19d9ba3cb9adeefd49f371b42a",
        "69affb46550951145cbd37b654c3ab74c6b4faa1d0dd35e9d6afd1d98e0ad02c",
    ];

    for receiver in 0..nodes {
        let sk = SecretKey::deserialize(receiver_sk.get(&receiver).unwrap());

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

    let resharing_secret = SecretKeyBytes::new(SecretArray::new_and_dont_zeroize_argument(
        &[42; SecretKeyBytes::SIZE],
    ));

    let expected_dealing_hashes = [
        "c20776601f7900367194bb8f37aa530fa9798a24aa4086804abfd9e65e1d45e2",
        "57ad68aba3ec1cb8d2522de43d0bbb3678e3d7426cece31c5f491aabe7cca944",
        "32c27739d296c456654f69eae77739217e1e965b39d969dd9e4c3150bef227e5",
        "901a893df6228332f08e25548729030b623ec03fc8f0b9f6627cdb45d31a607a",
    ];

    let mut dealings = BTreeMap::new();
    for dealer in 0..nodes {
        let dealing = create_and_verify_dealing(
            dealer,
            &receiver_pk,
            threshold,
            epoch,
            Some(resharing_secret.clone()),
        );

        assert_sha256_cbor_is(&dealing, expected_dealing_hashes[dealer as usize]);
        dealings.insert(dealer as NodeIndex, dealing);
    }

    let mut coefficients = vec![];

    let rng = &mut Seed::from_bytes(b"ic-crypto-generate-random-bls-coefficients").into_rng();

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
        "0443eec56f5993494689958102470bb72a8e3f0210f6318885237cc8dbacbf22",
    );

    let expected_threshold_key_hashes = [
        "f547614d6f8a641d60d1b05604f5a3bd1ed72f4efedd3cb868b5aa5178212635",
        "c500c383f6aeaa279ee199ae054e1aa40aa3066b3982ca6b0b18194f73feb3be",
        "4d20146d965b47387e56682d2475c9713727bad7b198ef7861267937ab3997ca",
        "c85d81742072f2126094192374256c5c23d1e2c58208000bdb89816554dfd2c0",
    ];

    for receiver in 0..nodes {
        let sk = SecretKey::deserialize(receiver_sk.get(&receiver).unwrap());

        let key = compute_threshold_signing_key(&transcript, receiver, &sk, epoch)
            .expect("Unable to compute threshold key");

        assert_sha256_cbor_is(&key, expected_threshold_key_hashes[receiver as usize]);
    }
}
