use assert_matches::assert_matches;
use ic_certification_test_utils::serialize_to_cbor;
use ic_crypto_internal_basic_sig_iccsa::types::*;
use ic_crypto_internal_basic_sig_iccsa::*;
use ic_crypto_internal_basic_sig_iccsa_test_utils::new_random_cert;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381;
use ic_crypto_test_utils::canister_signatures::canister_sig_pub_key_to_bytes;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use ic_types::crypto::{AlgorithmId, CryptoError};
use ic_types::messages::Blob;
use rand::{CryptoRng, Rng, RngCore};

#[test]
fn abc() {
    let canister_pk_bytes = PublicKeyBytes(hex::decode(
        "0a80000000001000050101c696ecfadbca862a8344a477c65fbc48af93091f72ee14ac10b72d17f62a128e",
    )
    .unwrap());
    let sig_bytes = SignatureBytes(hex::decode(
        "d9d9f7a26b63657274696669636174655901b1d9d9f7a2647472656583018301830182045820267d108b825149c889227f220ca201138ce621c31c7c3cf174117e7015110bb783024863616e69737465728301820458200dbfb8e99d2d846bfa0eadf3121273a0e37649e6067ddad6e542d6db16c3d6c6830182045820ab037ab997a41970ef58b7137353c190ea14e9dbb33a0c9abaa61f6d27a3e33583024a800000000010000301018301830183024e6365727469666965645f64617461820358208828baa2705be6be599f87847ca33bde4255baadd2d1ee61fb3acb483b3bceb882045820f0b1a53bf25b821852add1739bf64c8ac4f1ed5991602900f3b386aaa309e82882045820027c6d39dd379b697c9f17ae242f3f8bc40ea3ef61a1c2a722783b08ca00efb2820458201ea0bd7fc5b5c7356b6e4c97c0f19053e46b49c033a9c91c465d2b243e1cfcbb830182045820af8a3501882f87c92272d8b7528428819fb8947baa28bf12dd05e332f3c7277683024474696d65820349a880c4adf8caa28d18697369676e617475726558309708ab2f4f98d3a900e150a44875395901c7f94b9f11c0e9271bbab966d34dfcbb39a94b1c780048d400aaa261b71585647472656583018204582071c941c0c9b9e36d0979a8d0a09763f500f4535c929765c94e18f22ee0a6d748830243736967830258204afe0b94d4597bd4f6561d6c4e4fb0fd055a4e133e2bfcd366bb419b105823c7830258208a748712f3d0cdc2b7eeac7658d4c55c022dd9c97f8879b1ae039a7f45af1e01820340",
    ).unwrap());
    //     let canister_pk_bytes = PublicKeyBytes(hex::decode(
    //         "0a0000000000e08769010113dee6dfdf4338bfa7a6ad1346a7db177781c77d0cbb7fe7bd54c96dfcb83f61",
    //     )
    //     .unwrap());
    //     let sig_bytes = SignatureBytes(hex::decode(
    //     "d9d9f7a26b63657274696669636174655905c8d9d9f7a3647472656583018301830182045820a65afa38e224228863a89ebb73cfe55cf9c0b5e6c8f8756c3988cd7839765e8b83024863616e6973746572830182045820f10713ae473dcc0641f4087d02e43b4b11cd7c92c4732be1da413d34fde753e38301820458204f1b1ade2bf2df3b289b9dbcbd9744fb230187eec28bb72a14664d9625d643c3830182045820ead98a5dc4443583e7a7f21172070983c4ee976a3244596740f4a62583d3b247830183018204582040359d8def1c691c248e80f53a8aba59fbe6a1e50d02e129180edfd21db2e09c830182045820387dea80e62f0dbfa07f03dab79b87ce6b3064607490484175d27b502ff7c001830183018301830182045820fbed2907b8f5459948ce202f42b1195dd9906fd377c49cd1aa88efb17722b497830182045820d1a7f8911fff226d33f9b06054339e110ca542448c73fdbffce120de62b24fca83024a0000000000e0876901018301830183024e6365727469666965645f6461746182035820933e631e68b7b1084a6e95fe4a57ad5a153914fb3aeb98c6aa4fb2cf3ac13bf3820458200829df8f90932af88a1713103e2ad448a9aed5ca281ba6ed8ec14983d7e9effd820458209a48a01b312252fd3d99a8b4653faaceefa82d70f7c8e870ac48a170eaeed2218204582073a949d4310beee2caf96beb4540b58c6d45ec80867414745cc37cea169911fe8204582015d0042acd4e84d63073ae5d33049957a5bc611b4d1164c7deb46e5f745e5d1d82045820c6f7402eae9f2b4d218b7c335f9a6f1caed5fe5532b207583c4b9deceb68fbf1820458209bceb4b2c6930a6f087753f8af86e903c85a131b0e871726c6e30647387d04ca82045820065c149791637360b2b5a857d532cef8739cfd99674ec4dfa99105fcd7434b8c8301820458200cc5f79e687d743918d52837ebe7bc601beed0030625db2f269599cd3271c2ac83024474696d65820349beb3bf86e680f68d18697369676e6174757265583096305f92fd4497100020024e8d73e4209a0e6396bb3c38747b3190075c8b3ccae47e980c0d3c88ae25abe7c264af61bc6a64656c65676174696f6ea2697375626e65745f6964581d2ecc29447b0eef6c241dcfdf7dab077093ccd6a1266be0fe9c9b1276026b636572746966696361746559027dd9d9f7a26474726565830182045820c74f70cf1d15f56ff7bd0e1e340f590f06998e2beef93440fde1892be0a22a068301830182045820c2903e801596e66f2fcf55ce3ae0f048f0b5fbc08615ef01e13e78268612d02f8302467375626e6574830183018301820458200985315bbe905b7f9336d7064793905b005689f3c9c2a21ad9a31fbe6cdd55998301830183018302581d2ecc29447b0eef6c241dcfdf7dab077093ccd6a1266be0fe9c9b127602830183024f63616e69737465725f72616e6765738203581bd9d9f781824a0000000000e0000001014a0000000000efffff010183024a7075626c69635f6b657982035885308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c0503020103610091541cdc7b65c4828286c911602d9438de5649d698b60fc06aec73589395d0bca71746524ed2ff17b2c8da9fbc897f0f07a40b204871b6fe96d45ef10b51d1f1d530d0679a5db82de96929805fa17c737994ebcc2312d2a25bd94747ecf8f34b8204582036977d2eb5781a30f392aa49b68a99e752e3f180e7d6c65dc1155bac272096038204582070ffc8b074ec3f16c63c4ef67bfffa086f81abd71c92ca2bfb58a0fb5f6f9a1882045820ab74f479ced86b9d9505e2ba143c5d3e1c383a8a7e7c68a85a0ec66b45f6b741820458206961ef137c2aee0b0467082ef6d3c12c03e93013b602a4cb6214270e484863f182045820a5aaaae4ade1f4e05825f479f11cec60e33d2ddbe1588e79b487a9719949ec9983024474696d65820349a597f594d5f6c98d18697369676e61747572655830b4769533ae5f988ae2a682cf3f88ec2a4ec47886164b3c6b551bf71813f09812580f3a3ef3f01d50be8e6913be132b5864747265658301820458205c7e411bf1e02631d977532c89a992453377e6e79953095617b50f5b53f2ad4983024373696783025820a90bda9fe4705241fc20ffce06fe5f0a3ac5a097b03360b7c8a7b609c64f58f083025820660e66f039bb3672eb8738540c984b2e01b9e7234a05a4055ef783f3e6f47f01820340"
    // ).unwrap());
    let msg = hex::decode("aaaaaa").unwrap();
    let root_pk_bytes = hex::decode("814c0e6ec71fab583b08bd81373c255c3c371b2e84863c98a4f1e08b74235d14fb5d9c0cd546d9685f913a0c0b2cc5341583bf4b4392e467db96d65b9bb4cb717112f8472e0d5a4d14505ffd7484b01291091c5f87b98883463f98091a0baaae").unwrap();
    let root_pk = ThresholdSigPublicKey::from(bls12_381::PublicKeyBytes(
        <[u8; 96]>::try_from(&root_pk_bytes[..]).unwrap(),
    ));
    let result = verify(&msg[..], sig_bytes, canister_pk_bytes, &root_pk);
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn should_verify_valid_signature() {
    let rng = &mut reproducible_rng();
    for with_delegation in [false, true] {
        let (msg, sig_bytes, canister_pk_bytes, root_pk) = new_test_data(rng, with_delegation);
        assert!(verify(&msg[..], sig_bytes, canister_pk_bytes, &root_pk).is_ok());
    }
}

#[test]
fn should_fail_to_verify_if_cert_in_signature_is_malformed() {
    let rng = &mut reproducible_rng();
    for with_delegation in [false, true] {
        let (msg, sig_bytes, canister_pk_bytes, root_pk) = new_test_data(rng, with_delegation);
        let sig_with_malformed_cert = {
            let mut corrupted_sig_bytes = sig_bytes;
            // position 30 in the sig corrupts the certificate:
            corrupted_sig_bytes.0[30] ^= 0xFF;
            corrupted_sig_bytes
        };

        let result = verify(&msg, sig_with_malformed_cert, canister_pk_bytes, &root_pk);

        assert_matches!(result, Err(CryptoError::MalformedSignature {  algorithm, sig_bytes: _, internal_error})
            if internal_error.contains("malformed certificate")
            && algorithm == AlgorithmId::IcCanisterSignature
        );
    }
}

#[test]
fn should_fail_to_verify_if_signature_cbor_tag_malformed() {
    let rng = &mut reproducible_rng();
    for with_delegation in [false, true] {
        let (msg, sig_bytes, canister_pk_bytes, root_pk) = new_test_data(rng, with_delegation);
        let sig_with_malformed_cbor_tag = {
            let mut corrupted_sig = sig_bytes;
            // position 1 in the sig corrupts the CBOR tag:
            corrupted_sig.0[1] ^= 0xFF;
            corrupted_sig
        };

        let result = verify(
            &msg,
            sig_with_malformed_cbor_tag,
            canister_pk_bytes,
            &root_pk,
        );

        assert_matches!(result, Err(CryptoError::MalformedSignature {  algorithm, sig_bytes: _, internal_error})
            if internal_error.contains("signature CBOR doesn't have a self-describing tag")
            && algorithm == AlgorithmId::IcCanisterSignature
        );
    }
}

#[test]
fn should_fail_to_verify_if_signature_has_malformed_cbor() {
    let rng = &mut reproducible_rng();
    for with_delegation in [false, true] {
        let (msg, sig_bytes, canister_pk_bytes, root_pk) = new_test_data(rng, with_delegation);
        let sig_with_malformed_cbor = {
            let mut corrupted_sig = sig_bytes;
            // position 7 in the sig corrupts the CBOR:
            corrupted_sig.0[7] ^= 0xFF;
            corrupted_sig
        };

        let result = verify(&msg, sig_with_malformed_cbor, canister_pk_bytes, &root_pk);

        assert_matches!(result, Err(CryptoError::MalformedSignature {  algorithm, sig_bytes: _, internal_error})
            if internal_error.contains("failed to parse signature CBOR")
            && algorithm == AlgorithmId::IcCanisterSignature
        );
    }
}

#[test]
fn should_fail_to_verify_on_wrong_message() {
    let rng = &mut reproducible_rng();
    for with_delegation in [false, true] {
        let (msg, sig_bytes, canister_pk_bytes, root_pk) = new_test_data(rng, with_delegation);
        let wrong_msg = b"wrong message";
        assert_ne!(msg, wrong_msg);

        let result = verify(wrong_msg, sig_bytes, canister_pk_bytes, &root_pk);

        assert_matches!(result, Err(CryptoError::SignatureVerification {  algorithm, public_key_bytes: _, sig_bytes: _, internal_error})
            if internal_error.contains("the signature tree doesn't contain sig")
            && algorithm == AlgorithmId::IcCanisterSignature
        );
    }
}

#[test]
fn should_fail_to_verify_if_signature_certificate_verification_fails() {
    let rng = &mut reproducible_rng();
    for with_delegation in [false, true] {
        let (msg, sig_bytes, canister_pk_bytes, root_pk) = new_test_data(rng, with_delegation);
        let corrupted_sig = {
            let mut corrupted_sig = sig_bytes;
            let len = corrupted_sig.0.len();
            corrupted_sig.0[len - 5] ^= 0xFF;
            corrupted_sig
        };

        let result = verify(&msg, corrupted_sig, canister_pk_bytes, &root_pk);

        assert_matches!(result, Err(CryptoError::SignatureVerification {  algorithm, public_key_bytes: _, sig_bytes: _, internal_error})
            if internal_error.contains("certificate verification failed")
            && algorithm == AlgorithmId::IcCanisterSignature
        );
    }
}

#[test]
fn should_fail_to_verify_on_wrong_pubkey() {
    let rng = &mut reproducible_rng();
    for with_delegation in [false, true] {
        let (msg, sig_bytes, mut canister_pk_bytes, root_pk) = new_test_data(rng, with_delegation);
        canister_pk_bytes.0.push(9);

        let result = verify(&msg, sig_bytes, canister_pk_bytes, &root_pk);

        assert_matches!(result, Err(CryptoError::SignatureVerification {  algorithm, public_key_bytes: _, sig_bytes: _, internal_error})
            if internal_error.contains("the signature tree doesn't contain sig")
            && algorithm == AlgorithmId::IcCanisterSignature
        );
    }
}

#[test]
fn should_fail_to_verify_if_public_key_is_malformed() {
    let rng = &mut reproducible_rng();
    for with_delegation in [false, true] {
        let (msg, sig_bytes, _canister_pk_bytes, root_pk) = new_test_data(rng, with_delegation);
        let malformed_public_key = PublicKeyBytes(vec![42; 3]);

        let result = verify(&msg, sig_bytes, malformed_public_key, &root_pk);

        assert_matches!(result, Err(CryptoError::MalformedPublicKey {  algorithm, key_bytes: _, internal_error})
            if internal_error.contains("Malformed")
            && algorithm == AlgorithmId::IcCanisterSignature
        );
    }
}

#[test]
fn should_fail_to_verify_on_invalid_root_pubkey() {
    let rng = &mut reproducible_rng();
    for with_delegation in [false, true] {
        let (msg, sig_bytes, canister_pk_bytes, root_pk) = new_test_data(rng, with_delegation);
        let invalid_root_pk = ThresholdSigPublicKey::from(bls12_381::PublicKeyBytes(
            [42; bls12_381::PublicKeyBytes::SIZE],
        ));
        assert_ne!(root_pk, invalid_root_pk);

        let result = verify(&msg, sig_bytes, canister_pk_bytes, &invalid_root_pk);

        println!("{:?}", result.clone().err());

        assert_matches!(result, Err(CryptoError::SignatureVerification {  algorithm, public_key_bytes: _, sig_bytes: _, internal_error})
            if internal_error.contains("Invalid public key")
            && internal_error.contains("certificate verification failed")
            && algorithm == AlgorithmId::IcCanisterSignature
        );
    }
}

#[test]
fn should_fail_to_verify_on_wrong_root_pubkey() {
    let rng = &mut reproducible_rng();
    for with_delegation in [false, true] {
        let (msg, sig_bytes, canister_pk_bytes, root_pk) = new_test_data(rng, with_delegation);
        // This is a valid public key different from root_pk. It was extracted using
        // `From<&NiDkgTranscript> for ThresholdSigPublicKey` from an `NiDkgTranscript`
        // in an integration test.
        let wrong_root_pk = {
            let wrong_root_pk_vec = hex::decode("91cf31d8a6ac701281d2e38d285a4141858f355e05102cedd280f98dfb277613a8b96ac32a5f463ebea2ae493f4eba8006e30b0f2f5c426323fb825a191fb7f639f61d33a0c07addcdd2791d2ac32ec8be354e8465b6a18da6b5685deb0e9245").unwrap();
            let mut wrong_root_pk_bytes = [0; 96];
            wrong_root_pk_bytes.copy_from_slice(&wrong_root_pk_vec);
            ThresholdSigPublicKey::from(bls12_381::PublicKeyBytes(wrong_root_pk_bytes))
        };
        assert_ne!(root_pk, wrong_root_pk);

        let result = verify(&msg, sig_bytes, canister_pk_bytes, &wrong_root_pk);

        assert_matches!(result, Err(CryptoError::SignatureVerification {  algorithm, public_key_bytes: _, sig_bytes: _, internal_error})
            if internal_error.contains("Invalid combined threshold signature")
            && internal_error.contains("certificate verification failed")
            && algorithm == AlgorithmId::IcCanisterSignature
        );
    }
}

fn new_test_data<R: Rng + RngCore + CryptoRng>(
    rng: &mut R,
    with_delegation: bool,
) -> (
    Vec<u8>,
    SignatureBytes,
    PublicKeyBytes,
    ThresholdSigPublicKey,
) {
    let state = new_random_cert(rng, with_delegation);
    let pk_bytes = PublicKeyBytes(canister_sig_pub_key_to_bytes(
        state.canister_id,
        &state.seed[..],
    ));
    let sig = Signature {
        certificate: Blob(state.cbor),
        tree: state.witness,
    };
    let sig_bytes = SignatureBytes(serialize_to_cbor(&sig));
    (state.msg, sig_bytes, pk_bytes, state.root_pk)
}
