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
