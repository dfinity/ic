#![allow(clippy::unwrap_used)]
use super::*;
use ic_crypto::threshold_sig_public_key_from_der;
use ic_crypto_internal_test_vectors::iccsa;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381;
use ic_crypto_test_utils::canister_signatures::canister_sig_pub_key_to_bytes;
use ic_interfaces::crypto::Signable;
use ic_types::{messages::Delegation, time::Time, CanisterId};
use std::str::FromStr;

#[test]
fn should_verify_valid_signature() {
    let (msg, sig, pk, root_pk) = test_vec(iccsa::TestVectorId::STABILITY_1);

    assert!(verify(&msg, sig, pk, &root_pk).is_ok());
}

#[test]
fn should_fail_to_verify_if_cert_in_signature_is_malformed() {
    let (msg, sig, pk, root_pk) = test_vec(iccsa::TestVectorId::STABILITY_1);
    let sig_with_malformed_cert = {
        let mut corrupted_sig = sig;
        // position 30 in the sig corrupts the certificate:
        corrupted_sig.0[30] ^= 0xFF;
        corrupted_sig
    };

    let result = verify(&msg, sig_with_malformed_cert, pk, &root_pk);

    assert!(
        matches!(result, Err(CryptoError::MalformedSignature {  algorithm, sig_bytes: _, internal_error})
            if internal_error.contains("malformed certificate")
            && algorithm == AlgorithmId::IcCanisterSignature
        )
    );
}

#[test]
fn should_fail_to_verify_if_signature_cbor_tag_malformed() {
    let (msg, sig, pk, root_pk) = test_vec(iccsa::TestVectorId::STABILITY_1);
    let sig_with_malformed_cbor_tag = {
        let mut corrupted_sig = sig;
        // position 1 in the sig corrupts the CBOR tag:
        corrupted_sig.0[1] ^= 0xFF;
        corrupted_sig
    };

    let result = verify(&msg, sig_with_malformed_cbor_tag, pk, &root_pk);

    assert!(
        matches!(result, Err(CryptoError::MalformedSignature {  algorithm, sig_bytes: _, internal_error})
            if internal_error.contains("signature CBOR doesn't have a self-describing tag")
            && algorithm == AlgorithmId::IcCanisterSignature
        )
    );
}

#[test]
fn should_fail_to_verify_if_signature_has_malformed_cbor() {
    let (msg, sig, pk, root_pk) = test_vec(iccsa::TestVectorId::STABILITY_1);
    let sig_with_malformed_cbor = {
        let mut corrupted_sig = sig;
        // position 7 in the sig corrupts the CBOR:
        corrupted_sig.0[7] ^= 0xFF;
        corrupted_sig
    };

    let result = verify(&msg, sig_with_malformed_cbor, pk, &root_pk);

    assert!(
        matches!(result, Err(CryptoError::MalformedSignature {  algorithm, sig_bytes: _, internal_error})
            if internal_error.contains("failed to parse signature CBOR")
            && algorithm == AlgorithmId::IcCanisterSignature
        )
    );
}

#[test]
fn should_fail_to_verify_on_wrong_message() {
    let (msg, sig, pk, root_pk) = test_vec(iccsa::TestVectorId::STABILITY_1);
    let wrong_msg = b"wrong message";
    assert_ne!(msg, wrong_msg);

    let result = verify(wrong_msg, sig, pk, &root_pk);

    assert!(
        matches!(result, Err(CryptoError::SignatureVerification {  algorithm, public_key_bytes: _, sig_bytes: _, internal_error})
            if internal_error.contains("the signature tree doesn't contain sig")
            && algorithm == AlgorithmId::IcCanisterSignature
        )
    );
}

#[test]
fn should_fail_to_verify_if_signature_certificate_verification_fails() {
    let (msg, sig, pk, root_pk) = test_vec(iccsa::TestVectorId::STABILITY_1);
    let corrupted_sig = {
        let mut corrupted_sig = sig;
        let len = corrupted_sig.0.len();
        corrupted_sig.0[len - 5] ^= 0xFF;
        corrupted_sig
    };

    let result = verify(&msg, corrupted_sig, pk, &root_pk);

    assert!(
        matches!(result, Err(CryptoError::SignatureVerification {  algorithm, public_key_bytes: _, sig_bytes: _, internal_error})
            if internal_error.contains("certificate verification failed")
            && algorithm == AlgorithmId::IcCanisterSignature
        )
    );
}

#[test]
fn should_fail_to_verify_on_wrong_pubkey() {
    let (msg, sig, mut pk, root_pk) = test_vec(iccsa::TestVectorId::STABILITY_1);
    pk.0.push(9);

    let result = verify(&msg, sig, pk, &root_pk);

    assert!(
        matches!(result, Err(CryptoError::SignatureVerification {  algorithm, public_key_bytes: _, sig_bytes: _, internal_error})
            if internal_error.contains("the signature tree doesn't contain sig")
            && algorithm == AlgorithmId::IcCanisterSignature
        )
    );
}

#[test]
fn should_fail_to_verify_if_public_key_is_malformed() {
    let (msg, sig, _pk, root_pk) = test_vec(iccsa::TestVectorId::STABILITY_1);
    let malformed_public_key = PublicKeyBytes(vec![42; 3]);

    let result = verify(&msg, sig, malformed_public_key, &root_pk);

    assert!(
        matches!(result, Err(CryptoError::MalformedPublicKey {  algorithm, key_bytes: _, internal_error})
            if internal_error.contains("Malformed")
            && algorithm == AlgorithmId::IcCanisterSignature
        )
    );
}

#[test]
fn should_fail_to_verify_on_invalid_root_pubkey() {
    let (msg, sig, pk, root_pk) = test_vec(iccsa::TestVectorId::STABILITY_1);
    let invalid_root_pk = ThresholdSigPublicKey::from(bls12_381::PublicKeyBytes(
        [42; bls12_381::PublicKeyBytes::SIZE],
    ));
    assert_ne!(root_pk, invalid_root_pk);

    let result = verify(&msg, sig, pk, &invalid_root_pk);

    println!("{:?}", result.clone().err());

    assert!(
        matches!(result, Err(CryptoError::SignatureVerification {  algorithm, public_key_bytes: _, sig_bytes: _, internal_error})
            if internal_error.contains("Invalid public key")
            && internal_error.contains("certificate verification failed")
            && algorithm == AlgorithmId::IcCanisterSignature
        )
    );
}

#[test]
fn should_fail_to_verify_on_wrong_root_pubkey() {
    let (msg, sig, pk, root_pk) = test_vec(iccsa::TestVectorId::STABILITY_1);
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

    let result = verify(&msg, sig, pk, &wrong_root_pk);

    assert!(
        matches!(result, Err(CryptoError::SignatureVerification {  algorithm, public_key_bytes: _, sig_bytes: _, internal_error})
            if internal_error.contains("Invalid combined threshold signature")
            && internal_error.contains("certificate verification failed")
            && algorithm == AlgorithmId::IcCanisterSignature
        )
    );
}

fn test_vec(
    testvec_id: iccsa::TestVectorId,
) -> (
    Vec<u8>,
    SignatureBytes,
    PublicKeyBytes,
    ThresholdSigPublicKey,
) {
    let test_vec = iccsa::test_vec(testvec_id);
    let message = {
        let delegation = Delegation::new(
            test_vec.delegation_pubkey,
            Time::from_nanos_since_unix_epoch(test_vec.delegation_exp),
        );
        delegation.as_signed_bytes()
    };
    let signature_bytes = SignatureBytes(test_vec.signature);
    let public_key_bytes = {
        let canister_id = CanisterId::from_str(&test_vec.canister_id).unwrap();
        let public_key_bytes = canister_sig_pub_key_to_bytes(canister_id, &test_vec.seed);
        PublicKeyBytes(public_key_bytes)
    };
    let root_pubkey = threshold_sig_public_key_from_der(&test_vec.root_pubkey_der).unwrap();
    (message, signature_bytes, public_key_bytes, root_pubkey)
}
