#![allow(clippy::unwrap_used)]
use super::*;
use ic_crypto::threshold_sig_public_key_from_der;
use ic_crypto_internal_test_vectors::iccsa;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381;
use ic_interfaces::crypto::Signable;
use ic_types::{messages::Delegation, time::Time, CanisterId};
use std::str::FromStr;

#[test]
fn should_verify_valid_signature() {
    let (msg, sig, pk, root_pk) = test_vec(iccsa::TestVectorId::STABILITY_1);

    assert!(verify(&msg, sig, pk, &root_pk).is_ok());
}

#[test]
fn should_fail_to_verify_on_wrong_message() {
    let (msg, sig, pk, root_pk) = test_vec(iccsa::TestVectorId::STABILITY_1);
    let wrong_msg = b"wrong message";
    assert_ne!(msg, wrong_msg);

    let result = verify(wrong_msg, sig, pk, &root_pk);

    assert!(matches!(
        result,
        Err(CryptoError::SignatureVerification { .. })
    ));
}

#[test]
fn should_fail_to_verify_on_wrong_signature() {
    let (msg, sig, pk, root_pk) = test_vec(iccsa::TestVectorId::STABILITY_1);
    let corrupted_sig = {
        let mut corrupted_sig = sig;
        let len = corrupted_sig.0.len();
        corrupted_sig.0[len - 5] ^= 0xFF;
        corrupted_sig
    };

    let result = verify(&msg, corrupted_sig, pk, &root_pk);

    assert!(matches!(
        result,
        Err(CryptoError::SignatureVerification { .. })
    ));
}

#[test]
fn should_fail_to_verify_on_wrong_pubkey() {
    let (msg, sig, mut pk, root_pk) = test_vec(iccsa::TestVectorId::STABILITY_1);
    pk.0.push(9);

    let result = verify(&msg, sig, pk, &root_pk);

    assert!(matches!(
        result,
        Err(CryptoError::SignatureVerification { .. })
    ));
}

#[test]
fn should_fail_to_verify_on_wrong_root_pubkey() {
    let (msg, sig, pk, root_pk) = test_vec(iccsa::TestVectorId::STABILITY_1);
    let wrong_root_pk = ThresholdSigPublicKey::from(bls12_381::PublicKeyBytes(
        [42; bls12_381::PublicKeyBytes::SIZE],
    ));
    assert_ne!(root_pk, wrong_root_pk);

    let result = verify(&msg, sig, pk, &wrong_root_pk);

    assert!(matches!(
        result,
        Err(CryptoError::SignatureVerification { .. })
    ));
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
        let public_key_bytes = PublicKey::new(canister_id, test_vec.seed).to_bytes();
        PublicKeyBytes(public_key_bytes)
    };
    let root_pubkey = threshold_sig_public_key_from_der(&test_vec.root_pubkey_der).unwrap();
    (message, signature_bytes, public_key_bytes, root_pubkey)
}

// TODO(CRP-919): increase test coverage
