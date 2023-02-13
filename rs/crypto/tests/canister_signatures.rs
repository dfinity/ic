#![allow(clippy::unwrap_used)]
use assert_matches::assert_matches;
use ic_crypto::{user_public_key_from_bytes, KeyBytesContentType};
use ic_crypto_internal_basic_sig_der_utils::subject_public_key_info_der;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381;
use ic_crypto_test_utils::canister_signatures::canister_sig_pub_key_to_bytes;
use ic_crypto_test_utils_canister_sigs::{
    new_valid_sig_and_crypto_component, temp_crypto_with_registry_with_root_pubkey,
};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_interfaces::crypto::CanisterSigVerifier;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use ic_types::crypto::SignableMock;
use ic_types::crypto::{AlgorithmId, CanisterSig, CanisterSigOf, CryptoError};

use ic_types::{CanisterId, RegistryVersion, SubnetId};
use ic_types_test_utils::ids::SUBNET_1;
use simple_asn1::oid;

pub const REG_V1: RegistryVersion = RegistryVersion::new(5);
pub const ROOT_SUBNET_ID: SubnetId = SUBNET_1;

#[test]
fn should_correctly_parse_der_encoded_iccsa_pubkey() {
    let pubkey_bytes = canister_sig_pub_key_to_bytes(CanisterId::from_u64(42), b"seed");
    let pubkey_der =
        subject_public_key_info_der(oid!(1, 3, 6, 1, 4, 1, 56387, 1, 2), &pubkey_bytes).unwrap();

    let (parsed_pubkey, content_type) = user_public_key_from_bytes(&pubkey_der).unwrap();

    assert_eq!(parsed_pubkey.algorithm_id, AlgorithmId::IcCanisterSignature);
    assert_eq!(parsed_pubkey.key, pubkey_bytes);
    assert_eq!(
        content_type,
        KeyBytesContentType::IcCanisterSignatureAlgPublicKeyDer
    );
}

#[test]
fn should_verify_valid_canister_signature() {
    let mut rng = reproducible_rng();
    for with_delegation in [false, true] {
        let data = new_valid_sig_and_crypto_component(&mut rng, REG_V1, with_delegation);

        let result = data.crypto.verify_canister_sig(
            &data.canister_sig,
            &data.msg,
            &data.canister_pk,
            REG_V1,
        );

        assert!(result.is_ok());
    }
}

#[test]
fn should_fail_to_verify_on_wrong_signature() {
    let mut rng = reproducible_rng();
    for with_delegation in [false, true] {
        let data = new_valid_sig_and_crypto_component(&mut rng, REG_V1, with_delegation);
        // TODO Implement `CorruptBytes` (see CRP-1924)
        // TODO Randomize corruption of canister signature bytes (see CRP-1930)
        let corrupted_sig_bytes = {
            let mut corrupted_sig = data.canister_sig.clone().get().0;
            let len = corrupted_sig.len();
            corrupted_sig[len - 5] ^= 0xFF;
            corrupted_sig
        };
        let wrong_signature = CanisterSigOf::new(CanisterSig(corrupted_sig_bytes));
        assert_ne!(data.canister_sig, wrong_signature);

        let result =
            data.crypto
                .verify_canister_sig(&wrong_signature, &data.msg, &data.canister_pk, REG_V1);

        assert_matches!(result, Err(CryptoError::SignatureVerification {  algorithm, public_key_bytes: _, sig_bytes: _, internal_error})
                if internal_error.contains("certificate verification failed")
                && algorithm == AlgorithmId::IcCanisterSignature
        );
    }
}

#[test]
fn should_fail_to_verify_on_wrong_message() {
    let mut rng = reproducible_rng();
    for with_delegation in [false, true] {
        let data = new_valid_sig_and_crypto_component(&mut rng, REG_V1, with_delegation);
        let wrong_message = SignableMock::new(b"wrong message".to_vec());
        assert_ne!(data.msg, wrong_message);

        let result = data.crypto.verify_canister_sig(
            &data.canister_sig,
            &wrong_message,
            &data.canister_pk,
            REG_V1,
        );

        assert_matches!(result, Err(CryptoError::SignatureVerification {  algorithm, public_key_bytes: _, sig_bytes: _, internal_error})
                if internal_error.contains("the signature tree doesn't contain sig")
                && algorithm == AlgorithmId::IcCanisterSignature
        );
    }
}

#[test]
fn should_fail_to_verify_on_wrong_public_key() {
    let mut rng = reproducible_rng();
    for with_delegation in [false, true] {
        let data = new_valid_sig_and_crypto_component(&mut rng, REG_V1, with_delegation);
        let wrong_pubkey = {
            let mut wrong_pubkey = data.canister_pk;
            wrong_pubkey.key.push(42);
            wrong_pubkey
        };

        let result =
            data.crypto
                .verify_canister_sig(&data.canister_sig, &data.msg, &wrong_pubkey, REG_V1);

        assert_matches!(result, Err(CryptoError::SignatureVerification {  algorithm, public_key_bytes: _, sig_bytes: _, internal_error})
                if internal_error.contains("the signature tree doesn't contain sig")
                && algorithm == AlgorithmId::IcCanisterSignature
        );
    }
}

#[test]
fn should_fail_to_verify_on_invalid_root_public_key() {
    let mut rng = reproducible_rng();
    for with_delegation in [false, true] {
        let data = new_valid_sig_and_crypto_component(&mut rng, REG_V1, with_delegation);
        let invalid_root_pk = {
            ThresholdSigPublicKey::from(bls12_381::PublicKeyBytes(
                [42; bls12_381::PublicKeyBytes::SIZE],
            ))
        };
        assert_ne!(data.root_pk, invalid_root_pk);
        let temp_crypto = temp_crypto_with_registry_with_root_pubkey(invalid_root_pk, REG_V1);

        let result = temp_crypto.verify_canister_sig(
            &data.canister_sig,
            &data.msg,
            &data.canister_pk,
            REG_V1,
        );

        assert_matches!(result, Err(CryptoError::SignatureVerification {  algorithm, public_key_bytes: _, sig_bytes: _, internal_error})
                if internal_error.contains("Invalid public key")
                && internal_error.contains("certificate verification failed")
                && algorithm == AlgorithmId::IcCanisterSignature
        );
    }
}

#[test]
fn should_fail_to_verify_on_wrong_root_public_key() {
    let mut rng = reproducible_rng();
    for with_delegation in [false, true] {
        let data = new_valid_sig_and_crypto_component(&mut rng, REG_V1, with_delegation);
        // This is a valid public key different from root_pk. It was extracted using
        // `From<&NiDkgTranscript> for ThresholdSigPublicKey` from an `NiDkgTranscript`
        // in an integration test.
        let wrong_root_pk = {
            let wrong_root_pk_vec = hex::decode("91cf31d8a6ac701281d2e38d285a4141858f355e05102cedd280f98dfb277613a8b96ac32a5f463ebea2ae493f4eba8006e30b0f2f5c426323fb825a191fb7f639f61d33a0c07addcdd2791d2ac32ec8be354e8465b6a18da6b5685deb0e9245").unwrap();
            let mut wrong_root_pk_bytes = [0; 96];
            wrong_root_pk_bytes.copy_from_slice(&wrong_root_pk_vec);
            ThresholdSigPublicKey::from(bls12_381::PublicKeyBytes(wrong_root_pk_bytes))
        };
        assert_ne!(data.root_pk, wrong_root_pk);
        let temp_crypto = temp_crypto_with_registry_with_root_pubkey(wrong_root_pk, REG_V1);

        let result = temp_crypto.verify_canister_sig(
            &data.canister_sig,
            &data.msg,
            &data.canister_pk,
            REG_V1,
        );

        assert_matches!(result, Err(CryptoError::SignatureVerification {  algorithm, public_key_bytes: _, sig_bytes: _, internal_error})
                if internal_error.contains("Invalid combined threshold signature")
                && internal_error.contains("certificate verification failed")
                && algorithm == AlgorithmId::IcCanisterSignature
        );
    }
}

#[test]
fn should_fail_to_verify_if_root_public_key_not_found_in_registry() {
    let mut rng = reproducible_rng();
    for with_delegation in [false, true] {
        let data = new_valid_sig_and_crypto_component(&mut rng, REG_V1, with_delegation);

        let registry_version_where_root_pubkey_is_not_available_yet =
            REG_V1 - RegistryVersion::new(1);
        let result = data.crypto.verify_canister_sig(
            &data.canister_sig,
            &data.msg,
            &data.canister_pk,
            registry_version_where_root_pubkey_is_not_available_yet,
        );

        assert_matches!(result, Err(CryptoError::RootSubnetPublicKeyNotFound { .. }));
    }
}
