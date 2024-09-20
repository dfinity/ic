#![allow(clippy::unwrap_used)]
use assert_matches::assert_matches;
use ic_config::crypto::CryptoConfig;
use ic_crypto::CryptoComponent;
use ic_crypto_interfaces_sig_verification::BasicSigVerifierByPublicKey;
use ic_crypto_internal_csp::vault::vault_from_config;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_internal_test_vectors::test_data;
use ic_crypto_standalone_sig_verifier::{
    ecdsa_p256_signature_from_der_bytes, ed25519_public_key_to_der, user_public_key_from_bytes,
    KeyBytesContentType,
};
use ic_logger::replica_logger::no_op_logger;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::crypto::{AlgorithmId, BasicSig, BasicSigOf, CryptoError, UserPublicKey};
use ic_types::crypto::{SignableMock, DOMAIN_IC_REQUEST};
use ic_types::messages::MessageId;
use rand::{CryptoRng, Rng};
use std::sync::Arc;

use ic_crypto_sha2::Sha256;
use ic_crypto_test_utils::ed25519_utils::ed25519_signature_and_public_key;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;

#[test]
fn should_verify_request_id_ed25519_signature() {
    let rng = &mut reproducible_rng();
    let request_id = MessageId::from([42; 32]);
    let (signature, public_key) = ed25519_signature_and_public_key(&request_id, rng);
    CryptoConfig::run_with_temp_config(|config| {
        let crypto = crypto_component(&config);
        assert!(crypto
            .verify_basic_sig_by_public_key(&signature, &request_id, &public_key)
            .is_ok());
    })
}

#[test]
fn should_correctly_parse_der_encoded_ed25519_pk() {
    for pk_der_hex in &[
        test_data::ED25519_PK_1_DER_HEX,
        test_data::ED25519_PK_2_DER_HEX,
        test_data::ED25519_PK_3_DER_HEX,
    ] {
        let pk_der = hex::decode(pk_der_hex).unwrap();
        let (pk, bytes_type) = user_public_key_from_bytes(&pk_der).unwrap();
        assert_eq!(pk.algorithm_id, AlgorithmId::Ed25519);
        assert_eq!(bytes_type, KeyBytesContentType::Ed25519PublicKeyDer);
    }
}

#[test]
fn should_correctly_verify_sig_with_der_encoded_ed25519_pk() {
    for (pk_der_hex, sig_hex, msg_hex) in &[
        (
            test_data::ED25519_PK_1_DER_HEX,
            test_data::ED25519_SIG_1_HEX,
            test_data::ED25519_MSG_1_HEX,
        ),
        (
            test_data::ED25519_PK_2_DER_HEX,
            test_data::ED25519_SIG_2_HEX,
            test_data::ED25519_MSG_2_HEX,
        ),
        (
            test_data::ED25519_PK_3_DER_HEX,
            test_data::ED25519_SIG_3_HEX,
            test_data::ED25519_MSG_3_HEX,
        ),
    ] {
        let pk_der = hex::decode(pk_der_hex).unwrap();
        let (pk, _) = user_public_key_from_bytes(&pk_der).unwrap();
        let sig = {
            let sig_bytes = hex::decode(sig_hex).unwrap();
            BasicSigOf::new(BasicSig(sig_bytes))
        };
        let msg = SignableMock {
            domain: vec![],
            signed_bytes_without_domain: hex::decode(msg_hex).unwrap(),
        };
        CryptoConfig::run_with_temp_config(|config| {
            let crypto = crypto_component(&config);
            assert!(crypto
                .verify_basic_sig_by_public_key(&sig, &msg, &pk)
                .is_ok());
        })
    }
}

#[test]
fn should_correctly_der_encode_ed25519_pk() {
    for (pk_hex, pk_der_hex) in &[
        (test_data::ED25519_PK_1_HEX, test_data::ED25519_PK_1_DER_HEX),
        (test_data::ED25519_PK_2_HEX, test_data::ED25519_PK_2_DER_HEX),
        (test_data::ED25519_PK_3_HEX, test_data::ED25519_PK_3_DER_HEX),
    ] {
        let pk_raw = hex::decode(pk_hex).unwrap();
        let pk_der = ed25519_public_key_to_der(pk_raw.clone()).unwrap();
        assert_eq!(hex::decode(pk_der_hex).unwrap(), pk_der);

        // Decode DER PK back to PK.
        let (pk, bytes_type) = user_public_key_from_bytes(&pk_der).unwrap();
        assert_eq!(pk.algorithm_id, AlgorithmId::Ed25519);
        assert_eq!(pk.key, pk_raw);
        assert_eq!(bytes_type, KeyBytesContentType::Ed25519PublicKeyDer);
    }
}

#[test]
fn should_fail_to_der_encode_malformed_ed25519_pk() {
    // Test incorrect lengths. Should all fail.
    assert!(ed25519_public_key_to_der(vec![]).is_err());
    assert!(ed25519_public_key_to_der(vec![31; 0]).is_err());
    assert!(ed25519_public_key_to_der(vec![33; 0]).is_err());
}

#[test]
fn should_fail_verifying_corrupted_sig_with_der_encoded_ed25519_pk() {
    let pk_der = hex::decode(test_data::ED25519_PK_1_DER_HEX).unwrap();
    let (pk, _) = user_public_key_from_bytes(&pk_der).unwrap();
    let corrupted_sig = {
        let mut sig_bytes = hex::decode(test_data::ED25519_SIG_1_HEX).unwrap();
        sig_bytes[0] += 1;
        BasicSigOf::new(BasicSig(sig_bytes))
    };
    let msg = SignableMock {
        domain: vec![],
        signed_bytes_without_domain: hex::decode(test_data::ED25519_MSG_1_HEX).unwrap(),
    };
    CryptoConfig::run_with_temp_config(|config| {
        let crypto = crypto_component(&config);
        assert!(crypto
            .verify_basic_sig_by_public_key(&corrupted_sig, &msg, &pk)
            .is_err());
    })
}

#[test]
fn should_fail_verifying_sig_on_wrong_msg_with_der_encoded_ed25519_pk() {
    let pk_der = hex::decode(test_data::ED25519_PK_1_DER_HEX).unwrap();
    let (pk, _) = user_public_key_from_bytes(&pk_der).unwrap();
    let sig = {
        let sig_bytes = hex::decode(test_data::ED25519_SIG_1_HEX).unwrap();
        BasicSigOf::new(BasicSig(sig_bytes))
    };
    let wrong_msg = SignableMock {
        domain: vec![],
        signed_bytes_without_domain: vec![1, 2, 3],
    };
    CryptoConfig::run_with_temp_config(|config| {
        let crypto = crypto_component(&config);
        assert!(crypto
            .verify_basic_sig_by_public_key(&sig, &wrong_msg, &pk)
            .is_err());
    })
}

#[test]
fn should_verify_request_id_ecdsa_signature() {
    let rng = &mut reproducible_rng();
    let request_id = MessageId::from([42; 32]);
    let (signature, public_key) = ecdsa_secp256k1_signature_and_public_key(&request_id, rng);
    CryptoConfig::run_with_temp_config(|config| {
        let crypto = crypto_component(&config);
        assert!(crypto
            .verify_basic_sig_by_public_key(&signature, &request_id, &public_key)
            .is_ok());
    });
    let (signature, public_key) = ecdsa_secp256r1_signature_and_public_key(&request_id, rng);
    CryptoConfig::run_with_temp_config(|config| {
        let crypto = crypto_component(&config);
        assert_eq!(
            crypto.verify_basic_sig_by_public_key(&signature, &request_id, &public_key),
            Ok(())
        );
    });
}

#[test]
fn should_correctly_parse_der_encoded_openssl_ecdsa_p256_pk() {
    let pk_der = hex::decode(test_data::ECDSA_P256_PK_DER_HEX).unwrap();
    let (pk, bytes_type) = user_public_key_from_bytes(&pk_der).unwrap();
    assert_eq!(pk.algorithm_id, AlgorithmId::EcdsaP256);
    assert_eq!(bytes_type, KeyBytesContentType::EcdsaP256PublicKeyDer);
}

#[test]
fn should_correctly_parse_cose_encoded_der_wrapped_ecdsa_p256_pk() {
    for pk_cose_der_hex in &[
        test_data::ECDSA_P256_PK_1_COSE_DER_WRAPPED_HEX,
        test_data::ECDSA_P256_PK_2_COSE_DER_WRAPPED_HEX,
        test_data::ECDSA_P256_PK_3_COSE_DER_WRAPPED_HEX,
    ] {
        let pk_cose_der = hex::decode(pk_cose_der_hex).unwrap();
        let pk_result = user_public_key_from_bytes(&pk_cose_der);
        assert!(
            pk_result.is_ok(),
            "Failed with {} for pk_hex: {}",
            pk_result.unwrap_err(),
            pk_cose_der_hex
        );
        let (pk, bytes_type) = pk_result.unwrap();
        assert_eq!(
            pk.algorithm_id,
            AlgorithmId::EcdsaP256,
            "Failed for pk_hex: {}",
            pk_cose_der_hex
        );
        assert_eq!(
            bytes_type,
            KeyBytesContentType::EcdsaP256PublicKeyDerWrappedCose
        );
    }
}

#[test]
fn should_correctly_verify_sig_with_der_wrapped_cose_encoded_ecdsa_p256_pk() {
    for (pk_der_hex, sig_der_hex, msg_hex) in &[
        (
            test_data::ECDSA_P256_PK_1_COSE_DER_WRAPPED_HEX,
            test_data::ECDSA_P256_SIG_1_DER_HEX,
            test_data::WEBAUTHN_MSG_1_HEX,
        ),
        (
            test_data::ECDSA_P256_PK_2_COSE_DER_WRAPPED_HEX,
            test_data::ECDSA_P256_SIG_2_DER_HEX,
            test_data::WEBAUTHN_MSG_2_HEX,
        ),
    ] {
        let pk_der = hex::decode(pk_der_hex).unwrap();
        let (pk, _) = user_public_key_from_bytes(&pk_der).unwrap();
        let sig = {
            let sig_der = hex::decode(sig_der_hex).unwrap();
            BasicSigOf::new(ecdsa_p256_signature_from_der_bytes(&sig_der).unwrap())
        };
        let msg = SignableMock {
            domain: vec![],
            signed_bytes_without_domain: hex::decode(msg_hex).unwrap(),
        };
        CryptoConfig::run_with_temp_config(|config| {
            let crypto = crypto_component(&config);
            assert!(
                crypto
                    .verify_basic_sig_by_public_key(&sig, &msg, &pk)
                    .is_ok(),
                "Failed for pk_hex: {}",
                pk_der_hex
            );
        })
    }
}

#[test]
fn should_correctly_parse_der_encoded_safari_ecdsa_p256_pk() {
    let pk_der = hex::decode(test_data::SAFARI_ECDSA_P256_PK_DER_HEX).unwrap();
    let (pk, bytes_type) = user_public_key_from_bytes(&pk_der).unwrap();
    assert_eq!(pk.algorithm_id, AlgorithmId::EcdsaP256);
    assert_eq!(bytes_type, KeyBytesContentType::EcdsaP256PublicKeyDer);
}

#[test]
fn should_correctly_parse_der_encoded_chrome_ecdsa_p256_pk() {
    let pk_der = hex::decode(test_data::CHROME_ECDSA_P256_PK_DER_HEX).unwrap();
    let (pk, bytes_type) = user_public_key_from_bytes(&pk_der).unwrap();
    assert_eq!(pk.algorithm_id, AlgorithmId::EcdsaP256);
    assert_eq!(bytes_type, KeyBytesContentType::EcdsaP256PublicKeyDer);
}

#[test]
fn should_correctly_parse_der_encoded_firefox_ecdsa_p256_pk() {
    let pk_der = hex::decode(test_data::FIREFOX_ECDSA_P256_PK_DER_HEX).unwrap();
    let (pk, bytes_type) = user_public_key_from_bytes(&pk_der).unwrap();
    assert_eq!(pk.algorithm_id, AlgorithmId::EcdsaP256);
    assert_eq!(bytes_type, KeyBytesContentType::EcdsaP256PublicKeyDer);
}

#[test]
fn should_fail_parse_raw_ed25519_pk() {
    let pk_raw = hex::decode(test_data::ED25519_PK_1_RFC8032_HEX).unwrap();
    let result = user_public_key_from_bytes(&pk_raw);
    assert!(result.is_err());
}

#[test]
fn should_correctly_parse_der_encoded_ecdsa_p256_pk() {
    let rng = &mut reproducible_rng();
    let pk_der = new_secp256r1_pk_der(rng);
    let (pk, bytes_type) = user_public_key_from_bytes(&pk_der).unwrap();
    assert_eq!(pk.algorithm_id, AlgorithmId::EcdsaP256);
    assert_eq!(bytes_type, KeyBytesContentType::EcdsaP256PublicKeyDer);
}

#[test]
fn should_correctly_parse_der_encoded_ecdsa_secp256k1_pk() {
    let rng = &mut reproducible_rng();
    let pk_der = new_secp256k1_pk_der(rng);
    let (pk, bytes_type) = user_public_key_from_bytes(&pk_der).unwrap();
    assert_eq!(pk.algorithm_id, AlgorithmId::EcdsaSecp256k1);
    assert_eq!(bytes_type, KeyBytesContentType::EcdsaSecp256k1PublicKeyDer);
}

#[test]
fn should_fail_parsing_corrupted_raw_ed25519_pk() {
    let pk_raw = hex::decode(test_data::ED25519_PK_1_RFC8032_HEX).unwrap();
    let pk_result = user_public_key_from_bytes(&pk_raw[1..]);
    assert!(pk_result.is_err());
}

#[test]
fn should_fail_parsing_corrupted_der_pk() {
    let pk_der = hex::decode(test_data::FIREFOX_ECDSA_P256_PK_DER_HEX).unwrap();
    let pk_result = user_public_key_from_bytes(&pk_der[1..]);
    assert!(pk_result.is_err());
}

#[test]
fn should_fail_parsing_corrupted_cose_pk() {
    let pk_der = hex::decode(test_data::WEBAUTHN_ECDSA_P256_PK_COSE_HEX).unwrap();
    let pk_result = user_public_key_from_bytes(&pk_der[1..]);
    assert!(pk_result.is_err());
}

#[test]
fn should_fail_parsing_corrupted_cose_encoded_der_wrapped_pk() {
    let pk_cose_der = hex::decode(test_data::ECDSA_P256_PK_3_COSE_DER_WRAPPED_HEX).unwrap();
    let pk_result = user_public_key_from_bytes(&pk_cose_der[1..]);
    assert!(pk_result.is_err());
}

#[test]
fn should_fail_parsing_ec_keys_on_unsupported_curves() {
    // valid public keys generated with openssl
    const VALID_PRIME192V1_PUBKEY_DER_HEX: &str = "3049301306072a8648ce3d020106082a8648ce3d0301010332000425adc4047e9dcf0d7efbe6bb6e76794555c51f0dfd6f7f90f3067f69e17e989d5969f68e9aefbef70a1788af0b86c03e";
    const VALID_PRIME239V2_PUBKEY_DER_HEX: &str = "3055301306072a8648ce3d020106082a8648ce3d030105033e00046e1e1bf9e0b7b341d118f6a9acb08c1300af5804617098387b37e705625d6ff0ba958781f35dcec26f568481777a4827aea87c92a6ee0e48c72ce733";

    for valid_pubkey_der_hex in [
        VALID_PRIME192V1_PUBKEY_DER_HEX,
        VALID_PRIME239V2_PUBKEY_DER_HEX,
    ]
    .iter()
    {
        let pk_der = hex::decode(valid_pubkey_der_hex).expect("invalid hex");
        let pk_result = user_public_key_from_bytes(&pk_der);
        assert_matches!(
            pk_result,
            Err(CryptoError::MalformedPublicKey { internal_error, .. })
            if internal_error.contains("Unsupported or unparsable public key")
        );
    }
}

fn new_secp256r1_pk_der<R: Rng + CryptoRng>(rng: &mut R) -> Vec<u8> {
    let sk = ic_crypto_ecdsa_secp256r1::PrivateKey::generate_using_rng(rng);
    sk.public_key().serialize_der()
}

fn new_secp256k1_pk_der<R: Rng + CryptoRng>(rng: &mut R) -> Vec<u8> {
    let sk = ic_crypto_secp256k1::PrivateKey::generate_using_rng(rng);
    sk.public_key().serialize_der()
}

fn ecdsa_secp256r1_signature_and_public_key<R: Rng + CryptoRng>(
    request_id: &MessageId,
    rng: &mut R,
) -> (BasicSigOf<MessageId>, UserPublicKey) {
    let sk = ic_crypto_ecdsa_secp256r1::PrivateKey::generate_using_rng(rng);

    let signature: BasicSigOf<MessageId> = {
        let bytes_to_sign = {
            let mut buf = vec![];
            buf.extend_from_slice(DOMAIN_IC_REQUEST);
            buf.extend_from_slice(request_id.as_bytes());
            Sha256::hash(&buf)
        };
        let signature_bytes = sk.sign_digest(&bytes_to_sign).expect("failed to sign");
        BasicSigOf::new(BasicSig(signature_bytes.to_vec()))
    };

    let pk_der = sk.public_key().serialize_der();
    let (public_key, _) = user_public_key_from_bytes(&pk_der).unwrap();

    (signature, public_key)
}

fn ecdsa_secp256k1_signature_and_public_key<R: Rng + CryptoRng>(
    request_id: &MessageId,
    rng: &mut R,
) -> (BasicSigOf<MessageId>, UserPublicKey) {
    let sk = ic_crypto_secp256k1::PrivateKey::generate_using_rng(rng);

    let signature: BasicSigOf<MessageId> = {
        let bytes_to_sign = {
            let mut buf = vec![];
            buf.extend_from_slice(DOMAIN_IC_REQUEST);
            buf.extend_from_slice(request_id.as_bytes());
            Sha256::hash(&buf)
        };
        let signature_bytes = sk.sign_digest_with_ecdsa(&bytes_to_sign);
        BasicSigOf::new(BasicSig(signature_bytes.to_vec()))
    };

    let pk_der = sk.public_key().serialize_der();
    let (public_key, _) = user_public_key_from_bytes(&pk_der).unwrap();

    (signature, public_key)
}

fn crypto_component(config: &CryptoConfig) -> CryptoComponent {
    let dummy_registry = FakeRegistryClient::new(Arc::new(ProtoRegistryDataProvider::new()));

    let vault = vault_from_config(
        config,
        None,
        no_op_logger(),
        Arc::new(CryptoMetrics::none()),
    );
    ic_crypto_node_key_generation::generate_node_signing_keys(vault.as_ref());

    CryptoComponent::new(config, None, Arc::new(dummy_registry), no_op_logger(), None)
}
