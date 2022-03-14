#![allow(clippy::unwrap_used)]
use ic_config::crypto::CryptoConfig;
use ic_crypto::{
    ecdsa_p256_signature_from_der_bytes, ed25519_public_key_to_der, user_public_key_from_bytes,
    CryptoComponent, KeyBytesContentType,
};
use ic_crypto_internal_test_vectors::test_data;
use ic_interfaces::crypto::{BasicSigVerifierByPublicKey, SignableMock, DOMAIN_IC_REQUEST};
use ic_logger::replica_logger::no_op_logger;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_test_utilities::types::ids::node_test_id;
use ic_types::crypto::{AlgorithmId, BasicSig, BasicSigOf, UserPublicKey};
use ic_types::messages::MessageId;
use std::sync::Arc;

use crate::ed25519_utils::ed25519_signature_and_public_key;
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::sha::sha256;

mod ed25519_utils;

#[test]
fn should_verify_request_id_ed25519_signature() {
    let request_id = MessageId::from([42; 32]);
    let (signature, public_key) = ed25519_signature_and_public_key(&request_id);
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
    let request_id = MessageId::from([42; 32]);
    let (signature, public_key) = ecdsa_signature_and_public_key(Nid::SECP256K1, &request_id);
    CryptoConfig::run_with_temp_config(|config| {
        let crypto = crypto_component(&config);
        assert!(crypto
            .verify_basic_sig_by_public_key(&signature, &request_id, &public_key)
            .is_ok());
    });
    let (signature, public_key) =
        ecdsa_signature_and_public_key(Nid::X9_62_PRIME256V1, &request_id);
    CryptoConfig::run_with_temp_config(|config| {
        let crypto = crypto_component(&config);
        assert!(crypto
            .verify_basic_sig_by_public_key(&signature, &request_id, &public_key)
            .is_ok());
    });
}

#[test]
fn should_correctly_parse_der_encoded_ecdsa_p256_pk() {
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
fn should_correctly_parse_der_encoded_openssl_ecdsa_p256_pk() {
    let pk_der = new_pk_der(Nid::X9_62_PRIME256V1);
    let (pk, bytes_type) = user_public_key_from_bytes(&pk_der).unwrap();
    assert_eq!(pk.algorithm_id, AlgorithmId::EcdsaP256);
    assert_eq!(bytes_type, KeyBytesContentType::EcdsaP256PublicKeyDer);
}

#[test]
fn should_correctly_parse_der_encoded_openssl_ecdsa_secp256k1_pk() {
    let pk_der = new_pk_der(Nid::SECP256K1);
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
    for curve_name in [Nid::X9_62_PRIME192V1, Nid::X9_62_PRIME239V2].iter() {
        let pk_der = new_pk_der(*curve_name);
        let pk_result = user_public_key_from_bytes(&pk_der);
        assert!(pk_result.is_err());
    }
}

fn new_pk_der(curve_name: Nid) -> Vec<u8> {
    let group = EcGroup::from_curve_name(curve_name).expect("unable to create EC group");
    let ec_key = EcKey::generate(&group).expect("unable to generate EC key");
    let pkey = PKey::from_ec_key(ec_key).expect("unable to create PKey");
    pkey.public_key_to_der()
        .expect("unable to DER-encode public key")
}

fn ecdsa_signature_and_public_key(
    nid: Nid,
    request_id: &MessageId,
) -> (BasicSigOf<MessageId>, UserPublicKey) {
    let ec_key = {
        let group = EcGroup::from_curve_name(nid).expect("unable to create EC group");
        EcKey::generate(&group).expect("unable to generate EC key")
    };

    let signature: BasicSigOf<MessageId> = {
        let bytes_to_sign = {
            let mut buf = vec![];
            buf.extend_from_slice(DOMAIN_IC_REQUEST);
            buf.extend_from_slice(request_id.as_bytes());
            sha256(&buf)
        };
        let ecdsa_sig = EcdsaSig::sign(&bytes_to_sign, &ec_key).expect("unable to ECDSA-sign");
        let r = ecdsa_sig.r().to_vec();
        let s = ecdsa_sig.s().to_vec();
        let signature_bytes: Vec<u8> =
            [vec![0; 32 - r.len()], r, vec![0; 32 - s.len()], s].concat();
        BasicSigOf::new(BasicSig(signature_bytes))
    };

    let pkey = PKey::from_ec_key(ec_key).expect("unable to create PKey");
    let pk_der = pkey
        .public_key_to_der()
        .expect("unable to DER-encode public key");
    let (public_key, _) = user_public_key_from_bytes(&pk_der).unwrap();

    (signature, public_key)
}

fn crypto_component(config: &CryptoConfig) -> CryptoComponent {
    let dummy_registry = FakeRegistryClient::new(Arc::new(ProtoRegistryDataProvider::new()));
    CryptoComponent::new_with_fake_node_id(
        config,
        Arc::new(dummy_registry),
        node_test_id(42),
        no_op_logger(),
    )
}
