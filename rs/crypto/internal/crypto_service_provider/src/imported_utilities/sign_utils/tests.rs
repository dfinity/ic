#![allow(clippy::unwrap_used)]
use crate::imported_utilities::sign_utils as utils;
use ic_crypto_internal_basic_sig_der_utils::subject_public_key_info_der;
use ic_crypto_internal_test_vectors::test_data;
use simple_asn1::oid;

use ic_types::crypto::AlgorithmId;
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::pkey::PKey;

const MESSAGE: &str = "some message";

#[test]
fn should_correctly_parse_der_encoded_ecdsa_p256_pk() {
    let pk_der = hex::decode(test_data::ECDSA_P256_PK_DER_HEX).unwrap();
    let (pk, bytes_type) = utils::user_public_key_from_bytes(&pk_der).unwrap();
    assert_eq!(pk.algorithm_id, AlgorithmId::EcdsaP256);
    assert_eq!(
        bytes_type,
        utils::KeyBytesContentType::EcdsaP256PublicKeyDer
    );
}

#[test]
fn should_correctly_parse_der_encoded_iccsa_pubkey() {
    let pubkey = b"public key".to_vec();
    let pubkey_der =
        subject_public_key_info_der(oid!(1, 3, 6, 1, 4, 1, 56387, 1, 2), &pubkey).unwrap();

    let (parsed_pubkey, content_type) = utils::user_public_key_from_bytes(&pubkey_der).unwrap();

    assert_eq!(parsed_pubkey.algorithm_id, AlgorithmId::IcCanisterSignature);
    assert_eq!(parsed_pubkey.key, pubkey);
    assert_eq!(
        content_type,
        utils::KeyBytesContentType::IcCanisterSignatureAlgPublicKeyDer
    );
}

#[test]
fn should_correctly_parse_der_encoded_safari_ecdsa_p256_pk() {
    let pk_der = hex::decode(test_data::SAFARI_ECDSA_P256_PK_DER_HEX).unwrap();
    let (pk, bytes_type) = utils::user_public_key_from_bytes(&pk_der).unwrap();
    assert_eq!(pk.algorithm_id, AlgorithmId::EcdsaP256);
    assert_eq!(
        bytes_type,
        utils::KeyBytesContentType::EcdsaP256PublicKeyDer
    );
}

#[test]
fn should_correctly_parse_der_encoded_chrome_ecdsa_p256_pk() {
    let pk_der = hex::decode(test_data::CHROME_ECDSA_P256_PK_DER_HEX).unwrap();
    let (pk, bytes_type) = utils::user_public_key_from_bytes(&pk_der).unwrap();
    assert_eq!(pk.algorithm_id, AlgorithmId::EcdsaP256);
    assert_eq!(
        bytes_type,
        utils::KeyBytesContentType::EcdsaP256PublicKeyDer
    );
}

#[test]
fn should_correctly_parse_der_encoded_firefox_ecdsa_p256_pk() {
    let pk_der = hex::decode(test_data::FIREFOX_ECDSA_P256_PK_DER_HEX).unwrap();
    let (pk, bytes_type) = utils::user_public_key_from_bytes(&pk_der).unwrap();
    assert_eq!(pk.algorithm_id, AlgorithmId::EcdsaP256);
    assert_eq!(
        bytes_type,
        utils::KeyBytesContentType::EcdsaP256PublicKeyDer
    );
}

#[test]
fn should_correctly_parse_der_encoded_ecdsa_secp256k1_pk() {
    let pk_der = hex::decode(test_data::ECDSA_SECP256K1_PK_DER_HEX).unwrap();
    let (pk, bytes_type) = utils::user_public_key_from_bytes(&pk_der).unwrap();
    assert_eq!(pk.algorithm_id, AlgorithmId::EcdsaSecp256k1);
    assert_eq!(
        bytes_type,
        utils::KeyBytesContentType::EcdsaSecp256k1PublicKeyDer
    );
}

#[test]
fn should_fail_parse_raw_ed25519_pk() {
    let pk_raw = hex::decode(test_data::ED25519_PK_1_RFC8032_HEX).unwrap();
    let result = utils::user_public_key_from_bytes(&pk_raw);
    assert!(result.is_err());
}

#[test]
fn should_correctly_parse_der_encoded_openssl_ecdsa_p256_pk() {
    let (pk_der, _) = new_pk_and_sig_der(Nid::X9_62_PRIME256V1);
    let (pk, bytes_type) = utils::user_public_key_from_bytes(&pk_der).unwrap();
    assert_eq!(pk.algorithm_id, AlgorithmId::EcdsaP256);
    assert_eq!(
        bytes_type,
        utils::KeyBytesContentType::EcdsaP256PublicKeyDer
    );
}

#[test]
fn should_correctly_parse_der_encoded_ecdsa_p256_sig() {
    let (_, sig_der) = new_pk_and_sig_der(Nid::X9_62_PRIME256V1);
    let sig = utils::ecdsa_p256_signature_from_der_bytes(&sig_der).unwrap();
    assert_eq!(sig.0.len(), 64);
}

#[test]
fn should_fail_parsing_corrupted_der_encoded_ecdsa_p256_sig() {
    let (_, sig_der) = new_pk_and_sig_der(Nid::X9_62_PRIME256V1);
    let sig_result = utils::ecdsa_p256_signature_from_der_bytes(&sig_der[1..]);
    assert!(sig_result.is_err());
}

#[test]
fn should_fail_parsing_corrupted_raw_pk() {
    let pk_raw = hex::decode(test_data::ED25519_PK_1_RFC8032_HEX).unwrap();
    let pk_result = utils::user_public_key_from_bytes(&pk_raw[1..]);
    assert!(pk_result.is_err());
}

#[test]
fn should_fail_parsing_corrupted_der_pk() {
    let pk_der = hex::decode(test_data::FIREFOX_ECDSA_P256_PK_DER_HEX).unwrap();
    let pk_result = utils::user_public_key_from_bytes(&pk_der[1..]);
    assert!(pk_result.is_err());
}

#[test]
fn should_fail_parsing_ec_keys_on_unsupported_curves() {
    for curve_name in [Nid::X9_62_PRIME192V1, Nid::X9_62_PRIME239V2].iter() {
        let (pk_der, _) = new_pk_and_sig_der(*curve_name);
        let pk_result = utils::user_public_key_from_bytes(&pk_der);
        assert!(pk_result.is_err());
    }
}

// Genereates a new EC key pair, and computes an ECDSA signature on MESSAGE.
// Returns the generated public key and the signature, both DER-encoded.
fn new_pk_and_sig_der(curve_name: Nid) -> (Vec<u8>, Vec<u8>) {
    let group = EcGroup::from_curve_name(curve_name).expect("unable to create EC group");
    let ec_key = EcKey::generate(&group).expect("unable to generate EC key");
    let ecdsa_sig = EcdsaSig::sign(MESSAGE.as_ref(), &ec_key).expect("unable to sign");
    let pkey = PKey::from_ec_key(ec_key).expect("unable to create PKey");

    (
        pkey.public_key_to_der()
            .expect("unable to DER-encode public key"),
        ecdsa_sig.to_der().expect("unable to DER-encode signature"),
    )
}
