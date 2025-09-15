use ic_crypto_internal_basic_sig_der_utils::subject_public_key_info_der;
use ic_crypto_internal_test_vectors::test_data;
use ic_crypto_standalone_sig_verifier::{
    KeyBytesContentType, ecdsa_p256_signature_from_der_bytes, user_public_key_from_bytes,
};
use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
use simple_asn1::oid;

use ic_types::crypto::AlgorithmId;
use rand::{CryptoRng, Rng};

const MESSAGE: &str = "some message";

#[test]
fn should_correctly_parse_der_encoded_ecdsa_p256_pk() {
    let pk_der = hex::decode(test_data::ECDSA_P256_PK_DER_HEX).unwrap();
    let (pk, bytes_type) = user_public_key_from_bytes(&pk_der).unwrap();
    assert_eq!(pk.algorithm_id, AlgorithmId::EcdsaP256);
    assert_eq!(bytes_type, KeyBytesContentType::EcdsaP256PublicKeyDer);
}

#[test]
fn should_correctly_parse_der_encoded_iccsa_pubkey() {
    let pubkey = b"public key".to_vec();
    let pubkey_der =
        subject_public_key_info_der(oid!(1, 3, 6, 1, 4, 1, 56387, 1, 2), &pubkey).unwrap();

    let (parsed_pubkey, content_type) = user_public_key_from_bytes(&pubkey_der).unwrap();

    assert_eq!(parsed_pubkey.algorithm_id, AlgorithmId::IcCanisterSignature);
    assert_eq!(parsed_pubkey.key, pubkey);
    assert_eq!(
        content_type,
        KeyBytesContentType::IcCanisterSignatureAlgPublicKeyDer
    );
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
fn should_correctly_parse_der_encoded_ecdsa_secp256k1_pk() {
    let pk_der = hex::decode(test_data::ECDSA_SECP256K1_PK_DER_HEX).unwrap();
    let (pk, bytes_type) = user_public_key_from_bytes(&pk_der).unwrap();
    assert_eq!(pk.algorithm_id, AlgorithmId::EcdsaSecp256k1);
    assert_eq!(bytes_type, KeyBytesContentType::EcdsaSecp256k1PublicKeyDer);
}

#[test]
fn should_fail_parse_raw_ed25519_pk() {
    let pk_raw = hex::decode(test_data::ED25519_PK_1_RFC8032_HEX).unwrap();
    let result = user_public_key_from_bytes(&pk_raw);
    assert!(result.is_err());
}

#[test]
fn should_correctly_parse_der_encoded_openssl_ecdsa_p256_pk() {
    let rng = &mut ReproducibleRng::new();
    let pk_der = ic_secp256r1::PrivateKey::generate_using_rng(rng)
        .public_key()
        .serialize_der();
    let (pk, bytes_type) = user_public_key_from_bytes(&pk_der).unwrap();
    assert_eq!(pk.algorithm_id, AlgorithmId::EcdsaP256);
    assert_eq!(bytes_type, KeyBytesContentType::EcdsaP256PublicKeyDer);
}

#[test]
fn should_correctly_parse_der_encoded_ecdsa_p256_sig() {
    let rng = &mut ReproducibleRng::new();
    let (_, sig_der) = new_p256_pk_and_sig_der(rng);
    let sig = ecdsa_p256_signature_from_der_bytes(&sig_der).unwrap();
    assert_eq!(sig.0.len(), 64);
}

#[test]
fn should_fail_parsing_corrupted_der_encoded_ecdsa_p256_sig() {
    let rng = &mut ReproducibleRng::new();
    let (_, sig_der) = new_p256_pk_and_sig_der(rng);
    let sig_result = ecdsa_p256_signature_from_der_bytes(&sig_der[1..]);
    assert!(sig_result.is_err());
}

#[test]
fn should_fail_parsing_corrupted_raw_pk() {
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
        assert!(pk_result.is_err());
    }
}

// Generates a new P256 key pair, and computes an ECDSA signature on MESSAGE.
// Returns the generated public key and the signature, both DER-encoded.
fn new_p256_pk_and_sig_der<R: Rng + CryptoRng>(rng: &mut R) -> (Vec<u8>, Vec<u8>) {
    let sk = ic_secp256r1::PrivateKey::generate_using_rng(rng);
    let pk_der = sk.public_key().serialize_der();
    let sig_raw = sk.sign_message(MESSAGE.as_bytes());
    let sig_der = p256::ecdsa::Signature::from_slice(&sig_raw)
        .expect("invalid P256 signature")
        .to_der()
        .as_bytes()
        .to_vec();
    (pk_der, sig_der)
}
