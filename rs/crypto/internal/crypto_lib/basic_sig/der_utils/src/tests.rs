#![allow(clippy::unwrap_used)]
use super::*;
use simple_asn1::oid;

#[cfg(test)]
use ic_crypto_internal_test_vectors::test_data;

#[test]
fn should_have_compatible_subject_public_key_info_der_encoder_and_decoder() {
    let oid = oid!(1, 2, 3, 4, 5);
    let pubkey = b"subject public key";

    let pubkey_der_encoded = subject_public_key_info_der(oid.clone(), pubkey).unwrap();
    let (algo_id, pubkey_bytes) =
        algo_id_and_public_key_bytes_from_der(&pubkey_der_encoded).unwrap();

    assert_eq!(algo_id.oid, oid);
    assert_eq!(pubkey_bytes, pubkey);
}

#[test]
fn should_correctly_parse_cose_encoded_der_wrapped_ecdsa_p256_pk() {
    let pk_cose_der = hex::decode(test_data::ECDSA_P256_PK_3_COSE_DER_WRAPPED_HEX).unwrap();
    let _pk_cose = public_key_bytes_from_der_wrapped_cose(&pk_cose_der).unwrap();
}

#[test]
fn should_fail_parsing_a_corrupted_cose_encoded_der_wrapped_ecdsa_p256_pk() {
    let mut pk_cose_der = hex::decode(test_data::ECDSA_P256_PK_3_COSE_DER_WRAPPED_HEX).unwrap();
    pk_cose_der[0] += 1;
    let pk_result = public_key_bytes_from_der_wrapped_cose(&pk_cose_der);
    assert!(pk_result.is_err());
}

#[test]
fn should_fail_parsing_cose_encoded_der_wrapped_ecdsa_p256_pk_with_wrong_oid() {
    let mut pk_cose_der = hex::decode(test_data::ECDSA_P256_PK_3_COSE_DER_WRAPPED_HEX).unwrap();
    // OID starts at 7-th byte and is 10 bytes long.
    pk_cose_der[6] += 1;
    let pk_result = public_key_bytes_from_der_wrapped_cose(&pk_cose_der);
    assert!(pk_result.is_err());
    let err = pk_result.unwrap_err();
    assert!(err.internal_error.contains("Wrong OID:"));
}
