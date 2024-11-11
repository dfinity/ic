#![allow(clippy::unwrap_used)]
use super::*;
use simple_asn1::oid;

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
