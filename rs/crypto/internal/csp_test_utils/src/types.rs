use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
use ic_crypto_internal_csp::types::{CspPop, CspPublicKey, CspSecretKey, CspSignature};
use ic_crypto_internal_multi_sig_bls12381::types as multi_types;
use ic_crypto_internal_test_vectors::unhex::*;
use ic_protobuf::registry::crypto::v1::{
    AlgorithmId as AlgorithmIdProto, PublicKey as PublicKeyProto,
};
use ic_types::crypto::{AlgorithmId, UserPublicKey};

pub fn csp_pk_ed25519_from_hex(hex: &str) -> CspPublicKey {
    CspPublicKey::try_from(&UserPublicKey {
        key: ed25519_types::PublicKeyBytes(hex_to_32_bytes(hex))
            .0
            .to_vec(),
        algorithm_id: AlgorithmId::Ed25519,
    })
    .expect("failed to convert hex value to ed25519 CSP public key")
}

pub fn csp_pk_multi_bls12381_from_hex(hex: &str) -> CspPublicKey {
    let pk_proto = PublicKeyProto {
        version: 0,
        algorithm: i32::from(AlgorithmIdProto::MultiBls12381),
        key_value: multi_types::PublicKeyBytes(hex_to_96_bytes(hex)).0.to_vec(),
        proof_data: None,
        timestamp: None,
    };
    CspPublicKey::try_from(&pk_proto)
        .expect("failed to convert hex value to multi bls12-381 CSP public key")
}

pub fn csp_pop_multi_bls12381_from_hex(hex: &str) -> CspPop {
    let pop_bytes = multi_types::PopBytes(hex_to_48_bytes(hex));
    let pk_proto = PublicKeyProto {
        version: 0,
        algorithm: i32::from(AlgorithmIdProto::MultiBls12381),
        key_value: vec![],
        proof_data: Some(pop_bytes.0.to_vec()),
        timestamp: None,
    };
    CspPop::try_from(&pk_proto)
        .expect("failed to convert hex value to multi bls12-381 CSP proof of possession")
}

pub fn csp_sk_ed25519_from_hex(hex: &str) -> CspSecretKey {
    let key_bytes = hex_to_32_bytes(hex);
    let mut cbor = vec![161, 103, 69, 100, 50, 53, 53, 49, 57, 88, 32];
    cbor.extend_from_slice(&key_bytes);
    serde_cbor::from_slice(&cbor).expect("failed to convert hex value to ed25519 CSP secret key")
}

pub fn csp_sk_multi_bls12381_from_hex(hex: &str) -> CspSecretKey {
    let key_bytes = hex_to_32_bytes(hex);
    let mut cbor = vec![
        161, 110, 77, 117, 108, 116, 105, 66, 108, 115, 49, 50, 95, 51, 56, 49, 88, 32,
    ];
    cbor.extend_from_slice(&key_bytes);
    serde_cbor::from_slice(&cbor)
        .expect("failed to convert hex value to multi_bls12381 CSP secret key")
}

pub fn csp_sig_thres_bls12381_indiv_from_array_of(byte: u8) -> CspSignature {
    let mut cbor = vec![
        161, 110, 84, 104, 114, 101, 115, 66, 108, 115, 49, 50, 95, 51, 56, 49, 161, 106, 73, 110,
        100, 105, 118, 105, 100, 117, 97, 108, 88, 48,
    ];
    cbor.extend_from_slice(&[byte; 48]);
    serde_cbor::from_slice(&cbor)
        .expect("failed to convert hex value to multi_bls12381_individual CSP signature")
}

pub fn csp_sig_thres_bls12381_combined_from_array_of(byte: u8) -> CspSignature {
    let mut cbor = vec![
        161, 110, 84, 104, 114, 101, 115, 66, 108, 115, 49, 50, 95, 51, 56, 49, 161, 104, 67, 111,
        109, 98, 105, 110, 101, 100, 88, 48,
    ];
    cbor.extend_from_slice(&[byte; 48]);
    serde_cbor::from_slice(&cbor)
        .expect("failed to convert hex value to multi_bls12381_combined CSP signature")
}
