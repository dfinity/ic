#![allow(clippy::unwrap_used)]
use super::*;

#[test]
fn should_convert_proto_to_pubkey_bytes() {
    let pubkey_bytes = PublicKeyBytes([42; PublicKeyBytes::SIZE]);
    let pk_proto = PublicKeyProto {
        key_value: pubkey_bytes.0.to_vec(),
        ..dummy_node_signing_pubkey_proto()
    };

    let result = PublicKeyBytes::try_from(&pk_proto);

    assert_eq!(result.unwrap(), pubkey_bytes);
}

#[test]
fn should_return_error_if_length_invalid() {
    let pubkey_bytes_with_invalid_length = [42; PublicKeyBytes::SIZE - 1];
    let pk_proto = PublicKeyProto {
        key_value: pubkey_bytes_with_invalid_length.to_vec(),
        ..dummy_node_signing_pubkey_proto()
    };

    let result = PublicKeyBytes::try_from(&pk_proto);

    assert_eq!(
        result.unwrap_err(),
        PublicKeyBytesFromProtoError {
            key_bytes: pubkey_bytes_with_invalid_length.to_vec(),
            internal_error: format!(
                "Wrong data length {}, expected length {}.",
                pubkey_bytes_with_invalid_length.len(),
                PublicKeyBytes::SIZE
            )
        }
    );
}

#[test]
fn should_return_error_if_algorithm_invalid() {
    let unknown_algorithm = AlgorithmIdProto::Unspecified as i32;
    let pk_proto = PublicKeyProto {
        algorithm: unknown_algorithm,
        ..dummy_node_signing_pubkey_proto()
    };

    let result = PublicKeyBytes::try_from(&pk_proto);

    assert_eq!(
        result.unwrap_err(),
        PublicKeyBytesFromProtoError {
            key_bytes: pk_proto.key_value,
            internal_error: format!("Unknown algorithm: {}", unknown_algorithm,)
        }
    );
}

fn dummy_node_signing_pubkey_proto() -> PublicKeyProto {
    PublicKeyProto {
        algorithm: AlgorithmIdProto::Ed25519 as i32,
        key_value: [0; PublicKeyBytes::SIZE].to_vec(),
        version: 0,
        proof_data: None,
    }
}
