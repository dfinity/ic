#![allow(clippy::unwrap_used)]
use super::*;

mod pubkey_proto_to_pubkey_bytes {
    use super::*;

    #[test]
    fn should_convert_proto_to_pubkey_bytes() {
        let pubkey_bytes = PublicKeyBytes([42; PublicKeyBytes::SIZE]);
        let pk_proto = PublicKeyProto {
            key_value: pubkey_bytes.0.to_vec(),
            ..dummy_committee_signing_pubkey_proto()
        };

        let result = PublicKeyBytes::try_from(&pk_proto);

        assert_eq!(result.unwrap(), pubkey_bytes);
    }

    #[test]
    fn should_return_error_if_length_invalid() {
        let pubkey_bytes_with_invalid_length = [42; PublicKeyBytes::SIZE - 1];
        let pk_proto = PublicKeyProto {
            key_value: pubkey_bytes_with_invalid_length.to_vec(),
            ..dummy_committee_signing_pubkey_proto()
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
            ..dummy_committee_signing_pubkey_proto()
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
}

mod pubkey_proto_to_pop_bytes {
    use super::*;

    #[test]
    fn should_convert_proto_to_pop_bytes() {
        let pop_bytes = PopBytes([42; PopBytes::SIZE]);
        let pk_proto = PublicKeyProto {
            proof_data: Some(pop_bytes.0.to_vec()),
            ..dummy_committee_signing_pubkey_proto()
        };

        let result = PopBytes::try_from(&pk_proto);

        assert_eq!(result.unwrap(), pop_bytes);
    }

    #[test]
    fn should_return_error_if_proof_data_missing() {
        let pk_proto = PublicKeyProto {
            proof_data: None,
            ..dummy_committee_signing_pubkey_proto()
        };

        let result = PopBytes::try_from(&pk_proto);

        assert_eq!(
            result.unwrap_err(),
            PopBytesFromProtoError::MissingProofData
        );
    }

    #[test]
    fn should_return_error_if_algorithm_invalid() {
        let invalid_algorithm = AlgorithmIdProto::Unspecified as i32;
        let pk_proto = PublicKeyProto {
            algorithm: invalid_algorithm,
            ..dummy_committee_signing_pubkey_proto()
        };

        let result = PopBytes::try_from(&pk_proto);

        assert_eq!(
            result.unwrap_err(),
            PopBytesFromProtoError::UnknownAlgorithm {
                algorithm: invalid_algorithm
            }
        );
    }

    #[test]
    fn should_return_error_if_proof_data_length_invalid() {
        let proof_data_with_invalid_length = [42; PopBytes::SIZE + 1];
        let pk_proto = PublicKeyProto {
            proof_data: Some(proof_data_with_invalid_length.to_vec()),
            ..dummy_committee_signing_pubkey_proto()
        };

        let result = PopBytes::try_from(&pk_proto);

        assert_eq!(
            result.unwrap_err(),
            PopBytesFromProtoError::InvalidLength {
                pop_bytes: proof_data_with_invalid_length.to_vec(),
                internal_error: format!(
                    "Wrong pop length {}, expected length {}.",
                    proof_data_with_invalid_length.len(),
                    PopBytes::SIZE
                ),
            }
        );
    }
}

fn dummy_committee_signing_pubkey_proto() -> PublicKeyProto {
    PublicKeyProto {
        algorithm: AlgorithmIdProto::MultiBls12381 as i32,
        key_value: [1; PublicKeyBytes::SIZE].to_vec(),
        version: 0,
        proof_data: Some([2; PopBytes::SIZE].to_vec()),
    }
}
