#![allow(clippy::unwrap_used)]
use super::*;

mod proto_to_csp_fs_enc_pubkey_conversions_tests {
    use super::*;

    #[test]
    fn should_convert_pk_proto_to_csp_fs_enc_pk() {
        let pk_data = [42; groth20_bls12_381::FsEncryptionPublicKey::SIZE];
        let pk_proto = PublicKeyProto {
            algorithm: AlgorithmIdProto::Groth20Bls12381 as i32,
            key_value: pk_data.to_vec(),
            version: 0,
            proof_data: None,
        };

        let csp_fs_enc_pk = CspFsEncryptionPublicKey::try_from(pk_proto);

        assert_eq!(
            csp_fs_enc_pk.unwrap(),
            CspFsEncryptionPublicKey::Groth20_Bls12_381(groth20_bls12_381::FsEncryptionPublicKey(
                bls12_381::G1(pk_data)
            ))
        );
    }

    #[test]
    fn should_not_convert_pk_proto_to_csp_fs_enc_pk_if_length_wrong() {
        const WRONG_LENGTH: usize = groth20_bls12_381::FsEncryptionPublicKey::SIZE - 5;
        let pk_data = [42; WRONG_LENGTH];
        let pk_proto = PublicKeyProto {
            algorithm: AlgorithmIdProto::Groth20Bls12381 as i32,
            key_value: pk_data.to_vec(),
            version: 0,
            proof_data: None,
        };

        let csp_fs_enc_pk = CspFsEncryptionPublicKey::try_from(pk_proto);

        assert_eq!(
            csp_fs_enc_pk.unwrap_err(),
            MalformedFsEncryptionPublicKeyError {
                key_bytes: pk_data.to_vec(),
                internal_error: format!(
                    "Wrong data length {}, expected length {}.",
                    WRONG_LENGTH,
                    groth20_bls12_381::FsEncryptionPublicKey::SIZE
                )
            }
        );
    }

    #[test]
    fn should_not_convert_pk_proto_to_csp_fs_enc_pk_if_algorithm_unknown() {
        let unknown_algorithm = AlgorithmIdProto::Unspecified as i32;
        let pk_data = [42; groth20_bls12_381::FsEncryptionPublicKey::SIZE];
        let pk_proto = PublicKeyProto {
            algorithm: unknown_algorithm,
            key_value: pk_data.to_vec(),
            version: 0,
            proof_data: None,
        };

        let csp_fs_enc_pk = CspFsEncryptionPublicKey::try_from(pk_proto);

        assert_eq!(
            csp_fs_enc_pk.unwrap_err(),
            MalformedFsEncryptionPublicKeyError {
                key_bytes: pk_data.to_vec(),
                internal_error: "Unknown algorithm: 0".to_string()
            }
        );
    }
}

mod proto_to_csp_fs_enc_pop_conversions_tests {
    use super::*;
    use crate::curves::bls12_381::{Fr, G1};

    #[test]
    fn should_convert_proto_to_pop() {
        let csp_pop = dummy_csp_pop();
        let pk_proto = PublicKeyProto {
            algorithm: AlgorithmIdProto::Groth20Bls12381 as i32,
            key_value: [42; groth20_bls12_381::FsEncryptionPublicKey::SIZE].to_vec(),
            version: 0,
            proof_data: Some(serde_cbor::to_vec(&csp_pop).unwrap()),
        };

        let deserialized_pop = CspFsEncryptionPop::try_from(&pk_proto).unwrap();

        assert_eq!(deserialized_pop, csp_pop);
    }

    #[test]
    fn should_return_error_if_proof_data_missing() {
        let pk_proto = PublicKeyProto {
            algorithm: AlgorithmIdProto::Groth20Bls12381 as i32,
            key_value: [42; groth20_bls12_381::FsEncryptionPublicKey::SIZE].to_vec(),
            version: 0,
            proof_data: None,
        };

        let error = CspFsEncryptionPop::try_from(&pk_proto).unwrap_err();

        assert_eq!(
            error,
            CspFsEncryptionPopFromPublicKeyProtoError::MissingProofData
        );
    }

    #[test]
    fn should_return_error_if_algorithm_wrong() {
        let unknown_algorithm = AlgorithmIdProto::Unspecified as i32;
        let pk_proto = PublicKeyProto {
            algorithm: unknown_algorithm,
            key_value: [42; groth20_bls12_381::FsEncryptionPublicKey::SIZE].to_vec(),
            version: 0,
            proof_data: Some(serde_cbor::to_vec(&dummy_csp_pop()).unwrap()),
        };

        let error = CspFsEncryptionPop::try_from(&pk_proto).unwrap_err();

        assert_eq!(
            error,
            CspFsEncryptionPopFromPublicKeyProtoError::UnknownAlgorithm {
                algorithm: unknown_algorithm
            }
        );
    }

    #[test]
    fn should_return_error_if_proof_data_malformed() {
        let malformed_proof_data = vec![42, 42];
        let pk_proto = PublicKeyProto {
            algorithm: AlgorithmIdProto::Groth20Bls12381 as i32,
            key_value: [42; groth20_bls12_381::FsEncryptionPublicKey::SIZE].to_vec(),
            version: 0,
            proof_data: Some(malformed_proof_data.clone()),
        };

        let error = CspFsEncryptionPop::try_from(&pk_proto).unwrap_err();

        assert_eq!(
            error,
            CspFsEncryptionPopFromPublicKeyProtoError::MalformedPop {
                pop_bytes: malformed_proof_data,
                internal_error: "invalid type: integer `-11`, expected variant identifier"
                    .to_string()
            }
        );
    }

    fn dummy_csp_pop() -> CspFsEncryptionPop {
        CspFsEncryptionPop::Groth20WithPop_Bls12_381(groth20_bls12_381::FsEncryptionPop {
            pop_key: G1([42; G1::SIZE]),
            challenge: Fr([42; Fr::SIZE]),
            response: Fr([42; Fr::SIZE]),
        })
    }
}
