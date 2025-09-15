use super::*;
use crate::types::CspPublicCoefficients;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::PublicCoefficientsBytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use proptest::prelude::*;

proptest! {
    /// Verifies that supported CspPublicKeys can be converted to UserPublicKeys
    #[test]
    fn csp_public_key_to_user_key(csp_public_key: CspPublicKey) {
       match (csp_public_key.clone(), UserPublicKey::try_from(csp_public_key)) {
         (CspPublicKey::EcdsaP256(_), Ok(_)) => (),
         (CspPublicKey::EcdsaP256(_), Err(error)) => panic!("Failed to convert supported type: {error:?}"),
         (CspPublicKey::Ed25519(_), Ok(_)) => (),
         (CspPublicKey::Ed25519(_), Err(error)) => panic!("Failed to convert supported type: {error:?}"),
         (unsupported, Ok(_)) => panic!("Unsupported type was successfully converted to a UserPublicKey: {unsupported:?}"),
         (_, Err(_)) => (),
       };
    }
}

#[test]
fn should_determine_algorithm_id_from_csp_public_coefficients() {
    assert_eq!(
        AlgorithmId::from(&CspPublicCoefficients::Bls12_381(pub_coeff_bytes())),
        AlgorithmId::ThresBls12_381
    );
}

fn pub_coeff_bytes() -> PublicCoefficientsBytes {
    PublicCoefficientsBytes {
        coefficients: vec![PublicKeyBytes([42; PublicKeyBytes::SIZE])],
    }
}

mod proto_to_csp_pubkey {
    use super::*;
    use ic_crypto_internal_test_vectors::ed25519::TESTVEC_RFC8032_ED25519_SHA_ABC_PK;
    use ic_crypto_internal_test_vectors::multi_bls12_381::TESTVEC_MULTI_BLS12_381_1_PK;
    use ic_crypto_internal_test_vectors::unhex::hex_to_byte_vec;

    #[test]
    fn should_correctly_convert_ed25519_pk_proto_to_csp_public_key() {
        let pk_proto = PublicKeyProto {
            algorithm: AlgorithmIdProto::Ed25519 as i32,
            key_value: hex_to_byte_vec(TESTVEC_RFC8032_ED25519_SHA_ABC_PK),
            version: 0,
            proof_data: None,
            timestamp: None,
        };
        let ed25519_csp_pk = CspPublicKey::try_from(pk_proto).unwrap();

        assert_eq!(
            ed25519_csp_pk.ed25519_bytes().unwrap().to_vec(),
            hex_to_byte_vec(TESTVEC_RFC8032_ED25519_SHA_ABC_PK)
        );
    }

    #[test]
    fn should_correctly_convert_multi_bls12_381_pk_proto_to_csp_public_key() {
        let pk_proto = PublicKeyProto {
            algorithm: AlgorithmIdProto::MultiBls12381 as i32,
            key_value: hex_to_byte_vec(TESTVEC_MULTI_BLS12_381_1_PK),
            version: 0,
            proof_data: None,
            timestamp: None,
        };
        let multi_bls_csp_pk = CspPublicKey::try_from(pk_proto).unwrap();

        assert_eq!(
            multi_bls_csp_pk.multi_bls12_381_bytes().unwrap().to_vec(),
            hex_to_byte_vec(TESTVEC_MULTI_BLS12_381_1_PK)
        );
    }

    #[test]
    fn should_fail_conversion_to_csp_public_key_if_ed25519_pk_proto_is_too_short() {
        let pk_proto = PublicKeyProto {
            algorithm: AlgorithmIdProto::Ed25519 as i32,
            key_value: vec![0; ed25519_types::PublicKeyBytes::SIZE - 1],
            version: 0,
            proof_data: None,
            timestamp: None,
        };
        let ed25519_csp_pk_result = CspPublicKey::try_from(pk_proto);
        assert!(ed25519_csp_pk_result.is_err());
        assert!(ed25519_csp_pk_result.unwrap_err().is_malformed_public_key());
    }

    #[test]
    fn should_fail_conversion_to_csp_public_key_if_ed25519_pk_proto_is_too_long() {
        let pk_proto = PublicKeyProto {
            algorithm: AlgorithmIdProto::Ed25519 as i32,
            key_value: vec![0; ed25519_types::PublicKeyBytes::SIZE + 1],
            version: 0,
            proof_data: None,
            timestamp: None,
        };
        let ed25519_csp_pk_result = CspPublicKey::try_from(pk_proto);
        assert!(ed25519_csp_pk_result.is_err());
        assert!(ed25519_csp_pk_result.unwrap_err().is_malformed_public_key());
    }

    #[test]
    fn should_fail_conversion_to_csp_public_key_if_multi_bls12_381_pk_proto_is_too_short() {
        let pk_proto = PublicKeyProto {
            algorithm: AlgorithmIdProto::MultiBls12381 as i32,
            key_value: vec![0; multi_types::PublicKeyBytes::SIZE - 1],
            version: 0,
            proof_data: None,
            timestamp: None,
        };
        let multi_csp_pk_result = CspPublicKey::try_from(pk_proto);
        assert!(multi_csp_pk_result.is_err());
        assert!(multi_csp_pk_result.unwrap_err().is_malformed_public_key());
    }

    #[test]
    fn should_fail_conversion_to_csp_public_key_if_multi_bls12_381_pk_proto_is_too_long() {
        let pk_proto = PublicKeyProto {
            algorithm: AlgorithmIdProto::MultiBls12381 as i32,
            key_value: vec![0; multi_types::PublicKeyBytes::SIZE + 1],
            version: 0,
            proof_data: None,
            timestamp: None,
        };
        let multi_csp_pk_result = CspPublicKey::try_from(pk_proto);
        assert!(multi_csp_pk_result.is_err());
        assert!(multi_csp_pk_result.unwrap_err().is_malformed_public_key());
    }
}

mod proto_to_csp_pop_tests {
    use super::*;

    #[test]
    fn should_convert_proto_to_pop() {
        let pop_bytes = vec![42; multi_types::PopBytes::SIZE];
        let pk_proto = PublicKeyProto {
            algorithm: AlgorithmIdProto::MultiBls12381 as i32,
            key_value: [42; 10].to_vec(),
            version: 1,
            proof_data: Some(pop_bytes.clone()),
            timestamp: None,
        };

        let deserialized_pop = CspPop::try_from(&pk_proto).unwrap();

        let CspPop::MultiBls12_381(multi_types::PopBytes(deserialized_bytes)) = deserialized_pop;
        assert_eq!(deserialized_bytes.to_vec(), pop_bytes.to_vec());
    }

    #[test]
    fn should_return_error_if_proof_data_missing() {
        let pk_proto = PublicKeyProto {
            algorithm: AlgorithmIdProto::MultiBls12381 as i32,
            key_value: [42; 10].to_vec(),
            version: 1,
            proof_data: None,
            timestamp: None,
        };

        let error = CspPop::try_from(&pk_proto).unwrap_err();

        assert_eq!(error, CspPopFromPublicKeyProtoError::MissingProofData);
    }

    #[test]
    fn should_return_error_if_algorithm_wrong() {
        let unknown_algorithm = AlgorithmIdProto::Unspecified as i32;
        let pk_proto = PublicKeyProto {
            algorithm: unknown_algorithm,
            key_value: [42; 10].to_vec(),
            version: 1,
            proof_data: Some(vec![42; multi_types::IndividualSignatureBytes::SIZE]),
            timestamp: None,
        };

        let error = CspPop::try_from(&pk_proto).unwrap_err();

        assert_eq!(
            error,
            CspPopFromPublicKeyProtoError::NoPopForAlgorithm {
                algorithm: AlgorithmId::from(unknown_algorithm)
            }
        );
    }

    #[test]
    fn should_return_error_if_proof_data_malformed() {
        let malformed_proof_data = vec![42; multi_types::IndividualSignatureBytes::SIZE - 1];
        let pk_proto = PublicKeyProto {
            algorithm: AlgorithmIdProto::MultiBls12381 as i32,
            key_value: [42; 10].to_vec(),
            version: 1,
            proof_data: Some(malformed_proof_data.clone()),
            timestamp: None,
        };

        let error = CspPop::try_from(&pk_proto).unwrap_err();

        assert_eq!(
            error,
            CspPopFromPublicKeyProtoError::MalformedPop {
                pop_bytes: malformed_proof_data,
                internal_error: "Wrong pop length 47, expected length 48.".to_string()
            }
        );
    }
}

#[test]
fn csp_pop_from_public_key_proto_error_debug_print() {
    let test_vectors = vec![
        (
            CspPopFromPublicKeyProtoError::NoPopForAlgorithm {
                algorithm: AlgorithmId::Ed25519,
            },
            "CspPopFromPublicKeyProtoError::NoPopForAlgorithm{ algorithm: Ed25519 }",
        ),
        (
            CspPopFromPublicKeyProtoError::MissingProofData,
            "CspPopFromPublicKeyProtoError::MissingProofData",
        ),
        (
            CspPopFromPublicKeyProtoError::MalformedPop {
                pop_bytes: vec![1, 2, 3],
                internal_error: "Foo".to_string(),
            },
            "CspPopFromPublicKeyProtoError::MalformedPop{ pop_bytes: \"010203\", internal_error: Foo }",
        ),
    ];
    for (value, formatted) in test_vectors {
        assert_eq!(format!("{value:?}"), *formatted);
    }
}
