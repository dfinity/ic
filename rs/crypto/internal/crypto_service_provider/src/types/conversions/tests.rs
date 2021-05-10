#![allow(clippy::unwrap_used)]
use super::*;
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
         (CspPublicKey::EcdsaP256(_), Err(error)) => panic!("Failed to convert supported type: {:?}", error),
         (CspPublicKey::Ed25519(_), Ok(_)) => (),
         (CspPublicKey::Ed25519(_), Err(error)) => panic!("Failed to convert supported type: {:?}", error),
         (unsupported, Ok(_)) => panic!("Unsupported type was successfuly converted to a UserPublicKey: {:?}", unsupported),
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
        };

        let deserialized_pop = CspPop::try_from(&pk_proto).unwrap();

        if let CspPop::MultiBls12_381(multi_types::PopBytes(deserialized_bytes)) = deserialized_pop
        {
            assert_eq!(deserialized_bytes.to_vec(), pop_bytes.to_vec());
        } else {
            panic!("Unexpected POP");
        }
    }

    #[test]
    fn should_return_error_if_proof_data_missing() {
        let pk_proto = PublicKeyProto {
            algorithm: AlgorithmIdProto::MultiBls12381 as i32,
            key_value: [42; 10].to_vec(),
            version: 1,
            proof_data: None,
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
