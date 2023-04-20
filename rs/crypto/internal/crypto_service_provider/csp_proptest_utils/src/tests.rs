use super::*;
use crate::common::MAX_ALGORITHM_ID_INDEX;

#[test]
fn should_be_maximal_algorithm_index_id_to_ensure_all_variants_covered_by_strategy() {
    assert_eq!(
        AlgorithmId::MegaSecp256k1,
        AlgorithmId::from(MAX_ALGORITHM_ID_INDEX)
    );
    assert_eq!(
        AlgorithmId::Placeholder,
        AlgorithmId::from(MAX_ALGORITHM_ID_INDEX + 1)
    );
}

mod csp_basic_signature_error {
    use super::*;
    use crate::csp_basic_signature_error;
    use ic_crypto_internal_csp::vault::api::CspBasicSignatureError;

    #[test]
    fn should_have_a_strategy_for_each_variant() {
        let csp_basic_signature_error = CspBasicSignatureError::InternalError {
            internal_error: "dummy error to match upon".to_string(),
        };

        let _ = match csp_basic_signature_error {
            CspBasicSignatureError::SecretKeyNotFound { .. } => {
                csp_basic_signature_error::arb_secret_key_not_found_error().boxed()
            }
            CspBasicSignatureError::UnsupportedAlgorithm { .. } => {
                csp_basic_signature_error::arb_unsupported_algorithm_error().boxed()
            }
            CspBasicSignatureError::WrongSecretKeyType { .. } => {
                csp_basic_signature_error::arb_wrong_secret_key_type_error().boxed()
            }
            CspBasicSignatureError::MalformedSecretKey { .. } => {
                csp_basic_signature_error::arb_malformed_secret_key_error().boxed()
            }
            CspBasicSignatureError::InternalError { .. } => {
                csp_basic_signature_error::arb_internal_error().boxed()
            }
        };
    }
}

mod csp_signature {
    use super::*;
    use crate::csp_signature;
    use ic_crypto_internal_csp::types::CspSignature;

    #[test]
    fn should_have_a_strategy_for_each_variant() {
        let csp_signature = CspSignature::RsaSha256(b"dummy signature to match upon".to_vec());

        let _ = match csp_signature {
            CspSignature::EcdsaP256(_) => csp_signature::arb_ecdsa_p256_signature().boxed(),
            CspSignature::EcdsaSecp256k1(_) => {
                csp_signature::arb_ecdsa_secp_256k1_signature().boxed()
            }
            CspSignature::Ed25519(_) => csp_signature::arb_ed25519_signature().boxed(),
            CspSignature::MultiBls12_381(_) => {
                csp_signature::arb_multi_bls12_381_csp_signature().boxed()
            }
            CspSignature::ThresBls12_381(_) => {
                csp_signature::arb_thres_bls12_381_csp_signature().boxed()
            }
            CspSignature::RsaSha256(_) => csp_signature::arb_rsa_sha256_signature().boxed(),
        };
    }

    mod multi_bls12_381_signature {
        use super::*;
        use crate::csp_signature::multi_bls12_381_signature;
        use ic_crypto_internal_csp::types::MultiBls12_381_Signature;
        use ic_crypto_internal_multi_sig_bls12381::types as multi_types;

        #[test]
        fn should_have_a_strategy_for_each_variant() {
            let multi_bls12_381_signature = MultiBls12_381_Signature::Individual(
                multi_types::IndividualSignatureBytes([42; 48]),
            );

            let _ = match multi_bls12_381_signature {
                MultiBls12_381_Signature::Individual(_) => {
                    multi_bls12_381_signature::arb_individual().boxed()
                }
                MultiBls12_381_Signature::Combined(_) => {
                    multi_bls12_381_signature::arb_combined().boxed()
                }
            };
        }
    }

    mod thres_bls12_381_signature {
        use super::*;
        use crate::csp_signature::thres_bls12_381_signature;
        use ic_crypto_internal_csp::types::ThresBls12_381_Signature;
        use ic_crypto_internal_threshold_sig_bls12381::types as threshold_types;

        #[test]
        fn should_have_a_strategy_for_each_variant() {
            let thres_bls12_381_signature = ThresBls12_381_Signature::Individual(
                threshold_types::IndividualSignatureBytes([42; 48]),
            );

            let _ = match thres_bls12_381_signature {
                ThresBls12_381_Signature::Individual(_) => {
                    thres_bls12_381_signature::arb_individual().boxed()
                }
                ThresBls12_381_Signature::Combined(_) => {
                    thres_bls12_381_signature::arb_combined().boxed()
                }
            };
        }
    }
}

mod csp_public_key {
    use super::*;
    use crate::csp_public_key;
    use ic_crypto_internal_basic_sig_ecdsa_secp256r1::types as ecdsa_secp256r1_types;
    use ic_crypto_internal_csp::types::CspPublicKey;

    #[test]
    fn should_have_a_strategy_for_each_variant() {
        let csp_public_key = CspPublicKey::EcdsaP256(ecdsa_secp256r1_types::PublicKeyBytes(
            b"dummy value to match upon".to_vec(),
        ));

        let _ = match csp_public_key {
            CspPublicKey::EcdsaP256(_) => csp_public_key::arb_ecdsa_p256_public_key().boxed(),
            CspPublicKey::EcdsaSecp256k1(_) => {
                csp_public_key::arb_ecdsa_secp_256k1_public_key().boxed()
            }
            CspPublicKey::Ed25519(_) => csp_public_key::arb_ed25519_public_key().boxed(),
            CspPublicKey::MultiBls12_381(_) => {
                csp_public_key::arb_multi_bls12_381_public_key().boxed()
            }
            CspPublicKey::RsaSha256(_) => csp_public_key::arb_rsa_sha_256_public_key().boxed(),
        };
    }
}

mod csp_pop {
    use super::*;
    use crate::csp_pop;
    use ic_crypto_internal_csp::types::CspPop;
    use ic_crypto_internal_multi_sig_bls12381::types as multi_types;

    #[test]
    fn should_have_a_strategy_for_each_variant() {
        let csp_pop = CspPop::MultiBls12_381(multi_types::PopBytes([0; 48]));

        let _ = match csp_pop {
            CspPop::MultiBls12_381(_) => csp_pop::arb_multi_bls12_381().boxed(),
        };
    }
}

mod csp_basic_signature_keygen_error {
    use super::*;
    use crate::csp_basic_signature_keygen_error;
    use ic_crypto_internal_csp::vault::api::CspBasicSignatureKeygenError;

    #[test]
    fn should_have_a_strategy_for_each_variant() {
        let csp_basic_signature_keygen_error = CspBasicSignatureKeygenError::InternalError {
            internal_error: "dummy error to match upon".to_string(),
        };

        let _ = match csp_basic_signature_keygen_error {
            CspBasicSignatureKeygenError::InternalError { .. } => {
                csp_basic_signature_keygen_error::arb_internal_error().boxed()
            }
            CspBasicSignatureKeygenError::DuplicateKeyId { .. } => {
                csp_basic_signature_keygen_error::arb_duplicated_key_id_error().boxed()
            }
            CspBasicSignatureKeygenError::TransientInternalError { .. } => {
                csp_basic_signature_keygen_error::arb_transient_internal_error().boxed()
            }
        };
    }
}

mod csp_multi_signature_error {
    use super::*;
    use crate::csp_multi_signature_error;
    use ic_crypto_internal_csp::vault::api::CspMultiSignatureError;

    #[test]
    fn should_have_a_strategy_for_each_variant() {
        let csp_multi_signature_error = CspMultiSignatureError::InternalError {
            internal_error: "dummy error to match upon".to_string(),
        };

        let _ = match csp_multi_signature_error {
            CspMultiSignatureError::SecretKeyNotFound { .. } => {
                csp_multi_signature_error::arb_secret_key_not_found_error().boxed()
            }
            CspMultiSignatureError::UnsupportedAlgorithm { .. } => {
                csp_multi_signature_error::arb_unsupported_algorithm_error().boxed()
            }
            CspMultiSignatureError::WrongSecretKeyType { .. } => {
                csp_multi_signature_error::arb_wrong_secret_key_type_error().boxed()
            }
            CspMultiSignatureError::InternalError { .. } => {
                csp_multi_signature_error::arb_internal_error().boxed()
            }
        };
    }
}

mod csp_multi_signature_keygen_error {
    use super::*;
    use crate::csp_multi_signature_keygen_error;
    use ic_crypto_internal_csp::vault::api::CspMultiSignatureKeygenError;

    #[test]
    fn should_have_a_strategy_for_each_variant() {
        let csp_multi_signature_keygen_error = CspMultiSignatureKeygenError::InternalError {
            internal_error: "dummy error to match upon".to_string(),
        };

        let _ = match csp_multi_signature_keygen_error {
            CspMultiSignatureKeygenError::MalformedPublicKey { .. } => {
                csp_multi_signature_keygen_error::arb_malformed_public_key_error().boxed()
            }
            CspMultiSignatureKeygenError::InternalError { .. } => {
                csp_multi_signature_keygen_error::arb_internal_error().boxed()
            }
            CspMultiSignatureKeygenError::DuplicateKeyId { .. } => {
                csp_multi_signature_keygen_error::arb_duplicated_key_id_error().boxed()
            }
            CspMultiSignatureKeygenError::TransientInternalError { .. } => {
                csp_multi_signature_keygen_error::arb_transient_internal_error().boxed()
            }
        };
    }
}

mod csp_threshold_sign_error {
    use super::*;
    use crate::csp_threshold_sign_error;
    use ic_crypto_internal_csp::api::CspThresholdSignError;

    #[test]
    fn should_have_a_strategy_for_each_variant() {
        let csp_threshold_sign_error = CspThresholdSignError::InternalError {
            internal_error: "dummy error to match upon".to_string(),
        };

        let _ = match csp_threshold_sign_error {
            CspThresholdSignError::SecretKeyNotFound { .. } => {
                csp_threshold_sign_error::arb_secret_key_not_found_error().boxed()
            }
            CspThresholdSignError::UnsupportedAlgorithm { .. } => {
                csp_threshold_sign_error::arb_unsupported_algorithm_error().boxed()
            }
            CspThresholdSignError::WrongSecretKeyType { .. } => {
                csp_threshold_sign_error::arb_wrong_secret_key_type_error().boxed()
            }
            CspThresholdSignError::MalformedSecretKey { .. } => {
                csp_threshold_sign_error::arb_malformed_secret_key_error().boxed()
            }
            CspThresholdSignError::InternalError { .. } => {
                csp_threshold_sign_error::arb_internal_error().boxed()
            }
        };
    }
}
