#![allow(clippy::unwrap_used)]
use crate::LocalCspVault;

mod key_id_computations {
    use super::*;
    use crate::vault::api::PublicKeyStoreCspVault;
    use crate::vault::local_csp_vault::public_and_secret_key_store::{
        compute_committee_signing_key_id, compute_dkg_dealing_encryption_key_id,
        compute_idkg_dealing_encryption_key_id, compute_node_signing_key_id,
        compute_tls_certificate_key_id, ExternalPublicKeyError,
    };
    use crate::vault::test_utils::pks_and_sks::{
        generate_idkg_dealing_encryption_key_pair, NODE_1,
    };
    use crate::CspVault;
    use assert_matches::assert_matches;
    use ic_crypto_internal_types::encrypt::forward_secure::groth20_bls12_381;
    use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
    use ic_protobuf::registry::crypto::v1::{AlgorithmId as AlgorithmIdProto, X509PublicKeyCert};
    use ic_types::crypto::AlgorithmId;
    use ic_types_test_utils::ids::node_test_id;
    use std::sync::Arc;

    #[test]
    fn should_fail_to_compute_node_signing_key_id_on_incorrect_algorithm_id() {
        let csp_vault: Arc<dyn CspVault> = LocalCspVault::builder_for_test().build_into_arc();
        let mut node_signing_public_key = {
            let _ = csp_vault
                .gen_node_signing_key_pair()
                .expect("Error generating node signing key pair");
            csp_vault
                .current_node_public_keys()
                .expect("Error getting current node public keys")
                .node_signing_public_key
                .expect("Node public key missing")
        };
        node_signing_public_key.algorithm = AlgorithmId::MegaSecp256k1 as i32;
        let result = compute_node_signing_key_id(&node_signing_public_key);
        assert_matches!(
            result,
            Err(ExternalPublicKeyError(internal_error))
            if internal_error.contains("expected public key algorithm Ed25519, but found MegaSecp256k1")
        )
    }

    #[test]
    fn should_fail_to_compute_committee_signing_key_id_on_incorrect_algorithm_id() {
        let csp_vault: Arc<dyn CspVault> = LocalCspVault::builder_for_test().build_into_arc();
        let mut committee_signing_public_key = {
            let _ = csp_vault
                .gen_committee_signing_key_pair()
                .expect("Error generating committee signing key pair");
            csp_vault
                .current_node_public_keys()
                .expect("Error getting current node public keys")
                .committee_signing_public_key
                .expect("Committee public key missing")
        };
        committee_signing_public_key.algorithm = AlgorithmId::MegaSecp256k1 as i32;
        let result = compute_committee_signing_key_id(&committee_signing_public_key);
        assert_matches!(result,
        Err(ExternalPublicKeyError(internal_error)) if internal_error.contains("expected public key algorithm MultiBls12_381, but found MegaSecp256k1"))
    }

    #[test]
    fn should_fail_to_compute_dkg_dealing_encryption_key_id_on_incorrect_algorithm_id() {
        let csp_vault: Arc<dyn CspVault> = LocalCspVault::builder_for_test().build_into_arc();
        let mut dkg_dealing_encryption_public_key = {
            let _ = csp_vault
                .gen_dealing_encryption_key_pair(node_test_id(NODE_1))
                .expect("Error generating DKG dealing encryption key pair");
            csp_vault
                .current_node_public_keys()
                .expect("Error getting current node public keys")
                .dkg_dealing_encryption_public_key
                .expect("DKG dealing encryption public key missing")
        };
        dkg_dealing_encryption_public_key.algorithm = AlgorithmId::MegaSecp256k1 as i32;
        let result = compute_dkg_dealing_encryption_key_id(&dkg_dealing_encryption_public_key);
        assert_matches!(result,
        Err(ExternalPublicKeyError(internal_error)) if internal_error.contains("Malformed public key: Expected public key algorithm Groth20_Bls12_381, but found MegaSecp256k1"))
    }

    #[test]
    fn should_fail_to_compute_dkg_dealing_encryption_key_id_if_length_is_wrong() {
        const WRONG_LENGTH: usize = groth20_bls12_381::FsEncryptionPublicKey::SIZE - 5;
        let pk_data = [42; WRONG_LENGTH];
        let pk_proto = PublicKeyProto {
            algorithm: AlgorithmIdProto::Groth20Bls12381 as i32,
            key_value: pk_data.to_vec(),
            version: 0,
            proof_data: None,
            timestamp: None,
        };
        let result = compute_dkg_dealing_encryption_key_id(&pk_proto);
        assert_matches!(
            result,
            Err(ExternalPublicKeyError(internal_error))
            if internal_error.contains("Malformed public key MissingProofData")
        );
    }

    #[test]
    fn should_fail_to_compute_dkg_dealing_encryption_key_id_if_proof_data_is_malformed() {
        let malformed_proof_data = vec![42, 42];
        let pk_proto = PublicKeyProto {
            algorithm: AlgorithmIdProto::Groth20Bls12381 as i32,
            key_value: [42; groth20_bls12_381::FsEncryptionPublicKey::SIZE].to_vec(),
            version: 0,
            proof_data: Some(malformed_proof_data),
            timestamp: None,
        };
        let result = compute_dkg_dealing_encryption_key_id(&pk_proto);
        assert_matches!(
            result,
            Err(ExternalPublicKeyError(internal_error))
            if internal_error.contains("Malformed public key MalformedPop")
        );
    }

    #[test]
    fn should_fail_to_compute_tls_certificate_key_id_on_incorrect_algorithm_id() {
        let tls_certificate = X509PublicKeyCert {
            certificate_der: b"malformed certificate".to_vec(),
        };
        let result = compute_tls_certificate_key_id(&tls_certificate);
        assert_matches!(result,
        Err(ExternalPublicKeyError(internal_error)) if internal_error.contains("Malformed certificate: TlsPublicKeyCertCreationError"))
    }

    #[test]
    fn should_fail_to_compute_idkg_dealing_encryption_key_id_on_incorrect_algorithm_id() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let mut idkg_dealing_encryption_public_key = {
            let _ = generate_idkg_dealing_encryption_key_pair(&csp_vault);
            csp_vault
                .current_node_public_keys()
                .expect("Error getting current node public keys")
                .idkg_dealing_encryption_public_key
                .expect("iDKG dealing encryption public key missing")
        };
        idkg_dealing_encryption_public_key.algorithm = AlgorithmId::Groth20_Bls12_381 as i32;
        let result = compute_idkg_dealing_encryption_key_id(&idkg_dealing_encryption_public_key);
        assert_matches!(result,
        Err(ExternalPublicKeyError(internal_error)) if internal_error.contains("Malformed public key: unsupported algorithm"))
    }

    #[test]
    fn should_fail_if_committee_signing_key_missing_proof_data() {
        let pk_proto = PublicKeyProto {
            algorithm: AlgorithmIdProto::MultiBls12381 as i32,
            key_value: [42; 10].to_vec(),
            version: 1,
            proof_data: None,
            timestamp: None,
        };

        let result = compute_committee_signing_key_id(&pk_proto);
        assert_matches!(
            result,
            Err(ExternalPublicKeyError(error_string))
            if *error_string == "Malformed public key (Missing proof data)"
        );
    }

    #[test]
    fn should_fail_if_committee_signing_key_pop_is_malformed() {
        let malformed_proof_data = vec![
            42;
            ic_crypto_internal_multi_sig_bls12381::types::IndividualSignatureBytes::SIZE
                - 1
        ];
        let pk_proto = PublicKeyProto {
            algorithm: AlgorithmIdProto::MultiBls12381 as i32,
            key_value: [42; 10].to_vec(),
            version: 1,
            proof_data: Some(malformed_proof_data),
            timestamp: None,
        };

        let result = compute_committee_signing_key_id(&pk_proto);
        assert_matches!(
            result,
            Err(ExternalPublicKeyError(error_string))
            if *error_string == "Malformed public key (Malformed Pop)"
        );
    }
}

mod public_key_comparisons {
    use super::*;
    use crate::vault::api::LocalPublicKeyError;
    use crate::vault::local_csp_vault::public_and_secret_key_store::{
        compare_public_keys, LocalNodePublicKeyResults, LocalNodePublicKeys,
    };
    use crate::vault::test_utils::pks_and_sks::{
        convert_to_external_public_keys, generate_all_keys,
    };
    use assert_matches::assert_matches;
    use ic_types::crypto::CurrentNodePublicKeys;

    #[test]
    fn should_return_success_for_identical_registry_and_local_public_keys() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let current_node_public_keys = generate_all_keys(&csp_vault);
        let external_public_keys =
            convert_to_external_public_keys(current_node_public_keys.clone());
        let local_public_keys = convert_to_local_public_keys(current_node_public_keys);
        let results = compare_public_keys(&external_public_keys, &local_public_keys);
        assert!(results.is_ok());
    }

    #[test]
    fn should_fail_for_node_signing_public_keys_mismatch() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let current_node_public_keys = generate_all_keys(&csp_vault);
        let mut external_public_keys =
            convert_to_external_public_keys(current_node_public_keys.clone());
        external_public_keys.node_signing_public_key.key_value = b"malformed key".to_vec();
        let local_public_keys = convert_to_local_public_keys(current_node_public_keys);
        let results = compare_public_keys(&external_public_keys, &local_public_keys);
        assert_matches!(
            results,
            LocalNodePublicKeyResults {
                node_signing_public_key_result: Err(LocalPublicKeyError::Mismatch),
                committee_signing_public_key_result: Ok(()),
                tls_certificate_public_key_result: Ok(()),
                dkg_dealing_encryption_public_key_result: Ok(()),
                idkg_dealing_encryption_public_key_result: Ok(()),
            }
        );
    }

    #[test]
    fn should_fail_for_committee_signing_public_keys_mismatch() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let current_node_public_keys = generate_all_keys(&csp_vault);
        let mut external_public_keys =
            convert_to_external_public_keys(current_node_public_keys.clone());
        external_public_keys.committee_signing_public_key.key_value = b"malformed key".to_vec();
        let local_public_keys = convert_to_local_public_keys(current_node_public_keys);
        let results = compare_public_keys(&external_public_keys, &local_public_keys);
        assert_matches!(
            results,
            LocalNodePublicKeyResults {
                node_signing_public_key_result: Ok(()),
                committee_signing_public_key_result: Err(LocalPublicKeyError::Mismatch),
                tls_certificate_public_key_result: Ok(()),
                dkg_dealing_encryption_public_key_result: Ok(()),
                idkg_dealing_encryption_public_key_result: Ok(()),
            }
        );
    }

    #[test]
    fn should_fail_for_tls_certificate_mismatch() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let current_node_public_keys = generate_all_keys(&csp_vault);
        let mut external_public_keys =
            convert_to_external_public_keys(current_node_public_keys.clone());
        external_public_keys.tls_certificate.certificate_der = b"malformed certificate".to_vec();
        let local_public_keys = convert_to_local_public_keys(current_node_public_keys);
        let results = compare_public_keys(&external_public_keys, &local_public_keys);
        assert_matches!(
            results,
            LocalNodePublicKeyResults {
                node_signing_public_key_result: Ok(()),
                committee_signing_public_key_result: Ok(()),
                tls_certificate_public_key_result: Err(LocalPublicKeyError::Mismatch),
                dkg_dealing_encryption_public_key_result: Ok(()),
                idkg_dealing_encryption_public_key_result: Ok(()),
            }
        );
    }

    #[test]
    fn should_fail_for_dkg_dealing_encryption_public_keys_mismatch() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let current_node_public_keys = generate_all_keys(&csp_vault);
        let mut external_public_keys =
            convert_to_external_public_keys(current_node_public_keys.clone());
        external_public_keys
            .dkg_dealing_encryption_public_key
            .key_value = b"malformed key".to_vec();
        let local_public_keys = convert_to_local_public_keys(current_node_public_keys);
        let results = compare_public_keys(&external_public_keys, &local_public_keys);
        assert_matches!(
            results,
            LocalNodePublicKeyResults {
                node_signing_public_key_result: Ok(()),
                committee_signing_public_key_result: Ok(()),
                tls_certificate_public_key_result: Ok(()),
                dkg_dealing_encryption_public_key_result: Err(LocalPublicKeyError::Mismatch),
                idkg_dealing_encryption_public_key_result: Ok(()),
            }
        );
    }

    #[test]
    fn should_fail_for_idkg_dealing_encryption_public_keys_mismatch() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let current_node_public_keys = generate_all_keys(&csp_vault);
        let mut external_public_keys =
            convert_to_external_public_keys(current_node_public_keys.clone());
        external_public_keys
            .idkg_dealing_encryption_public_key
            .key_value = b"malformed key".to_vec();
        let local_public_keys = convert_to_local_public_keys(current_node_public_keys);
        let results = compare_public_keys(&external_public_keys, &local_public_keys);
        assert_matches!(
            results,
            LocalNodePublicKeyResults {
                node_signing_public_key_result: Ok(()),
                committee_signing_public_key_result: Ok(()),
                tls_certificate_public_key_result: Ok(()),
                dkg_dealing_encryption_public_key_result: Ok(()),
                idkg_dealing_encryption_public_key_result: Err(LocalPublicKeyError::Mismatch),
            }
        );
    }

    #[test]
    fn should_fail_for_missing_local_node_signing_public_key() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let current_node_public_keys = generate_all_keys(&csp_vault);
        let external_public_keys =
            convert_to_external_public_keys(current_node_public_keys.clone());
        let mut local_public_keys = convert_to_local_public_keys(current_node_public_keys);
        local_public_keys.node_signing_public_key = None;
        let results = compare_public_keys(&external_public_keys, &local_public_keys);
        assert_matches!(
            results,
            LocalNodePublicKeyResults {
                node_signing_public_key_result: Err(LocalPublicKeyError::NotFound),
                committee_signing_public_key_result: Ok(()),
                tls_certificate_public_key_result: Ok(()),
                dkg_dealing_encryption_public_key_result: Ok(()),
                idkg_dealing_encryption_public_key_result: Ok(()),
            }
        );
    }

    #[test]
    fn should_fail_for_missing_local_committee_signing_public_key() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let current_node_public_keys = generate_all_keys(&csp_vault);
        let external_public_keys =
            convert_to_external_public_keys(current_node_public_keys.clone());
        let mut local_public_keys = convert_to_local_public_keys(current_node_public_keys);
        local_public_keys.committee_signing_public_key = None;
        let results = compare_public_keys(&external_public_keys, &local_public_keys);
        assert_matches!(
            results,
            LocalNodePublicKeyResults {
                node_signing_public_key_result: Ok(()),
                committee_signing_public_key_result: Err(LocalPublicKeyError::NotFound),
                tls_certificate_public_key_result: Ok(()),
                dkg_dealing_encryption_public_key_result: Ok(()),
                idkg_dealing_encryption_public_key_result: Ok(()),
            }
        );
    }

    #[test]
    fn should_fail_for_missing_local_tls_certificate() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let current_node_public_keys = generate_all_keys(&csp_vault);
        let external_public_keys =
            convert_to_external_public_keys(current_node_public_keys.clone());
        let mut local_public_keys = convert_to_local_public_keys(current_node_public_keys);
        local_public_keys.tls_certificate = None;
        let results = compare_public_keys(&external_public_keys, &local_public_keys);
        assert_matches!(
            results,
            LocalNodePublicKeyResults {
                node_signing_public_key_result: Ok(()),
                committee_signing_public_key_result: Ok(()),
                tls_certificate_public_key_result: Err(LocalPublicKeyError::NotFound),
                dkg_dealing_encryption_public_key_result: Ok(()),
                idkg_dealing_encryption_public_key_result: Ok(()),
            }
        );
    }

    #[test]
    fn should_fail_for_missing_local_dkg_dealing_encryption_public_keys() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let current_node_public_keys = generate_all_keys(&csp_vault);
        let external_public_keys =
            convert_to_external_public_keys(current_node_public_keys.clone());
        let mut local_public_keys = convert_to_local_public_keys(current_node_public_keys);
        local_public_keys.dkg_dealing_encryption_public_key = None;
        let results = compare_public_keys(&external_public_keys, &local_public_keys);
        assert_matches!(
            results,
            LocalNodePublicKeyResults {
                node_signing_public_key_result: Ok(()),
                committee_signing_public_key_result: Ok(()),
                tls_certificate_public_key_result: Ok(()),
                dkg_dealing_encryption_public_key_result: Err(LocalPublicKeyError::NotFound),
                idkg_dealing_encryption_public_key_result: Ok(()),
            }
        );
    }

    #[test]
    fn should_fail_for_missing_local_idkg_dealing_encryption_public_keys() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let current_node_public_keys = generate_all_keys(&csp_vault);
        let external_public_keys =
            convert_to_external_public_keys(current_node_public_keys.clone());
        let mut local_public_keys = convert_to_local_public_keys(current_node_public_keys);
        local_public_keys.idkg_dealing_encryption_public_keys = vec![];
        let results = compare_public_keys(&external_public_keys, &local_public_keys);
        assert_matches!(
            results,
            LocalNodePublicKeyResults {
                node_signing_public_key_result: Ok(()),
                committee_signing_public_key_result: Ok(()),
                tls_certificate_public_key_result: Ok(()),
                dkg_dealing_encryption_public_key_result: Ok(()),
                idkg_dealing_encryption_public_key_result: Err(LocalPublicKeyError::NotFound),
            }
        );
    }

    fn convert_to_local_public_keys(
        current_node_public_keys: CurrentNodePublicKeys,
    ) -> LocalNodePublicKeys {
        LocalNodePublicKeys {
            node_signing_public_key: current_node_public_keys.node_signing_public_key,
            committee_signing_public_key: current_node_public_keys.committee_signing_public_key,
            tls_certificate: current_node_public_keys.tls_certificate,
            dkg_dealing_encryption_public_key: current_node_public_keys
                .dkg_dealing_encryption_public_key,
            idkg_dealing_encryption_public_keys: current_node_public_keys
                .idkg_dealing_encryption_public_key
                .map_or(vec![], |public_key| vec![public_key]),
        }
    }
}

mod pks_and_sks_contains {
    use super::*;
    use crate::vault::api::PublicAndSecretKeyStoreCspVault;
    use crate::vault::api::PublicKeyStoreCspVault;
    use crate::vault::api::{
        BasicSignatureCspVault, ExternalPublicKeyError, LocalPublicKeyError,
        MultiSignatureCspVault, NiDkgCspVault, NodeKeysError, NodeKeysErrors,
        PksAndSksContainsErrors, SecretKeyError, TlsHandshakeCspVault,
    };
    use crate::vault::test_utils::pks_and_sks::convert_to_external_public_keys;
    use crate::vault::test_utils::pks_and_sks::generate_all_keys;
    use crate::vault::test_utils::pks_and_sks::generate_idkg_dealing_encryption_key_pair;
    use crate::vault::test_utils::pks_and_sks::NODE_1;
    use assert_matches::assert_matches;
    use ic_types_test_utils::ids::node_test_id;

    #[test]
    fn should_return_success_for_pks_and_sks_contains_if_all_keys_match_with_one_idkg_key() {
        let csp_vault = LocalCspVault::builder_for_test().build();

        let current_node_public_keys = generate_all_keys(&csp_vault);

        assert!(csp_vault
            .pks_and_sks_contains(convert_to_external_public_keys(current_node_public_keys))
            .is_ok());
    }

    #[test]
    fn should_return_success_for_pks_and_sks_contains_if_all_keys_match_with_multiple_idkg_keys() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let current_node_public_keys = generate_all_keys(&csp_vault);
        let _second_idkg_pk = generate_idkg_dealing_encryption_key_pair(&csp_vault);
        let _third_idkg_pk = generate_idkg_dealing_encryption_key_pair(&csp_vault);

        assert!(csp_vault
            .pks_and_sks_contains(convert_to_external_public_keys(current_node_public_keys))
            .is_ok());
    }

    #[test]
    fn should_return_success_for_pks_and_sks_contains_if_all_keys_match_with_multiple_idkg_keys_and_external_key_not_first_in_vector(
    ) {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let _initial_node_public_keys = generate_all_keys(&csp_vault);
        let _second_idkg_pk = generate_idkg_dealing_encryption_key_pair(&csp_vault);
        let current_node_public_keys = csp_vault
            .current_node_public_keys()
            .expect("Failed to get current node public keys");
        let _third_idkg_pk = generate_idkg_dealing_encryption_key_pair(&csp_vault);

        assert!(csp_vault
            .pks_and_sks_contains(convert_to_external_public_keys(current_node_public_keys))
            .is_ok());
    }

    #[test]
    fn should_return_success_for_pks_and_sks_contains_if_all_keys_match_where_idkg_keys_have_different_timestamps(
    ) {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let _current_node_public_keys = generate_all_keys(&csp_vault);
        let mut external_public_keys = convert_to_external_public_keys(
            csp_vault
                .current_node_public_keys_with_timestamps()
                .expect("error getting current node public keys with timestamp"),
        );
        external_public_keys
            .idkg_dealing_encryption_public_key
            .timestamp = external_public_keys
            .idkg_dealing_encryption_public_key
            .timestamp
            .expect("timestamp of generated iDKG dealing encryption key is none")
            .checked_add(42);

        assert!(csp_vault.pks_and_sks_contains(external_public_keys).is_ok());
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_no_keys_match() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let shadow_csp_vault = LocalCspVault::builder_for_test().build();
        let _current_node_public_keys = generate_all_keys(&csp_vault);
        let shadow_node_public_keys = generate_all_keys(&shadow_csp_vault);

        let result = csp_vault
            .pks_and_sks_contains(convert_to_external_public_keys(shadow_node_public_keys));

        assert_matches!(
            result,
            Err(PksAndSksContainsErrors::NodeKeysErrors(NodeKeysErrors {
                node_signing_key_error: Some(NodeKeysError {
                    external_public_key_error: None,
                    local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                    secret_key_error: Some(SecretKeyError::NotFound),
                }),
                committee_signing_key_error: Some(NodeKeysError {
                    external_public_key_error: None,
                    local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                    secret_key_error: Some(SecretKeyError::NotFound),
                }),
                tls_certificate_error: Some(NodeKeysError {
                    external_public_key_error: None,
                    local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                    secret_key_error: Some(SecretKeyError::NotFound),
                }),
                dkg_dealing_encryption_key_error: Some(NodeKeysError {
                    external_public_key_error: None,
                    local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                    secret_key_error: Some(SecretKeyError::NotFound),
                }),
                idkg_dealing_encryption_key_error: Some(NodeKeysError {
                    external_public_key_error: None,
                    local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                    secret_key_error: Some(SecretKeyError::NotFound),
                }),
            }))
        );
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_node_signing_key_does_not_match() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let shadow_csp_vault = LocalCspVault::builder_for_test().build();
        let mut current_node_public_keys = generate_all_keys(&csp_vault);
        current_node_public_keys.node_signing_public_key = {
            let _ = shadow_csp_vault
                .gen_node_signing_key_pair()
                .expect("Failed to generate node signing key pair");
            shadow_csp_vault
                .current_node_public_keys()
                .expect("Failed to get current node public keys")
                .node_signing_public_key
        };

        let result = csp_vault
            .pks_and_sks_contains(convert_to_external_public_keys(current_node_public_keys));

        assert_matches!(
            result,
            Err(PksAndSksContainsErrors::NodeKeysErrors(NodeKeysErrors {
                node_signing_key_error: Some(NodeKeysError {
                    external_public_key_error: None,
                    local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                    secret_key_error: Some(SecretKeyError::NotFound),
                }),
                committee_signing_key_error: None,
                tls_certificate_error: None,
                dkg_dealing_encryption_key_error: None,
                idkg_dealing_encryption_key_error: None,
            }))
        );
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_committee_signing_key_does_not_match() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let shadow_csp_vault = LocalCspVault::builder_for_test().build();
        let mut current_node_public_keys = generate_all_keys(&csp_vault);
        current_node_public_keys.committee_signing_public_key = {
            let _ = shadow_csp_vault
                .gen_committee_signing_key_pair()
                .expect("Failed to generate committee signing key pair");
            shadow_csp_vault
                .current_node_public_keys()
                .expect("Failed to get current node public keys")
                .committee_signing_public_key
        };

        let result = csp_vault
            .pks_and_sks_contains(convert_to_external_public_keys(current_node_public_keys));

        assert_matches!(
            result,
            Err(PksAndSksContainsErrors::NodeKeysErrors(NodeKeysErrors {
                node_signing_key_error: None,
                committee_signing_key_error: Some(NodeKeysError {
                    external_public_key_error: None,
                    local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                    secret_key_error: Some(SecretKeyError::NotFound),
                }),
                tls_certificate_error: None,
                dkg_dealing_encryption_key_error: None,
                idkg_dealing_encryption_key_error: None,
            }))
        );
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_dkg_dealing_encryption_key_does_not_match() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let shadow_csp_vault = LocalCspVault::builder_for_test().build();
        let mut current_node_public_keys = generate_all_keys(&csp_vault);
        current_node_public_keys.dkg_dealing_encryption_public_key = {
            let _ = shadow_csp_vault
                .gen_dealing_encryption_key_pair(node_test_id(NODE_1))
                .expect("Failed to generate dkg dealing encryption signing key pair");
            shadow_csp_vault
                .current_node_public_keys()
                .expect("Failed to get current node public keys")
                .dkg_dealing_encryption_public_key
        };

        let result = csp_vault
            .pks_and_sks_contains(convert_to_external_public_keys(current_node_public_keys));

        assert_matches!(
            result,
            Err(PksAndSksContainsErrors::NodeKeysErrors(NodeKeysErrors {
                node_signing_key_error: None,
                committee_signing_key_error: None,
                tls_certificate_error: None,
                dkg_dealing_encryption_key_error: Some(NodeKeysError {
                    external_public_key_error: None,
                    local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                    secret_key_error: Some(SecretKeyError::NotFound),
                }),
                idkg_dealing_encryption_key_error: None,
            }))
        );
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_tls_certificate_does_not_match() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let shadow_csp_vault = LocalCspVault::builder_for_test().build();
        let mut current_node_public_keys = generate_all_keys(&csp_vault);
        current_node_public_keys.tls_certificate = {
            let _ = shadow_csp_vault
                .gen_tls_key_pair(node_test_id(NODE_1))
                .expect("Failed to generate tks certificate");
            shadow_csp_vault
                .current_node_public_keys()
                .expect("Failed to get current node public keys")
                .tls_certificate
        };

        let result = csp_vault
            .pks_and_sks_contains(convert_to_external_public_keys(current_node_public_keys));

        assert_matches!(
            result,
            Err(PksAndSksContainsErrors::NodeKeysErrors(NodeKeysErrors {
                node_signing_key_error: None,
                committee_signing_key_error: None,
                tls_certificate_error: Some(NodeKeysError {
                    external_public_key_error: None,
                    local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                    secret_key_error: Some(SecretKeyError::NotFound),
                }),
                dkg_dealing_encryption_key_error: None,
                idkg_dealing_encryption_key_error: None,
            }))
        );
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_idkg_dealing_encryption_key_does_not_match()
    {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let shadow_csp_vault = LocalCspVault::builder_for_test().build();
        let mut current_node_public_keys = generate_all_keys(&csp_vault);
        current_node_public_keys.idkg_dealing_encryption_public_key = {
            let _ = generate_idkg_dealing_encryption_key_pair(&shadow_csp_vault);
            shadow_csp_vault
                .current_node_public_keys()
                .expect("Failed to get current node public keys")
                .idkg_dealing_encryption_public_key
        };

        let result = csp_vault
            .pks_and_sks_contains(convert_to_external_public_keys(current_node_public_keys));

        assert_matches!(
            result,
            Err(PksAndSksContainsErrors::NodeKeysErrors(NodeKeysErrors {
                node_signing_key_error: None,
                committee_signing_key_error: None,
                tls_certificate_error: None,
                dkg_dealing_encryption_key_error: None,
                idkg_dealing_encryption_key_error: Some(NodeKeysError {
                    external_public_key_error: None,
                    local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                    secret_key_error: Some(SecretKeyError::NotFound),
                }),
            }))
        );
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_external_node_signing_key_is_malformed() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let mut current_node_public_keys = generate_all_keys(&csp_vault);
        if let Some(node_signing_public_key) = &mut current_node_public_keys.node_signing_public_key
        {
            node_signing_public_key.key_value = b"malformed key".to_vec();
        } else {
            panic!("Node signing key missing");
        }

        let result = csp_vault
            .pks_and_sks_contains(convert_to_external_public_keys(current_node_public_keys));

        assert_matches!(
            result,
            Err(PksAndSksContainsErrors::NodeKeysErrors(NodeKeysErrors {
                node_signing_key_error: Some(NodeKeysError {
                    external_public_key_error: Some(ExternalPublicKeyError(malformed_error)),
                    local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                    secret_key_error: Some(SecretKeyError::CannotComputeKeyId),
                }),
                committee_signing_key_error: None,
                tls_certificate_error: None,
                dkg_dealing_encryption_key_error: None,
                idkg_dealing_encryption_key_error: None,
            })) if malformed_error.contains("Malformed Ed25519 public key")
        );
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_external_committee_signing_key_is_malformed()
    {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let mut current_node_public_keys = generate_all_keys(&csp_vault);
        if let Some(committee_signing_public_key) =
            &mut current_node_public_keys.committee_signing_public_key
        {
            committee_signing_public_key.key_value = b"malformed key".to_vec();
        } else {
            panic!("Committee signing key missing");
        }

        let result = csp_vault
            .pks_and_sks_contains(convert_to_external_public_keys(current_node_public_keys));

        assert_matches!(
            result,
            Err(PksAndSksContainsErrors::NodeKeysErrors(NodeKeysErrors {
                node_signing_key_error: None,
                committee_signing_key_error: Some(NodeKeysError {
                    external_public_key_error: Some(ExternalPublicKeyError(malformed_error)),
                    local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                    secret_key_error: Some(SecretKeyError::CannotComputeKeyId),
                }),
                tls_certificate_error: None,
                dkg_dealing_encryption_key_error: None,
                idkg_dealing_encryption_key_error: None,
            })) if malformed_error.contains("Malformed MultiBls12_381 public key")
        );
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_external_dkg_dealing_encryption_key_is_malformed(
    ) {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let mut current_node_public_keys = generate_all_keys(&csp_vault);
        if let Some(dkg_dealing_encryption_public_key) =
            &mut current_node_public_keys.dkg_dealing_encryption_public_key
        {
            dkg_dealing_encryption_public_key.key_value = b"malformed key".to_vec();
        } else {
            panic!("DKG dealing encryption key missing");
        }

        let result = csp_vault
            .pks_and_sks_contains(convert_to_external_public_keys(current_node_public_keys));

        assert_matches!(
            result,
            Err(PksAndSksContainsErrors::NodeKeysErrors(NodeKeysErrors {
                node_signing_key_error: None,
                committee_signing_key_error: None,
                tls_certificate_error: None,
                dkg_dealing_encryption_key_error: Some(NodeKeysError {
                    external_public_key_error: Some(ExternalPublicKeyError(malformed_error)),
                    local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                    secret_key_error: Some(SecretKeyError::CannotComputeKeyId),
                }),
                idkg_dealing_encryption_key_error: None,
            })) if malformed_error.contains("Malformed public key")
        );
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_external_tls_certificate_is_malformed() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let mut current_node_public_keys = generate_all_keys(&csp_vault);
        if let Some(tls_certificate) = &mut current_node_public_keys.tls_certificate {
            tls_certificate.certificate_der = b"malformed certificate".to_vec();
        } else {
            panic!("TLS certificate missing");
        }

        let result = csp_vault
            .pks_and_sks_contains(convert_to_external_public_keys(current_node_public_keys));

        assert_matches!(
            result,
            Err(PksAndSksContainsErrors::NodeKeysErrors(NodeKeysErrors {
                node_signing_key_error: None,
                committee_signing_key_error: None,
                tls_certificate_error: Some(NodeKeysError {
                    external_public_key_error: Some(ExternalPublicKeyError(malformed_error)),
                    local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                    secret_key_error: Some(SecretKeyError::CannotComputeKeyId),
                }),
                dkg_dealing_encryption_key_error: None,
                idkg_dealing_encryption_key_error: None,
            })) if malformed_error.contains("Malformed certificate: TlsPublicKeyCertCreationError")
        );
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_external_idkg_dealing_encryption_key_is_malformed(
    ) {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let mut current_node_public_keys = generate_all_keys(&csp_vault);
        if let Some(idkg_dealing_encryption_public_key) =
            &mut current_node_public_keys.idkg_dealing_encryption_public_key
        {
            idkg_dealing_encryption_public_key.key_value = b"malformed key".to_vec();
        } else {
            panic!("iDKG dealing encryption key missing");
        }

        let result = csp_vault
            .pks_and_sks_contains(convert_to_external_public_keys(current_node_public_keys));

        assert_matches!(
            result,
            Err(PksAndSksContainsErrors::NodeKeysErrors(NodeKeysErrors {
                node_signing_key_error: None,
                committee_signing_key_error: None,
                tls_certificate_error: None,
                dkg_dealing_encryption_key_error: None,
                idkg_dealing_encryption_key_error: Some(NodeKeysError {
                    external_public_key_error: Some(ExternalPublicKeyError(malformed_error)),
                    local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                    secret_key_error: Some(SecretKeyError::CannotComputeKeyId),
                }),
            })) if malformed_error.contains("Malformed public key: I-DKG dealing encryption key malformed")
        );
    }
}

mod validate_pks_and_sks {
    use crate::key_id::KeyId;
    use crate::keygen::utils::mega_public_key_from_proto;
    use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
    use crate::public_key_store::PublicKeyStore;
    use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
    use crate::secret_key_store::SecretKeyStore;
    use crate::types::CspPublicKey;
    use crate::vault::api::ValidatePksAndSksKeyPairError::{
        PublicKeyInvalid, PublicKeyNotFound, SecretKeyNotFound,
    };
    use crate::vault::api::{PublicAndSecretKeyStoreCspVault, ValidatePksAndSksError};
    use crate::vault::local_csp_vault::public_and_secret_key_store::LocalNodePublicKeys;
    use crate::LocalCspVault;
    use assert_matches::assert_matches;
    use ic_crypto_internal_types::encrypt::forward_secure::CspFsEncryptionPublicKey;
    use ic_crypto_test_utils_keys::public_keys::{
        valid_committee_signing_public_key, valid_dkg_dealing_encryption_public_key,
        valid_idkg_dealing_encryption_public_key, valid_idkg_dealing_encryption_public_key_2,
        valid_idkg_dealing_encryption_public_key_3, valid_node_signing_public_key,
        valid_tls_certificate_and_validation_time,
    };
    use ic_crypto_tls_interfaces::TlsPublicKeyCert;
    use ic_protobuf::registry::crypto::v1::{PublicKey, X509PublicKeyCert};
    use ic_test_utilities_time::FastForwardTimeSource;
    use ic_types::time::Time;
    use std::collections::HashSet;
    use std::sync::Arc;

    #[test]
    fn should_return_empty_public_key_store_when_no_keys() {
        let vault = LocalCspVault::builder_for_test().build();
        let result = vault.validate_pks_and_sks();
        assert_matches!(result, Err(ValidatePksAndSksError::EmptyPublicKeyStore))
    }

    #[test]
    fn should_return_public_key_not_found() {
        let tests = vec![
            ParameterizedTest {
                input: LocalNodePublicKeys {
                    node_signing_public_key: None,
                    ..required_node_public_keys_and_time().0
                },
                expected: ValidatePksAndSksError::NodeSigningKeyError(PublicKeyNotFound),
            },
            ParameterizedTest {
                input: LocalNodePublicKeys {
                    committee_signing_public_key: None,
                    ..required_node_public_keys_and_time().0
                },
                expected: ValidatePksAndSksError::CommitteeSigningKeyError(PublicKeyNotFound),
            },
            ParameterizedTest {
                input: LocalNodePublicKeys {
                    tls_certificate: None,
                    ..required_node_public_keys_and_time().0
                },
                expected: ValidatePksAndSksError::TlsCertificateError(PublicKeyNotFound),
            },
            ParameterizedTest {
                input: LocalNodePublicKeys {
                    dkg_dealing_encryption_public_key: None,
                    ..required_node_public_keys_and_time().0
                },
                expected: ValidatePksAndSksError::DkgDealingEncryptionKeyError(PublicKeyNotFound),
            },
            ParameterizedTest {
                input: LocalNodePublicKeys {
                    idkg_dealing_encryption_public_keys: vec![],
                    ..required_node_public_keys_and_time().0
                },
                expected: ValidatePksAndSksError::IdkgDealingEncryptionKeyError(PublicKeyNotFound),
            },
        ];

        for test in tests {
            let vault = LocalCspVault::builder_for_test()
                .with_mock_stores()
                .with_public_key_store(public_key_store_containing_exactly(test.input))
                .build();

            let result = vault.validate_pks_and_sks();

            assert_matches!(result, Err(error) if error == test.expected, "where expected error {:?}", &test.expected)
        }
    }

    #[test]
    fn should_return_public_key_invalid_when_validating_public_key() {
        let tests = vec![
            ParameterizedTest {
                input: LocalNodePublicKeys {
                    node_signing_public_key: Some(invalid_node_signing_public_key()),
                    ..required_node_public_keys_and_time().0
                },
                expected: ValidatePksAndSksError::NodeSigningKeyError(PublicKeyInvalid(
                    "invalid node signing key: verification failed".to_string(),
                )),
            },
            ParameterizedTest {
                input: LocalNodePublicKeys {
                    committee_signing_public_key: Some(invalid_committee_signing_public_key()),
                    ..required_node_public_keys_and_time().0
                },
                expected: ValidatePksAndSksError::CommitteeSigningKeyError(PublicKeyInvalid(
                    "invalid committee signing key: Malformed MultiBls12_381 public key"
                        .to_string(),
                )),
            },
            ParameterizedTest {
                input: LocalNodePublicKeys {
                    tls_certificate: Some(tls_certificate_with_invalid_not_before_time()),
                    ..required_node_public_keys_and_time().0
                },
                expected: ValidatePksAndSksError::TlsCertificateError(PublicKeyInvalid(
                    "Malformed certificate: TlsPublicKeyCertCreationError(\"Error parsing DER: Parsing Error: InvalidDate\"".to_string(),
                )),
            },
            ParameterizedTest {
                input: LocalNodePublicKeys {
                    dkg_dealing_encryption_public_key: Some(invalid_dkg_dealing_encryption_key()),
                    ..required_node_public_keys_and_time().0
                },
                expected: ValidatePksAndSksError::DkgDealingEncryptionKeyError(PublicKeyInvalid(
                    "invalid DKG dealing encryption key: verification failed".to_string(),
                )),
            },
            // No `ParameterizedTest` for the iDKG dealing encryption key, since the same checks
            // are performed for computing the `KeyId` as in `RequiredNodePublicKeys::validate()`.
            // Therefore, there is no way to produce an invalid iDKG dealing encryption key that
            // passes the first check, but fails the second.
        ];

        let time_source = FastForwardTimeSource::new();
        time_source
            .set_time(required_node_public_keys_and_time().1)
            .expect("failed to set time");

        for test in tests {
            let mut sks = MockSecretKeyStore::new();

            sks.expect_contains().return_const(true);
            let vault = LocalCspVault::builder_for_test()
                .with_mock_stores()
                .with_public_key_store(public_key_store_containing_exactly(test.input))
                .with_node_secret_key_store(sks)
                .with_time_source(Arc::clone(&time_source) as Arc<_>)
                .build();

            let result = vault.validate_pks_and_sks();

            assert_matches!((result, test.expected),
                (Err(ValidatePksAndSksError::NodeSigningKeyError(PublicKeyInvalid(actual))),
                    ValidatePksAndSksError::NodeSigningKeyError(PublicKeyInvalid(expected)),
                )
                | (Err(ValidatePksAndSksError::CommitteeSigningKeyError(PublicKeyInvalid(actual))),
                    ValidatePksAndSksError::CommitteeSigningKeyError(PublicKeyInvalid(expected)),
                )
                | (Err(ValidatePksAndSksError::TlsCertificateError(PublicKeyInvalid(actual))),
                    ValidatePksAndSksError::TlsCertificateError(PublicKeyInvalid(expected)),
                )
                | (Err(ValidatePksAndSksError::DkgDealingEncryptionKeyError(PublicKeyInvalid(actual))),
                    ValidatePksAndSksError::DkgDealingEncryptionKeyError(PublicKeyInvalid(expected)),
                )
                if actual.starts_with(&expected)
            );
        }
    }

    #[test]
    fn should_return_public_key_invalid_when_computing_key_id() {
        let tests = vec![
            ParameterizedTest {
                input: LocalNodePublicKeys {
                    node_signing_public_key: Some(invalid_public_key()),
                    ..required_node_public_keys_and_time().0
                },
                expected: ValidatePksAndSksError::NodeSigningKeyError(PublicKeyInvalid(
                    "expected public key algorithm Ed25519".to_string(),
                )),
            },
            ParameterizedTest {
                input: LocalNodePublicKeys {
                    committee_signing_public_key: Some(invalid_public_key()),
                    ..required_node_public_keys_and_time().0
                },
                expected: ValidatePksAndSksError::CommitteeSigningKeyError(PublicKeyInvalid(
                    "expected public key algorithm MultiBls12_381".to_string(),
                )),
            },
            ParameterizedTest {
                input: LocalNodePublicKeys {
                    tls_certificate: Some(invalid_tls_certificate()),
                    ..required_node_public_keys_and_time().0
                },
                expected: ValidatePksAndSksError::TlsCertificateError(PublicKeyInvalid(
                    "Malformed certificate".to_string(),
                )),
            },
            ParameterizedTest {
                input: LocalNodePublicKeys {
                    dkg_dealing_encryption_public_key: Some(invalid_public_key()),
                    ..required_node_public_keys_and_time().0
                },
                expected: ValidatePksAndSksError::DkgDealingEncryptionKeyError(PublicKeyInvalid(
                    "Malformed public key: Expected public key algorithm Groth20_Bls12_381"
                        .to_string(),
                )),
            },
            ParameterizedTest {
                input: LocalNodePublicKeys {
                    idkg_dealing_encryption_public_keys: vec![invalid_public_key()],
                    ..required_node_public_keys_and_time().0
                },
                expected: ValidatePksAndSksError::IdkgDealingEncryptionKeyError(PublicKeyInvalid(
                    "Malformed public key: unsupported algorithm".to_string(),
                )),
            },
        ];

        for test in tests {
            let vault = LocalCspVault::builder_for_test()
                .with_mock_stores()
                .with_public_key_store(public_key_store_containing_exactly(test.input))
                .build();

            let result = vault.validate_pks_and_sks();

            assert_matches!((result, test.expected),
                (Err(ValidatePksAndSksError::NodeSigningKeyError(PublicKeyInvalid(actual))),
                    ValidatePksAndSksError::NodeSigningKeyError(PublicKeyInvalid(expected)),
                )
                | (Err(ValidatePksAndSksError::CommitteeSigningKeyError(PublicKeyInvalid(actual))),
                    ValidatePksAndSksError::CommitteeSigningKeyError(PublicKeyInvalid(expected)),
                )
                | (Err(ValidatePksAndSksError::TlsCertificateError(PublicKeyInvalid(actual))),
                    ValidatePksAndSksError::TlsCertificateError(PublicKeyInvalid(expected)),
                )
                | (Err(ValidatePksAndSksError::DkgDealingEncryptionKeyError(PublicKeyInvalid(actual))),
                    ValidatePksAndSksError::DkgDealingEncryptionKeyError(PublicKeyInvalid(expected)),
                )
                | (Err(ValidatePksAndSksError::IdkgDealingEncryptionKeyError(PublicKeyInvalid(actual))),
                    ValidatePksAndSksError::IdkgDealingEncryptionKeyError(PublicKeyInvalid(expected)),
                )
                if actual.starts_with(&expected)
            );
        }
    }

    #[test]
    fn should_return_public_key_invalid_when_a_single_idkg_public_key_is_invalid() {
        let vault = LocalCspVault::builder_for_test()
            .with_mock_stores()
            .with_public_key_store(public_key_store_containing_exactly(LocalNodePublicKeys {
                idkg_dealing_encryption_public_keys: vec![
                    valid_idkg_dealing_encryption_public_key(),
                    invalid_public_key(),
                    valid_idkg_dealing_encryption_public_key_2(),
                ],
                ..required_node_public_keys_and_time().0
            }))
            .build();

        let result = vault.validate_pks_and_sks();

        assert_matches!(
            result,
            Err(ValidatePksAndSksError::IdkgDealingEncryptionKeyError(
                PublicKeyInvalid(_)
            ))
        )
    }

    #[test]
    fn should_return_secret_key_not_found() {
        let (required_public_keys, _validation_time, required_key_ids) =
            required_node_public_keys_and_their_key_ids();

        let tests = vec![
            ParameterizedTest {
                input: LocalKeyIds {
                    node_signing_key_id: None,
                    ..required_key_ids.clone()
                },
                expected: ValidatePksAndSksError::NodeSigningKeyError(SecretKeyNotFound {
                    key_id: node_signing_secret_key_id().to_string(),
                }),
            },
            ParameterizedTest {
                input: LocalKeyIds {
                    committee_signing_key_id: None,
                    ..required_key_ids.clone()
                },
                expected: ValidatePksAndSksError::CommitteeSigningKeyError(SecretKeyNotFound {
                    key_id: committee_signing_secret_key_id().to_string(),
                }),
            },
            ParameterizedTest {
                input: LocalKeyIds {
                    tls_secret_key_id: None,
                    ..required_key_ids.clone()
                },
                expected: ValidatePksAndSksError::TlsCertificateError(SecretKeyNotFound {
                    key_id: tls_certificate_key_id().to_string(),
                }),
            },
            ParameterizedTest {
                input: LocalKeyIds {
                    dkg_dealing_encryption_key_id: None,
                    ..required_key_ids.clone()
                },
                expected: ValidatePksAndSksError::DkgDealingEncryptionKeyError(SecretKeyNotFound {
                    key_id: dkg_dealing_encryption_key_id().to_string(),
                }),
            },
            ParameterizedTest {
                input: LocalKeyIds {
                    idkg_dealing_encryption_key_ids: vec![],
                    ..required_key_ids
                },
                expected: ValidatePksAndSksError::IdkgDealingEncryptionKeyError(
                    SecretKeyNotFound {
                        key_id: idkg_dealing_encryption_key_id().to_string(),
                    },
                ),
            },
        ];

        for test in tests {
            let vault = LocalCspVault::builder_for_test()
                .with_mock_stores()
                .with_public_key_store(public_key_store_containing_exactly(
                    required_public_keys.clone(),
                ))
                .with_node_secret_key_store(secret_key_store_containing_exactly(test.input))
                .build();

            let result = vault.validate_pks_and_sks();

            assert_matches!(result, Err(error) if error == test.expected, "where expected error {:?}", &test.expected)
        }
    }

    #[test]
    fn should_return_secret_key_not_found_when_single_idkg_secret_key_missing() {
        let idkg_pk_1 = valid_idkg_dealing_encryption_public_key();
        let idkg_pk_with_no_secret_key = valid_idkg_dealing_encryption_public_key_2();
        let idkg_pk_3 = valid_idkg_dealing_encryption_public_key_3();
        let idkg_key_id_1 = idkg_dealing_encryption_key_id_from(&idkg_pk_1);
        let idkg_missing_key_id = idkg_dealing_encryption_key_id_from(&idkg_pk_with_no_secret_key);
        let idkg_key_id_3 = idkg_dealing_encryption_key_id_from(&idkg_pk_3);
        let vault = LocalCspVault::builder_for_test()
            .with_mock_stores()
            .with_public_key_store(public_key_store_containing_exactly(LocalNodePublicKeys {
                idkg_dealing_encryption_public_keys: vec![
                    idkg_pk_1,
                    idkg_pk_with_no_secret_key,
                    idkg_pk_3,
                ],
                ..required_node_public_keys_and_time().0
            }))
            .with_node_secret_key_store(secret_key_store_containing_exactly(LocalKeyIds {
                idkg_dealing_encryption_key_ids: vec![idkg_key_id_1, idkg_key_id_3],
                ..required_key_ids()
            }))
            .build();

        let result = vault.validate_pks_and_sks();

        assert_matches!(result, Err(ValidatePksAndSksError::IdkgDealingEncryptionKeyError(SecretKeyNotFound {key_id}))
            if key_id == idkg_missing_key_id.to_string());
    }

    #[test]
    fn should_return_tls_certificate_pk_invalid_when_tls_certificate_is_not_yet_valid() {
        use crate::vault::api::ValidatePksAndSksKeyPairError;
        use core::time::Duration;
        use ic_crypto_node_key_validation::ValidNodePublicKeys;

        let (required_node_public_keys, valid_time) = required_node_public_keys_and_time();

        fn test_impl(
            required_node_public_keys: LocalNodePublicKeys,
            time: Time,
        ) -> Result<ValidNodePublicKeys, ValidatePksAndSksError> {
            let time_source = FastForwardTimeSource::new();
            time_source.set_time(time).expect("failed to set time");

            let mut sks = MockSecretKeyStore::new();
            sks.expect_contains().return_const(true);

            let vault = LocalCspVault::builder_for_test()
                .with_mock_stores()
                .with_public_key_store(public_key_store_containing_exactly(
                    required_node_public_keys,
                ))
                .with_node_secret_key_store(sks)
                .with_time_source(Arc::clone(&time_source) as Arc<_>)
                .build();

            vault.validate_pks_and_sks()
        }

        // validating with correct validation time works
        let result = test_impl(required_node_public_keys.clone(), valid_time);
        assert_matches!(result, Ok(_));

        // validating with time one second earlier than `not_before` doesn't
        // work
        let one_sec_too_early_validation_time = valid_time
            .checked_sub(Duration::from_secs(1))
            .expect("failed to compute too early validation time");
        let result = test_impl(required_node_public_keys, one_sec_too_early_validation_time);

        assert_matches!(
            result,
            Err(ValidatePksAndSksError::TlsCertificateError(ValidatePksAndSksKeyPairError::PublicKeyInvalid(e))) if
                e.contains("invalid TLS certificate: notBefore date") &&
                e.contains("is in the future compared to current time")
        );
    }

    #[test]
    fn should_return_valid_node_public_keys() {
        let (required_public_keys, validation_time, required_key_ids) =
            required_node_public_keys_and_their_key_ids();

        let time_source = FastForwardTimeSource::new();
        time_source
            .set_time(validation_time)
            .expect("failed to set time");

        let vault = LocalCspVault::builder_for_test()
            .with_mock_stores()
            .with_public_key_store(public_key_store_containing_exactly(
                required_public_keys.clone(),
            ))
            .with_node_secret_key_store(secret_key_store_containing_exactly(required_key_ids))
            .with_time_source(time_source)
            .build();

        let result = vault.validate_pks_and_sks();

        assert_matches!(result, Ok(public_keys)
            if public_keys.node_signing_key() == &required_public_keys.node_signing_public_key.unwrap()
            && public_keys.committee_signing_key() == &required_public_keys.committee_signing_public_key.unwrap()
            && public_keys.tls_certificate() == &required_public_keys.tls_certificate.unwrap()
            && public_keys.dkg_dealing_encryption_key() == &required_public_keys.dkg_dealing_encryption_public_key.unwrap()
            && public_keys.idkg_dealing_encryption_key() == &required_public_keys.idkg_dealing_encryption_public_keys[0]
        )
    }

    #[test]
    fn should_return_valid_node_public_keys_with_last_idkg_public_key() {
        let idkg_pk_1 = valid_idkg_dealing_encryption_public_key();
        let idkg_pk_2 = valid_idkg_dealing_encryption_public_key_2();
        let idkg_pk_3 = valid_idkg_dealing_encryption_public_key_3();
        let idkg_key_id_1 = idkg_dealing_encryption_key_id_from(&idkg_pk_1);
        let idkg_key_id_2 = idkg_dealing_encryption_key_id_from(&idkg_pk_2);
        let idkg_key_id_3 = idkg_dealing_encryption_key_id_from(&idkg_pk_3);

        let (node_public_keys, validation_time) = required_node_public_keys_and_time();

        let time_source = FastForwardTimeSource::new();
        time_source
            .set_time(validation_time)
            .expect("failed to set time");

        let vault = LocalCspVault::builder_for_test()
            .with_mock_stores()
            .with_public_key_store(public_key_store_containing_exactly(LocalNodePublicKeys {
                idkg_dealing_encryption_public_keys: vec![idkg_pk_1, idkg_pk_2, idkg_pk_3.clone()],
                ..node_public_keys
            }))
            .with_node_secret_key_store(secret_key_store_containing_exactly(LocalKeyIds {
                idkg_dealing_encryption_key_ids: vec![idkg_key_id_1, idkg_key_id_2, idkg_key_id_3],
                ..required_key_ids()
            }))
            .with_time_source(time_source)
            .build();

        let result = vault.validate_pks_and_sks();

        assert_matches!(result, Ok(public_keys)
            if public_keys.node_signing_key() == &valid_node_signing_public_key()
            && public_keys.committee_signing_key() == & valid_committee_signing_public_key()
            && public_keys.tls_certificate() == & valid_tls_certificate_and_validation_time().0
            && public_keys.dkg_dealing_encryption_key() == & valid_dkg_dealing_encryption_public_key()
            && public_keys.idkg_dealing_encryption_key() == & idkg_pk_3
        )
    }

    #[derive(Debug)]
    struct ParameterizedTest<U, V> {
        input: U,
        expected: V,
    }

    fn public_key_store_containing_exactly(
        public_keys: LocalNodePublicKeys,
    ) -> impl PublicKeyStore {
        let mut public_key_store = MockPublicKeyStore::new();
        public_key_store
            .expect_node_signing_pubkey()
            .times(1)
            .return_const(public_keys.node_signing_public_key);
        public_key_store
            .expect_committee_signing_pubkey()
            .times(1)
            .return_const(public_keys.committee_signing_public_key);
        public_key_store
            .expect_tls_certificate()
            .times(1)
            .return_const(public_keys.tls_certificate);
        public_key_store
            .expect_ni_dkg_dealing_encryption_pubkey()
            .times(1)
            .return_const(public_keys.dkg_dealing_encryption_public_key);
        public_key_store
            .expect_idkg_dealing_encryption_pubkeys()
            .times(1)
            .return_const(public_keys.idkg_dealing_encryption_public_keys);
        public_key_store
    }

    fn secret_key_store_containing_exactly(key_ids: LocalKeyIds) -> impl SecretKeyStore {
        let mut secret_key_store = MockSecretKeyStore::new();
        let mut key_ids_to_insert = HashSet::new();
        if let Some(key_id) = key_ids.node_signing_key_id {
            assert!(
                key_ids_to_insert.insert(key_id),
                "duplicated key ID {:?}",
                key_id
            );
        }
        if let Some(key_id) = key_ids.committee_signing_key_id {
            assert!(
                key_ids_to_insert.insert(key_id),
                "duplicated key ID {:?}",
                key_id
            );
        }
        if let Some(key_id) = key_ids.tls_secret_key_id {
            assert!(
                key_ids_to_insert.insert(key_id),
                "duplicated key ID {:?}",
                key_id
            );
        }
        if let Some(key_id) = key_ids.dkg_dealing_encryption_key_id {
            assert!(
                key_ids_to_insert.insert(key_id),
                "duplicated key ID {:?}",
                key_id
            );
        }
        for key_id in key_ids.idkg_dealing_encryption_key_ids {
            assert!(
                key_ids_to_insert.insert(key_id),
                "duplicated key ID {:?}",
                key_id
            );
        }
        for key_id in key_ids_to_insert {
            secret_key_store
                .expect_contains()
                .times(..=1)
                .withf(move |actual_key_id| *actual_key_id == key_id)
                .return_const(true);
        }
        secret_key_store.expect_contains().return_const(false);
        secret_key_store
    }

    /// Returns the required node public keys and hard-coded validation time for
    /// which the TLS certificate is valid.
    fn required_node_public_keys_and_time() -> (LocalNodePublicKeys, Time) {
        let (tls_certificate, validation_time) = valid_tls_certificate_and_validation_time();
        (
            LocalNodePublicKeys {
                node_signing_public_key: Some(valid_node_signing_public_key()),
                committee_signing_public_key: Some(valid_committee_signing_public_key()),
                tls_certificate: Some(tls_certificate),
                dkg_dealing_encryption_public_key: Some(valid_dkg_dealing_encryption_public_key()),
                idkg_dealing_encryption_public_keys: vec![
                    valid_idkg_dealing_encryption_public_key(),
                ],
            },
            validation_time,
        )
    }

    fn node_signing_secret_key_id() -> KeyId {
        KeyId::try_from(
            &CspPublicKey::try_from(&valid_node_signing_public_key()).expect("invalid public key"),
        )
        .expect("invalid public key")
    }

    fn committee_signing_secret_key_id() -> KeyId {
        KeyId::try_from(
            &CspPublicKey::try_from(&valid_committee_signing_public_key())
                .expect("invalid public key"),
        )
        .expect("invalid public key")
    }

    fn tls_certificate_key_id() -> KeyId {
        KeyId::try_from(
            &TlsPublicKeyCert::new_from_der(
                valid_tls_certificate_and_validation_time()
                    .0
                    .certificate_der,
            )
            .expect("invalid certificate"),
        )
        .expect("invalid certificate")
    }

    fn dkg_dealing_encryption_key_id() -> KeyId {
        KeyId::from(
            &CspFsEncryptionPublicKey::try_from(&valid_dkg_dealing_encryption_public_key())
                .expect("invalid public key"),
        )
    }

    fn idkg_dealing_encryption_key_id() -> KeyId {
        idkg_dealing_encryption_key_id_from(&valid_idkg_dealing_encryption_public_key())
    }

    fn idkg_dealing_encryption_key_id_from(idkg_pk: &PublicKey) -> KeyId {
        KeyId::try_from(&mega_public_key_from_proto(idkg_pk).expect("invalid public key"))
            .expect("invalid public key")
    }

    fn invalid_public_key() -> PublicKey {
        PublicKey::default()
    }

    fn invalid_tls_certificate() -> X509PublicKeyCert {
        X509PublicKeyCert::default()
    }

    fn invalid_node_signing_public_key() -> PublicKey {
        PublicKey {
            // Point not on curve, from `ic_crypto_internal_basic_sig_ed25519::api::tests::verify_public_key::should_fail_public_key_verification_if_point_is_not_on_curve`
            key_value: vec![
                2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            ..valid_node_signing_public_key()
        }
    }

    fn invalid_committee_signing_public_key() -> PublicKey {
        PublicKey {
            key_value: vec![
                0u8;
                ic_crypto_internal_multi_sig_bls12381::types::PublicKeyBytes::SIZE
            ],
            ..valid_committee_signing_public_key()
        }
    }

    fn tls_certificate_with_invalid_not_before_time() -> X509PublicKeyCert {
        X509PublicKeyCert {
            // Tweaked certificate from `ic_crypto_test_utils_keys::public_keys::valid_tls_certificate`
            certificate_der: hex::decode(
                "3082015630820108a00302010202140098d0747d24ca04a2f036d8665402b4ea78483030\
                0506032b6570304a3148304606035504030c3f34696e71622d327a63766b2d663679716c2d736f\
                776f6c2d76673365732d7a32346a642d6a726b6f772d6d686e73642d756b7666702d66616b3570\
                2d6161653020170d3939393930343138313231345a180f39393939313233313233353935395a30\
                4a3148304606035504030c3f34696e71622d327a63766b2d663679716c2d736f776f6c2d766733\
                65732d7a32346a642d6a726b6f772d6d686e73642d756b7666702d66616b35702d616165302a30\
                0506032b6570032100246acd5f38372411103768e91169dadb7370e99909a65639186ac6d1c36f\
                3735300506032b6570034100d37e5ccfc32146767e5fd73343649f5b5564eb78e6d8d424d8f012\
                40708bc537a2a9bcbcf6c884136d18d2b475706d7bb905f52faf28707735f1d90ab654380b",
            )
            .expect("should successfully decode hex cert"),
        }
    }

    fn invalid_dkg_dealing_encryption_key() -> PublicKey {
        let mut dkg_dealing_encryption_key = valid_dkg_dealing_encryption_public_key();
        if let Some(proof_data) = &mut dkg_dealing_encryption_key.proof_data {
            let index = &proof_data.len() - 1;
            proof_data[index] ^= 0xff;
        }
        dkg_dealing_encryption_key
    }

    #[derive(Clone, Debug)]
    struct LocalKeyIds {
        node_signing_key_id: Option<KeyId>,
        committee_signing_key_id: Option<KeyId>,
        dkg_dealing_encryption_key_id: Option<KeyId>,
        tls_secret_key_id: Option<KeyId>,
        idkg_dealing_encryption_key_ids: Vec<KeyId>,
    }

    fn required_key_ids() -> LocalKeyIds {
        LocalKeyIds {
            node_signing_key_id: Some(node_signing_secret_key_id()),
            committee_signing_key_id: Some(committee_signing_secret_key_id()),
            dkg_dealing_encryption_key_id: Some(dkg_dealing_encryption_key_id()),
            tls_secret_key_id: Some(tls_certificate_key_id()),
            idkg_dealing_encryption_key_ids: vec![idkg_dealing_encryption_key_id()],
        }
    }

    fn required_node_public_keys_and_their_key_ids() -> (LocalNodePublicKeys, Time, LocalKeyIds) {
        let (keys, validation_time) = required_node_public_keys_and_time();
        (keys, validation_time, required_key_ids())
    }
}
