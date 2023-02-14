use crate::vault::test_utils;
use crate::LocalCspVault;

mod key_id_computations {
    use super::*;
    use crate::vault::local_csp_vault::public_and_secret_key_store::{
        compute_committee_signing_key_id, compute_dkg_dealing_encryption_key_id,
        compute_idkg_dealing_encryption_key_id, compute_node_signing_key_id,
        compute_tls_certificate_key_id, ExternalPublicKeyError,
    };
    use crate::vault::test_utils::public_key_store::{
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
        let csp_vault: Arc<dyn CspVault> = LocalCspVault::builder().build_into_arc();
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
        let csp_vault: Arc<dyn CspVault> = LocalCspVault::builder().build_into_arc();
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
        let csp_vault: Arc<dyn CspVault> = LocalCspVault::builder().build_into_arc();
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
        let csp_vault: Arc<dyn CspVault> = LocalCspVault::builder().build_into_arc();
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
    use crate::vault::test_utils::pks_and_sks::convert_to_external_public_keys;
    use crate::vault::test_utils::public_key_store::generate_all_keys;
    use crate::CspVault;
    use assert_matches::assert_matches;
    use ic_types::crypto::CurrentNodePublicKeys;
    use std::sync::Arc;

    #[test]
    fn should_return_success_for_identical_registry_and_local_public_keys() {
        let csp_vault: Arc<dyn CspVault> = LocalCspVault::builder().build_into_arc();
        let current_node_public_keys = generate_all_keys(&csp_vault);
        let external_public_keys =
            convert_to_external_public_keys(current_node_public_keys.clone());
        let local_public_keys = convert_to_local_public_keys(current_node_public_keys);
        let results = compare_public_keys(&external_public_keys, &local_public_keys);
        assert!(results.is_ok());
    }

    #[test]
    fn should_fail_for_node_signing_public_keys_mismatch() {
        let csp_vault: Arc<dyn CspVault> = LocalCspVault::builder().build_into_arc();
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
        let csp_vault: Arc<dyn CspVault> = LocalCspVault::builder().build_into_arc();
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
        let csp_vault: Arc<dyn CspVault> = LocalCspVault::builder().build_into_arc();
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
        let csp_vault: Arc<dyn CspVault> = LocalCspVault::builder().build_into_arc();
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
        let csp_vault: Arc<dyn CspVault> = LocalCspVault::builder().build_into_arc();
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
        let csp_vault: Arc<dyn CspVault> = LocalCspVault::builder().build_into_arc();
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
        let csp_vault: Arc<dyn CspVault> = LocalCspVault::builder().build_into_arc();
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
        let csp_vault: Arc<dyn CspVault> = LocalCspVault::builder().build_into_arc();
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
        let csp_vault: Arc<dyn CspVault> = LocalCspVault::builder().build_into_arc();
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
        let csp_vault: Arc<dyn CspVault> = LocalCspVault::builder().build_into_arc();
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

    #[test]
    fn should_return_success_for_pks_and_sks_contains_if_all_keys_match_with_one_idkg_key() {
        test_utils::pks_and_sks::should_return_success_for_pks_and_sks_contains_if_all_keys_match_with_one_idkg_key(LocalCspVault::builder().build_into_arc());
    }

    #[test]
    fn should_return_success_for_pks_and_sks_contains_if_all_keys_match_with_multiple_idkg_keys() {
        test_utils::pks_and_sks::should_return_success_for_pks_and_sks_contains_if_all_keys_match_with_multiple_idkg_keys(
            LocalCspVault::builder().build_into_arc(),
        );
    }

    #[test]
    fn should_return_success_for_pks_and_sks_contains_if_all_keys_match_with_multiple_idkg_keys_and_external_key_not_first_in_vector(
    ) {
        test_utils::pks_and_sks::should_return_success_for_pks_and_sks_contains_if_all_keys_match_with_multiple_idkg_keys_and_external_key_not_first_in_vector(
            LocalCspVault::builder().build_into_arc(),
        );
    }

    #[test]
    fn should_return_success_for_pks_and_sks_contains_if_all_keys_match_where_idkg_keys_have_different_timestamps(
    ) {
        test_utils::pks_and_sks::should_return_success_for_pks_and_sks_contains_if_all_keys_match_where_idkg_keys_have_different_timestamps(
            LocalCspVault::builder().build_into_arc(),
        );
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_no_keys_match() {
        test_utils::pks_and_sks::should_return_error_for_pks_and_sks_contains_if_no_keys_match(
            LocalCspVault::builder().build_into_arc(),
            LocalCspVault::builder().build_into_arc(),
        );
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_node_signing_key_does_not_match() {
        test_utils::pks_and_sks::should_return_error_for_pks_and_sks_contains_if_node_signing_key_does_not_match(
            LocalCspVault::builder().build_into_arc(),
            LocalCspVault::builder().build_into_arc()
        );
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_committee_signing_key_does_not_match() {
        test_utils::pks_and_sks::should_return_error_for_pks_and_sks_contains_if_committee_signing_key_does_not_match(
            LocalCspVault::builder().build_into_arc(),
            LocalCspVault::builder().build_into_arc()
        );
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_dkg_dealing_encryption_key_does_not_match() {
        test_utils::pks_and_sks::should_return_error_for_pks_and_sks_contains_if_dkg_dealing_encryption_key_does_not_match(
            LocalCspVault::builder().build_into_arc(),
            LocalCspVault::builder().build_into_arc()
        );
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_tls_certificate_does_not_match() {
        test_utils::pks_and_sks::should_return_error_for_pks_and_sks_contains_if_tls_certificate_does_not_match(
            LocalCspVault::builder().build_into_arc(),
            LocalCspVault::builder().build_into_arc()
        );
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_idkg_dealing_encryption_key_does_not_match()
    {
        test_utils::pks_and_sks::should_return_error_for_pks_and_sks_contains_if_idkg_dealing_encryption_key_does_not_match(
            LocalCspVault::builder().build_into_arc(),
            LocalCspVault::builder().build_into_arc()
        );
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_external_node_signing_key_is_malformed() {
        test_utils::pks_and_sks::should_return_error_for_pks_and_sks_contains_if_external_node_signing_key_is_malformed(
            LocalCspVault::builder().build_into_arc(),
        );
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_external_committee_signing_key_is_malformed()
    {
        test_utils::pks_and_sks::should_return_error_for_pks_and_sks_contains_if_external_committee_signing_key_is_malformed(
            LocalCspVault::builder().build_into_arc(),
        );
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_external_dkg_dealing_encryption_key_is_malformed(
    ) {
        test_utils::pks_and_sks::should_return_error_for_pks_and_sks_contains_if_external_dkg_dealing_encryption_key_is_malformed(
            LocalCspVault::builder().build_into_arc(),
        );
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_external_tls_certificate_is_malformed() {
        test_utils::pks_and_sks::should_return_error_for_pks_and_sks_contains_if_external_tls_certificate_is_malformed(
            LocalCspVault::builder().build_into_arc(),
        );
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_external_idkg_dealing_encryption_key_is_malformed(
    ) {
        test_utils::pks_and_sks::should_return_error_for_pks_and_sks_contains_if_external_idkg_dealing_encryption_key_is_malformed(
            LocalCspVault::builder().build_into_arc(),
        );
    }
}

mod pks_and_sks_complete {
    use crate::vault::api::{PksAndSksCompleteError, PublicAndSecretKeyStoreCspVault};
    use crate::LocalCspVault;
    use assert_matches::assert_matches;

    #[test]
    fn should_return_empty_public_key_store() {
        let vault = LocalCspVault::builder().build();
        let result = vault.pks_and_sks_complete();
        assert_matches!(result, Err(error) if error == PksAndSksCompleteError::EmptyPublicKeyStore)
    }
}
