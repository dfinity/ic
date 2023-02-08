#![allow(clippy::unwrap_used)]

use crate::vault::local_csp_vault::tls::SecretKeyStoreError;
use crate::vault::local_csp_vault::tls::SecretKeyStorePersistenceError;
use crate::vault::test_utils;
use crate::vault::test_utils::sks::secret_key_store_containing_key_with_invalid_encoding;
use crate::vault::test_utils::sks::secret_key_store_with_duplicated_key_id_error_on_insert;
use crate::LocalCspVault;
use assert_matches::assert_matches;
use ic_types_test_utils::ids::node_test_id;

mod keygen {
    use super::*;
    use crate::key_id::KeyId;
    use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
    use crate::public_key_store::PublicKeySetOnceError;
    use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
    use crate::vault::api::CspTlsKeygenError;
    use crate::vault::api::TlsHandshakeCspVault;
    use crate::vault::local_csp_vault::LocalCspVault;
    use mockall::Sequence;

    const NOT_AFTER: &str = "99991231235959Z";

    #[test]
    fn should_generate_tls_key_pair_and_store_certificate() {
        test_utils::tls::should_generate_tls_key_pair_and_store_certificate(
            LocalCspVault::builder().build_into_arc(),
        );
    }

    #[test]
    fn should_fail_if_secret_key_insertion_yields_duplicate_error() {
        let duplicated_key_id = KeyId::from([42; 32]);
        let secret_key_store =
            secret_key_store_with_duplicated_key_id_error_on_insert(duplicated_key_id);
        let csp_vault = LocalCspVault::builder()
            .with_node_secret_key_store(secret_key_store)
            .build_into_arc();

        test_utils::tls::should_fail_if_secret_key_insertion_yields_duplicate_error(
            csp_vault,
            &duplicated_key_id,
        );
    }

    #[test]
    fn should_return_der_encoded_self_signed_certificate() {
        test_utils::tls::should_return_der_encoded_self_signed_certificate(
            LocalCspVault::builder().build_into_arc(),
        );
    }

    #[test]
    fn should_set_cert_subject_cn_as_node_id() {
        test_utils::tls::should_set_cert_subject_cn_as_node_id(
            LocalCspVault::builder().build_into_arc(),
        );
    }

    #[test]
    fn should_use_stable_node_id_string_representation_as_subject_cn() {
        test_utils::tls::should_use_stable_node_id_string_representation_as_subject_cn(
            LocalCspVault::builder().build_into_arc(),
        );
    }

    #[test]
    fn should_set_cert_issuer_cn_as_node_id() {
        test_utils::tls::should_set_cert_issuer_cn_as_node_id(
            LocalCspVault::builder().build_into_arc(),
        );
    }

    #[test]
    fn should_not_set_cert_subject_alt_name() {
        test_utils::tls::should_not_set_cert_subject_alt_name(
            LocalCspVault::builder().build_into_arc(),
        );
    }

    #[test]
    fn should_set_random_cert_serial_number() {
        let csp_vault = LocalCspVault::builder()
            .with_rng(test_utils::tls::csprng_seeded_with(
                test_utils::tls::FIXED_SEED,
            ))
            .build_into_arc();
        test_utils::tls::should_set_random_cert_serial_number(csp_vault);
    }

    #[test]
    fn should_set_different_serial_numbers_for_multiple_certs() {
        test_utils::tls::should_set_different_serial_numbers_for_multiple_certs(
            &(|| LocalCspVault::builder().build_into_arc()),
        );
    }

    #[test]
    fn should_set_cert_not_after_correctly() {
        test_utils::tls::should_set_cert_not_after_correctly(
            LocalCspVault::builder().build_into_arc(),
        );
    }

    #[test]
    fn should_return_error_on_invalid_not_after_date() {
        let csp_vault = LocalCspVault::builder().build_into_arc();
        let invalid_not_after = "invalid_not_after_date";
        let result =
            csp_vault.gen_tls_key_pair(node_test_id(test_utils::tls::NODE_1), invalid_not_after);
        assert_matches!(result, Err(CspTlsKeygenError::InvalidNotAfterDate { message, not_after })
            if message.eq("invalid X.509 certificate expiration date (not_after)") && not_after.eq(invalid_not_after)
        );
    }

    #[test]
    fn should_return_error_if_not_after_date_is_in_the_past() {
        let csp_vault = LocalCspVault::builder().build_into_arc();
        let date_in_the_past = "20211004235959Z";

        let result =
            csp_vault.gen_tls_key_pair(node_test_id(test_utils::tls::NODE_1), date_in_the_past);
        assert_matches!(result, Err(CspTlsKeygenError::InvalidNotAfterDate { message, not_after })
            if message.eq("'not after' date must not be in the past") && not_after.eq(date_in_the_past)
        );
    }

    #[test]
    fn should_return_error_if_not_after_date_does_not_equal_99991231235959z() {
        let csp_vault = LocalCspVault::builder().build_into_arc();
        let unexpected_not_after_date = "25670102030405Z";

        let result = csp_vault.gen_tls_key_pair(
            node_test_id(test_utils::tls::NODE_1),
            unexpected_not_after_date,
        );

        assert_matches!(result, Err(CspTlsKeygenError::InternalError {internal_error}) 
            if internal_error.contains("TLS certificate validation error") &&
            internal_error.contains("notAfter date is not RFC 5280 value 99991231235959Z"));
    }

    #[test]
    fn should_store_tls_secret_key_before_certificate() {
        let mut seq = Sequence::new();
        let mut sks = MockSecretKeyStore::new();
        sks.expect_insert()
            .times(1)
            .returning(|_key, _key_id, _scope| Ok(()))
            .in_sequence(&mut seq);
        let mut pks = MockPublicKeyStore::new();
        pks.expect_set_once_tls_certificate()
            .times(1)
            .returning(|_key| Ok(()))
            .in_sequence(&mut seq);
        let vault = LocalCspVault::builder()
            .with_node_secret_key_store(sks)
            .with_public_key_store(pks)
            .build_into_arc();

        let _ = vault.gen_tls_key_pair(node_test_id(test_utils::tls::NODE_1), NOT_AFTER);
    }

    #[test]
    fn should_fail_with_internal_error_if_tls_certificate_already_set() {
        let mut pks_returning_already_set_error = MockPublicKeyStore::new();
        pks_returning_already_set_error
            .expect_set_once_tls_certificate()
            .returning(|_key| Err(PublicKeySetOnceError::AlreadySet));
        let vault = LocalCspVault::builder()
            .with_public_key_store(pks_returning_already_set_error)
            .build_into_arc();
        test_utils::tls::should_fail_with_internal_error_if_tls_certificate_already_set(vault);
    }

    #[test]
    fn should_fail_with_internal_error_if_tls_certificate_generated_more_than_once() {
        let vault = LocalCspVault::builder().build_into_arc();
        test_utils::tls::should_fail_with_internal_error_if_tls_certificate_generated_more_than_once(vault);
    }

    #[test]
    fn should_fail_with_transient_internal_error_if_tls_keygen_persistence_fails() {
        let mut pks_returning_io_error = MockPublicKeyStore::new();
        let io_error = std::io::Error::new(std::io::ErrorKind::Other, "oh no!");
        pks_returning_io_error
            .expect_set_once_tls_certificate()
            .return_once(|_key| Err(PublicKeySetOnceError::Io(io_error)));
        let vault = LocalCspVault::builder()
            .with_public_key_store(pks_returning_io_error)
            .build_into_arc();
        test_utils::tls::should_fail_with_transient_internal_error_if_tls_keygen_persistance_fails(
            vault,
        );
    }

    #[test]
    fn should_fail_with_transient_internal_error_if_node_signing_secret_key_persistence_fails_due_to_io_error(
    ) {
        let mut sks_returning_io_error = MockSecretKeyStore::new();
        let expected_io_error = "cannot write to file".to_string();
        sks_returning_io_error
            .expect_insert()
            .times(1)
            .return_const(Err(SecretKeyStoreError::PersistenceError(
                SecretKeyStorePersistenceError::IoError(expected_io_error.clone()),
            )));
        let vault = LocalCspVault::builder()
            .with_node_secret_key_store(sks_returning_io_error)
            .build();

        let result = vault.gen_tls_key_pair(node_test_id(42), NOT_AFTER);

        assert_matches!(
            result,
            Err(CspTlsKeygenError::TransientInternalError { internal_error })
            if internal_error.contains(&expected_io_error)
        );
    }

    #[test]
    fn should_fail_with_internal_error_if_node_signing_secret_key_persistence_fails_due_to_serialization_error(
    ) {
        let mut sks_returning_serialization_error = MockSecretKeyStore::new();
        let expected_serialization_error = "cannot serialize keys".to_string();
        sks_returning_serialization_error
            .expect_insert()
            .times(1)
            .return_const(Err(SecretKeyStoreError::PersistenceError(
                SecretKeyStorePersistenceError::SerializationError(
                    expected_serialization_error.clone(),
                ),
            )));
        let vault = LocalCspVault::builder()
            .with_node_secret_key_store(sks_returning_serialization_error)
            .build();

        let result = vault.gen_tls_key_pair(node_test_id(42), NOT_AFTER);

        assert_matches!(
            result,
            Err(CspTlsKeygenError::InternalError { internal_error })
            if internal_error.contains(&expected_serialization_error)
        );
    }
}

mod sign {
    use super::*;
    use crate::key_id::KeyId;
    use crate::vault::test_utils::sks::secret_key_store_containing_key_with_invalid_length;

    #[test]
    fn should_sign_with_valid_key() {
        test_utils::tls::should_sign_with_valid_key(LocalCspVault::builder().build_into_arc());
    }

    #[test]
    fn should_sign_verifiably() {
        test_utils::tls::should_sign_verifiably(LocalCspVault::builder().build_into_arc());
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_not_found() {
        test_utils::tls::should_fail_to_sign_if_secret_key_not_found(
            LocalCspVault::builder().build_into_arc(),
        );
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_in_store_has_wrong_type() {
        test_utils::tls::should_fail_to_sign_if_secret_key_in_store_has_wrong_type(
            LocalCspVault::builder().build_into_arc(),
        );
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_in_store_has_invalid_encoding() {
        let key_id = KeyId::from([42; 32]);
        let key_store = secret_key_store_containing_key_with_invalid_encoding(key_id);
        let csp_vault = LocalCspVault::builder()
            .with_node_secret_key_store(key_store)
            .build_into_arc();

        test_utils::tls::should_fail_to_sign_if_secret_key_in_store_has_invalid_encoding(
            key_id, csp_vault,
        );
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_in_store_has_invalid_length() {
        let key_id = KeyId::from([43; 32]);
        let key_store = secret_key_store_containing_key_with_invalid_length(key_id);
        let csp_vault = LocalCspVault::builder()
            .with_node_secret_key_store(key_store)
            .build_into_arc();

        test_utils::tls::should_fail_to_sign_if_secret_key_in_store_has_invalid_length(
            key_id, csp_vault,
        );
    }
}
