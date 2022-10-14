#![allow(clippy::unwrap_used)]
use crate::secret_key_store::test_utils::TempSecretKeyStore;
use crate::vault::test_utils;
use crate::vault::test_utils::sks::secret_key_store_containing_key_with_invalid_encoding;
use crate::vault::test_utils::sks::secret_key_store_with_error_on_insert;
use ic_types_test_utils::ids::node_test_id;

mod keygen {
    use super::*;
    use crate::key_id::KeyId;
    use crate::vault::api::CspTlsKeygenError;
    use crate::vault::local_csp_vault::LocalCspVault;
    use crate::vault::test_utils::local_csp_vault::{
        new_local_csp_vault, new_local_csp_vault_with_secret_key_store,
    };
    use std::sync::Arc;

    #[test]
    fn should_insert_secret_key_into_key_store() {
        test_utils::tls::should_insert_secret_key_into_key_store(new_local_csp_vault());
    }

    #[test]
    fn should_fail_if_secret_key_insertion_yields_duplicate_error() {
        let duplicated_key_id = KeyId::from([42; 32]);
        let csp_vault = new_local_csp_vault_with_secret_key_store(
            secret_key_store_with_error_on_insert(duplicated_key_id),
        );

        test_utils::tls::should_fail_if_secret_key_insertion_yields_duplicate_error(
            csp_vault,
            &duplicated_key_id,
        );
    }

    #[test]
    fn should_return_der_encoded_self_signed_certificate() {
        test_utils::tls::should_return_der_encoded_self_signed_certificate(new_local_csp_vault());
    }

    #[test]
    fn should_set_cert_subject_cn_as_node_id() {
        test_utils::tls::should_set_cert_subject_cn_as_node_id(new_local_csp_vault());
    }

    #[test]
    fn should_use_stable_node_id_string_representation_as_subject_cn() {
        test_utils::tls::should_use_stable_node_id_string_representation_as_subject_cn(
            new_local_csp_vault(),
        );
    }

    #[test]
    fn should_set_cert_issuer_cn_as_node_id() {
        test_utils::tls::should_set_cert_issuer_cn_as_node_id(new_local_csp_vault());
    }

    #[test]
    fn should_not_set_cert_subject_alt_name() {
        test_utils::tls::should_not_set_cert_subject_alt_name(new_local_csp_vault());
    }

    #[test]
    fn should_set_random_cert_serial_number() {
        let csp_vault = {
            let key_store = TempSecretKeyStore::new();
            LocalCspVault::new_for_test(
                test_utils::tls::csprng_seeded_with(test_utils::tls::FIXED_SEED),
                key_store,
            )
        };
        test_utils::tls::should_set_random_cert_serial_number(Arc::new(csp_vault));
    }

    #[test]
    fn should_set_different_serial_numbers_for_multiple_certs() {
        test_utils::tls::should_set_different_serial_numbers_for_multiple_certs(
            new_local_csp_vault(),
        );
    }

    #[test]
    fn should_set_cert_not_after_correctly() {
        test_utils::tls::should_set_cert_not_after_correctly(new_local_csp_vault());
    }

    #[test]
    fn should_return_error_on_invalid_not_after_date() {
        let csp_vault = new_local_csp_vault();
        let invalid_not_after = "invalid_not_after_date";
        let result =
            csp_vault.gen_tls_key_pair(node_test_id(test_utils::tls::NODE_1), invalid_not_after);
        assert!(
            matches!(result, Err(CspTlsKeygenError::InvalidNotAfterDate { message, not_after })
                if message.eq("invalid X.509 certificate expiration date (not_after)") && not_after.eq(invalid_not_after)
            )
        );
    }

    #[test]
    fn should_return_error_if_not_after_date_is_in_the_past() {
        let csp_vault = new_local_csp_vault();
        let date_in_the_past = "20211004235959Z";

        let result =
            csp_vault.gen_tls_key_pair(node_test_id(test_utils::tls::NODE_1), date_in_the_past);
        assert!(
            matches!(result, Err(CspTlsKeygenError::InvalidNotAfterDate { message, not_after })
                if message.eq("'not after' date must not be in the past") && not_after.eq(date_in_the_past)
            )
        );
    }
}

mod sign {
    use super::*;
    use crate::key_id::KeyId;
    use crate::vault::test_utils::local_csp_vault::{
        new_local_csp_vault, new_local_csp_vault_with_secret_key_store,
    };
    use crate::vault::test_utils::sks::secret_key_store_containing_key_with_invalid_length;

    #[test]
    fn should_sign_with_valid_key() {
        test_utils::tls::should_sign_with_valid_key(new_local_csp_vault());
    }

    #[test]
    fn should_sign_verifiably() {
        test_utils::tls::should_sign_verifiably(new_local_csp_vault());
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_not_found() {
        test_utils::tls::should_fail_to_sign_if_secret_key_not_found(new_local_csp_vault());
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_in_store_has_wrong_type() {
        test_utils::tls::should_fail_to_sign_if_secret_key_in_store_has_wrong_type(
            new_local_csp_vault(),
        );
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_in_store_has_invalid_encoding() {
        let key_id = KeyId([42; 32]);
        let key_store = secret_key_store_containing_key_with_invalid_encoding(key_id);
        let csp_vault = new_local_csp_vault_with_secret_key_store(key_store);

        test_utils::tls::should_fail_to_sign_if_secret_key_in_store_has_invalid_encoding(
            key_id, csp_vault,
        );
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_in_store_has_invalid_length() {
        let key_id = KeyId([43; 32]);
        let key_store = secret_key_store_containing_key_with_invalid_length(key_id);
        let csp_vault = new_local_csp_vault_with_secret_key_store(key_store);

        test_utils::tls::should_fail_to_sign_if_secret_key_in_store_has_invalid_length(
            key_id, csp_vault,
        );
    }
}
