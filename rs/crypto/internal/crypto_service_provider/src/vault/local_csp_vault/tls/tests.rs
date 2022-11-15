#![allow(clippy::unwrap_used)]
use std::sync::Arc;

use crate::public_key_store::PublicKeyStore;
use crate::secret_key_store::test_utils::TempSecretKeyStore;
use crate::secret_key_store::SecretKeyStore;
use crate::vault::api::CspVault;
use crate::vault::test_utils;
use crate::vault::test_utils::sks::secret_key_store_containing_key_with_invalid_encoding;
use crate::vault::test_utils::sks::secret_key_store_with_duplicated_key_id_error_on_insert;
use crate::LocalCspVault;
use ic_types_test_utils::ids::node_test_id;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

mod keygen {
    use super::*;
    use crate::key_id::KeyId;
    use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
    use crate::public_key_store::temp_pubkey_store::TempPublicKeyStore;
    use crate::public_key_store::PublicKeySetOnceError;
    use crate::secret_key_store::test_utils::MockSecretKeyStore;
    use crate::vault::api::CspTlsKeygenError;
    use crate::vault::local_csp_vault::LocalCspVault;
    use crate::vault::test_utils::local_csp_vault::{
        new_local_csp_vault, new_local_csp_vault_with_secret_key_store,
    };
    use mockall::Sequence;
    use std::sync::Arc;

    const NOT_AFTER: &str = "25670102030405Z";

    #[test]
    fn should_generate_tls_key_pair_and_store_certificate() {
        test_utils::tls::should_generate_tls_key_pair_and_store_certificate(new_local_csp_vault());
    }

    #[test]
    fn should_fail_if_secret_key_insertion_yields_duplicate_error() {
        let duplicated_key_id = KeyId::from([42; 32]);
        let csp_vault = new_local_csp_vault_with_secret_key_store(
            secret_key_store_with_duplicated_key_id_error_on_insert(duplicated_key_id),
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
            let secret_key_store = TempSecretKeyStore::new();
            let public_key_store = TempPublicKeyStore::new();
            LocalCspVault::new_for_test(
                test_utils::tls::csprng_seeded_with(test_utils::tls::FIXED_SEED),
                secret_key_store,
                public_key_store,
            )
        };
        test_utils::tls::should_set_random_cert_serial_number(Arc::new(csp_vault));
    }

    #[test]
    fn should_set_different_serial_numbers_for_multiple_certs() {
        test_utils::tls::should_set_different_serial_numbers_for_multiple_certs(
            &new_local_csp_vault,
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
        let vault = vault_with_node_secret_key_store_and_public_key_store(sks, pks);

        let _ = vault.gen_tls_key_pair(node_test_id(test_utils::tls::NODE_1), NOT_AFTER);
    }

    #[test]
    fn should_fail_with_internal_error_if_tls_certificate_already_set() {
        let mut pks_returning_already_set_error = MockPublicKeyStore::new();
        pks_returning_already_set_error
            .expect_set_once_tls_certificate()
            .returning(|_key| Err(PublicKeySetOnceError::AlreadySet));
        let vault = vault_with_public_key_store(pks_returning_already_set_error);
        test_utils::tls::should_fail_with_internal_error_if_tls_certificate_already_set(vault);
    }

    #[test]
    fn should_fail_with_internal_error_if_tls_certificate_generated_more_than_once() {
        let vault = new_local_csp_vault();
        test_utils::tls::should_fail_with_internal_error_if_tls_certificate_generated_more_than_once(vault);
    }

    #[test]
    fn should_fail_with_transient_internal_error_if_tls_keygen_persistance_fails() {
        let mut pks_returning_io_error = MockPublicKeyStore::new();
        let io_error = std::io::Error::new(std::io::ErrorKind::Other, "oh no!");
        pks_returning_io_error
            .expect_set_once_tls_certificate()
            .return_once(|_key| Err(PublicKeySetOnceError::Io(io_error)));
        let vault = vault_with_public_key_store(pks_returning_io_error);
        test_utils::tls::should_fail_with_transient_internal_error_if_tls_keygen_persistance_fails(
            vault,
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
        let key_id = KeyId::from([42; 32]);
        let key_store = secret_key_store_containing_key_with_invalid_encoding(key_id);
        let csp_vault = new_local_csp_vault_with_secret_key_store(key_store);

        test_utils::tls::should_fail_to_sign_if_secret_key_in_store_has_invalid_encoding(
            key_id, csp_vault,
        );
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_in_store_has_invalid_length() {
        let key_id = KeyId::from([43; 32]);
        let key_store = secret_key_store_containing_key_with_invalid_length(key_id);
        let csp_vault = new_local_csp_vault_with_secret_key_store(key_store);

        test_utils::tls::should_fail_to_sign_if_secret_key_in_store_has_invalid_length(
            key_id, csp_vault,
        );
    }
}

fn vault_with_public_key_store<P: PublicKeyStore + 'static>(
    public_key_store: P,
) -> Arc<dyn CspVault> {
    let dummy_rng = ChaCha20Rng::seed_from_u64(42);
    let temp_sks = TempSecretKeyStore::new();
    let vault = LocalCspVault::new_for_test(dummy_rng, temp_sks, public_key_store);
    Arc::new(vault)
}

fn vault_with_node_secret_key_store_and_public_key_store<
    S: SecretKeyStore + 'static,
    P: PublicKeyStore + 'static,
>(
    node_secret_key_store: S,
    public_key_store: P,
) -> Arc<dyn CspVault> {
    let dummy_rng = ChaCha20Rng::seed_from_u64(42);
    let vault = LocalCspVault::new_for_test(dummy_rng, node_secret_key_store, public_key_store);
    Arc::new(vault)
}
