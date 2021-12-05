#![allow(clippy::unwrap_used)]
use crate::secret_key_store::test_utils::TempSecretKeyStore;
use crate::vault::test_utils;
use ic_types_test_utils::ids::node_test_id;
use openssl::pkey::PKey;
use rand::{thread_rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

mod keygen {
    use super::*;
    use crate::secret_key_store::test_utils::MockSecretKeyStore;
    use crate::secret_key_store::SecretKeyStoreError;
    use crate::vault::local_csp_vault::test_utils::new_csp_vault;
    use crate::vault::local_csp_vault::LocalCspVault;
    use crate::TlsHandshakeCspVault;
    use ic_types::crypto::KeyId;
    use rand::Rng;
    use std::sync::Arc;

    #[test]
    fn should_insert_secret_key_into_key_store() {
        test_utils::tls::should_insert_secret_key_into_key_store(new_csp_vault());
    }

    #[test]
    #[should_panic(expected = "has already been inserted")]
    fn should_panic_if_secret_key_insertion_yields_duplicate_error() {
        let mut sks_returning_error_on_insert = MockSecretKeyStore::new();
        sks_returning_error_on_insert
            .expect_insert()
            .times(1)
            .return_const(Err(SecretKeyStoreError::DuplicateKeyId(KeyId::from(
                [42; 32],
            ))));

        let csp_vault = {
            let csprng = ChaCha20Rng::from_seed(thread_rng().gen::<[u8; 32]>());
            LocalCspVault::new_for_test(csprng, sks_returning_error_on_insert)
        };

        let _ = csp_vault.gen_tls_key_pair(
            node_test_id(test_utils::tls::NODE_1),
            test_utils::tls::NOT_AFTER,
        );
    }

    #[test]
    fn should_return_der_encoded_self_signed_certificate() {
        test_utils::tls::should_return_der_encoded_self_signed_certificate(new_csp_vault());
    }

    #[test]
    fn should_set_cert_subject_cn_as_node_id() {
        test_utils::tls::should_set_cert_subject_cn_as_node_id(new_csp_vault());
    }

    #[test]
    fn should_use_stable_node_id_string_representation_as_subject_cn() {
        test_utils::tls::should_use_stable_node_id_string_representation_as_subject_cn(
            new_csp_vault(),
        );
    }

    #[test]
    fn should_set_cert_issuer_cn_as_node_id() {
        test_utils::tls::should_set_cert_issuer_cn_as_node_id(new_csp_vault());
    }

    #[test]
    fn should_not_set_cert_subject_alt_name() {
        test_utils::tls::should_not_set_cert_subject_alt_name(new_csp_vault());
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
        test_utils::tls::should_set_different_serial_numbers_for_multiple_certs(new_csp_vault());
    }

    #[test]
    fn should_set_cert_not_after_correctly() {
        test_utils::tls::should_set_cert_not_after_correctly(new_csp_vault());
    }

    // TODO(CRP-1303): reconsider whether `gen_tls_key_pair()` should panic.
    #[test]
    #[should_panic(expected = "invalid X.509 certificate expiration date (not_after)")]
    fn should_panic_on_invalid_not_after_date() {
        let csp_vault = new_csp_vault();
        let _panic = csp_vault.gen_tls_key_pair(
            node_test_id(test_utils::tls::NODE_1),
            "invalid_not_after_date",
        );
    }

    #[test]
    #[should_panic(expected = "'not after' date must not be in the past")]
    fn should_panic_if_not_after_date_is_in_the_past() {
        let csp_vault = new_csp_vault();
        let date_in_the_past = "20211004235959Z";

        let _panic =
            csp_vault.gen_tls_key_pair(node_test_id(test_utils::tls::NODE_1), date_in_the_past);
    }
}

mod sign {
    use super::*;
    use crate::secret_key_store::SecretKeyStore;
    use crate::types::CspSecretKey;
    use crate::vault::local_csp_vault::test_utils::new_csp_vault;
    use crate::vault::local_csp_vault::LocalCspVault;
    use ic_crypto_internal_tls::keygen::TlsEd25519SecretKeyDerBytes;
    use ic_types::crypto::KeyId;
    use std::sync::Arc;

    #[test]
    fn should_sign_with_valid_key() {
        test_utils::tls::should_sign_with_valid_key(new_csp_vault());
    }

    #[test]
    fn should_sign_verifiably() {
        test_utils::tls::should_sign_verifiably(new_csp_vault());
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_not_found() {
        test_utils::tls::should_fail_to_sign_if_secret_key_not_found(new_csp_vault());
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_in_store_has_wrong_type() {
        test_utils::tls::should_fail_to_sign_if_secret_key_in_store_has_wrong_type(new_csp_vault());
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_in_store_has_invalid_encoding() {
        let key_id = KeyId([42; 32]);
        let csp_vault = {
            let mut key_store = TempSecretKeyStore::new();
            let secret_key_with_invalid_der =
                CspSecretKey::TlsEd25519(TlsEd25519SecretKeyDerBytes {
                    bytes: b"invalid DER encoding".to_vec(),
                });
            assert!(key_store
                .insert(key_id, secret_key_with_invalid_der, None)
                .is_ok());
            LocalCspVault::new_for_test(
                test_utils::tls::csprng_seeded_with(test_utils::tls::FIXED_SEED),
                key_store,
            )
        };
        test_utils::tls::should_fail_to_sign_if_secret_key_in_store_has_invalid_encoding(
            key_id,
            Arc::new(csp_vault),
        );
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_in_store_has_invalid_length() {
        let key_id = KeyId([43; 32]);
        let csp_vault = {
            let mut key_store = TempSecretKeyStore::new();
            let secret_key_with_invalid_length =
                CspSecretKey::TlsEd25519(TlsEd25519SecretKeyDerBytes {
                    bytes: PKey::generate_ed448()
                        .expect("failed to create Ed2448 key pair")
                        .private_key_to_der()
                        .expect("failed to serialize Ed2448 key to DER"),
                });
            assert!(key_store
                .insert(key_id, secret_key_with_invalid_length, None)
                .is_ok());
            LocalCspVault::new_for_test(
                test_utils::tls::csprng_seeded_with(test_utils::tls::FIXED_SEED),
                key_store,
            )
        };

        test_utils::tls::should_fail_to_sign_if_secret_key_in_store_has_invalid_length(
            key_id,
            Arc::new(csp_vault),
        );
    }
}
