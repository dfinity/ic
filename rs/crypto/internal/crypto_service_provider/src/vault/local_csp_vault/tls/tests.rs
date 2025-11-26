use crate::LocalCspVault;
use crate::vault::local_csp_vault::tls::SecretKeyStoreInsertionError;
use crate::vault::test_utils::sks::secret_key_store_containing_key_with_invalid_encoding;
use crate::vault::test_utils::sks::secret_key_store_with_duplicated_key_id_error_on_insert;
use assert_matches::assert_matches;
use ic_test_utilities_time::FastForwardTimeSource;
use ic_types_test_utils::ids::node_test_id;

const NODE_1: u64 = 4241;

mod keygen {
    use super::*;
    use crate::key_id::KeyId;
    use crate::public_key_store::PublicKeySetOnceError;
    use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
    use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
    use crate::vault::api::CspTlsKeygenError;
    use crate::vault::api::PublicKeyStoreCspVault;
    use crate::vault::api::SecretKeyStoreCspVault;
    use crate::vault::api::TlsHandshakeCspVault;
    use crate::vault::local_csp_vault::LocalCspVault;
    use crate::vault::local_csp_vault::tls::RFC5280_NO_WELL_DEFINED_CERTIFICATE_EXPIRATION_DATE;
    use ic_crypto_tls_interfaces::TlsPublicKeyCert;
    use ic_interfaces::time_source::TimeSource;
    use mockall::Sequence;
    use proptest::proptest;
    use rand::SeedableRng;
    use rand::{CryptoRng, Rng};
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::time::Duration;
    use time::PrimitiveDateTime;
    use time::macros::datetime;
    use time::macros::format_description;
    use x509_parser::num_bigint;
    use x509_parser::{certificate::X509Certificate, prelude::FromDer, x509::X509Name}; // re-export of num_bigint

    const NANOS_PER_SEC: i64 = 1_000_000_000;

    #[test]
    fn should_generate_tls_key_pair_and_store_certificate() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let cert = csp_vault
            .gen_tls_key_pair(node_test_id(NODE_1))
            .expect("Generation of TLS keys failed.");
        let key_id = KeyId::from(&cert);

        assert!(csp_vault.sks_contains(key_id).expect("SKS call failed"));
        assert_eq!(
            csp_vault
                .current_node_public_keys()
                .expect("missing public keys")
                .tls_certificate
                .expect("missing tls certificate"),
            cert.to_proto()
        );
    }

    #[test]
    fn should_fail_if_secret_key_insertion_yields_duplicate_error() {
        let duplicated_key_id = KeyId::from([42; 32]);
        let secret_key_store =
            secret_key_store_with_duplicated_key_id_error_on_insert(duplicated_key_id);
        let csp_vault = LocalCspVault::builder_for_test()
            .with_node_secret_key_store(secret_key_store)
            .build();

        let result = csp_vault.gen_tls_key_pair(node_test_id(NODE_1));

        assert_matches!(
            result,
            Err(CspTlsKeygenError::DuplicateKeyId { key_id }) if key_id ==  duplicated_key_id
        );
    }

    #[test]
    fn should_create_cert_that_passes_node_key_validation() {
        let node_id = node_test_id(NODE_1);
        let time_source = FastForwardTimeSource::new();
        let csp_vault = LocalCspVault::builder_for_test()
            .with_time_source(Arc::clone(&time_source) as _)
            .build();
        let cert = csp_vault
            .gen_tls_key_pair(node_id)
            .expect("Generation of TLS keys failed.");

        assert_matches!(
            ic_crypto_node_key_validation::ValidTlsCertificate::try_from((
                cert.to_proto(),
                node_id,
                time_source.get_relative_time(),
            )),
            Ok(_)
        );
    }

    #[test]
    fn should_set_cert_subject_cn_as_node_id() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let cert = csp_vault
            .gen_tls_key_pair(node_test_id(NODE_1))
            .expect("Generation of TLS keys failed.");

        let x509_cert = &x509(&cert);
        let expected_subject_cn = node_test_id(NODE_1).get().to_string();
        assert_single_cn_eq(x509_cert.subject(), &expected_subject_cn);
    }

    #[test]
    fn should_use_stable_node_id_string_representation_as_subject_cn() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let cert = csp_vault
            .gen_tls_key_pair(node_test_id(NODE_1))
            .expect("Generation of TLS keys failed.");
        let cert_x509 = x509(&cert);

        assert_single_cn_eq(cert_x509.subject(), "w43gn-nurca-aaaaa-aaaap-2ai");
    }

    #[test]
    fn should_set_cert_issuer_cn_as_node_id() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let cert = csp_vault
            .gen_tls_key_pair(node_test_id(NODE_1))
            .expect("Generation of TLS keys failed.");
        let cert_x509 = &x509(&cert);

        let expected_subject_cn = node_test_id(NODE_1).get().to_string();
        assert_single_cn_eq(cert_x509.issuer(), &expected_subject_cn);
    }

    #[test]
    fn should_not_set_cert_subject_alt_name() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let cert = csp_vault
            .gen_tls_key_pair(node_test_id(NODE_1))
            .expect("Generation of TLS keys failed.");

        assert_eq!(x509(&cert).subject_alternative_name(), Ok(None));
    }

    #[test]
    fn should_set_random_cert_serial_number() {
        pub const FIXED_SEED: u64 = 42;
        let csp_vault = LocalCspVault::builder_for_test()
            .with_rng(csprng_seeded_with(FIXED_SEED))
            .build();
        let cert = csp_vault
            .gen_tls_key_pair(node_test_id(NODE_1))
            .expect("Generation of TLS keys failed.");

        let cert_serial = &x509(&cert).serial;
        let expected_randomness = csprng_seeded_with(FIXED_SEED).r#gen::<[u8; 19]>();
        let expected_serial = &num_bigint::BigUint::from_bytes_be(&expected_randomness);
        assert_eq!(expected_serial, cert_serial);
    }

    #[test]
    fn should_set_different_serial_numbers_for_multiple_certs() {
        let csp_vault_factory = &(|| LocalCspVault::builder_for_test().build());
        const SAMPLE_SIZE: usize = 20;
        let mut serial_samples = BTreeSet::new();
        for _i in 0..SAMPLE_SIZE {
            let cert = csp_vault_factory()
                .gen_tls_key_pair(node_test_id(NODE_1))
                .expect("Generation of TLS keys failed.");
            serial_samples.insert(serial_number(&cert));
        }
        assert_eq!(serial_samples.len(), SAMPLE_SIZE);
    }

    #[test]
    fn should_set_cert_not_before_correctly() {
        use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
        use ic_types::time::Time;

        const NANOS_PER_SEC: u64 = 1_000_000_000;
        const MAX_TIME_SECS: u64 = u64::MAX / NANOS_PER_SEC;
        const GRACE_PERIOD_SECS: u64 = 120;

        let mut rng = reproducible_rng();

        // generate random values
        let mut inputs: Vec<_> = (0..100)
            .map(|_| rng.random_range(0..MAX_TIME_SECS))
            .collect();

        // append edge cases (when time is below `GRACE_PERIOD_SECS`)
        inputs.push(0);
        inputs.push(1);
        inputs.push(2);
        inputs.push(GRACE_PERIOD_SECS - 1);
        inputs.push(GRACE_PERIOD_SECS);

        for random_current_time_secs in inputs {
            let time_source = FastForwardTimeSource::new();
            time_source
                .set_time(
                    Time::from_secs_since_unix_epoch(random_current_time_secs)
                        .expect("failed to convert time"),
                )
                .expect("failed to set time");
            let csp_vault = LocalCspVault::builder_for_test()
                .with_time_source(Arc::clone(&time_source) as _)
                .build();

            let cert = csp_vault
                .gen_tls_key_pair(node_test_id(NODE_1))
                .expect("error generating TLS certificate");

            // We are deliberately not using `Asn1Time::from_unix` used in
            // production to ensure the right time unit is passed.
            let expected_not_before = {
                let secs = time_source
                    .get_relative_time()
                    .as_secs_since_unix_epoch()
                    .saturating_sub(GRACE_PERIOD_SECS);
                i64::try_from(secs).expect("invalid i64")
            };

            assert_eq!(
                x509(&cert).validity().not_before.timestamp(),
                expected_not_before
            );
        }
    }

    #[test]
    fn should_set_cert_not_after_correctly() {
        let not_after_unix = datetime!(9999-12-31 23:59:59 UTC).unix_timestamp();

        let csp_vault = LocalCspVault::builder_for_test().build();
        let cert = csp_vault
            .gen_tls_key_pair(node_test_id(NODE_1))
            .expect("Generation of TLS keys failed.");
        assert_eq!(x509(&cert).validity().not_after.timestamp(), not_after_unix);
    }

    proptest! {
        #[test]
        fn should_pass_the_correct_time_and_date(secs in 0..i64::MAX / NANOS_PER_SEC) {
            const GRACE_PERIOD_SECS: i64 = 120;

            let time_source = FastForwardTimeSource::new();
            time_source.advance_time(Duration::from_secs(secs as u64));
            let csp_vault = LocalCspVault::builder_for_test()
                .with_time_source(time_source)
                .build();

            let cert = csp_vault
                .gen_tls_key_pair(node_test_id(NODE_1))
                .expect("Failed to generate certificate");
            let not_before_unix_i64 = x509(&cert).validity().not_before.timestamp();

            let expected_not_before_unix_i64 = secs.saturating_sub(GRACE_PERIOD_SECS);
            assert_eq!(expected_not_before_unix_i64, not_before_unix_i64);
        }
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
        let vault = LocalCspVault::builder_for_test()
            .with_node_secret_key_store(sks)
            .with_public_key_store(pks)
            .build();

        let _ = vault.gen_tls_key_pair(node_test_id(NODE_1));
    }

    #[test]
    fn should_fail_with_internal_error_if_tls_certificate_already_set() {
        let mut pks_returning_already_set_error = MockPublicKeyStore::new();
        pks_returning_already_set_error
            .expect_set_once_tls_certificate()
            .returning(|_key| Err(PublicKeySetOnceError::AlreadySet));
        let vault = LocalCspVault::builder_for_test()
            .with_public_key_store(pks_returning_already_set_error)
            .build();
        for node_id in [NODE_1, NODE_1 + 1] {
            let result = vault.gen_tls_key_pair(node_test_id(node_id));

            assert_matches!(result,
                Err(CspTlsKeygenError::InternalError { internal_error })
                if internal_error.contains("TLS certificate already set")
            );
        }
    }

    #[test]
    fn should_fail_with_internal_error_if_tls_certificate_generated_more_than_once() {
        let vault = LocalCspVault::builder_for_test().build();
        assert!(vault.gen_tls_key_pair(node_test_id(NODE_1)).is_ok());

        for node_id in [NODE_1, NODE_1 + 1, NODE_1 + 2] {
            let result = vault.gen_tls_key_pair(node_test_id(node_id));

            assert_matches!(result,
                Err(CspTlsKeygenError::InternalError { internal_error })
                if internal_error.contains("TLS certificate already set")
            );
        }
    }

    #[test]
    fn should_fail_with_transient_internal_error_if_tls_keygen_persistence_fails() {
        let mut pks_returning_io_error = MockPublicKeyStore::new();
        let io_error = std::io::Error::other("oh no!");
        pks_returning_io_error
            .expect_set_once_tls_certificate()
            .return_once(|_key| Err(PublicKeySetOnceError::Io(io_error)));
        let vault = LocalCspVault::builder_for_test()
            .with_public_key_store(pks_returning_io_error)
            .build();
        let result = vault.gen_tls_key_pair(node_test_id(NODE_1));

        assert_matches!(result,
            Err(CspTlsKeygenError::TransientInternalError { internal_error })
            if internal_error.contains("IO error")
        );
    }

    #[test]
    fn should_fail_with_transient_internal_error_if_node_signing_secret_key_persistence_fails_due_to_io_error()
     {
        let mut sks_returning_io_error = MockSecretKeyStore::new();
        let expected_io_error = "cannot write to file".to_string();
        sks_returning_io_error
            .expect_insert()
            .times(1)
            .return_const(Err(SecretKeyStoreInsertionError::TransientError(
                expected_io_error.clone(),
            )));
        let vault = LocalCspVault::builder_for_test()
            .with_node_secret_key_store(sks_returning_io_error)
            .build();

        let result = vault.gen_tls_key_pair(node_test_id(42));

        assert_matches!(
            result,
            Err(CspTlsKeygenError::TransientInternalError { internal_error })
            if internal_error.contains(&expected_io_error)
        );
    }

    #[test]
    fn should_fail_with_internal_error_if_node_signing_secret_key_persistence_fails_due_to_serialization_error()
     {
        let mut sks_returning_serialization_error = MockSecretKeyStore::new();
        let expected_serialization_error = "cannot serialize keys".to_string();
        sks_returning_serialization_error
            .expect_insert()
            .times(1)
            .return_const(Err(SecretKeyStoreInsertionError::SerializationError(
                expected_serialization_error.clone(),
            )));
        let vault = LocalCspVault::builder_for_test()
            .with_node_secret_key_store(sks_returning_serialization_error)
            .build();

        let result = vault.gen_tls_key_pair(node_test_id(42));

        assert_matches!(
            result,
            Err(CspTlsKeygenError::InternalError { internal_error })
            if internal_error.contains(&expected_serialization_error)
        );
    }

    #[test]
    fn should_compute_not_after_constant_correctly() {
        let rfc_5280_no_well_defined_cert_expiration_date_string = "99991231235959Z";
        let asn1_format = format_description!("[year][month][day][hour][minute][second]Z"); // e.g., 99991231235959Z
        let time_primitivedatetime = PrimitiveDateTime::parse(
            rfc_5280_no_well_defined_cert_expiration_date_string,
            asn1_format,
        )
        .expect("invalid expiration date: failed to parse ASN1 datetime format");
        let time_i64 = time_primitivedatetime.assume_utc().unix_timestamp();
        let time_u64 =
            u64::try_from(time_i64).expect("invalid expiration date: failed to convert to u64");
        assert_eq!(
            RFC5280_NO_WELL_DEFINED_CERTIFICATE_EXPIRATION_DATE as u64,
            time_u64
        );
    }

    pub fn csprng_seeded_with(seed: u64) -> impl CryptoRng + Rng {
        rand_chacha::ChaCha20Rng::seed_from_u64(seed)
    }

    fn serial_number(cert: &TlsPublicKeyCert) -> num_bigint::BigUint {
        x509(cert).serial.clone()
    }

    fn x509(tls_cert: &TlsPublicKeyCert) -> X509Certificate<'_> {
        let (remainder, x509_cert) =
            X509Certificate::from_der(tls_cert.as_der()).expect("Error parsing DER");
        assert!(remainder.is_empty());
        x509_cert
    }

    fn assert_single_cn_eq(name: &X509Name<'_>, cn_str: &str) {
        let mut cn_iter = name.iter_common_name();
        let first_cn_str = cn_iter
            .next()
            .unwrap()
            .as_str()
            .expect("common name (CN) not a string");
        assert_eq!(first_cn_str, cn_str);
        assert_eq!(cn_iter.next(), None, "more than one common name");
    }
}

mod sign {
    use super::*;
    use crate::Csp;
    use crate::api::CspSigner;
    use crate::key_id::KeyId;
    use crate::vault::api::BasicSignatureCspVault;
    use crate::vault::api::CspTlsSignError;
    use crate::vault::api::SecretKeyStoreCspVault;
    use crate::vault::api::TlsHandshakeCspVault;
    use crate::vault::test_utils::ed25519_csp_pubkey_from_tls_pubkey_cert;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_types::crypto::AlgorithmId;
    use rand::{CryptoRng, Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn should_sign_with_valid_key() {
        let rng = &mut reproducible_rng();
        let csp_vault = LocalCspVault::builder_for_test()
            .with_rng(ChaCha20Rng::from_seed(rng.r#gen()))
            .build();
        let public_key_cert = csp_vault
            .gen_tls_key_pair(node_test_id(NODE_1))
            .expect("Generation of TLS keys failed.");

        assert!(
            csp_vault
                .tls_sign(random_message(rng), KeyId::from(&public_key_cert))
                .is_ok()
        );
    }

    #[test]
    fn should_sign_verifiably() {
        let rng = &mut reproducible_rng();
        let csp_vault = LocalCspVault::builder_for_test()
            .with_rng(ChaCha20Rng::from_seed(rng.r#gen()))
            .build();
        let verifier = Csp::builder_for_test().build();
        let public_key_cert = csp_vault
            .gen_tls_key_pair(node_test_id(NODE_1))
            .expect("Generation of TLS keys failed.");
        let msg = random_message(rng);

        let sig = csp_vault
            .tls_sign(msg.clone(), KeyId::from(&public_key_cert))
            .expect("failed to generate signature");

        let csp_pub_key = ed25519_csp_pubkey_from_tls_pubkey_cert(&public_key_cert);
        assert!(
            verifier
                .verify(&sig, &msg, AlgorithmId::Ed25519, csp_pub_key)
                .is_ok()
        );
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_not_found() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let non_existent_key_id = KeyId::from(b"non-existent-key-id-000000000000".to_owned());

        let result = csp_vault.tls_sign(b"message".to_vec(), non_existent_key_id);

        assert_eq!(
            result.expect_err("Unexpected success."),
            CspTlsSignError::SecretKeyNotFound {
                key_id: non_existent_key_id
            }
        );
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_in_store_has_wrong_type() {
        let rng = &mut reproducible_rng();
        let csp_vault = LocalCspVault::builder_for_test()
            .with_rng(ChaCha20Rng::from_seed(rng.r#gen()))
            .build();
        let wrong_csp_pub_key = csp_vault
            .gen_node_signing_key_pair()
            .expect("failed to generate keys");
        let msg = random_message(rng);

        let result = csp_vault.tls_sign(msg, KeyId::from(&wrong_csp_pub_key));

        assert_eq!(
            result.expect_err("Unexpected success."),
            CspTlsSignError::WrongSecretKeyType {
                algorithm: AlgorithmId::Tls,
                secret_key_variant: "Ed25519".to_string()
            }
        );
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_in_store_has_invalid_encoding() {
        let rng = &mut reproducible_rng();
        let key_id = KeyId::from([42; 32]);
        let key_store = secret_key_store_containing_key_with_invalid_encoding(key_id);
        let csp_vault = LocalCspVault::builder_for_test()
            .with_node_secret_key_store(key_store)
            .with_rng(ChaCha20Rng::from_seed(rng.r#gen()))
            .build();

        assert!(csp_vault.sks_contains(key_id).expect("SKS call failed"));
        let result = csp_vault.tls_sign(random_message(rng), key_id);
        assert_matches!(result, Err(CspTlsSignError::MalformedSecretKey { error })
            if error.starts_with("Failed to convert TLS secret key DER from key store to Ed25519 secret key")
        );
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_in_store_has_invalid_length() {
        let rng = &mut reproducible_rng();
        use crate::vault::test_utils::sks::secret_key_store_containing_key_with_invalid_length;

        let key_id = KeyId::from([43; 32]);
        let key_store = secret_key_store_containing_key_with_invalid_length(key_id);
        let csp_vault = LocalCspVault::builder_for_test()
            .with_node_secret_key_store(key_store)
            .with_rng(ChaCha20Rng::from_seed(rng.r#gen()))
            .build();

        let result = csp_vault.tls_sign(random_message(rng), key_id);
        assert_matches!(result, Err(CspTlsSignError::MalformedSecretKey { error })
            if error.starts_with("Failed to convert TLS secret key DER from key store to Ed25519 secret key")
        );
    }

    fn random_message<R: Rng + CryptoRng>(rng: &mut R) -> Vec<u8> {
        let msg_len: usize = rng.random_range(0..1024);
        (0..msg_len).map(|_| rng.r#gen::<u8>()).collect()
    }
}
