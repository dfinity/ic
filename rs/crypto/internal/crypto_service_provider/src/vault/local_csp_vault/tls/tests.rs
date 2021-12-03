#![allow(clippy::unwrap_used)]
use crate::secret_key_store::test_utils::TempSecretKeyStore;
use ic_types_test_utils::ids::node_test_id;
use openssl::x509::{X509NameEntries, X509VerifyResult, X509};
use openssl::{bn::BigNum, nid::Nid, pkey::PKey};
use rand::{thread_rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

mod test_utils {
    use super::*;
    use crate::api::CspSigner;
    use crate::keygen::tls_cert_hash_as_key_id;
    use crate::types::CspPublicKey;
    use crate::vault::api::{CspTlsSignError, CspVault};
    use crate::{CryptoServiceProvider, Csp};
    use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
    use ic_crypto_tls_interfaces::TlsPublicKeyCert;
    use ic_types::crypto::{AlgorithmId, KeyId};
    use openssl::asn1::Asn1Time;
    use rand::{CryptoRng, Rng};
    use std::collections::BTreeSet;
    use std::sync::Arc;

    pub const NODE_1: u64 = 4241;
    pub const FIXED_SEED: u64 = 42;
    pub const NOT_AFTER: &str = "25670102030405Z";

    pub fn should_insert_secret_key_into_key_store(csp_vault: Arc<dyn CspVault>) {
        let (key_id, cert) = csp_vault.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);
        assert_eq!(key_id, tls_cert_hash_as_key_id(&cert));
        assert!(csp_vault.sks_contains(&key_id));
    }

    pub fn should_return_der_encoded_self_signed_certificate(csp_vault: Arc<dyn CspVault>) {
        let (_key_id, cert) = csp_vault.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        let x509_cert = cert.as_x509();
        let public_key = x509_cert.public_key().unwrap();
        assert_eq!(x509_cert.verify(&public_key).ok(), Some(true));
        assert_eq!(x509_cert.issued(x509_cert), X509VerifyResult::OK);
    }

    pub fn should_set_cert_subject_cn_as_node_id(csp_vault: Arc<dyn CspVault>) {
        let (_key_id, cert) = csp_vault.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        let x509_cert = cert.as_x509();
        assert_eq!(cn_entries(x509_cert).count(), 1);
        let subject_cn = cn_entries(x509_cert).next().unwrap();
        let expected_subject_cn = node_test_id(NODE_1).get().to_string();
        assert_eq!(expected_subject_cn.as_bytes(), subject_cn.data().as_slice());
    }

    pub fn should_use_stable_node_id_string_representation_as_subject_cn(
        csp_vault: Arc<dyn CspVault>,
    ) {
        let (_key_id, cert) = csp_vault.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        let subject_cn = cn_entries(cert.as_x509()).next().unwrap();
        assert_eq!(b"w43gn-nurca-aaaaa-aaaap-2ai", subject_cn.data().as_slice());
    }

    pub fn should_set_cert_issuer_cn_as_node_id(csp_vault: Arc<dyn CspVault>) {
        let (_key_id, cert) = csp_vault.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        let issuer_cn = cert
            .as_x509()
            .issuer_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .unwrap();
        let expected_issuer_cn = node_test_id(NODE_1).get().to_string();
        assert_eq!(expected_issuer_cn.as_bytes(), issuer_cn.data().as_slice());
    }

    pub fn should_not_set_cert_subject_alt_name(csp_vault: Arc<dyn CspVault>) {
        let (_key_id, cert) = csp_vault.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        let subject_alt_names = cert.as_x509().subject_alt_names();
        assert!(subject_alt_names.is_none());
    }

    pub fn should_set_random_cert_serial_number(csp_vault: Arc<dyn CspVault>) {
        let (_key_id, cert) = csp_vault.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        let cert_serial = cert.as_x509().serial_number().to_bn().unwrap();
        let expected_randomness = csprng_seeded_with(FIXED_SEED).gen::<[u8; 19]>();
        let expected_serial = BigNum::from_slice(&expected_randomness).unwrap();
        assert_eq!(expected_serial, cert_serial);
    }

    pub fn should_set_different_serial_numbers_for_multiple_certs(csp_vault: Arc<dyn CspVault>) {
        const SAMPLE_SIZE: usize = 20;
        let mut serial_samples = BTreeSet::new();
        for _i in 0..SAMPLE_SIZE {
            let (_key_id, cert) = csp_vault.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);
            serial_samples.insert(serial_number(&cert));
        }
        assert_eq!(serial_samples.len(), SAMPLE_SIZE);
    }

    pub fn should_set_cert_not_after_correctly(csp_vault: Arc<dyn CspVault>) {
        let (_key_id, cert) = csp_vault.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);
        assert!(cert.as_x509().not_after() == Asn1Time::from_str_x509(NOT_AFTER).unwrap());
    }

    fn cn_entries(x509_cert: &X509) -> X509NameEntries {
        x509_cert.subject_name().entries_by_nid(Nid::COMMONNAME)
    }

    pub fn csprng_seeded_with(seed: u64) -> impl CryptoRng + Rng + Clone {
        ChaCha20Rng::seed_from_u64(seed)
    }

    fn serial_number(cert: &TlsPublicKeyCert) -> BigNum {
        cert.as_x509().serial_number().to_bn().unwrap()
    }

    pub fn should_sign_with_valid_key(csp_vault: Arc<dyn CspVault>) {
        let (key_id, _public_key_cert) =
            csp_vault.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        assert!(csp_vault.tls_sign(&random_message(), &key_id).is_ok());
    }

    pub fn should_sign_verifiably(csp_vault: Arc<dyn CspVault>) {
        let verifier = verifier();
        let (key_id, public_key_cert) = csp_vault.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);
        let msg = random_message();

        let sig = csp_vault
            .tls_sign(&msg, &key_id)
            .expect("failed to generate signature");

        let csp_pub_key = ed25519_csp_pubkey_from_tls_pubkey_cert(&public_key_cert);
        assert!(verifier
            .verify(&sig, &msg, AlgorithmId::Ed25519, csp_pub_key)
            .is_ok());
    }

    pub fn should_fail_to_sign_if_secret_key_not_found(csp_vault: Arc<dyn CspVault>) {
        let non_existent_key_id = KeyId(b"non-existent-key-id-000000000000".to_owned());

        let result = csp_vault.tls_sign(b"message", &non_existent_key_id);

        assert_eq!(
            result.unwrap_err(),
            CspTlsSignError::SecretKeyNotFound {
                key_id: non_existent_key_id
            }
        );
    }

    pub fn should_fail_to_sign_if_secret_key_in_store_has_wrong_type(csp_vault: Arc<dyn CspVault>) {
        let (key_id, _wrong_csp_pub_key) = csp_vault
            .gen_key_pair(AlgorithmId::Ed25519)
            .expect("failed to generate keys");
        let msg = random_message();

        let result = csp_vault.tls_sign(&msg, &key_id);

        assert_eq!(
            result.unwrap_err(),
            CspTlsSignError::WrongSecretKeyType {
                algorithm: AlgorithmId::Ed25519
            }
        );
    }

    pub fn should_fail_to_sign_if_secret_key_in_store_has_invalid_encoding(
        key_id: KeyId,
        csp_vault: Arc<dyn CspVault>,
    ) {
        assert!(csp_vault.sks_contains(&key_id));
        let result = csp_vault.tls_sign(&random_message(), &key_id);
        assert_eq!(
            result.unwrap_err(),
            CspTlsSignError::MalformedSecretKey {
                error: "Failed to convert TLS secret key DER from key store to OpenSSL private key"
                    .to_string()
            }
        );
    }

    pub fn should_fail_to_sign_if_secret_key_in_store_has_invalid_length(
        key_id: KeyId,
        csp_vault: Arc<dyn CspVault>,
    ) {
        let result = csp_vault.tls_sign(&random_message(), &key_id);
        assert_eq!(
            result.unwrap_err(),
            CspTlsSignError::MalformedSecretKey {
                error: "Invalid length of raw OpenSSL private key: expected 32 bytes, but got 57"
                    .to_string()
            }
        );
    }

    fn verifier() -> impl CryptoServiceProvider {
        let dummy_key_store = TempSecretKeyStore::new();
        let csprng = ChaCha20Rng::from_seed(thread_rng().gen::<[u8; 32]>());
        Csp::of(csprng, dummy_key_store)
    }

    fn ed25519_csp_pubkey_from_tls_pubkey_cert(public_key_cert: &TlsPublicKeyCert) -> CspPublicKey {
        let pubkey_bytes = public_key_cert
            .as_x509()
            .public_key()
            .expect("failed to get public key")
            .raw_public_key()
            .expect("failed to get raw public key bytes");

        const PUBKEY_LEN: usize = ed25519_types::PublicKeyBytes::SIZE;
        if pubkey_bytes.len() != PUBKEY_LEN {
            panic!("invalid public key length");
        }
        let mut bytes: [u8; PUBKEY_LEN] = [0; PUBKEY_LEN];
        bytes.copy_from_slice(&pubkey_bytes);
        CspPublicKey::Ed25519(ed25519_types::PublicKeyBytes(bytes))
    }

    fn random_message() -> Vec<u8> {
        let mut rng = thread_rng();
        let msg_len: usize = rng.gen_range(0, 1024);
        (0..msg_len).map(|_| rng.gen::<u8>()).collect()
    }
}

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
        test_utils::should_insert_secret_key_into_key_store(new_csp_vault());
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

        let _ = csp_vault.gen_tls_key_pair(node_test_id(test_utils::NODE_1), test_utils::NOT_AFTER);
    }

    #[test]
    fn should_return_der_encoded_self_signed_certificate() {
        test_utils::should_return_der_encoded_self_signed_certificate(new_csp_vault());
    }

    #[test]
    fn should_set_cert_subject_cn_as_node_id() {
        test_utils::should_set_cert_subject_cn_as_node_id(new_csp_vault());
    }

    #[test]
    fn should_use_stable_node_id_string_representation_as_subject_cn() {
        test_utils::should_use_stable_node_id_string_representation_as_subject_cn(new_csp_vault());
    }

    #[test]
    fn should_set_cert_issuer_cn_as_node_id() {
        test_utils::should_set_cert_issuer_cn_as_node_id(new_csp_vault());
    }

    #[test]
    fn should_not_set_cert_subject_alt_name() {
        test_utils::should_not_set_cert_subject_alt_name(new_csp_vault());
    }

    #[test]
    fn should_set_random_cert_serial_number() {
        let csp_vault = {
            let key_store = TempSecretKeyStore::new();
            LocalCspVault::new_for_test(
                test_utils::csprng_seeded_with(test_utils::FIXED_SEED),
                key_store,
            )
        };
        test_utils::should_set_random_cert_serial_number(Arc::new(csp_vault));
    }

    #[test]
    fn should_set_different_serial_numbers_for_multiple_certs() {
        test_utils::should_set_different_serial_numbers_for_multiple_certs(new_csp_vault());
    }

    #[test]
    fn should_set_cert_not_after_correctly() {
        test_utils::should_set_cert_not_after_correctly(new_csp_vault());
    }

    #[test]
    #[should_panic(expected = "invalid X.509 certificate expiration date (not_after)")]
    fn should_panic_on_invalid_not_after_date() {
        let csp_vault = new_csp_vault();
        let _panic =
            csp_vault.gen_tls_key_pair(node_test_id(test_utils::NODE_1), "invalid_not_after_date");
    }

    #[test]
    #[should_panic(expected = "'not after' date must not be in the past")]
    fn should_panic_if_not_after_date_is_in_the_past() {
        let csp_vault = new_csp_vault();
        let date_in_the_past = "20211004235959Z";

        let _panic = csp_vault.gen_tls_key_pair(node_test_id(test_utils::NODE_1), date_in_the_past);
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
        test_utils::should_sign_with_valid_key(new_csp_vault());
    }

    #[test]
    fn should_sign_verifiably() {
        test_utils::should_sign_verifiably(new_csp_vault());
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_not_found() {
        test_utils::should_fail_to_sign_if_secret_key_not_found(new_csp_vault());
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_in_store_has_wrong_type() {
        test_utils::should_fail_to_sign_if_secret_key_in_store_has_wrong_type(new_csp_vault());
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
                test_utils::csprng_seeded_with(test_utils::FIXED_SEED),
                key_store,
            )
        };
        test_utils::should_fail_to_sign_if_secret_key_in_store_has_invalid_encoding(
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
                test_utils::csprng_seeded_with(test_utils::FIXED_SEED),
                key_store,
            )
        };

        test_utils::should_fail_to_sign_if_secret_key_in_store_has_invalid_length(
            key_id,
            Arc::new(csp_vault),
        );
    }
}
