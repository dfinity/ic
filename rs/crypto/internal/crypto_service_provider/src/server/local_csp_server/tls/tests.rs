#![allow(clippy::unwrap_used)]
use super::*;
use crate::secret_key_store::test_utils::TempSecretKeyStore;
use ic_types_test_utils::ids::node_test_id;
use openssl::x509::{X509NameEntries, X509VerifyResult, X509};
use openssl::{bn::BigNum, nid::Nid, pkey::Id, pkey::PKey};
use rand::{thread_rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

const NODE_1: u64 = 4241;
const FIXED_SEED: u64 = 42;
const NOT_AFTER: &str = "25670102030405Z";

mod keygen {
    use super::*;
    use crate::secret_key_store::test_utils::MockSecretKeyStore;
    use crate::secret_key_store::SecretKeyStoreError;
    use std::collections::BTreeSet;

    #[test]
    fn should_insert_secret_key_into_store_in_der_format() {
        let mut csp_server = csp_server_with_empty_key_store();

        let (_key_id, cert) = csp_server.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        let secret_key = secret_key_from_store(&mut csp_server, cert.as_x509().clone());
        if let CspSecretKey::TlsEd25519(sk_der_bytes) = secret_key {
            let private_key = PKey::private_key_from_der(&sk_der_bytes.bytes)
                .expect("unable to parse DER secret key");
            assert_eq!(private_key.id(), Id::ED25519);
        } else {
            panic!("secret key has the wrong type");
        }
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

        let csp_server = {
            let csprng = ChaCha20Rng::from_seed(thread_rng().gen::<[u8; 32]>());
            LocalCspServer::new_for_test(csprng, sks_returning_error_on_insert)
        };

        let _ = csp_server.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);
    }

    #[test]
    fn should_return_der_encoded_self_signed_certificate() {
        let csp_server = csp_server_with_empty_key_store();

        let (_key_id, cert) = csp_server.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        let x509_cert = cert.as_x509();
        let public_key = x509_cert.public_key().unwrap();
        assert_eq!(x509_cert.verify(&public_key).ok(), Some(true));
        assert_eq!(x509_cert.issued(&x509_cert), X509VerifyResult::OK);
    }

    #[test]
    fn should_set_cert_subject_cn_as_node_id() {
        let csp_server = csp_server_with_empty_key_store();

        let (_key_id, cert) = csp_server.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        let x509_cert = cert.as_x509();
        assert_eq!(cn_entries(&x509_cert).count(), 1);
        let subject_cn = cn_entries(&x509_cert).next().unwrap();
        let expected_subject_cn = node_test_id(NODE_1).get().to_string();
        assert_eq!(expected_subject_cn.as_bytes(), subject_cn.data().as_slice());
    }

    #[test]
    fn should_use_stable_node_id_string_representation_as_subject_cn() {
        let csp_server = csp_server_with_empty_key_store();

        let (_key_id, cert) = csp_server.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        let subject_cn = cn_entries(&cert.as_x509()).next().unwrap();
        assert_eq!(b"w43gn-nurca-aaaaa-aaaap-2ai", subject_cn.data().as_slice());
    }

    #[test]
    fn should_set_cert_issuer_cn_as_node_id() {
        let csp_server = csp_server_with_empty_key_store();

        let (_key_id, cert) = csp_server.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        let issuer_cn = cert
            .as_x509()
            .issuer_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .unwrap();
        let expected_issuer_cn = node_test_id(NODE_1).get().to_string();
        assert_eq!(expected_issuer_cn.as_bytes(), issuer_cn.data().as_slice());
    }

    #[test]
    fn should_not_set_cert_subject_alt_name() {
        let csp_server = csp_server_with_empty_key_store();

        let (_key_id, cert) = csp_server.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        let subject_alt_names = cert.as_x509().subject_alt_names();
        assert!(subject_alt_names.is_none());
    }

    #[test]
    fn should_set_random_cert_serial_number() {
        let csp_server = {
            let key_store = TempSecretKeyStore::new();
            LocalCspServer::new_for_test(csprng_seeded_with(FIXED_SEED), key_store)
        };

        let (_key_id, cert) = csp_server.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        let cert_serial = cert.as_x509().serial_number().to_bn().unwrap();
        let expected_randomness = csprng_seeded_with(FIXED_SEED).gen::<[u8; 19]>();
        let expected_serial = BigNum::from_slice(&expected_randomness).unwrap();
        assert_eq!(expected_serial, cert_serial);
    }

    #[test]
    fn should_set_different_serial_numbers_for_multiple_certs() {
        let csp_server = csp_server_with_empty_key_store();

        const SAMPLE_SIZE: usize = 20;
        let mut serial_samples = BTreeSet::new();
        for _i in 0..SAMPLE_SIZE {
            let (_key_id, cert) = csp_server.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);
            serial_samples.insert(serial_number(&cert));
        }
        assert_eq!(serial_samples.len(), SAMPLE_SIZE);
    }

    #[test]
    fn should_set_cert_not_after_correctly() {
        let csp_server = csp_server_with_empty_key_store();
        let not_after = NOT_AFTER;

        let (_key_id, cert) = csp_server.gen_tls_key_pair(node_test_id(NODE_1), not_after);

        assert!(cert.as_x509().not_after() == Asn1Time::from_str_x509(not_after).unwrap());
    }

    #[test]
    #[should_panic(expected = "invalid X.509 certificate expiration date (not_after)")]
    fn should_panic_on_invalid_not_after_date() {
        let csp_server = csp_server_with_empty_key_store();

        let _panic = csp_server.gen_tls_key_pair(node_test_id(NODE_1), "invalid_not_after_date");
    }

    #[test]
    #[should_panic(expected = "'not after' date must not be in the past")]
    fn should_panic_if_not_after_date_is_in_the_past() {
        let csp_server = csp_server_with_empty_key_store();
        let date_in_the_past = "20211004235959Z";

        let _panic = csp_server.gen_tls_key_pair(node_test_id(NODE_1), &date_in_the_past);
    }

    fn secret_key_from_store(
        csp_server: &mut LocalCspServer<impl CryptoRng + Rng, TempSecretKeyStore>,
        x509_cert: X509,
    ) -> CspSecretKey {
        let cert = TlsPublicKeyCert::new_from_x509(x509_cert)
            .expect("failed to convert X509 into TlsPublicKeyCert");
        let key_id = tls_cert_hash_as_key_id(&cert);
        csp_server
            .sks_read_lock()
            .get(&key_id)
            .expect("secret key not found")
    }

    fn cn_entries(x509_cert: &X509) -> X509NameEntries {
        x509_cert.subject_name().entries_by_nid(Nid::COMMONNAME)
    }

    fn csprng_seeded_with(seed: u64) -> impl CryptoRng + Rng + Clone {
        ChaCha20Rng::seed_from_u64(seed)
    }

    fn serial_number(cert: &TlsPublicKeyCert) -> BigNum {
        cert.as_x509().serial_number().to_bn().unwrap()
    }
}

mod sign {
    use super::*;
    use crate::api::CspSigner;
    use crate::server::api::TlsHandshakeCspServer;
    use crate::types::CspPublicKey;
    use crate::Csp;
    use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
    use ic_types::crypto::AlgorithmId;

    #[test]
    fn should_sign_with_valid_key() {
        let csp_server = csp_server_with_empty_key_store();
        let (key_id, _public_key_cert) =
            csp_server.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        assert!(csp_server.sign(&random_message(), &key_id).is_ok());
    }

    #[test]
    fn should_sign_verifiably() {
        let csp_server = csp_server_with_empty_key_store();
        let verifier = verifier();
        let (key_id, public_key_cert) =
            csp_server.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);
        let msg = random_message();

        let sig = csp_server
            .sign(&msg, &key_id)
            .expect("failed to generate signature");

        let csp_pub_key = ed25519_csp_pubkey_from_tls_pubkey_cert(&public_key_cert);
        assert!(verifier
            .verify(&sig, &msg, AlgorithmId::Ed25519, csp_pub_key)
            .is_ok());
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_not_found() {
        let csp_server = csp_server_with_empty_key_store();
        let non_existent_key_id = KeyId(b"non-existent-key-id-000000000000".to_owned());

        let result = csp_server.sign(b"message", &non_existent_key_id);

        assert_eq!(
            result.unwrap_err(),
            CspTlsSignError::SecretKeyNotFound {
                key_id: non_existent_key_id
            }
        );
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_in_store_has_wrong_type() {
        let csp_server = csp_server_with_empty_key_store();
        use crate::server::api::BasicSignatureCspServer;
        let (key_id, _wrong_csp_pub_key) =
            BasicSignatureCspServer::gen_key_pair(&csp_server, AlgorithmId::Ed25519)
                .expect("failed to generate keys");
        let msg = random_message();

        let result = TlsHandshakeCspServer::sign(&csp_server, &msg, &key_id);

        assert_eq!(
            result.unwrap_err(),
            CspTlsSignError::WrongSecretKeyType {
                algorithm: AlgorithmId::Ed25519
            }
        );
    }

    fn verifier() -> Csp<ChaCha20Rng, TempSecretKeyStore> {
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

fn csp_server_with_empty_key_store() -> LocalCspServer<ChaCha20Rng, TempSecretKeyStore> {
    let key_store = TempSecretKeyStore::new();
    let csprng = ChaCha20Rng::from_seed(thread_rng().gen::<[u8; 32]>());
    LocalCspServer::new_for_test(csprng, key_store)
}
