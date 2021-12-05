use crate::api::CspSigner;
use crate::keygen::tls_cert_hash_as_key_id;
use crate::secret_key_store::test_utils::TempSecretKeyStore;
use crate::types::CspPublicKey;
use crate::vault::api::{CspTlsSignError, CspVault};
use crate::{CryptoServiceProvider, Csp};
use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_types::crypto::{AlgorithmId, KeyId};
use ic_types_test_utils::ids::node_test_id;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::nid::Nid;
use openssl::x509::{X509NameEntries, X509VerifyResult, X509};
use rand::{thread_rng, CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeSet;
use std::sync::Arc;

pub const NODE_1: u64 = 4241;
pub const FIXED_SEED: u64 = 42;
pub const NOT_AFTER: &str = "25670102030405Z";

pub fn should_insert_secret_key_into_key_store(csp_vault: Arc<dyn CspVault>) {
    let (key_id, cert) = csp_vault
        .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
        .expect("Generation of TLS keys failed.");
    assert_eq!(key_id, tls_cert_hash_as_key_id(&cert));
    assert!(csp_vault.sks_contains(&key_id));
}

pub fn should_return_der_encoded_self_signed_certificate(csp_vault: Arc<dyn CspVault>) {
    let (_key_id, cert) = csp_vault
        .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
        .expect("Generation of TLS keys failed.");

    let x509_cert = cert.as_x509();
    let public_key = x509_cert
        .public_key()
        .expect("Missing public key in a certificate.");
    assert_eq!(x509_cert.verify(&public_key).ok(), Some(true));
    assert_eq!(x509_cert.issued(x509_cert), X509VerifyResult::OK);
}

pub fn should_set_cert_subject_cn_as_node_id(csp_vault: Arc<dyn CspVault>) {
    let (_key_id, cert) = csp_vault
        .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
        .expect("Generation of TLS keys failed.");

    let x509_cert = cert.as_x509();
    assert_eq!(cn_entries(x509_cert).count(), 1);
    let subject_cn = cn_entries(x509_cert)
        .next()
        .expect("Missing 'subject CN' entry in a certificate");
    let expected_subject_cn = node_test_id(NODE_1).get().to_string();
    assert_eq!(expected_subject_cn.as_bytes(), subject_cn.data().as_slice());
}

pub fn should_use_stable_node_id_string_representation_as_subject_cn(csp_vault: Arc<dyn CspVault>) {
    let (_key_id, cert) = csp_vault
        .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
        .expect("Generation of TLS keys failed.");

    let subject_cn = cn_entries(cert.as_x509())
        .next()
        .expect("Missing 'subject CN' entry in a certificate");
    assert_eq!(b"w43gn-nurca-aaaaa-aaaap-2ai", subject_cn.data().as_slice());
}

pub fn should_set_cert_issuer_cn_as_node_id(csp_vault: Arc<dyn CspVault>) {
    let (_key_id, cert) = csp_vault
        .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
        .expect("Generation of TLS keys failed.");

    let issuer_cn = cert
        .as_x509()
        .issuer_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .expect("Missing 'issuer CN' entry in a certificate");
    let expected_issuer_cn = node_test_id(NODE_1).get().to_string();
    assert_eq!(expected_issuer_cn.as_bytes(), issuer_cn.data().as_slice());
}

pub fn should_not_set_cert_subject_alt_name(csp_vault: Arc<dyn CspVault>) {
    let (_key_id, cert) = csp_vault
        .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
        .expect("Generation of TLS keys failed.");

    let subject_alt_names = cert.as_x509().subject_alt_names();
    assert!(subject_alt_names.is_none());
}

pub fn should_set_random_cert_serial_number(csp_vault: Arc<dyn CspVault>) {
    let (_key_id, cert) = csp_vault
        .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
        .expect("Generation of TLS keys failed.");

    let cert_serial = cert
        .as_x509()
        .serial_number()
        .to_bn()
        .expect("Failed parsing SN as BigNum.");
    let expected_randomness = csprng_seeded_with(FIXED_SEED).gen::<[u8; 19]>();
    let expected_serial =
        BigNum::from_slice(&expected_randomness).expect("Failed parsing random bits as BigNum");
    assert_eq!(expected_serial, cert_serial);
}

pub fn should_set_different_serial_numbers_for_multiple_certs(csp_vault: Arc<dyn CspVault>) {
    const SAMPLE_SIZE: usize = 20;
    let mut serial_samples = BTreeSet::new();
    for _i in 0..SAMPLE_SIZE {
        let (_key_id, cert) = csp_vault
            .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
            .expect("Generation of TLS keys failed.");
        serial_samples.insert(serial_number(&cert));
    }
    assert_eq!(serial_samples.len(), SAMPLE_SIZE);
}

pub fn should_set_cert_not_after_correctly(csp_vault: Arc<dyn CspVault>) {
    let (_key_id, cert) = csp_vault
        .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
        .expect("Generation of TLS keys failed.");
    assert!(
        cert.as_x509().not_after()
            == Asn1Time::from_str_x509(NOT_AFTER).expect("Failed parsing string as Asn1Time")
    );
}

fn cn_entries(x509_cert: &X509) -> X509NameEntries {
    x509_cert.subject_name().entries_by_nid(Nid::COMMONNAME)
}

pub fn csprng_seeded_with(seed: u64) -> impl CryptoRng + Rng + Clone {
    ChaCha20Rng::seed_from_u64(seed)
}

fn serial_number(cert: &TlsPublicKeyCert) -> BigNum {
    cert.as_x509()
        .serial_number()
        .to_bn()
        .expect("Failed parsing SN as BigNum")
}

pub fn should_sign_with_valid_key(csp_vault: Arc<dyn CspVault>) {
    let (key_id, _public_key_cert) = csp_vault
        .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
        .expect("Generation of TLS keys failed.");

    assert!(csp_vault.tls_sign(&random_message(), &key_id).is_ok());
}

pub fn should_sign_verifiably(csp_vault: Arc<dyn CspVault>) {
    let verifier = verifier();
    let (key_id, public_key_cert) = csp_vault
        .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
        .expect("Generation of TLS keys failed.");
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
