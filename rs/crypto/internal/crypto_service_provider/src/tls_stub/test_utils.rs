#![allow(clippy::unwrap_used)]
use crate::keygen::tls_cert_hash_as_key_id;
use crate::secret_key_store::test_utils::TempSecretKeyStore;
use crate::secret_key_store::SecretKeyStore;
use crate::types::CspSecretKey;
use ic_crypto_internal_tls::keygen::TlsEd25519SecretKeyDerBytes;
use ic_crypto_test_utils::tls::x509_certificates::private_key_to_der;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use openssl::pkey::{PKey, Private};
use rand::Rng;
use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, SeedableRng};

pub fn tls_secret_key(private_key: &PKey<Private>) -> CspSecretKey {
    tls_secret_key_with_bytes(private_key_to_der(private_key))
}

pub fn tls_secret_key_with_bytes(bytes: Vec<u8>) -> CspSecretKey {
    CspSecretKey::TlsEd25519(TlsEd25519SecretKeyDerBytes { bytes })
}

pub fn secret_key_store_with_key(
    private_key: &PKey<Private>,
    cert: &TlsPublicKeyCert,
) -> impl SecretKeyStore {
    let secret_key = tls_secret_key(private_key);
    secret_key_store_with_csp_key(cert, secret_key)
}

pub fn secret_key_store_with_csp_key(
    cert: &TlsPublicKeyCert,
    csp_key: CspSecretKey,
) -> impl SecretKeyStore {
    let key_id = tls_cert_hash_as_key_id(cert);
    let mut sks = TempSecretKeyStore::new();
    let scope = None;
    sks.insert(key_id, csp_key, scope).unwrap();
    sks
}

pub fn dummy_csprng() -> impl CryptoRng + Rng + Clone {
    ChaChaRng::seed_from_u64(42)
}
