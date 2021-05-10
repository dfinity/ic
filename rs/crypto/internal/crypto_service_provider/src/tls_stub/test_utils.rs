#![allow(clippy::unwrap_used)]
use crate::keygen::tls_cert_hash_as_key_id;
use crate::secret_key_store::test_utils::TempSecretKeyStore;
use crate::secret_key_store::SecretKeyStore;
use crate::types::CspSecretKey;
use ic_crypto_internal_tls::keygen::{TlsEd25519CertificateDerBytes, TlsEd25519SecretKeyDerBytes};
use ic_crypto_test_utils::tls::x509_certificates::{cert_to_der, private_key_to_der};
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_types::crypto::KeyId;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use rand::Rng;
use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, SeedableRng};

pub fn tls_secret_key(private_key: &PKey<Private>) -> CspSecretKey {
    tls_secret_key_with_bytes(private_key_to_der(&private_key))
}

pub fn tls_secret_key_with_bytes(bytes: Vec<u8>) -> CspSecretKey {
    CspSecretKey::TlsEd25519(TlsEd25519SecretKeyDerBytes { bytes })
}

pub fn secret_key_store_with_key(private_key: &PKey<Private>, cert: &X509) -> impl SecretKeyStore {
    let secret_key = tls_secret_key(private_key);
    secret_key_store_with_csp_key(cert, secret_key)
}

pub fn secret_key_store_with_csp_key(cert: &X509, csp_key: CspSecretKey) -> impl SecretKeyStore {
    let key_id = key_id_for_cert(&cert_to_der(&cert));
    let mut sks = TempSecretKeyStore::new();
    let scope = None;
    sks.insert(key_id, csp_key, scope).unwrap();
    sks
}

pub fn dummy_csprng() -> impl CryptoRng + Rng {
    ChaChaRng::seed_from_u64(42)
}

pub fn key_id_for_cert(cert_der: &[u8]) -> KeyId {
    tls_cert_hash_as_key_id(&TlsEd25519CertificateDerBytes {
        bytes: cert_der.to_vec(),
    })
}

pub fn malformed_cert() -> X509PublicKeyCert {
    X509PublicKeyCert {
        certificate_der: vec![42; 10],
    }
}
