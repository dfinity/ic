//! Utilities for testing `CspVault`-implementations

pub mod idkg;
pub mod ni_dkg;
pub mod pks_and_sks;
pub mod sks;
pub mod threshold_sig;

use crate::types::CspPublicKey;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
pub fn ed25519_csp_pubkey_from_tls_pubkey_cert(public_key_cert: &TlsPublicKeyCert) -> CspPublicKey {
    use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
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
