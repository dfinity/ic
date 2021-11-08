//! TLS handshake operations provided by the CSP server
use crate::keygen::tls_cert_hash_as_key_id;
use crate::secret_key_store::SecretKeyStore;
use crate::server::api::{CspTlsSignError, TlsHandshakeCspServer};
use crate::server::local_csp_server::LocalCspServer;
use crate::types::{CspSecretKey, CspSignature};
use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
use ic_crypto_internal_tls::keygen::generate_tls_key_pair_der;
use ic_crypto_internal_tls::keygen::TlsEd25519SecretKeyDerBytes;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_types::crypto::KeyId;
use ic_types::NodeId;
use openssl::asn1::Asn1Time;
use rand::{CryptoRng, Rng};

#[cfg(test)]
mod tests;

impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore> TlsHandshakeCspServer
    for LocalCspServer<R, S>
{
    fn gen_tls_key_pair(&self, node: NodeId, not_after: &str) -> (KeyId, TlsPublicKeyCert) {
        let serial = self.rng_write_lock().gen::<[u8; 19]>();
        let common_name = &node.get().to_string()[..];
        let not_after = Asn1Time::from_str_x509(not_after)
            .expect("invalid X.509 certificate expiration date (not_after)");
        let (cert, secret_key) = generate_tls_key_pair_der(common_name, serial, &not_after);

        let x509_pk_cert = TlsPublicKeyCert::new_from_der(cert.bytes)
            .expect("generated X509 certificate has malformed DER encoding");
        let key_id = self.store_tls_secret_key(&x509_pk_cert, secret_key);
        (key_id, x509_pk_cert)
    }

    fn sign(&self, message: &[u8], key_id: &KeyId) -> Result<CspSignature, CspTlsSignError> {
        let secret_key: CspSecretKey = self
            .sks_read_lock()
            .get(key_id)
            .ok_or(CspTlsSignError::SecretKeyNotFound { key_id: *key_id })?;

        match secret_key {
            CspSecretKey::TlsEd25519(secret_key_der) => {
                // TODO (CRP-1174): Use internal Ed25519 library as ring keypair is not zeroized
                let ring_keypair = ring_keypair_from_secret_key_pkcs8(&secret_key_der.bytes)?;
                let ring_signature = ring_keypair.sign(message);
                Ok(ed25519_csp_signature_from_ring_signature(ring_signature)?)
            }
            _ => Err(CspTlsSignError::WrongSecretKeyType {
                algorithm: secret_key.algorithm_id(),
            }),
        }
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore> LocalCspServer<R, S> {
    pub(super) fn store_tls_secret_key(
        &self,
        cert: &TlsPublicKeyCert,
        secret_key: TlsEd25519SecretKeyDerBytes,
    ) -> KeyId {
        let key_id = tls_cert_hash_as_key_id(&cert);
        self.store_secret_key_or_panic(CspSecretKey::TlsEd25519(secret_key), key_id);
        key_id
    }
}

fn ring_keypair_from_secret_key_pkcs8(
    secret_key_pkcs8: &[u8],
) -> Result<ring::signature::Ed25519KeyPair, CspTlsSignError> {
    ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(secret_key_pkcs8).map_err(|_e| {
        // `_e` is unused so the secret key cannot be leaked in the error message
        CspTlsSignError::MalformedSecretKey {
            error: "Failed to convert TLS secret key from key store to ring key pair".to_string(),
        }
    })
}

fn ed25519_csp_signature_from_ring_signature(
    ring_signature: ring::signature::Signature,
) -> Result<CspSignature, CspTlsSignError> {
    const SIGNATURE_LEN: usize = ed25519_types::SignatureBytes::SIZE;
    if ring_signature.as_ref().len() != SIGNATURE_LEN {
        return Err(CspTlsSignError::InvalidRingSignatureLength {
            length: ring_signature.as_ref().len(),
        });
    }
    let mut bytes: [u8; SIGNATURE_LEN] = [0; SIGNATURE_LEN];
    bytes.copy_from_slice(ring_signature.as_ref());
    Ok(CspSignature::Ed25519(ed25519_types::SignatureBytes(bytes)))
}
