//! TLS handshake operations provided by the CSP vault
use crate::keygen::tls_cert_hash_as_key_id;
use crate::secret_key_store::SecretKeyStore;
use crate::server::api::{CspTlsSignError, TlsHandshakeCspVault};
use crate::server::local_csp_server::LocalCspVault;
use crate::types::{CspSecretKey, CspSignature};
use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
use ic_crypto_internal_tls::keygen::generate_tls_key_pair_der;
use ic_crypto_internal_tls::keygen::TlsEd25519SecretKeyDerBytes;
use ic_crypto_secrets_containers::{SecretArray, SecretVec};
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_types::crypto::KeyId;
use ic_types::NodeId;
use openssl::asn1::Asn1Time;
use openssl::pkey::PKey;
use rand::{CryptoRng, Rng};

#[cfg(test)]
mod tests;

impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore, C: SecretKeyStore> TlsHandshakeCspVault
    for LocalCspVault<R, S, C>
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
                let secret_key_bytes = ed25519_secret_key_bytes_from_der(&secret_key_der)?;

                let signature_bytes =
                    ic_crypto_internal_basic_sig_ed25519::sign(message, &secret_key_bytes)
                        .map_err(|e| CspTlsSignError::SigningFailed {
                            error: format!("{}", e),
                        })?;

                Ok(CspSignature::Ed25519(signature_bytes))
            }
            _ => Err(CspTlsSignError::WrongSecretKeyType {
                algorithm: secret_key.algorithm_id(),
            }),
        }
    }
}

fn ed25519_secret_key_bytes_from_der(
    secret_key_der: &TlsEd25519SecretKeyDerBytes,
) -> Result<ed25519_types::SecretKeyBytes, CspTlsSignError> {
    // TODO (CRP-1229): Ensure proper zeroization of TLS secret key bytes
    let raw_private_key = SecretVec::new_and_zeroize_argument(
        &mut PKey::private_key_from_der(&secret_key_der.bytes)
            .map_err(
                |_ignore_error_to_prevent_key_leakage| CspTlsSignError::MalformedSecretKey {
                    error:
                        "Failed to convert TLS secret key DER from key store to OpenSSL private key"
                            .to_string(),
                },
            )?
            .raw_private_key()
            .map_err(|_ignore_error_to_prevent_key_leakage| {
                CspTlsSignError::MalformedSecretKey {
                    error: "Failed to get OpenSSL private key in raw form".to_string(),
                }
            })?,
    );

    const SECRET_KEY_LEN: usize = ed25519_types::SecretKeyBytes::SIZE;
    if raw_private_key.expose_secret().len() != SECRET_KEY_LEN {
        return Err(CspTlsSignError::MalformedSecretKey {
            error: format!(
                "Invalid length of raw OpenSSL private key: expected {} bytes, but got {}",
                SECRET_KEY_LEN,
                raw_private_key.expose_secret().len(),
            ),
        });
    }
    let mut sk_bytes_array: [u8; SECRET_KEY_LEN] = [0; SECRET_KEY_LEN];
    sk_bytes_array.copy_from_slice(raw_private_key.expose_secret());

    Ok(ed25519_types::SecretKeyBytes(
        SecretArray::new_and_zeroize_argument(&mut sk_bytes_array),
    ))
}

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore> LocalCspVault<R, S, C> {
    pub(super) fn store_tls_secret_key(
        &self,
        cert: &TlsPublicKeyCert,
        secret_key: TlsEd25519SecretKeyDerBytes,
    ) -> KeyId {
        let key_id = tls_cert_hash_as_key_id(cert);
        self.store_secret_key_or_panic(CspSecretKey::TlsEd25519(secret_key), key_id);
        key_id
    }
}
