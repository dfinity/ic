//! TLS handshake operations provided by the CSP vault
use crate::key_id::KeyId;
use crate::public_key_store::{PublicKeySetOnceError, PublicKeyStore};
use crate::secret_key_store::SecretKeyStore;
use crate::types::{CspSecretKey, CspSignature};
use crate::vault::api::{CspTlsKeygenError, CspTlsSignError, TlsHandshakeCspVault};
use crate::vault::local_csp_vault::LocalCspVault;
use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
use ic_crypto_internal_logmon::metrics::{MetricsDomain, MetricsResult, MetricsScope};
use ic_crypto_internal_tls::keygen::{
    generate_tls_key_pair_der, TlsEd25519SecretKeyDerBytes, TlsKeyPairAndCertGenerationError,
};
use ic_crypto_secrets_containers::{SecretArray, SecretVec};
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_types::crypto::AlgorithmId;
use ic_types::NodeId;
use openssl::asn1::Asn1Time;
use openssl::pkey::PKey;
use rand::{CryptoRng, Rng};

#[cfg(test)]
mod tests;

impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    TlsHandshakeCspVault for LocalCspVault<R, S, C, P>
{
    fn gen_tls_key_pair(
        &self,
        node: NodeId,
        not_after: &str,
    ) -> Result<TlsPublicKeyCert, CspTlsKeygenError> {
        let start_time = self.metrics.now();
        let (sk, cert) = self.gen_tls_key_pair_internal(node, not_after)?;
        let result = self
            .store_tls_secret_key(&cert, sk)
            .and_then(|_key_id| self.store_tls_certificate(&cert).map(|()| cert));

        self.metrics.observe_duration_seconds(
            MetricsDomain::TlsHandshake,
            MetricsScope::Local,
            "gen_tls_key_pair",
            MetricsResult::from(&result),
            start_time,
        );
        result
    }

    fn tls_sign(&self, message: &[u8], key_id: &KeyId) -> Result<CspSignature, CspTlsSignError> {
        let start_time = self.metrics.now();
        let result = self.tls_sign_internal(message, key_id);
        self.metrics.observe_duration_seconds(
            MetricsDomain::TlsHandshake,
            MetricsScope::Local,
            "tls_sign",
            MetricsResult::from(&result),
            start_time,
        );
        result
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

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    LocalCspVault<R, S, C, P>
{
    fn store_tls_secret_key(
        &self,
        cert: &TlsPublicKeyCert,
        secret_key: TlsEd25519SecretKeyDerBytes,
    ) -> Result<KeyId, CspTlsKeygenError> {
        let key_id = KeyId::from(cert);
        self.store_secret_key(CspSecretKey::TlsEd25519(secret_key), key_id)?;
        Ok(key_id)
    }

    fn store_tls_certificate(&self, cert: &TlsPublicKeyCert) -> Result<(), CspTlsKeygenError> {
        self.public_key_store_write_lock()
            .set_once_tls_certificate(cert.clone().to_proto())
            .map_err(|e| match e {
                PublicKeySetOnceError::AlreadySet => CspTlsKeygenError::InternalError {
                    internal_error: "TLS certificate already set".to_string(),
                },
                PublicKeySetOnceError::Io(io_error) => CspTlsKeygenError::TransientInternalError {
                    internal_error: format!("IO error: {}", io_error),
                },
            })?;
        Ok(())
    }

    fn gen_tls_key_pair_internal(
        &self,
        node: NodeId,
        not_after: &str,
    ) -> Result<(TlsEd25519SecretKeyDerBytes, TlsPublicKeyCert), CspTlsKeygenError> {
        let common_name = &node.get().to_string()[..];
        let not_after_asn1 = Asn1Time::from_str_x509(not_after).map_err(|_| {
            CspTlsKeygenError::InvalidNotAfterDate {
                message: "invalid X.509 certificate expiration date (not_after)".to_string(),
                not_after: not_after.to_string(),
            }
        })?;

        let (cert, secret_key) =
            generate_tls_key_pair_der(&mut *self.rng_write_lock(), common_name, &not_after_asn1)
                .map_err(
                    |TlsKeyPairAndCertGenerationError::InvalidNotAfterDate { message: e }| {
                        CspTlsKeygenError::InvalidNotAfterDate {
                            message: e,
                            not_after: not_after.to_string(),
                        }
                    },
                )?;

        let x509_pk_cert = TlsPublicKeyCert::new_from_der(cert.bytes)
            .expect("generated X509 certificate has malformed DER encoding");
        Ok((secret_key, x509_pk_cert))
    }

    fn tls_sign_internal(
        &self,
        message: &[u8],
        key_id: &KeyId,
    ) -> Result<CspSignature, CspTlsSignError> {
        let maybe_secret_key = self.sks_read_lock().get(key_id);
        let secret_key: CspSecretKey =
            maybe_secret_key.ok_or(CspTlsSignError::SecretKeyNotFound { key_id: *key_id })?;

        let result = match &secret_key {
            CspSecretKey::TlsEd25519(secret_key_der) => {
                let secret_key_bytes = ed25519_secret_key_bytes_from_der(secret_key_der)?;

                let signature_bytes =
                    ic_crypto_internal_basic_sig_ed25519::sign(message, &secret_key_bytes)
                        .map_err(|e| CspTlsSignError::SigningFailed {
                            error: format!("{}", e),
                        })?;

                Ok(CspSignature::Ed25519(signature_bytes))
            }
            _ => Err(CspTlsSignError::WrongSecretKeyType {
                algorithm: AlgorithmId::Tls,
                secret_key_variant: secret_key.enum_variant().to_string(),
            }),
        };
        result
    }
}
