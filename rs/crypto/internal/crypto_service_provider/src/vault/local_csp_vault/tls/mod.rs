//! TLS handshake operations provided by the CSP vault
use crate::key_id::KeyId;
use crate::public_key_store::{PublicKeySetOnceError, PublicKeyStore};
use crate::secret_key_store::{SecretKeyStore, SecretKeyStoreInsertionError};
use crate::types::{CspSecretKey, CspSignature};
use crate::vault::api::{CspTlsKeygenError, CspTlsSignError, TlsHandshakeCspVault};
use crate::vault::local_csp_vault::LocalCspVault;
use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
use ic_crypto_internal_logmon::metrics::{MetricsDomain, MetricsResult, MetricsScope};
use ic_crypto_internal_tls::keygen::{
    generate_tls_key_pair_der, TlsEd25519SecretKeyDerBytes, TlsKeyPairAndCertGenerationError,
};
use ic_crypto_node_key_validation::ValidTlsCertificate;
use ic_crypto_secrets_containers::{SecretArray, SecretVec};
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
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
        let result = self.gen_tls_key_pair_internal(node, not_after);
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
        &mut PKey::private_key_from_der(secret_key_der.bytes.expose_secret())
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
    fn gen_tls_key_pair_internal(
        &self,
        node: NodeId,
        not_after: &str,
    ) -> Result<TlsPublicKeyCert, CspTlsKeygenError> {
        let common_name = &node.get().to_string()[..];
        let not_after_asn1 = Asn1Time::from_str_x509(not_after).map_err(|_| {
            CspTlsKeygenError::InvalidNotAfterDate {
                message: "invalid X.509 certificate expiration date (not_after)".to_string(),
                not_after: not_after.to_string(),
            }
        })?;
        let secs_since_unix_epoch = (self
            .time_source
            .get_relative_time()
            .as_secs_since_unix_epoch()) as i64;
        let not_before = Asn1Time::from_unix(secs_since_unix_epoch).map_err(|_| {
            CspTlsKeygenError::InternalError {
                internal_error: format!("Failed to convert raw not_before ({secs_since_unix_epoch} seconds since Unix epoch) to Asn1Time"),
            }
        })?;

        let (cert, secret_key) = generate_tls_key_pair_der(
            &mut *self.rng_write_lock(),
            common_name,
            &not_before,
            &not_after_asn1,
        )
        .map_err(
            |TlsKeyPairAndCertGenerationError::InvalidNotAfterDate { message: e }| {
                CspTlsKeygenError::InvalidNotAfterDate {
                    message: e,
                    not_after: not_after.to_string(),
                }
            },
        )?;
        let x509_pk_cert = TlsPublicKeyCert::new_from_der(cert.bytes).map_err(|err| {
            CspTlsKeygenError::InternalError {
                internal_error: format!(
                    "generated X509 certificate has malformed DER encoding: {}",
                    err
                ),
            }
        })?;

        let key_id =
            KeyId::try_from(&x509_pk_cert).map_err(|error| CspTlsKeygenError::InternalError {
                internal_error: format!("Cannot instantiate KeyId: {:?}", error),
            })?;
        let secret_key = CspSecretKey::TlsEd25519(secret_key);
        let cert_proto = x509_pk_cert.to_proto();
        let valid_cert = validate_tls_certificate(cert_proto, node)?;
        self.store_tls_key_pair(key_id, secret_key, valid_cert.get().clone())?;

        Ok(x509_pk_cert)
    }

    fn store_tls_key_pair(
        &self,
        key_id: KeyId,
        secret_key: CspSecretKey,
        cert_proto: X509PublicKeyCert,
    ) -> Result<(), CspTlsKeygenError> {
        let (mut sks_write_lock, mut pks_write_lock) = self.sks_and_pks_write_locks();
        sks_write_lock
            .insert(key_id, secret_key, None)
            .map_err(|sks_error| match sks_error {
                SecretKeyStoreInsertionError::DuplicateKeyId(key_id) => {
                    CspTlsKeygenError::DuplicateKeyId { key_id }
                }
                SecretKeyStoreInsertionError::SerializationError(serialization_error) => {
                    CspTlsKeygenError::InternalError {
                        internal_error: format!(
                            "Error persisting secret key store during CSP TLS key generation: {}",
                            serialization_error
                        ),
                    }
                }
                SecretKeyStoreInsertionError::TransientError(io_error) => {
                    CspTlsKeygenError::TransientInternalError {
                        internal_error: format!(
                            "Error persisting secret key store during CSP TLS key generation: {}",
                            io_error
                        ),
                    }
                }
            })
            .and_then(|()| {
                pks_write_lock
                    .set_once_tls_certificate(cert_proto)
                    .map_err(|e| match e {
                        PublicKeySetOnceError::AlreadySet => CspTlsKeygenError::InternalError {
                            internal_error: "TLS certificate already set".to_string(),
                        },
                        PublicKeySetOnceError::Io(io_error) => {
                            CspTlsKeygenError::TransientInternalError {
                                internal_error: format!(
                                    "IO error persisting TLS certificate: {}",
                                    io_error
                                ),
                            }
                        }
                    })
            })
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

fn validate_tls_certificate(
    cert_proto: X509PublicKeyCert,
    node: NodeId,
) -> Result<ValidTlsCertificate, CspTlsKeygenError> {
    ValidTlsCertificate::try_from((cert_proto, node)).map_err(|error| {
        CspTlsKeygenError::InternalError {
            internal_error: format!("TLS certificate validation error: {}", error),
        }
    })
}
