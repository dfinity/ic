//! TLS handshake operations provided by the CSP vault
use crate::key_id::KeyId;
use crate::public_key_store::{PublicKeySetOnceError, PublicKeyStore};
use crate::secret_key_store::{SecretKeyStore, SecretKeyStoreInsertionError};
use crate::types::{CspSecretKey, CspSignature};
use crate::vault::api::{CspTlsKeygenError, CspTlsSignError, TlsHandshakeCspVault};
use crate::vault::local_csp_vault::LocalCspVault;
use ic_crypto_internal_logmon::metrics::{MetricsDomain, MetricsResult, MetricsScope};
use ic_crypto_internal_tls::{generate_tls_key_pair_der, TlsKeyPairAndCertGenerationError};
use ic_crypto_node_key_validation::ValidTlsCertificate;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_types::crypto::AlgorithmId;
use ic_types::{NodeId, Time};
use rand::{CryptoRng, Rng};
use std::time::Duration;
use time::macros::format_description;
use time::PrimitiveDateTime;

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

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    LocalCspVault<R, S, C, P>
{
    fn gen_tls_key_pair_internal(
        &self,
        node: NodeId,
        not_after: &str,
    ) -> Result<TlsPublicKeyCert, CspTlsKeygenError> {
        const TWO_MINUTES: Duration = Duration::from_secs(120);

        let issuance_time: Time = self
            .time_source
            .get_relative_time()
            .saturating_sub_duration(TWO_MINUTES);

        let common_name = &node.get().to_string()[..];
        let not_after_u64 = asn1_time_string_to_unix_timestamp(not_after)?;

        let (cert, secret_key) = generate_tls_key_pair_der(
            &mut *self.rng_write_lock(),
            common_name,
            issuance_time.as_secs_since_unix_epoch(),
            not_after_u64,
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
        let valid_cert = validate_tls_certificate(cert_proto, node, issuance_time)?;
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

        match &secret_key {
            CspSecretKey::TlsEd25519(secret_key_der) => {
                let secret_key_bytes =
                    ic_crypto_internal_basic_sig_ed25519::secret_key_from_pkcs8_v1_der(
                        &secret_key_der.bytes,
                    )
                    .map_err(|e| {
                        CspTlsSignError::MalformedSecretKey {
                            error: format!("Failed to convert TLS secret key DER from key store to Ed25519 secret key: {e:?}")
                    }})?;

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
        }
    }
}

fn validate_tls_certificate(
    cert_proto: X509PublicKeyCert,
    node: NodeId,
    current_time: Time,
) -> Result<ValidTlsCertificate, CspTlsKeygenError> {
    ValidTlsCertificate::try_from((cert_proto, node, current_time)).map_err(|error| {
        CspTlsKeygenError::InternalError {
            internal_error: format!("TLS certificate validation error: {}", error),
        }
    })
}

fn asn1_time_string_to_unix_timestamp(time_asn1: &str) -> Result<u64, CspTlsKeygenError> {
    let asn1_format = format_description!("[year][month][day][hour][minute][second]Z"); // e.g., 99991231235959Z
    let time_primitivedatetime = PrimitiveDateTime::parse(time_asn1, asn1_format)
        .map_err(|_e| CspTlsKeygenError::InvalidArguments {
            message: format!("invalid X.509 certificate expiration date (notAfter={time_asn1}): failed to parse ASN1 datetime format"),
        })?;
    let time_i64 = time_primitivedatetime.assume_utc().unix_timestamp();
    let time_u64 = u64::try_from(time_i64).map_err(|_e| CspTlsKeygenError::InvalidArguments {
        message: format!(
            "invalid X.509 certificate expiration date (notAfter={time_asn1}): failed to convert to u64"
        ),
    })?;
    Ok(time_u64)
}

impl From<TlsKeyPairAndCertGenerationError> for CspTlsKeygenError {
    fn from(tls_keys_generation_error: TlsKeyPairAndCertGenerationError) -> Self {
        match tls_keys_generation_error {
            TlsKeyPairAndCertGenerationError::InvalidArguments(e) => {
                Self::InvalidArguments { message: e }
            }
            TlsKeyPairAndCertGenerationError::InternalError(e) => {
                Self::InternalError { internal_error: e }
            }
        }
    }
}
