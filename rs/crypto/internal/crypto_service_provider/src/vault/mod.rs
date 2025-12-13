use self::api::CspVault;
use self::local_csp_vault::ProdLocalCspVault;
use self::remote_csp_vault::RemoteCspVault;
use crate::vault::api::{
    CspBasicSignatureError, CspMultiSignatureError, CspSecretKeyStoreContainsError,
};
use ic_adapter_metrics_client::AdapterMetrics;
use ic_config::crypto::{CryptoConfig, CspVaultType};
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_logger::{ReplicaLogger, info};
use ic_types::crypto::CryptoError;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub mod api;
pub mod local_csp_vault;
pub mod remote_csp_vault;
#[cfg(test)]
pub mod test_utils;

/// Creates a production-grade crypto vault.
///
/// If the `config`'s vault type is `UnixSocket`, a `tokio_runtime_handle`
/// is provided, which is then used for the `async`hronous communication
/// with the vault via RPC.
///
/// # Panics
/// Panics if the `config`'s vault type is `UnixSocket` and
/// `tokio_runtime_handle` is `None`.
pub fn vault_from_config(
    config: &CryptoConfig,
    tokio_runtime_handle: Option<tokio::runtime::Handle>,
    logger: ReplicaLogger,
    metrics: Arc<CryptoMetrics>,
) -> Arc<dyn CspVault> {
    match &config.csp_vault_type {
        CspVaultType::InReplica => in_replica_vault(config, logger, metrics),
        CspVaultType::UnixSocket {
            logic: logic_socket_path,
            metrics: metrics_socket_path,
        } => unix_socket_vault(
            logic_socket_path,
            metrics_socket_path.as_ref(),
            tokio_runtime_handle.expect("missing tokio runtime handle"),
            config,
            logger,
            metrics,
        ),
    }
}

fn in_replica_vault(
    config: &CryptoConfig,
    logger: ReplicaLogger,
    metrics: Arc<CryptoMetrics>,
) -> Arc<dyn CspVault> {
    info!(
        logger,
        "Proceeding with an in-replica csp_vault, CryptoConfig: {:?}", config
    );
    let vault = ProdLocalCspVault::new_in_dir(&config.crypto_root, metrics, logger);
    Arc::new(vault)
}

fn unix_socket_vault(
    socket_path: &Path,
    metrics_socket_path: Option<&PathBuf>,
    rt_handle: tokio::runtime::Handle,
    config: &CryptoConfig,
    logger: ReplicaLogger,
    metrics: Arc<CryptoMetrics>,
) -> Arc<dyn CspVault> {
    info!(
        logger,
        "Proceeding with a remote csp_vault, CryptoConfig: {:?}", config
    );
    if let (Some(metrics_uds_path), Some(global_metrics)) =
        (metrics_socket_path, metrics.metrics_registry())
    {
        global_metrics.register_adapter(AdapterMetrics::new(
            "cryptocsp",
            metrics_uds_path.clone(),
            rt_handle.clone(),
        ));
    }
    let vault = RemoteCspVault::new(socket_path, rt_handle, logger, metrics).unwrap_or_else(|e| {
        panic!("Could not connect to CspVault at socket {socket_path:?}: {e:?}")
    });
    Arc::new(vault)
}

impl From<CspBasicSignatureError> for CryptoError {
    fn from(e: CspBasicSignatureError) -> CryptoError {
        match e {
            CspBasicSignatureError::SecretKeyNotFound(key_id) => CryptoError::InternalError {
                internal_error: format!(
                    "missing node signing secret key in secret key store (Key ID: {key_id})"
                ),
            },
            CspBasicSignatureError::WrongSecretKeyType { secret_key_variant } => {
                CryptoError::InternalError {
                    internal_error: format!(
                        "the node signing secret key has the wrong type in the secret key store: {secret_key_variant}"
                    ),
                }
            }
            CspBasicSignatureError::TransientInternalError { internal_error } => {
                CryptoError::TransientInternalError { internal_error }
            }
            CspBasicSignatureError::PublicKeyNotFound => CryptoError::InternalError {
                internal_error: "missing node signing public key in public key store".to_string(),
            },
            CspBasicSignatureError::MalformedPublicKey(error) => CryptoError::InternalError {
                internal_error: format!(
                    "malformed node signing public key in public key store: {error}"
                ),
            },
        }
    }
}

impl From<CspMultiSignatureError> for CryptoError {
    fn from(e: CspMultiSignatureError) -> CryptoError {
        match e {
            CspMultiSignatureError::SecretKeyNotFound { algorithm, key_id } => {
                CryptoError::SecretKeyNotFound {
                    algorithm,
                    key_id: key_id.to_string(),
                }
            }
            CspMultiSignatureError::UnsupportedAlgorithm { algorithm } => {
                CryptoError::AlgorithmNotSupported {
                    algorithm,
                    reason: "Unsupported algorithm".to_string(),
                }
            }
            CspMultiSignatureError::WrongSecretKeyType {
                algorithm,
                secret_key_variant,
            } => CryptoError::InvalidArgument {
                message: format!(
                    "Wrong secret key type: expected {algorithm:?} but found {secret_key_variant}"
                ),
            },
            CspMultiSignatureError::TransientInternalError { internal_error } => {
                CryptoError::TransientInternalError { internal_error }
            }
        }
    }
}

impl From<CspSecretKeyStoreContainsError> for CryptoError {
    fn from(e: CspSecretKeyStoreContainsError) -> Self {
        match e {
            CspSecretKeyStoreContainsError::TransientInternalError { internal_error } => {
                CryptoError::TransientInternalError { internal_error }
            }
        }
    }
}
