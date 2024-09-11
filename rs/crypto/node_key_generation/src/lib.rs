//! Static crypto utility methods.
use ic_config::crypto::CryptoConfig;
use ic_crypto_internal_csp::api::CspCreateMEGaKeyError;
use ic_crypto_internal_csp::vault::api::{CspVault, ValidatePksAndSksError};
use ic_crypto_internal_csp::vault::vault_from_config;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_node_key_validation::ValidNodePublicKeys;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_crypto_utils_basic_sig::conversions as basicsig_conversions;
use ic_interfaces::crypto::ErrorReproducibility;
use ic_logger::replica_logger::no_op_logger;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_types::NodeId;
use std::sync::Arc;

#[cfg(test)]
mod tests;

fn derive_node_id(node_signing_pk: &PublicKeyProto) -> NodeId {
    basicsig_conversions::derive_node_id(node_signing_pk)
        .expect("Node signing public key should be valid")
}

pub fn generate_node_signing_keys(vault: &dyn CspVault) -> PublicKeyProto {
    let generated = vault
        .gen_node_signing_key_pair()
        .expect("Could not generate node signing keys");
    ic_crypto_internal_csp::keygen::utils::node_signing_pk_to_proto(generated)
}

pub fn generate_committee_signing_keys(vault: &dyn CspVault) -> PublicKeyProto {
    let generated = vault
        .gen_committee_signing_key_pair()
        .expect("Could not generate committee signing keys");
    ic_crypto_internal_csp::keygen::utils::committee_signing_pk_to_proto(generated)
}

/// Generates (forward-secure) NI-DKG dealing encryption key material given the
/// `node_id` of the node.
///
/// The secret key is stored in the key store of the provided `csp`, while the corresponding
/// public key is returned by this function.
pub fn generate_dkg_dealing_encryption_keys(
    vault: &dyn CspVault,
    node_id: NodeId,
) -> PublicKeyProto {
    let (pubkey, pop) = vault
        .gen_dealing_encryption_key_pair(node_id)
        .expect("Failed to generate DKG dealing encryption keys");
    ic_crypto_internal_csp::keygen::utils::dkg_dealing_encryption_pk_to_proto(pubkey, pop)
}

/// Generates (MEGa) I-DKG dealing encryption key material.
///
/// The secret key is stored in the key store of the provided `csp`, while the corresponding
/// public key is returned by this function.
///
/// # Errors
/// * `IDkgDealingEncryptionKeysGenerationError::InternalError` if an unrecoverable error occurs
/// * `IDkgDealingEncryptionKeysGenerationError::TransientInternalError` if a transient error (e.g.,
///   an RPC timeout, or an error persisting the secret key store) occurs
pub fn generate_idkg_dealing_encryption_keys(
    vault: &dyn CspVault,
) -> Result<PublicKeyProto, IDkgDealingEncryptionKeysGenerationError> {
    let pubkey = vault
        .idkg_gen_dealing_encryption_key_pair()
        .map_err(|e| match e {
            CspCreateMEGaKeyError::TransientInternalError { internal_error } => {
                IDkgDealingEncryptionKeysGenerationError::TransientInternalError(internal_error)
            }
            _ => IDkgDealingEncryptionKeysGenerationError::InternalError(format!("{}", e)),
        })?;
    Ok(ic_crypto_internal_csp::keygen::utils::idkg_dealing_encryption_pk_to_proto(pubkey))
}

#[derive(Debug)]
pub enum IDkgDealingEncryptionKeysGenerationError {
    InternalError(String),
    TransientInternalError(String),
}

impl ErrorReproducibility for IDkgDealingEncryptionKeysGenerationError {
    fn is_reproducible(&self) -> bool {
        match &self {
            // true, since regular internal errors are treated as reproducible
            IDkgDealingEncryptionKeysGenerationError::InternalError(_) => true,
            // false, since by definition, transient errors are non-reproducible
            IDkgDealingEncryptionKeysGenerationError::TransientInternalError(_) => false,
        }
    }
}

/// Generates TLS key material for a `node`.
///
/// The secret key is stored in the key store of the provided `csp`,
/// and is used to create a self-signed public key certificate returned by this function.
///
/// The certificate's notAfter date will be set according to RFC5280 (section 4.1.2.5; see
/// https://tools.ietf.org/html/rfc5280#section-4.1.2.5) to indicate that the certificate has no
/// well-defined expiration date.
pub fn generate_tls_keys(vault: &dyn CspVault, node: NodeId) -> TlsPublicKeyCert {
    vault
        .gen_tls_key_pair(node)
        .expect("error generating TLS key pair")
}

/// Generates all required node key pairs and ensure that the public and secret key store are consistent.
/// If the key stores already contain some key material, no key will be generated.
/// Return validated node public keys.
///
/// To check/generate the keys, a CSP client is created according to the given `config`.
/// First, tries to retrieve the node's public keys from `config.crypto_root`. If they
/// exist and they are consistent with the secret keys in kept by the CSP, the
/// public keys are returned in validated form which also contains the corresponding node ID
/// (see `[ValidNodePublicKeys::node_id]).
///
/// If they do not exist, new keys are generated: the secret parts are stored in
/// the secret key store of the CSP, and the public parts are stored in a
/// public key store at `config.crypto_root`. The keys are generated for a particular
/// node ID, which is derived from the node's signing public key. In particular,
/// the node's TLS certificate and the node's DKG dealing encryption key are
/// bound to this node ID. The newly generated public keys are then returned in
/// validated form, which also contains the corresponding node ID.
///
/// The `config.crypto_root` directory must exist and have the [permissions required
/// for storing crypto state](CryptoConfig::check_dir_has_required_permissions).
/// If there exists no key store in `config.crypto_root`, a new one is created.
///
/// # Panics
///  * if public keys exist but are inconsistent with the secret keys.
///  * if an error occurs when generating the keys.
///  * if the node ID cannot be derived from the node signing public key.
///
/// # Errors
/// * [`NodeKeyGenerationError::TransientInternalError`] if a transient internal error occurs, e.g.,
///   an RPC error communicating with the remote vault.
pub fn generate_node_keys_once(
    config: &CryptoConfig,
    tokio_runtime_handle: Option<tokio::runtime::Handle>,
) -> Result<ValidNodePublicKeys, NodeKeyGenerationError> {
    let vault = vault_from_config(
        config,
        tokio_runtime_handle,
        no_op_logger(),
        Arc::new(CryptoMetrics::none()),
    );
    generate_node_keys_once_internal(vault.as_ref())
}

fn generate_node_keys_once_internal(
    vault: &dyn CspVault,
) -> Result<ValidNodePublicKeys, NodeKeyGenerationError> {
    match vault.validate_pks_and_sks() {
        Ok(valid_public_keys) => Ok(valid_public_keys),
        Err(ValidatePksAndSksError::EmptyPublicKeyStore) => {
            generate_all_node_keys(vault);
            vault.validate_pks_and_sks().map_err(|error| match error {
                ValidatePksAndSksError::TransientInternalError(transient_error) => {
                    NodeKeyGenerationError::TransientInternalError(transient_error)
                }
                _ => panic!("Node contains inconsistent key material: {:?}", error),
            })
        }
        Err(ValidatePksAndSksError::TransientInternalError(transient_error)) => Err(
            NodeKeyGenerationError::TransientInternalError(transient_error),
        ),
        Err(error) => panic!("Node contains inconsistent key material: {:?}", error),
    }
}

fn generate_all_node_keys(vault: &dyn CspVault) {
    let node_signing_public_key = generate_node_signing_keys(vault);
    let node_id = derive_node_id(&node_signing_public_key);
    let _committee_signing_public_key = generate_committee_signing_keys(vault);
    let _tls_certificate = generate_tls_keys(vault, node_id);
    let _dkg_dealing_encryption_public_key = generate_dkg_dealing_encryption_keys(vault, node_id);
    let _idkg_dealing_encryption_public_key = generate_idkg_dealing_encryption_keys(vault)
        .unwrap_or_else(|e| panic!("Error generating I-DKG dealing encryption keys: {:?}", e));
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum NodeKeyGenerationError {
    /// If a transient internal error occurs, e.g., an RPC error communicating with the remote vault
    TransientInternalError(String),
}

impl ErrorReproducibility for NodeKeyGenerationError {
    fn is_reproducible(&self) -> bool {
        match self {
            NodeKeyGenerationError::TransientInternalError(_) => false,
        }
    }
}
