use super::super::types::{CspPop, CspPublicKey};
use crate::key_id::KeyId;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_types::crypto::{CryptoError, CurrentNodePublicKeys};
use ic_types::NodeId;

/// A trait that can be used to generate cryptographic key pairs
pub trait CspKeyGenerator {
    /// Generate a node signing public/private key pair.
    ///
    /// # Returns
    /// The public key of the keypair
    /// # Errors
    /// * `CryptoError::InternalError` if there is an internal
    ///   error (e.g., the public key in the public key store is already set).
    /// * `CryptoError::TransientInternalError` if there is a transient
    ///   internal error, e.g., an IO error when writing a key to disk, or an
    ///   RPC error when calling a remote CSP vault.
    /// # Panics
    /// If there already exists a secret key in the store for the secret key ID
    /// derived from the public key. This error most likely indicates a bad
    /// randomness source.
    fn gen_node_signing_key_pair(&self) -> Result<CspPublicKey, CryptoError>;

    /// Generates a committee signing public/private key pair.
    ///
    /// # Returns
    /// The public key and the proof of possession (PoP) of the keypair
    ///
    /// # Errors
    /// * `CryptoError::InternalError` if there is an internal
    ///   error (e.g., the public key in the public key store is already set).
    /// * `CryptoError::TransientInternalError` if there is a transient
    ///   internal error, e.g,. an IO error when writing a key to disk, or an
    ///   RPC error when calling a remote CSP vault.
    ///
    /// # Panics
    /// If there already exists a secret key in the store for the secret key ID
    /// derived from the public key. This error most likely indicates a bad
    /// randomness source.
    fn gen_committee_signing_key_pair(&self) -> Result<(CspPublicKey, CspPop), CryptoError>;

    /// Generates TLS key material for node with ID `node_id`.
    ///
    /// The secret key is stored in the key store and used to create a
    /// self-signed X.509 public key certificate with
    /// * a random serial,
    /// * the common name of both subject and issuer being the `ToString` form
    ///   of the given `node_id`,
    /// * validity starting at the time of calling this method, and
    /// * validity ending at `not_after`, which must be specified according to
    ///   section 4.1.2.5 in RFC 5280.
    ///
    /// # Returns
    /// The public key certificate.
    ///
    /// # Errors
    /// * if `not_after` is not specified according to RFC 5280 or if
    /// `not_after` is in the past
    /// * if a malformed X509 certificate is generated
    /// * if this function is called more than once
    fn gen_tls_key_pair(
        &self,
        node_id: NodeId,
        not_after: &str,
    ) -> Result<TlsPublicKeyCert, CryptoError>;
}

/// A trait that allows checking the secret key store for the availability of a
/// key.
pub trait CspSecretKeyStoreChecker {
    /// Checks whether the store contains a key with the given `id`.
    fn sks_contains(&self, key_id: &KeyId) -> Result<bool, CryptoError>;

    /// Checks whether the store contains a private key for the given `cert`.
    fn sks_contains_tls_key(&self, cert: &TlsPublicKeyCert) -> Result<bool, CryptoError>;
}

/// A trait that exposes the information about node public keys and key
/// identifiers.
pub trait NodePublicKeyData {
    /// Checks whether the local public key store contains the provided public keys.
    ///
    /// # Returns
    /// `true` if all the provided public keys exist in the local public key store,
    /// `false` if one or more of the provided public keys do not exist in the local
    /// public key store
    ///
    /// # Errors
    /// * `CryptoError::TransientInternalError` if there is a transient
    ///   internal error, e.g., an RPC error when calling a remote CSP vault.
    fn pks_contains(&self, public_keys: CurrentNodePublicKeys) -> Result<bool, CryptoError>;
    /// Returns the node's current public keys.
    fn current_node_public_keys(&self) -> CurrentNodePublicKeys;
    /// Returns the id of the dkg dealing encryption key.
    fn dkg_dealing_encryption_key_id(&self) -> KeyId;
}
