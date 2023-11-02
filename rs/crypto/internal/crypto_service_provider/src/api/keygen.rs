use ic_crypto_node_key_validation::ValidNodePublicKeys;

use super::super::types::{CspPop, CspPublicKey};
use crate::vault::api::{
    CspBasicSignatureKeygenError, CspMultiSignatureKeygenError, CspPublicKeyStoreError,
    CspTlsKeygenError, ValidatePksAndSksError,
};
use crate::{ExternalPublicKeys, PksAndSksContainsErrors};
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_types::crypto::CurrentNodePublicKeys;
use ic_types::NodeId;

/// A trait that can be used to generate cryptographic key pairs
pub trait CspKeyGenerator {
    /// Generate a node signing public/private key pair.
    ///
    /// # Returns
    /// The public key of the keypair
    /// # Errors
    /// * [`CryptoError::InternalError`] if there is an internal
    ///   error (e.g., the public key in the public key store is already set).
    /// * [`CryptoError::TransientInternalError`] if there is a transient
    ///   internal error, e.g., an IO error when writing a key to disk, or an
    ///   RPC error when calling the CSP vault.
    /// # Panics
    /// If there already exists a secret key in the store for the secret key ID
    /// derived from the public key. This error most likely indicates a bad
    /// randomness source.
    fn gen_node_signing_key_pair(&self) -> Result<CspPublicKey, CspBasicSignatureKeygenError>;

    /// Generates a committee signing public/private key pair.
    ///
    /// # Returns
    /// The public key and the proof of possession (PoP) of the keypair
    ///
    /// # Errors
    /// * [`CryptoError::InternalError`] if there is an internal
    ///   error (e.g., the public key in the public key store is already set).
    /// * [`CryptoError::TransientInternalError`] if there is a transient
    ///   internal error, e.g,. an IO error when writing a key to disk, or an
    ///   RPC error when calling the CSP vault.
    ///
    /// # Panics
    /// If there already exists a secret key in the store for the secret key ID
    /// derived from the public key. This error most likely indicates a bad
    /// randomness source.
    fn gen_committee_signing_key_pair(
        &self,
    ) -> Result<(CspPublicKey, CspPop), CspMultiSignatureKeygenError>;

    /// Generates TLS key material for node with ID `node_id`.
    ///
    /// The secret key is stored in the key store and used to create a
    /// self-signed X.509 public key certificate with
    /// * a random serial,
    /// * the common name of both subject and issuer being the `ToString` form
    ///   of the given `node_id`,
    /// * validity starting 2 minutes before the time of calling this method, and
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
    ) -> Result<TlsPublicKeyCert, CspTlsKeygenError>;
}

/// A trait that allows simultaneously checking the public and secret key stores for the
/// availability of a key.
pub trait CspPublicAndSecretKeyStoreChecker {
    /// Checks whether the keys corresponding to the provided external public keys exist locally.
    /// In particular, this means the provided public keys themselves are stored locally, as well
    /// as the corresponding secret keys. Key comparisons will not take timestamps into account.
    ///
    /// # Parameters
    /// The current external node public keys and TLS certificate.
    ///
    /// # Returns
    /// An empty result if all the external public keys, and the corresponding secret keys, were
    /// all found locally.
    ///
    /// # Errors
    /// * `PksAndSksContainsErrors::NodeKeysErrors` if local public or secret keys were not
    ///   consistent with the provided external keys.
    /// * `PksAndSksContainsErrors::TransientInternalError` if a transient internal error, e.g., an RPC
    ///   error, occurred.
    fn pks_and_sks_contains(
        &self,
        external_public_keys: ExternalPublicKeys,
    ) -> Result<(), PksAndSksContainsErrors>;

    /// See documentation in [`crate::vault::api::PublicAndSecretKeyStoreCspVault::validate_pks_and_sks`].
    fn validate_pks_and_sks(&self) -> Result<ValidNodePublicKeys, ValidatePksAndSksError>;
}

/// A trait that exposes the information about the node public key store.
pub trait CspPublicKeyStore {
    /// Returns the node's current public keys where generation timestamps are stripped.
    ///
    /// # Errors
    /// * [`CspPublicKeyStoreError::TransientInternalError`] if there is a transient internal
    ///   error when calling the CSP vault.
    fn current_node_public_keys(&self) -> Result<CurrentNodePublicKeys, CspPublicKeyStoreError>;

    /// Returns the node's current public keys with their associated timestamps.
    ///
    /// If timestamps are not needed, you should use [`Self::current_node_public_keys`].
    ///
    /// # Errors
    /// * [`CspPublicKeyStoreError::TransientInternalError`] if there is a transient internal
    ///   error when calling the CSP vault.
    fn current_node_public_keys_with_timestamps(
        &self,
    ) -> Result<CurrentNodePublicKeys, CspPublicKeyStoreError>;

    /// Returns the number of iDKG dealing encryption public keys stored locally.
    ///
    /// # Errors
    /// * if a transient error (e.g., RPC timeout) occurs when accessing the public key store
    fn idkg_dealing_encryption_pubkeys_count(&self) -> Result<usize, CspPublicKeyStoreError>;
}
