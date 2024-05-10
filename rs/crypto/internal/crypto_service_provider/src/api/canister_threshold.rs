//! CSP canister threshold signature traits

use ic_crypto_internal_threshold_sig_ecdsa::MEGaPublicKey;

pub mod errors;
pub use errors::*;

/// Crypto service provider (CSP) client for interactive distributed key
/// generation (IDkg) for canister threshold signatures.
pub trait CspIDkgProtocol {
    /// Generate a MEGa public/private key pair for encrypting threshold key shares in transmission
    /// from dealers to receivers. The generated public key will be stored in the node's public key store
    /// while the private key will be stored in the node's secret key store.
    ///
    /// # Returns
    /// Generated public key.
    ///
    /// # Errors
    /// * [`CspCreateMEGaKeyError::SerializationError`] if serialization of public or private key
    ///   before storing it in their respective key store failed.
    /// * [`CspCreateMEGaKeyError::TransientInternalError`] if there is a
    ///   transient internal error, e.g,. an IO error when writing a key to
    ///   disk, or an RPC error when calling a remote CSP vault.
    /// * [`CspCreateMEGaKeyError::DuplicateKeyId`] if there already
    ///   exists a secret key in the store for the secret key ID derived from
    ///   the public part of the randomly generated key pair. This error
    ///   most likely indicates a bad randomness source.
    /// * [`CspCreateMEGaKeyError::InternalError`]: if the key ID for the secret key cannot be
    ///   derived from the generated public key.
    fn idkg_gen_dealing_encryption_key_pair(&self) -> Result<MEGaPublicKey, CspCreateMEGaKeyError>;
}
