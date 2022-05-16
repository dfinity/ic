use super::super::types::{CspPop, CspPublicKey};
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_types::crypto::{AlgorithmId, CryptoError, KeyId};
use ic_types::NodeId;

/// A trait that can be used to generate cryptographic key pairs
pub trait CspKeyGenerator {
    /// Generate a public/private key pair.
    ///
    /// # Arguments
    /// * `alg_id` specifies the algorithm to be used
    /// # Returns
    /// The key ID and the public key of the keypair
    /// # Errors
    /// * `CryptoError::InvalidArgument` if the algorithm is not supported by
    ///   the trait implementation. (Note: Currently only BLS12-381 and Ed25519
    ///   are supported by implementations of this trait)
    fn gen_key_pair(&self, alg_id: AlgorithmId) -> Result<(KeyId, CspPublicKey), CryptoError>;

    /// Generate a public/private key pair with proof of possession.
    ///
    /// # Arguments
    /// * `alg_id` specifies the algorithm to be used
    /// # Returns
    /// The key ID referring to the secret key, the public key, and the PoP
    /// # Errors
    /// * `CryptoError::InvalidArgument` if the algorithm is not supported by
    ///   the trait implementation. (Note: Currently only BLS12-381 is supported
    ///   by implementations of this trait)
    fn gen_key_pair_with_pop(
        &self,
        algorithm_id: AlgorithmId,
    ) -> Result<(KeyId, CspPublicKey, CspPop), CryptoError>;

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
    /// Returns the public key certificate.
    ///
    /// # Panics
    /// * if `not_after` is not specified according to RFC 5280 or if
    /// `not_after` is in the past
    /// * if a malformed X509 certificate is generated
    fn gen_tls_key_pair(&mut self, node_id: NodeId, not_after: &str) -> TlsPublicKeyCert;
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
    /// Returns the public keys of this node.
    fn node_public_keys(&self) -> NodePublicKeys;
    /// Returns the id of the node signing key.
    fn node_signing_key_id(&self) -> KeyId;
    /// Returns the id of the dkg dealing encryption key.
    fn dkg_dealing_encryption_key_id(&self) -> KeyId;
}
