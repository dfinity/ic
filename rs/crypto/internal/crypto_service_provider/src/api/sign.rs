use super::super::types::{CspPop, CspPublicKey, CspSignature};
use ic_types::crypto::CryptoResult;
use ic_types::crypto::{AlgorithmId, KeyId};

/// A trait that can generate and verify public key signatures
pub trait CspSigner {
    /// Sign a message using the specified algorithm and key IDs
    ///
    /// # Arguments
    /// * `algorithm_id` specifies the signature algorithm
    /// * `msg` is the message data to be signed
    /// * `key_id` specifies the private key to sign with
    /// # Errors
    /// * `CryptoError::SecretKeyNotFound` if the key ID could not be located in
    ///   the secret key store.
    /// * `CryptoError::MalformedSecretKey` if the key data could be loaded from
    ///   the secret key store, but the key type does not match algorithm_id
    /// * `CryptoError::InvalidArgument` if the algorithm is not supported by
    ///   the trait implementation.
    /// # Returns
    /// The generated signature
    fn sign(
        &self,
        algorithm_id: AlgorithmId,
        msg: &[u8],
        key_id: KeyId,
    ) -> CryptoResult<CspSignature>;

    /// Verify a public key signature.
    ///
    /// # Arguments
    /// * `sig` the signature
    /// * `msg` the message data to be verified
    /// * `algorithm_id` the signature algorithm
    /// * `signer` the public key of the signer
    /// # Errors
    /// * `CryptoError::SignatureVerification` if the signature algorithm used
    ///   is not supported by the trait implementation, or if the signature was
    ///   checked and found to be invalid.
    /// * `CryptoError::MalformedPublicKey` if the public key seems to be
    ///   invalid or malformed
    /// * `CryptoError::MalformedSignature` if the signature seems to be invalid
    ///   or malformed
    /// # Returns
    /// `Ok(())` if the signature is valid or an `Err` otherwise
    fn verify(
        &self,
        sig: &CspSignature,
        msg: &[u8],
        algorithm_id: AlgorithmId,
        signer: CspPublicKey,
    ) -> CryptoResult<()>;

    /// Verify a proof of posession (PoP).
    ///
    /// # Arguments
    /// * `pop` the proof of posession
    /// * `algorithm_id` the signature algorithm
    /// * `public_key` the public key of the signer
    /// # Errors
    /// * `CryptoError::PopVerification` if the algorithm used is not supported
    /// by the trait implementation, or if the signature was checked and found
    /// to be invalid.
    /// # Returns
    /// `Ok(())` if the PoP is valid or an `Err` otherwise
    fn verify_pop(
        &self,
        pop: &CspPop,
        algorithm_id: AlgorithmId,
        public_key: CspPublicKey,
    ) -> CryptoResult<()>;

    /// Combines individual signatures into a multisignature
    ///
    /// # Arguments
    /// * `signatures` a Vec of public keys and associated signatures
    /// * `algorithm_id` the signature algorithm
    /// # Errors
    /// * `CryptoError::AlgorithmNotSupported` if the signature algorithm used
    ///   does not support multisignatures.
    /// * `CryptoError::MalformedSignature` if an individual signature is
    ///   malformed.
    /// # Returns
    /// The combined multisignature
    fn combine_sigs(
        &self,
        signatures: Vec<(CspPublicKey, CspSignature)>,
        algorithm_id: AlgorithmId,
    ) -> CryptoResult<CspSignature>;

    /// Verify a multisignature
    ///
    /// # Arguments
    /// * `signers` a Vec of public keys used to create the multisignature
    /// * `signature` the multisignature
    /// * `msg` is the message data to be verified
    /// * `algorithm_id` the signature algorithm
    /// # Errors
    /// * `CryptoError::AlgorithmNotSupported` if the signature algorithm used
    ///   does not support multisignatures.
    /// * `CryptoError::SignatureVerification` if the multisignature was checked
    /// and found to be invalid.
    /// * `CryptoError::MalformedSignature` if the multisignature is malformed.
    /// # Returns
    /// `Ok(())` if the signature is valid or an `Err` otherwise
    fn verify_multisig(
        &self,
        signers: Vec<CspPublicKey>,
        signature: CspSignature,
        msg: &[u8],
        algorithm_id: AlgorithmId,
    ) -> CryptoResult<()>;
}
