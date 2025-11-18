//! # Signature Verification API
//! The signature verification API contains traits for verifying basic signatures by public key,
//! (ICCSA) canister signatures, and ingress message signatures.
//!
//! Please refer to the trait documentation for details.

use ic_types::crypto::threshold_sig::IcRootOfTrust;
use ic_types::crypto::{BasicSigOf, CanisterSigOf, CryptoResult, Signable, UserPublicKey};
use ic_types::messages::{Delegation, MessageId, WebAuthnEnvelope};

/// A Crypto Component interface to verify basic signatures by public key.
pub trait BasicSigVerifierByPublicKey<T: Signable> {
    /// Verifies a basic signature using the given `public_key`.
    ///
    /// # Errors
    /// * `CryptoError::MalformedPublicKey`: if the `public_key` is malformed.
    /// * `CryptoError::MalformedSignature`: if the `signature` is malformed.
    /// * `CryptoError::AlgorithmNotSupported`: if the signature algorithm is
    ///   not supported, or if the `public_key` is for an unsupported algorithm.
    /// * `CryptoError::SignatureVerification`: if the `signature` could not be
    ///   verified.
    fn verify_basic_sig_by_public_key(
        &self,
        signature: &BasicSigOf<T>,
        signed_bytes: &T,
        public_key: &UserPublicKey,
    ) -> CryptoResult<()>;
}

/// A Crypto Component interface to verify (ICCSA) canister signatures.
pub trait CanisterSigVerifier<T: Signable> {
    /// Verifies an ICCSA canister signature.
    ///
    /// # Errors
    /// * `CryptoError::AlgorithmNotSupported`: if the signature algorithm is
    ///   not supported for canister signatures.
    /// * `CryptoError::RegistryClient`: if the registry cannot be accessed at
    ///   `registry_version`.
    /// * `CryptoError::RootSubnetPublicKeyNotFound`: if the root subnet id or
    ///   the root subnet threshold signing public key cannot be found in the
    ///   registry at `registry_version`.
    /// * `CryptoError::MalformedPublicKey`: if the root subnet's threshold
    ///   signing public key is malformed.
    /// * `CryptoError::MalformedSignature`: if the `signature` is malformed.
    /// * `CryptoError::SignatureVerification`: if the `signature` could not be
    ///   verified.
    fn verify_canister_sig(
        &self,
        signature: &CanisterSigOf<T>,
        signed_bytes: &T,
        public_key: &UserPublicKey,
        root_of_trust: &IcRootOfTrust,
    ) -> CryptoResult<()>;
}

/// A Crypto Component interface to verify ingress messages.
pub trait IngressSigVerifier:
    Send
    + Sync
    + BasicSigVerifierByPublicKey<WebAuthnEnvelope>
    + BasicSigVerifierByPublicKey<MessageId>
    + BasicSigVerifierByPublicKey<Delegation>
    + CanisterSigVerifier<Delegation>
    + CanisterSigVerifier<MessageId>
{
}

impl<T> IngressSigVerifier for T where
    T: Send
        + Sync
        + BasicSigVerifierByPublicKey<WebAuthnEnvelope>
        + BasicSigVerifierByPublicKey<MessageId>
        + BasicSigVerifierByPublicKey<Delegation>
        + CanisterSigVerifier<Delegation>
        + CanisterSigVerifier<MessageId>
{
}
