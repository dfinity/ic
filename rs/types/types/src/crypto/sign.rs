//! Defines signature types.

use crate::canister_http::CanisterHttpResponseMetadata;
use crate::consensus::{
    certification::CertificationContent,
    dkg::DealingContent,
    ecdsa::{EcdsaComplaintContent, EcdsaOpeningContent, EcdsaSigShare},
    Block, CatchUpContent, CatchUpContentProtobufBytes, FinalizationContent, NotarizationContent,
    RandomBeaconContent, RandomTapeContent,
};
use crate::crypto::canister_threshold_sig::idkg::{IDkgDealing, SignedIDkgDealing};
use crate::crypto::hash::{
    DOMAIN_BLOCK, DOMAIN_CATCH_UP_CONTENT, DOMAIN_CERTIFICATION_CONTENT,
    DOMAIN_CRYPTO_HASH_OF_CANISTER_HTTP_RESPONSE_METADATA, DOMAIN_DEALING_CONTENT,
    DOMAIN_ECDSA_COMPLAINT_CONTENT, DOMAIN_ECDSA_OPENING_CONTENT, DOMAIN_FINALIZATION_CONTENT,
    DOMAIN_IDKG_DEALING, DOMAIN_NOTARIZATION_CONTENT, DOMAIN_RANDOM_BEACON_CONTENT,
    DOMAIN_RANDOM_TAPE_CONTENT, DOMAIN_SIGNED_IDKG_DEALING,
};
use crate::crypto::SignedBytesWithoutDomainSeparator;
use crate::messages::{Delegation, MessageId, WebAuthnEnvelope};
use std::convert::TryFrom;

const SIG_DOMAIN_IC_REQUEST_AUTH_DELEGATION: &str = "ic-request-auth-delegation";
const SIG_DOMAIN_IC_REQUEST: &str = "ic-request";

/// `Signable` represents an object whose byte-vector representation
/// can be signed using a digital signature scheme.
/// It supports domain separation via `SignatureDomain` trait.
pub trait Signable: SignatureDomain + SignedBytesWithoutDomainSeparator {
    /// Returns a byte-vector that is used as input for signing/verification
    /// in a digital signature scheme.
    fn as_signed_bytes(&self) -> Vec<u8>;
}

impl<T> Signable for T
where
    T: SignatureDomain + SignedBytesWithoutDomainSeparator,
{
    fn as_signed_bytes(&self) -> Vec<u8> {
        let mut bytes = self.domain();
        bytes.append(&mut self.as_signed_bytes_without_domain_separator());
        bytes
    }
}

/// This trait is sealed and can only be implemented by types that are
/// explicitly approved by the Github owners of this file (that is, the
/// crypto team) via an implementation of the `SignatureDomainSeal`. Explicit
/// approval is required for security reasons to ensure proper domain
/// separation.
pub trait SignatureDomain: private::SignatureDomainSeal {
    fn domain(&self) -> Vec<u8>;
}

mod private {
    use super::*;
    use crate::crypto::canister_threshold_sig::idkg::{IDkgDealing, SignedIDkgDealing};

    pub trait SignatureDomainSeal {}

    impl SignatureDomainSeal for Block {}
    impl SignatureDomainSeal for DealingContent {}
    impl SignatureDomainSeal for NotarizationContent {}
    impl SignatureDomainSeal for FinalizationContent {}
    impl SignatureDomainSeal for IDkgDealing {}
    impl SignatureDomainSeal for SignedIDkgDealing {}
    impl SignatureDomainSeal for EcdsaSigShare {}
    impl SignatureDomainSeal for EcdsaComplaintContent {}
    impl SignatureDomainSeal for EcdsaOpeningContent {}
    impl SignatureDomainSeal for WebAuthnEnvelope {}
    impl SignatureDomainSeal for Delegation {}
    impl SignatureDomainSeal for CanisterHttpResponseMetadata {}
    impl SignatureDomainSeal for MessageId {}
    impl SignatureDomainSeal for CertificationContent {}
    impl SignatureDomainSeal for CatchUpContent {}
    impl SignatureDomainSeal for CatchUpContentProtobufBytes {}
    impl SignatureDomainSeal for RandomBeaconContent {}
    impl SignatureDomainSeal for RandomTapeContent {}
    impl SignatureDomainSeal for SignableMock {}
}

impl SignatureDomain for CanisterHttpResponseMetadata {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DOMAIN_CRYPTO_HASH_OF_CANISTER_HTTP_RESPONSE_METADATA)
    }
}

impl SignatureDomain for Block {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DOMAIN_BLOCK)
    }
}

impl SignatureDomain for DealingContent {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DOMAIN_DEALING_CONTENT)
    }
}

impl SignatureDomain for NotarizationContent {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DOMAIN_NOTARIZATION_CONTENT)
    }
}

impl SignatureDomain for FinalizationContent {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DOMAIN_FINALIZATION_CONTENT)
    }
}

impl SignatureDomain for IDkgDealing {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DOMAIN_IDKG_DEALING)
    }
}

impl SignatureDomain for SignedIDkgDealing {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DOMAIN_SIGNED_IDKG_DEALING)
    }
}

impl SignatureDomain for EcdsaSigShare {
    // ECDSA is an external standard, hence no domain is used.
    fn domain(&self) -> Vec<u8> {
        vec![]
    }
}

impl SignatureDomain for EcdsaComplaintContent {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DOMAIN_ECDSA_COMPLAINT_CONTENT)
    }
}

impl SignatureDomain for EcdsaOpeningContent {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DOMAIN_ECDSA_OPENING_CONTENT)
    }
}

impl SignatureDomain for WebAuthnEnvelope {
    // WebAuthn is an external standard, hence no domain is used.
    fn domain(&self) -> Vec<u8> {
        vec![]
    }
}

impl SignatureDomain for Delegation {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(SIG_DOMAIN_IC_REQUEST_AUTH_DELEGATION)
    }
}

impl SignatureDomain for MessageId {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(SIG_DOMAIN_IC_REQUEST)
    }
}

impl SignatureDomain for CertificationContent {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DOMAIN_CERTIFICATION_CONTENT)
    }
}

impl SignatureDomain for CatchUpContent {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DOMAIN_CATCH_UP_CONTENT)
    }
}

// This is INTENTIONALLY made the same as CatchUpContent, because this type is
// used to verify the signature over the bytes of a catch up package without
// necessarily needing to deserialize them into CatchUpContent.
impl SignatureDomain for CatchUpContentProtobufBytes {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DOMAIN_CATCH_UP_CONTENT)
    }
}

impl SignatureDomain for RandomBeaconContent {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DOMAIN_RANDOM_BEACON_CONTENT)
    }
}

impl SignatureDomain for RandomTapeContent {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DOMAIN_RANDOM_TAPE_CONTENT)
    }
}

// Returns a vector of bytes that contains the given domain
// prepended with a single byte that holds the length of the domain.
// This is the recommended format for non-empty domain separators,
// and this helper be used for simple implementations of
// `SignatureDomain`-trait, e.g.:
//
// const SOME_DOMAIN : &str = "some_domain";
//
// impl SignatureDomain for SomeDomain {
//     fn domain(&self) -> Vec<u8> {
//         domain_with_prepended_length(SOME_DOMAIN)
//     }
// }
fn domain_with_prepended_length(domain: &str) -> Vec<u8> {
    let domain_len = u8::try_from(domain.len()).expect("domain too long");
    let mut ret = vec![domain_len];
    ret.extend(domain.as_bytes());
    ret
}

/// A helper struct for testing that implements `Signable`.
///
/// `SignableMock` is needed for testing interfaces that use `Signable`-trait.
/// It is defined here because `SignatureDomain` is _sealed_ and must only be
/// implemented here in this crate.
///
/// Ideally, this struct would be annotated with `#[cfg(test)]` so that it is
/// only available in test code, however, then it would not be visible outside
/// of this crate where it is needed.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SignableMock {
    pub domain: Vec<u8>,
    pub signed_bytes_without_domain: Vec<u8>,
}

impl SignableMock {
    pub fn new(signed_bytes_without_domain: Vec<u8>) -> Self {
        Self {
            domain: domain_with_prepended_length("signable_mock_domain"),
            signed_bytes_without_domain,
        }
    }
}

impl SignatureDomain for SignableMock {
    fn domain(&self) -> Vec<u8> {
        self.domain.clone()
    }
}

impl SignedBytesWithoutDomainSeparator for SignableMock {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        self.signed_bytes_without_domain.clone()
    }
}
