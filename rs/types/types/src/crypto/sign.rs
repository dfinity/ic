//! Defines signature types.

use super::hash::domain_separator::DomainSeparator;
use crate::canister_http::CanisterHttpResponseMetadata;
use crate::consensus::{
    BlockMetadata, CatchUpContent, CatchUpContentProtobufBytes, FinalizationContent,
    NotarizationContent, RandomBeaconContent, RandomTapeContent,
    certification::CertificationContent,
    dkg::DealingContent,
    idkg::{IDkgComplaintContent, IDkgOpeningContent},
};
use crate::crypto::SignedBytesWithoutDomainSeparator;
use crate::crypto::canister_threshold_sig::idkg::{IDkgDealing, SignedIDkgDealing};
use crate::crypto::vetkd::VetKdEncryptedKeyShareContent;
use crate::messages::{Delegation, MessageId, QueryResponseHash, WebAuthnEnvelope};
use std::convert::TryFrom;

/// The domain separator to be used when calculating the sender signature for a
/// request to the Internet Computer according to the
/// [interface specification](https://internetcomputer.org/docs/current/references/ic-interface-spec).
pub const DOMAIN_IC_REQUEST: &[u8; 11] = b"\x0Aic-request";

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
    use crate::{
        crypto::canister_threshold_sig::idkg::{IDkgDealing, SignedIDkgDealing},
        messages::QueryResponseHash,
    };

    pub trait SignatureDomainSeal {}

    impl SignatureDomainSeal for BlockMetadata {}
    impl SignatureDomainSeal for DealingContent {}
    impl SignatureDomainSeal for NotarizationContent {}
    impl SignatureDomainSeal for FinalizationContent {}
    impl SignatureDomainSeal for IDkgDealing {}
    impl SignatureDomainSeal for SignedIDkgDealing {}
    impl SignatureDomainSeal for IDkgComplaintContent {}
    impl SignatureDomainSeal for IDkgOpeningContent {}
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
    impl SignatureDomainSeal for QueryResponseHash {}
    impl SignatureDomainSeal for VetKdEncryptedKeyShareContent {}
}

impl SignatureDomain for CanisterHttpResponseMetadata {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(
            DomainSeparator::CryptoHashOfCanisterHttpResponseMetadata.as_str(),
        )
    }
}

impl SignatureDomain for BlockMetadata {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DomainSeparator::BlockMetadata.as_str())
    }
}

impl SignatureDomain for DealingContent {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DomainSeparator::DealingContent.as_str())
    }
}

impl SignatureDomain for NotarizationContent {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DomainSeparator::NotarizationContent.as_str())
    }
}

impl SignatureDomain for FinalizationContent {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DomainSeparator::FinalizationContent.as_str())
    }
}

impl SignatureDomain for IDkgDealing {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DomainSeparator::IdkgDealing.as_str())
    }
}

impl SignatureDomain for SignedIDkgDealing {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DomainSeparator::SignedIdkgDealing.as_str())
    }
}

impl SignatureDomain for IDkgComplaintContent {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DomainSeparator::IDkgComplaintContent.as_str())
    }
}

impl SignatureDomain for IDkgOpeningContent {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DomainSeparator::IDkgOpeningContent.as_str())
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
        domain_with_prepended_length(DomainSeparator::IcRequestAuthDelegation.as_str())
    }
}

impl SignatureDomain for MessageId {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DomainSeparator::IcRequest.as_str())
    }
}

impl SignatureDomain for CertificationContent {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DomainSeparator::CertificationContent.as_str())
    }
}

impl SignatureDomain for CatchUpContent {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DomainSeparator::CatchUpContent.as_str())
    }
}

// This is INTENTIONALLY made the same as CatchUpContent, because this type is
// used to verify the signature over the bytes of a catch up package without
// necessarily needing to deserialize them into CatchUpContent.
impl SignatureDomain for CatchUpContentProtobufBytes {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DomainSeparator::CatchUpContent.as_str())
    }
}

impl SignatureDomain for RandomBeaconContent {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DomainSeparator::RandomBeaconContent.as_str())
    }
}

impl SignatureDomain for RandomTapeContent {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DomainSeparator::RandomTapeContent.as_str())
    }
}

impl SignatureDomain for QueryResponseHash {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DomainSeparator::QueryResponse.as_str())
    }
}

impl SignatureDomain for VetKdEncryptedKeyShareContent {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length(DomainSeparator::VetKdEncryptedKeyShareContent.as_str())
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
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
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
