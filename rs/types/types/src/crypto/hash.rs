//! Defines hash types.

use crate::canister_http::{
    CanisterHttpResponse, CanisterHttpResponseMetadata, CanisterHttpResponseShare,
};
use crate::consensus::{
    certification::{
        Certification, CertificationContent, CertificationMessage, CertificationShare,
    },
    dkg as consensus_dkg,
    idkg::{EcdsaSigShare, IDkgComplaintContent, IDkgMessage, IDkgOpeningContent, SchnorrSigShare},
    Block, BlockMetadata, BlockPayload, CatchUpContent, CatchUpContentProtobufBytes,
    CatchUpShareContent, ConsensusMessage, EquivocationProof, FinalizationContent, HashedBlock,
    NotarizationContent, RandomBeaconContent, RandomTapeContent,
};
use crate::crypto::canister_threshold_sig::idkg::{
    IDkgDealing, IDkgDealingSupport, IDkgTranscript, SignedIDkgDealing,
};
use crate::crypto::{CryptoHash, CryptoHashOf, Signed};
use crate::messages::{HttpCanisterUpdate, MessageId, SignedRequestBytes};
use crate::signature::{
    BasicSignature, MultiSignature, MultiSignatureShare, ThresholdSignature,
    ThresholdSignatureShare,
};
use ic_crypto_sha2::{DomainSeparationContext, Sha256};
use std::hash::Hash;

pub(crate) mod domain_separator;
use domain_separator::DomainSeparator;

#[cfg(test)]
mod tests;

/// The domain separator to be used when calculating the sender signature for a
/// request to the Internet Computer according to the
/// [interface specification](https://internetcomputer.org/docs/current/references/ic-interface-spec).
pub const DOMAIN_IC_REQUEST: &[u8; 11] = b"\x0Aic-request";

/// A type that specifies a domain for a cryptographic hash.
///
/// This trait is sealed and can only be implemented by types that are
/// explicitly approved by the Github owners of this file (that is, the
/// crypto team) via an implementation of the `CryptoHashDomainSeal`. Explicit
/// approval is required for security reasons to ensure proper domain
/// separation.
pub trait CryptoHashDomain: private::CryptoHashDomainSeal {
    /// Returns the domain separator used in cryptographic hashes.
    fn domain(&self) -> String;
}
mod private {
    use super::*;

    pub trait CryptoHashDomainSeal {}

    impl CryptoHashDomainSeal for NotarizationContent {}
    impl CryptoHashDomainSeal for Signed<NotarizationContent, MultiSignature<NotarizationContent>> {}
    impl CryptoHashDomainSeal
        for Signed<NotarizationContent, MultiSignatureShare<NotarizationContent>>
    {
    }

    impl CryptoHashDomainSeal for FinalizationContent {}
    impl CryptoHashDomainSeal for Signed<FinalizationContent, MultiSignature<FinalizationContent>> {}
    impl CryptoHashDomainSeal
        for Signed<FinalizationContent, MultiSignatureShare<FinalizationContent>>
    {
    }

    impl CryptoHashDomainSeal for Block {}
    impl CryptoHashDomainSeal for Signed<HashedBlock, BasicSignature<BlockMetadata>> {}
    impl CryptoHashDomainSeal for EquivocationProof {}
    impl CryptoHashDomainSeal for BlockPayload {}

    impl CryptoHashDomainSeal for RandomBeaconContent {}
    impl CryptoHashDomainSeal for Signed<RandomBeaconContent, ThresholdSignature<RandomBeaconContent>> {}
    impl CryptoHashDomainSeal
        for Signed<RandomBeaconContent, ThresholdSignatureShare<RandomBeaconContent>>
    {
    }

    impl CryptoHashDomainSeal for CertificationContent {}
    impl CryptoHashDomainSeal for Certification {}
    impl CryptoHashDomainSeal for CertificationShare {}

    impl CryptoHashDomainSeal for consensus_dkg::Message {}
    impl CryptoHashDomainSeal for consensus_dkg::DealingContent {}

    impl CryptoHashDomainSeal for MessageId {}

    impl CryptoHashDomainSeal for HttpCanisterUpdate {}

    impl CryptoHashDomainSeal for SignedRequestBytes {}

    impl CryptoHashDomainSeal for RandomTapeContent {}
    impl CryptoHashDomainSeal for Signed<RandomTapeContent, ThresholdSignature<RandomTapeContent>> {}
    impl CryptoHashDomainSeal
        for Signed<RandomTapeContent, ThresholdSignatureShare<RandomTapeContent>>
    {
    }

    impl CryptoHashDomainSeal for CatchUpContent {}
    impl CryptoHashDomainSeal for CatchUpContentProtobufBytes {}
    impl CryptoHashDomainSeal for Signed<CatchUpContent, ThresholdSignature<CatchUpContent>> {}

    impl CryptoHashDomainSeal for CatchUpShareContent {}
    impl CryptoHashDomainSeal for Signed<CatchUpShareContent, ThresholdSignatureShare<CatchUpContent>> {}

    impl CryptoHashDomainSeal for ConsensusMessage {}
    impl CryptoHashDomainSeal for CertificationMessage {}

    impl CryptoHashDomainSeal for IDkgMessage {}

    impl CryptoHashDomainSeal for IDkgDealing {}

    impl CryptoHashDomainSeal for SignedIDkgDealing {}
    impl CryptoHashDomainSeal for IDkgDealingSupport {}

    impl CryptoHashDomainSeal for IDkgTranscript {}
    impl CryptoHashDomainSeal for EcdsaSigShare {}
    impl CryptoHashDomainSeal for SchnorrSigShare {}

    impl CryptoHashDomainSeal for IDkgComplaintContent {}
    impl CryptoHashDomainSeal for Signed<IDkgComplaintContent, BasicSignature<IDkgComplaintContent>> {}

    impl CryptoHashDomainSeal for IDkgOpeningContent {}
    impl CryptoHashDomainSeal for Signed<IDkgOpeningContent, BasicSignature<IDkgOpeningContent>> {}

    impl CryptoHashDomainSeal for CanisterHttpResponse {}
    impl CryptoHashDomainSeal for CanisterHttpResponseMetadata {}
    impl CryptoHashDomainSeal for CanisterHttpResponseShare {}

    impl CryptoHashDomainSeal for CryptoHashableTestDummy {}
}

impl CryptoHashDomain for CanisterHttpResponse {
    fn domain(&self) -> String {
        DomainSeparator::CanisterHttpResponse.to_string()
    }
}

impl CryptoHashDomain for CanisterHttpResponseMetadata {
    fn domain(&self) -> String {
        DomainSeparator::CryptoHashOfCanisterHttpResponseMetadata.to_string()
    }
}

impl CryptoHashDomain for CanisterHttpResponseShare {
    fn domain(&self) -> String {
        DomainSeparator::CanisterHttpResponseShare.to_string()
    }
}

impl CryptoHashDomain for NotarizationContent {
    fn domain(&self) -> String {
        DomainSeparator::NotarizationContent.to_string()
    }
}

impl CryptoHashDomain for Signed<NotarizationContent, MultiSignature<NotarizationContent>> {
    fn domain(&self) -> String {
        DomainSeparator::Notarization.to_string()
    }
}

impl CryptoHashDomain for Signed<NotarizationContent, MultiSignatureShare<NotarizationContent>> {
    fn domain(&self) -> String {
        DomainSeparator::NotarizationShare.to_string()
    }
}

impl CryptoHashDomain for FinalizationContent {
    fn domain(&self) -> String {
        DomainSeparator::FinalizationContent.to_string()
    }
}

impl CryptoHashDomain for Signed<FinalizationContent, MultiSignature<FinalizationContent>> {
    fn domain(&self) -> String {
        DomainSeparator::Finalization.to_string()
    }
}

impl CryptoHashDomain for Signed<FinalizationContent, MultiSignatureShare<FinalizationContent>> {
    fn domain(&self) -> String {
        DomainSeparator::FinalizationShare.to_string()
    }
}

impl CryptoHashDomain for CertificationContent {
    fn domain(&self) -> String {
        DomainSeparator::CertificationContent.to_string()
    }
}

impl CryptoHashDomain for Certification {
    fn domain(&self) -> String {
        DomainSeparator::Certification.to_string()
    }
}

impl CryptoHashDomain for CertificationShare {
    fn domain(&self) -> String {
        DomainSeparator::CertificationShare.to_string()
    }
}

impl CryptoHashDomain for Block {
    fn domain(&self) -> String {
        DomainSeparator::Block.to_string()
    }
}

impl CryptoHashDomain for Signed<HashedBlock, BasicSignature<BlockMetadata>> {
    fn domain(&self) -> String {
        DomainSeparator::BlockMetadataProposal.to_string()
    }
}

impl CryptoHashDomain for EquivocationProof {
    fn domain(&self) -> String {
        DomainSeparator::EquivocationProof.to_string()
    }
}

impl CryptoHashDomain for BlockPayload {
    fn domain(&self) -> String {
        DomainSeparator::InmemoryPayload.to_string()
    }
}

impl CryptoHashDomain for RandomBeaconContent {
    fn domain(&self) -> String {
        DomainSeparator::RandomBeaconContent.to_string()
    }
}

impl CryptoHashDomain for Signed<RandomBeaconContent, ThresholdSignature<RandomBeaconContent>> {
    fn domain(&self) -> String {
        DomainSeparator::RandomBeacon.to_string()
    }
}

impl CryptoHashDomain
    for Signed<RandomBeaconContent, ThresholdSignatureShare<RandomBeaconContent>>
{
    fn domain(&self) -> String {
        DomainSeparator::RandomBeaconShare.to_string()
    }
}

impl CryptoHashDomain for consensus_dkg::DealingContent {
    fn domain(&self) -> String {
        DomainSeparator::DealingContent.to_string()
    }
}

impl CryptoHashDomain for consensus_dkg::Message {
    fn domain(&self) -> String {
        DomainSeparator::DkgMessage.to_string()
    }
}

impl CryptoHashDomain for HttpCanisterUpdate {
    fn domain(&self) -> String {
        DomainSeparator::HttpCanisterUpdate.to_string()
    }
}

impl CryptoHashDomain for SignedRequestBytes {
    fn domain(&self) -> String {
        DomainSeparator::SignedRequestBytes.to_string()
    }
}

impl CryptoHashDomain for MessageId {
    fn domain(&self) -> String {
        DomainSeparator::MessageId.to_string()
    }
}

impl CryptoHashDomain for RandomTapeContent {
    fn domain(&self) -> String {
        DomainSeparator::RandomTapeContent.to_string()
    }
}

impl CryptoHashDomain for Signed<RandomTapeContent, ThresholdSignature<RandomTapeContent>> {
    fn domain(&self) -> String {
        DomainSeparator::RandomTape.to_string()
    }
}

impl CryptoHashDomain for Signed<RandomTapeContent, ThresholdSignatureShare<RandomTapeContent>> {
    fn domain(&self) -> String {
        DomainSeparator::RandomTapeShare.to_string()
    }
}

impl CryptoHashDomain for CatchUpContent {
    fn domain(&self) -> String {
        DomainSeparator::CatchUpContent.to_string()
    }
}

impl CryptoHashDomain for CatchUpContentProtobufBytes {
    fn domain(&self) -> String {
        DomainSeparator::CatchUpContentProto.to_string()
    }
}

impl CryptoHashDomain for CatchUpShareContent {
    fn domain(&self) -> String {
        DomainSeparator::CatchUpShareContent.to_string()
    }
}

impl CryptoHashDomain for Signed<CatchUpContent, ThresholdSignature<CatchUpContent>> {
    fn domain(&self) -> String {
        DomainSeparator::CatchUpPackage.to_string()
    }
}

impl CryptoHashDomain for Signed<CatchUpShareContent, ThresholdSignatureShare<CatchUpContent>> {
    fn domain(&self) -> String {
        DomainSeparator::CatchUpPackageShare.to_string()
    }
}

impl CryptoHashDomain for ConsensusMessage {
    fn domain(&self) -> String {
        DomainSeparator::ConsensusMessage.to_string()
    }
}

impl CryptoHashDomain for CertificationMessage {
    fn domain(&self) -> String {
        DomainSeparator::CertificationMessage.to_string()
    }
}

impl CryptoHashDomain for IDkgMessage {
    fn domain(&self) -> String {
        DomainSeparator::IDkgMessage.to_string()
    }
}

impl CryptoHashDomain for IDkgDealing {
    fn domain(&self) -> String {
        DomainSeparator::IdkgDealing.to_string()
    }
}

impl CryptoHashDomain for SignedIDkgDealing {
    fn domain(&self) -> String {
        DomainSeparator::SignedIdkgDealing.to_string()
    }
}

impl CryptoHashDomain for IDkgDealingSupport {
    fn domain(&self) -> String {
        DomainSeparator::IdkgDealingSupport.to_string()
    }
}

impl CryptoHashDomain for IDkgTranscript {
    fn domain(&self) -> String {
        DomainSeparator::IDkgTranscript.to_string()
    }
}

impl CryptoHashDomain for EcdsaSigShare {
    fn domain(&self) -> String {
        DomainSeparator::EcdsaSigShare.to_string()
    }
}

impl CryptoHashDomain for SchnorrSigShare {
    fn domain(&self) -> String {
        DomainSeparator::SchnorrSigShare.to_string()
    }
}

impl CryptoHashDomain for IDkgComplaintContent {
    fn domain(&self) -> String {
        DomainSeparator::IDkgComplaintContent.to_string()
    }
}

impl CryptoHashDomain for Signed<IDkgComplaintContent, BasicSignature<IDkgComplaintContent>> {
    fn domain(&self) -> String {
        DomainSeparator::SignedIDkgComplaint.to_string()
    }
}

impl CryptoHashDomain for IDkgOpeningContent {
    fn domain(&self) -> String {
        DomainSeparator::IDkgOpeningContent.to_string()
    }
}

impl CryptoHashDomain for Signed<IDkgOpeningContent, BasicSignature<IDkgOpeningContent>> {
    fn domain(&self) -> String {
        DomainSeparator::SignedIDkgOpening.to_string()
    }
}

impl CryptoHashDomain for CryptoHashableTestDummy {
    fn domain(&self) -> String {
        "test_struct_domain".to_string()
    }
}

/// A helper struct for testing that implements `CryptoHashable`.
///
/// It is defined here because the struct must implement the `CryptoHashDomain`
/// trait, which is _sealed_ and must only be implemented here in this crate.
/// Ideally, this struct would be annotated with `#[cfg(test)]` so that it is
/// only available in test code, however, then it would not be visible outside
/// of this crate where it is needed.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct CryptoHashableTestDummy(pub Vec<u8>);

/// A cryptographically hashable type.
pub trait CryptoHashable: CryptoHashDomain + Hash {}
impl<T> CryptoHashable for T where T: CryptoHashDomain + Hash {}

/// Creates a (typed) domain-separated cryptographic hash.
///
/// The bytes that are hashed are a combination of
/// * the byte representation of the hash domain obtained via `CryptoHashable`s
///   supertrait `CryptoHashDomain`
/// * the bytes fed to the hasher state via `CryptoHashable`s supertrait `Hash`
///
/// Note that the trait `CryptoHashDomain` is sealed for security reasons. To
/// implement this trait for a new struct that shall be cryptographically
/// hashed, contact the crypto team.
///
/// The (secure) hashing algorithm that is used internally is intentionally
/// unspecified because it may be subject to change across registry/protocol
/// versions. Use `Sha256` instead if the algorithm used for producing
/// the hash must not change across registry/protocol versions.
pub fn crypto_hash<T: CryptoHashable>(data: &T) -> CryptoHashOf<T> {
    let mut hash = Sha256::new_with_context(&DomainSeparationContext::new(data.domain()));
    data.hash(&mut hash);
    CryptoHashOf::new(CryptoHash(hash.finish().to_vec()))
}
