use ic_types::artifact::StateSyncMessage;
use ic_types::consensus::certification::CertificationMessage;
use ic_types::consensus::dkg as consensus_dkg;
use ic_types::consensus::{
    certification::{Certification, CertificationContent, CertificationShare},
    BasicSignature, Block, BlockPayload, CatchUpContent, CatchUpContentProtobufBytes,
    CatchUpShareContent, ConsensusMessage, FinalizationContent, HashedBlock, MultiSignature,
    MultiSignatureShare, NotarizationContent, RandomBeaconContent, RandomTapeContent,
    ThresholdSignature, ThresholdSignatureShare,
};
use ic_types::crypto::Signed;
use ic_types::messages::{HttpCanisterUpdate, MessageId, SignedRequestBytes};
use std::hash::Hash;

/// The domain separator to be used when calculating the sender signature for a
/// request to the Internet Computer according to the
/// [interface specification](https://sdk.dfinity.org/docs/interface-spec/index.html).
pub const DOMAIN_IC_REQUEST: &[u8; 11] = b"\x0Aic-request";

pub(crate) const DOMAIN_NOTARIZATION_CONTENT: &str = "notarization_content_domain";
const DOMAIN_NOTARIZATION: &str = "notarization_domain";
const DOMAIN_NOTARIZATION_SHARE: &str = "notarization_share_domain";

pub(crate) const DOMAIN_FINALIZATION_CONTENT: &str = "finalization_content_domain";
const DOMAIN_FINALIZATION: &str = "finalization_domain";
const DOMAIN_FINALIZATION_SHARE: &str = "finalization_share_domain";

pub(crate) const DOMAIN_BLOCK: &str = "block_domain";
const DOMAIN_BLOCK_PROPOSAL: &str = "block_proposal_domain";

const DOMAIN_INMEMORY_PAYLOAD: &str = "inmemory_payload_domain";

pub(crate) const DOMAIN_RANDOM_BEACON_CONTENT: &str = "random_beacon_content_domain";
const DOMAIN_RANDOM_BEACON: &str = "random_beacon_domain";
const DOMAIN_RANDOM_BEACON_SHARE: &str = "random_beacon_share_domain";

pub(crate) const DOMAIN_CERTIFICATION_CONTENT: &str = "ic-state-root";
const DOMAIN_CERTIFICATION: &str = "certification_domain";
const DOMAIN_CERTIFICATION_SHARE: &str = "certification_share_domain";

pub(crate) const DOMAIN_DEALING_CONTENT: &str = "dealing_content_non_interactive";

const DOMAIN_DKG_MESSAGE: &str = "dkg_message_non_interactive";

const DOMAIN_HTTP_CANISTER_UPDATE: &str = "http_canister_update_domain";

const DOMAIN_SIGNED_REQUEST_BYTES: &str = "signed_request_bytes_domain";

const DOMAIN_MESSAGEID: &str = "messageid_domain";

pub(crate) const DOMAIN_RANDOM_TAPE_CONTENT: &str = "random_tape_content_domain";
const DOMAIN_RANDOM_TAPE: &str = "random_tape_domain";
const DOMAIN_RANDOM_TAPE_SHARE: &str = "random_tape_share_domain";

pub(crate) const DOMAIN_CATCH_UP_CONTENT: &str = "catch_up_content_domain";
const DOMAIN_CATCH_UP_CONTENT_PROTO: &str = "catch_up_content_proto_domain";
const DOMAIN_CATCH_UP_SHARE_CONTENT: &str = "catch_up_share_content_domain";
const DOMAIN_CATCH_UP_PACKAGE: &str = "catch_up_package_domain";
const DOMAIN_CATCH_UP_PACKAGE_SHARE: &str = "catch_up_package_share_domain";

const DOMAIN_STATE_SYNC_MESSAGE: &str = "state_sync_message_domain";
const DOMAIN_CONSENSUS_MESSAGE: &str = "consensus_message_domain";
const DOMAIN_CERTIFICATION_MESSAGE: &str = "certification_message_domain";

/// A cryptographically hashable type.
pub trait CryptoHashable: CryptoHashDomain + Hash {}
impl<T> CryptoHashable for T where T: CryptoHashDomain + Hash {}

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
    impl CryptoHashDomainSeal for Signed<HashedBlock, BasicSignature<Block>> {}

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

    impl CryptoHashDomainSeal for StateSyncMessage {}
    impl CryptoHashDomainSeal for ConsensusMessage {}
    impl CryptoHashDomainSeal for CertificationMessage {}

    impl CryptoHashDomainSeal for CryptoHashableTestDummy {}
}

impl CryptoHashDomain for NotarizationContent {
    fn domain(&self) -> String {
        DOMAIN_NOTARIZATION_CONTENT.to_string()
    }
}

impl CryptoHashDomain for Signed<NotarizationContent, MultiSignature<NotarizationContent>> {
    fn domain(&self) -> String {
        DOMAIN_NOTARIZATION.to_string()
    }
}

impl CryptoHashDomain for Signed<NotarizationContent, MultiSignatureShare<NotarizationContent>> {
    fn domain(&self) -> String {
        DOMAIN_NOTARIZATION_SHARE.to_string()
    }
}

impl CryptoHashDomain for FinalizationContent {
    fn domain(&self) -> String {
        DOMAIN_FINALIZATION_CONTENT.to_string()
    }
}

impl CryptoHashDomain for Signed<FinalizationContent, MultiSignature<FinalizationContent>> {
    fn domain(&self) -> String {
        DOMAIN_FINALIZATION.to_string()
    }
}

impl CryptoHashDomain for Signed<FinalizationContent, MultiSignatureShare<FinalizationContent>> {
    fn domain(&self) -> String {
        DOMAIN_FINALIZATION_SHARE.to_string()
    }
}

impl CryptoHashDomain for CertificationContent {
    fn domain(&self) -> String {
        DOMAIN_CERTIFICATION_CONTENT.to_string()
    }
}

impl CryptoHashDomain for Certification {
    fn domain(&self) -> String {
        DOMAIN_CERTIFICATION.to_string()
    }
}

impl CryptoHashDomain for CertificationShare {
    fn domain(&self) -> String {
        DOMAIN_CERTIFICATION_SHARE.to_string()
    }
}

impl CryptoHashDomain for Block {
    fn domain(&self) -> String {
        DOMAIN_BLOCK.to_string()
    }
}

impl CryptoHashDomain for Signed<HashedBlock, BasicSignature<Block>> {
    fn domain(&self) -> String {
        DOMAIN_BLOCK_PROPOSAL.to_string()
    }
}

impl CryptoHashDomain for BlockPayload {
    fn domain(&self) -> String {
        DOMAIN_INMEMORY_PAYLOAD.to_string()
    }
}

impl CryptoHashDomain for RandomBeaconContent {
    fn domain(&self) -> String {
        DOMAIN_RANDOM_BEACON_CONTENT.to_string()
    }
}

impl CryptoHashDomain for Signed<RandomBeaconContent, ThresholdSignature<RandomBeaconContent>> {
    fn domain(&self) -> String {
        DOMAIN_RANDOM_BEACON.to_string()
    }
}

impl CryptoHashDomain
    for Signed<RandomBeaconContent, ThresholdSignatureShare<RandomBeaconContent>>
{
    fn domain(&self) -> String {
        DOMAIN_RANDOM_BEACON_SHARE.to_string()
    }
}

impl CryptoHashDomain for consensus_dkg::DealingContent {
    fn domain(&self) -> String {
        DOMAIN_DEALING_CONTENT.to_string()
    }
}

impl CryptoHashDomain for consensus_dkg::Message {
    fn domain(&self) -> String {
        DOMAIN_DKG_MESSAGE.to_string()
    }
}

impl CryptoHashDomain for HttpCanisterUpdate {
    fn domain(&self) -> String {
        DOMAIN_HTTP_CANISTER_UPDATE.to_string()
    }
}

impl CryptoHashDomain for SignedRequestBytes {
    fn domain(&self) -> String {
        DOMAIN_SIGNED_REQUEST_BYTES.to_string()
    }
}

impl CryptoHashDomain for MessageId {
    fn domain(&self) -> String {
        DOMAIN_MESSAGEID.to_string()
    }
}

impl CryptoHashDomain for RandomTapeContent {
    fn domain(&self) -> String {
        DOMAIN_RANDOM_TAPE_CONTENT.to_string()
    }
}

impl CryptoHashDomain for Signed<RandomTapeContent, ThresholdSignature<RandomTapeContent>> {
    fn domain(&self) -> String {
        DOMAIN_RANDOM_TAPE.to_string()
    }
}

impl CryptoHashDomain for Signed<RandomTapeContent, ThresholdSignatureShare<RandomTapeContent>> {
    fn domain(&self) -> String {
        DOMAIN_RANDOM_TAPE_SHARE.to_string()
    }
}

impl CryptoHashDomain for CatchUpContent {
    fn domain(&self) -> String {
        DOMAIN_CATCH_UP_CONTENT.to_string()
    }
}

impl CryptoHashDomain for CatchUpContentProtobufBytes {
    fn domain(&self) -> String {
        DOMAIN_CATCH_UP_CONTENT_PROTO.to_string()
    }
}

impl CryptoHashDomain for CatchUpShareContent {
    fn domain(&self) -> String {
        DOMAIN_CATCH_UP_SHARE_CONTENT.to_string()
    }
}

impl CryptoHashDomain for Signed<CatchUpContent, ThresholdSignature<CatchUpContent>> {
    fn domain(&self) -> String {
        DOMAIN_CATCH_UP_PACKAGE.to_string()
    }
}

impl CryptoHashDomain for Signed<CatchUpShareContent, ThresholdSignatureShare<CatchUpContent>> {
    fn domain(&self) -> String {
        DOMAIN_CATCH_UP_PACKAGE_SHARE.to_string()
    }
}

impl CryptoHashDomain for StateSyncMessage {
    fn domain(&self) -> String {
        DOMAIN_STATE_SYNC_MESSAGE.to_string()
    }
}

impl CryptoHashDomain for ConsensusMessage {
    fn domain(&self) -> String {
        DOMAIN_CONSENSUS_MESSAGE.to_string()
    }
}

impl CryptoHashDomain for CertificationMessage {
    fn domain(&self) -> String {
        DOMAIN_CERTIFICATION_MESSAGE.to_string()
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CryptoHashableTestDummy(pub Vec<u8>);
