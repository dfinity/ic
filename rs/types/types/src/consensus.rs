//! Defines types used internally by consensus components.
use crate::{
    artifact::ConsensusMessageId,
    batch::{BatchPayload, ValidationContext},
    crypto::threshold_sig::ni_dkg::NiDkgId,
    crypto::*,
    replica_version::ReplicaVersion,
    signature::*,
    *,
};
use ic_base_types::subnet_id_try_from_option;
use ic_base_types::PrincipalIdError;
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_protobuf::types::v1::{self as pb, consensus_message::Msg};
use ic_protobuf::{
    log::block_log_entry::v1::BlockLogEntry,
    proxy::{try_from_option_field, ProxyDecodeError},
};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::hash::Hash;
use std::{cmp::PartialOrd, convert::Infallible};

pub mod block_maker;
pub mod catchup;
pub mod certification;
pub mod dkg;
pub mod hashed;
pub mod idkg;
mod payload;
pub mod thunk;

pub use catchup::*;
use hashed::Hashed;
pub use payload::{BlockPayload, DataPayload, Payload, PayloadType, SummaryPayload};

use self::artifact::{IdentifiableArtifact, PbArtifact};

/// Abstract messages with height attribute
pub trait HasHeight {
    fn height(&self) -> Height;
}

/// Abstract messages with block hash
pub trait HasBlockHash {
    fn block_hash(&self) -> &CryptoHashOf<Block>;
}

/// Abstract messages with rank attribute
pub trait HasRank {
    fn rank(&self) -> Rank;
}

/// Abstract messages with committee attribute
pub trait HasCommittee {
    fn committee() -> Committee;
}

/// Abstract messages with version attribute
pub trait HasVersion {
    fn version(&self) -> &ReplicaVersion;
}

/// Abstract messages that may be a share or not
pub trait IsShare {
    fn is_share(&self) -> bool;
}

/// Abstract messages with hash attribute. The [`hash`] implementation is expected
/// to return an existing hash value, instead of computing one.
pub trait HasHash {
    fn hash(&self) -> &CryptoHash;
}

impl<T: HasHeight, S> HasHeight for Signed<T, S> {
    fn height(&self) -> Height {
        self.content.height()
    }
}

impl<T: HasBlockHash, S> HasBlockHash for Signed<T, S> {
    fn block_hash(&self) -> &CryptoHashOf<Block> {
        self.content.block_hash()
    }
}

impl<T: HasRank, S> HasRank for Signed<T, S> {
    fn rank(&self) -> Rank {
        self.content.rank()
    }
}

impl<T: HasCommittee, S> HasCommittee for Signed<T, S> {
    fn committee() -> Committee {
        T::committee()
    }
}

impl<T: HasVersion, S> HasVersion for Signed<T, S> {
    fn version(&self) -> &ReplicaVersion {
        self.content.version()
    }
}

impl HasVersion for Block {
    fn version(&self) -> &ReplicaVersion {
        &self.version
    }
}

impl<H, T: HasVersion> HasVersion for Hashed<H, T> {
    fn version(&self) -> &ReplicaVersion {
        self.value.version()
    }
}

impl HasHeight for Block {
    fn height(&self) -> Height {
        self.height
    }
}

impl<H, T: HasHeight> HasHeight for Hashed<H, T> {
    fn height(&self) -> Height {
        self.value.height()
    }
}

impl HasRank for Block {
    fn rank(&self) -> Rank {
        self.rank
    }
}

impl<H, T: HasRank> HasRank for Hashed<H, T> {
    fn rank(&self) -> Rank {
        self.value.rank()
    }
}

impl HasVersion for NotarizationContent {
    fn version(&self) -> &ReplicaVersion {
        &self.version
    }
}

impl HasHeight for NotarizationContent {
    fn height(&self) -> Height {
        self.height
    }
}

impl HasBlockHash for HashedBlock {
    fn block_hash(&self) -> &CryptoHashOf<Block> {
        &self.hash
    }
}

impl HasBlockHash for NotarizationContent {
    fn block_hash(&self) -> &CryptoHashOf<Block> {
        &self.block
    }
}

impl HasCommittee for NotarizationContent {
    fn committee() -> Committee {
        Committee::Notarization
    }
}

impl HasVersion for FinalizationContent {
    fn version(&self) -> &ReplicaVersion {
        &self.version
    }
}

impl HasHeight for FinalizationContent {
    fn height(&self) -> Height {
        self.height
    }
}

impl HasBlockHash for FinalizationContent {
    fn block_hash(&self) -> &CryptoHashOf<Block> {
        &self.block
    }
}

impl HasCommittee for FinalizationContent {
    fn committee() -> Committee {
        Committee::Notarization
    }
}

impl HasVersion for RandomBeaconContent {
    fn version(&self) -> &ReplicaVersion {
        &self.version
    }
}

impl HasHeight for RandomBeaconContent {
    fn height(&self) -> Height {
        self.height
    }
}

impl HasCommittee for RandomBeaconContent {
    fn committee() -> Committee {
        Committee::LowThreshold
    }
}

impl HasVersion for RandomTapeContent {
    fn version(&self) -> &ReplicaVersion {
        &self.version
    }
}

impl HasHeight for RandomTapeContent {
    fn height(&self) -> Height {
        self.height
    }
}

impl HasCommittee for RandomTapeContent {
    fn committee() -> Committee {
        Committee::LowThreshold
    }
}

impl HasVersion for EquivocationProof {
    fn version(&self) -> &ReplicaVersion {
        &self.version
    }
}

impl HasHeight for EquivocationProof {
    fn height(&self) -> Height {
        self.height
    }
}

impl HasVersion for BlockMetadata {
    fn version(&self) -> &ReplicaVersion {
        &self.version
    }
}

impl HasHeight for BlockMetadata {
    fn height(&self) -> Height {
        self.height
    }
}

/// Rank is used to indicate the priority of a block maker, where 0 indicates
/// the highest priority.
#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct Rank(pub u64);

/// Block is the type that is used to create blocks out of which we build a
/// block chain
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct Block {
    pub version: ReplicaVersion,
    /// the parent block that this block extends, forming a block chain
    pub parent: CryptoHashOf<Block>,
    /// the payload of the block
    pub payload: Payload,
    /// the height of the block, which is the height of the parent + 1
    pub height: Height,
    /// rank indicates the rank of the block maker that created this block
    pub rank: Rank,
    /// the context with respect to which this block should be validated
    pub context: ValidationContext,
}

impl Block {
    /// Create a new block
    pub fn new(
        parent: CryptoHashOf<Block>,
        payload: Payload,
        height: Height,
        rank: Rank,
        context: ValidationContext,
    ) -> Self {
        Block {
            version: ReplicaVersion::default(),
            parent,
            payload,
            height,
            rank,
            context,
        }
    }

    /// Create a BlockLogEntry from this block
    pub fn log_entry(&self, block_hash: String) -> BlockLogEntry {
        BlockLogEntry {
            byte_size: None,
            certified_height: Some(self.context.certified_height.get()),
            dkg_payload_type: Some(self.payload.as_ref().payload_type().to_string()),
            hash: Some(block_hash),
            height: Some(self.height.get()),
            parent_hash: Some(hex::encode(self.parent.get_ref().0.clone())),
            rank: Some(self.rank.0),
            registry_version: Some(self.context.registry_version.get()),
            time: Some(self.context.time.as_nanos_since_unix_epoch()),
            version: Some(self.version().to_string()),
        }
    }
}

impl SignedBytesWithoutDomainSeparator for BlockMetadata {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).unwrap()
    }
}

/// HashedBlock contains a Block together with its hash
pub type HashedBlock = Hashed<CryptoHashOf<Block>, Block>;

/// BlockMetadata contains the version, height and hash of a block
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct BlockMetadata {
    version: ReplicaVersion,
    height: Height,
    subnet_id: SubnetId,
    hash: CryptoHashOf<Block>,
}

impl BlockMetadata {
    pub fn subnet_id(&self) -> SubnetId {
        self.subnet_id
    }

    pub fn from_block(block: &HashedBlock, subnet_id: SubnetId) -> Self {
        Self {
            version: block.version().clone(),
            height: block.height(),
            subnet_id,
            hash: block.get_hash().clone(),
        }
    }

    /// Creates a signed block metadata instance from a given block proposal.
    pub fn signed_from_proposal(
        proposal: &BlockProposal,
        subnet_id: SubnetId,
    ) -> Signed<Self, BasicSignature<Self>> {
        Signed {
            content: Self::from_block(&proposal.content, subnet_id),
            signature: proposal.signature.clone(),
        }
    }
}

impl HasHash for BlockMetadata {
    fn hash(&self) -> &CryptoHash {
        self.hash.get_ref()
    }
}

/// A BlockProposal is a HashedBlock with BlockMetadata signed by the block maker.
pub type BlockProposal = Signed<HashedBlock, BasicSignature<BlockMetadata>>;

impl From<&BlockProposal> for pb::BlockProposal {
    fn from(block_proposal: &BlockProposal) -> Self {
        Self {
            hash: block_proposal.content.hash.clone().get().0,
            value: Some((&block_proposal.content.value).into()),
            signature: block_proposal.signature.signature.clone().get().0,
            signer: Some(node_id_into_protobuf(block_proposal.signature.signer)),
        }
    }
}

impl TryFrom<pb::BlockProposal> for BlockProposal {
    type Error = ProxyDecodeError;

    fn try_from(block_proposal: pb::BlockProposal) -> Result<Self, Self::Error> {
        Ok(Signed {
            content: Hashed {
                value: try_from_option_field(block_proposal.value, "BlockProposal::value")?,
                hash: CryptoHashOf::from(CryptoHash(block_proposal.hash)),
            },
            signature: BasicSignature {
                signature: BasicSigOf::from(BasicSig(block_proposal.signature)),
                signer: node_id_try_from_option(block_proposal.signer)?,
            },
        })
    }
}

impl From<BlockProposal> for Block {
    fn from(proposal: BlockProposal) -> Block {
        proposal.content.value
    }
}

impl AsRef<Block> for BlockProposal {
    fn as_ref(&self) -> &Block {
        self.content.as_ref()
    }
}

/// NotarizationContent holds the values that are signed in a notarization
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct NotarizationContent {
    pub version: ReplicaVersion,
    pub height: Height,
    pub block: CryptoHashOf<Block>,
}

impl NotarizationContent {
    /// Create a new notarization content from a height and a block hash
    pub fn new(height: Height, block: CryptoHashOf<Block>) -> Self {
        NotarizationContent {
            version: ReplicaVersion::default(),
            height,
            block,
        }
    }
}

impl SignedBytesWithoutDomainSeparator for NotarizationContent {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).unwrap()
    }
}

/// A notarization is a multi-signature on a NotarizationContent
pub type Notarization = Signed<NotarizationContent, MultiSignature<NotarizationContent>>;

impl From<&Notarization> for pb::Notarization {
    fn from(notarization: &Notarization) -> Self {
        Self {
            version: notarization.content.version.to_string(),
            height: notarization.content.height.get(),
            block: notarization.content.block.clone().get().0,
            signature: notarization.signature.signature.clone().get().0,
            signers: notarization
                .signature
                .signers
                .iter()
                .map(|node_id| (*node_id).get().into_vec())
                .collect(),
        }
    }
}

impl TryFrom<pb::Notarization> for Notarization {
    type Error = ProxyDecodeError;
    fn try_from(notarization: pb::Notarization) -> Result<Self, Self::Error> {
        Ok(Signed {
            content: NotarizationContent {
                version: ReplicaVersion::try_from(notarization.version.as_str())?,
                height: Height::from(notarization.height),
                block: CryptoHashOf::from(CryptoHash(notarization.block)),
            },
            signature: MultiSignature {
                signature: CombinedMultiSigOf::from(CombinedMultiSig(notarization.signature)),
                signers: notarization
                    .signers
                    .iter()
                    .map(|n| Ok(NodeId::from(PrincipalId::try_from(&n[..])?)))
                    .collect::<Result<_, PrincipalIdError>>()?,
            },
        })
    }
}

/// A notarization share is a multi-signature share on a notarization content.
/// If sufficiently many replicas create notarization shares, the shares can be
/// aggregated into a full notarization.
pub type NotarizationShare = Signed<NotarizationContent, MultiSignatureShare<NotarizationContent>>;

impl From<&NotarizationShare> for pb::NotarizationShare {
    fn from(notarization: &NotarizationShare) -> Self {
        Self {
            version: notarization.content.version.to_string(),
            height: notarization.content.height.get(),
            block: notarization.content.block.clone().get().0,
            signature: notarization.signature.signature.clone().get().0,
            signer: Some(node_id_into_protobuf(notarization.signature.signer)),
        }
    }
}

impl TryFrom<pb::NotarizationShare> for NotarizationShare {
    type Error = ProxyDecodeError;
    fn try_from(notarization: pb::NotarizationShare) -> Result<Self, Self::Error> {
        Ok(Signed {
            content: NotarizationContent {
                version: ReplicaVersion::try_from(notarization.version.as_str())?,
                height: Height::from(notarization.height),
                block: CryptoHashOf::from(CryptoHash(notarization.block)),
            },
            signature: MultiSignatureShare {
                signature: IndividualMultiSigOf::new(IndividualMultiSig(notarization.signature)),
                signer: node_id_try_from_option(notarization.signer)?,
            },
        })
    }
}

/// FinalizationContent holds the values that are signed in a finalization
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct FinalizationContent {
    pub version: ReplicaVersion,
    pub height: Height,
    pub block: CryptoHashOf<Block>,
}

impl FinalizationContent {
    pub fn new(height: Height, block: CryptoHashOf<Block>) -> Self {
        FinalizationContent {
            version: ReplicaVersion::default(),
            height,
            block,
        }
    }
}

impl SignedBytesWithoutDomainSeparator for FinalizationContent {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).unwrap()
    }
}

/// A finalization is a multi-signature on a FinalizationContent. A finalization
/// proves that the block identified by the block hash in the finalization
/// content (and the block chain it implies) is agreed upon.
pub type Finalization = Signed<FinalizationContent, MultiSignature<FinalizationContent>>;

impl From<&Finalization> for pb::Finalization {
    fn from(finalization: &Finalization) -> Self {
        Self {
            version: finalization.content.version.to_string(),
            height: finalization.content.height.get(),
            block: finalization.content.block.clone().get().0,
            signature: finalization.signature.signature.clone().get().0,
            signers: finalization
                .signature
                .signers
                .iter()
                .map(|node_id| (*node_id).get().into_vec())
                .collect(),
        }
    }
}

impl TryFrom<pb::Finalization> for Finalization {
    type Error = ProxyDecodeError;
    fn try_from(finalization: pb::Finalization) -> Result<Self, Self::Error> {
        Ok(Signed {
            content: FinalizationContent {
                version: ReplicaVersion::try_from(finalization.version.as_str())?,
                height: Height::from(finalization.height),
                block: CryptoHashOf::from(CryptoHash(finalization.block)),
            },
            signature: MultiSignature {
                signature: CombinedMultiSigOf::from(CombinedMultiSig(finalization.signature)),
                signers: finalization
                    .signers
                    .iter()
                    .map(|n| Ok(NodeId::from(PrincipalId::try_from(&n[..])?)))
                    .collect::<Result<_, PrincipalIdError>>()?,
            },
        })
    }
}

/// A finalization share is a multi-signature share on a finalization content.
/// If sufficiently many replicas create finalization shares, the shares can be
/// aggregated into a full finalization.
pub type FinalizationShare = Signed<FinalizationContent, MultiSignatureShare<FinalizationContent>>;

impl From<&FinalizationShare> for pb::FinalizationShare {
    fn from(finalization: &FinalizationShare) -> Self {
        Self {
            version: finalization.content.version.to_string(),
            height: finalization.content.height.get(),
            block: finalization.content.block.clone().get().0,
            signature: finalization.signature.signature.clone().get().0,
            signer: Some(node_id_into_protobuf(finalization.signature.signer)),
        }
    }
}

impl TryFrom<pb::FinalizationShare> for FinalizationShare {
    type Error = ProxyDecodeError;
    fn try_from(finalization: pb::FinalizationShare) -> Result<Self, Self::Error> {
        Ok(Signed {
            content: FinalizationContent {
                version: ReplicaVersion::try_from(finalization.version.as_str())?,
                height: Height::from(finalization.height),
                block: CryptoHashOf::from(CryptoHash(finalization.block)),
            },
            signature: MultiSignatureShare {
                signature: IndividualMultiSigOf::new(IndividualMultiSig(finalization.signature)),
                signer: node_id_try_from_option(finalization.signer)?,
            },
        })
    }
}
/// RandomBeaconContent holds the content that is signed in the random beacon,
/// which is the previous random beacon, the height, and the replica version
/// used to create the random beacon.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct RandomBeaconContent {
    pub version: ReplicaVersion,
    pub height: Height,
    pub parent: CryptoHashOf<RandomBeacon>,
}

/// HashedRandomBeacon holds a RandomBeacon and its hash
pub type HashedRandomBeacon = Hashed<CryptoHashOf<RandomBeacon>, RandomBeacon>;

impl RandomBeaconContent {
    /// Create a new RandomBeaconContent with a given height and parent
    /// RandomBeacon
    pub fn new(height: Height, parent: CryptoHashOf<RandomBeacon>) -> Self {
        Self {
            version: ReplicaVersion::default(),
            height,
            parent,
        }
    }
}

impl SignedBytesWithoutDomainSeparator for RandomBeaconContent {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).unwrap()
    }
}

/// A RandomBeacon is a RandomBeaconContent signed using a threshold signature.
/// The RandomBeacon provides pseudo-randomness to the consensus protocol that
/// is used to assign ranks to block makers and determine which replicas are
/// notaries.
pub type RandomBeacon = Signed<RandomBeaconContent, ThresholdSignature<RandomBeaconContent>>;

impl From<&RandomBeacon> for pb::RandomBeacon {
    fn from(random_beacon: &RandomBeacon) -> Self {
        Self {
            version: random_beacon.content.version.to_string(),
            height: random_beacon.content.height.get(),
            parent: random_beacon.content.parent.clone().get().0,
            signature: random_beacon.signature.signature.clone().get().0,
            signer: Some(pb::NiDkgId::from(random_beacon.signature.signer)),
        }
    }
}

impl TryFrom<pb::RandomBeacon> for RandomBeacon {
    type Error = ProxyDecodeError;

    fn try_from(beacon: pb::RandomBeacon) -> Result<Self, Self::Error> {
        Ok(Signed {
            content: RandomBeaconContent {
                version: ReplicaVersion::try_from(beacon.version)?,
                height: Height::from(beacon.height),
                parent: CryptoHashOf::from(CryptoHash(beacon.parent)),
            },
            signature: ThresholdSignature {
                signature: CombinedThresholdSigOf::new(CombinedThresholdSig(beacon.signature)),
                signer: try_from_option_field(beacon.signer, "RandomBeacon::signer")?,
            },
        })
    }
}

/// RandomBeaconShare is a threshold signature share on a RandomBeaconContent.
/// If sufficiently many replicas create random beacon shares, the shares can be
/// aggregated into a RandomBeacon.
pub type RandomBeaconShare =
    Signed<RandomBeaconContent, ThresholdSignatureShare<RandomBeaconContent>>;

impl From<&RandomBeaconShare> for pb::RandomBeaconShare {
    fn from(random_beacon: &RandomBeaconShare) -> Self {
        Self {
            version: random_beacon.content.version.to_string(),
            height: random_beacon.content.height.get(),
            parent: random_beacon.content.parent.clone().get().0,
            signature: random_beacon.signature.signature.clone().get().0,
            signer: Some(node_id_into_protobuf(random_beacon.signature.signer)),
        }
    }
}

impl TryFrom<pb::RandomBeaconShare> for RandomBeaconShare {
    type Error = ProxyDecodeError;

    fn try_from(beacon: pb::RandomBeaconShare) -> Result<Self, Self::Error> {
        Ok(Signed {
            content: RandomBeaconContent {
                version: ReplicaVersion::try_from(beacon.version)?,
                height: Height::from(beacon.height),
                parent: CryptoHashOf::from(CryptoHash(beacon.parent)),
            },
            signature: ThresholdSignatureShare {
                signature: ThresholdSigShareOf::new(ThresholdSigShare(beacon.signature)),
                signer: node_id_try_from_option(beacon.signer)?,
            },
        })
    }
}
/// RandomTapeContent holds the content that is signed in the random tape,
/// which is the height and the replica version used to create the random
/// tape.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct RandomTapeContent {
    pub version: ReplicaVersion,
    pub height: Height,
}

impl SignedBytesWithoutDomainSeparator for RandomTapeContent {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).unwrap()
    }
}

impl RandomTapeContent {
    /// Create a new RandomTapeContent from a given height
    pub fn new(height: Height) -> Self {
        RandomTapeContent {
            version: ReplicaVersion::default(),
            height,
        }
    }
}

/// A RandomTape is a RandomTapeContent signed using a threshold signature.
/// The RandomTape provides pseudo-randomness for executing the messages ordered
/// by consensus.
pub type RandomTape = Signed<RandomTapeContent, ThresholdSignature<RandomTapeContent>>;

impl From<&RandomTape> for pb::RandomTape {
    fn from(random_tape: &RandomTape) -> Self {
        Self {
            version: random_tape.content.version.to_string(),
            height: random_tape.content.height.get(),
            signature: random_tape.signature.signature.clone().get().0,
            signer: Some(pb::NiDkgId::from(random_tape.signature.signer)),
        }
    }
}

impl TryFrom<pb::RandomTape> for RandomTape {
    type Error = ProxyDecodeError;

    fn try_from(tape: pb::RandomTape) -> Result<Self, Self::Error> {
        Ok(Signed {
            content: RandomTapeContent {
                version: ReplicaVersion::try_from(tape.version)?,
                height: Height::from(tape.height),
            },
            signature: ThresholdSignature {
                signature: CombinedThresholdSigOf::new(CombinedThresholdSig(tape.signature)),
                signer: try_from_option_field(tape.signer, "RandomTape::signer")?,
            },
        })
    }
}

/// RandomTapeShare is a threshold signature share on a RandomTapeContent. If
/// sufficiently many replicas create random tape shares, the shares can be
/// aggregated into a RandomTape.
pub type RandomTapeShare = Signed<RandomTapeContent, ThresholdSignatureShare<RandomTapeContent>>;

impl From<&RandomTapeShare> for pb::RandomTapeShare {
    fn from(tape_share: &RandomTapeShare) -> Self {
        Self {
            version: tape_share.content.version.to_string(),
            height: tape_share.content.height.get(),
            signature: tape_share.signature.signature.clone().get().0,
            signer: Some(node_id_into_protobuf(tape_share.signature.signer)),
        }
    }
}

impl TryFrom<pb::RandomTapeShare> for RandomTapeShare {
    type Error = ProxyDecodeError;

    fn try_from(tape_share: pb::RandomTapeShare) -> Result<Self, Self::Error> {
        Ok(Signed {
            content: RandomTapeContent {
                version: ReplicaVersion::try_from(tape_share.version)?,
                height: Height::from(tape_share.height),
            },
            signature: ThresholdSignatureShare {
                signature: ThresholdSigShareOf::new(ThresholdSigShare(tape_share.signature)),
                signer: node_id_try_from_option(tape_share.signer)?,
            },
        })
    }
}

/// A proof that shows a block maker has produced equivocating blocks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct EquivocationProof {
    pub signer: NodeId,
    pub version: ReplicaVersion,
    pub height: Height,
    pub subnet_id: SubnetId,
    // Hash and signature of the first and second blocks
    pub hash1: CryptoHashOf<Block>,
    pub signature1: BasicSigOf<BlockMetadata>,
    pub hash2: CryptoHashOf<Block>,
    pub signature2: BasicSigOf<BlockMetadata>,
}

impl EquivocationProof {
    /// Returns two signed block metadata. This function guarantees that the
    /// signers, replica version, height and subnet id of the two objects are
    /// identical.
    pub fn into_signed_metadata(
        &self,
    ) -> (
        Signed<BlockMetadata, BasicSignature<BlockMetadata>>,
        Signed<BlockMetadata, BasicSignature<BlockMetadata>>,
    ) {
        (
            Signed {
                content: BlockMetadata {
                    version: self.version.clone(),
                    height: self.height,
                    subnet_id: self.subnet_id,
                    hash: self.hash1.clone(),
                },
                signature: BasicSignature {
                    signature: self.signature1.clone(),
                    signer: self.signer,
                },
            },
            Signed {
                content: BlockMetadata {
                    version: self.version.clone(),
                    height: self.height,
                    subnet_id: self.subnet_id,
                    hash: self.hash2.clone(),
                },
                signature: BasicSignature {
                    signature: self.signature2.clone(),
                    signer: self.signer,
                },
            },
        )
    }
}

impl From<&EquivocationProof> for pb::EquivocationProof {
    fn from(proof: &EquivocationProof) -> Self {
        Self {
            signer: Some(node_id_into_protobuf(proof.signer)),
            version: proof.version.to_string(),
            height: proof.height.get(),
            subnet_id: Some(subnet_id_into_protobuf(proof.subnet_id)),
            hash1: proof.hash1.clone().get().0,
            signature1: proof.signature1.clone().get().0,
            hash2: proof.hash2.clone().get().0,
            signature2: proof.signature2.clone().get().0,
        }
    }
}

impl TryFrom<pb::EquivocationProof> for EquivocationProof {
    type Error = ProxyDecodeError;
    fn try_from(proof: pb::EquivocationProof) -> Result<Self, Self::Error> {
        Ok(Self {
            signer: node_id_try_from_option(proof.signer)?,
            version: ReplicaVersion::try_from(proof.version)?,
            height: Height::new(proof.height),
            subnet_id: subnet_id_try_from_option(proof.subnet_id)?,
            hash1: CryptoHashOf::new(CryptoHash(proof.hash1)),
            signature1: BasicSigOf::new(BasicSig(proof.signature1)),
            hash2: CryptoHashOf::new(CryptoHash(proof.hash2)),
            signature2: BasicSigOf::new(BasicSig(proof.signature2)),
        })
    }
}

/// The enum encompassing all of the consensus artifacts exchanged between
/// replicas.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum ConsensusMessage {
    RandomBeacon(RandomBeacon),
    Finalization(Finalization),
    Notarization(Notarization),
    BlockProposal(BlockProposal),
    RandomBeaconShare(RandomBeaconShare),
    NotarizationShare(NotarizationShare),
    FinalizationShare(FinalizationShare),
    RandomTape(RandomTape),
    RandomTapeShare(RandomTapeShare),
    CatchUpPackage(CatchUpPackage),
    CatchUpPackageShare(CatchUpPackageShare),
    EquivocationProof(EquivocationProof),
}

impl IdentifiableArtifact for ConsensusMessage {
    const NAME: &'static str = "consensus";
    type Id = ConsensusMessageId;
    type Attribute = ();
    fn id(&self) -> Self::Id {
        self.get_id()
    }
    fn attribute(&self) -> Self::Attribute {}
}

impl PbArtifact for ConsensusMessage {
    type PbId = ic_protobuf::types::v1::ConsensusMessageId;
    type PbIdError = ProxyDecodeError;
    type PbMessage = ic_protobuf::types::v1::ConsensusMessage;
    type PbMessageError = ProxyDecodeError;
    type PbAttribute = ();
    type PbAttributeError = Infallible;
}

impl From<ConsensusMessage> for pb::ConsensusMessage {
    fn from(value: ConsensusMessage) -> Self {
        Self {
            msg: Some(match value {
                ConsensusMessage::RandomBeacon(ref x) => Msg::RandomBeacon(x.into()),
                ConsensusMessage::Finalization(ref x) => Msg::Finalization(x.into()),
                ConsensusMessage::Notarization(ref x) => Msg::Notarization(x.into()),
                ConsensusMessage::BlockProposal(ref x) => Msg::BlockProposal(x.into()),
                ConsensusMessage::RandomBeaconShare(ref x) => Msg::RandomBeaconShare(x.into()),
                ConsensusMessage::NotarizationShare(ref x) => Msg::NotarizationShare(x.into()),
                ConsensusMessage::FinalizationShare(ref x) => Msg::FinalizationShare(x.into()),
                ConsensusMessage::RandomTape(ref x) => Msg::RandomTape(x.into()),
                ConsensusMessage::RandomTapeShare(ref x) => Msg::RandomTapeShare(x.into()),
                ConsensusMessage::CatchUpPackage(ref x) => Msg::Cup(x.into()),
                ConsensusMessage::CatchUpPackageShare(ref x) => Msg::CupShare(x.into()),
                ConsensusMessage::EquivocationProof(ref x) => Msg::EquivocationProof(x.into()),
            }),
        }
    }
}

impl TryFrom<pb::ConsensusMessage> for ConsensusMessage {
    type Error = ProxyDecodeError;
    fn try_from(value: pb::ConsensusMessage) -> Result<Self, Self::Error> {
        let Some(msg) = value.msg else {
            return Err(ProxyDecodeError::MissingField("ConsensusMessage::msg"));
        };
        Ok(match msg {
            Msg::RandomBeacon(x) => ConsensusMessage::RandomBeacon(x.try_into()?),
            Msg::Finalization(x) => ConsensusMessage::Finalization(x.try_into()?),
            Msg::Notarization(x) => ConsensusMessage::Notarization(x.try_into()?),
            Msg::BlockProposal(x) => ConsensusMessage::BlockProposal(x.try_into()?),
            Msg::RandomBeaconShare(x) => ConsensusMessage::RandomBeaconShare(x.try_into()?),
            Msg::NotarizationShare(x) => ConsensusMessage::NotarizationShare(x.try_into()?),
            Msg::FinalizationShare(x) => ConsensusMessage::FinalizationShare(x.try_into()?),
            Msg::RandomTape(x) => ConsensusMessage::RandomTape(x.try_into()?),
            Msg::RandomTapeShare(x) => ConsensusMessage::RandomTapeShare(x.try_into()?),
            Msg::Cup(ref x) => ConsensusMessage::CatchUpPackage(x.try_into()?),
            Msg::CupShare(x) => ConsensusMessage::CatchUpPackageShare(x.try_into()?),
            Msg::EquivocationProof(x) => ConsensusMessage::EquivocationProof(x.try_into()?),
        })
    }
}

/// Implements back-and-forth conversion between consensus message and the
/// individual variants' wrapped type. The wrapped type should have the same
/// name as its corresponding enum variant.
macro_rules! impl_cm_conversion {
    ($type:ident) => {
        impl TryFrom<ConsensusMessage> for $type {
            type Error = ConsensusMessage;
            fn try_from(msg: ConsensusMessage) -> Result<Self, Self::Error> {
                match msg {
                    ConsensusMessage::$type(x) => Ok(x),
                    _ => Err(msg),
                }
            }
        }
        impl<'a> TryFrom<&'a ConsensusMessage> for &'a $type {
            type Error = ();
            fn try_from(msg: &'a ConsensusMessage) -> Result<Self, Self::Error> {
                match msg {
                    ConsensusMessage::$type(x) => Ok(x),
                    _ => Err(()),
                }
            }
        }

    };
    ($type:ident, $($rest:ident),+) => {
        impl_cm_conversion!($type);
        impl_cm_conversion!($($rest),+);
    };
}

impl_cm_conversion! {
    RandomBeacon, Finalization, Notarization, BlockProposal, RandomBeaconShare,
    NotarizationShare, FinalizationShare, RandomTape, RandomTapeShare,
    CatchUpPackage, CatchUpPackageShare, EquivocationProof
}

/// ConsensusMessageHash has the same variants as [ConsensusMessage], but
/// contains only a hash instead of the full message in each variant.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ConsensusMessageHash {
    RandomBeacon(CryptoHashOf<RandomBeacon>),
    Finalization(CryptoHashOf<Finalization>),
    Notarization(CryptoHashOf<Notarization>),
    BlockProposal(CryptoHashOf<BlockProposal>),
    RandomBeaconShare(CryptoHashOf<RandomBeaconShare>),
    NotarizationShare(CryptoHashOf<NotarizationShare>),
    FinalizationShare(CryptoHashOf<FinalizationShare>),
    RandomTape(CryptoHashOf<RandomTape>),
    RandomTapeShare(CryptoHashOf<RandomTapeShare>),
    CatchUpPackage(CryptoHashOf<CatchUpPackage>),
    CatchUpPackageShare(CryptoHashOf<CatchUpPackageShare>),
    EquivocationProof(CryptoHashOf<EquivocationProof>),
}

impl From<&ConsensusMessageHash> for pb::ConsensusMessageHash {
    fn from(value: &ConsensusMessageHash) -> Self {
        use pb::consensus_message_hash::Kind;
        let kind = match value.clone() {
            ConsensusMessageHash::RandomBeacon(x) => Kind::RandomBeacon(x.get().0),
            ConsensusMessageHash::Finalization(x) => Kind::Finalization(x.get().0),
            ConsensusMessageHash::Notarization(x) => Kind::Notarization(x.get().0),
            ConsensusMessageHash::BlockProposal(x) => Kind::BlockProposal(x.get().0),
            ConsensusMessageHash::RandomBeaconShare(x) => Kind::RandomBeaconShare(x.get().0),
            ConsensusMessageHash::NotarizationShare(x) => Kind::NotarizationShare(x.get().0),
            ConsensusMessageHash::FinalizationShare(x) => Kind::FinalizationShare(x.get().0),
            ConsensusMessageHash::RandomTape(x) => Kind::RandomTape(x.get().0),
            ConsensusMessageHash::RandomTapeShare(x) => Kind::RandomTapeShare(x.get().0),
            ConsensusMessageHash::CatchUpPackage(x) => Kind::CatchUpPackage(x.get().0),
            ConsensusMessageHash::CatchUpPackageShare(x) => Kind::CatchUpPackageShare(x.get().0),
            ConsensusMessageHash::EquivocationProof(x) => Kind::EquivocationProof(x.get().0),
        };
        Self { kind: Some(kind) }
    }
}

impl TryFrom<&pb::ConsensusMessageHash> for ConsensusMessageHash {
    type Error = ProxyDecodeError;
    fn try_from(value: &pb::ConsensusMessageHash) -> Result<Self, Self::Error> {
        use pb::consensus_message_hash::Kind;
        let kind = value
            .kind
            .clone()
            .ok_or_else(|| ProxyDecodeError::MissingField("ConsensusMessageHash::kind"))?;

        Ok(match kind {
            Kind::RandomBeacon(x) => {
                ConsensusMessageHash::RandomBeacon(CryptoHashOf::new(CryptoHash(x)))
            }
            Kind::Finalization(x) => {
                ConsensusMessageHash::Finalization(CryptoHashOf::new(CryptoHash(x)))
            }
            Kind::Notarization(x) => {
                ConsensusMessageHash::Notarization(CryptoHashOf::new(CryptoHash(x)))
            }
            Kind::BlockProposal(x) => {
                ConsensusMessageHash::BlockProposal(CryptoHashOf::new(CryptoHash(x)))
            }
            Kind::RandomBeaconShare(x) => {
                ConsensusMessageHash::RandomBeaconShare(CryptoHashOf::new(CryptoHash(x)))
            }
            Kind::NotarizationShare(x) => {
                ConsensusMessageHash::NotarizationShare(CryptoHashOf::new(CryptoHash(x)))
            }
            Kind::FinalizationShare(x) => {
                ConsensusMessageHash::FinalizationShare(CryptoHashOf::new(CryptoHash(x)))
            }
            Kind::RandomTape(x) => {
                ConsensusMessageHash::RandomTape(CryptoHashOf::new(CryptoHash(x)))
            }
            Kind::RandomTapeShare(x) => {
                ConsensusMessageHash::RandomTapeShare(CryptoHashOf::new(CryptoHash(x)))
            }
            Kind::CatchUpPackage(x) => {
                ConsensusMessageHash::CatchUpPackage(CryptoHashOf::new(CryptoHash(x)))
            }
            Kind::CatchUpPackageShare(x) => {
                ConsensusMessageHash::CatchUpPackageShare(CryptoHashOf::new(CryptoHash(x)))
            }
            Kind::EquivocationProof(x) => {
                ConsensusMessageHash::EquivocationProof(CryptoHashOf::new(CryptoHash(x)))
            }
        })
    }
}

/// Useful to compare equality by content, for example Signed<C,S> can be
/// compared by equality on C.
pub trait ContentEq {
    /// content_eq compares two values and returns true if their content is
    /// equal. We implement this for signed artifacts, and say that they are
    /// content_eq if the value they sign is equal, even if the signature is
    /// different.
    fn content_eq(&self, other: &Self) -> bool;
}

impl<C: PartialEq, S> ContentEq for Signed<C, S> {
    fn content_eq(&self, other: &Self) -> bool {
        self.content.eq(&other.content)
    }
}

impl ContentEq for EquivocationProof {
    fn content_eq(&self, other: &EquivocationProof) -> bool {
        let same_hash = (self.hash1 == other.hash1 && self.hash2 == other.hash2)
            || (self.hash1 == other.hash2 && self.hash2 == other.hash1);

        self.signer == other.signer
            && self.version == other.version
            && self.height == other.height
            && self.subnet_id == other.subnet_id
            && same_hash
    }
}

impl ContentEq for ConsensusMessage {
    fn content_eq(&self, other: &ConsensusMessage) -> bool {
        match self {
            ConsensusMessage::RandomBeacon(x) => other
                .try_into()
                .is_ok_and(|y: &RandomBeacon| y.content_eq(x)),
            ConsensusMessage::Finalization(x) => other
                .try_into()
                .is_ok_and(|y: &Finalization| y.content_eq(x)),
            ConsensusMessage::Notarization(x) => other
                .try_into()
                .is_ok_and(|y: &Notarization| y.content_eq(x)),
            ConsensusMessage::BlockProposal(x) => other
                .try_into()
                .is_ok_and(|y: &BlockProposal| y.content_eq(x)),
            ConsensusMessage::RandomBeaconShare(x) => other
                .try_into()
                .is_ok_and(|y: &RandomBeaconShare| y.content_eq(x)),
            ConsensusMessage::NotarizationShare(x) => other
                .try_into()
                .is_ok_and(|y: &NotarizationShare| y.content_eq(x)),
            ConsensusMessage::FinalizationShare(x) => other
                .try_into()
                .is_ok_and(|y: &FinalizationShare| y.content_eq(x)),
            ConsensusMessage::RandomTape(x) => {
                other.try_into().is_ok_and(|y: &RandomTape| y.content_eq(x))
            }
            ConsensusMessage::RandomTapeShare(x) => other
                .try_into()
                .is_ok_and(|y: &RandomTapeShare| y.content_eq(x)),
            ConsensusMessage::CatchUpPackage(x) => other
                .try_into()
                .is_ok_and(|y: &CatchUpPackage| y.content_eq(x)),
            ConsensusMessage::CatchUpPackageShare(x) => other
                .try_into()
                .is_ok_and(|y: &CatchUpPackageShare| y.content_eq(x)),
            ConsensusMessage::EquivocationProof(x) => other
                .try_into()
                .is_ok_and(|y: &EquivocationProof| y.content_eq(x)),
        }
    }
}

impl HasVersion for ConsensusMessage {
    fn version(&self) -> &ReplicaVersion {
        match self {
            ConsensusMessage::RandomBeacon(x) => x.version(),
            ConsensusMessage::Finalization(x) => x.version(),
            ConsensusMessage::Notarization(x) => x.version(),
            ConsensusMessage::BlockProposal(x) => x.version(),
            ConsensusMessage::RandomBeaconShare(x) => x.version(),
            ConsensusMessage::NotarizationShare(x) => x.version(),
            ConsensusMessage::FinalizationShare(x) => x.version(),
            ConsensusMessage::RandomTape(x) => x.version(),
            ConsensusMessage::RandomTapeShare(x) => x.version(),
            ConsensusMessage::CatchUpPackage(x) => x.version(),
            ConsensusMessage::CatchUpPackageShare(x) => x.version(),
            ConsensusMessage::EquivocationProof(x) => x.version(),
        }
    }
}

impl HasHeight for ConsensusMessage {
    fn height(&self) -> Height {
        match self {
            ConsensusMessage::RandomBeacon(x) => x.height(),
            ConsensusMessage::Finalization(x) => x.height(),
            ConsensusMessage::Notarization(x) => x.height(),
            ConsensusMessage::BlockProposal(x) => x.height(),
            ConsensusMessage::RandomBeaconShare(x) => x.height(),
            ConsensusMessage::NotarizationShare(x) => x.height(),
            ConsensusMessage::FinalizationShare(x) => x.height(),
            ConsensusMessage::RandomTape(x) => x.height(),
            ConsensusMessage::RandomTapeShare(x) => x.height(),
            ConsensusMessage::CatchUpPackage(x) => x.height(),
            ConsensusMessage::CatchUpPackageShare(x) => x.height(),
            ConsensusMessage::EquivocationProof(x) => x.height(),
        }
    }
}

impl IsShare for ConsensusMessage {
    fn is_share(&self) -> bool {
        match self {
            ConsensusMessage::RandomBeacon(_)
            | ConsensusMessage::RandomTape(_)
            | ConsensusMessage::Notarization(_)
            | ConsensusMessage::Finalization(_)
            | ConsensusMessage::CatchUpPackage(_)
            | ConsensusMessage::BlockProposal(_)
            | ConsensusMessage::EquivocationProof(_) => false,

            ConsensusMessage::RandomBeaconShare(_)
            | ConsensusMessage::RandomTapeShare(_)
            | ConsensusMessage::NotarizationShare(_)
            | ConsensusMessage::FinalizationShare(_)
            | ConsensusMessage::CatchUpPackageShare(_) => true,
        }
    }
}

impl ConsensusMessageHash {
    pub fn digest(&self) -> &CryptoHash {
        match self {
            ConsensusMessageHash::RandomBeacon(hash) => hash.get_ref(),
            ConsensusMessageHash::Finalization(hash) => hash.get_ref(),
            ConsensusMessageHash::Notarization(hash) => hash.get_ref(),
            ConsensusMessageHash::BlockProposal(hash) => hash.get_ref(),
            ConsensusMessageHash::RandomBeaconShare(hash) => hash.get_ref(),
            ConsensusMessageHash::NotarizationShare(hash) => hash.get_ref(),
            ConsensusMessageHash::FinalizationShare(hash) => hash.get_ref(),
            ConsensusMessageHash::RandomTape(hash) => hash.get_ref(),
            ConsensusMessageHash::RandomTapeShare(hash) => hash.get_ref(),
            ConsensusMessageHash::CatchUpPackage(hash) => hash.get_ref(),
            ConsensusMessageHash::CatchUpPackageShare(hash) => hash.get_ref(),
            ConsensusMessageHash::EquivocationProof(hash) => hash.get_ref(),
        }
    }
}

/// Indicates one of the consensus committees that are responsible for creating
/// signature shares on various types of artifacts
#[derive(Debug, PartialEq, Eq)]
pub enum Committee {
    /// LowThreshold indicates the committee that creates threshold signatures
    /// with a low threshold. That is, f+1 out the 3f+1 committee members can
    /// collaboratively create a threshold signature.
    LowThreshold,
    /// HighThreshold indicates the committee that creates threshold signatures
    /// with a high threshold. That is, 2f+1 out the 3f+1 committee members can
    /// collaboratively create a threshold signature.
    HighThreshold,
    /// Notarization indicates the committee that creates notarization and
    /// finalization artifacts by using multi-signatures.
    Notarization,
    /// CanisterHttp indicates the committee for canister http.
    CanisterHttp,
}

/// Threshold indicates how many replicas of a committee need to create a
/// signature share in order to create a signature on behalf of the committee
pub type Threshold = usize;

/// Compute the size of the committee given the total amount of nodes on the
/// subnet
pub fn get_committee_size(nodes_on_subnet: usize) -> usize {
    let f = get_faults_tolerated(nodes_on_subnet);
    3 * f + 1
}

/// Returns the upper limit of faulty participants for `n` participants.
pub fn get_faults_tolerated(n: usize) -> usize {
    (n.max(1) - 1) / 3
}

impl From<&Block> for pb::Block {
    fn from(block: &Block) -> Self {
        let payload: &BlockPayload = block.payload.as_ref();
        let (
            dkg_payload,
            xnet_payload,
            ingress_payload,
            self_validating_payload,
            canister_http_payload_bytes,
            query_stats_payload_bytes,
            idkg_payload,
        ) = if payload.is_summary() {
            (
                pb::DkgPayload::from(&payload.as_summary().dkg),
                None,
                None,
                None,
                vec![],
                vec![],
                payload.as_summary().idkg.as_ref().map(|idkg| idkg.into()),
            )
        } else {
            let batch = &payload.as_data().batch;
            (
                pb::DkgPayload::from(&payload.as_data().dealings),
                Some(pb::XNetPayload::from(&batch.xnet)),
                Some(pb::IngressPayload::from(&batch.ingress)),
                Some(pb::SelfValidatingPayload::from(&batch.self_validating)),
                batch.canister_http.clone(),
                batch.query_stats.clone(),
                payload.as_data().idkg.as_ref().map(|idkg| idkg.into()),
            )
        };
        Self {
            version: block.version.to_string(),
            parent: block.parent.clone().get().0,
            dkg_payload: Some(dkg_payload),
            height: block.height().get(),
            rank: block.rank.0,
            registry_version: block.context.registry_version.get(),
            certified_height: block.context.certified_height.get(),
            time: block.context.time.as_nanos_since_unix_epoch(),
            xnet_payload,
            ingress_payload,
            self_validating_payload,
            canister_http_payload_bytes,
            query_stats_payload_bytes,
            idkg_payload,
            payload_hash: block.payload.get_hash().clone().get().0,
        }
    }
}

impl TryFrom<pb::Block> for Block {
    type Error = ProxyDecodeError;

    fn try_from(block: pb::Block) -> Result<Self, Self::Error> {
        let dkg_payload = try_from_option_field(block.dkg_payload, "Block::dkg_payload")?;

        let batch = BatchPayload {
            ingress: block
                .ingress_payload
                .map(crate::batch::IngressPayload::try_from)
                .transpose()?
                .unwrap_or_default(),
            xnet: block
                .xnet_payload
                .map(crate::batch::XNetPayload::try_from)
                .transpose()?
                .unwrap_or_default(),
            self_validating: block
                .self_validating_payload
                .map(crate::batch::SelfValidatingPayload::try_from)
                .transpose()?
                .unwrap_or_default(),
            canister_http: block.canister_http_payload_bytes,
            query_stats: block.query_stats_payload_bytes,
        };

        let payload = match dkg_payload {
            dkg::Payload::Summary(summary) => {
                if !batch.is_empty() {
                    return Err(ProxyDecodeError::Other(String::from(
                        "Summary block has non-empty batch payload.",
                    )));
                }

                // Convert the idkg summary. Note that the summary may contain
                // transcript references, and here we are NOT checking if these
                // references are valid. Such checks, if required, should be done
                // after converting from protobuf to rust internal type.
                //
                // If after conversion, the summary block is intend to get a different
                // height value (e.g. when a new CUP is created), then a call to
                // idkg.update_refs(height) should be manually called.
                let idkg = block
                    .idkg_payload
                    .as_ref()
                    .map(|idkg| idkg.try_into())
                    .transpose()?;

                BlockPayload::Summary(SummaryPayload { dkg: summary, idkg })
            }
            dkg::Payload::Dealings(dealings) => {
                let idkg = block
                    .idkg_payload
                    .as_ref()
                    .map(|idkg| idkg.try_into())
                    .transpose()?;

                BlockPayload::Data(DataPayload {
                    batch,
                    dealings,
                    idkg,
                })
            }
        };
        Ok(Block {
            version: ReplicaVersion::try_from(block.version)?,
            parent: CryptoHashOf::from(CryptoHash(block.parent)),
            height: Height::from(block.height),
            rank: Rank(block.rank),
            context: ValidationContext {
                registry_version: RegistryVersion::from(block.registry_version),
                certified_height: Height::from(block.certified_height),
                time: Time::from_nanos_since_unix_epoch(block.time),
            },
            // Ideally we would have an integrity check here, but we don't have
            // access to the hash function in this module. This conversion is
            // really only used for retrieving catch up packages and since those
            // are signed, the entire content can be trusted and so this should
            // not be too much of an issue.
            payload: Payload::new_from_hash_and_value(
                CryptoHashOf::from(CryptoHash(block.payload_hash)),
                payload,
            ),
        })
    }
}

impl CountBytes for NiDkgId {
    fn count_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

impl<T> CountBytes for ThresholdSignature<T> {
    fn count_bytes(&self) -> usize {
        self.signature.get_ref().0.len() + self.signer.count_bytes()
    }
}

pub trait ConsensusMessageHashable: Clone {
    fn get_id(&self) -> ConsensusMessageId;
    fn get_cm_hash(&self) -> ConsensusMessageHash;
    fn assert(msg: &ConsensusMessage) -> Option<&Self>;
    fn into_message(self) -> ConsensusMessage;

    /// Check integrity of a message. Default is false.
    /// This should be implemented for those that have `Hashed<H, V>`.
    /// Note that if lazy loading is also used, it will force evaluation.
    fn check_integrity(&self) -> bool {
        false
    }
}

impl ConsensusMessageHashable for Finalization {
    fn get_id(&self) -> ConsensusMessageId {
        ConsensusMessageId {
            hash: self.get_cm_hash(),
            height: self.content.height,
        }
    }

    fn get_cm_hash(&self) -> ConsensusMessageHash {
        ConsensusMessageHash::Finalization(crypto_hash(self))
    }

    fn assert(msg: &ConsensusMessage) -> Option<&Self> {
        if let ConsensusMessage::Finalization(value) = msg {
            Some(value)
        } else {
            None
        }
    }

    fn into_message(self) -> ConsensusMessage {
        ConsensusMessage::Finalization(self)
    }
}

impl ConsensusMessageHashable for FinalizationShare {
    fn get_id(&self) -> ConsensusMessageId {
        ConsensusMessageId {
            hash: self.get_cm_hash(),
            height: self.content.height,
        }
    }

    fn get_cm_hash(&self) -> ConsensusMessageHash {
        ConsensusMessageHash::FinalizationShare(crypto_hash(self))
    }

    fn assert(msg: &ConsensusMessage) -> Option<&Self> {
        if let ConsensusMessage::FinalizationShare(value) = msg {
            Some(value)
        } else {
            None
        }
    }

    fn into_message(self) -> ConsensusMessage {
        ConsensusMessage::FinalizationShare(self)
    }
}

impl ConsensusMessageHashable for Notarization {
    fn get_id(&self) -> ConsensusMessageId {
        ConsensusMessageId {
            hash: self.get_cm_hash(),
            height: self.content.height,
        }
    }

    fn get_cm_hash(&self) -> ConsensusMessageHash {
        ConsensusMessageHash::Notarization(crypto_hash(self))
    }

    fn assert(msg: &ConsensusMessage) -> Option<&Self> {
        if let ConsensusMessage::Notarization(value) = msg {
            Some(value)
        } else {
            None
        }
    }

    fn into_message(self) -> ConsensusMessage {
        ConsensusMessage::Notarization(self)
    }
}

impl ConsensusMessageHashable for NotarizationShare {
    fn get_id(&self) -> ConsensusMessageId {
        ConsensusMessageId {
            hash: self.get_cm_hash(),
            height: self.content.height,
        }
    }

    fn get_cm_hash(&self) -> ConsensusMessageHash {
        ConsensusMessageHash::NotarizationShare(crypto_hash(self))
    }

    fn assert(msg: &ConsensusMessage) -> Option<&Self> {
        if let ConsensusMessage::NotarizationShare(value) = msg {
            Some(value)
        } else {
            None
        }
    }

    fn into_message(self) -> ConsensusMessage {
        ConsensusMessage::NotarizationShare(self)
    }
}

impl ConsensusMessageHashable for RandomBeacon {
    fn get_id(&self) -> ConsensusMessageId {
        ConsensusMessageId {
            hash: self.get_cm_hash(),
            height: self.content.height,
        }
    }

    fn get_cm_hash(&self) -> ConsensusMessageHash {
        ConsensusMessageHash::RandomBeacon(crypto_hash(self))
    }

    fn assert(msg: &ConsensusMessage) -> Option<&Self> {
        if let ConsensusMessage::RandomBeacon(value) = msg {
            Some(value)
        } else {
            None
        }
    }

    fn into_message(self) -> ConsensusMessage {
        ConsensusMessage::RandomBeacon(self)
    }
}

impl ConsensusMessageHashable for RandomBeaconShare {
    fn get_id(&self) -> ConsensusMessageId {
        ConsensusMessageId {
            hash: self.get_cm_hash(),
            height: self.content.height,
        }
    }

    fn get_cm_hash(&self) -> ConsensusMessageHash {
        ConsensusMessageHash::RandomBeaconShare(crypto_hash(self))
    }

    fn assert(msg: &ConsensusMessage) -> Option<&Self> {
        if let ConsensusMessage::RandomBeaconShare(value) = msg {
            Some(value)
        } else {
            None
        }
    }

    fn into_message(self) -> ConsensusMessage {
        ConsensusMessage::RandomBeaconShare(self)
    }
}

impl ConsensusMessageHashable for BlockProposal {
    fn get_id(&self) -> ConsensusMessageId {
        ConsensusMessageId {
            hash: self.get_cm_hash(),
            height: self.height(),
        }
    }

    fn get_cm_hash(&self) -> ConsensusMessageHash {
        ConsensusMessageHash::BlockProposal(crypto_hash(self))
    }

    fn assert(msg: &ConsensusMessage) -> Option<&Self> {
        if let ConsensusMessage::BlockProposal(value) = msg {
            Some(value)
        } else {
            None
        }
    }

    fn into_message(self) -> ConsensusMessage {
        ConsensusMessage::BlockProposal(self)
    }

    fn check_integrity(&self) -> bool {
        let block_hash = self.content.get_hash();
        let block = self.as_ref();
        let payload_hash = block.payload.get_hash();
        let block_payload = block.payload.as_ref();
        block.payload.is_summary() == block_payload.is_summary()
            && &crypto_hash(block_payload) == payload_hash
            && &crypto_hash(block) == block_hash
    }
}

impl ConsensusMessageHashable for RandomTape {
    fn get_id(&self) -> ConsensusMessageId {
        ConsensusMessageId {
            hash: self.get_cm_hash(),
            height: self.content.height,
        }
    }

    fn get_cm_hash(&self) -> ConsensusMessageHash {
        ConsensusMessageHash::RandomTape(crypto_hash(self))
    }

    fn assert(msg: &ConsensusMessage) -> Option<&Self> {
        if let ConsensusMessage::RandomTape(value) = msg {
            Some(value)
        } else {
            None
        }
    }

    fn into_message(self) -> ConsensusMessage {
        ConsensusMessage::RandomTape(self)
    }
}

impl ConsensusMessageHashable for RandomTapeShare {
    fn get_id(&self) -> ConsensusMessageId {
        ConsensusMessageId {
            hash: self.get_cm_hash(),
            height: self.content.height,
        }
    }

    fn get_cm_hash(&self) -> ConsensusMessageHash {
        ConsensusMessageHash::RandomTapeShare(crypto_hash(self))
    }

    fn assert(msg: &ConsensusMessage) -> Option<&Self> {
        if let ConsensusMessage::RandomTapeShare(value) = msg {
            Some(value)
        } else {
            None
        }
    }

    fn into_message(self) -> ConsensusMessage {
        ConsensusMessage::RandomTapeShare(self)
    }
}

impl ConsensusMessageHashable for CatchUpPackage {
    fn get_id(&self) -> ConsensusMessageId {
        ConsensusMessageId {
            hash: self.get_cm_hash(),
            height: self.height(),
        }
    }

    fn get_cm_hash(&self) -> ConsensusMessageHash {
        ConsensusMessageHash::CatchUpPackage(crypto_hash(self))
    }

    fn assert(msg: &ConsensusMessage) -> Option<&Self> {
        if let ConsensusMessage::CatchUpPackage(value) = msg {
            Some(value)
        } else {
            None
        }
    }

    fn into_message(self) -> ConsensusMessage {
        ConsensusMessage::CatchUpPackage(self)
    }

    fn check_integrity(&self) -> bool {
        self.content.check_integrity()
    }
}

impl ConsensusMessageHashable for CatchUpPackageShare {
    fn get_id(&self) -> ConsensusMessageId {
        ConsensusMessageId {
            hash: self.get_cm_hash(),
            height: self.height(),
        }
    }

    fn get_cm_hash(&self) -> ConsensusMessageHash {
        ConsensusMessageHash::CatchUpPackageShare(crypto_hash(self))
    }

    fn assert(msg: &ConsensusMessage) -> Option<&Self> {
        if let ConsensusMessage::CatchUpPackageShare(value) = msg {
            Some(value)
        } else {
            None
        }
    }

    fn into_message(self) -> ConsensusMessage {
        ConsensusMessage::CatchUpPackageShare(self)
    }

    fn check_integrity(&self) -> bool {
        let content = &self.content;
        let random_beacon_hash = content.random_beacon.get_hash();
        &crypto_hash(content.random_beacon.as_ref()) == random_beacon_hash
    }
}

impl ConsensusMessageHashable for EquivocationProof {
    fn get_id(&self) -> ConsensusMessageId {
        ConsensusMessageId {
            hash: self.get_cm_hash(),
            height: self.height(),
        }
    }

    fn get_cm_hash(&self) -> ConsensusMessageHash {
        ConsensusMessageHash::EquivocationProof(crypto_hash(self))
    }

    fn assert(msg: &ConsensusMessage) -> Option<&Self> {
        if let ConsensusMessage::EquivocationProof(value) = msg {
            Some(value)
        } else {
            None
        }
    }

    fn into_message(self) -> ConsensusMessage {
        ConsensusMessage::EquivocationProof(self)
    }
}

impl ConsensusMessageHashable for ConsensusMessage {
    fn get_id(&self) -> ConsensusMessageId {
        ConsensusMessageId {
            hash: self.get_cm_hash(),
            height: self.height(),
        }
    }

    fn get_cm_hash(&self) -> ConsensusMessageHash {
        match self {
            ConsensusMessage::RandomBeacon(value) => value.get_cm_hash(),
            ConsensusMessage::Finalization(value) => value.get_cm_hash(),
            ConsensusMessage::Notarization(value) => value.get_cm_hash(),
            ConsensusMessage::BlockProposal(value) => value.get_cm_hash(),
            ConsensusMessage::RandomBeaconShare(value) => value.get_cm_hash(),
            ConsensusMessage::NotarizationShare(value) => value.get_cm_hash(),
            ConsensusMessage::FinalizationShare(value) => value.get_cm_hash(),
            ConsensusMessage::RandomTape(value) => value.get_cm_hash(),
            ConsensusMessage::RandomTapeShare(value) => value.get_cm_hash(),
            ConsensusMessage::CatchUpPackage(value) => value.get_cm_hash(),
            ConsensusMessage::CatchUpPackageShare(value) => value.get_cm_hash(),
            ConsensusMessage::EquivocationProof(value) => value.get_cm_hash(),
        }
    }

    fn assert(msg: &ConsensusMessage) -> Option<&Self> {
        Some(msg)
    }

    fn into_message(self) -> ConsensusMessage {
        self
    }

    fn check_integrity(&self) -> bool {
        match self {
            ConsensusMessage::RandomBeacon(value) => value.check_integrity(),
            ConsensusMessage::Finalization(value) => value.check_integrity(),
            ConsensusMessage::Notarization(value) => value.check_integrity(),
            ConsensusMessage::BlockProposal(value) => value.check_integrity(),
            ConsensusMessage::RandomBeaconShare(value) => value.check_integrity(),
            ConsensusMessage::NotarizationShare(value) => value.check_integrity(),
            ConsensusMessage::FinalizationShare(value) => value.check_integrity(),
            ConsensusMessage::RandomTape(value) => value.check_integrity(),
            ConsensusMessage::RandomTapeShare(value) => value.check_integrity(),
            ConsensusMessage::CatchUpPackage(value) => value.check_integrity(),
            ConsensusMessage::CatchUpPackageShare(value) => value.check_integrity(),
            ConsensusMessage::EquivocationProof(value) => value.check_integrity(),
        }
    }
}
