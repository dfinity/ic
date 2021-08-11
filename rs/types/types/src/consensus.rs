//! Defines types used internally by consensus components.
use crate::{
    batch::{BatchPayload, ValidationContext},
    crypto::threshold_sig::ni_dkg::NiDkgId,
    crypto::*,
    replica_version::ReplicaVersion,
    *,
};
use ic_protobuf::log::block_log_entry::v1::BlockLogEntry;
use ic_protobuf::types::v1 as pb;
use serde::{Deserialize, Serialize};
use std::cmp::PartialOrd;
use std::convert::TryInto;
use std::hash::Hash;

pub mod catchup;
pub mod certification;
pub mod dkg;
pub mod hashed;
mod payload;
pub mod thunk;

pub use catchup::*;
use hashed::Hashed;
pub use payload::{BlockPayload, Payload};

/// BasicSignature captures basic signature on a value and the identity of the
/// replica that signed it
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BasicSignature<T> {
    pub signature: BasicSigOf<T>,
    pub signer: NodeId,
}

/// BasicSigned<T> captures a value of type T and a BasicSignature on it
pub type BasicSigned<T> = Signed<T, BasicSignature<T>>;

/// ThresholdSignature captures a threshold signature on a value and the
/// DKG id of the threshold key material used to sign
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ThresholdSignature<T> {
    pub signature: CombinedThresholdSigOf<T>,
    pub signer: NiDkgId,
}

/// ThresholdSignatureShare captures a share of a threshold signature on a value
/// and the identity of the replica that signed
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ThresholdSignatureShare<T> {
    pub signature: ThresholdSigShareOf<T>,
    pub signer: NodeId,
}

/// MultiSignature captures a cryptographic multi-signature, which is one
/// message signed by multiple signers
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MultiSignature<T> {
    pub signature: CombinedMultiSigOf<T>,
    pub signers: Vec<NodeId>,
}

/// MultiSignatureShare is a signature from one replica. Multiple shares can be
/// aggregated into a MultiSignature.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MultiSignatureShare<T> {
    pub signature: IndividualMultiSigOf<T>,
    pub signer: NodeId,
}

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
        &self.value.version()
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

/// Rank is used to indicate the priority of a block maker, where 0 indicates
/// the highest priority.
#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Rank(pub u64);

/// Block is the type that is used to create blocks out of which we build a
/// block chain
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Block {
    version: ReplicaVersion,
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

    /// Create a new block of a particular replica version
    pub fn new_with_replica_version(
        version: ReplicaVersion,
        parent: CryptoHashOf<Block>,
        payload: Payload,
        height: Height,
        rank: Rank,
        context: ValidationContext,
    ) -> Self {
        Block {
            version,
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

impl SignedBytesWithoutDomainSeparator for Block {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).unwrap()
    }
}

/// HashedBlock contains a Block together with its hash
pub type HashedBlock = Hashed<CryptoHashOf<Block>, Block>;

/// A BlockProposal is a HashedBlock that is signed by the block maker.
pub type BlockProposal = Signed<HashedBlock, BasicSignature<Block>>;

impl From<&BlockProposal> for pb::BlockProposal {
    fn from(block_proposal: &BlockProposal) -> Self {
        Self {
            hash: block_proposal.content.hash.clone().get().0,
            value: Some((&block_proposal.content.value).into()),
            signature: block_proposal.signature.signature.clone().get().0,
            signer: block_proposal.signature.signer.get().into_vec(),
        }
    }
}

impl TryFrom<pb::BlockProposal> for BlockProposal {
    type Error = String;
    fn try_from(block_proposal: pb::BlockProposal) -> Result<Self, Self::Error> {
        Ok(Signed {
            content: Hashed {
                value: Block::try_from(
                    block_proposal
                        .value
                        .ok_or_else(|| "No block proposal value found".to_string())?,
                )?,
                hash: CryptoHashOf::from(CryptoHash(block_proposal.hash)),
            },
            signature: BasicSignature {
                signature: BasicSigOf::from(BasicSig(block_proposal.signature)),
                signer: NodeId::from(
                    PrincipalId::try_from(block_proposal.signer)
                        .expect("Couldn't parse principal id."),
                ),
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
pub struct NotarizationContent {
    version: ReplicaVersion,
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
                .map(|node_id| node_id.clone().get().into_vec())
                .collect(),
        }
    }
}

impl TryFrom<pb::Notarization> for Notarization {
    type Error = String;
    fn try_from(notarization: pb::Notarization) -> Result<Self, Self::Error> {
        Ok(Signed {
            content: NotarizationContent {
                version: ReplicaVersion::try_from(notarization.version.as_str())
                    .map_err(|e| format!("Notarization replica version failed to parse {:?}", e))?,
                height: Height::from(notarization.height),
                block: CryptoHashOf::from(CryptoHash(notarization.block)),
            },
            signature: MultiSignature {
                signature: CombinedMultiSigOf::from(CombinedMultiSig(notarization.signature)),
                signers: notarization
                    .signers
                    .iter()
                    .map(|n| {
                        NodeId::from(
                            PrincipalId::try_from(&n[..])
                                .expect("Could not deserialize principal id."),
                        )
                    })
                    .collect(),
            },
        })
    }
}

/// A notarization share is a multi-signature share on a notarization content.
/// If sufficiently many replicas create notarization shares, the shares can be
/// aggregated into a full notarization.
pub type NotarizationShare = Signed<NotarizationContent, MultiSignatureShare<NotarizationContent>>;

/// FinalizationContent holds the values that are signed in a finalization
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FinalizationContent {
    version: ReplicaVersion,
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
                .map(|node_id| node_id.clone().get().into_vec())
                .collect(),
        }
    }
}

impl TryFrom<pb::Finalization> for Finalization {
    type Error = String;
    fn try_from(finalization: pb::Finalization) -> Result<Self, Self::Error> {
        Ok(Signed {
            content: FinalizationContent {
                version: ReplicaVersion::try_from(finalization.version.as_str())
                    .map_err(|e| format!("Finalization replica version failed to parse {:?}", e))?,
                height: Height::from(finalization.height),
                block: CryptoHashOf::from(CryptoHash(finalization.block)),
            },
            signature: MultiSignature {
                signature: CombinedMultiSigOf::from(CombinedMultiSig(finalization.signature)),
                signers: finalization
                    .signers
                    .iter()
                    .map(|n| NodeId::from(PrincipalId::try_from(&n[..]).unwrap()))
                    .collect(),
            },
        })
    }
}

/// A finalization share is a multi-signature share on a finalization content.
/// If sufficiently many replicas create finalization shares, the shares can be
/// aggregated into a full finalization.
pub type FinalizationShare = Signed<FinalizationContent, MultiSignatureShare<FinalizationContent>>;

/// RandomBeaconContent holds the content that is signed in the random beacon,
/// which is the previous random beacon, the height, and the replica version
/// used to create the random beacon.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RandomBeaconContent {
    version: ReplicaVersion,
    pub height: Height,
    pub parent: CryptoHashOf<RandomBeacon>,
}

/// HashedRandomBeacon holds a RandomBeacon and its hash
pub type HashedRandomBeacon = Hashed<CryptoHashOf<RandomBeacon>, RandomBeacon>;

impl RandomBeaconContent {
    /// Create a new RandomBeaconContent with a given height and parent
    /// RandomBeacon
    pub fn new(height: Height, parent: CryptoHashOf<RandomBeacon>) -> Self {
        RandomBeaconContent {
            version: ReplicaVersion::default(),
            height,
            parent,
        }
    }

    /// Create a new RandomBeaconContent with a given replica version
    pub fn new_with_replica_version(
        version: ReplicaVersion,
        height: Height,
        parent: CryptoHashOf<RandomBeacon>,
    ) -> Self {
        RandomBeaconContent {
            version,
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
    type Error = String;
    fn try_from(beacon: pb::RandomBeacon) -> Result<Self, Self::Error> {
        Ok(Signed {
            content: RandomBeaconContent {
                version: ReplicaVersion::try_from(beacon.version.as_str())
                    .map_err(|e| format!("RandomBeacon replica version failed to parse {:?}", e))?,
                height: Height::from(beacon.height),
                parent: CryptoHashOf::from(CryptoHash(beacon.parent)),
            },
            signature: ThresholdSignature {
                signature: CombinedThresholdSigOf::new(CombinedThresholdSig(beacon.signature)),
                signer: NiDkgId::try_from(
                    beacon
                        .signer
                        .ok_or_else(|| String::from("Error: RandomBeacon signer not present"))?,
                )
                .map_err(|e| format!("Unable to decode Random beacon signer {:?}", e))?,
            },
        })
    }
}

/// RandomBeaconShare is a threshold signature share on a RandomBeaconContent.
/// If sufficiently many replicas create random beacon shares, the shares can be
/// aggregated into a RandomBeacon.
pub type RandomBeaconShare =
    Signed<RandomBeaconContent, ThresholdSignatureShare<RandomBeaconContent>>;

/// RandomTapeContent holds the content that is signed in the random tape,
/// which is the height and the replica version used to create the random
/// tape.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RandomTapeContent {
    version: ReplicaVersion,
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
    type Error = String;
    fn try_from(tape: pb::RandomTape) -> Result<Self, Self::Error> {
        Ok(Signed {
            content: RandomTapeContent {
                version: ReplicaVersion::try_from(tape.version.as_str())
                    .map_err(|e| format!("RandomTape replica version failed to parse {:?}", e))?,
                height: Height::from(tape.height),
            },
            signature: ThresholdSignature {
                signature: CombinedThresholdSigOf::new(CombinedThresholdSig(tape.signature)),
                signer: NiDkgId::try_from(
                    tape.signer
                        .ok_or_else(|| String::from("Error: RandomTape signer not present"))?,
                )
                .map_err(|e| format!("Unable to decode RandomTape signer {:?}", e))?,
            },
        })
    }
}

/// RandomTapeShare is a threshold signature share on a RandomTapeContent. If
/// sufficiently many replicas create random tape shares, the shares can be
/// aggregated into a RandomTape.
pub type RandomTapeShare = Signed<RandomTapeContent, ThresholdSignatureShare<RandomTapeContent>>;

/// The enum encompassing all of the consensus artifacts exchanged between
/// replicas.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
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
}

impl TryFrom<ConsensusMessage> for RandomBeacon {
    type Error = ConsensusMessage;
    fn try_from(msg: ConsensusMessage) -> Result<Self, Self::Error> {
        match msg {
            ConsensusMessage::RandomBeacon(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

impl TryFrom<ConsensusMessage> for Finalization {
    type Error = ConsensusMessage;
    fn try_from(msg: ConsensusMessage) -> Result<Self, Self::Error> {
        match msg {
            ConsensusMessage::Finalization(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

impl TryFrom<ConsensusMessage> for Notarization {
    type Error = ConsensusMessage;
    fn try_from(msg: ConsensusMessage) -> Result<Self, Self::Error> {
        match msg {
            ConsensusMessage::Notarization(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

impl TryFrom<ConsensusMessage> for BlockProposal {
    type Error = ConsensusMessage;
    fn try_from(msg: ConsensusMessage) -> Result<Self, Self::Error> {
        match msg {
            ConsensusMessage::BlockProposal(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

impl TryFrom<ConsensusMessage> for RandomBeaconShare {
    type Error = ConsensusMessage;
    fn try_from(msg: ConsensusMessage) -> Result<Self, Self::Error> {
        match msg {
            ConsensusMessage::RandomBeaconShare(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

impl TryFrom<ConsensusMessage> for NotarizationShare {
    type Error = ConsensusMessage;
    fn try_from(msg: ConsensusMessage) -> Result<Self, Self::Error> {
        match msg {
            ConsensusMessage::NotarizationShare(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

impl TryFrom<ConsensusMessage> for FinalizationShare {
    type Error = ConsensusMessage;
    fn try_from(msg: ConsensusMessage) -> Result<Self, Self::Error> {
        match msg {
            ConsensusMessage::FinalizationShare(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

impl TryFrom<ConsensusMessage> for RandomTape {
    type Error = ConsensusMessage;
    fn try_from(msg: ConsensusMessage) -> Result<Self, Self::Error> {
        match msg {
            ConsensusMessage::RandomTape(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

impl TryFrom<ConsensusMessage> for RandomTapeShare {
    type Error = ConsensusMessage;
    fn try_from(msg: ConsensusMessage) -> Result<Self, Self::Error> {
        match msg {
            ConsensusMessage::RandomTapeShare(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

impl TryFrom<ConsensusMessage> for CatchUpPackage {
    type Error = ConsensusMessage;
    fn try_from(msg: ConsensusMessage) -> Result<Self, Self::Error> {
        match msg {
            ConsensusMessage::CatchUpPackage(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

impl TryFrom<ConsensusMessage> for CatchUpPackageShare {
    type Error = ConsensusMessage;
    fn try_from(msg: ConsensusMessage) -> Result<Self, Self::Error> {
        match msg {
            ConsensusMessage::CatchUpPackageShare(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

impl<'a> TryFrom<&'a ConsensusMessage> for &'a RandomBeacon {
    type Error = ();
    fn try_from(msg: &'a ConsensusMessage) -> Result<Self, Self::Error> {
        match msg {
            ConsensusMessage::RandomBeacon(x) => Ok(x),
            _ => Err(()),
        }
    }
}

impl<'a> TryFrom<&'a ConsensusMessage> for &'a Finalization {
    type Error = ();
    fn try_from(msg: &'a ConsensusMessage) -> Result<Self, Self::Error> {
        match msg {
            ConsensusMessage::Finalization(x) => Ok(x),
            _ => Err(()),
        }
    }
}

impl<'a> TryFrom<&'a ConsensusMessage> for &'a Notarization {
    type Error = ();
    fn try_from(msg: &'a ConsensusMessage) -> Result<Self, Self::Error> {
        match msg {
            ConsensusMessage::Notarization(x) => Ok(x),
            _ => Err(()),
        }
    }
}

impl<'a> TryFrom<&'a ConsensusMessage> for &'a BlockProposal {
    type Error = ();
    fn try_from(msg: &'a ConsensusMessage) -> Result<Self, Self::Error> {
        match msg {
            ConsensusMessage::BlockProposal(x) => Ok(x),
            _ => Err(()),
        }
    }
}

impl<'a> TryFrom<&'a ConsensusMessage> for &'a RandomBeaconShare {
    type Error = ();
    fn try_from(msg: &'a ConsensusMessage) -> Result<Self, Self::Error> {
        match msg {
            ConsensusMessage::RandomBeaconShare(x) => Ok(x),
            _ => Err(()),
        }
    }
}

impl<'a> TryFrom<&'a ConsensusMessage> for &'a NotarizationShare {
    type Error = ();
    fn try_from(msg: &'a ConsensusMessage) -> Result<Self, Self::Error> {
        match msg {
            ConsensusMessage::NotarizationShare(x) => Ok(x),
            _ => Err(()),
        }
    }
}

impl<'a> TryFrom<&'a ConsensusMessage> for &'a FinalizationShare {
    type Error = ();
    fn try_from(msg: &'a ConsensusMessage) -> Result<Self, Self::Error> {
        match msg {
            ConsensusMessage::FinalizationShare(x) => Ok(x),
            _ => Err(()),
        }
    }
}

impl<'a> TryFrom<&'a ConsensusMessage> for &'a RandomTape {
    type Error = ();
    fn try_from(msg: &'a ConsensusMessage) -> Result<Self, Self::Error> {
        match msg {
            ConsensusMessage::RandomTape(x) => Ok(x),
            _ => Err(()),
        }
    }
}

impl<'a> TryFrom<&'a ConsensusMessage> for &'a RandomTapeShare {
    type Error = ();
    fn try_from(msg: &'a ConsensusMessage) -> Result<Self, Self::Error> {
        match msg {
            ConsensusMessage::RandomTapeShare(x) => Ok(x),
            _ => Err(()),
        }
    }
}

impl<'a> TryFrom<&'a ConsensusMessage> for &'a CatchUpPackage {
    type Error = ();
    fn try_from(msg: &'a ConsensusMessage) -> Result<Self, Self::Error> {
        match msg {
            ConsensusMessage::CatchUpPackage(x) => Ok(x),
            _ => Err(()),
        }
    }
}

impl<'a> TryFrom<&'a ConsensusMessage> for &'a CatchUpPackageShare {
    type Error = ();
    fn try_from(msg: &'a ConsensusMessage) -> Result<Self, Self::Error> {
        match msg {
            ConsensusMessage::CatchUpPackageShare(x) => Ok(x),
            _ => Err(()),
        }
    }
}

/// ConsensusMessageHash has the same variants as [ConsensusMessage], but
/// contains only a hash instead of the full message in each variant.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
}

/// ConsensusMessageAttribute has the same variants as [ConsensusMessage], but
/// contains only the attributes for each variant. The attributes are the values
/// that are used in the p2p layer to determine whether an artifact is
/// interesting to a replica before fetching the full artifact.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConsensusMessageAttribute {
    RandomBeacon(Height),
    Finalization(CryptoHashOf<Block>, Height),
    Notarization(CryptoHashOf<Block>, Height),
    BlockProposal(Rank, Height),
    RandomBeaconShare(Height),
    NotarizationShare(Height),
    FinalizationShare(Height),
    RandomTape(Height),
    RandomTapeShare(Height),
    CatchUpPackage(Height),
    CatchUpPackageShare(Height),
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

impl ContentEq for ConsensusMessage {
    fn content_eq(&self, other: &ConsensusMessage) -> bool {
        match self {
            ConsensusMessage::RandomBeacon(x) => {
                other.try_into().map(|y: &RandomBeacon| y.content_eq(x)) == Ok(true)
            }
            ConsensusMessage::Finalization(x) => {
                other.try_into().map(|y: &Finalization| y.content_eq(x)) == Ok(true)
            }
            ConsensusMessage::Notarization(x) => {
                other.try_into().map(|y: &Notarization| y.content_eq(x)) == Ok(true)
            }
            ConsensusMessage::BlockProposal(x) => {
                other.try_into().map(|y: &BlockProposal| y.content_eq(x)) == Ok(true)
            }
            ConsensusMessage::RandomBeaconShare(x) => {
                other
                    .try_into()
                    .map(|y: &RandomBeaconShare| y.content_eq(x))
                    == Ok(true)
            }
            ConsensusMessage::NotarizationShare(x) => {
                other
                    .try_into()
                    .map(|y: &NotarizationShare| y.content_eq(x))
                    == Ok(true)
            }
            ConsensusMessage::FinalizationShare(x) => {
                other
                    .try_into()
                    .map(|y: &FinalizationShare| y.content_eq(x))
                    == Ok(true)
            }
            ConsensusMessage::RandomTape(x) => {
                other.try_into().map(|y: &RandomTape| y.content_eq(x)) == Ok(true)
            }
            ConsensusMessage::RandomTapeShare(x) => {
                other.try_into().map(|y: &RandomTapeShare| y.content_eq(x)) == Ok(true)
            }
            ConsensusMessage::CatchUpPackage(x) => {
                other.try_into().map(|y: &CatchUpPackage| y.content_eq(x)) == Ok(true)
            }
            ConsensusMessage::CatchUpPackageShare(x) => {
                other
                    .try_into()
                    .map(|y: &CatchUpPackageShare| y.content_eq(x))
                    == Ok(true)
            }
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
        }
    }
}

impl HasHeight for ConsensusMessageAttribute {
    fn height(&self) -> Height {
        match self {
            ConsensusMessageAttribute::RandomBeacon(h) => *h,
            ConsensusMessageAttribute::Finalization(_, h) => *h,
            ConsensusMessageAttribute::Notarization(_, h) => *h,
            ConsensusMessageAttribute::BlockProposal(_, h) => *h,
            ConsensusMessageAttribute::RandomBeaconShare(h) => *h,
            ConsensusMessageAttribute::NotarizationShare(h) => *h,
            ConsensusMessageAttribute::FinalizationShare(h) => *h,
            ConsensusMessageAttribute::RandomTape(h) => *h,
            ConsensusMessageAttribute::RandomTapeShare(h) => *h,
            ConsensusMessageAttribute::CatchUpPackage(h) => *h,
            ConsensusMessageAttribute::CatchUpPackageShare(h) => *h,
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
        }
    }

    pub fn from_attribute(hash: CryptoHash, attr: &ConsensusMessageAttribute) -> Self {
        match attr {
            ConsensusMessageAttribute::RandomBeacon(_) => {
                ConsensusMessageHash::RandomBeacon(CryptoHashOf::from(hash))
            }
            ConsensusMessageAttribute::Finalization(_, _) => {
                ConsensusMessageHash::Finalization(CryptoHashOf::from(hash))
            }
            ConsensusMessageAttribute::Notarization(_, _) => {
                ConsensusMessageHash::Notarization(CryptoHashOf::from(hash))
            }
            ConsensusMessageAttribute::BlockProposal(_, _) => {
                ConsensusMessageHash::BlockProposal(CryptoHashOf::from(hash))
            }
            ConsensusMessageAttribute::RandomBeaconShare(_) => {
                ConsensusMessageHash::RandomBeaconShare(CryptoHashOf::from(hash))
            }
            ConsensusMessageAttribute::NotarizationShare(_) => {
                ConsensusMessageHash::NotarizationShare(CryptoHashOf::from(hash))
            }
            ConsensusMessageAttribute::FinalizationShare(_) => {
                ConsensusMessageHash::FinalizationShare(CryptoHashOf::from(hash))
            }
            ConsensusMessageAttribute::RandomTape(_) => {
                ConsensusMessageHash::RandomTape(CryptoHashOf::from(hash))
            }
            ConsensusMessageAttribute::RandomTapeShare(_) => {
                ConsensusMessageHash::RandomTapeShare(CryptoHashOf::from(hash))
            }
            ConsensusMessageAttribute::CatchUpPackage(_) => {
                ConsensusMessageHash::CatchUpPackage(CryptoHashOf::from(hash))
            }
            ConsensusMessageAttribute::CatchUpPackageShare(_) => {
                ConsensusMessageHash::CatchUpPackageShare(CryptoHashOf::from(hash))
            }
        }
    }
}

impl From<&ConsensusMessage> for ConsensusMessageAttribute {
    fn from(msg: &ConsensusMessage) -> ConsensusMessageAttribute {
        let height = msg.height();
        match msg {
            ConsensusMessage::RandomBeacon(_) => ConsensusMessageAttribute::RandomBeacon(height),
            ConsensusMessage::Finalization(x) => {
                ConsensusMessageAttribute::Finalization(x.content.block.clone(), height)
            }
            ConsensusMessage::Notarization(x) => {
                ConsensusMessageAttribute::Notarization(x.content.block.clone(), height)
            }
            ConsensusMessage::BlockProposal(x) => {
                ConsensusMessageAttribute::BlockProposal(x.rank(), height)
            }

            ConsensusMessage::RandomBeaconShare(_) => {
                ConsensusMessageAttribute::RandomBeaconShare(height)
            }

            ConsensusMessage::NotarizationShare(_) => {
                ConsensusMessageAttribute::NotarizationShare(height)
            }

            ConsensusMessage::FinalizationShare(_) => {
                ConsensusMessageAttribute::FinalizationShare(height)
            }
            ConsensusMessage::RandomTape(_) => ConsensusMessageAttribute::RandomTape(height),
            ConsensusMessage::RandomTapeShare(_) => {
                ConsensusMessageAttribute::RandomTapeShare(height)
            }
            ConsensusMessage::CatchUpPackage(_) => {
                ConsensusMessageAttribute::CatchUpPackage(height)
            }
            ConsensusMessage::CatchUpPackageShare(_) => {
                ConsensusMessageAttribute::CatchUpPackageShare(height)
            }
        }
    }
}

/// Indicates one of the consensus committees that are responsible for creating
/// signature shares on various types of artifacts
#[derive(Debug, PartialEq)]
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
        let (dkg_payload, xnet_payload, ingress_payload) = if payload.is_summary() {
            (pb::DkgPayload::from(payload.as_summary()), None, None)
        } else {
            let batch = payload.as_batch_payload();
            (
                pb::DkgPayload::from(payload.as_dealings()),
                Some(pb::XNetPayload::from(&batch.xnet)),
                Some(pb::IngressPayload::from(&batch.ingress)),
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
            payload_hash: block.payload.get_hash().clone().get().0,
        }
    }
}

impl TryFrom<pb::Block> for Block {
    type Error = String;
    fn try_from(block: pb::Block) -> Result<Self, Self::Error> {
        let dkg_payload = dkg::Payload::try_from(
            block
                .dkg_payload
                .ok_or_else(|| String::from("Error: Block missing dkg_payload"))?,
        )?;
        let batch = BatchPayload::new(
            block
                .ingress_payload
                .map(crate::batch::IngressPayload::try_from)
                .transpose()?
                .unwrap_or_default(),
            block
                .xnet_payload
                .map(crate::batch::XNetPayload::try_from)
                .transpose()?
                .unwrap_or_default(),
        );
        let payload = match dkg_payload {
            dkg::Payload::Summary(summary) => {
                assert!(
                    batch.is_empty(),
                    "Error: Summary block has non-empty batch payload."
                );
                BlockPayload::Summary(summary)
            }
            dkg::Payload::Dealings(dealings) => (batch, dealings).into(),
        };
        Ok(Block {
            version: ReplicaVersion::try_from(block.version.as_str())
                .map_err(|e| format!("Block replica version failed to parse {:?}", e))?,
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
