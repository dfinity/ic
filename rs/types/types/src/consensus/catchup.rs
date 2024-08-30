//! Defines types that allow outdated replicas to catch up to the latest state.

use crate::{
    consensus::{
        Block, Committee, ConsensusMessageHashable, HasCommittee, HasHeight, HasVersion,
        HashedBlock, HashedRandomBeacon, ThresholdSignature, ThresholdSignatureShare,
    },
    crypto::*,
    node_id_into_protobuf, node_id_try_from_option, CryptoHashOfState, Height, RegistryVersion,
    ReplicaVersion,
};
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    types::v1 as pb,
};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::cmp::{Ordering, PartialOrd};
use std::convert::TryFrom;

/// [`CatchUpContent`] contains all necessary data to bootstrap a subnet's participant.
pub type CatchUpContent = CatchUpContentT<HashedBlock>;

/// A generic struct shared between [`CatchUpContent`] and [`CatchUpShareContent`].
/// Consists of objects all occurring at a specific height which we will refer to
/// as the catch up height.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
pub struct CatchUpContentT<T> {
    /// Replica version that was running when this CUP was created.
    pub version: ReplicaVersion,
    /// A finalized Block that contains DKG summary.
    pub block: T,
    /// The RandomBeacon that is used at the catchup height.
    pub random_beacon: HashedRandomBeacon,
    /// Hash of the subnet execution state that has been fully computed at the
    /// catchup height.
    pub state_hash: CryptoHashOfState,
    /// The oldest registry version that is still referenced by
    /// structures in replicated state.
    pub oldest_registry_version_in_use_by_replicated_state: Option<RegistryVersion>,
}

impl CatchUpContent {
    /// Creates a new [`CatchUpContent`]
    pub fn new(
        block: HashedBlock,
        random_beacon: HashedRandomBeacon,
        state_hash: CryptoHashOfState,
        oldest_registry_version_in_use_by_replicated_state: Option<RegistryVersion>,
    ) -> Self {
        Self {
            version: block.version().clone(),
            block,
            random_beacon,
            state_hash,
            oldest_registry_version_in_use_by_replicated_state,
        }
    }

    /// Returns the registry version as recorded in the DKG summary of
    /// the block contained in the [`CatchUpContent`].
    pub fn registry_version(&self) -> RegistryVersion {
        self.block
            .as_ref()
            .payload
            .as_ref()
            .as_summary()
            .dkg
            .registry_version
    }

    /// Creates a [`CatchUpContent`] from a [`CatchUpShareContent`].
    pub fn from_share_content(share: CatchUpShareContent, block: Block) -> Self {
        Self {
            version: share.version,
            block: HashedBlock {
                hash: share.block,
                value: block,
            },
            random_beacon: share.random_beacon,
            state_hash: share.state_hash,
            oldest_registry_version_in_use_by_replicated_state: share
                .oldest_registry_version_in_use_by_replicated_state,
        }
    }

    /// Check the integrity of block, block payload and random beacon in this CUP content.
    pub fn check_integrity(&self) -> bool {
        let block_hash = self.block.get_hash();
        let block = self.block.as_ref();
        let random_beacon_hash = self.random_beacon.get_hash();
        let random_beacon = self.random_beacon.as_ref();
        let payload_hash = block.payload.get_hash();
        let block_payload = block.payload.as_ref();
        block.payload.is_summary() == block_payload.is_summary()
            && &crypto_hash(random_beacon) == random_beacon_hash
            && &crypto_hash(block) == block_hash
            && &crypto_hash(block_payload) == payload_hash
    }
}

impl From<&CatchUpContent> for pb::CatchUpContent {
    fn from(content: &CatchUpContent) -> Self {
        Self {
            block: Some(pb::Block::from(content.block.as_ref())),
            random_beacon: Some(pb::RandomBeacon::from(content.random_beacon.as_ref())),
            block_hash: content.block.get_hash().clone().get().0,
            random_beacon_hash: content.random_beacon.get_hash().clone().get().0,
            state_hash: content.state_hash.clone().get().0,
            oldest_registry_version_in_use_by_replicated_state: content
                .oldest_registry_version_in_use_by_replicated_state
                .map(|v| v.get()),
        }
    }
}

impl TryFrom<pb::CatchUpContent> for CatchUpContent {
    type Error = ProxyDecodeError;

    fn try_from(content: pb::CatchUpContent) -> Result<CatchUpContent, Self::Error> {
        let block = try_from_option_field(content.block, "CatchUpContent::block")?;

        let random_beacon =
            try_from_option_field(content.random_beacon, "CatchUpContent::random_beacon")?;

        Ok(Self::new(
            HashedBlock {
                hash: CryptoHashOf::from(CryptoHash(content.block_hash)),
                value: block,
            },
            HashedRandomBeacon {
                hash: CryptoHashOf::from(CryptoHash(content.random_beacon_hash)),
                value: random_beacon,
            },
            CryptoHashOf::from(CryptoHash(content.state_hash)),
            content
                .oldest_registry_version_in_use_by_replicated_state
                .map(RegistryVersion::from),
        ))
    }
}

impl SignedBytesWithoutDomainSeparator for CatchUpContent {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        pb::CatchUpContent::from(self).as_protobuf_vec()
    }
}

impl<T> HasVersion for CatchUpContentT<T> {
    fn version(&self) -> &ReplicaVersion {
        &self.version
    }
}

impl<T> HasHeight for CatchUpContentT<T> {
    fn height(&self) -> Height {
        self.random_beacon.height()
    }
}

impl<T> HasCommittee for CatchUpContentT<T> {
    fn committee() -> Committee {
        Committee::HighThreshold
    }
}

/// [`CatchUpPackage`] is signed by a threshold public key. Its [`CatchUpContent`] is
/// only trusted if the threshold public key is trusted.
pub type CatchUpPackage = Signed<CatchUpContent, ThresholdSignature<CatchUpContent>>;

impl CatchUpPackage {
    /// Returns whether this CUP is signed.
    ///
    /// This is `false` for Genesis and recovery CUPs.
    pub fn is_signed(&self) -> bool {
        !self.signature.signature.as_ref().0.is_empty()
    }

    /// Return the oldest registry version that is still referenced by
    /// parts of the summary block, or structures in replicated state.
    ///
    /// P2P should keep up connections to all nodes registered in any registry
    /// between the one returned from this function and the current
    /// `RegistryVersion`.
    pub fn get_oldest_registry_version_in_use(&self) -> RegistryVersion {
        let summary_version = self
            .content
            .block
            .get_value()
            .payload
            .as_ref()
            .as_summary()
            .get_oldest_registry_version_in_use();
        let Some(cup_version) = self
            .content
            .oldest_registry_version_in_use_by_replicated_state
        else {
            return summary_version;
        };
        cup_version.min(summary_version)
    }
}

/// [`CatchUpContentHash`] is the type of a hashed [`CatchUpContent`]
pub type CatchUpContentHash = CryptoHashOf<CatchUpContent>;

impl From<&CatchUpPackage> for pb::CatchUpPackage {
    fn from(cup: &CatchUpPackage) -> Self {
        Self {
            signer: Some(pb::NiDkgId::from(cup.signature.signer)),
            signature: cup.signature.signature.clone().get().0,
            content: pb::CatchUpContent::from(&cup.content).as_protobuf_vec(),
        }
    }
}

impl From<CatchUpPackage> for pb::CatchUpPackage {
    fn from(cup: CatchUpPackage) -> Self {
        Self::from(&cup)
    }
}

impl TryFrom<&pb::CatchUpPackage> for CatchUpPackage {
    type Error = ProxyDecodeError;
    fn try_from(cup: &pb::CatchUpPackage) -> Result<CatchUpPackage, Self::Error> {
        let ret = CatchUpPackage {
            content: CatchUpContent::try_from(
                pb::CatchUpContent::decode(cup.content.as_slice())
                    .map_err(ProxyDecodeError::DecodeError)?,
            )?,
            signature: ThresholdSignature {
                signature: CombinedThresholdSigOf::new(CombinedThresholdSig(cup.signature.clone())),
                signer: try_from_option_field(cup.signer.clone(), "CatchUpPackage::signer")?,
            },
        };
        if ret.check_integrity() {
            Ok(ret)
        } else {
            Err(ProxyDecodeError::Other(
                "CatchUpPackage validity check failed".to_string(),
            ))
        }
    }
}

/// Content of [`CatchUpPackageShare`] uses the block hash to keep its size small.
pub type CatchUpShareContent = CatchUpContentT<CryptoHashOf<Block>>;

impl From<&CatchUpContent> for CatchUpShareContent {
    fn from(content: &CatchUpContent) -> Self {
        Self {
            version: content.version().clone(),
            block: content.block.get_hash().clone(),
            random_beacon: content.random_beacon.clone(),
            state_hash: content.state_hash.clone(),
            oldest_registry_version_in_use_by_replicated_state: content
                .oldest_registry_version_in_use_by_replicated_state,
        }
    }
}

/// [`CatchUpPackageShare`] is signed by individual members in a threshold committee.
pub type CatchUpPackageShare = Signed<CatchUpShareContent, ThresholdSignatureShare<CatchUpContent>>;

impl From<&CatchUpPackageShare> for pb::CatchUpPackageShare {
    fn from(cup_share: &CatchUpPackageShare) -> Self {
        Self {
            version: cup_share.content.version.to_string(),
            random_beacon: Some((&cup_share.content.random_beacon.value).into()),
            state_hash: cup_share.content.state_hash.clone().get().0,
            block_hash: cup_share.content.block.clone().get().0,
            random_beacon_hash: cup_share.content.random_beacon.hash.clone().get().0,
            signature: cup_share.signature.signature.clone().get().0,
            signer: Some(node_id_into_protobuf(cup_share.signature.signer)),
            oldest_registry_version_in_use_by_replicated_state: cup_share
                .content
                .oldest_registry_version_in_use_by_replicated_state
                .map(|v| v.get()),
        }
    }
}

impl TryFrom<pb::CatchUpPackageShare> for CatchUpPackageShare {
    type Error = ProxyDecodeError;
    fn try_from(cup_share: pb::CatchUpPackageShare) -> Result<Self, Self::Error> {
        Ok(Signed {
            content: CatchUpShareContent {
                version: ReplicaVersion::try_from(cup_share.version.as_str())?,
                block: CryptoHashOf::new(CryptoHash(cup_share.block_hash)),
                random_beacon: HashedRandomBeacon::recompose(
                    CryptoHashOf::from(CryptoHash(cup_share.random_beacon_hash)),
                    try_from_option_field(
                        cup_share.random_beacon,
                        "CatchUpPackageShare::random_beacon",
                    )?,
                ),
                state_hash: CryptoHashOf::from(CryptoHash(cup_share.state_hash)),
                oldest_registry_version_in_use_by_replicated_state: cup_share
                    .oldest_registry_version_in_use_by_replicated_state
                    .map(RegistryVersion::from),
            },
            signature: ThresholdSignatureShare {
                signature: ThresholdSigShareOf::new(ThresholdSigShare(cup_share.signature)),
                signer: node_id_try_from_option(cup_share.signer)?,
            },
        })
    }
}
/// The parameters used to request [`CatchUpPackage`] (by orchestrator).
///
/// We make use of the [`Ord`] trait to determine if one [`CatchUpPackage`] is newer
/// than the other:
///
/// ```ignore
/// C1 > C2 iff
///   C1.height > C2.height ||
///   C1.height == C2.height && C1.registry_version > C2.registry_version
/// ```
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct CatchUpPackageParam {
    height: Height,
    registry_version: RegistryVersion,
}

/// The [`PartialOrd`] instance is explicitly given below to avoid relying on
/// the ordering of the struct fields.
impl PartialOrd for CatchUpPackageParam {
    fn partial_cmp(&self, other: &CatchUpPackageParam) -> Option<Ordering> {
        match (
            self.height.cmp(&other.height),
            self.registry_version.partial_cmp(&other.registry_version),
        ) {
            // If height is less, registry version needs to be less or equal
            (Ordering::Less, Some(x)) if x != Ordering::Greater => Some(Ordering::Less),
            // If height is equal, registry version decides ordering
            (Ordering::Equal, Some(x)) => Some(x),
            // If height is greater, registry version needs to be equal or greater
            (Ordering::Greater, Some(x)) if x != Ordering::Less => Some(Ordering::Greater),
            // All other combinations of height and registry versions are incomparable
            // This also covers the case, that the registry versions themselves are incomparable
            _ => None,
        }
    }
}

impl From<&CatchUpPackage> for CatchUpPackageParam {
    fn from(catch_up_package: &CatchUpPackage) -> Self {
        Self::from(&catch_up_package.content)
    }
}

impl From<&CatchUpContent> for CatchUpPackageParam {
    fn from(catch_up_content: &CatchUpContent) -> Self {
        Self {
            height: catch_up_content.height(),
            registry_version: catch_up_content.registry_version(),
        }
    }
}

impl TryFrom<&pb::CatchUpPackage> for CatchUpPackageParam {
    type Error = ProxyDecodeError;
    fn try_from(catch_up_package: &pb::CatchUpPackage) -> Result<Self, Self::Error> {
        let catch_up_content = CatchUpContent::try_from(
            pb::CatchUpContent::decode(catch_up_package.content.as_slice())
                .map_err(ProxyDecodeError::DecodeError)?,
        )?;

        Ok(Self::from(&catch_up_content))
    }
}

/// [`CatchUpContentProtobufBytes`] holds bytes that represent a protobuf serialized
/// catch-up package
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub struct CatchUpContentProtobufBytes(Vec<u8>);

impl From<&pb::CatchUpPackage> for CatchUpContentProtobufBytes {
    fn from(proto: &pb::CatchUpPackage) -> Self {
        Self(proto.content.clone())
    }
}

impl SignedBytesWithoutDomainSeparator for CatchUpContentProtobufBytes {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        self.0.clone()
    }
}

#[test]
fn test_catch_up_package_param_partial_ord() {
    let c1 = CatchUpPackageParam {
        height: Height::from(1),
        registry_version: RegistryVersion::from(1),
    };
    let c2 = CatchUpPackageParam {
        height: Height::from(2),
        registry_version: RegistryVersion::from(1),
    };
    let c3 = CatchUpPackageParam {
        height: Height::from(2),
        registry_version: RegistryVersion::from(2),
    };
    let c4 = CatchUpPackageParam {
        height: Height::from(1),
        registry_version: RegistryVersion::from(2),
    };
    let c5 = CatchUpPackageParam {
        height: Height::from(0),
        registry_version: RegistryVersion::from(2),
    };
    // c2 > c1
    assert_eq!(c2.partial_cmp(&c1), Some(Ordering::Greater));
    // c3 > c1
    assert_eq!(c3.partial_cmp(&c1), Some(Ordering::Greater));
    // c3 > c2. This can happen when we want to recover a stuck subnet
    // with a new CatchUpPackage.
    assert_eq!(c3.partial_cmp(&c2), Some(Ordering::Greater));
    // c3 == c3
    assert_eq!(c3.partial_cmp(&c3), Some(Ordering::Equal));
    // c4 > c1
    assert_eq!(c4.partial_cmp(&c1), Some(Ordering::Greater));
    // c5 does not compare to c1
    assert_eq!(c5.partial_cmp(&c1), None);
}
