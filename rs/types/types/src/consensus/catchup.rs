//! Defines types that allow outdated replicas to catch up to the latest state.

use crate::{
    consensus::{
        Block, Committee, HasCommittee, HasHeight, HasVersion, HashedBlock, HashedRandomBeacon,
        RandomBeacon, ThresholdSignature, ThresholdSignatureShare,
    },
    crypto::threshold_sig::ni_dkg::NiDkgId,
    crypto::*,
    CryptoHashOfState, Height, RegistryVersion, ReplicaVersion,
};
use ic_protobuf::types::v1 as pb;
use prost::Message;
use serde::{Deserialize, Serialize};
use std::cmp::{Ordering, PartialOrd};
use std::convert::TryFrom;

/// CatchUpContent contains all necessary data to bootstrap a subnet's
/// participant.
pub type CatchUpContent = CatchUpContentT<HashedBlock>;

/// A generic struct shared between CatchUpContent and CatchUpContentShare.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord, Hash)]
pub struct CatchUpContentT<T> {
    /// Replica version that was running when this CUP was created.
    version: ReplicaVersion,
    /// A finalized Block that contains DKG summary. We call its height the
    /// catchup height.
    pub block: T,
    /// The RandomBeacon that is used at the catchup height.
    pub random_beacon: HashedRandomBeacon,
    /// Hash of the subnet execution state that has been fully computed at the
    /// catchup height.
    pub state_hash: CryptoHashOfState,
}

impl CatchUpContent {
    /// Create a new CatchUpContent
    pub fn new(
        block: HashedBlock,
        random_beacon: HashedRandomBeacon,
        state_hash: CryptoHashOfState,
    ) -> Self {
        Self {
            version: block.version().clone(),
            block,
            random_beacon,
            state_hash,
        }
    }
    /// Return the registry version as recorded in the DKG summary of
    /// the block contained in the CatchUpContent.
    pub fn registry_version(&self) -> RegistryVersion {
        self.block
            .as_ref()
            .payload
            .as_ref()
            .as_summary()
            .registry_version
    }

    /// Create a CatchupContent from a
    pub fn from_share_content(share: CatchUpShareContent, block: Block) -> Self {
        Self {
            version: share.version,
            block: HashedBlock {
                hash: share.block,
                value: block,
            },
            random_beacon: share.random_beacon,
            state_hash: share.state_hash,
        }
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
        }
    }
}

impl TryFrom<pb::CatchUpContent> for CatchUpContent {
    type Error = String;
    fn try_from(content: pb::CatchUpContent) -> Result<CatchUpContent, String> {
        let block = super::Block::try_from(
            content
                .block
                .ok_or_else(|| String::from("Error: CUP missing block"))?,
        )?;
        let random_beacon = RandomBeacon::try_from(
            content
                .random_beacon
                .ok_or_else(|| String::from("Error: CUP missing block"))?,
        )?;
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

/// CatchUpPackage is signed by a threshold public key. Its CatchUpContent is
/// only trusted if the threshold public key is trusted.
pub type CatchUpPackage = Signed<CatchUpContent, ThresholdSignature<CatchUpContent>>;

/// CatchUpContentHash is the type of a hashed `CatchUpContent`
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

impl TryFrom<&pb::CatchUpPackage> for CatchUpPackage {
    type Error = String;
    fn try_from(cup: &pb::CatchUpPackage) -> Result<CatchUpPackage, String> {
        Ok(CatchUpPackage {
            content: CatchUpContent::try_from(
                pb::CatchUpContent::decode(&cup.content[..])
                    .map_err(|e| format!("CatchUpContent failed to decode {:?}", e))?,
            )?,
            signature: ThresholdSignature {
                signature: CombinedThresholdSigOf::new(CombinedThresholdSig(cup.signature.clone())),
                signer: NiDkgId::try_from(
                    cup.signer
                        .as_ref()
                        .ok_or_else(|| String::from("Error: CUP signer not present"))?
                        .clone(),
                )
                .map_err(|e| format!("Unable to decode CUP signer {:?}", e))?,
            },
        })
    }
}

/// Content of CatchUpPackageShare uses the block hash to keep its size small.
pub type CatchUpShareContent = CatchUpContentT<CryptoHashOf<Block>>;

impl From<&CatchUpContent> for CatchUpShareContent {
    fn from(content: &CatchUpContent) -> Self {
        Self {
            version: content.version().clone(),
            block: content.block.get_hash().clone(),
            random_beacon: content.random_beacon.clone(),
            state_hash: content.state_hash.clone(),
        }
    }
}

/// CatchUpPackageShare is signed by individual members in a threshold
/// committee.
pub type CatchUpPackageShare = Signed<CatchUpShareContent, ThresholdSignatureShare<CatchUpContent>>;

/// The parameters used to request `CatchUpPackage` (by nodemanager).
///
/// We make use of the `Ord` trait to determine if one `CatchUpPackage` is newer
/// than the other:
///
/// ```ignore
/// C1 > C2 iff
///   C1.height > C2.height ||
///   C1.height == C2.height && C1.registry_version > C2.registry_version
/// ```
#[derive(Serialize, Deserialize, Ord, PartialEq, Eq, Clone, Copy, Debug)]
pub struct CatchUpPackageParam {
    height: Height,
    registry_version: RegistryVersion,
}

/// The PartialOrd instance is explicitly given below to avoid relying on
/// the ordering of the struct fields.
impl PartialOrd for CatchUpPackageParam {
    fn partial_cmp(&self, other: &CatchUpPackageParam) -> Option<Ordering> {
        match self.height.cmp(&other.height) {
            Ordering::Greater => Some(Ordering::Greater),
            _ => self.registry_version.partial_cmp(&other.registry_version),
        }
    }
}

impl From<&CatchUpPackage> for CatchUpPackageParam {
    fn from(catch_up_package: &CatchUpPackage) -> Self {
        Self {
            height: catch_up_package.height(),
            registry_version: catch_up_package.content.registry_version(),
        }
    }
}

/// CatchUpContentProtobufBytes holds bytes that represent a protobuf serialized
/// catch-up package
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct CatchUpContentProtobufBytes(pub Vec<u8>);

/// A catch up package paired with the original protobuf. Note that the protobuf
/// contained in this struct is only partially deserialized and has the ORIGINAL
/// bytes CatchUpContent bytes that were signed in yet to be deserialized form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct CUPWithOriginalProtobuf {
    /// The CUP as [`CatchUpPackage`](type@CatchUpPackage)
    pub cup: CatchUpPackage,
    /// The CUP as protobuf message
    pub protobuf: pb::CatchUpPackage,
}

impl CUPWithOriginalProtobuf {
    /// Create a CUPWithOriginalProtobuf from a CatchUpPackage
    pub fn from_cup(cup: CatchUpPackage) -> Self {
        let protobuf = pb::CatchUpPackage::from(&cup);
        Self { cup, protobuf }
    }
}

impl From<&CUPWithOriginalProtobuf> for CatchUpPackageParam {
    fn from(c: &CUPWithOriginalProtobuf) -> Self {
        Self::from(&c.cup)
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
    // c2 > c1
    assert_eq!(c2.cmp(&c1), Ordering::Greater);
    // c3 > c1
    assert_eq!(c3.cmp(&c1), Ordering::Greater);
    // c3 > c2. This can happen when we want to recover a stuck subnet
    // with a new CatchUpPackage.
    assert_eq!(c3.cmp(&c2), Ordering::Greater);
    // c3 == c3
    assert_eq!(c3.cmp(&c3), Ordering::Equal);
}
