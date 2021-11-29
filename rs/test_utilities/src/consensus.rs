#![allow(clippy::ptr_arg)]
pub mod fake;
use mockall::predicate::*;
use mockall::*;

use crate::crypto::empty_ni_dkg_transcripts_with_committee;
use ic_base_types::RegistryVersion;
use ic_consensus_message::ConsensusMessageHashable;
use ic_crypto::crypto_hash;
use ic_interfaces::{
    consensus::*,
    consensus_pool::{ChangeAction, ChangeSet, ConsensusPool, ConsensusPoolCache},
    ingress_pool::IngressPoolSelect,
    registry::RegistryClient,
    validation::*,
};
use ic_registry_client::helper::subnet::SubnetRegistry;
use ic_types::{
    artifact::*,
    batch::ValidationContext,
    consensus::{
        catchup::CUPWithOriginalProtobuf, dkg, Block, CatchUpContent, CatchUpPackage, HasHeight,
        HashedBlock, HashedRandomBeacon, Payload, RandomBeaconContent, Rank, ThresholdSignature,
    },
    crypto::{
        threshold_sig::ni_dkg::NiDkgTag, CombinedThresholdSig, CombinedThresholdSigOf, CryptoHash,
        Signed,
    },
    time::UNIX_EPOCH,
    Height, SubnetId, Time,
};
use phantom_newtype::Id;
use std::sync::{Arc, RwLock};

#[macro_export]
macro_rules! assert_changeset_matches_pattern {
    ($v:expr, $p:pat) => {
        assert_eq!($v.len(), 1);
        assert!(matches_pattern!($v[0], $p));
    };
}

#[macro_export]
macro_rules! matches_pattern {
    ($v:expr, $p:pat) => {
        if let $p = $v {
            true
        } else {
            false
        }
    };
}

pub fn assert_result_invalid<P, T>(result: ValidationResult<ValidationError<P, T>>) {
    assert!(matches_pattern!(result, Err(ValidationError::Permanent(_))));
}

pub fn assert_action_invalid<T: ConsensusMessageHashable>(action: ChangeAction, msg: &T) {
    match action {
        ChangeAction::HandleInvalid(actual, _) => assert_eq!(actual, msg.clone().into_message()),
        _ => panic!("Expected HandleInvalid ChangeAction"),
    }
}

mock! {
    pub Consensus {}

    pub trait ConsensusGossip: Send + Sync {
        fn get_priority_function<'a>(
            &'a self,
            consensus_pool: &'a (dyn ConsensusPool + 'a),
        ) -> PriorityFn<ConsensusMessageId, ConsensusMessageAttribute>;

        fn get_filter(&self) -> ConsensusMessageFilter;
    }

    pub trait Consensus: Send {
        fn on_state_change<'a>(
            &'a self,
            consensus_pool: &'a (dyn ConsensusPool + 'a),
            ingress_pool: &'a (dyn IngressPoolSelect + 'a),
        ) -> ChangeSet;
    }
}

mock! {

    pub ConsensusCache {}

    pub trait ConsensusPoolCache: Send + Sync {
        fn finalized_block(&self) -> Block;

        fn consensus_time(&self) -> Option<Time>;

        fn catch_up_package(&self) -> CatchUpPackage;

        fn summary_block(&self) -> Block;

        fn cup_with_protobuf(&self) -> CUPWithOriginalProtobuf;

        fn get_subnet_membership_version(&self) -> RegistryVersion;
    }
}

// CachedData for fake ConsensusPoolCache
struct CachedData {
    finalized_block: Block,
    summary_block: Block,
    catch_up_package: CUPWithOriginalProtobuf,
}

pub struct FakeConsensusPoolCache {
    cache: RwLock<CachedData>,
}

// FakeConsensusPoolCache. Used as fake which allows for updating CUP and blocks
// during unit tests.
impl FakeConsensusPoolCache {
    pub fn new(catch_up_package: CUPWithOriginalProtobuf) -> Self {
        let latest_block = catch_up_package.cup.content.block.as_ref();
        Self {
            cache: RwLock::new(CachedData {
                finalized_block: latest_block.clone(),
                summary_block: latest_block.clone(),
                catch_up_package,
            }),
        }
    }

    pub fn update_cup(&self, catch_up_package: CUPWithOriginalProtobuf) {
        let latest_block = catch_up_package.cup.content.block.as_ref();
        let cache = &mut *self.cache.write().unwrap();
        cache.finalized_block = latest_block.clone();
        cache.summary_block = latest_block.clone();
        cache.catch_up_package = catch_up_package;
    }
}

impl ConsensusPoolCache for FakeConsensusPoolCache {
    fn finalized_block(&self) -> Block {
        self.cache.read().unwrap().finalized_block.clone()
    }

    fn consensus_time(&self) -> Option<Time> {
        let cache = &*self.cache.read().unwrap();
        if cache.finalized_block.height() == Height::from(0) {
            None
        } else {
            Some(cache.finalized_block.context.time)
        }
    }

    fn catch_up_package(&self) -> CatchUpPackage {
        self.cache.read().unwrap().catch_up_package.cup.clone()
    }

    fn cup_with_protobuf(&self) -> CUPWithOriginalProtobuf {
        self.cache.read().unwrap().catch_up_package.clone()
    }

    fn summary_block(&self) -> Block {
        self.cache.read().unwrap().summary_block.clone()
    }
}

/// Return a CatchUpPackage created with empty transcript, from the given
/// committee.
pub fn make_catch_up_package_with_empty_transcript(
    registry_client: Arc<dyn RegistryClient>,
    subnet_id: SubnetId,
) -> CatchUpPackage {
    make_catch_up_package_with_empty_transcript_with_version(registry_client, subnet_id, 1)
}

pub fn make_catch_up_package_with_empty_transcript_with_version(
    registry_client: Arc<dyn RegistryClient>,
    subnet_id: SubnetId,
    version: u64,
) -> CatchUpPackage {
    let version = ic_types::RegistryVersion::from(version);
    let subnet_members: Vec<_> = registry_client
        .get_node_ids_on_subnet(subnet_id, version)
        .expect("Could not get node ids from registry")
        .expect("Node ids not available at given registry version");
    let ni_transcripts = empty_ni_dkg_transcripts_with_committee(subnet_members, version.get());
    let summary = ic_consensus::dkg::make_genesis_summary(
        &*registry_client,
        subnet_id,
        Option::from(version),
    )
    .with_current_transcripts(ni_transcripts);
    make_genesis(summary)
}

/// Return the genesis BlockProposal and RandomBeacon made for the given height.
pub fn make_genesis(summary: dkg::Summary) -> CatchUpPackage {
    // Use the registry version and height, from which the summary package was
    // created.
    let registry_version = summary.registry_version;
    let height = summary.height;
    let low_dkg_id = summary.current_transcript(&NiDkgTag::LowThreshold).dkg_id;
    let high_dkg_id = summary.current_transcript(&NiDkgTag::HighThreshold).dkg_id;
    let block = Block::new(
        Id::from(CryptoHash(Vec::new())),
        Payload::new(crypto_hash, summary.into()),
        height,
        Rank(0),
        ValidationContext {
            certified_height: Height::from(0),
            registry_version,
            time: UNIX_EPOCH,
        },
    );
    let random_beacon = Signed {
        content: RandomBeaconContent::new(height, Id::from(CryptoHash(Vec::new()))),
        signature: ThresholdSignature {
            signer: low_dkg_id,
            signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![])),
        },
    };
    CatchUpPackage {
        content: CatchUpContent::new(
            HashedBlock::new(crypto_hash, block),
            HashedRandomBeacon::new(crypto_hash, random_beacon),
            Id::from(CryptoHash(Vec::new())),
        ),
        signature: ThresholdSignature {
            signer: high_dkg_id,
            signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![])),
        },
    }
}
