pub mod batch;
pub mod fake;
pub mod idkg;

use assert_matches::assert_matches;
use ic_interfaces::{
    consensus_pool::{ChangeAction, ConsensusPoolCache, ConsensusTime},
    validation::*,
};
use ic_protobuf::types::v1 as pb;
use ic_types::{
    Height, Time,
    batch::ValidationContext,
    consensus::{
        Block, BlockPayload, CatchUpContent, CatchUpPackage, ConsensusMessageHashable, HasHeight,
        HashedBlock, HashedRandomBeacon, Payload, RandomBeaconContent, Rank, SummaryPayload,
        dkg::DkgSummary,
        idkg::{IDkgBlockReader, IDkgStats, RequestId},
    },
    crypto::{
        CombinedThresholdSig, CombinedThresholdSigOf, CryptoHash, Signed,
        canister_threshold_sig::idkg::{IDkgDealingSupport, IDkgTranscriptParams},
        crypto_hash,
        threshold_sig::ni_dkg::NiDkgTag,
    },
    signature::ThresholdSignature,
    time::UNIX_EPOCH,
};
use phantom_newtype::Id;
use std::{fmt::Debug, sync::RwLock, time::Duration};

#[macro_export]
macro_rules! assert_changeset_matches_pattern {
    ($v:expr, $p:pat) => {
        assert_eq!($v.len(), 1);
        assert_matches!($v[0], $p);
    };
}

pub fn assert_result_invalid<P: Debug, T: Debug>(result: ValidationResult<ValidationError<P, T>>) {
    assert_matches!(result, Err(ValidationError::InvalidArtifact(_)));
}

pub fn assert_action_invalid<T: ConsensusMessageHashable>(action: ChangeAction, msg: &T) {
    match action {
        ChangeAction::HandleInvalid(actual, _) => assert_eq!(actual, msg.clone().into_message()),
        _ => panic!("Expected HandleInvalid ChangeAction"),
    }
}

// CachedData for fake ConsensusPoolCache
struct CachedData {
    finalized_block: Block,
    summary_block: Block,
    catch_up_package: CatchUpPackage,
    catch_up_package_proto: pb::CatchUpPackage,
}

pub struct FakeConsensusPoolCache {
    cache: RwLock<CachedData>,
}

// FakeConsensusPoolCache. Used as fake which allows for updating CUP and blocks
// during unit tests.
impl FakeConsensusPoolCache {
    pub fn new(cup_proto: pb::CatchUpPackage) -> Self {
        let catch_up_package: CatchUpPackage = (&cup_proto)
            .try_into()
            .expect("deserialization of CUP failed");
        let latest_block = catch_up_package.content.block.as_ref();
        Self {
            cache: RwLock::new(CachedData {
                finalized_block: latest_block.clone(),
                summary_block: latest_block.clone(),
                catch_up_package,
                catch_up_package_proto: cup_proto,
            }),
        }
    }

    pub fn update_cup(&self, cup_proto: pb::CatchUpPackage) {
        let catch_up_package: CatchUpPackage = (&cup_proto)
            .try_into()
            .expect("deserialization of CUP failed");
        let latest_block = catch_up_package.content.block.as_ref();
        let cache = &mut *self.cache.write().unwrap();
        cache.finalized_block = latest_block.clone();
        cache.summary_block = latest_block.clone();
        cache.catch_up_package = catch_up_package;
        cache.catch_up_package_proto = cup_proto;
    }
}

impl ConsensusTime for FakeConsensusPoolCache {
    fn consensus_time(&self) -> Option<Time> {
        let cache = &*self.cache.read().unwrap();
        if cache.finalized_block.height() == Height::from(0) {
            None
        } else {
            Some(cache.finalized_block.context.time)
        }
    }
}

impl ConsensusPoolCache for FakeConsensusPoolCache {
    fn finalized_block(&self) -> Block {
        self.cache.read().unwrap().finalized_block.clone()
    }

    fn catch_up_package(&self) -> CatchUpPackage {
        self.cache.read().unwrap().catch_up_package.clone()
    }

    fn cup_as_protobuf(&self) -> pb::CatchUpPackage {
        self.cache.read().unwrap().catch_up_package_proto.clone()
    }

    fn summary_block(&self) -> Block {
        self.cache.read().unwrap().summary_block.clone()
    }
}

/// Return the genesis BlockProposal and RandomBeacon made for the given height.
pub fn make_genesis(summary: DkgSummary) -> CatchUpPackage {
    // Use the registry version and height, from which the summary package was
    // created.
    let registry_version = summary.registry_version;
    let height = summary.height;
    let low_dkg_id = summary
        .current_transcript(&NiDkgTag::LowThreshold)
        .unwrap()
        .dkg_id
        .clone();
    let high_dkg_id = summary
        .current_transcript(&NiDkgTag::HighThreshold)
        .unwrap()
        .dkg_id
        .clone();
    let block = Block::new(
        Id::from(CryptoHash(Vec::new())),
        Payload::new(
            crypto_hash,
            BlockPayload::Summary(SummaryPayload {
                dkg: summary,
                idkg: None,
            }),
        ),
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
            None,
        ),
        signature: ThresholdSignature {
            signer: high_dkg_id,
            signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![])),
        },
    }
}

pub struct IDkgStatsNoOp {}
impl IDkgStats for IDkgStatsNoOp {
    fn update_active_transcripts(&self, _block_reader: &dyn IDkgBlockReader) {}
    fn update_active_pre_signatures(&self, _block_reader: &dyn IDkgBlockReader) {}
    fn record_support_validation(&self, _support: &IDkgDealingSupport, _duration: Duration) {}
    fn record_support_aggregation(
        &self,
        _transcript_params: &IDkgTranscriptParams,
        _support_shares: &[IDkgDealingSupport],
        _duration: Duration,
    ) {
    }
    fn record_transcript_creation(
        &self,
        _transcript_params: &IDkgTranscriptParams,
        _duration: Duration,
    ) {
    }
    fn update_active_signature_requests(&self, _requests: Vec<RequestId>) {}
    fn record_sig_share_validation(&self, _request_id: &RequestId, _duration: Duration) {}
    fn record_sig_share_aggregation(&self, _request_id: &RequestId, _duration: Duration) {}
}
