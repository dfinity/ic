pub mod batch;
pub mod dkg;
pub mod fake;
pub mod idkg;

use assert_matches::assert_matches;
use ic_crypto_tree_hash::{LabeledTree, MatchPatternPath, MixedHashTree};
use ic_interfaces::{
    consensus_pool::{ChangeAction, ConsensusPoolCache, ConsensusTime},
    validation::*,
};
use ic_interfaces_state_manager::{CertifiedStateSnapshot, Labeled};
use ic_protobuf::types::v1 as pb;
use ic_replicated_state::{
    ReplicatedState,
    metadata_state::subnet_call_context_manager::{
        SetupInitialDkgContext, SignWithThresholdContext,
    },
};
use ic_test_utilities_state::ReplicatedStateBuilder;
use ic_types::{
    Height, Time,
    batch::ValidationContext,
    consensus::{
        Block, BlockPayload, CatchUpContent, CatchUpPackage, ConsensusMessageHashable, HasHeight,
        HashedBlock, HashedRandomBeacon, Payload, RandomBeaconContent, Rank, SummaryPayload,
        certification::Certification,
        dkg::DkgSummary,
        idkg::{IDkgBlockReader, IDkgStats, RequestId},
    },
    crypto::{
        CombinedThresholdSig, CombinedThresholdSigOf, CryptoHash, Signed,
        canister_threshold_sig::idkg::{IDkgDealingSupport, IDkgTranscriptParams},
        crypto_hash,
        threshold_sig::ni_dkg::NiDkgTag,
    },
    messages::CallbackId,
    signature::ThresholdSignature,
    time::UNIX_EPOCH,
};
use phantom_newtype::Id;
use std::{
    fmt::Debug,
    sync::{Arc, RwLock},
    time::Duration,
};

#[derive(Clone)]
pub struct FakeCertifiedStateSnapshot {
    pub height: Height,
    pub state: Arc<ReplicatedState>,
}

impl FakeCertifiedStateSnapshot {
    pub fn get_labeled_state(&self) -> Labeled<Arc<ReplicatedState>> {
        Labeled::new(self.height, self.state.clone())
    }

    pub fn inc_height_by(&mut self, height: u64) -> Height {
        self.height += Height::from(height);
        self.height
    }
}

impl CertifiedStateSnapshot for FakeCertifiedStateSnapshot {
    type State = ReplicatedState;

    fn get_state(&self) -> &Self::State {
        &self.state
    }

    fn get_height(&self) -> Height {
        self.height
    }

    fn read_certified_state_with_exclusion(
        &self,
        _paths: &LabeledTree<()>,
        _exclusion: Option<&MatchPatternPath>,
    ) -> Option<(MixedHashTree, Certification)> {
        None
    }
}

/// Builds a [`FakeCertifiedStateSnapshot`] whose replicated state has the
/// given `sign_with_threshold_contexts` and `setup_initial_dkg_contexts`
/// installed in its subnet call context manager. Callback IDs are assigned
/// sequentially and are unique across both context types, matching production
/// behaviour.
pub fn fake_state_with_contexts<S, D>(
    height: Height,
    signature_contexts: S,
    setup_initial_dkg_contexts: D,
) -> FakeCertifiedStateSnapshot
where
    S: IntoIterator<Item = SignWithThresholdContext>,
    D: IntoIterator<Item = SetupInitialDkgContext>,
{
    let mut callback_ids = 0..;
    let mut next_callback_id = || CallbackId::from(callback_ids.next().unwrap());

    let mut state: ReplicatedState = ReplicatedStateBuilder::default().build();
    state
        .metadata
        .subnet_call_context_manager
        .sign_with_threshold_contexts = signature_contexts
        .into_iter()
        .map(|c| (next_callback_id(), c))
        .collect();
    state
        .metadata
        .subnet_call_context_manager
        .setup_initial_dkg_contexts = setup_initial_dkg_contexts
        .into_iter()
        .map(|c| (next_callback_id(), c))
        .collect();

    FakeCertifiedStateSnapshot {
        height,
        state: Arc::new(state),
    }
}

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
