//! This module provides the component responsible for generating and validating
//! payloads relevant to canister threshold signatures.
//!
//! # Goal
//! We want canisters to be able to hold tokens of other chains, i.e. BTC, ETH, SOL,
//! and for them to create transactions for these networks, i.e. bitcoin, ethereum,
//! solana. Since those networks use specific signature schemes such as ECDSA or Schnorr,
//! a canister must be able to create signatures according to these schemes. Since a
//! canister cannot hold the secret key itself, the secret key will be shared among the
//! replicas of the subnet, and they must be able to collaboratively create threshold
//! signatures.
//!
//! # High level implementation design
//! Each subnet will have a single threshold key for each scheme deployed to the subnet.
//! Currently, only threshold ECDSA and threshold Schnorr are supported. From this key,
//! we will derive per-canister keys. A canister can via a system API request a signature,
//! and this request is stored in the replicated state. Consensus will observe these
//! requests and begin working on them by assembling required artifacts in blocks.
//!
//! ## Interactive Distributed Key Generation & Transcripts
//! To create canister threshold signatures we need a `Transcript` that gives all
//! replicas shares of a secret key. However, this is not sufficient: we need additional
//! transcripts to share the ephemeral values used in a signature.
//!
//! The creation of one ECDSA signature requires a transcript that
//! shares the ECDSA signing key `x`, and additionally four IDKG transcripts,
//! with a special structure: we need transcripts `t1`, `t2`, `t3`, `t4`, such
//! that `t1` and `t2` share random values `r1` and `r2` respectively, `t3`
//! shares the product `r1 * r2`, and `t4` shares `r2 * x`.
//!
//! Similarly, the creation of one Schnorr signature requires a transcript that
//! shares the Schnorr signing key `x`, and one additional IDKG transcript (blinder) `t`,
//! such that `t` shares a random value `r`.
//!
//! Such transcripts are created via an interactive distributed key generation (IDKG)
//! protocol. Especially for the ECDSA case, the DKG for these transcripts must be
//! computationally efficient, because we need four transcripts per signature, and we
//! want to be able to create many signatures. This means that we need interactive DKG
//! for canister threshold signatures, instead of non-interactive DKG like we do for
//! our threshold BLS signatures.
//!
//! Consensus orchestrates the creation of these transcripts. Blocks contain
//! configs (also called params) indicating which transcripts should be created.
//! Such configs come in different types, because some transcripts should share a
//! random value, while others need to share the product of two other transcripts.
//! Complete transcripts will be included in blocks via the functions
//! `create_data_payload` and `create_summary_payload`.
//!
//! # [IDkgImpl] behavior
//! The IDKG component is responsible for adding artifacts to the IDKG
//! artifact pool, and validating artifacts in that pool, by exposing a function
//! `on_state_change`. This function behaves as follows, where `finalized_tip`
//! denotes the latest finalized consensus block, and `certified_state` denotes
//! the latest certified state.
//!
//! ## add DKG dealings
//! for every config in `finalized_tip.idkg.configs`, do the following: if this
//! replica is a dealer in this config, and no dealing for this config created
//! by this replica is in the validated pool, attempt to load the dependencies and,
//! if successful, create a dealing for this config, and add it to the validated pool.
//! If loading the dependencies (i.e. t3 depends on t2 and t1) wasn't successful,
//! we instead send a complaint for the transcript that failed to load.
//!
//! ## validate IDKG dealings
//! for every unvalidated dealing d, do the following. If `d.config_id` is an
//! element of `finalized_tip.idkg.configs`, the validated pool does not yet
//! contain a dealing from `d.dealer` for `d.config_id`, then do the public
//! cryptographic validation of the dealing, and move it to the validated pool
//! if valid, or remove it from the unvalidated pool if invalid.
//!
//! ## Support DKG dealings
//! In the previous step, we only did the "public" verification of the dealings,
//! which does not check that the dealing encrypts a good share for this
//! replica. For every validated dealing d for which no support message by this
//! replica exists in the validated pool, do the "private" cryptographic
//! validation, and if valid, add a support dealing message for d to the
//! validated pool.
//!
//! ## Remove stale dealings
//! for every validated or unvalidated dealing or support d, do the following.
//! If `d.config_id` is not an element of `finalized_tip.idkg.configs`, and
//! `d.config_id` is older than `finalized_tip`, remove `d` from the pool.
//!
//! ## add signature shares
//! for every signature request `req` in
//! `certified_state.signature_requests`, do the following: if this replica
//! is a signer for `req` and no signature share by this replica is in the
//! validated pool, load the dependencies (i.e. the pre-signature and key transcripts),
//! then create a signature share for `req` and add it to the validated pool.
//!
//! ## validate signature shares
//! for every unvalidated signature share `s`, do the following: if `s.request_id`
//! is an element of `certified_state.signature_requests`, and there is no signature
//! share by `s.signer` for `s.request_id` in the validated pool yet, then load the
//! dependencies and cryptographically validate the signature share. If valid, move
//! `s` to validated, and if invalid, remove `s` from unvalidated.
//!
//! ## aggregate signature shares
//! Signature shares are aggregated into full signatures and included into a block
//! by the block maker, once enough shares are available.
//!
//! ## validate complaints
//! for every unvalidated complaint `c`, do the following: if `c.config_id`
//! is an element of `finalized_tip.idkg.configs`, and there is no complaint
//! by `c.complainer` for `c.config_id` in the validated pool yet, then
//! cryptographically validate the signature of the complaint and the complaint
//! itself. If valid, move `c` to validated, and if invalid, remove `c` from unvalidated.
//!
//! ## send openings
//! for every validated complaint `c` for which this node has not sent an opening yet and
//! for which `c.config_id` is an element of `finalized_tip.idkg.configs`: create and sign
//! the opening, and add it to the validated pool.
//!
//!
//! # IDKG payload on blocks
//! The IDKG payload on blocks serves some purposes: it should ensure that all
//! replicas are doing IDKGs to help create the transcripts required for more
//! pre-signatures which are used to create threshold signatures. Additionally, it
//! should contain newly aggregated signatures that can be delivered back to execution.
//!
//! Every block contains
//! - a set of "pre-signatures being created"
//! - a set of "available pre-signatures"
//! - newly finished signatures to deliver up
//!
//! The ECDSA "pre-signatures in creation" contain the following information
//! - kappa_config: config for 1st unmasked random transcript
//! - optionally, kappa_unmasked: transcript resulting from kappa_config
//! - lambda_config: config for 2nd masked random transcript
//! - optionally, lambda_masked: transcript resulting from lambda_config
//! - optionally, key_times_lambda_config: multiplication of the ECDSA secret
//!   key and lambda_masked transcript (so masked multiplication of unmasked and
//!   masked)
//! - optionally, key_times_lambda: transcript resulting from
//!   key_times_lambda_config
//! - optionally, kappa_times_lambda_config: config of multiplication
//!   kappa_unmasked and lambda_masked (so masked multiplication of unmasked and
//!   masked)
//! - optionally, kappa_times_lambda: transcript resulting from
//!   kappa_times_lambda_config
//!
//! The relation between the different configs/transcripts can be summarized as
//! follows:
//! ```text
//! kappa_unmasked ─────────►
//!                           kappa_times_lambda
//!         ┌───────────────►
//!         │
//! lambda_masked
//!         │
//!         └───────────────►
//!                           key_times_lambda
//! ecdsa_key  ─────────────►
//! ```
//! The data transforms like a state machine:
//! - when a new transcript is complete, it is added to the corresponding
//!   "4-tuple being created"
//!     - when lambda_masked is set, key_times_lambda_config should be set
//!     - when lambda_masked and kappa_unmasked are set,
//!       kappa_times_lambda_config must be set
//!     - when kappa_unmasked, lambda_masked, key_times_lambda,
//!       kappa_times_lambda are set, the tuple should no longer be in "in
//!       creation", but instead be moved to the complete 4-tuples.
//!
//! //! The Schnorr "pre-signatures in creation" contain the following information
//! - blinder_config: config for unmasked random transcript
//! - optionally, blinder_unmasked: transcript resulting from blinder_config
//!
//! The relation between the different configs/transcripts can be summarized as
//! follows:
//! ```text
//! blinder_unmasked
//! ```
//! The data transforms like a state machine:
//! - when a new transcript is complete, it is added to the corresponding
//!   "pre-signature being created"
//!     - when blinder_unmasked is set, the pre-signature should no longer be in "in
//!       creation", but instead be moved to the complete pre-signatures.
//!
//! Completed pre-signatures are delivered to the deterministic state machnine,
//! where they are matched with incoming signature requests.

use crate::{
    complaints::{IDkgComplaintHandler, IDkgComplaintHandlerImpl},
    metrics::{CRITICAL_ERROR_IDKG_RETAIN_ACTIVE_TRANSCRIPTS, IDkgClientMetrics, timed_call},
    pre_signer::{IDkgPreSigner, IDkgPreSignerImpl},
    signer::{ThresholdSigner, ThresholdSignerImpl},
    utils::{IDkgBlockReaderImpl, build_thread_pool},
};
use ic_consensus_utils::{bouncer_metrics::BouncerMetrics, crypto::ConsensusCrypto};
use ic_interfaces::{
    consensus_pool::{ConsensusBlockCache, ConsensusPoolCache},
    crypto::IDkgProtocol,
    idkg::{IDkgChangeSet, IDkgPool},
    p2p::consensus::{Bouncer, BouncerFactory, BouncerValue, PoolMutationsProducer},
};
use ic_interfaces_state_manager::StateReader;
use ic_logger::{ReplicaLogger, error, warn};
use ic_metrics::MetricsRegistry;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    Height, NodeId, SubnetId,
    artifact::IDkgMessageId,
    consensus::{HasHeight, idkg::IDkgBlockReader},
    crypto::canister_threshold_sig::{error::IDkgRetainKeysError, idkg::IDkgTranscript},
    malicious_flags::MaliciousFlags,
};
use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};
use utils::IDkgSchedule;

pub(crate) mod complaints;
#[cfg(any(feature = "malicious_code", test))]
pub mod malicious_pre_signer;
pub mod metrics;
pub(crate) mod payload_builder;
pub(crate) mod payload_verifier;
pub(crate) mod pre_signer;
pub(crate) mod signer;
pub mod stats;
#[cfg(test)]
pub(crate) mod test_utils;
pub mod utils;

pub use payload_builder::{
    create_data_payload, create_summary_payload, make_bootstrap_summary,
    make_bootstrap_summary_with_initial_dealings,
};
pub use payload_verifier::{
    IDkgPayloadValidationFailure, InvalidIDkgPayloadReason, validate_payload,
};
pub use stats::IDkgStatsImpl;

/// The maximum number of threads used to process IDkg artifacts in parallel.
pub(crate) const MAX_IDKG_THREADS: usize = 16;

/// Similar to consensus, we don't fetch artifacts too far ahead in future.
const LOOK_AHEAD: u64 = 10;

/// Frequency for clearing the inactive key transcripts.
pub(crate) const INACTIVE_TRANSCRIPT_PURGE_SECS: Duration = Duration::from_secs(60);

/// `IDkgImpl` is the consensus component responsible for processing threshold
/// IDKG payloads.
pub struct IDkgImpl {
    /// The Pre-Signer subcomponent
    pub pre_signer: Box<IDkgPreSignerImpl>,
    pre_signer_schedule: IDkgSchedule<Height>,
    signer: Box<dyn ThresholdSigner>,
    signer_schedule: IDkgSchedule<Height>,
    complaint_handler: Box<dyn IDkgComplaintHandler>,
    complaint_schedule: IDkgSchedule<Height>,
    consensus_block_cache: Arc<dyn ConsensusBlockCache>,
    crypto: Arc<dyn ConsensusCrypto>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    schedule: IDkgSchedule<Instant>,
    metrics: IDkgClientMetrics,
    logger: ReplicaLogger,
    #[cfg_attr(not(feature = "malicious_code"), allow(dead_code))]
    malicious_flags: MaliciousFlags,
}

impl IDkgImpl {
    /// Builds a new IDKG component
    pub fn new(
        node_id: NodeId,
        consensus_block_cache: Arc<dyn ConsensusBlockCache>,
        crypto: Arc<dyn ConsensusCrypto>,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        metrics_registry: MetricsRegistry,
        logger: ReplicaLogger,
        malicious_flags: MaliciousFlags,
    ) -> Self {
        let thread_pool = build_thread_pool(MAX_IDKG_THREADS);
        let pre_signer = Box::new(IDkgPreSignerImpl::new(
            node_id,
            consensus_block_cache.clone(),
            crypto.clone(),
            thread_pool.clone(),
            metrics_registry.clone(),
            logger.clone(),
        ));
        let signer = Box::new(ThresholdSignerImpl::new(
            node_id,
            crypto.clone(),
            thread_pool,
            state_reader.clone(),
            metrics_registry.clone(),
            logger.clone(),
        ));
        let complaint_handler = Box::new(IDkgComplaintHandlerImpl::new(
            node_id,
            consensus_block_cache.clone(),
            crypto.clone(),
            state_reader.clone(),
            metrics_registry.clone(),
            logger.clone(),
        ));
        Self {
            pre_signer,
            pre_signer_schedule: IDkgSchedule::new(Height::from(0)),
            signer,
            signer_schedule: IDkgSchedule::new(Height::from(0)),
            complaint_handler,
            complaint_schedule: IDkgSchedule::new(Height::from(0)),
            crypto,
            state_reader,
            consensus_block_cache,
            schedule: IDkgSchedule::new(Instant::now()),
            metrics: IDkgClientMetrics::new(metrics_registry),
            logger,
            malicious_flags,
        }
    }

    /// Purges the transcripts that are no longer active.
    fn purge_inactive_transcripts(&self, block_reader: &dyn IDkgBlockReader) {
        let active_transcripts = match get_active_transcripts(
            block_reader,
            self.state_reader.as_ref(),
            &self.metrics,
            &self.logger,
        ) {
            Ok(transcripts) => transcripts,
            Err(err) => {
                warn!(
                    self.logger,
                    "purge_inactive_transcripts(): abort due to: {}", err,
                );
                return;
            }
        };

        match IDkgProtocol::retain_active_transcripts(&*self.crypto, &active_transcripts) {
            Err(IDkgRetainKeysError::TransientInternalError { internal_error }) => {
                warn!(
                    self.logger,
                    "purge_inactive_transcripts(): failed due to transient error: {}",
                    internal_error
                );
                self.metrics
                    .client_errors
                    .with_label_values(&["retain_active_transcripts_transient"])
                    .inc();
            }
            Err(error) => {
                error!(
                    self.logger,
                    "{}: failed with error = {:?}",
                    CRITICAL_ERROR_IDKG_RETAIN_ACTIVE_TRANSCRIPTS,
                    error
                );
                self.metrics
                    .critical_error_idkg_retain_active_transcripts
                    .inc();
            }
            Ok(()) => {
                self.metrics
                    .client_metrics
                    .with_label_values(&["retain_active_transcripts"])
                    .inc();
            }
        }
    }
}

fn get_active_transcripts(
    block_reader: &dyn IDkgBlockReader,
    state_reader: &dyn StateReader<State = ReplicatedState>,
    metrics: &IDkgClientMetrics,
    logger: &ReplicaLogger,
) -> Result<HashSet<IDkgTranscript>, String> {
    let mut active_transcripts = HashSet::new();
    let mut error_count = 0;
    // Retain all active transcripts on the blockchain
    for transcript_ref in block_reader.active_transcripts() {
        match block_reader.transcript(&transcript_ref) {
            Ok(transcript) => {
                metrics
                    .client_metrics
                    .with_label_values(&["resolve_active_transcript_refs"])
                    .inc();
                active_transcripts.insert(transcript);
            }
            Err(error) => {
                warn!(
                    logger,
                    "purge_inactive_transcripts(): failed to resolve transcript ref: err = {:?}, \
                        {:?}",
                    error,
                    transcript_ref,
                );
                metrics
                    .client_errors
                    .with_label_values(&["resolve_active_transcript_refs"])
                    .inc();
                error_count += 1;
            }
        }
    }

    if error_count > 0 {
        return Err(format!(
            "Received {error_count} errors when resolving transcipts"
        ));
    }

    if let Some(snapshot) = state_reader.get_certified_state_snapshot() {
        let state = snapshot.get_state();

        // Retain all stashed key transcripts
        for stash in state.pre_signature_stashes().values() {
            active_transcripts.insert((*stash.key_transcript).clone());
        }

        // Retain transcripts paired with ongoing requests
        for request in state.signature_request_contexts().values() {
            for transcript in request.iter_idkg_transcripts() {
                active_transcripts.insert(transcript.clone());
            }
        }
    }
    Ok(active_transcripts)
}

impl<T: IDkgPool> PoolMutationsProducer<T> for IDkgImpl {
    type Mutations = IDkgChangeSet;

    fn on_state_change(&self, idkg_pool: &T) -> IDkgChangeSet {
        let metrics = self.metrics.clone();
        let pre_signer = || {
            let changeset = timed_call(
                "pre_signer",
                || {
                    self.pre_signer.on_state_change(
                        idkg_pool,
                        self.complaint_handler.as_transcript_loader(),
                        &self.pre_signer_schedule,
                    )
                },
                &metrics.on_state_change_duration,
            );
            #[cfg(any(feature = "malicious_code", test))]
            if self.malicious_flags.is_idkg_malicious() {
                return crate::malicious_pre_signer::maliciously_alter_changeset(
                    changeset,
                    &self.pre_signer,
                    &self.malicious_flags,
                );
            }
            changeset
        };
        let signer = || {
            timed_call(
                "signer",
                || {
                    self.signer.on_state_change(
                        idkg_pool,
                        self.complaint_handler.as_transcript_loader(),
                        &self.signer_schedule,
                    )
                },
                &metrics.on_state_change_duration,
            )
        };
        let complaint_handler = || {
            timed_call(
                "complaint_handler",
                || {
                    self.complaint_handler
                        .on_state_change(idkg_pool, &self.complaint_schedule)
                },
                &metrics.on_state_change_duration,
            )
        };

        let calls: [&'_ dyn Fn() -> IDkgChangeSet; 3] = [&pre_signer, &signer, &complaint_handler];
        let ret = self.schedule.call_next(&calls);

        if self.schedule.last_purge.borrow().elapsed() >= INACTIVE_TRANSCRIPT_PURGE_SECS {
            let block_reader =
                IDkgBlockReaderImpl::new(self.consensus_block_cache.finalized_chain());
            timed_call(
                "purge_inactive_transcripts",
                || self.purge_inactive_transcripts(&block_reader),
                &metrics.on_state_change_duration,
            );
            self.schedule.update_last_purge(Instant::now());
        }
        ret
    }
}

/// Implements the BouncerFactory interface for IDkg.
pub struct IDkgBouncer {
    subnet_id: SubnetId,
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    metrics: BouncerMetrics,
}

impl IDkgBouncer {
    /// Builds a new IDkgBouncer component
    pub fn new(
        metrics_registry: &MetricsRegistry,
        subnet_id: SubnetId,
        consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    ) -> Self {
        Self {
            subnet_id,
            consensus_pool_cache,
            state_reader,
            metrics: BouncerMetrics::new(metrics_registry, "idkg_pool"),
        }
    }

    fn compute_args(&self) -> IDkgBouncerArgs {
        IDkgBouncerArgs {
            finalized_height: self.consensus_pool_cache.finalized_block().height(),
            certified_height: self.state_reader.latest_certified_height(),
        }
    }
}

struct IDkgBouncerArgs {
    finalized_height: Height,
    certified_height: Height,
}

impl<Pool: IDkgPool> BouncerFactory<IDkgMessageId, Pool> for IDkgBouncer {
    fn new_bouncer(&self, _idkg_pool: &Pool) -> Bouncer<IDkgMessageId> {
        let _timer = self.metrics.update_duration.start_timer();

        let subnet_id = self.subnet_id;
        let args = self.compute_args();
        Box::new(move |id| compute_bouncer(id, subnet_id, &args))
    }

    fn refresh_period(&self) -> Duration {
        Duration::from_secs(3)
    }
}

fn compute_bouncer(
    id: &IDkgMessageId,
    subnet_id: SubnetId,
    args: &IDkgBouncerArgs,
) -> BouncerValue {
    match id {
        IDkgMessageId::Dealing(_, data) => {
            if data.get_ref().subnet_id != subnet_id {
                return BouncerValue::Wants;
            }

            if data.get_ref().height <= args.finalized_height + Height::from(LOOK_AHEAD) {
                BouncerValue::Wants
            } else {
                BouncerValue::MaybeWantsLater
            }
        }
        IDkgMessageId::DealingSupport(_, data) => {
            // For xnet dealings(target side), always fetch the artifacts,
            // as the source_height from different subnet cannot be compared
            // anyways.
            if data.get_ref().subnet_id != subnet_id {
                return BouncerValue::Wants;
            }

            if data.get_ref().height <= args.finalized_height + Height::from(LOOK_AHEAD) {
                BouncerValue::Wants
            } else {
                BouncerValue::MaybeWantsLater
            }
        }
        IDkgMessageId::EcdsaSigShare(_, data) => {
            if data.get_ref().height <= args.certified_height + Height::from(LOOK_AHEAD) {
                BouncerValue::Wants
            } else {
                BouncerValue::MaybeWantsLater
            }
        }
        IDkgMessageId::SchnorrSigShare(_, data) => {
            if data.get_ref().height <= args.certified_height + Height::from(LOOK_AHEAD) {
                BouncerValue::Wants
            } else {
                BouncerValue::MaybeWantsLater
            }
        }
        IDkgMessageId::VetKdKeyShare(_, data) => {
            if data.get_ref().height <= args.certified_height + Height::from(LOOK_AHEAD) {
                BouncerValue::Wants
            } else {
                BouncerValue::MaybeWantsLater
            }
        }
        IDkgMessageId::Complaint(_, data) => {
            if data.get_ref().height <= args.finalized_height + Height::from(LOOK_AHEAD) {
                BouncerValue::Wants
            } else {
                BouncerValue::MaybeWantsLater
            }
        }
        IDkgMessageId::Opening(_, data) => {
            if data.get_ref().height <= args.finalized_height + Height::from(LOOK_AHEAD) {
                BouncerValue::Wants
            } else {
                BouncerValue::MaybeWantsLater
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::RwLock};

    use crate::test_utils::create_transcript;

    use self::test_utils::TestIDkgBlockReader;

    use super::*;
    use ic_consensus_mocks::{Dependencies, dependencies};
    use ic_logger::no_op_logger;
    use ic_management_canister_types_private::MasterPublicKeyId;
    use ic_test_utilities::state_manager::RefMockStateManager;
    use ic_test_utilities_consensus::idkg::{
        FakeCertifiedStateSnapshot, fake_ecdsa_idkg_master_public_key_id,
        fake_master_public_key_ids_for_all_algorithms,
        fake_master_public_key_ids_for_all_idkg_algorithms, fake_pre_signature_stash,
        fake_signature_request_context_from_id, request_id,
    };
    use ic_types::{
        consensus::idkg::{
            IDkgArtifactIdData, PreSigId, RequestId, SigShareIdData, TranscriptRef,
            complaint_prefix, dealing_prefix, dealing_support_prefix, ecdsa_sig_share_prefix,
            opening_prefix, schnorr_sig_share_prefix, vetkd_key_share_prefix,
        },
        crypto::{CryptoHash, canister_threshold_sig::idkg::IDkgTranscriptId},
        messages::CallbackId,
    };
    use ic_types_test_utils::ids::{NODE_1, NODE_2, SUBNET_1, SUBNET_2, subnet_test_id};

    #[test]
    fn test_get_active_transcripts() {
        let mut block_reader = TestIDkgBlockReader::new();
        let logger = no_op_logger();
        let metrics = IDkgClientMetrics::new(MetricsRegistry::new());

        let mut state = ic_test_utilities_state::get_initial_state(0, 0);
        let expected_state_snapshot = Arc::new(RwLock::new(FakeCertifiedStateSnapshot {
            height: Height::from(1),
            state: Arc::new(state.clone()),
        }));
        let expected_state_snapshot_clone = expected_state_snapshot.clone();

        let state_manager = Arc::new(RefMockStateManager::default());
        state_manager
            .get_mut()
            .expect_get_certified_state_snapshot()
            .returning(move || {
                Some(Box::new(
                    expected_state_snapshot_clone.read().unwrap().clone(),
                ))
            });

        let transcripts =
            get_active_transcripts(&block_reader, state_manager.as_ref(), &metrics, &logger)
                .unwrap();

        assert!(transcripts.is_empty());

        // Add some transcripts to the blockchain
        let chain_transcripts = 3;
        for i in 0..chain_transcripts {
            let height = Height::from(1);
            let key_id = fake_ecdsa_idkg_master_public_key_id();
            let transcript_id = IDkgTranscriptId::new(SUBNET_1, i, height);
            let transcript = create_transcript(&key_id, transcript_id, &[NODE_1, NODE_2]);
            let transcript_ref = TranscriptRef {
                height,
                transcript_id,
            };
            block_reader.add_transcript(transcript_ref, transcript);
        }

        let transcripts =
            get_active_transcripts(&block_reader, state_manager.as_ref(), &metrics, &logger)
                .unwrap();
        assert_eq!(transcripts.len() as u64, chain_transcripts);

        // Create some pre-signature stashes
        let mut stashes = BTreeMap::new();
        for key_id in fake_master_public_key_ids_for_all_idkg_algorithms() {
            stashes.insert(key_id.clone(), fake_pre_signature_stash(&key_id, 5));
        }
        let stashed_transcripts = stashes.len() as u64;
        state
            .metadata
            .subnet_call_context_manager
            .pre_signature_stashes = stashes;
        expected_state_snapshot.write().unwrap().state = Arc::new(state.clone());

        let transcripts =
            get_active_transcripts(&block_reader, state_manager.as_ref(), &metrics, &logger)
                .unwrap();
        assert_eq!(
            transcripts.len() as u64,
            chain_transcripts + stashed_transcripts
        );

        // Create some paired signature requests
        let mut contexts = BTreeMap::new();
        let mut context_transcripts = 0;
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            let callback_id = CallbackId::from(context_transcripts);
            let pre_sig_id = PreSigId(context_transcripts);
            let request_id = RequestId {
                callback_id,
                height: Height::from(1),
            };
            match &key_id {
                MasterPublicKeyId::Ecdsa(_) => context_transcripts += 5, // quadruple + key transcript
                MasterPublicKeyId::Schnorr(_) => context_transcripts += 2, // blinder + key transcript
                MasterPublicKeyId::VetKd(_) => {}                          // No IDkgTranscripts
            }
            contexts.insert(
                callback_id,
                fake_signature_request_context_from_id(key_id, pre_sig_id, request_id).1,
            );
        }
        state
            .metadata
            .subnet_call_context_manager
            .sign_with_threshold_contexts = contexts;
        expected_state_snapshot.write().unwrap().state = Arc::new(state.clone());

        let transcripts =
            get_active_transcripts(&block_reader, state_manager.as_ref(), &metrics, &logger)
                .unwrap();
        assert_eq!(
            transcripts.len() as u64,
            chain_transcripts + stashed_transcripts + context_transcripts
        );
    }

    #[test]
    fn test_idkg_priority_fn_args() {
        const EXPECTED_CERTIFIED_HEIGHT: u64 = 10;
        const EXPECTED_FINALIZED_HEIGHT: u64 = 12;
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies { mut pool, .. } = dependencies(pool_config.clone(), 1);

            let state_manager = Arc::new(RefMockStateManager::default());
            state_manager
                .get_mut()
                .expect_latest_certified_height()
                .returning(move || EXPECTED_CERTIFIED_HEIGHT.into());

            pool.advance_round_normal_operation_n(EXPECTED_FINALIZED_HEIGHT);

            let bouncer_factory = IDkgBouncer::new(
                &MetricsRegistry::new(),
                subnet_test_id(1),
                pool.get_cache(),
                state_manager as Arc<_>,
            );

            let args = bouncer_factory.compute_args();

            assert_eq!(args.certified_height.get(), EXPECTED_CERTIFIED_HEIGHT);
            assert_eq!(args.finalized_height.get(), EXPECTED_FINALIZED_HEIGHT);
        });
    }

    fn get_fake_artifact_id_data(i: IDkgTranscriptId) -> IDkgArtifactIdData {
        IDkgArtifactIdData {
            height: i.source_height(),
            subnet_id: *i.source_subnet(),
            hash: CryptoHash(vec![]),
        }
    }

    fn get_fake_share_id_data(i: &RequestId) -> SigShareIdData {
        SigShareIdData {
            hash: CryptoHash(vec![]),
            height: i.height,
        }
    }

    // Tests the bouncer computation for dealings/support.
    #[test]
    fn test_idkg_priority_fn_dealing_support() {
        let xnet_transcript_id = IDkgTranscriptId::new(SUBNET_1, 1, Height::from(1000));
        let local_subnet_id = SUBNET_2;
        let transcript_id_fetch_1 = IDkgTranscriptId::new(local_subnet_id, 1, Height::from(80));
        let transcript_id_fetch_2 = IDkgTranscriptId::new(local_subnet_id, 3, Height::from(102));
        let transcript_id_stash = IDkgTranscriptId::new(local_subnet_id, 4, Height::from(200));

        let args = IDkgBouncerArgs {
            finalized_height: Height::from(100),
            certified_height: Height::from(100),
        };

        let tests = vec![
            // Signed dealings
            (
                IDkgMessageId::Dealing(
                    dealing_prefix(&xnet_transcript_id, &NODE_1),
                    get_fake_artifact_id_data(xnet_transcript_id).into(),
                ),
                BouncerValue::Wants,
            ),
            (
                IDkgMessageId::Dealing(
                    dealing_prefix(&transcript_id_fetch_1, &NODE_1),
                    get_fake_artifact_id_data(transcript_id_fetch_1).into(),
                ),
                BouncerValue::Wants,
            ),
            (
                IDkgMessageId::Dealing(
                    dealing_prefix(&transcript_id_fetch_2, &NODE_1),
                    get_fake_artifact_id_data(transcript_id_fetch_2).into(),
                ),
                BouncerValue::Wants,
            ),
            (
                IDkgMessageId::Dealing(
                    dealing_prefix(&transcript_id_stash, &NODE_1),
                    get_fake_artifact_id_data(transcript_id_stash).into(),
                ),
                BouncerValue::MaybeWantsLater,
            ),
            // Dealing support
            (
                IDkgMessageId::DealingSupport(
                    dealing_support_prefix(&xnet_transcript_id, &NODE_1, &NODE_2),
                    get_fake_artifact_id_data(xnet_transcript_id).into(),
                ),
                BouncerValue::Wants,
            ),
            (
                IDkgMessageId::DealingSupport(
                    dealing_support_prefix(&transcript_id_fetch_1, &NODE_1, &NODE_2),
                    get_fake_artifact_id_data(transcript_id_fetch_1).into(),
                ),
                BouncerValue::Wants,
            ),
            (
                IDkgMessageId::DealingSupport(
                    dealing_support_prefix(&transcript_id_fetch_2, &NODE_1, &NODE_2),
                    get_fake_artifact_id_data(transcript_id_fetch_2).into(),
                ),
                BouncerValue::Wants,
            ),
            (
                IDkgMessageId::DealingSupport(
                    dealing_support_prefix(&transcript_id_stash, &NODE_1, &NODE_2),
                    get_fake_artifact_id_data(transcript_id_stash).into(),
                ),
                BouncerValue::MaybeWantsLater,
            ),
        ];

        for (id, expected) in tests {
            assert_eq!(compute_bouncer(&id, local_subnet_id, &args), expected);
        }
    }

    // Tests the bouncer computation for sig shares.
    #[test]
    fn test_idkg_priority_fn_sig_shares() {
        let local_subnet_id = SUBNET_2;
        let request_id_fetch_1 = request_id(1, Height::from(80));
        let request_id_fetch_2 = request_id(2, Height::from(102));
        let request_id_stash = request_id(3, Height::from(200));

        let args = IDkgBouncerArgs {
            finalized_height: Height::from(100),
            certified_height: Height::from(100),
        };

        let tests = vec![
            (
                IDkgMessageId::EcdsaSigShare(
                    ecdsa_sig_share_prefix(&request_id_fetch_1, &NODE_1),
                    get_fake_share_id_data(&request_id_fetch_1).into(),
                ),
                BouncerValue::Wants,
            ),
            (
                IDkgMessageId::SchnorrSigShare(
                    schnorr_sig_share_prefix(&request_id_fetch_1, &NODE_1),
                    get_fake_share_id_data(&request_id_fetch_1).into(),
                ),
                BouncerValue::Wants,
            ),
            (
                IDkgMessageId::VetKdKeyShare(
                    vetkd_key_share_prefix(&request_id_fetch_1, &NODE_1),
                    get_fake_share_id_data(&request_id_fetch_1).into(),
                ),
                BouncerValue::Wants,
            ),
            (
                IDkgMessageId::EcdsaSigShare(
                    ecdsa_sig_share_prefix(&request_id_fetch_2, &NODE_1),
                    get_fake_share_id_data(&request_id_fetch_2).into(),
                ),
                BouncerValue::Wants,
            ),
            (
                IDkgMessageId::SchnorrSigShare(
                    schnorr_sig_share_prefix(&request_id_fetch_2, &NODE_1),
                    get_fake_share_id_data(&request_id_fetch_2).into(),
                ),
                BouncerValue::Wants,
            ),
            (
                IDkgMessageId::VetKdKeyShare(
                    vetkd_key_share_prefix(&request_id_fetch_2, &NODE_1),
                    get_fake_share_id_data(&request_id_fetch_2).into(),
                ),
                BouncerValue::Wants,
            ),
            (
                IDkgMessageId::EcdsaSigShare(
                    ecdsa_sig_share_prefix(&request_id_stash, &NODE_1),
                    get_fake_share_id_data(&request_id_stash).into(),
                ),
                BouncerValue::MaybeWantsLater,
            ),
            (
                IDkgMessageId::SchnorrSigShare(
                    schnorr_sig_share_prefix(&request_id_stash, &NODE_1),
                    get_fake_share_id_data(&request_id_stash).into(),
                ),
                BouncerValue::MaybeWantsLater,
            ),
            (
                IDkgMessageId::VetKdKeyShare(
                    vetkd_key_share_prefix(&request_id_stash, &NODE_1),
                    get_fake_share_id_data(&request_id_stash).into(),
                ),
                BouncerValue::MaybeWantsLater,
            ),
        ];

        for (id, expected) in tests {
            assert_eq!(compute_bouncer(&id, local_subnet_id, &args), expected);
        }
    }

    // Tests the priority computation for complaints/openings.
    #[test]
    fn test_idkg_priority_fn_complaint_opening() {
        let local_subnet_id = SUBNET_2;
        let transcript_id_fetch_1 = IDkgTranscriptId::new(local_subnet_id, 1, Height::from(80));
        let transcript_id_fetch_2 = IDkgTranscriptId::new(local_subnet_id, 3, Height::from(102));
        let transcript_id_stash = IDkgTranscriptId::new(local_subnet_id, 4, Height::from(200));
        let transcript_id_fetch_3 = IDkgTranscriptId::new(local_subnet_id, 5, Height::from(80));

        let args = IDkgBouncerArgs {
            finalized_height: Height::from(100),
            certified_height: Height::from(100),
        };

        let tests = vec![
            // Complaints
            (
                IDkgMessageId::Complaint(
                    complaint_prefix(&transcript_id_fetch_1, &NODE_1, &NODE_2),
                    get_fake_artifact_id_data(transcript_id_fetch_1).into(),
                ),
                BouncerValue::Wants,
            ),
            (
                IDkgMessageId::Complaint(
                    complaint_prefix(&transcript_id_fetch_2, &NODE_1, &NODE_2),
                    get_fake_artifact_id_data(transcript_id_fetch_2).into(),
                ),
                BouncerValue::Wants,
            ),
            (
                IDkgMessageId::Complaint(
                    complaint_prefix(&transcript_id_stash, &NODE_1, &NODE_2),
                    get_fake_artifact_id_data(transcript_id_stash).into(),
                ),
                BouncerValue::MaybeWantsLater,
            ),
            (
                IDkgMessageId::Complaint(
                    complaint_prefix(&transcript_id_fetch_3, &NODE_1, &NODE_2),
                    get_fake_artifact_id_data(transcript_id_fetch_3).into(),
                ),
                BouncerValue::Wants,
            ),
            // Openings
            (
                IDkgMessageId::Opening(
                    opening_prefix(&transcript_id_fetch_1, &NODE_1, &NODE_2),
                    get_fake_artifact_id_data(transcript_id_fetch_1).into(),
                ),
                BouncerValue::Wants,
            ),
            (
                IDkgMessageId::Opening(
                    opening_prefix(&transcript_id_fetch_2, &NODE_1, &NODE_2),
                    get_fake_artifact_id_data(transcript_id_fetch_2).into(),
                ),
                BouncerValue::Wants,
            ),
            (
                IDkgMessageId::Opening(
                    opening_prefix(&transcript_id_stash, &NODE_1, &NODE_2),
                    get_fake_artifact_id_data(transcript_id_stash).into(),
                ),
                BouncerValue::MaybeWantsLater,
            ),
            (
                IDkgMessageId::Opening(
                    opening_prefix(&transcript_id_fetch_3, &NODE_1, &NODE_2),
                    get_fake_artifact_id_data(transcript_id_fetch_3).into(),
                ),
                BouncerValue::Wants,
            ),
        ];

        for (id, expected) in tests {
            assert_eq!(compute_bouncer(&id, local_subnet_id, &args), expected);
        }
    }
}
