//! This module provides the component responsible for generating and validating
//! payloads relevant to threshold ECDSA signatures.
//!
//! # Goal of threshold ECDSA
//! We want canisters to be able to hold BTC, ETH, and for them to create
//! bitcoin and ethereum transactions. Since those networks use ECDSA, a
//! canister must be able to create ECDSA signatures. Since a canister cannot
//! hold the secret key itself, the secret key will be shared among the replicas
//! of the subnet, and they must be able to collaboratively create ECDSA
//! signatures.
//!
//! # High level implementation design
//! Each subnet will have a single threshold ECDSA key. From this key, we will
//! derive per-canister keys. A canister can via a system API request an ECDSA
//! signature, and this request is stored in the replicated state. Consensus
//! will observe these requests and store in blocks which signatures should be
//! created.
//!
//! ## Distributed Key Generation & Transcripts
//! To create threshold ECDSA signatures we need a `Transcript` that gives all
//! replicas shares of an ECDSA secret key. However, this is not sufficient: we
//! need additional transcripts to share the ephemeral values used in an ECDSA
//! signature. The creation of one ECDSA signature requires a transcript that
//! shares the ECDSA signing key `x`, and additionally four DKG transcripts,
//! with a special structure: we need transcripts `t1`, `t2`, `t3`, `t4`, such
//! that `t1` and `t2` share a random values `r1` and `r2` respectively, `t3`
//! shares the product `r1 * r2`, and `t4` shares `r2 * x`.
//!
//! Such transcripts are created via a distributed key generation (DKG)
//! protocol. The DKG for these transcripts must be computationally efficient,
//! because we need four transcripts per signature, and we want to be able to
//! create many signatures. This means that we need interactive DKG for ECDSA
//! related things, instead of non-interactive DKG like we do for our threshold
//! BLS signatures.
//!
//! Consensus orchestrates the creation of these transcripts. Blocks contain
//! configs indicating which transcripts should be created. Such configs come in
//! different types, because some transcripts should share a random value, while
//! others need to share the product of two other transcripts. Complete
//! transcripts will be included in blocks via the functions
//! [create_data_payload] and [create_summary_payload].
//!
//! # [EcdsaImpl] behavior
//! The ECDSA component is responsible for adding artifacts to the ECDSA
//! artifact pool, and validating artifacts in that pool, by exposing a function
//! `on_state_change`. This function behaves as follows, where `finalized_tip`
//! denotes the latest finalized consensus block.
//!
//! ## add DKG dealings
//! for every config in `finalized_tip.ecdsa.configs`, do the following: if this
//! replica is a dealer in this config, and no dealing for this config created
//! by this replica is in the validated pool,then create a dealing for this
//! config, and add it to the validated pool
//!
//! ## validate DKG dealings
//! for every unvalidated dealing d, do the following. If `d.config_id` is an
//! element of `finalized_tip.ecdsa.configs`, the validated pool does not yet
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
//! for every validated or unvalidated dealing d, do the following. If
//! `d.config_id` is not an element of `finalized_tip.ecdsa.configs`, and
//! `d.config_id` is older than `finalized_tip`, remove `d` from the pool.
//!
//! ## add signature shares
//! for every signature request `req` in
//! `finalized_tip.ecdsa.signature_requests`, do the following: if this replica
//! is a signer for `req` and no signature share by this replica is in the
//! validated pool, create a signature share for `req` and add it to the
//! validated pool.
//!
//! ## validate signature shares
//! for every unvalidated signature share s, do the following: if `s.config_id`
//! is an element of `finalized_tip.ecdsa.configs`, and there is no signature
//! share by `s.signer` for `s.config_id` in the validated pool yet, then
//! cryptographically validate the signature share. If valid, move `s` to
//! validated, and if invalid, remove `s` from unvalidated.
//!
//! ## aggregate ECDSA signatures
//! For every signature request `req` in
//! `finalized_tip.ecdsa.signature_requests` for which no signature is present
//! in the validated pool, do the following: if there are at least
//! `req.threshold` signature shares wrt `req.config` from distinct signers in
//! the validated pool, aggregate the shares into a full ECDSA signature, and
//! add this signature to the validated pool.
//!
//! ## validate full ECDSA signature
//! // TODO
//!
//! ## complaints & openings
//! // TODO
//!
//! # ECDSA payload on blocks
//! The ECDSA payload on blocks serves some purposes: it should ensure that all
//! replicas are doing DKGs to help create the transcripts required for more
//! 4-tuples which are used to create ECDSA signatures. In addition, it should
//! match signature requests to available 4-tuples and generate signatures.
//!
//! Every block contains
//! - a set of "4-tuples being created"
//! - a set of "available 4-tuples"
//! - a set of "ongoing signing requests", which pair signing requests with
//!   4-tuples
//! - newly finished signatures to deliver up
//!
//! The "4 tuples in creation" contain the following information
//! - kappa_config: config for 1st masked random transcript
//! - optionally, kappa_masked: transcript resulting from kappa_config
//! - lambda_config: config for 2nd masked random transcript
//! - optionally, lambda_masked: transcript resulting from kappa_config
//! - optionally, unmask_kappa_config: config for resharing as unmasked of
//!   kappa_masked
//! - optionally, kappa_unmasked: transcript resulting from unmask_kappa_config
//! - optionally, key_times_lambda_config: multiplication of the ECDSA secret
//!   key and lambda_masked transcript (so masked multiplication of unmasked and
//!   masked)
//! - optionally, key_times_lambda: transcript resulting from
//!   key_times_lambda_config
//! - optionally, kappa_times_lambda_config: config of multiplication
//!   kappa_unasmked and lambda_masked (so masked multiplication of unmasked and
//!   masked)
//! - optionally, kappa_times_lambda: transcript resulting from
//!   kappa_times_lambda_config
//!
//! The relation between the different configs/transcripts can be summarized as
//! follows:
//! ```text
//! kappa_masked ────────► kappa_unmasked ─────────►
//!                                                 kappa_times_lambda
//!         ┌──────────────────────────────────────►
//!         │
//! lambda_masked
//!         │
//!         └───────────►
//!                        key_times_lambda
//! ecdsa_key  ─────────►
//! ```
//! The data transforms like a state machine:
//! - remove all signature requests from "ongoing signature requests" that are
//!   no longer present in the replicated state (referenced via the validation
//!   context)
//! - when a new transcript is complete, it is added to the corresponding
//!   "4-tuple being created"
//!     - when kappa_masked is set, unmask_kappa_config should be set (reshare
//!       to unmask)
//!     - when lambda_masked is set, key_times_lambda_config should be set
//!     - when lambda_masked and kappa_unmasked are set,
//!       kappa_times_lambda_config must be set
//!     - when kappa_unmasked, lambda_masked, key_times_lambda,
//!       kappa_times_lambda are set, the tuple should no longer be in "in
//!       creation", but instead be moved to the complete 4-tuples.
//! - whenever the state lists a new signature request (for which no "ongoing
//!   signing request" is present) and available 4-tuples is not empty, remove
//!   the first 4-tuple from the available 4 tuples and make an entry in ongoing
//!   signatures with the signing request and the 4-tuple.
// TODO: Remove after implementing functionality
#![allow(dead_code)]

use crate::consensus::{
    metrics::{timed_call, EcdsaClientMetrics, EcdsaGossipMetrics},
    utils::RoundRobin,
    ConsensusCrypto,
};
use crate::ecdsa::complaints::{EcdsaComplaintHandler, EcdsaComplaintHandlerImpl};
use crate::ecdsa::pre_signer::{EcdsaPreSigner, EcdsaPreSignerImpl};
use crate::ecdsa::signer::{EcdsaSigner, EcdsaSignerImpl};
use crate::ecdsa::utils::EcdsaBlockReaderImpl;

use ic_interfaces::consensus_pool::ConsensusBlockCache;
use ic_interfaces::crypto::IDkgProtocol;
use ic_interfaces::ecdsa::{Ecdsa, EcdsaChangeSet, EcdsaGossip, EcdsaPool};
use ic_logger::{warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_types::{
    artifact::{EcdsaMessageAttribute, EcdsaMessageId, Priority, PriorityFn},
    consensus::ecdsa::{EcdsaBlockReader, RequestId},
    crypto::canister_threshold_sig::idkg::IDkgTranscriptId,
    malicious_flags::MaliciousFlags,
    Height, NodeId, SubnetId,
};

use std::cell::RefCell;
use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(crate) mod complaints;
pub(crate) mod payload_builder;
pub(crate) mod payload_verifier;
pub(crate) mod pre_signer;
pub(crate) mod signer;
pub mod stats;
pub(crate) mod utils;

pub use payload_builder::make_bootstrap_summary;
pub(crate) use payload_builder::{create_data_payload, create_summary_payload};
pub(crate) use payload_verifier::{validate_payload, PermanentError, TransientError};
pub use stats::EcdsaStatsImpl;

/// Similar to consensus, we don't fetch artifacts too far ahead in future.
const LOOK_AHEAD: u64 = 10;

/// Frequency for clearing the inactive key transcripts.
pub const INACTIVE_TRANSCRIPT_PURGE_SECS: Duration = Duration::from_secs(60);

/// `EcdsaImpl` is the consensus component responsible for processing threshold
/// ECDSA payloads.
pub struct EcdsaImpl {
    subnet_id: SubnetId,
    pre_signer: Box<dyn EcdsaPreSigner>,
    signer: Box<dyn EcdsaSigner>,
    complaint_handler: Box<dyn EcdsaComplaintHandler>,
    consensus_block_cache: Arc<dyn ConsensusBlockCache>,
    crypto: Arc<dyn ConsensusCrypto>,
    schedule: RoundRobin,
    last_transcript_purge_ts: RefCell<Instant>,
    metrics: EcdsaClientMetrics,
    logger: ReplicaLogger,
}

impl EcdsaImpl {
    /// Builds a new threshold ECDSA component
    pub fn new(
        node_id: NodeId,
        subnet_id: SubnetId,
        consensus_block_cache: Arc<dyn ConsensusBlockCache>,
        crypto: Arc<dyn ConsensusCrypto>,
        metrics_registry: MetricsRegistry,
        logger: ReplicaLogger,
        malicious_flags: MaliciousFlags,
    ) -> Self {
        let pre_signer = Box::new(EcdsaPreSignerImpl::new(
            node_id,
            subnet_id,
            consensus_block_cache.clone(),
            crypto.clone(),
            metrics_registry.clone(),
            logger.clone(),
            malicious_flags,
        ));
        let signer = Box::new(EcdsaSignerImpl::new(
            node_id,
            consensus_block_cache.clone(),
            crypto.clone(),
            metrics_registry.clone(),
            logger.clone(),
        ));
        let complaint_handler = Box::new(EcdsaComplaintHandlerImpl::new(
            node_id,
            consensus_block_cache.clone(),
            crypto.clone(),
            metrics_registry.clone(),
            logger.clone(),
        ));
        Self {
            subnet_id,
            pre_signer,
            signer,
            complaint_handler,
            crypto,
            consensus_block_cache,
            schedule: RoundRobin::default(),
            last_transcript_purge_ts: RefCell::new(Instant::now()),
            metrics: EcdsaClientMetrics::new(metrics_registry),
            logger,
        }
    }

    /// Purges the transcripts that are no longer active.
    fn purge_inactive_transcripts(&self, block_reader: &dyn EcdsaBlockReader) {
        let mut active_transcripts = HashSet::new();
        for transcript_ref in block_reader.active_transcripts() {
            match block_reader.transcript(&transcript_ref) {
                Ok(transcript) => {
                    self.metrics
                        .client_metrics
                        .with_label_values(&["resolve_active_transcript_refs"])
                        .inc();
                    active_transcripts.insert(transcript);
                }
                Err(error) => {
                    warn!(
                        self.logger,
                        "purge_inactive_transcripts(): failed to resolve transcript ref: err = {:?}, \
                        {:?}",
                        error,
                        transcript_ref,
                    );
                    self.metrics
                        .client_errors
                        .with_label_values(&["resolve_active_transcript_refs"])
                        .inc();
                }
            }
        }

        if let Err(error) =
            IDkgProtocol::retain_active_transcripts(&*self.crypto, &active_transcripts)
        {
            warn!(
                self.logger,
                "purge_inactive_transcripts(): retain_active_transcripts() failed: err = {:?}",
                error,
            );
            self.metrics
                .client_errors
                .with_label_values(&["retain_active_transcripts"])
                .inc();
        } else {
            self.metrics
                .client_metrics
                .with_label_values(&["retain_active_transcripts"])
                .inc();
        }
    }
}

impl Ecdsa for EcdsaImpl {
    fn on_state_change(&self, ecdsa_pool: &dyn EcdsaPool) -> EcdsaChangeSet {
        let metrics = self.metrics.clone();
        let pre_signer = || {
            timed_call(
                "pre_signer",
                || {
                    self.pre_signer
                        .on_state_change(ecdsa_pool, self.complaint_handler.as_transcript_loader())
                },
                &metrics.on_state_change_duration,
            )
        };
        let signer = || {
            timed_call(
                "signer",
                || {
                    self.signer
                        .on_state_change(ecdsa_pool, self.complaint_handler.as_transcript_loader())
                },
                &metrics.on_state_change_duration,
            )
        };
        let complaint_handler = || {
            timed_call(
                "complaint_handler",
                || self.complaint_handler.on_state_change(ecdsa_pool),
                &metrics.on_state_change_duration,
            )
        };

        let calls: [&'_ dyn Fn() -> EcdsaChangeSet; 3] = [&pre_signer, &signer, &complaint_handler];
        let ret = self.schedule.call_next(&calls);

        if self.last_transcript_purge_ts.borrow().elapsed() >= INACTIVE_TRANSCRIPT_PURGE_SECS {
            let block_reader =
                EcdsaBlockReaderImpl::new(self.consensus_block_cache.finalized_chain());
            timed_call(
                "purge_inactive_transcripts",
                || self.purge_inactive_transcripts(&block_reader),
                &metrics.on_state_change_duration,
            );
            *self.last_transcript_purge_ts.borrow_mut() = Instant::now();
        }
        ret
    }
}

/// `EcdsaGossipImpl` implements the priority function and other gossip related
/// functionality
pub struct EcdsaGossipImpl {
    subnet_id: SubnetId,
    consensus_block_cache: Arc<dyn ConsensusBlockCache>,
    metrics: EcdsaGossipMetrics,
}

impl EcdsaGossipImpl {
    /// Builds a new EcdsaGossipImpl component
    pub fn new(
        subnet_id: SubnetId,
        consensus_block_cache: Arc<dyn ConsensusBlockCache>,
        metrics_registry: MetricsRegistry,
    ) -> Self {
        Self {
            subnet_id,
            consensus_block_cache,
            metrics: EcdsaGossipMetrics::new(metrics_registry),
        }
    }
}

struct EcdsaPriorityFnArgs {
    finalized_height: Height,
    requested_transcripts: BTreeSet<IDkgTranscriptId>,
    requested_signatures: BTreeSet<RequestId>,
    active_transcripts: BTreeSet<IDkgTranscriptId>,
}

impl EcdsaPriorityFnArgs {
    fn new(block_reader: &EcdsaBlockReaderImpl) -> Self {
        let mut requested_transcripts = BTreeSet::new();
        for params in block_reader.requested_transcripts() {
            requested_transcripts.insert(params.transcript_id);
        }

        let mut requested_signatures = BTreeSet::new();
        for (request_id, _) in block_reader.requested_signatures() {
            requested_signatures.insert(*request_id);
        }

        let mut active_transcripts = BTreeSet::new();
        for transcript_ref in block_reader.active_transcripts() {
            active_transcripts.insert(transcript_ref.transcript_id);
        }

        Self {
            finalized_height: block_reader.tip_height(),
            requested_transcripts,
            requested_signatures,
            active_transcripts,
        }
    }
}

impl EcdsaGossip for EcdsaGossipImpl {
    fn get_priority_function(
        &self,
        _ecdsa_pool: &dyn EcdsaPool,
    ) -> PriorityFn<EcdsaMessageId, EcdsaMessageAttribute> {
        let block_reader = EcdsaBlockReaderImpl::new(self.consensus_block_cache.finalized_chain());
        let subnet_id = self.subnet_id;
        let args = EcdsaPriorityFnArgs::new(&block_reader);
        let metrics = self.metrics.clone();
        Box::new(move |_, attr: &'_ EcdsaMessageAttribute| {
            compute_priority(attr, subnet_id, &args, &metrics)
        })
    }
}

fn compute_priority(
    attr: &EcdsaMessageAttribute,
    subnet_id: SubnetId,
    args: &EcdsaPriorityFnArgs,
    metrics: &EcdsaGossipMetrics,
) -> Priority {
    match attr {
        EcdsaMessageAttribute::EcdsaSignedDealing(transcript_id)
        | EcdsaMessageAttribute::EcdsaDealingSupport(transcript_id) => {
            // For xnet dealings(target side), always fetch the artifacts,
            // as the source_height from different subnet cannot be compared
            // anyways.
            if *transcript_id.source_subnet() != subnet_id {
                return Priority::Fetch;
            }

            let height = transcript_id.source_height();
            if height <= args.finalized_height {
                if args.requested_transcripts.contains(transcript_id) {
                    Priority::Fetch
                } else {
                    metrics
                        .dropped_adverts
                        .with_label_values(&[attr.as_str()])
                        .inc();
                    Priority::Drop
                }
            } else if height < args.finalized_height + Height::from(LOOK_AHEAD) {
                Priority::Fetch
            } else {
                Priority::Stash
            }
        }
        EcdsaMessageAttribute::EcdsaSigShare(request_id) => {
            if request_id.height <= args.finalized_height {
                if args.requested_signatures.contains(request_id) {
                    Priority::Fetch
                } else {
                    metrics
                        .dropped_adverts
                        .with_label_values(&[attr.as_str()])
                        .inc();
                    Priority::Drop
                }
            } else if request_id.height < args.finalized_height + Height::from(LOOK_AHEAD) {
                Priority::Fetch
            } else {
                Priority::Stash
            }
        }
        EcdsaMessageAttribute::EcdsaComplaint(transcript_id)
        | EcdsaMessageAttribute::EcdsaOpening(transcript_id) => {
            let height = transcript_id.source_height();
            if height <= args.finalized_height {
                if args.active_transcripts.contains(transcript_id) {
                    Priority::Fetch
                } else {
                    metrics
                        .dropped_adverts
                        .with_label_values(&[attr.as_str()])
                        .inc();
                    Priority::Drop
                }
            } else if height < args.finalized_height + Height::from(LOOK_AHEAD) {
                Priority::Fetch
            } else {
                Priority::Stash
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscriptId;
    use ic_types::{
        consensus::ecdsa::{QuadrupleId, RequestId},
        PrincipalId, SubnetId,
    };

    // Tests the priority computation for dealings/support.
    #[test]
    fn test_ecdsa_priority_fn_dealing_support() {
        let xnet_subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(1));
        let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(2));
        let xnet_transcript_id = IDkgTranscriptId::new(xnet_subnet_id, 1, Height::from(1000));
        let transcript_id_fetch_1 = IDkgTranscriptId::new(subnet_id, 1, Height::from(80));
        let transcript_id_drop = IDkgTranscriptId::new(subnet_id, 2, Height::from(70));
        let transcript_id_fetch_2 = IDkgTranscriptId::new(subnet_id, 3, Height::from(102));
        let transcript_id_stash = IDkgTranscriptId::new(subnet_id, 4, Height::from(200));

        let metrics_registry = MetricsRegistry::new();
        let metrics = EcdsaGossipMetrics::new(metrics_registry);

        let mut requested_transcripts = BTreeSet::new();
        requested_transcripts.insert(transcript_id_fetch_1);
        let args = EcdsaPriorityFnArgs {
            finalized_height: Height::from(100),
            requested_transcripts,
            requested_signatures: BTreeSet::new(),
            active_transcripts: BTreeSet::new(),
        };

        let tests = vec![
            // Signed dealings
            (
                EcdsaMessageAttribute::EcdsaSignedDealing(xnet_transcript_id),
                Priority::Fetch,
            ),
            (
                EcdsaMessageAttribute::EcdsaSignedDealing(transcript_id_fetch_1),
                Priority::Fetch,
            ),
            (
                EcdsaMessageAttribute::EcdsaSignedDealing(transcript_id_drop),
                Priority::Drop,
            ),
            (
                EcdsaMessageAttribute::EcdsaSignedDealing(transcript_id_fetch_2),
                Priority::Fetch,
            ),
            (
                EcdsaMessageAttribute::EcdsaSignedDealing(transcript_id_stash),
                Priority::Stash,
            ),
            // Dealing support
            (
                EcdsaMessageAttribute::EcdsaDealingSupport(xnet_transcript_id),
                Priority::Fetch,
            ),
            (
                EcdsaMessageAttribute::EcdsaDealingSupport(transcript_id_fetch_1),
                Priority::Fetch,
            ),
            (
                EcdsaMessageAttribute::EcdsaDealingSupport(transcript_id_drop),
                Priority::Drop,
            ),
            (
                EcdsaMessageAttribute::EcdsaDealingSupport(transcript_id_fetch_2),
                Priority::Fetch,
            ),
            (
                EcdsaMessageAttribute::EcdsaDealingSupport(transcript_id_stash),
                Priority::Stash,
            ),
        ];

        for (attr, expected) in tests {
            assert_eq!(
                compute_priority(&attr, subnet_id, &args, &metrics),
                expected
            );
        }
    }

    // Tests the priority computation for sig shares.
    #[test]
    fn test_ecdsa_priority_fn_sig_shares() {
        let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(2));
        let request_id_fetch_1 = RequestId {
            quadruple_id: QuadrupleId(80),
            pseudo_random_id: [1; 32],
            height: Height::from(80),
        };
        let request_id_drop = RequestId {
            quadruple_id: QuadrupleId(70),
            pseudo_random_id: [2; 32],
            height: Height::from(70),
        };
        let request_id_fetch_2 = RequestId {
            quadruple_id: QuadrupleId(102),
            pseudo_random_id: [3; 32],
            height: Height::from(102),
        };
        let request_id_stash = RequestId {
            quadruple_id: QuadrupleId(200),
            pseudo_random_id: [4; 32],
            height: Height::from(200),
        };

        let metrics_registry = MetricsRegistry::new();
        let metrics = EcdsaGossipMetrics::new(metrics_registry);

        let mut requested_signatures = BTreeSet::new();
        requested_signatures.insert(request_id_fetch_1);
        let args = EcdsaPriorityFnArgs {
            finalized_height: Height::from(100),
            requested_transcripts: BTreeSet::new(),
            requested_signatures,
            active_transcripts: BTreeSet::new(),
        };

        let tests = vec![
            (
                EcdsaMessageAttribute::EcdsaSigShare(request_id_fetch_1),
                Priority::Fetch,
            ),
            (
                EcdsaMessageAttribute::EcdsaSigShare(request_id_drop),
                Priority::Drop,
            ),
            (
                EcdsaMessageAttribute::EcdsaSigShare(request_id_fetch_2),
                Priority::Fetch,
            ),
            (
                EcdsaMessageAttribute::EcdsaSigShare(request_id_stash),
                Priority::Stash,
            ),
        ];

        for (attr, expected) in tests {
            assert_eq!(
                compute_priority(&attr, subnet_id, &args, &metrics),
                expected
            );
        }
    }

    // Tests the priority computation for complaints/openings.
    #[test]
    fn test_ecdsa_priority_fn_complaint_opening() {
        let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(2));
        let transcript_id_fetch_1 = IDkgTranscriptId::new(subnet_id, 1, Height::from(80));
        let transcript_id_drop = IDkgTranscriptId::new(subnet_id, 2, Height::from(70));
        let transcript_id_fetch_2 = IDkgTranscriptId::new(subnet_id, 3, Height::from(102));
        let transcript_id_stash = IDkgTranscriptId::new(subnet_id, 4, Height::from(200));

        let metrics_registry = MetricsRegistry::new();
        let metrics = EcdsaGossipMetrics::new(metrics_registry);

        let mut active_transcripts = BTreeSet::new();
        active_transcripts.insert(transcript_id_fetch_1);
        let args = EcdsaPriorityFnArgs {
            finalized_height: Height::from(100),
            requested_transcripts: BTreeSet::new(),
            requested_signatures: BTreeSet::new(),
            active_transcripts,
        };

        let tests = vec![
            // Complaints
            (
                EcdsaMessageAttribute::EcdsaComplaint(transcript_id_fetch_1),
                Priority::Fetch,
            ),
            (
                EcdsaMessageAttribute::EcdsaComplaint(transcript_id_drop),
                Priority::Drop,
            ),
            (
                EcdsaMessageAttribute::EcdsaComplaint(transcript_id_fetch_2),
                Priority::Fetch,
            ),
            (
                EcdsaMessageAttribute::EcdsaComplaint(transcript_id_stash),
                Priority::Stash,
            ),
            // Openings
            (
                EcdsaMessageAttribute::EcdsaOpening(transcript_id_fetch_1),
                Priority::Fetch,
            ),
            (
                EcdsaMessageAttribute::EcdsaOpening(transcript_id_drop),
                Priority::Drop,
            ),
            (
                EcdsaMessageAttribute::EcdsaOpening(transcript_id_fetch_2),
                Priority::Fetch,
            ),
            (
                EcdsaMessageAttribute::EcdsaOpening(transcript_id_stash),
                Priority::Stash,
            ),
        ];

        for (attr, expected) in tests {
            assert_eq!(
                compute_priority(&attr, subnet_id, &args, &metrics),
                expected
            );
        }
    }
}
