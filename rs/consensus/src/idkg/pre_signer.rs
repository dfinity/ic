//! The pre signature process manager

use crate::idkg::complaints::IDkgTranscriptLoader;
use crate::idkg::metrics::{timed_call, IDkgPayloadMetrics, IDkgPreSignerMetrics};
use crate::idkg::utils::{load_transcripts, transcript_op_summary, IDkgBlockReaderImpl};
use ic_consensus_utils::crypto::ConsensusCrypto;
use ic_consensus_utils::RoundRobin;
use ic_interfaces::consensus_pool::ConsensusBlockCache;
use ic_interfaces::crypto::{ErrorReproducibility, IDkgProtocol};
use ic_interfaces::idkg::{IDkgChangeAction, IDkgChangeSet, IDkgPool};
use ic_logger::{debug, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_types::artifact::IDkgMessageId;
use ic_types::consensus::idkg::{
    dealing_prefix, dealing_support_prefix, IDkgBlockReader, IDkgMessage, IDkgStats,
    IDkgTranscriptParamsRef,
};
use ic_types::crypto::canister_threshold_sig::error::IDkgCreateDealingError;
use ic_types::crypto::canister_threshold_sig::idkg::{
    BatchSignedIDkgDealing, BatchSignedIDkgDealings, IDkgDealingSupport, IDkgTranscript,
    IDkgTranscriptId, IDkgTranscriptOperation, IDkgTranscriptParams, SignedIDkgDealing,
};
use ic_types::crypto::CryptoHashOf;
use ic_types::signature::BasicSignatureBatch;
use ic_types::{Height, NodeId};
use std::cell::RefCell;
use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use super::utils::update_purge_height;

pub(crate) trait IDkgPreSigner: Send {
    /// The on_state_change() called from the main IDKG path.
    fn on_state_change(
        &self,
        idkg_pool: &dyn IDkgPool,
        transcript_loader: &dyn IDkgTranscriptLoader,
    ) -> IDkgChangeSet;
}

/// Pre-Signer subcomponent.
pub struct IDkgPreSignerImpl {
    pub(crate) node_id: NodeId,
    pub(crate) consensus_block_cache: Arc<dyn ConsensusBlockCache>,
    pub(crate) crypto: Arc<dyn ConsensusCrypto>,
    schedule: RoundRobin,
    pub(crate) metrics: IDkgPreSignerMetrics,
    pub(crate) log: ReplicaLogger,
    prev_finalized_height: RefCell<Height>,
}

impl IDkgPreSignerImpl {
    pub(crate) fn new(
        node_id: NodeId,
        consensus_block_cache: Arc<dyn ConsensusBlockCache>,
        crypto: Arc<dyn ConsensusCrypto>,
        metrics_registry: MetricsRegistry,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            node_id,
            consensus_block_cache,
            crypto,
            schedule: RoundRobin::default(),
            metrics: IDkgPreSignerMetrics::new(metrics_registry),
            log,
            prev_finalized_height: RefCell::new(Height::from(0)),
        }
    }

    /// Starts the transcript generation sequence by issuing the
    /// dealing for the transcript. The requests for new transcripts
    /// come from the latest finalized block.
    fn send_dealings(
        &self,
        idkg_pool: &dyn IDkgPool,
        transcript_loader: &dyn IDkgTranscriptLoader,
        block_reader: &dyn IDkgBlockReader,
    ) -> IDkgChangeSet {
        let mut target_subnet_xnet_transcripts = BTreeSet::new();
        for transcript_params_ref in block_reader.target_subnet_xnet_transcripts() {
            target_subnet_xnet_transcripts.insert(transcript_params_ref.transcript_id);
        }

        block_reader
            .requested_transcripts()
            .filter_map(|transcript_params_ref| {
                let mut ret = None;
                if let Some(transcript_params) =
                    self.resolve_ref(transcript_params_ref, block_reader, "send_dealings")
                {
                    // Issue a dealing if we are in the dealer list and we haven't
                    //already issued a dealing for this transcript
                    if transcript_params.dealers().contains(self.node_id)
                        && !self.has_dealer_issued_dealing(
                            idkg_pool,
                            &transcript_params.transcript_id(),
                            &self.node_id,
                        )
                    {
                        ret = Some(transcript_params);
                    }
                }
                ret
            })
            .flat_map(|transcript_params| {
                if target_subnet_xnet_transcripts.contains(&transcript_params.transcript_id()) {
                    self.metrics
                        .pre_sign_errors_inc("create_dealing_for_xnet_transcript");
                    warn!(
                        self.log,
                        "Dealing creation: dealing for target xnet dealing: {:?}",
                        transcript_params,
                    );
                }

                self.crypto_create_dealing(idkg_pool, transcript_loader, &transcript_params)
            })
            .collect()
    }

    /// Processes the dealings received from peer dealers
    fn validate_dealings(
        &self,
        idkg_pool: &dyn IDkgPool,
        block_reader: &dyn IDkgBlockReader,
    ) -> IDkgChangeSet {
        // TranscriptId -> TranscriptParamsRef
        let transcript_param_map = self.requested_transcripts(block_reader);

        let mut target_subnet_xnet_transcripts = BTreeSet::new();
        for transcript_params_ref in block_reader.target_subnet_xnet_transcripts() {
            target_subnet_xnet_transcripts.insert(transcript_params_ref.transcript_id);
        }

        let mut validated_dealings = BTreeSet::new();
        let mut ret = Vec::new();
        for (id, signed_dealing) in idkg_pool.unvalidated().signed_dealings() {
            let dealing = signed_dealing.idkg_dealing();
            // We already accepted a dealing for the same <transcript_id, dealer_id>
            // in the current batch, drop the subsequent ones. This scheme does create a
            // risk when we get several invalid dealings for the same <transcript_id, dealer_id>
            // before we see a good one. In this case, we would spend several cycles
            // to just check/discard the invalid ones.
            let key = (dealing.transcript_id, signed_dealing.dealer_id());
            if validated_dealings.contains(&key) {
                self.metrics
                    .pre_sign_errors_inc("duplicate_dealing_in_batch");
                ret.push(IDkgChangeAction::HandleInvalid(
                    id,
                    format!("Duplicate dealing in unvalidated batch: {}", signed_dealing),
                ));
                continue;
            }

            // Disable the height check on target subnet side for the initial transcripts.
            // Since the transcript_id.source_height is from the source subnet, the height
            // cannot be relied upon. This also lets us process the shares for the initial
            // bootstrap with higher urgency, without deferring it.
            let msg_height = if target_subnet_xnet_transcripts.contains(&dealing.transcript_id) {
                None
            } else {
                Some(dealing.transcript_id.source_height())
            };

            match Action::action(
                block_reader,
                &transcript_param_map,
                msg_height,
                &dealing.transcript_id,
            ) {
                Action::Process(transcript_params_ref) => {
                    let transcript_params = match self.resolve_ref(
                        transcript_params_ref,
                        block_reader,
                        "validate_dealings",
                    ) {
                        Some(transcript_params) => transcript_params,
                        None => {
                            ret.push(IDkgChangeAction::HandleInvalid(
                                id,
                                format!(
                                    "validate_dealings(): failed to translate transcript_params_ref: {}",
                                    signed_dealing
                                ),
                            ));
                            continue;
                        }
                    };

                    if !transcript_params
                        .dealers()
                        .contains(signed_dealing.dealer_id())
                    {
                        // The node is not in the dealer list for this transcript
                        self.metrics.pre_sign_errors_inc("unexpected_dealing");
                        ret.push(IDkgChangeAction::HandleInvalid(
                            id,
                            format!("Dealing from unexpected node: {}", signed_dealing),
                        ))
                    } else if self.has_dealer_issued_dealing(
                        idkg_pool,
                        &dealing.transcript_id,
                        &signed_dealing.dealer_id(),
                    ) {
                        // The node already sent a valid dealing for this transcript
                        self.metrics.pre_sign_errors_inc("duplicate_dealing");
                        ret.push(IDkgChangeAction::HandleInvalid(
                            id,
                            format!("Duplicate dealing: {}", signed_dealing),
                        ))
                    } else {
                        let action =
                            self.crypto_verify_dealing(id, &transcript_params, signed_dealing);
                        if let Some(IDkgChangeAction::MoveToValidated(_)) = action {
                            validated_dealings.insert(key);
                        }
                        ret.append(&mut action.into_iter().collect());
                    }
                }
                Action::Drop => ret.push(IDkgChangeAction::RemoveUnvalidated(id)),
                Action::Defer => {}
            }
        }
        ret
    }

    /// Does "private" validation of the dealings received from peer dealers and,
    /// if successful, sends out the signature share (support message) for it.
    fn send_dealing_support(
        &self,
        idkg_pool: &dyn IDkgPool,
        block_reader: &dyn IDkgBlockReader,
    ) -> IDkgChangeSet {
        // TranscriptId -> TranscriptParamsRef
        let transcript_param_map = self.requested_transcripts(block_reader);

        let mut source_subnet_xnet_transcripts = BTreeSet::new();
        for transcript_params_ref in block_reader.source_subnet_xnet_transcripts() {
            source_subnet_xnet_transcripts.insert(transcript_params_ref.transcript_id);
        }

        idkg_pool
            .validated()
            .signed_dealings()
            .filter(|(id, signed_dealing)| {
                id.dealing_hash().map_or_else(
                    || {
                        self.metrics
                            .pre_sign_errors_inc("create_support_id_dealing_hash");
                        warn!(
                            self.log,
                            "send_dealing_support(): Failed to get dealing hash: {:?}", id
                        );
                        false
                    },
                    |dealing_hash| {
                        !self.has_node_issued_dealing_support(
                            idkg_pool,
                            &signed_dealing.idkg_dealing().transcript_id,
                            &signed_dealing.dealer_id(),
                            &self.node_id,
                            &dealing_hash,
                        )
                    },
                )
            })
            .filter_map(|(id, signed_dealing)| {
                let dealing = signed_dealing.idkg_dealing();
                // Look up the transcript params for the dealing, and check if we
                // are a receiver for this dealing
                if let Some(transcript_params_ref) =
                    transcript_param_map.get(&dealing.transcript_id)
                {
                    self.resolve_ref(transcript_params_ref, block_reader, "send_dealing_support")
                        .and_then(|transcript_params| {
                            transcript_params
                                .receiver_index(self.node_id)
                                .map(|_| (id, transcript_params, signed_dealing))
                        })
                } else {
                    self.metrics
                        .pre_sign_errors_inc("create_support_missing_transcript_params");
                    warn!(
                        self.log,
                        "Dealing support creation: transcript_param not found: {}", signed_dealing,
                    );
                    None
                }
            })
            .flat_map(|(id, transcript_params, signed_dealing)| {
                let dealing = signed_dealing.idkg_dealing();
                if source_subnet_xnet_transcripts.contains(&dealing.transcript_id) {
                    self.metrics
                        .pre_sign_errors_inc("create_support_for_xnet_transcript");
                    warn!(
                        self.log,
                        "Dealing support creation: support for target xnet dealing: {}",
                        signed_dealing,
                    );
                }
                self.crypto_create_dealing_support(&id, &transcript_params, &signed_dealing)
            })
            .collect()
    }

    /// Processes the received dealing support messages
    fn validate_dealing_support(
        &self,
        idkg_pool: &dyn IDkgPool,
        block_reader: &dyn IDkgBlockReader,
    ) -> IDkgChangeSet {
        // TranscriptId -> TranscriptParamsRef
        let transcript_param_map = self.requested_transcripts(block_reader);

        // Build the map of valid dealings crypto hash -> dealings
        let mut valid_dealings = BTreeMap::new();
        for (id, signed_dealing) in idkg_pool.validated().signed_dealings() {
            if let Some(dealing_hash) = id.dealing_hash() {
                valid_dealings.insert(dealing_hash, signed_dealing);
            } else {
                self.metrics
                    .pre_sign_errors_inc("validate_dealing_support_id_dealing_hash");
                warn!(
                    self.log,
                    "validate_dealing_support(): Failed to get dealing hash: {:?}", id
                )
            }
        }

        let mut source_subnet_xnet_transcripts = BTreeSet::new();
        for transcript_params_ref in block_reader.source_subnet_xnet_transcripts() {
            source_subnet_xnet_transcripts.insert(transcript_params_ref.transcript_id);
        }

        let mut target_subnet_xnet_transcripts = BTreeSet::new();
        for transcript_params_ref in block_reader.target_subnet_xnet_transcripts() {
            target_subnet_xnet_transcripts.insert(transcript_params_ref.transcript_id);
        }

        let mut validated_dealing_supports = BTreeSet::new();
        let mut ret = Vec::new();
        for (id, support) in idkg_pool.unvalidated().dealing_support() {
            // Dedup dealing support by (transcript_id, dealer_id, signer_id)
            // Also see has_node_issued_dealing_support().
            let key = (
                support.transcript_id,
                support.dealer_id,
                support.sig_share.signer,
            );
            if validated_dealing_supports.contains(&key) {
                ret.push(IDkgChangeAction::HandleInvalid(
                    id,
                    format!(
                        "Duplicate dealing support in unvalidated batch: {}",
                        support
                    ),
                ));
                continue;
            };
            // Drop shares for xnet reshare transcripts
            if source_subnet_xnet_transcripts.contains(&support.transcript_id) {
                self.metrics.pre_sign_errors_inc("xnet_reshare_support");
                ret.push(IDkgChangeAction::HandleInvalid(
                    id,
                    format!("Support for xnet reshare transcript: {}", support),
                ));
                continue;
            }

            // Disable the height check on target subnet side for the initial transcripts.
            // Since the transcript_id.source_height is from the source subnet, the height
            // cannot be relied upon. This also lets us process the shares for the initial
            // bootstrap with higher urgency, without deferring it.
            let msg_height = if target_subnet_xnet_transcripts.contains(&support.transcript_id) {
                None
            } else {
                Some(support.transcript_id.source_height())
            };

            match Action::action(
                block_reader,
                &transcript_param_map,
                msg_height,
                &support.transcript_id,
            ) {
                Action::Process(transcript_params_ref) => {
                    let transcript_params = match self.resolve_ref(
                        transcript_params_ref,
                        block_reader,
                        "validate_dealing_support",
                    ) {
                        Some(transcript_params) => transcript_params,
                        None => {
                            ret.push(IDkgChangeAction::HandleInvalid(
                                id,
                                format!("Failed to translate transcript_params_ref: {}", support),
                            ));
                            continue;
                        }
                    };

                    if !transcript_params
                        .receivers()
                        .contains(support.sig_share.signer)
                    {
                        // The node is not in the receiver list for this transcript,
                        // support share is not expected from it
                        self.metrics.pre_sign_errors_inc("unexpected_support");
                        ret.push(IDkgChangeAction::HandleInvalid(
                            id,
                            format!("Support from unexpected node: {}", support),
                        ))
                    } else if let Some(signed_dealing) = valid_dealings.get(&support.dealing_hash) {
                        let dealing = signed_dealing.idkg_dealing();
                        if self.has_node_issued_dealing_support(
                            idkg_pool,
                            &signed_dealing.idkg_dealing().transcript_id,
                            &signed_dealing.dealer_id(),
                            &support.sig_share.signer,
                            &support.dealing_hash,
                        ) {
                            // The node already sent a valid support for this dealing
                            self.metrics.pre_sign_errors_inc("duplicate_support");
                            ret.push(IDkgChangeAction::HandleInvalid(
                                id,
                                format!("Duplicate support: {}", support),
                            ))
                        } else if support.transcript_id != dealing.transcript_id
                            || support.dealer_id != signed_dealing.dealer_id()
                        {
                            // Meta data mismatch
                            self.metrics
                                .pre_sign_errors_inc("support_meta_data_mismatch");
                            ret.push(IDkgChangeAction::HandleInvalid(
                                id,
                                format!(
                                    "Support meta data mismatch: expected = {:?}/{:?}, \
                                         received = {:?}/{:?}",
                                    support.transcript_id,
                                    support.dealer_id,
                                    dealing.transcript_id,
                                    signed_dealing.dealer_id()
                                ),
                            ))
                        } else {
                            let action = self.crypto_verify_dealing_support(
                                id,
                                &transcript_params,
                                signed_dealing,
                                support,
                                idkg_pool.stats(),
                            );
                            if let Some(IDkgChangeAction::MoveToValidated(_)) = action {
                                validated_dealing_supports.insert(key);
                            }
                            ret.append(&mut action.into_iter().collect());
                        }
                    } else {
                        // If the dealer_id in the share is invalid, drop it.
                        if !transcript_params.dealers().contains(support.dealer_id) {
                            self.metrics
                                .pre_sign_errors_inc("missing_hash_invalid_dealer");
                            ret.push(IDkgChangeAction::RemoveUnvalidated(id));
                            warn!(
                                self.log,
                                "validate_dealing_support(): Missing hash, invalid dealer: {:?}",
                                support
                            );
                        } else {
                            // If the share points to a different dealing hash than what we
                            // have for the same <transcript Id, dealer Id>, drop it. This is
                            // different from the case where we don't have the dealing yet
                            let mut dealing_hash_mismatch = false;
                            for signed_dealing in valid_dealings.values() {
                                if support.transcript_id
                                    == signed_dealing.idkg_dealing().transcript_id
                                    && support.dealer_id == signed_dealing.dealer_id()
                                {
                                    dealing_hash_mismatch = true;
                                    break;
                                }
                            }
                            if dealing_hash_mismatch {
                                self.metrics
                                    .pre_sign_errors_inc("missing_hash_meta_data_mismatch");
                                ret.push(IDkgChangeAction::RemoveUnvalidated(id));
                                warn!(
                                self.log,
                                "validate_dealing_support(): Missing hash, meta data mismatch: {:?}",
                                support
                            );
                            }
                            // Else: Support for a dealing we don't have yet, defer it
                        }
                    }
                }
                Action::Drop => ret.push(IDkgChangeAction::RemoveUnvalidated(id)),
                Action::Defer => {}
            }
        }

        ret
    }

    /// Purges the entries no longer needed from the artifact pool
    fn purge_artifacts(
        &self,
        idkg_pool: &dyn IDkgPool,
        block_reader: &dyn IDkgBlockReader,
    ) -> IDkgChangeSet {
        let in_progress = block_reader
            .requested_transcripts()
            .map(|transcript_params| transcript_params.transcript_id)
            .collect::<BTreeSet<_>>();

        let mut ret = Vec::new();
        let current_height = block_reader.tip_height();
        let mut target_subnet_xnet_transcripts = BTreeSet::new();
        for transcript_params_ref in block_reader.target_subnet_xnet_transcripts() {
            target_subnet_xnet_transcripts.insert(transcript_params_ref.transcript_id);
        }

        // Unvalidated dealings.
        let mut action = idkg_pool
            .unvalidated()
            .signed_dealings()
            .filter(|(_, signed_dealing)| {
                self.should_purge(
                    &signed_dealing.idkg_dealing().transcript_id,
                    current_height,
                    &in_progress,
                    &target_subnet_xnet_transcripts,
                )
            })
            .map(|(id, _)| IDkgChangeAction::RemoveUnvalidated(id))
            .collect();
        ret.append(&mut action);

        // Validated dealings.
        let mut action = idkg_pool
            .validated()
            .signed_dealings()
            .filter(|(_, signed_dealing)| {
                self.should_purge(
                    &signed_dealing.idkg_dealing().transcript_id,
                    current_height,
                    &in_progress,
                    &target_subnet_xnet_transcripts,
                )
            })
            .map(|(id, _)| IDkgChangeAction::RemoveValidated(id))
            .collect();
        ret.append(&mut action);

        // Unvalidated dealing support.
        let mut action = idkg_pool
            .unvalidated()
            .dealing_support()
            .filter(|(_, support)| {
                self.should_purge(
                    &support.transcript_id,
                    current_height,
                    &in_progress,
                    &target_subnet_xnet_transcripts,
                )
            })
            .map(|(id, _)| IDkgChangeAction::RemoveUnvalidated(id))
            .collect();
        ret.append(&mut action);

        // Validated dealing support.
        let mut action = idkg_pool
            .validated()
            .dealing_support()
            .filter(|(_, support)| {
                self.should_purge(
                    &support.transcript_id,
                    current_height,
                    &in_progress,
                    &target_subnet_xnet_transcripts,
                )
            })
            .map(|(id, _)| IDkgChangeAction::RemoveValidated(id))
            .collect();
        ret.append(&mut action);

        ret
    }

    /// Helper to create dealing
    fn crypto_create_dealing(
        &self,
        idkg_pool: &dyn IDkgPool,
        transcript_loader: &dyn IDkgTranscriptLoader,
        transcript_params: &IDkgTranscriptParams,
    ) -> IDkgChangeSet {
        if let Some(changes) =
            self.load_dependencies(idkg_pool, transcript_loader, transcript_params)
        {
            return changes;
        }
        match IDkgProtocol::create_dealing(&*self.crypto, transcript_params) {
            Ok(idkg_dealing) => {
                self.metrics.pre_sign_metrics_inc("dealing_created");
                self.metrics.pre_sign_metrics_inc("dealing_sent");
                vec![IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(
                    idkg_dealing,
                ))]
            }
            Err(IDkgCreateDealingError::SignatureError { internal_error }) => {
                warn!(
                    self.log,
                    "Failed to sign dealing: transcript_id = {:?}, type = {:?}, error = {:?}",
                    transcript_params.transcript_id(),
                    transcript_op_summary(transcript_params.operation_type()),
                    internal_error
                );
                self.metrics.pre_sign_errors_inc("sign_dealing");
                Default::default()
            }
            Err(err) => {
                // TODO: currently, transcript creation will be retried the next time, which
                // will most likely fail again. This should be signaled up so that the bad
                // transcript params can be acted on
                warn!(
                    self.log,
                    "Failed to create dealing: transcript_id = {:?}, type = {:?}, error = {:?}",
                    transcript_params.transcript_id(),
                    transcript_op_summary(transcript_params.operation_type()),
                    err
                );
                self.metrics.pre_sign_errors_inc("create_dealing");
                Default::default()
            }
        }
    }

    /// Helper to do public verification of a dealing received for a transcript we are building
    fn crypto_verify_dealing(
        &self,
        id: IDkgMessageId,
        transcript_params: &IDkgTranscriptParams,
        signed_dealing: SignedIDkgDealing,
    ) -> Option<IDkgChangeAction> {
        match IDkgProtocol::verify_dealing_public(&*self.crypto, transcript_params, &signed_dealing)
        {
            Err(error) if error.is_reproducible() => {
                self.metrics.pre_sign_errors_inc("verify_dealing_permanent");
                Some(IDkgChangeAction::HandleInvalid(
                    id,
                    format!(
                        "Dealing validation(permanent error): {}, error = {:?}",
                        signed_dealing, error
                    ),
                ))
            }
            Err(error) => {
                // Defer in case of transient errors
                debug!(
                    self.log,
                    "Dealing validation(transient error): {}, error = {:?}", signed_dealing, error
                );
                self.metrics.pre_sign_errors_inc("verify_dealing_transient");
                None
            }
            Ok(()) => {
                self.metrics.pre_sign_metrics_inc("dealing_received");
                Some(IDkgChangeAction::MoveToValidated(IDkgMessage::Dealing(
                    signed_dealing,
                )))
            }
        }
    }

    /// Helper to do private verification of a dealing and, if successful, issue a support share for it.
    /// Assumes we are a receiver for the dealing.
    fn crypto_create_dealing_support(
        &self,
        id: &IDkgMessageId,
        transcript_params: &IDkgTranscriptParams,
        signed_dealing: &SignedIDkgDealing,
    ) -> IDkgChangeSet {
        let dealing = signed_dealing.idkg_dealing();
        if let Err(error) =
            IDkgProtocol::verify_dealing_private(&*self.crypto, transcript_params, signed_dealing)
        {
            if error.is_reproducible() {
                self.metrics
                    .pre_sign_errors_inc("verify_dealing_private_permanent");
                warn!(
                    self.log,
                    "Dealing private verification(permanent error): {}, error = {:?}",
                    dealing,
                    error
                );
                return vec![IDkgChangeAction::HandleInvalid(
                    id.clone(),
                    format!(
                        "Dealing private verification(permanent error): {}, error = {:?}",
                        dealing, error
                    ),
                )];
            } else {
                self.metrics
                    .pre_sign_errors_inc("verify_dealing_private_transient");
                debug!(
                    self.log,
                    "Dealing private verification(transient error): {}, error = {:?}",
                    dealing,
                    error
                );
                return Default::default();
            }
        }

        // Generate the multi sig share
        self.crypto
            .sign(
                signed_dealing,
                self.node_id,
                transcript_params.registry_version(),
            )
            .map_or_else(
                |error| {
                    debug!(
                        self.log,
                        "Dealing multi sign failed: {}, error = {:?}", dealing, error
                    );
                    self.metrics
                        .pre_sign_errors_inc("dealing_support_multi_sign");
                    Default::default()
                },
                |multi_sig_share| {
                    let dealing_support = IDkgDealingSupport {
                        transcript_id: dealing.transcript_id,
                        dealer_id: signed_dealing.dealer_id(),
                        dealing_hash: ic_types::crypto::crypto_hash(signed_dealing),
                        sig_share: multi_sig_share,
                    };
                    self.metrics.pre_sign_metrics_inc("dealing_support_sent");
                    vec![IDkgChangeAction::AddToValidated(
                        IDkgMessage::DealingSupport(dealing_support),
                    )]
                },
            )
    }

    /// Helper to verify a support share for a dealing
    fn crypto_verify_dealing_support(
        &self,
        id: IDkgMessageId,
        transcript_params: &IDkgTranscriptParams,
        signed_dealing: &SignedIDkgDealing,
        support: IDkgDealingSupport,
        stats: &dyn IDkgStats,
    ) -> Option<IDkgChangeAction> {
        let start = std::time::Instant::now();
        let ret = self.crypto.verify_basic_sig(
            &support.sig_share.signature,
            signed_dealing,
            support.sig_share.signer,
            transcript_params.registry_version(),
        );
        stats.record_support_validation(&support, start.elapsed());

        match ret {
            Err(error) => {
                self.metrics.pre_sign_errors_inc("verify_dealing_support");
                Some(IDkgChangeAction::HandleInvalid(
                    id,
                    format!(
                        "Support validation failed: {}, error = {:?}",
                        support, error
                    ),
                ))
            }
            Ok(_) => {
                self.metrics
                    .pre_sign_metrics_inc("dealing_support_received");
                Some(IDkgChangeAction::MoveToValidated(
                    IDkgMessage::DealingSupport(support),
                ))
            }
        }
    }

    /// Helper to load the transcripts the given transcript config is dependent on.
    ///
    /// Returns None if all the transcripts could be loaded successfully.
    /// Otherwise, returns the complaint change set to be added to the pool
    fn load_dependencies(
        &self,
        idkg_pool: &dyn IDkgPool,
        transcript_loader: &dyn IDkgTranscriptLoader,
        transcript_params: &IDkgTranscriptParams,
    ) -> Option<IDkgChangeSet> {
        match &transcript_params.operation_type() {
            IDkgTranscriptOperation::Random => None,
            IDkgTranscriptOperation::RandomUnmasked => None,
            IDkgTranscriptOperation::ReshareOfMasked(t) => {
                load_transcripts(idkg_pool, transcript_loader, &[t])
            }
            IDkgTranscriptOperation::ReshareOfUnmasked(t) => {
                load_transcripts(idkg_pool, transcript_loader, &[t])
            }
            IDkgTranscriptOperation::UnmaskedTimesMasked(t1, t2) => {
                load_transcripts(idkg_pool, transcript_loader, &[t1, t2])
            }
        }
    }

    /// Checks if we have a valid dealing from the dealer for the given
    /// transcript
    fn has_dealer_issued_dealing(
        &self,
        idkg_pool: &dyn IDkgPool,
        transcript_id: &IDkgTranscriptId,
        dealer_id: &NodeId,
    ) -> bool {
        let prefix = dealing_prefix(transcript_id, dealer_id);
        idkg_pool
            .validated()
            .signed_dealings_by_prefix(prefix)
            .any(|(_, signed_dealing)| {
                let dealing = signed_dealing.idkg_dealing();
                signed_dealing.dealer_id() == *dealer_id && dealing.transcript_id == *transcript_id
            })
    }

    /// Checks if we have a valid dealing support from the node for the
    /// given dealing
    fn has_node_issued_dealing_support(
        &self,
        idkg_pool: &dyn IDkgPool,
        transcript_id: &IDkgTranscriptId,
        dealer_id: &NodeId,
        signer_id: &NodeId,
        dealing_hash: &CryptoHashOf<SignedIDkgDealing>,
    ) -> bool {
        let prefix = dealing_support_prefix(transcript_id, dealer_id, signer_id);
        idkg_pool
            .validated()
            .dealing_support_by_prefix(prefix)
            .any(|(_, support)| {
                support.dealing_hash == *dealing_hash
                    && support.sig_share.signer == *signer_id
                    && support.transcript_id == *transcript_id
            })
    }

    /// Checks if the dealing should be purged
    fn should_purge(
        &self,
        transcript_id: &IDkgTranscriptId,
        current_height: Height,
        in_progress: &BTreeSet<IDkgTranscriptId>,
        target_subnet_xnet_transcripts: &BTreeSet<IDkgTranscriptId>,
    ) -> bool {
        // It is possible the IDKG component runs and tries to purge the initial
        // dealings before the finalized tip has the next_key_transcript_creation
        // set up. Avoid this by keeping the initial dealings until the initial
        // resharing completes.
        if target_subnet_xnet_transcripts.contains(transcript_id) {
            return false;
        }

        transcript_id.source_height() <= current_height && !in_progress.contains(transcript_id)
    }

    /// Resolves the IDkgTranscriptParamsRef -> IDkgTranscriptParams.
    pub(crate) fn resolve_ref(
        &self,
        transcript_params_ref: &IDkgTranscriptParamsRef,
        block_reader: &dyn IDkgBlockReader,
        reason: &str,
    ) -> Option<IDkgTranscriptParams> {
        match transcript_params_ref.translate(block_reader) {
            Ok(transcript_params) => {
                self.metrics.pre_sign_metrics_inc("resolve_transcript_refs");
                Some(transcript_params)
            }
            Err(error) => {
                warn!(
                    self.log,
                    "Failed to translate transcript ref: reason = {}, \
                     transcript_params_ref = {:?}, tip = {:?}, error = {:?}",
                    reason,
                    transcript_params_ref,
                    block_reader.tip_height(),
                    error
                );
                self.metrics.pre_sign_errors_inc("resolve_transcript_refs");
                None
            }
        }
    }

    /// Returns the requested transcript map.
    fn requested_transcripts<'a>(
        &self,
        block_reader: &'a dyn IDkgBlockReader,
    ) -> BTreeMap<IDkgTranscriptId, &'a IDkgTranscriptParamsRef> {
        block_reader
            .requested_transcripts()
            .map(|transcript_params| (transcript_params.transcript_id, transcript_params))
            .collect::<BTreeMap<_, _>>()
    }
}

impl IDkgPreSigner for IDkgPreSignerImpl {
    fn on_state_change(
        &self,
        idkg_pool: &dyn IDkgPool,
        transcript_loader: &dyn IDkgTranscriptLoader,
    ) -> IDkgChangeSet {
        let block_reader = IDkgBlockReaderImpl::new(self.consensus_block_cache.finalized_chain());
        let metrics = self.metrics.clone();
        idkg_pool.stats().update_active_transcripts(&block_reader);
        idkg_pool
            .stats()
            .update_active_pre_signatures(&block_reader);

        let mut changes =
            update_purge_height(&self.prev_finalized_height, block_reader.tip_height())
                .then(|| {
                    timed_call(
                        "purge_artifacts",
                        || self.purge_artifacts(idkg_pool, &block_reader),
                        &metrics.on_state_change_duration,
                    )
                })
                .unwrap_or_default();

        let send_dealings = || {
            timed_call(
                "send_dealings",
                || self.send_dealings(idkg_pool, transcript_loader, &block_reader),
                &metrics.on_state_change_duration,
            )
        };
        let validate_dealings = || {
            timed_call(
                "validate_dealings",
                || self.validate_dealings(idkg_pool, &block_reader),
                &metrics.on_state_change_duration,
            )
        };
        let send_dealing_support = || {
            timed_call(
                "send_dealing_support",
                || self.send_dealing_support(idkg_pool, &block_reader),
                &metrics.on_state_change_duration,
            )
        };
        let validate_dealing_support = || {
            timed_call(
                "validate_dealing_support",
                || self.validate_dealing_support(idkg_pool, &block_reader),
                &metrics.on_state_change_duration,
            )
        };

        let calls: [&'_ dyn Fn() -> IDkgChangeSet; 4] = [
            &send_dealings,
            &validate_dealings,
            &send_dealing_support,
            &validate_dealing_support,
        ];

        changes.append(&mut self.schedule.call_next(&calls));
        changes
    }
}

pub(crate) trait IDkgTranscriptBuilder {
    /// Returns the specified transcript if it can be successfully
    /// built from the current entries in the IDKG pool
    fn get_completed_transcript(&self, transcript_id: IDkgTranscriptId) -> Option<IDkgTranscript>;

    /// Returns the validated dealings for the given transcript Id from
    /// the IDKG pool
    fn get_validated_dealings(&self, transcript_id: IDkgTranscriptId) -> Vec<SignedIDkgDealing>;
}

pub(crate) struct IDkgTranscriptBuilderImpl<'a> {
    block_reader: &'a dyn IDkgBlockReader,
    crypto: &'a dyn ConsensusCrypto,
    metrics: &'a IDkgPayloadMetrics,
    idkg_pool: &'a dyn IDkgPool,
    cache: RefCell<BTreeMap<IDkgTranscriptId, IDkgTranscript>>,
    log: ReplicaLogger,
}

impl<'a> IDkgTranscriptBuilderImpl<'a> {
    pub(crate) fn new(
        block_reader: &'a dyn IDkgBlockReader,
        crypto: &'a dyn ConsensusCrypto,
        idkg_pool: &'a dyn IDkgPool,
        metrics: &'a IDkgPayloadMetrics,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            block_reader,
            crypto,
            idkg_pool,
            cache: RefCell::new(BTreeMap::new()),
            metrics,
            log,
        }
    }

    /// Build the specified transcript from the pool.
    fn build_transcript(&self, transcript_id: IDkgTranscriptId) -> Option<IDkgTranscript> {
        // Look up the transcript params
        let transcript_params = match self
            .block_reader
            .requested_transcripts()
            .find(|transcript_params| transcript_params.transcript_id == transcript_id)
        {
            Some(params_ref) => match params_ref.translate(self.block_reader) {
                Ok(transcript_params) => transcript_params,
                Err(error) => {
                    warn!(
                        self.log,
                        "build_transcript(): failed to translate transcript ref: \
                                transcript_params_ref = {:?}, tip = {:?}, error = {:?}",
                        params_ref,
                        self.block_reader.tip_height(),
                        error
                    );
                    self.metrics
                        .transcript_builder_errors_inc("resolve_transcript_refs");
                    return None;
                }
            },
            None => {
                self.metrics
                    .transcript_builder_errors_inc("missing_transcript_params");
                return None;
            }
        };
        let mut completed_dealings = BatchSignedIDkgDealings::new();

        // Step 1: Build the verified dealings by aggregating the support shares
        timed_call(
            "aggregate_dealing_support",
            || {
                let mut transcript_state = TranscriptState::new();
                // Walk the dealings to get the dealings belonging to the transcript
                for (id, signed_dealing) in self.idkg_pool.validated().signed_dealings() {
                    if signed_dealing.idkg_dealing().transcript_id == transcript_id {
                        if let Some(dealing_hash) = id.dealing_hash() {
                            transcript_state.init_dealing_state(dealing_hash, signed_dealing);
                        } else {
                            self.metrics
                                .transcript_builder_errors_inc("build_transcript_id_dealing_hash");
                            warn!(
                                self.log,
                                "build_transcript(): Failed to get dealing hash: {:?}", id
                            );
                        }
                    }
                }

                // Walk the support shares and assign to the corresponding dealing
                for (_, support) in self.idkg_pool.validated().dealing_support() {
                    if support.transcript_id == transcript_id {
                        if let Err(err) = transcript_state.add_dealing_support(support) {
                            warn!(
                                self.log,
                                "Failed to add support: transcript_id = {:?}, error = {:?}",
                                transcript_id,
                                err
                            );
                            self.metrics
                                .transcript_builder_errors_inc("add_dealing_support");
                        }
                    }
                }

                // Aggregate the support shares per dealing
                for dealing_state in transcript_state.dealing_state.into_values() {
                    if let Some(sig_batch) = self.crypto_aggregate_dealing_support(
                        &transcript_params,
                        &dealing_state.support_shares,
                    ) {
                        let verified_dealing = BatchSignedIDkgDealing {
                            content: dealing_state.signed_dealing,
                            signature: sig_batch,
                        };
                        completed_dealings.insert_or_update(verified_dealing);
                    }
                }
            },
            &self.metrics.transcript_builder_duration,
        );

        // Step 2: Build the transcript from the verified dealings
        timed_call(
            "create_transcript",
            || self.crypto_create_transcript(&transcript_params, &completed_dealings),
            &self.metrics.transcript_builder_duration,
        )
    }

    /// Helper to combine the multi sig shares for a dealing
    fn crypto_aggregate_dealing_support(
        &self,
        transcript_params: &IDkgTranscriptParams,
        support_shares: &[IDkgDealingSupport],
    ) -> Option<BasicSignatureBatch<SignedIDkgDealing>> {
        // Check if we have enough shares for aggregation
        if support_shares.len() < (transcript_params.verification_threshold().get() as usize) {
            self.metrics
                .transcript_builder_metrics_inc("insufficient_support_shares");
            return None;
        }

        let mut signatures = Vec::new();
        for support_share in support_shares {
            signatures.push(&support_share.sig_share);
        }

        let start = std::time::Instant::now();
        let ret = self
            .crypto
            .aggregate(signatures, transcript_params.registry_version());
        self.idkg_pool.stats().record_support_aggregation(
            transcript_params,
            support_shares,
            start.elapsed(),
        );

        ret.map_or_else(
            |error| {
                warn!(
                    self.log,
                    "Failed to aggregate: transcript_id = {:?}, error = {:?}",
                    transcript_params.transcript_id(),
                    error
                );
                self.metrics
                    .transcript_builder_errors_inc("aggregate_dealing_support");
                None
            },
            |multi_sig| {
                self.metrics.transcript_builder_metrics_inc_by(
                    support_shares.len() as u64,
                    "support_aggregated",
                );
                self.metrics
                    .transcript_builder_metrics_inc("dealing_aggregated");
                Some(multi_sig)
            },
        )
    }

    /// Helper to create the transcript from the verified dealings
    fn crypto_create_transcript(
        &self,
        transcript_params: &IDkgTranscriptParams,
        verified_dealings: &BatchSignedIDkgDealings,
    ) -> Option<IDkgTranscript> {
        // Check if we have enough dealings to create transcript
        if verified_dealings.len() < (transcript_params.collection_threshold().get() as usize) {
            self.metrics
                .transcript_builder_metrics_inc("insufficient_dealings");
            return None;
        }

        let start = std::time::Instant::now();
        let ret =
            IDkgProtocol::create_transcript(self.crypto, transcript_params, verified_dealings);
        self.idkg_pool
            .stats()
            .record_transcript_creation(transcript_params, start.elapsed());

        ret.map_or_else(
            |error| {
                warn!(
                    self.log,
                    "Failed to create transcript: transcript_id = {:?}, error = {:?}",
                    transcript_params.transcript_id(),
                    error
                );
                self.metrics
                    .transcript_builder_errors_inc("create_transcript");
                None
            },
            |transcript| {
                self.metrics
                    .transcript_builder_metrics_inc("transcript_created");
                Some(transcript)
            },
        )
    }

    /// Helper to get the validated dealings.
    fn validated_dealings(&self, transcript_id: IDkgTranscriptId) -> Vec<SignedIDkgDealing> {
        let mut ret = Vec::new();
        for (_, signed_dealing) in self.idkg_pool.validated().signed_dealings() {
            let dealing = signed_dealing.idkg_dealing();
            if dealing.transcript_id == transcript_id {
                ret.push(signed_dealing.clone());
            }
        }
        ret
    }
}

impl<'a> IDkgTranscriptBuilder for IDkgTranscriptBuilderImpl<'a> {
    fn get_completed_transcript(&self, transcript_id: IDkgTranscriptId) -> Option<IDkgTranscript> {
        timed_call(
            "get_completed_transcript",
            || match self.cache.borrow_mut().entry(transcript_id) {
                Entry::Vacant(e) => self
                    .build_transcript(transcript_id)
                    .map(|transcript| e.insert(transcript).clone()),
                Entry::Occupied(e) => Some(e.get().clone()),
            },
            &self.metrics.transcript_builder_duration,
        )
    }

    fn get_validated_dealings(&self, transcript_id: IDkgTranscriptId) -> Vec<SignedIDkgDealing> {
        timed_call(
            "get_validated_dealings",
            || self.validated_dealings(transcript_id),
            &self.metrics.transcript_builder_duration,
        )
    }
}

/// Specifies how to handle a received message
#[derive(Eq, PartialEq)]
enum Action<'a> {
    /// The message is relevant to our current state, process it
    /// immediately. The transcript params for this transcript
    /// (as specified by the finalized block) is the argument
    Process(&'a IDkgTranscriptParamsRef),

    /// Keep it to be processed later (e.g) this is from a node
    /// ahead of us
    Defer,

    /// Don't need it
    Drop,
}

impl<'a> Action<'a> {
    /// Decides the action to take on a received message with the given
    /// height/transcriptId
    #[allow(clippy::self_named_constructors)]
    fn action(
        block_reader: &'a dyn IDkgBlockReader,
        requested_transcripts: &'a BTreeMap<IDkgTranscriptId, &'a IDkgTranscriptParamsRef>,
        msg_height: Option<Height>,
        msg_transcript_id: &IDkgTranscriptId,
    ) -> Action<'a> {
        if let Some(height) = msg_height {
            if height > block_reader.tip_height() {
                // Message is from a node ahead of us, keep it to be
                // processed later
                return Action::Defer;
            }
        }

        match requested_transcripts.get(msg_transcript_id) {
            Some(transcript_params_ref) => Action::Process(transcript_params_ref),
            None => {
                // Its for a transcript that has not been requested, drop it
                Action::Drop
            }
        }
    }
}

/// Needed as IDKGTranscriptParams doesn't implement Debug
impl<'a> Debug for Action<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self {
            Self::Process(transcript_params) => {
                write!(
                    f,
                    "Action::Process(): transcript_id = {:?}",
                    transcript_params.transcript_id
                )
            }
            Self::Defer => write!(f, "Action::Defer"),
            Self::Drop => write!(f, "Action::Drop"),
        }
    }
}

/// Helper to hold the transcript/dealing state during the transcript
/// building process
struct TranscriptState {
    dealing_state: BTreeMap<CryptoHashOf<SignedIDkgDealing>, DealingState>,
}

struct DealingState {
    signed_dealing: SignedIDkgDealing,
    support_shares: Vec<IDkgDealingSupport>,
}

impl TranscriptState {
    fn new() -> Self {
        Self {
            dealing_state: BTreeMap::new(),
        }
    }

    // Initializes the per-dealing info
    fn init_dealing_state(
        &mut self,
        dealing_hash: CryptoHashOf<SignedIDkgDealing>,
        signed_dealing: SignedIDkgDealing,
    ) {
        self.dealing_state.insert(
            dealing_hash,
            DealingState {
                signed_dealing,
                support_shares: Vec::new(),
            },
        );
    }

    // Adds support for a dealing
    fn add_dealing_support(&mut self, support: IDkgDealingSupport) -> Result<(), String> {
        if let Some(dealing_state) = self.dealing_state.get_mut(&support.dealing_hash) {
            dealing_state.support_shares.push(support);
            Ok(())
        } else {
            Err(format!(
                "TranscriptState::add_dealing_support(): dealing not found: {:}",
                support
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::idkg::test_utils::*;
    use crate::idkg::utils::algorithm_for_key_id;
    use assert_matches::assert_matches;
    use ic_crypto_test_utils_canister_threshold_sigs::{
        setup_masked_random_params, CanisterThresholdSigTestEnvironment, IDkgParticipants,
    };
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_interfaces::p2p::consensus::{MutablePool, UnvalidatedArtifact};
    use ic_management_canister_types::MasterPublicKeyId;
    use ic_test_utilities_consensus::IDkgStatsNoOp;
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_types::ids::{NODE_1, NODE_2, NODE_3, NODE_4};
    use ic_types::consensus::idkg::IDkgObject;
    use ic_types::crypto::{BasicSig, BasicSigOf, CryptoHash};
    use ic_types::time::UNIX_EPOCH;
    use ic_types::{Height, RegistryVersion};
    use std::collections::HashSet;
    use std::ops::Deref;

    // Tests the Action logic
    #[test]
    fn test_ecdsa_pre_signer_action() {
        let key_id = fake_ecdsa_master_public_key_id();
        let (id_1, id_2, id_3, id_4) = (
            create_transcript_id(1),
            create_transcript_id(2),
            create_transcript_id(3),
            create_transcript_id(4),
        );

        // The finalized block requests transcripts 1, 2, 3
        let nodes = [NODE_1];
        let block_reader = TestIDkgBlockReader::for_pre_signer_test(
            Height::from(100),
            vec![
                create_transcript_param(&key_id, id_1, &nodes, &nodes),
                create_transcript_param(&key_id, id_2, &nodes, &nodes),
                create_transcript_param(&key_id, id_3, &nodes, &nodes),
            ],
        );
        let mut requested = BTreeMap::new();
        for transcript_params_ref in block_reader.requested_transcripts() {
            requested.insert(transcript_params_ref.transcript_id, transcript_params_ref);
        }

        // Message from a node ahead of us
        assert_eq!(
            Action::action(&block_reader, &requested, Some(Height::from(200)), &id_4),
            Action::Defer
        );

        // Messages for transcripts not being currently requested
        assert_eq!(
            Action::action(
                &block_reader,
                &requested,
                Some(Height::from(100)),
                &create_transcript_id(234)
            ),
            Action::Drop
        );
        assert_eq!(
            Action::action(
                &block_reader,
                &requested,
                Some(Height::from(10)),
                &create_transcript_id(234)
            ),
            Action::Drop
        );

        // Messages for transcripts currently requested
        let action = Action::action(&block_reader, &requested, Some(Height::from(100)), &id_1);
        assert_matches!(action, Action::Process(_));

        let action = Action::action(&block_reader, &requested, Some(Height::from(10)), &id_2);
        assert_matches!(action, Action::Process(_));
    }

    // Tests that dealings are sent for new transcripts, and requests already
    // in progress are filtered out.
    #[test]
    fn test_send_dealings_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_send_dealings(key_id);
        }
    }

    fn test_send_dealings(key_id: MasterPublicKeyId) {
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let (id_1, id_2, id_3, id_4, id_5) = (
                    create_transcript_id(1),
                    create_transcript_id(2),
                    create_transcript_id(3),
                    create_transcript_id(4),
                    create_transcript_id(5),
                );

                // Set up the IDKG pool. Pool has dealings for transcripts 1, 2, 3.
                // Only dealing for transcript 1 is issued by us.
                let dealing_1 = create_dealing(id_1, NODE_1);
                let dealing_2 = create_dealing(id_2, NODE_2);
                let dealing_3 = create_dealing(id_3, NODE_3);
                let change_set = vec![
                    IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(dealing_1)),
                    IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(dealing_2)),
                    IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(dealing_3)),
                ];
                idkg_pool.apply_changes(change_set);

                // Set up the transcript creation request
                // The block requests transcripts 1, 4, 5
                let t1 = create_transcript_param(&key_id, id_1, &[NODE_1], &[NODE_2]);
                let t2 = create_transcript_param(&key_id, id_4, &[NODE_1], &[NODE_3]);
                let t3 = create_transcript_param(&key_id, id_5, &[NODE_1], &[NODE_4]);
                let block_reader =
                    TestIDkgBlockReader::for_pre_signer_test(Height::from(100), vec![t1, t2, t3]);
                let transcript_loader: TestIDkgTranscriptLoader = Default::default();

                // Since transcript 1 is already in progress, we should issue
                // dealings only for transcripts 4, 5
                let change_set =
                    pre_signer.send_dealings(&idkg_pool, &transcript_loader, &block_reader);
                assert_eq!(change_set.len(), 2);
                assert!(is_dealing_added_to_validated(&change_set, &id_4,));
                assert!(is_dealing_added_to_validated(&change_set, &id_5,));
            })
        })
    }

    // Tests that dealings are purged once the finalized height increases
    #[test]
    fn test_ecdsa_dealings_purging() {
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, pre_signer, mut consensus_pool) =
                    create_pre_signer_dependencies_and_pool(pool_config, logger);
                let transcript_loader = TestIDkgTranscriptLoader::default();
                let transcript_height = Height::from(30);
                let id_1 = create_transcript_id_with_height(1, Height::from(0));
                let id_2 = create_transcript_id_with_height(2, transcript_height);

                let dealing1 = create_dealing(id_1, NODE_2);
                let msg_id1 = dealing1.message_id();
                let dealing2 = create_dealing(id_2, NODE_2);
                let msg_id2 = dealing2.message_id();
                let change_set = vec![
                    IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(dealing1)),
                    IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(dealing2)),
                ];
                idkg_pool.apply_changes(change_set);

                // Finalized height doesn't increase, so dealing1 shouldn't be purged
                let change_set = pre_signer.on_state_change(&idkg_pool, &transcript_loader);
                assert_eq!(*pre_signer.prev_finalized_height.borrow(), Height::from(0));
                assert!(change_set.is_empty());

                // Finalized height increases, so dealing1 is purged
                let new_height = consensus_pool.advance_round_normal_operation_n(29);
                let change_set = pre_signer.on_state_change(&idkg_pool, &transcript_loader);
                assert_eq!(*pre_signer.prev_finalized_height.borrow(), new_height);
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_validated(&change_set, &msg_id1));

                idkg_pool.apply_changes(change_set);

                // Finalized height increases above dealing2, so it is purged
                let new_height = consensus_pool.advance_round_normal_operation();
                let change_set = pre_signer.on_state_change(&idkg_pool, &transcript_loader);
                assert_eq!(*pre_signer.prev_finalized_height.borrow(), new_height);
                assert_eq!(transcript_height, new_height);
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_validated(&change_set, &msg_id2));
            })
        })
    }

    // Tests that dealing is not issued if the node isn't in the list of dealers
    // specified by the transcript params
    #[test]
    fn test_non_dealers_dont_send_dealings_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_non_dealers_dont_send_dealings(key_id);
        }
    }

    fn test_non_dealers_dont_send_dealings(key_id: MasterPublicKeyId) {
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (idkg_pool, pre_signer) = create_pre_signer_dependencies(pool_config, logger);
                let (id_1, id_2) = (create_transcript_id(1), create_transcript_id(2));

                // transcript 1 has NODE_1 as a dealer
                let t1 = create_transcript_param(&key_id, id_1, &[NODE_1], &[NODE_1]);

                // Transcript 2 doesn't have NODE_1 as a dealer
                let t2 = create_transcript_param(&key_id, id_2, &[NODE_2], &[NODE_2]);

                // Transcript 2 should not result in a dealing
                let block_reader =
                    TestIDkgBlockReader::for_pre_signer_test(Height::from(100), vec![t1, t2]);
                let transcript_loader: TestIDkgTranscriptLoader = Default::default();

                let change_set =
                    pre_signer.send_dealings(&idkg_pool, &transcript_loader, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_dealing_added_to_validated(&change_set, &id_1,));
            })
        })
    }

    // Tests that dealing is not issued if the crypto component returns an error
    #[test]
    fn test_ecdsa_crypto_error_results_in_no_dealing() {
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let key_id = fake_ecdsa_master_public_key_id();
                let crypto = crypto_without_keys();
                let (idkg_pool, pre_signer) =
                    create_pre_signer_dependencies_with_crypto(pool_config, logger, Some(crypto));
                let id_1 = create_transcript_id(1);

                // transcript 1 has NODE_1 as a dealer
                let t1 = create_transcript_param(&key_id, id_1, &[NODE_1], &[NODE_1]);
                let block_reader =
                    TestIDkgBlockReader::for_pre_signer_test(Height::from(100), vec![t1.clone()])
                        .with_target_subnet_xnet_transcripts(vec![t1.transcript_params_ref]);
                let transcript_loader: TestIDkgTranscriptLoader = Default::default();

                let change_set =
                    pre_signer.send_dealings(&idkg_pool, &transcript_loader, &block_reader);
                assert!(change_set.is_empty());
            })
        })
    }

    // Tests that complaints are generated and added to the pool if loading transcript
    // results in complaints.
    #[test]
    fn test_send_dealings_with_complaints_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_send_dealings_with_complaints(key_id);
        }
    }

    fn test_send_dealings_with_complaints(key_id: MasterPublicKeyId) {
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (idkg_pool, pre_signer) = create_pre_signer_dependencies(pool_config, logger);
                let (id_1, id_2, id_3) = (
                    create_transcript_id(1),
                    create_transcript_id(2),
                    create_transcript_id(3),
                );

                // Set up the transcript creation request
                // The block requests transcripts 1, 2, 3
                let t1 = create_transcript_param(&key_id, id_1, &[NODE_1], &[NODE_2]);
                let t2 = create_transcript_param(&key_id, id_2, &[NODE_1], &[NODE_3]);
                let t3 = create_transcript_param(&key_id, id_3, &[NODE_1], &[NODE_4]);
                let block_reader =
                    TestIDkgBlockReader::for_pre_signer_test(Height::from(100), vec![t1, t2, t3]);
                let transcript_loader =
                    TestIDkgTranscriptLoader::new(TestTranscriptLoadStatus::Complaints);

                let change_set =
                    pre_signer.send_dealings(&idkg_pool, &transcript_loader, &block_reader);
                let complaints = transcript_loader.returned_complaints();
                assert_eq!(change_set.len(), complaints.len());
                assert_eq!(change_set.len(), 3);
                for complaint in complaints {
                    assert!(is_complaint_added_to_validated(
                        &change_set,
                        &complaint.content.idkg_complaint.transcript_id,
                        &NODE_1,
                        &NODE_1,
                    ));
                }
            })
        })
    }

    #[test]
    fn test_crypto_verify_dealing() {
        let mut rng = reproducible_rng();
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let env = CanisterThresholdSigTestEnvironment::new(1, &mut rng);
                let subnet_nodes: BTreeSet<_> = env.nodes.ids();
                let crypto = first_crypto(&env);
                let (_, pre_signer) =
                    create_pre_signer_dependencies_with_crypto(pool_config, logger, Some(crypto));
                let id = create_transcript_id_with_height(4, Height::from(5));
                let params = IDkgTranscriptParams::new(
                    id,
                    subnet_nodes.clone(),
                    subnet_nodes,
                    env.newest_registry_version,
                    ic_types::crypto::AlgorithmId::ThresholdEcdsaSecp256k1,
                    IDkgTranscriptOperation::Random,
                )
                .unwrap();
                let dealing = create_dealing(id, NODE_2);
                let changeset: Vec<_> = pre_signer
                    .crypto_verify_dealing(dealing.message_id(), &params, dealing.clone())
                    .into_iter()
                    .collect();
                // assert that the mock dealing does not pass real crypto check
                assert!(is_handle_invalid(&changeset, &dealing.message_id()));
            })
        })
    }

    // Tests that received dealings are accepted/processed for eligible transcript
    // requests, and others dealings are either deferred or dropped.
    #[test]
    fn test_validate_dealings_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_validate_dealings(key_id);
        }
    }

    fn test_validate_dealings(key_id: MasterPublicKeyId) {
        let (id_2, id_3, id_4, id_5, id_6) = (
            // A dealing for a transcript that is requested by finalized block (accepted)
            create_transcript_id_with_height(2, Height::from(100)),
            // A dealing for a transcript that is requested by finalized block (accepted)
            create_transcript_id_with_height(3, Height::from(10)),
            // A dealing for a transcript that is not requested by finalized block (dropped)
            create_transcript_id_with_height(4, Height::from(5)),
            // A dealing for a transcript that is not requested and references a future block height (deferred)
            create_transcript_id_with_height(5, Height::from(500)),
            // A dealing for a XNet transcript that is requested and references a future block height (accepted)
            create_transcript_id_with_height(6, Height::from(500)),
        );
        let mut artifacts = vec![];

        let ids = vec![id_2, id_3, id_4, id_5, id_6];
        let msg_ids = ids
            .into_iter()
            .map(|id| {
                let dealing = create_dealing(id, NODE_2);
                let msg_id = dealing.message_id();
                artifacts.push(UnvalidatedArtifact {
                    message: IDkgMessage::Dealing(dealing),
                    peer_id: NODE_2,
                    timestamp: UNIX_EPOCH,
                });
                msg_id
            })
            .collect::<Vec<_>>();
        let (msg_id_2, msg_id_3, msg_id_4, msg_id_6) =
            (&msg_ids[0], &msg_ids[1], &msg_ids[2], &msg_ids[4]);

        // Set up the transcript creation request
        // The block requests transcripts 2, 3, 6
        let t2 = create_transcript_param(&key_id, id_2, &[NODE_2], &[NODE_1]);
        let t3 = create_transcript_param(&key_id, id_3, &[NODE_2], &[NODE_1]);
        let t6 = create_transcript_param(&key_id, id_6, &[NODE_2], &[NODE_1]);
        let block_reader = TestIDkgBlockReader::for_pre_signer_test(
            Height::from(100),
            vec![t2, t3.clone(), t6.clone()],
        );

        // Validate dealings using `CryptoReturningOk`. Requested dealings should be moved to validated
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);

                artifacts.iter().for_each(|a| idkg_pool.insert(a.clone()));

                let change_set = pre_signer.validate_dealings(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 3);
                assert!(is_moved_to_validated(&change_set, msg_id_2));
                assert!(is_moved_to_validated(&change_set, msg_id_3));
                assert!(is_removed_from_unvalidated(&change_set, msg_id_4));
            })
        });

        // Validate dealings using `CryptoReturningOk`. Requested dealings should be moved to validated.
        // Dealings for requested target subnet xnet transcripts (even for future heights) should also be validated.
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let block_reader = block_reader
                    .clone()
                    .with_target_subnet_xnet_transcripts(vec![
                        t3.transcript_params_ref.clone(),
                        t6.transcript_params_ref.clone(),
                    ]);

                let (mut idkg_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);

                artifacts.iter().for_each(|a| idkg_pool.insert(a.clone()));

                let change_set = pre_signer.validate_dealings(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 4);
                assert!(is_moved_to_validated(&change_set, msg_id_2));
                assert!(is_moved_to_validated(&change_set, msg_id_3));
                assert!(is_removed_from_unvalidated(&change_set, msg_id_4));
                assert!(is_moved_to_validated(&change_set, msg_id_6));
            })
        });

        // Validate dealings using an empty transcript resolver. Dealings should fail to be resolved and thus
        // be handled invalid.
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);

                artifacts.iter().for_each(|a| idkg_pool.insert(a.clone()));

                let block_reader = block_reader.clone().with_fail_to_resolve();

                let change_set = pre_signer.validate_dealings(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 3);
                assert!(is_handle_invalid(&change_set, msg_id_2));
                assert!(is_handle_invalid(&change_set, msg_id_3));
                assert!(is_removed_from_unvalidated(&change_set, msg_id_4));
            })
        });

        // Validate dealings using a crypto component without keys. Crypto validation should return a
        // permanent error, thus the requested dealings should be handled as invalid.
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, pre_signer) = create_pre_signer_dependencies_with_crypto(
                    pool_config,
                    logger,
                    Some(crypto_without_keys()),
                );

                artifacts.iter().for_each(|a| idkg_pool.insert(a.clone()));

                let change_set = pre_signer.validate_dealings(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 3);
                assert!(is_handle_invalid(&change_set, msg_id_2));
                assert!(is_handle_invalid(&change_set, msg_id_3));
                assert!(is_removed_from_unvalidated(&change_set, msg_id_4));
            })
        });

        // Validate dealings for a transcript with a registry version that isn't available locally (yet).
        // Crypto validation should return a transient error, thus the requested dealings should be deferred.
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, pre_signer) = create_pre_signer_dependencies_with_crypto(
                    pool_config,
                    logger,
                    Some(crypto_without_keys()),
                );

                let v_1 = RegistryVersion::from(1);
                let t2 = create_transcript_param_with_registry_version(
                    &key_id,
                    id_2,
                    &[NODE_2],
                    &[NODE_1],
                    v_1,
                );
                let t3 = create_transcript_param_with_registry_version(
                    &key_id,
                    id_3,
                    &[NODE_2],
                    &[NODE_1],
                    v_1,
                );
                let block_reader =
                    TestIDkgBlockReader::for_pre_signer_test(Height::from(100), vec![t2, t3]);

                artifacts.iter().for_each(|a| idkg_pool.insert(a.clone()));

                let change_set = pre_signer.validate_dealings(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_unvalidated(&change_set, msg_id_4));
            })
        });
    }

    // Tests that duplicate dealings from a dealer for the same transcript
    // are dropped.
    #[test]
    fn test_duplicate_dealing_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_duplicate_dealing(key_id);
        }
    }

    fn test_duplicate_dealing(key_id: MasterPublicKeyId) {
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let id_2 = create_transcript_id_with_height(2, Height::from(100));

                // Set up the IDKG pool
                // Validated pool has: {transcript 2, dealer = NODE_2}
                let dealing = create_dealing(id_2, NODE_2);
                let change_set = vec![IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(
                    dealing,
                ))];
                idkg_pool.apply_changes(change_set);

                // Unvalidated pool has: {transcript 2, dealer = NODE_2, height = 100}
                let dealing = create_dealing(id_2, NODE_2);
                let msg_id_2 = dealing.message_id();
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::Dealing(dealing),
                    peer_id: NODE_2,
                    timestamp: UNIX_EPOCH,
                });

                let t2 = create_transcript_param(&key_id, id_2, &[NODE_2], &[NODE_1]);
                let block_reader =
                    TestIDkgBlockReader::for_pre_signer_test(Height::from(100), vec![t2]);

                let change_set = pre_signer.validate_dealings(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_handle_invalid(&change_set, &msg_id_2));
            })
        })
    }

    // Tests that duplicate dealings from a dealer for the same transcript
    // in the unvalidated pool are dropped.
    #[test]
    fn test_duplicate_dealing_in_batch_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_duplicate_dealing_in_batch(key_id);
        }
    }

    fn test_duplicate_dealing_in_batch(key_id: MasterPublicKeyId) {
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let id_2 = create_transcript_id_with_height(2, Height::from(100));

                // Set up the IDKG pool
                // Unvalidated pool has: {transcript 2, dealer = NODE_2, height = 100, internal_dealing_raw = vec[1]}
                let mut dealing = create_dealing(id_2, NODE_2);
                dealing.content.internal_dealing_raw = vec![1];
                let msg_id_2_a = dealing.message_id();
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::Dealing(dealing),
                    peer_id: NODE_2,
                    timestamp: UNIX_EPOCH,
                });

                // Unvalidated pool has: {transcript 2, dealer = NODE_2, height = 100, , internal_dealing_raw = vec[2]}
                let mut dealing = create_dealing(id_2, NODE_2);
                dealing.content.internal_dealing_raw = vec![2];
                let msg_id_2_b = dealing.message_id();
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::Dealing(dealing),
                    peer_id: NODE_2,
                    timestamp: UNIX_EPOCH,
                });

                // Unvalidated pool has: {transcript 2, dealer = NODE_3, height = 100, , internal_dealing_raw = vec[3]}
                let mut dealing = create_dealing(id_2, NODE_3);
                dealing.content.internal_dealing_raw = vec![3];
                let msg_id_3 = dealing.message_id();
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::Dealing(dealing),
                    peer_id: NODE_3,
                    timestamp: UNIX_EPOCH,
                });

                let t2 = create_transcript_param(&key_id, id_2, &[NODE_2, NODE_3], &[NODE_1]);
                let block_reader =
                    TestIDkgBlockReader::for_pre_signer_test(Height::from(100), vec![t2]);

                // One of msg_id_2_a or msg_id_2_b should be accepted, the other one dropped
                let change_set = pre_signer.validate_dealings(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 3);
                if is_moved_to_validated(&change_set, &msg_id_2_a) {
                    assert!(is_handle_invalid(&change_set, &msg_id_2_b));
                } else if is_moved_to_validated(&change_set, &msg_id_2_b) {
                    assert!(is_handle_invalid(&change_set, &msg_id_2_a));
                } else {
                    panic!("Neither dealing was accepted");
                }
                assert!(is_moved_to_validated(&change_set, &msg_id_3));
            })
        })
    }

    // Tests that dealings from a dealer that is not in the dealer list for the
    // transcript are dropped.
    #[test]
    fn test_unexpected_dealing_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_unexpected_dealing(key_id);
        }
    }

    fn test_unexpected_dealing(key_id: MasterPublicKeyId) {
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let id_2 = create_transcript_id_with_height(2, Height::from(100));

                // Unvalidated pool has: {transcript 2, dealer = NODE_2, height = 100}
                let dealing = create_dealing(id_2, NODE_2);
                let msg_id_2 = dealing.message_id();
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::Dealing(dealing),
                    peer_id: NODE_2,
                    timestamp: UNIX_EPOCH,
                });

                // NODE_2 is not in the dealer list
                let t2 = create_transcript_param(&key_id, id_2, &[NODE_3], &[NODE_1]);
                let block_reader =
                    TestIDkgBlockReader::for_pre_signer_test(Height::from(100), vec![t2]);

                let change_set = pre_signer.validate_dealings(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_handle_invalid(&change_set, &msg_id_2));
            })
        })
    }

    // Tests that support shares are sent to eligible dealings
    #[test]
    fn test_send_support_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_send_support(key_id);
        }
    }

    fn test_send_support(key_id: MasterPublicKeyId) {
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let id = create_transcript_id(1);

                // We haven't sent support yet, and we are in the receiver list
                let dealing = create_dealing(id, NODE_2);
                let change_set = vec![IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(
                    dealing,
                ))];
                idkg_pool.apply_changes(change_set);
                let t = create_transcript_param(&key_id, id, &[NODE_2], &[NODE_1]);

                let block_reader =
                    TestIDkgBlockReader::for_pre_signer_test(Height::from(100), vec![t]);
                let change_set = pre_signer.send_dealing_support(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_dealing_support_added_to_validated(
                    &change_set,
                    &id,
                    &NODE_2,
                ));
                idkg_pool.apply_changes(change_set);

                // Since we already issued support for the dealing, it should not produce any
                // more support.
                let change_set = pre_signer.send_dealing_support(&idkg_pool, &block_reader);
                assert!(change_set.is_empty());
            })
        })
    }

    // Tests that sending support shares is deferred if crypto returns transient error.
    #[test]
    fn test_defer_sending_dealing_support_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_defer_sending_dealing_support(key_id);
        }
    }

    fn test_defer_sending_dealing_support(key_id: MasterPublicKeyId) {
        let mut rng = reproducible_rng();
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, pre_signer) = create_pre_signer_dependencies_with_crypto(
                    pool_config,
                    logger,
                    Some(crypto_without_keys()),
                );
                let id = create_transcript_id(1);

                // We haven't sent support yet, and we are in the receiver list
                let dealing = create_dealing_with_payload(&key_id, id, NODE_2, &mut rng);
                let change_set = vec![IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(
                    dealing,
                ))];
                idkg_pool.apply_changes(change_set);
                // create a transcript with unknown future registry version
                let rv = RegistryVersion::from(1);
                let t = create_transcript_param_with_registry_version(
                    &key_id,
                    id,
                    &[NODE_2],
                    &[NODE_1],
                    rv,
                );

                let block_reader =
                    TestIDkgBlockReader::for_pre_signer_test(Height::from(100), vec![t.clone()])
                        // Xnet transcripts should raise a warning but should not stop this node from supporting it.
                        .with_source_subnet_xnet_transcripts(vec![t.transcript_params_ref]);

                // Sending support should be deferred until registry version exists locally
                let change_set = pre_signer.send_dealing_support(&idkg_pool, &block_reader);
                assert!(change_set.is_empty());
            })
        })
    }

    // Tests that invalid dealings are handled invalid when creating new dealing support.
    #[test]
    fn test_dont_send_support_for_invalid_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_dont_send_support_for_invalid(key_id);
        }
    }

    fn test_dont_send_support_for_invalid(key_id: MasterPublicKeyId) {
        let mut rng = reproducible_rng();
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, pre_signer) = create_pre_signer_dependencies_with_crypto(
                    pool_config,
                    logger,
                    Some(crypto_without_keys()),
                );
                let id = create_transcript_id(1);

                // We haven't sent support yet, and we are in the receiver list
                let dealing = create_dealing_with_payload(&key_id, id, NODE_2, &mut rng);
                let change_set = vec![IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(
                    dealing.clone(),
                ))];
                idkg_pool.apply_changes(change_set);
                let t = create_transcript_param(&key_id, id, &[NODE_2], &[NODE_1]);

                let block_reader =
                    TestIDkgBlockReader::for_pre_signer_test(Height::from(100), vec![t]);

                // Since there are no keys in the crypto component, dealing verification should fail permanently and
                // the dealing is considered invalid.
                let change_set = pre_signer.send_dealing_support(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_handle_invalid(&change_set, &dealing.message_id()))
            })
        })
    }

    // Tests that support shares are not sent by nodes not in the receiver list for
    // the transcript
    #[test]
    fn test_non_receivers_dont_send_support_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_non_receivers_dont_send_support(key_id);
        }
    }

    fn test_non_receivers_dont_send_support(key_id: MasterPublicKeyId) {
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let id = create_transcript_id(1);

                // We are not in the receiver list for the transcript
                let dealing = create_dealing(id, NODE_2);
                let change_set = vec![IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(
                    dealing,
                ))];
                idkg_pool.apply_changes(change_set);
                let t = create_transcript_param(&key_id, id, &[NODE_2], &[NODE_3]);

                let block_reader =
                    TestIDkgBlockReader::for_pre_signer_test(Height::from(100), vec![t]);
                let change_set = pre_signer.send_dealing_support(&idkg_pool, &block_reader);
                assert!(change_set.is_empty());
            })
        })
    }

    // Tests that support shares are not sent for transcripts we are not building
    #[test]
    fn test_ecdsa_no_support_for_missing_transcript_params() {
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let id = create_transcript_id(1);

                let dealing = create_dealing(id, NODE_2);
                let change_set = vec![IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(
                    dealing,
                ))];
                idkg_pool.apply_changes(change_set);

                let block_reader =
                    TestIDkgBlockReader::for_pre_signer_test(Height::from(100), vec![]);
                let change_set = pre_signer.send_dealing_support(&idkg_pool, &block_reader);
                assert!(change_set.is_empty());
            })
        })
    }

    #[test]
    fn test_crypto_verify_dealing_support() {
        let mut rng = reproducible_rng();
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let env = CanisterThresholdSigTestEnvironment::new(1, &mut rng);
                let subnet_nodes: BTreeSet<_> = env.nodes.ids();
                let crypto = first_crypto(&env);
                let (_, pre_signer) =
                    create_pre_signer_dependencies_with_crypto(pool_config, logger, Some(crypto));
                let id = create_transcript_id_with_height(4, Height::from(5));
                let params = IDkgTranscriptParams::new(
                    id,
                    subnet_nodes.clone(),
                    subnet_nodes,
                    env.newest_registry_version,
                    ic_types::crypto::AlgorithmId::ThresholdEcdsaSecp256k1,
                    IDkgTranscriptOperation::Random,
                )
                .unwrap();
                let (dealing, support) = create_support(id, NODE_2, NODE_3);
                let changeset: Vec<_> = pre_signer
                    .crypto_verify_dealing_support(
                        support.message_id(),
                        &params,
                        &dealing,
                        support.clone(),
                        &(IDkgStatsNoOp {}),
                    )
                    .into_iter()
                    .collect();
                // assert that the mock dealing support does not pass real crypto check
                assert!(is_handle_invalid(&changeset, &support.message_id()));
            })
        })
    }

    // Tests that received support shares are accepted/processed for eligible
    // transcript requests, and others dealings are either deferred or dropped.
    #[test]
    fn test_validate_dealing_support_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_validate_dealing_support(key_id);
        }
    }

    fn test_validate_dealing_support(key_id: MasterPublicKeyId) {
        let (id_2, id_3, id_4, id_5) = (
            create_transcript_id_with_height(2, Height::from(25)),
            create_transcript_id_with_height(3, Height::from(10)),
            create_transcript_id_with_height(4, Height::from(5)),
            create_transcript_id_with_height(4, Height::from(500)),
        );
        let mut artifacts = vec![];

        // Set up the transcript creation request
        // The block requests transcripts 2, 3
        let t2 = create_transcript_param(&key_id, id_2, &[NODE_2], &[NODE_3]);
        let t3 = create_transcript_param(&key_id, id_3, &[NODE_2], &[NODE_3]);
        let block_reader = TestIDkgBlockReader::for_pre_signer_test(
            Height::from(100),
            vec![t2.clone(), t3.clone()],
        );

        // A dealing for a transcript that is requested by finalized block,
        // and we already have the dealing(share accepted)
        let (dealing, mut support) = create_support(id_2, NODE_2, NODE_3);
        let msg_id_2 = support.message_id();
        artifacts.push(UnvalidatedArtifact {
            message: IDkgMessage::DealingSupport(support.clone()),
            peer_id: NODE_3,
            timestamp: UNIX_EPOCH,
        });
        support.sig_share.signature = BasicSigOf::new(BasicSig(vec![1]));
        let msg_id_2_dupl = support.message_id();
        artifacts.push(UnvalidatedArtifact {
            message: IDkgMessage::DealingSupport(support),
            peer_id: NODE_3,
            timestamp: UNIX_EPOCH,
        });

        // A dealing for a transcript that is requested by finalized block,
        // but we don't have the dealing yet(share deferred)
        let (_, support) = create_support(id_3, NODE_2, NODE_3);
        let msg_id_3 = support.message_id();
        artifacts.push(UnvalidatedArtifact {
            message: IDkgMessage::DealingSupport(support),
            peer_id: NODE_3,
            timestamp: UNIX_EPOCH,
        });

        // A dealing for a transcript that is not requested by finalized block
        // (share dropped)
        let (_, support) = create_support(id_4, NODE_2, NODE_3);
        let msg_id_4 = support.message_id();
        artifacts.push(UnvalidatedArtifact {
            message: IDkgMessage::DealingSupport(support),
            peer_id: NODE_3,
            timestamp: UNIX_EPOCH,
        });

        // A dealing for a transcript that references a future block height
        // (share deferred)
        let (_, support) = create_support(id_5, NODE_2, NODE_3);
        artifacts.push(UnvalidatedArtifact {
            message: IDkgMessage::DealingSupport(support),
            peer_id: NODE_3,
            timestamp: UNIX_EPOCH,
        });

        // Using CryptoReturningOK one of the shares with id_2 should be accepted, the other handled invalid
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);

                // Set up the IDKG pool
                let change_set = vec![IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(
                    dealing.clone(),
                ))];
                idkg_pool.apply_changes(change_set);
                artifacts.iter().for_each(|a| idkg_pool.insert(a.clone()));

                let change_set = pre_signer.validate_dealing_support(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 3);
                assert!(
                    is_moved_to_validated(&change_set, &msg_id_2)
                        || is_moved_to_validated(&change_set, &msg_id_2_dupl)
                );
                assert!(
                    is_handle_invalid(&change_set, &msg_id_2)
                        || is_handle_invalid(&change_set, &msg_id_2_dupl)
                );
                assert!(is_removed_from_unvalidated(&change_set, &msg_id_4));
            })
        });

        // Simulate failure of resolving refs by clearing transcripts of the block reader,
        // dealings for requested (but unresolvable) transcripts should be handled invalid.
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);

                // Set up the IDKG pool
                let change_set = vec![IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(
                    dealing.clone(),
                ))];
                idkg_pool.apply_changes(change_set);
                artifacts.iter().for_each(|a| idkg_pool.insert(a.clone()));

                let block_reader = block_reader.clone().with_fail_to_resolve();
                let change_set = pre_signer.validate_dealing_support(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 4);
                assert!(is_handle_invalid(&change_set, &msg_id_2));
                assert!(is_handle_invalid(&change_set, &msg_id_2_dupl));
                assert!(is_handle_invalid(&change_set, &msg_id_3));
                assert!(is_removed_from_unvalidated(&change_set, &msg_id_4));
            })
        });

        // Mark t2 as a source_subnet_xnet_transcript, its dealings should no longer be accepted.
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);

                // Set up the IDKG pool
                let change_set = vec![IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(
                    dealing.clone(),
                ))];
                idkg_pool.apply_changes(change_set);
                artifacts.iter().for_each(|a| idkg_pool.insert(a.clone()));

                let block_reader = block_reader
                    .clone()
                    .with_source_subnet_xnet_transcripts(vec![t2.transcript_params_ref])
                    .with_target_subnet_xnet_transcripts(vec![t3.transcript_params_ref]);
                let change_set = pre_signer.validate_dealing_support(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 3);
                assert!(is_handle_invalid(&change_set, &msg_id_2));
                assert!(is_handle_invalid(&change_set, &msg_id_2_dupl));
                assert!(is_removed_from_unvalidated(&change_set, &msg_id_4));
            })
        });
    }

    // Tests that duplicate support from a node for the same dealing
    // are dropped.
    #[test]
    fn test_ecdsa_duplicate_support_from_node() {
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let key_id = fake_ecdsa_master_public_key_id();
                let (mut idkg_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let id = create_transcript_id_with_height(1, Height::from(100));

                // Set up the IDKG pool
                // Validated pool has: support {transcript 2, dealer = NODE_2, signer = NODE_3}
                let (dealing, support) = create_support(id, NODE_2, NODE_3);
                let change_set = vec![IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(
                    dealing,
                ))];
                idkg_pool.apply_changes(change_set);

                let change_set = vec![IDkgChangeAction::AddToValidated(
                    IDkgMessage::DealingSupport(support.clone()),
                )];
                idkg_pool.apply_changes(change_set);

                // Unvalidated pool has: duplicate of the same support share
                let msg_id = support.message_id();
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::DealingSupport(support),
                    peer_id: NODE_3,
                    timestamp: UNIX_EPOCH,
                });

                let t = create_transcript_param(&key_id, id, &[NODE_2], &[NODE_3]);
                let block_reader =
                    TestIDkgBlockReader::for_pre_signer_test(Height::from(100), vec![t]);

                let change_set = pre_signer.validate_dealing_support(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_handle_invalid(&change_set, &msg_id));
            })
        })
    }

    // Tests that support from a node that is not in the receiver list for the
    // transcript are dropped.
    #[test]
    fn test_ecdsa_unexpected_support_from_node() {
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let key_id = fake_ecdsa_master_public_key_id();
                let (mut idkg_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let id = create_transcript_id_with_height(1, Height::from(10));

                // Unvalidated pool has: support {transcript 2, dealer = NODE_2, signer =
                // NODE_3}
                let (_, support) = create_support(id, NODE_2, NODE_3);
                let msg_id = support.message_id();
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::DealingSupport(support),
                    peer_id: NODE_3,
                    timestamp: UNIX_EPOCH,
                });

                // NODE_3 is not in the receiver list
                let t = create_transcript_param(&key_id, id, &[NODE_2], &[NODE_4]);
                let block_reader =
                    TestIDkgBlockReader::for_pre_signer_test(Height::from(100), vec![t]);
                let change_set = pre_signer.validate_dealing_support(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_handle_invalid(&change_set, &msg_id));
            })
        })
    }

    // Tests that support with a meta data mismatch is dropped.
    #[test]
    fn test_ecdsa_dealing_support_meta_data_mismatch() {
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let key_id = fake_ecdsa_master_public_key_id();
                let (mut idkg_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let id = create_transcript_id_with_height(1, Height::from(10));

                // Set up the IDKG pool
                // A dealing for a transcript that is requested by finalized block,
                // and we already have the dealing(share accepted)
                let (dealing, mut support) = create_support(id, NODE_2, NODE_3);
                let change_set = vec![IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(
                    dealing,
                ))];
                idkg_pool.apply_changes(change_set);

                support.dealer_id = NODE_3;
                let msg_id = support.message_id();
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::DealingSupport(support),
                    peer_id: NODE_3,
                    timestamp: UNIX_EPOCH,
                });

                // Set up the transcript creation request
                // The block requests transcripts 1
                let t = create_transcript_param(&key_id, id, &[NODE_2], &[NODE_3]);
                let block_reader =
                    TestIDkgBlockReader::for_pre_signer_test(Height::from(100), vec![t]);
                let change_set = pre_signer.validate_dealing_support(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_handle_invalid(&change_set, &msg_id));
            })
        })
    }

    // Tests that support with a dealing hash mismatch is dropped.
    #[test]
    fn test_ecdsa_dealing_support_missing_hash_meta_data_mismatch() {
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let key_id = fake_ecdsa_master_public_key_id();
                let (mut idkg_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let id = create_transcript_id_with_height(1, Height::from(10));

                // Set up the IDKG pool
                // A dealing for a transcript that is requested by finalized block,
                // and we already have the dealing(share accepted)
                let (dealing, mut support) = create_support(id, NODE_2, NODE_3);
                let change_set = vec![IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(
                    dealing,
                ))];
                idkg_pool.apply_changes(change_set);

                support.dealing_hash = CryptoHashOf::new(CryptoHash(vec![]));
                let msg_id = support.message_id();
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::DealingSupport(support),
                    peer_id: NODE_3,
                    timestamp: UNIX_EPOCH,
                });

                // Set up the transcript creation request
                // The block requests transcripts 1
                let t = create_transcript_param(&key_id, id, &[NODE_2], &[NODE_3]);
                let block_reader =
                    TestIDkgBlockReader::for_pre_signer_test(Height::from(100), vec![t]);
                let change_set = pre_signer.validate_dealing_support(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_unvalidated(&change_set, &msg_id));
            })
        })
    }

    // Tests that support with a missing dealing hash and invalid dealer is dropped.
    #[test]
    fn test_ecdsa_dealing_support_missing_hash_invalid_dealer() {
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let key_id = fake_ecdsa_master_public_key_id();
                let (mut idkg_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let id = create_transcript_id_with_height(1, Height::from(10));

                // Set up the IDKG pool
                // A dealing for a transcript that is requested by finalized block,
                // and we already have the dealing(share accepted)
                let (dealing, mut support) = create_support(id, NODE_2, NODE_3);
                let change_set = vec![IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(
                    dealing,
                ))];
                idkg_pool.apply_changes(change_set);

                support.dealing_hash = CryptoHashOf::new(CryptoHash(vec![]));
                support.dealer_id = NODE_4;
                let msg_id = support.message_id();
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::DealingSupport(support),
                    peer_id: NODE_3,
                    timestamp: UNIX_EPOCH,
                });

                // Set up the transcript creation request
                // The block requests transcripts 1
                let t = create_transcript_param(&key_id, id, &[NODE_2], &[NODE_3]);
                let block_reader =
                    TestIDkgBlockReader::for_pre_signer_test(Height::from(100), vec![t]);
                let change_set = pre_signer.validate_dealing_support(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_unvalidated(&change_set, &msg_id));
            })
        })
    }

    // Tests purging of dealings from unvalidated pool
    #[test]
    fn test_ecdsa_purge_unvalidated_dealings() {
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let key_id = fake_ecdsa_master_public_key_id();
                let (mut idkg_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let (id_1, id_2, id_3) = (
                    create_transcript_id_with_height(1, Height::from(20)),
                    create_transcript_id_with_height(2, Height::from(20)),
                    create_transcript_id_with_height(3, Height::from(200)),
                );

                // Dealing 1: height <= current_height, in_progress (not purged)
                let dealing_1 = create_dealing(id_1, NODE_2);
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::Dealing(dealing_1),
                    peer_id: NODE_2,
                    timestamp: UNIX_EPOCH,
                });

                // Dealing 2: height <= current_height, !in_progress (purged)
                let dealing_2 = create_dealing(id_2, NODE_2);
                let msg_id_2 = dealing_2.message_id();
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::Dealing(dealing_2),
                    peer_id: NODE_2,
                    timestamp: UNIX_EPOCH,
                });

                // Dealing 3: height > current_height (not purged)
                let dealing_3 = create_dealing(id_3, NODE_2);
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::Dealing(dealing_3),
                    peer_id: NODE_2,
                    timestamp: UNIX_EPOCH,
                });

                let t = create_transcript_param(&key_id, id_1, &[NODE_2], &[NODE_4]);
                let block_reader =
                    TestIDkgBlockReader::for_pre_signer_test(Height::from(100), vec![t]);
                let change_set = pre_signer.purge_artifacts(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_unvalidated(&change_set, &msg_id_2));
            })
        })
    }

    // Tests purging of dealings from validated pool
    #[test]
    fn test_ecdsa_purge_validated_dealings() {
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let key_id = fake_ecdsa_master_public_key_id();
                let (mut idkg_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let (id_1, id_2, id_3, id_4) = (
                    create_transcript_id_with_height(1, Height::from(20)),
                    create_transcript_id_with_height(2, Height::from(20)),
                    create_transcript_id_with_height(3, Height::from(200)),
                    create_transcript_id_with_height(4, Height::from(20)),
                );

                // Dealing 1: height <= current_height, in_progress (not purged)
                let dealing_1 = create_dealing(id_1, NODE_2);

                // Dealing 2: height <= current_height, !in_progress (purged)
                let dealing_2 = create_dealing(id_2, NODE_2);
                let msg_id_2 = dealing_2.message_id();

                // Dealing 3: height > current_height (not purged)
                let dealing_3 = create_dealing(id_3, NODE_2);

                // Dealing 4: height <= current_height, !in_progress, is target subnet xnet transcript (not purged)
                let dealing_4 = create_dealing(id_4, NODE_2);

                let change_set = vec![
                    IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(dealing_1)),
                    IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(dealing_2)),
                    IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(dealing_3)),
                    IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(dealing_4)),
                ];
                idkg_pool.apply_changes(change_set);

                let t = create_transcript_param(&key_id, id_1, &[NODE_2], &[NODE_4]);
                let t4 = create_transcript_param(&key_id, id_4, &[NODE_2], &[NODE_4]);
                let block_reader =
                    TestIDkgBlockReader::for_pre_signer_test(Height::from(100), vec![t])
                        .with_target_subnet_xnet_transcripts(vec![t4.transcript_params_ref]);
                let change_set = pre_signer.purge_artifacts(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_validated(&change_set, &msg_id_2));
            })
        })
    }

    // Tests purging of dealing support from unvalidated pool
    #[test]
    fn test_ecdsa_purge_unvalidated_dealing_support() {
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let key_id = fake_ecdsa_master_public_key_id();
                let (mut idkg_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let (id_1, id_2, id_3) = (
                    create_transcript_id_with_height(1, Height::from(20)),
                    create_transcript_id_with_height(2, Height::from(20)),
                    create_transcript_id_with_height(3, Height::from(200)),
                );

                // Support 1: height <= current_height, in_progress (not purged)
                let (_, support_1) = create_support(id_1, NODE_2, NODE_3);
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::DealingSupport(support_1),
                    peer_id: NODE_2,
                    timestamp: UNIX_EPOCH,
                });

                // Dealing 2: height <= current_height, !in_progress (purged)
                let (_, support_2) = create_support(id_2, NODE_2, NODE_3);
                let msg_id_2 = support_2.message_id();
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::DealingSupport(support_2),
                    peer_id: NODE_2,
                    timestamp: UNIX_EPOCH,
                });

                // Dealing 3: height > current_height (not purged)
                let (_, support_3) = create_support(id_3, NODE_2, NODE_3);
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::DealingSupport(support_3),
                    peer_id: NODE_2,
                    timestamp: UNIX_EPOCH,
                });

                let t = create_transcript_param(&key_id, id_1, &[NODE_2], &[NODE_4]);
                let block_reader =
                    TestIDkgBlockReader::for_pre_signer_test(Height::from(100), vec![t]);
                let change_set = pre_signer.purge_artifacts(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_unvalidated(&change_set, &msg_id_2));
            })
        })
    }

    // Tests purging of dealing support from validated pool
    #[test]
    fn test_ecdsa_purge_validated_dealing_support() {
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let key_id = fake_ecdsa_master_public_key_id();
                let (mut idkg_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let (id_1, id_2, id_3) = (
                    create_transcript_id_with_height(1, Height::from(20)),
                    create_transcript_id_with_height(2, Height::from(20)),
                    create_transcript_id_with_height(3, Height::from(200)),
                );

                // Support 1: height <= current_height, in_progress (not purged)
                let (_, support_1) = create_support(id_1, NODE_2, NODE_3);

                // Dealing 2: height <= current_height, !in_progress (purged)
                let (_, support_2) = create_support(id_2, NODE_2, NODE_3);
                let msg_id_2 = support_2.message_id();

                // Dealing 3: height > current_height (not purged)
                let (_, support_3) = create_support(id_3, NODE_2, NODE_3);

                let change_set = vec![
                    IDkgChangeAction::AddToValidated(IDkgMessage::DealingSupport(support_1)),
                    IDkgChangeAction::AddToValidated(IDkgMessage::DealingSupport(support_2)),
                    IDkgChangeAction::AddToValidated(IDkgMessage::DealingSupport(support_3)),
                ];
                idkg_pool.apply_changes(change_set);

                let t = create_transcript_param(&key_id, id_1, &[NODE_2], &[NODE_4]);
                let block_reader =
                    TestIDkgBlockReader::for_pre_signer_test(Height::from(100), vec![t]);
                let change_set = pre_signer.purge_artifacts(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_validated(&change_set, &msg_id_2));
            })
        })
    }

    // Tests transcript builder failures and success
    #[test]
    fn test_transcript_builder_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_transcript_builder(key_id);
        }
    }

    fn test_transcript_builder(key_id: MasterPublicKeyId) {
        let mut rng = reproducible_rng();
        let env = CanisterThresholdSigTestEnvironment::new(3, &mut rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::AllNodesAsDealersAndReceivers,
            &mut rng,
        );
        let params = setup_masked_random_params(
            &env,
            algorithm_for_key_id(&key_id),
            &dealers,
            &receivers,
            &mut rng,
        );
        let tid = params.transcript_id();
        let (dealings, supports) = get_dealings_and_support(&env, &params);
        let block_reader =
            TestIDkgBlockReader::for_pre_signer_test(tid.source_height(), vec![(&params).into()]);
        let metrics = IDkgPayloadMetrics::new(MetricsRegistry::new());
        let crypto = first_crypto(&env);

        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, _) =
                    create_pre_signer_dependencies(pool_config, logger.clone());

                {
                    let b = IDkgTranscriptBuilderImpl::new(
                        &block_reader,
                        crypto.deref(),
                        &idkg_pool,
                        &metrics,
                        logger.clone(),
                    );

                    // tid is requested, but there are no dealings for it, the transcript cannot
                    // be completed
                    let result = b.get_completed_transcript(tid);
                    assert_matches!(result, None);
                }

                // add dealings
                let change_set = dealings
                    .values()
                    .map(|d| IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(d.clone())))
                    .collect();
                idkg_pool.apply_changes(change_set);

                {
                    let b = IDkgTranscriptBuilderImpl::new(
                        &block_reader,
                        crypto.deref(),
                        &idkg_pool,
                        &metrics,
                        logger.clone(),
                    );

                    // cannot aggregate empty shares
                    let result = b.crypto_aggregate_dealing_support(&params, &[]);
                    assert_matches!(result, None);

                    // there are no support shares, no transcript should be completed
                    let result = b.get_completed_transcript(tid);
                    assert_matches!(result, None);
                }

                // add support
                let change_set = supports
                    .iter()
                    .map(|s| {
                        IDkgChangeAction::AddToValidated(IDkgMessage::DealingSupport(s.clone()))
                    })
                    .collect();
                idkg_pool.apply_changes(change_set);

                let b = IDkgTranscriptBuilderImpl::new(
                    &block_reader,
                    crypto.deref(),
                    &idkg_pool,
                    &metrics,
                    logger.clone(),
                );
                // the transcript should be completed now
                let result = b.get_completed_transcript(tid);
                assert_matches!(result, Some(t) if t.transcript_id == tid);

                // returned dealings should be equal to the ones we inserted
                let dealings1 = dealings.values().cloned().collect::<HashSet<_>>();
                let dealings2 = b
                    .get_validated_dealings(tid)
                    .into_iter()
                    .collect::<HashSet<_>>();
                assert_eq!(dealings1, dealings2);

                {
                    let block_reader =
                        TestIDkgBlockReader::for_pre_signer_test(tid.source_height(), vec![]);
                    let b = IDkgTranscriptBuilderImpl::new(
                        &block_reader,
                        crypto.deref(),
                        &idkg_pool,
                        &metrics,
                        logger.clone(),
                    );
                    // the transcript is no longer requested, it should not be returned
                    let result = b.get_completed_transcript(tid);
                    assert_matches!(result, None);
                }

                let crypto = crypto_without_keys();
                let b = IDkgTranscriptBuilderImpl::new(
                    &block_reader,
                    crypto.as_ref(),
                    &idkg_pool,
                    &metrics,
                    logger,
                );
                // transcript completion should fail on crypto failures
                let result = b.get_completed_transcript(tid);
                assert_matches!(result, None);
            })
        });
    }

    fn first_crypto(env: &CanisterThresholdSigTestEnvironment) -> Arc<dyn ConsensusCrypto> {
        env.nodes.iter().next().unwrap().crypto()
    }
}
