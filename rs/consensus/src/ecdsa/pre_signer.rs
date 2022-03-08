//! The pre signature process manager

use crate::consensus::{
    metrics::{timed_call, EcdsaPayloadMetrics, EcdsaPreSignerMetrics},
    utils::RoundRobin,
    ConsensusCrypto,
};
use crate::ecdsa::complaints::EcdsaTranscriptLoader;
use crate::ecdsa::utils::{load_transcripts, transcript_op_summary, EcdsaBlockReaderImpl};
use ic_interfaces::consensus_pool::{ConsensusBlockCache, ConsensusBlockChain};
use ic_interfaces::crypto::{ErrorReplication, IDkgProtocol};
use ic_interfaces::ecdsa::{EcdsaChangeAction, EcdsaChangeSet, EcdsaPool};
use ic_logger::{debug, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_types::artifact::EcdsaMessageId;
use ic_types::consensus::ecdsa::{
    EcdsaBlockReader, EcdsaDealing, EcdsaDealingSupport, EcdsaMessage, EcdsaSignedDealing,
    EcdsaVerifiedDealing,
};
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgMultiSignedDealing, IDkgTranscript, IDkgTranscriptId, IDkgTranscriptOperation,
    IDkgTranscriptParams,
};
use ic_types::malicious_flags::MaliciousFlags;
use ic_types::signature::MultiSignature;
use ic_types::{Height, NodeId};

#[cfg(feature = "malicious_code")]
use ic_types::crypto::canister_threshold_sig::idkg::IDkgDealing;

use prometheus::IntCounterVec;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

pub(crate) trait EcdsaPreSigner: Send {
    /// The on_state_change() called from the main ECDSA path.
    fn on_state_change(
        &self,
        ecdsa_pool: &dyn EcdsaPool,
        transcript_loader: &dyn EcdsaTranscriptLoader,
    ) -> EcdsaChangeSet;
}

pub(crate) struct EcdsaPreSignerImpl {
    node_id: NodeId,
    consensus_block_cache: Arc<dyn ConsensusBlockCache>,
    crypto: Arc<dyn ConsensusCrypto>,
    schedule: RoundRobin,
    metrics: EcdsaPreSignerMetrics,
    log: ReplicaLogger,
    malicious_flags: MaliciousFlags,
}

impl EcdsaPreSignerImpl {
    pub(crate) fn new(
        node_id: NodeId,
        consensus_block_cache: Arc<dyn ConsensusBlockCache>,
        crypto: Arc<dyn ConsensusCrypto>,
        metrics_registry: MetricsRegistry,
        log: ReplicaLogger,
        malicious_flags: MaliciousFlags,
    ) -> Self {
        Self {
            node_id,
            consensus_block_cache,
            crypto,
            schedule: RoundRobin::default(),
            metrics: EcdsaPreSignerMetrics::new(metrics_registry),
            log,
            malicious_flags,
        }
    }

    /// Starts the transcript generation sequence by issuing the
    /// dealing for the transcript. The requests for new transcripts
    /// come from the latest summary block
    fn send_dealings(
        &self,
        ecdsa_pool: &dyn EcdsaPool,
        transcript_loader: &dyn EcdsaTranscriptLoader,
        block_reader: &dyn EcdsaBlockReader,
    ) -> EcdsaChangeSet {
        let requested_transcripts = resolve_transcript_refs(
            block_reader,
            "send_dealings",
            self.metrics.pre_sign_errors.clone(),
            &self.log,
        );

        requested_transcripts
            .iter()
            .filter(|transcript_params| {
                // Issue a dealing if we are in the dealer list and we haven't
                //already issued a dealing for this transcript
                transcript_params.dealers().position(self.node_id).is_some()
                    && !self.has_dealer_issued_dealing(
                        ecdsa_pool,
                        &transcript_params.transcript_id(),
                        &self.node_id,
                    )
            })
            .map(|transcript_params| {
                self.crypto_create_dealing(
                    ecdsa_pool,
                    transcript_loader,
                    block_reader,
                    transcript_params,
                )
            })
            .flatten()
            .collect()
    }

    /// Processes the dealings received from peer dealers
    fn validate_dealings(
        &self,
        ecdsa_pool: &dyn EcdsaPool,
        block_reader: &dyn EcdsaBlockReader,
    ) -> EcdsaChangeSet {
        let requested_transcripts = resolve_transcript_refs(
            block_reader,
            "validate_dealings",
            self.metrics.pre_sign_errors.clone(),
            &self.log,
        );

        // Pass 1: collection of <TranscriptId, DealerId>
        let mut dealing_keys = BTreeSet::new();
        let mut duplicate_keys = BTreeSet::new();
        for (_, signed_dealing) in ecdsa_pool.unvalidated().signed_dealings() {
            let dealing = signed_dealing.get();
            let key = (
                dealing.idkg_dealing.transcript_id,
                dealing.idkg_dealing.dealer_id,
            );
            if !dealing_keys.insert(key) {
                duplicate_keys.insert(key);
            }
        }

        let mut ret = Vec::new();
        for (id, signed_dealing) in ecdsa_pool.unvalidated().signed_dealings() {
            let dealing = signed_dealing.get();
            // Remove the duplicate entries
            let key = (
                dealing.idkg_dealing.transcript_id,
                dealing.idkg_dealing.dealer_id,
            );
            if duplicate_keys.contains(&key) {
                self.metrics
                    .pre_sign_errors_inc("duplicate_dealing_in_batch");
                ret.push(EcdsaChangeAction::HandleInvalid(
                    id,
                    format!("Duplicate dealing in unvalidated batch: {}", signed_dealing),
                ));
                continue;
            }

            match Action::action(
                block_reader,
                &requested_transcripts,
                dealing.requested_height,
                &dealing.idkg_dealing.transcript_id,
            ) {
                Action::Process(transcript_params) => {
                    if transcript_params
                        .dealers()
                        .position(dealing.idkg_dealing.dealer_id)
                        .is_none()
                    {
                        // The node is not in the dealer list for this transcript
                        self.metrics.pre_sign_errors_inc("unexpected_dealing");
                        ret.push(EcdsaChangeAction::HandleInvalid(
                            id,
                            format!("Dealing from unexpected node: {}", signed_dealing),
                        ))
                    } else if self.has_dealer_issued_dealing(
                        ecdsa_pool,
                        &dealing.idkg_dealing.transcript_id,
                        &dealing.idkg_dealing.dealer_id,
                    ) {
                        // The node already sent a valid dealing for this transcript
                        self.metrics.pre_sign_errors_inc("duplicate_dealing");
                        ret.push(EcdsaChangeAction::HandleInvalid(
                            id,
                            format!("Duplicate dealing: {}", signed_dealing),
                        ))
                    } else {
                        let mut changes =
                            self.crypto_verify_dealing(&id, transcript_params, signed_dealing);
                        ret.append(&mut changes);
                    }
                }
                Action::Drop => ret.push(EcdsaChangeAction::RemoveUnvalidated(id)),
                Action::Defer => {}
            }
        }
        ret
    }

    /// Sends out the signature share for the dealings received from peer
    /// dealers
    fn send_dealing_support(
        &self,
        ecdsa_pool: &dyn EcdsaPool,
        block_reader: &dyn EcdsaBlockReader,
    ) -> EcdsaChangeSet {
        let requested_transcripts = resolve_transcript_refs(
            block_reader,
            "send_dealing_support",
            self.metrics.pre_sign_errors.clone(),
            &self.log,
        );

        // TranscriptId -> TranscriptParams
        let mut trancript_param_map = BTreeMap::new();
        for transcript_params in &requested_transcripts {
            trancript_param_map.insert(transcript_params.transcript_id(), transcript_params);
        }

        ecdsa_pool
            .validated()
            .signed_dealings()
            .filter(|(_, signed_dealing)| {
                let dealing = signed_dealing.get();
                !self.has_node_issued_dealing_support(
                    ecdsa_pool,
                    &dealing.idkg_dealing.transcript_id,
                    &dealing.idkg_dealing.dealer_id,
                    &self.node_id,
                )
            })
            .filter_map(|(id, signed_dealing)| {
                let dealing = signed_dealing.get();
                // Look up the transcript params for the dealing, and check if we
                // are a receiver for this dealing
                if let Some(transcript_params) =
                    trancript_param_map.get(&dealing.idkg_dealing.transcript_id)
                {
                    transcript_params
                        .receivers()
                        .position(self.node_id)
                        .map(|_| (id, transcript_params, dealing))
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
            .map(|(id, transcript_params, dealing)| {
                self.crypto_create_dealing_support(&id, transcript_params, dealing)
            })
            .flatten()
            .collect()
    }

    /// Processes the received dealing support messages
    fn validate_dealing_support(
        &self,
        ecdsa_pool: &dyn EcdsaPool,
        block_reader: &dyn EcdsaBlockReader,
    ) -> EcdsaChangeSet {
        let requested_transcripts = resolve_transcript_refs(
            block_reader,
            "validate_dealing_support",
            self.metrics.pre_sign_errors.clone(),
            &self.log,
        );

        // Get the set of valid dealings <TranscriptId, DealerId>
        let mut valid_dealings = BTreeSet::new();
        for (_, signed_dealing) in ecdsa_pool.validated().signed_dealings() {
            let dealing = signed_dealing.get();
            let dealing_key = (
                dealing.idkg_dealing.transcript_id,
                dealing.idkg_dealing.dealer_id,
            );
            valid_dealings.insert(dealing_key);
        }

        // Pass 1: collection of <TranscriptId, DealerId, SignerId>
        let mut supports = BTreeSet::new();
        let mut duplicate_supports = BTreeSet::new();
        for (_, support) in ecdsa_pool.unvalidated().dealing_support() {
            let dealing = &support.content;
            let support_key = (
                dealing.idkg_dealing.transcript_id,
                dealing.idkg_dealing.dealer_id,
                support.signature.signer,
            );
            if !supports.insert(support_key) {
                duplicate_supports.insert(support_key);
            }
        }

        let mut ret = Vec::new();
        for (id, support) in ecdsa_pool.unvalidated().dealing_support() {
            let dealing = &support.content;
            let dealing_key = (
                dealing.idkg_dealing.transcript_id,
                dealing.idkg_dealing.dealer_id,
            );
            let support_key = (
                dealing.idkg_dealing.transcript_id,
                dealing.idkg_dealing.dealer_id,
                support.signature.signer,
            );

            // Remove the duplicate entries
            if duplicate_supports.contains(&support_key) {
                self.metrics
                    .pre_sign_errors_inc("duplicate_support_in_batch");
                ret.push(EcdsaChangeAction::HandleInvalid(
                    id,
                    format!("Duplicate support in unvalidated batch: {}", support),
                ));
                continue;
            }

            match Action::action(
                block_reader,
                &requested_transcripts,
                dealing.requested_height,
                &dealing.idkg_dealing.transcript_id,
            ) {
                Action::Process(transcript_params) => {
                    if transcript_params
                        .receivers()
                        .position(support.signature.signer)
                        .is_none()
                    {
                        // The node is not in the receiver list for this transcript,
                        // support share is not expected from it
                        self.metrics.pre_sign_errors_inc("unexpected_support");
                        ret.push(EcdsaChangeAction::HandleInvalid(
                            id,
                            format!("Support from unexpected node: {}", support),
                        ))
                    } else if !valid_dealings.contains(&dealing_key) {
                        // Support for a dealing we don't have yet, defer it
                        continue;
                    } else if self.has_node_issued_dealing_support(
                        ecdsa_pool,
                        &dealing.idkg_dealing.transcript_id,
                        &dealing.idkg_dealing.dealer_id,
                        &support.signature.signer,
                    ) {
                        // The node already sent a valid support for this dealing
                        self.metrics.pre_sign_errors_inc("duplicate_support");
                        ret.push(EcdsaChangeAction::HandleInvalid(
                            id,
                            format!("Duplicate support: {}", support),
                        ))
                    } else {
                        let mut changes =
                            self.crypto_verify_dealing_support(&id, transcript_params, support);
                        ret.append(&mut changes);
                    }
                }
                Action::Drop => ret.push(EcdsaChangeAction::RemoveUnvalidated(id)),
                Action::Defer => {}
            }
        }

        ret
    }

    /// Purges the entries no longer needed from the artifact pool
    fn purge_artifacts(
        &self,
        ecdsa_pool: &dyn EcdsaPool,
        block_reader: &dyn EcdsaBlockReader,
    ) -> EcdsaChangeSet {
        let requested_transcripts = resolve_transcript_refs(
            block_reader,
            "purge_artifacts",
            self.metrics.pre_sign_errors.clone(),
            &self.log,
        );

        let mut in_progress = BTreeSet::new();
        for transcript_params in requested_transcripts {
            in_progress.insert(transcript_params.transcript_id());
        }

        let mut ret = Vec::new();
        let current_height = block_reader.tip_height();

        // Unvalidated dealings.
        let mut action = ecdsa_pool
            .unvalidated()
            .signed_dealings()
            .filter(|(_, signed_dealing)| {
                self.should_purge(signed_dealing.get(), current_height, &in_progress)
            })
            .map(|(id, _)| EcdsaChangeAction::RemoveUnvalidated(id))
            .collect();
        ret.append(&mut action);

        // Validated dealings.
        let mut action = ecdsa_pool
            .validated()
            .signed_dealings()
            .filter(|(_, signed_dealing)| {
                self.should_purge(signed_dealing.get(), current_height, &in_progress)
            })
            .map(|(id, _)| EcdsaChangeAction::RemoveValidated(id))
            .collect();
        ret.append(&mut action);

        // Unvalidated dealing support.
        let mut action = ecdsa_pool
            .unvalidated()
            .dealing_support()
            .filter(|(_, support)| {
                self.should_purge(&support.content, current_height, &in_progress)
            })
            .map(|(id, _)| EcdsaChangeAction::RemoveUnvalidated(id))
            .collect();
        ret.append(&mut action);

        // Validated dealing support.
        let mut action = ecdsa_pool
            .validated()
            .dealing_support()
            .filter(|(_, support)| {
                self.should_purge(&support.content, current_height, &in_progress)
            })
            .map(|(id, _)| EcdsaChangeAction::RemoveValidated(id))
            .collect();
        ret.append(&mut action);

        ret
    }

    /// Helper to create dealing
    fn crypto_create_dealing(
        &self,
        ecdsa_pool: &dyn EcdsaPool,
        transcript_loader: &dyn EcdsaTranscriptLoader,
        block_reader: &dyn EcdsaBlockReader,
        transcript_params: &IDkgTranscriptParams,
    ) -> EcdsaChangeSet {
        if let Some(changes) = self.load_dependencies(
            ecdsa_pool,
            transcript_loader,
            transcript_params,
            block_reader.tip_height(),
        ) {
            return changes;
        }

        // Create the dealing
        let idkg_dealing = match IDkgProtocol::create_dealing(&*self.crypto, transcript_params) {
            Ok(idkg_dealing) => {
                self.metrics.pre_sign_metrics_inc("dealing_created");
                idkg_dealing
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
                return Default::default();
            }
        };

        // Corrupt the dealing if malicious testing is enabled
        #[cfg(feature = "malicious_code")]
        let idkg_dealing = self.crypto_corrupt_dealing(idkg_dealing, transcript_params);

        let ecdsa_dealing = EcdsaDealing {
            requested_height: block_reader.tip_height(),
            idkg_dealing,
        };

        // Sign the dealing
        match self.crypto.sign(
            &ecdsa_dealing,
            self.node_id,
            transcript_params.registry_version(),
        ) {
            Ok(signature) => {
                let signed_dealing = EcdsaSignedDealing {
                    signature,
                    content: ecdsa_dealing,
                };
                self.metrics.pre_sign_metrics_inc("dealing_sent");
                vec![EcdsaChangeAction::AddToValidated(
                    EcdsaMessage::EcdsaSignedDealing(signed_dealing),
                )]
            }
            Err(err) => {
                warn!(
                    self.log,
                    "Failed to sign dealing: transcript_id = {:?}, type = {:?}, error = {:?}",
                    transcript_params.transcript_id(),
                    transcript_op_summary(transcript_params.operation_type()),
                    err
                );
                self.metrics.pre_sign_errors_inc("sign_dealing");
                Default::default()
            }
        }
    }

    /// Helper to verify a dealing received for a transcript we are building
    fn crypto_verify_dealing(
        &self,
        id: &EcdsaMessageId,
        transcript_params: &IDkgTranscriptParams,
        signed_dealing: &EcdsaSignedDealing,
    ) -> EcdsaChangeSet {
        let dealing = signed_dealing.get();

        // Verify the dealer signature
        if let Err(error) = self
            .crypto
            .verify(signed_dealing, transcript_params.registry_version())
        {
            if error.is_replicated() {
                self.metrics
                    .pre_sign_errors_inc("verify_dealing_signature_permanent");
                return vec![EcdsaChangeAction::HandleInvalid(
                    id.clone(),
                    format!(
                        "Dealing signature validation(permanent error): {}, error = {:?}",
                        signed_dealing, error
                    ),
                )];
            } else {
                // Defer in case of transient errors
                debug!(
                    self.log,
                    "Dealing signature validation(transient error): {}, error = {:?}",
                    signed_dealing,
                    error
                );
                self.metrics
                    .pre_sign_errors_inc("verify_dealing_signature_transient");
                return Default::default();
            }
        }

        IDkgProtocol::verify_dealing_public(
            &*self.crypto,
            transcript_params,
            dealing.idkg_dealing.dealer_id,
            &dealing.idkg_dealing,
        )
        .map_or_else(
            |error| {
                if error.is_replicated() {
                    self.metrics.pre_sign_errors_inc("verify_dealing_permanent");
                    vec![EcdsaChangeAction::HandleInvalid(
                        id.clone(),
                        format!(
                            "Dealing validation(permanent error): {}, error = {:?}",
                            signed_dealing, error
                        ),
                    )]
                } else {
                    // Defer in case of transient errors
                    debug!(
                        self.log,
                        "Dealing validation(transient error): {}, error = {:?}",
                        signed_dealing,
                        error
                    );
                    self.metrics.pre_sign_errors_inc("verify_dealing_transient");
                    Default::default()
                }
            },
            |()| {
                self.metrics.pre_sign_metrics_inc("dealing_received");
                vec![EcdsaChangeAction::MoveToValidated(id.clone())]
            },
        )
    }

    /// Helper to corrupt the crypto dealing for malicious testing
    #[cfg(feature = "malicious_code")]
    fn crypto_corrupt_dealing(
        &self,
        idkg_dealing: IDkgDealing,
        transcript_params: &IDkgTranscriptParams,
    ) -> IDkgDealing {
        if !self.malicious_flags.maliciously_corrupt_ecdsa_dealings {
            return idkg_dealing;
        }

        let mut rng = rand::thread_rng();
        match ic_crypto_test_utils_canister_threshold_sigs::corrupt_idkg_dealing(
            &idkg_dealing,
            transcript_params,
            &mut rng,
        ) {
            Ok(dealing) => {
                warn!(
                     every_n_seconds => 2,
                     self.log,
                    "Corrupted dealing: transcript_id = {:?}", transcript_params.transcript_id()
                );
                self.metrics.pre_sign_metrics_inc("dealing_corrupted");
                dealing
            }
            Err(err) => {
                warn!(
                    self.log,
                    "Failed to corrupt dealing: transcript_id = {:?}, type = {:?}, error = {:?}",
                    transcript_params.transcript_id(),
                    transcript_op_summary(transcript_params.operation_type()),
                    err
                );
                self.metrics.pre_sign_errors_inc("corrupt_dealing");
                idkg_dealing
            }
        }
    }

    /// Helper to issue a support share for a dealing. Assumes we are a receiver
    /// for the dealing.
    fn crypto_create_dealing_support(
        &self,
        id: &EcdsaMessageId,
        transcript_params: &IDkgTranscriptParams,
        dealing: &EcdsaDealing,
    ) -> EcdsaChangeSet {
        if let Err(error) = IDkgProtocol::verify_dealing_private(
            &*self.crypto,
            transcript_params,
            dealing.idkg_dealing.dealer_id,
            &dealing.idkg_dealing,
        ) {
            if error.is_replicated() {
                self.metrics
                    .pre_sign_errors_inc("verify_dealing_private_permanent");
                return vec![EcdsaChangeAction::HandleInvalid(
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
            .sign(dealing, self.node_id, transcript_params.registry_version())
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
                    let dealing_support = EcdsaDealingSupport {
                        content: dealing.clone(),
                        signature: multi_sig_share,
                    };
                    self.metrics.pre_sign_metrics_inc("dealing_support_sent");
                    vec![EcdsaChangeAction::AddToValidated(
                        EcdsaMessage::EcdsaDealingSupport(dealing_support),
                    )]
                },
            )
    }

    /// Helper to verify a support share for a dealing
    fn crypto_verify_dealing_support(
        &self,
        id: &EcdsaMessageId,
        transcript_params: &IDkgTranscriptParams,
        support: &EcdsaDealingSupport,
    ) -> EcdsaChangeSet {
        self.crypto
            .verify(support, transcript_params.registry_version())
            .map_or_else(
                |error| {
                    self.metrics.pre_sign_errors_inc("verify_dealing_support");
                    vec![EcdsaChangeAction::HandleInvalid(
                        id.clone(),
                        format!(
                            "Support validation failed: {}, error = {:?}",
                            support, error
                        ),
                    )]
                },
                |_| {
                    self.metrics
                        .pre_sign_metrics_inc("dealing_support_received");
                    vec![EcdsaChangeAction::MoveToValidated(id.clone())]
                },
            )
    }

    /// Helper to load the transcripts the given transcript is dependent on.
    /// Returns true if the dependencies were loaded successfully.
    fn load_dependencies(
        &self,
        ecdsa_pool: &dyn EcdsaPool,
        transcript_loader: &dyn EcdsaTranscriptLoader,
        transcript_params: &IDkgTranscriptParams,
        height: Height,
    ) -> Option<EcdsaChangeSet> {
        match &transcript_params.operation_type() {
            IDkgTranscriptOperation::Random => None,
            IDkgTranscriptOperation::ReshareOfMasked(t) => {
                load_transcripts(ecdsa_pool, transcript_loader, &[t], height)
            }
            IDkgTranscriptOperation::ReshareOfUnmasked(t) => {
                load_transcripts(ecdsa_pool, transcript_loader, &[t], height)
            }
            IDkgTranscriptOperation::UnmaskedTimesMasked(t1, t2) => {
                load_transcripts(ecdsa_pool, transcript_loader, &[t1, t2], height)
            }
        }
    }

    /// Checks if the we have a valid dealing from the dealer for the given
    /// transcript
    fn has_dealer_issued_dealing(
        &self,
        ecdsa_pool: &dyn EcdsaPool,
        transcript_id: &IDkgTranscriptId,
        dealer_id: &NodeId,
    ) -> bool {
        ecdsa_pool
            .validated()
            .signed_dealings()
            .any(|(_, signed_dealing)| {
                let dealing = signed_dealing.get();
                dealing.idkg_dealing.dealer_id == *dealer_id
                    && dealing.idkg_dealing.transcript_id == *transcript_id
            })
    }

    /// Checks if the we have a valid dealing support from the node for the
    /// given dealing
    fn has_node_issued_dealing_support(
        &self,
        ecdsa_pool: &dyn EcdsaPool,
        transcript_id: &IDkgTranscriptId,
        dealer_id: &NodeId,
        node_id: &NodeId,
    ) -> bool {
        ecdsa_pool
            .validated()
            .dealing_support()
            .any(|(_, support)| {
                support.content.idkg_dealing.dealer_id == *dealer_id
                    && support.content.idkg_dealing.transcript_id == *transcript_id
                    && support.signature.signer == *node_id
            })
    }

    /// Checks if the dealing should be purged
    fn should_purge(
        &self,
        dealing: &EcdsaDealing,
        current_height: Height,
        in_progress: &BTreeSet<IDkgTranscriptId>,
    ) -> bool {
        dealing.requested_height <= current_height
            && !in_progress.contains(&dealing.idkg_dealing.transcript_id)
    }
}

impl EcdsaPreSigner for EcdsaPreSignerImpl {
    fn on_state_change(
        &self,
        ecdsa_pool: &dyn EcdsaPool,
        transcript_loader: &dyn EcdsaTranscriptLoader,
    ) -> EcdsaChangeSet {
        let block_reader = EcdsaBlockReaderImpl::new(self.consensus_block_cache.finalized_chain());
        let metrics = self.metrics.clone();

        let send_dealings = || {
            timed_call(
                "send_dealings",
                || self.send_dealings(ecdsa_pool, transcript_loader, &block_reader),
                &metrics.on_state_change_duration,
            )
        };
        let validate_dealings = || {
            timed_call(
                "validate_dealings",
                || self.validate_dealings(ecdsa_pool, &block_reader),
                &metrics.on_state_change_duration,
            )
        };
        let send_dealing_support = || {
            timed_call(
                "send_dealing_support",
                || self.send_dealing_support(ecdsa_pool, &block_reader),
                &metrics.on_state_change_duration,
            )
        };
        let validate_dealing_support = || {
            timed_call(
                "validate_dealing_support",
                || self.validate_dealing_support(ecdsa_pool, &block_reader),
                &metrics.on_state_change_duration,
            )
        };
        let purge_artifacts = || {
            timed_call(
                "purge_artifacts",
                || self.purge_artifacts(ecdsa_pool, &block_reader),
                &metrics.on_state_change_duration,
            )
        };

        let calls: [&'_ dyn Fn() -> EcdsaChangeSet; 5] = [
            &send_dealings,
            &validate_dealings,
            &send_dealing_support,
            &validate_dealing_support,
            &purge_artifacts,
        ];
        self.schedule.call_next(&calls)
    }
}

pub(crate) trait EcdsaTranscriptBuilder: Send {
    /// Returns the transcripts that can be successfully built from
    /// the current entries in the ECDSA pool
    fn get_completed_transcripts(
        &self,
        chain: Arc<dyn ConsensusBlockChain>,
        ecdsa_pool: &dyn EcdsaPool,
    ) -> Vec<IDkgTranscript>;
}

pub(crate) struct EcdsaTranscriptBuilderImpl<'a> {
    crypto: &'a dyn ConsensusCrypto,
    metrics: &'a EcdsaPayloadMetrics,
    log: ReplicaLogger,
}

impl<'a> EcdsaTranscriptBuilderImpl<'a> {
    pub(crate) fn new(
        crypto: &'a dyn ConsensusCrypto,
        metrics: &'a EcdsaPayloadMetrics,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            crypto,
            metrics,
            log,
        }
    }

    /// Helper to combine the multi sig shares for a dealing
    fn crypto_aggregate_dealing_support(
        &self,
        transcript_params: &IDkgTranscriptParams,
        support_shares: &[&EcdsaDealingSupport],
    ) -> Option<MultiSignature<EcdsaDealing>> {
        // Check if we have enough shares for aggregation
        if support_shares.len() < (transcript_params.verification_threshold().get() as usize) {
            return None;
        }

        let mut signatures = Vec::new();
        for support_share in support_shares {
            signatures.push(&support_share.signature);
        }

        self.crypto
            .aggregate(signatures, transcript_params.registry_version())
            .map_or_else(
                |error| {
                    debug!(
                        self.log,
                        "Failed to aggregate: transcript_id = {:?}, error = {:?}",
                        transcript_params.transcript_id(),
                        error
                    );
                    self.metrics.payload_errors_inc("aggregate_dealing_support");
                    None
                },
                |multi_sig| {
                    self.metrics
                        .payload_metrics_inc("dealing_support_aggregated");
                    Some(multi_sig)
                },
            )
    }

    /// Helper to create the transcript from the verified dealings
    fn crypto_create_transcript(
        &self,
        transcript_params: &IDkgTranscriptParams,
        verified_dealings: &BTreeMap<NodeId, IDkgMultiSignedDealing>,
    ) -> Option<IDkgTranscript> {
        // Check if we have enough dealings to create transcript
        if verified_dealings.len() < (transcript_params.collection_threshold().get() as usize) {
            return None;
        }

        IDkgProtocol::create_transcript(&*self.crypto, transcript_params, verified_dealings)
            .map_or_else(
                |error| {
                    warn!(
                        self.log,
                        "Failed to create transcript: transcript_id = {:?}, error = {:?}",
                        transcript_params.transcript_id(),
                        error
                    );
                    self.metrics.payload_errors_inc("create_transcript");
                    None
                },
                |transcript| {
                    self.metrics.payload_metrics_inc("transcript_created");
                    Some(transcript)
                },
            )
    }
}

impl<'a> EcdsaTranscriptBuilder for EcdsaTranscriptBuilderImpl<'a> {
    fn get_completed_transcripts(
        &self,
        chain: Arc<dyn ConsensusBlockChain>,
        ecdsa_pool: &dyn EcdsaPool,
    ) -> Vec<IDkgTranscript> {
        // TranscriptId -> TranscriptParams
        let block_reader = EcdsaBlockReaderImpl::new(chain);
        let requested_transcripts = resolve_transcript_refs(
            &block_reader,
            "get_completed_transcripts",
            self.metrics.payload_errors.clone(),
            &self.log,
        );

        let mut trancript_state_map = BTreeMap::new();
        for transcript_params in &requested_transcripts {
            trancript_state_map.insert(
                transcript_params.transcript_id(),
                TranscriptState::new(transcript_params),
            );
        }

        // Step 1: Build the verified dealings from the support shares
        for (_, signed_dealing) in ecdsa_pool.validated().signed_dealings() {
            let dealing = signed_dealing.get();
            let transcript_state =
                match trancript_state_map.get_mut(&dealing.idkg_dealing.transcript_id) {
                    Some(state) => state,
                    None => continue,
                };

            // Collect the shares for this dealing and aggregate the shares
            // TODO: do preprocessing to avoid repeated walking of the
            // support pool
            let support_shares: Vec<&EcdsaDealingSupport> = ecdsa_pool
                .validated()
                .dealing_support()
                .filter_map(|(_, support)| {
                    if support.content.idkg_dealing.transcript_id
                        == dealing.idkg_dealing.transcript_id
                        && support.content.idkg_dealing.dealer_id == dealing.idkg_dealing.dealer_id
                    {
                        Some(support)
                    } else {
                        None
                    }
                })
                .collect();

            if let Some(multi_sig) = self.crypto_aggregate_dealing_support(
                transcript_state.transcript_params,
                &support_shares,
            ) {
                transcript_state.add_completed_dealing(dealing, multi_sig);
            }
        }

        // Step 2: Build the transcripts from the verified dealings
        let mut completed_transcripts = Vec::new();
        for transcript_state in trancript_state_map.values() {
            if let Some(transcript) = self.crypto_create_transcript(
                transcript_state.transcript_params,
                &transcript_state.completed_dealings,
            ) {
                completed_transcripts.push(transcript);
            }
        }
        completed_transcripts
    }
}

/// Specifies how to handle a received message
#[derive(Eq, PartialEq)]
enum Action<'a> {
    /// The message is relevant to our current state, process it
    /// immediately. The transcript params for this transcript
    /// (as specified by the finalized block) is the argument
    Process(&'a IDkgTranscriptParams),

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
        block_reader: &'a dyn EcdsaBlockReader,
        requested_transcripts: &'a [IDkgTranscriptParams],
        msg_height: Height,
        msg_transcript_id: &IDkgTranscriptId,
    ) -> Action<'a> {
        if msg_height > block_reader.tip_height() {
            // Message is from a node ahead of us, keep it to be
            // processed later
            return Action::Defer;
        }

        for transcript_params in requested_transcripts {
            if *msg_transcript_id == transcript_params.transcript_id() {
                return Action::Process(transcript_params);
            }
        }

        // Its for a transcript that has not been requested, drop it
        Action::Drop
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
                    transcript_params.transcript_id()
                )
            }
            Self::Defer => write!(f, "Action::Defer"),
            Self::Drop => write!(f, "Action::Drop"),
        }
    }
}

/// Helper to hold the per-transcript state during the transcript
/// building process
struct TranscriptState<'a> {
    transcript_params: &'a IDkgTranscriptParams,
    completed_dealings: BTreeMap<NodeId, IDkgMultiSignedDealing>,
}

impl<'a> TranscriptState<'a> {
    fn new(transcript_params: &'a IDkgTranscriptParams) -> Self {
        Self {
            transcript_params,
            completed_dealings: BTreeMap::new(),
        }
    }

    // Adds a completed dealing to the transcript state. The dealing
    // is stored in the IDkgMultiSignedDealing format
    fn add_completed_dealing(
        &mut self,
        dealing: &'a EcdsaDealing,
        multi_sig: MultiSignature<EcdsaDealing>,
    ) {
        let verified_dealing = EcdsaVerifiedDealing {
            content: dealing.clone(),
            signature: multi_sig,
        };
        self.completed_dealings
            .insert(dealing.idkg_dealing.dealer_id, verified_dealing.into());
    }
}

/// Resolves the IDkgTranscriptParamsRef -> IDkgTranscriptParams
fn resolve_transcript_refs(
    block_reader: &dyn EcdsaBlockReader,
    reason: &str,
    metric: IntCounterVec,
    log: &ReplicaLogger,
) -> Vec<IDkgTranscriptParams> {
    let mut ret = Vec::new();
    for transcript_params_ref in block_reader.requested_transcripts() {
        // Translate the IDkgTranscriptParamsRef -> IDkgTranscriptParams
        match transcript_params_ref.translate(block_reader) {
            Ok(transcript_params) => {
                ret.push(transcript_params);
            }
            Err(error) => {
                warn!(
                    log,
                    "Failed to translate transcript ref: reason = {}, \
                     transcript_params_ref = {:?}, error = {:?}",
                    reason,
                    transcript_params_ref,
                    error
                );
                metric.with_label_values(&[reason]).inc();
            }
        }
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecdsa::utils::test_utils::*;
    use ic_ecdsa_object::EcdsaObject;
    use ic_interfaces::artifact_pool::UnvalidatedArtifact;
    use ic_interfaces::ecdsa::MutableEcdsaPool;
    use ic_interfaces::time_source::TimeSource;
    use ic_test_utilities::types::ids::{NODE_1, NODE_2, NODE_3, NODE_4};
    use ic_test_utilities::with_test_replica_logger;
    use ic_test_utilities::FastForwardTimeSource;
    use ic_types::Height;

    // Tests the Action logic
    #[test]
    fn test_ecdsa_pre_signer_action() {
        let (id_1, id_2, id_3, id_4) = (
            create_transcript_id(1),
            create_transcript_id(2),
            create_transcript_id(3),
            create_transcript_id(4),
        );

        // The finalized block requests transcripts 1, 2, 3
        let nodes = [NODE_1];
        let block_reader = TestEcdsaBlockReader::for_pre_signer_test(
            Height::from(100),
            vec![
                create_transcript_param(id_1, &nodes, &nodes),
                create_transcript_param(id_2, &nodes, &nodes),
                create_transcript_param(id_3, &nodes, &nodes),
            ],
        );
        let mut requested = Vec::new();
        for transcript_params_ref in block_reader.requested_transcripts() {
            requested.push(transcript_params_ref.translate(&block_reader).unwrap());
        }

        // Message from a node ahead of us
        assert_eq!(
            Action::action(&block_reader, &requested, Height::from(200), &id_4),
            Action::Defer
        );

        // Messages for transcripts not being currently requested
        assert_eq!(
            Action::action(
                &block_reader,
                &requested,
                Height::from(100),
                &create_transcript_id(234)
            ),
            Action::Drop
        );
        assert_eq!(
            Action::action(
                &block_reader,
                &requested,
                Height::from(10),
                &create_transcript_id(234)
            ),
            Action::Drop
        );

        // Messages for transcripts currently requested
        let action = Action::action(&block_reader, &requested, Height::from(100), &id_1);
        match action {
            Action::Process(_) => {}
            _ => panic!("Unexpected action: {:?}", action),
        }

        let action = Action::action(&block_reader, &requested, Height::from(10), &id_2);
        match action {
            Action::Process(_) => {}
            _ => panic!("Unexpected action: {:?}", action),
        }
    }

    // Tests that dealings are sent for new transcripts, and requests already
    // in progress are filtered out.
    #[test]
    fn test_ecdsa_send_dealings() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut ecdsa_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let (id_1, id_2, id_3, id_4, id_5) = (
                    create_transcript_id(1),
                    create_transcript_id(2),
                    create_transcript_id(3),
                    create_transcript_id(4),
                    create_transcript_id(5),
                );

                // Set up the ECDSA pool. Pool has dealings for transcripts 1, 2, 3.
                // Only dealing for transcript 1 is issued by us.
                let dealing_1 = create_dealing(id_1, NODE_1);
                let dealing_2 = create_dealing(id_2, NODE_2);
                let dealing_3 = create_dealing(id_3, NODE_3);
                let change_set = vec![
                    EcdsaChangeAction::AddToValidated(EcdsaMessage::EcdsaSignedDealing(dealing_1)),
                    EcdsaChangeAction::AddToValidated(EcdsaMessage::EcdsaSignedDealing(dealing_2)),
                    EcdsaChangeAction::AddToValidated(EcdsaMessage::EcdsaSignedDealing(dealing_3)),
                ];
                ecdsa_pool.apply_changes(change_set);

                // Set up the transcript creation request
                // The block requests transcripts 1, 4, 5
                let t1 = create_transcript_param(id_1, &[NODE_1], &[NODE_2]);
                let t2 = create_transcript_param(id_4, &[NODE_1], &[NODE_3]);
                let t3 = create_transcript_param(id_5, &[NODE_1], &[NODE_4]);
                let block_reader =
                    TestEcdsaBlockReader::for_pre_signer_test(Height::from(100), vec![t1, t2, t3]);
                let transcript_loader: TestEcdsaTranscriptLoader = Default::default();

                // Since transcript 1 is already in progress, we should issue
                // dealings only for transcripts 4, 5
                let change_set =
                    pre_signer.send_dealings(&ecdsa_pool, &transcript_loader, &block_reader);
                assert_eq!(change_set.len(), 2);
                assert!(is_dealing_added_to_validated(
                    &change_set,
                    &id_4,
                    block_reader.tip_height()
                ));
                assert!(is_dealing_added_to_validated(
                    &change_set,
                    &id_5,
                    block_reader.tip_height()
                ));
            })
        })
    }

    // Tests that dealing is not issued if the node is in the list of dealers
    // specified by the transcript params
    #[test]
    fn test_ecdsa_non_dealers_dont_send_dealings() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (ecdsa_pool, pre_signer) = create_pre_signer_dependencies(pool_config, logger);
                let (id_1, id_2) = (create_transcript_id(1), create_transcript_id(2));

                // transcript 1 has NODE_1 as a dealer
                let t1 = create_transcript_param(id_1, &[NODE_1], &[NODE_1]);

                // Transcript 2 doesn't have NODE_1 as a dealer
                let t2 = create_transcript_param(id_2, &[NODE_2], &[NODE_2]);

                // Transcript 2 should not result in a dealing
                let block_reader =
                    TestEcdsaBlockReader::for_pre_signer_test(Height::from(100), vec![t1, t2]);
                let transcript_loader: TestEcdsaTranscriptLoader = Default::default();

                let change_set =
                    pre_signer.send_dealings(&ecdsa_pool, &transcript_loader, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_dealing_added_to_validated(
                    &change_set,
                    &id_1,
                    block_reader.tip_height()
                ));
            })
        })
    }

    // Tests that complaints are generated and added to the pool if loading transcript
    // results in complaints.
    #[test]
    fn test_ecdsa_send_dealings_with_complaints() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (ecdsa_pool, pre_signer) = create_pre_signer_dependencies(pool_config, logger);
                let (id_1, id_2, id_3) = (
                    create_transcript_id(1),
                    create_transcript_id(2),
                    create_transcript_id(3),
                );

                // Set up the transcript creation request
                // The block requests transcripts 1, 2, 3
                let t1 = create_transcript_param(id_1, &[NODE_1], &[NODE_2]);
                let t2 = create_transcript_param(id_2, &[NODE_1], &[NODE_3]);
                let t3 = create_transcript_param(id_3, &[NODE_1], &[NODE_4]);
                let block_reader =
                    TestEcdsaBlockReader::for_pre_signer_test(Height::from(100), vec![t1, t2, t3]);
                let transcript_loader =
                    TestEcdsaTranscriptLoader::new(TestTranscriptLoadStatus::Complaints);

                let change_set =
                    pre_signer.send_dealings(&ecdsa_pool, &transcript_loader, &block_reader);
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

    // Tests that received dealings are accepted/processed for eligible transcript
    // requests, and others dealings are either deferred or dropped.
    // TODO: mock crypto and test failure path
    #[test]
    fn test_ecdsa_validate_dealings() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut ecdsa_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let time_source = FastForwardTimeSource::new();
                let (id_1, id_2, id_3, id_4) = (
                    create_transcript_id(1),
                    create_transcript_id(2),
                    create_transcript_id(3),
                    create_transcript_id(4),
                );

                // Set up the transcript creation request
                // The block requests transcripts 2, 3
                let t2 = create_transcript_param(id_2, &[NODE_2], &[NODE_1]);
                let t3 = create_transcript_param(id_3, &[NODE_2], &[NODE_1]);
                let block_reader =
                    TestEcdsaBlockReader::for_pre_signer_test(Height::from(100), vec![t2, t3]);

                // Set up the ECDSA pool
                // A dealing from a node ahead of us (deferred)
                let mut dealing = create_dealing(id_1, NODE_2);
                dealing.content.requested_height = Height::from(200);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSignedDealing(dealing),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                // A dealing for a transcript that is requested by finalized block (accepted)
                let mut dealing = create_dealing(id_2, NODE_2);
                dealing.content.requested_height = Height::from(100);
                let key = dealing.key();
                let msg_id_2 = EcdsaSignedDealing::key_to_outer_hash(&key);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSignedDealing(dealing),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                // A dealing for a transcript that is requested by finalized block (accepted)
                let mut dealing = create_dealing(id_3, NODE_2);
                dealing.content.requested_height = Height::from(10);
                let key = dealing.key();
                let msg_id_3 = EcdsaSignedDealing::key_to_outer_hash(&key);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSignedDealing(dealing),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                // A dealing for a transcript that is not requested by finalized block (dropped)
                let mut dealing = create_dealing(id_4, NODE_2);
                dealing.content.requested_height = Height::from(5);
                let key = dealing.key();
                let msg_id_4 = EcdsaSignedDealing::key_to_outer_hash(&key);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSignedDealing(dealing),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                let change_set = pre_signer.validate_dealings(&ecdsa_pool, &block_reader);
                assert_eq!(change_set.len(), 3);
                assert!(is_moved_to_validated(&change_set, &msg_id_2));
                assert!(is_moved_to_validated(&change_set, &msg_id_3));
                assert!(is_removed_from_unvalidated(&change_set, &msg_id_4));
            })
        })
    }

    // Tests that duplicate dealings from a dealer for the same transcript
    // are dropped.
    #[test]
    fn test_ecdsa_duplicate_dealing() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut ecdsa_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let time_source = FastForwardTimeSource::new();
                let id_2 = create_transcript_id(2);

                // Set up the ECDSA pool
                // Validated pool has: {transcript 2, dealer = NODE_2}
                let dealing = create_dealing(id_2, NODE_2);
                let change_set = vec![EcdsaChangeAction::AddToValidated(
                    EcdsaMessage::EcdsaSignedDealing(dealing),
                )];
                ecdsa_pool.apply_changes(change_set);

                // Unvalidated pool has: {transcript 2, dealer = NODE_2, height = 100}
                let mut dealing = create_dealing(id_2, NODE_2);
                dealing.content.requested_height = Height::from(100);
                let key = dealing.key();
                let msg_id_2 = EcdsaSignedDealing::key_to_outer_hash(&key);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSignedDealing(dealing),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                let t2 = create_transcript_param(id_2, &[NODE_2], &[NODE_1]);
                let block_reader =
                    TestEcdsaBlockReader::for_pre_signer_test(Height::from(100), vec![t2]);

                let change_set = pre_signer.validate_dealings(&ecdsa_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_handle_invalid(&change_set, &msg_id_2));
            })
        })
    }

    // Tests that duplicate dealings from a dealer for the same transcript
    // in the unvalidated pool are dropped.
    #[test]
    fn test_ecdsa_duplicate_dealing_in_batch() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut ecdsa_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let time_source = FastForwardTimeSource::new();
                let id_2 = create_transcript_id(2);

                // Set up the ECDSA pool
                // Unvalidated pool has: {transcript 2, dealer = NODE_2, height = 100}
                let mut dealing = create_dealing(id_2, NODE_2);
                dealing.content.requested_height = Height::from(100);
                let key = dealing.key();
                let msg_id_2_a = EcdsaSignedDealing::key_to_outer_hash(&key);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSignedDealing(dealing),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                // Unvalidated pool has: {transcript 2, dealer = NODE_2, height = 10}
                let mut dealing = create_dealing(id_2, NODE_2);
                dealing.content.requested_height = Height::from(10);
                let key = dealing.key();
                let msg_id_2_b = EcdsaSignedDealing::key_to_outer_hash(&key);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSignedDealing(dealing),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                // Unvalidated pool has: {transcript 2, dealer = NODE_3, height = 90}
                let mut dealing = create_dealing(id_2, NODE_3);
                dealing.content.requested_height = Height::from(90);
                let key = dealing.key();
                let msg_id_3 = EcdsaSignedDealing::key_to_outer_hash(&key);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSignedDealing(dealing),
                    peer_id: NODE_3,
                    timestamp: time_source.get_relative_time(),
                });

                let t2 = create_transcript_param(id_2, &[NODE_2, NODE_3], &[NODE_1]);
                let block_reader =
                    TestEcdsaBlockReader::for_pre_signer_test(Height::from(100), vec![t2]);

                // msg_id_2_a, msg_id_2_a should be dropped as duplicates
                let change_set = pre_signer.validate_dealings(&ecdsa_pool, &block_reader);
                assert_eq!(change_set.len(), 3);
                assert!(is_handle_invalid(&change_set, &msg_id_2_a));
                assert!(is_handle_invalid(&change_set, &msg_id_2_b));
                assert!(is_moved_to_validated(&change_set, &msg_id_3));
            })
        })
    }

    // Tests that dealings from a dealer that is not in the dealer list for the
    // transcript are dropped.
    #[test]
    fn test_ecdsa_unexpected_dealing() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut ecdsa_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let time_source = FastForwardTimeSource::new();
                let id_2 = create_transcript_id(2);

                // Unvalidated pool has: {transcript 2, dealer = NODE_2, height = 100}
                let mut dealing = create_dealing(id_2, NODE_2);
                dealing.content.requested_height = Height::from(100);
                let key = dealing.key();
                let msg_id_2 = EcdsaSignedDealing::key_to_outer_hash(&key);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSignedDealing(dealing),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                // NODE_2 is not in the dealer list
                let t2 = create_transcript_param(id_2, &[NODE_3], &[NODE_1]);
                let block_reader =
                    TestEcdsaBlockReader::for_pre_signer_test(Height::from(100), vec![t2]);

                let change_set = pre_signer.validate_dealings(&ecdsa_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_handle_invalid(&change_set, &msg_id_2));
            })
        })
    }

    // Tests that support shares are sent to eligible dealings
    #[test]
    fn test_ecdsa_send_support() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut ecdsa_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let id = create_transcript_id(1);

                // We haven't sent support yet, and we are in the receiver list
                let dealing = create_dealing(id, NODE_2);
                let change_set = vec![EcdsaChangeAction::AddToValidated(
                    EcdsaMessage::EcdsaSignedDealing(dealing),
                )];
                ecdsa_pool.apply_changes(change_set);
                let t = create_transcript_param(id, &[NODE_2], &[NODE_1]);

                let block_reader =
                    TestEcdsaBlockReader::for_pre_signer_test(Height::from(100), vec![t]);
                let change_set = pre_signer.send_dealing_support(&ecdsa_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_dealing_support_added_to_validated(
                    &change_set,
                    &id,
                    &NODE_2,
                ));
                ecdsa_pool.apply_changes(change_set);

                // Since we already issued support for the dealing, it should not produce any
                // more support.
                let change_set = pre_signer.send_dealing_support(&ecdsa_pool, &block_reader);
                assert!(change_set.is_empty());
            })
        })
    }

    // Tests that support shares are not sent by nodes not in the receiver list for
    // the transcript
    #[test]
    fn test_ecdsa_non_receivers_dont_send_support() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut ecdsa_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let id = create_transcript_id(1);

                // We are not in the receiver list for the transcript
                let dealing = create_dealing(id, NODE_2);
                let change_set = vec![EcdsaChangeAction::AddToValidated(
                    EcdsaMessage::EcdsaSignedDealing(dealing),
                )];
                ecdsa_pool.apply_changes(change_set);
                let t = create_transcript_param(id, &[NODE_2], &[NODE_3]);

                let block_reader =
                    TestEcdsaBlockReader::for_pre_signer_test(Height::from(100), vec![t]);
                let change_set = pre_signer.send_dealing_support(&ecdsa_pool, &block_reader);
                assert!(change_set.is_empty());
            })
        })
    }

    // Tests that support shares are not sent for transcripts we are not building
    #[test]
    fn test_ecdsa_no_support_for_missing_transcript_params() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut ecdsa_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let id = create_transcript_id(1);

                let dealing = create_dealing(id, NODE_2);
                let change_set = vec![EcdsaChangeAction::AddToValidated(
                    EcdsaMessage::EcdsaSignedDealing(dealing),
                )];
                ecdsa_pool.apply_changes(change_set);

                let block_reader =
                    TestEcdsaBlockReader::for_pre_signer_test(Height::from(100), vec![]);
                let change_set = pre_signer.send_dealing_support(&ecdsa_pool, &block_reader);
                assert!(change_set.is_empty());
            })
        })
    }

    // Tests that received support shares are accepted/processed for eligible
    // transcript requests, and others dealings are either deferred or dropped.
    #[test]
    fn test_ecdsa_validate_dealing_support() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut ecdsa_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let time_source = FastForwardTimeSource::new();
                let (id_1, id_2, id_3, id_4) = (
                    create_transcript_id(1),
                    create_transcript_id(2),
                    create_transcript_id(3),
                    create_transcript_id(4),
                );

                // Set up the transcript creation request
                // The block requests transcripts 2, 3
                let t2 = create_transcript_param(id_2, &[NODE_2], &[NODE_3]);
                let t3 = create_transcript_param(id_3, &[NODE_2], &[NODE_3]);
                let block_reader =
                    TestEcdsaBlockReader::for_pre_signer_test(Height::from(100), vec![t2, t3]);

                // Set up the ECDSA pool
                // A share from a node ahead of us (share deferred)
                let mut support = create_support(id_1, NODE_2, NODE_3);
                support.content.requested_height = Height::from(200);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaDealingSupport(support),
                    peer_id: NODE_3,
                    timestamp: time_source.get_relative_time(),
                });

                // A dealing for a transcript that is requested by finalized block,
                // and we already have the dealing(share accepted)
                let mut dealing = create_dealing(id_2, NODE_2);
                dealing.content.requested_height = Height::from(25);
                let change_set = vec![EcdsaChangeAction::AddToValidated(
                    EcdsaMessage::EcdsaSignedDealing(dealing),
                )];
                ecdsa_pool.apply_changes(change_set);

                let mut support = create_support(id_2, NODE_2, NODE_3);
                support.content.requested_height = Height::from(25);
                let key = support.key();
                let msg_id_2 = EcdsaDealingSupport::key_to_outer_hash(&key);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaDealingSupport(support),
                    peer_id: NODE_3,
                    timestamp: time_source.get_relative_time(),
                });

                // A dealing for a transcript that is requested by finalized block,
                // but we don't have the dealing yet(share deferred)
                let mut support = create_support(id_3, NODE_2, NODE_3);
                support.content.requested_height = Height::from(10);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaDealingSupport(support),
                    peer_id: NODE_3,
                    timestamp: time_source.get_relative_time(),
                });

                // A dealing for a transcript that is not requested by finalized block
                // (share dropped)
                let mut support = create_support(id_4, NODE_2, NODE_3);
                support.content.requested_height = Height::from(5);
                let key = support.key();
                let msg_id_4 = EcdsaDealingSupport::key_to_outer_hash(&key);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaDealingSupport(support),
                    peer_id: NODE_3,
                    timestamp: time_source.get_relative_time(),
                });

                let change_set = pre_signer.validate_dealing_support(&ecdsa_pool, &block_reader);
                assert_eq!(change_set.len(), 2);
                assert!(is_moved_to_validated(&change_set, &msg_id_2));
                assert!(is_removed_from_unvalidated(&change_set, &msg_id_4));
            })
        })
    }

    // Tests that duplicate support from a node for the same dealing
    // are dropped.
    #[test]
    fn test_ecdsa_duplicate_support_from_node() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut ecdsa_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let time_source = FastForwardTimeSource::new();
                let id = create_transcript_id(1);

                // Set up the ECDSA pool
                // Validated pool has: support {transcript 2, dealer = NODE_2, signer = NODE_3}
                let dealing = create_dealing(id, NODE_2);
                let change_set = vec![EcdsaChangeAction::AddToValidated(
                    EcdsaMessage::EcdsaSignedDealing(dealing),
                )];
                ecdsa_pool.apply_changes(change_set);

                let support = create_support(id, NODE_2, NODE_3);
                let change_set = vec![EcdsaChangeAction::AddToValidated(
                    EcdsaMessage::EcdsaDealingSupport(support),
                )];
                ecdsa_pool.apply_changes(change_set);

                // Unvalidated pool has: support {transcript 2, dealer = NODE_2, signer =
                // NODE_3}
                let mut support = create_support(id, NODE_2, NODE_3);
                support.content.requested_height = Height::from(100);
                let key = support.key();
                let msg_id = EcdsaDealingSupport::key_to_outer_hash(&key);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaDealingSupport(support),
                    peer_id: NODE_3,
                    timestamp: time_source.get_relative_time(),
                });

                let t = create_transcript_param(id, &[NODE_2], &[NODE_3]);
                let block_reader =
                    TestEcdsaBlockReader::for_pre_signer_test(Height::from(100), vec![t]);

                let change_set = pre_signer.validate_dealing_support(&ecdsa_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_handle_invalid(&change_set, &msg_id));
            })
        })
    }

    // Tests that duplicate support from a node for the same dealing
    // in the unvalidated pool are dropped.
    #[test]
    fn test_ecdsa_duplicate_support_from_node_in_batch() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut ecdsa_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let time_source = FastForwardTimeSource::new();
                let id = create_transcript_id(1);

                // Set up the ECDSA pool
                // Unvalidated pool has: support {transcript 2, dealer = NODE_2, signer =
                // NODE_3}
                let mut support = create_support(id, NODE_2, NODE_3);
                support.content.requested_height = Height::from(100);
                let key = support.key();
                let msg_id_1_a = EcdsaDealingSupport::key_to_outer_hash(&key);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaDealingSupport(support),
                    peer_id: NODE_3,
                    timestamp: time_source.get_relative_time(),
                });

                // Unvalidated pool has: support {transcript 2, dealer = NODE_2, signer =
                // NODE_3}
                let mut support = create_support(id, NODE_2, NODE_3);
                support.content.requested_height = Height::from(10);
                let key = support.key();
                let msg_id_1_b = EcdsaDealingSupport::key_to_outer_hash(&key);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaDealingSupport(support),
                    peer_id: NODE_3,
                    timestamp: time_source.get_relative_time(),
                });

                // Unvalidated pool has: support {transcript 2, dealer = NODE_2, signer =
                // NODE_4}
                let dealing = create_dealing(id, NODE_2);
                let change_set = vec![EcdsaChangeAction::AddToValidated(
                    EcdsaMessage::EcdsaSignedDealing(dealing),
                )];
                ecdsa_pool.apply_changes(change_set);

                let mut support = create_support(id, NODE_2, NODE_4);
                support.content.requested_height = Height::from(10);
                let key = support.key();
                let msg_id_2 = EcdsaDealingSupport::key_to_outer_hash(&key);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaDealingSupport(support),
                    peer_id: NODE_4,
                    timestamp: time_source.get_relative_time(),
                });

                let t = create_transcript_param(id, &[NODE_2], &[NODE_3, NODE_4]);
                let block_reader =
                    TestEcdsaBlockReader::for_pre_signer_test(Height::from(100), vec![t]);

                let change_set = pre_signer.validate_dealing_support(&ecdsa_pool, &block_reader);
                assert_eq!(change_set.len(), 3);
                assert!(is_handle_invalid(&change_set, &msg_id_1_a));
                assert!(is_handle_invalid(&change_set, &msg_id_1_b));
                assert!(is_moved_to_validated(&change_set, &msg_id_2));
            })
        })
    }

    // Tests that support from a node that is not in the receiver list for the
    // transcript are dropped.
    #[test]
    fn test_ecdsa_unexpected_support_from_node() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut ecdsa_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let time_source = FastForwardTimeSource::new();
                let id = create_transcript_id(1);

                // Unvalidated pool has: support {transcript 2, dealer = NODE_2, signer =
                // NODE_3}
                let mut support = create_support(id, NODE_2, NODE_3);
                support.content.requested_height = Height::from(10);
                let key = support.key();
                let msg_id = EcdsaDealingSupport::key_to_outer_hash(&key);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaDealingSupport(support),
                    peer_id: NODE_3,
                    timestamp: time_source.get_relative_time(),
                });

                // NODE_3 is not in the receiver list
                let t = create_transcript_param(id, &[NODE_2], &[NODE_4]);
                let block_reader =
                    TestEcdsaBlockReader::for_pre_signer_test(Height::from(100), vec![t]);
                let change_set = pre_signer.validate_dealing_support(&ecdsa_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_handle_invalid(&change_set, &msg_id));
            })
        })
    }

    // Tests purging of dealings from unvalidated pool
    #[test]
    fn test_ecdsa_purge_unvalidated_dealings() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut ecdsa_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let time_source = FastForwardTimeSource::new();
                let (id_1, id_2, id_3) = (
                    create_transcript_id(1),
                    create_transcript_id(2),
                    create_transcript_id(3),
                );

                // Dealing 1: height <= current_height, in_progress (not purged)
                let mut dealing_1 = create_dealing(id_1, NODE_2);
                dealing_1.content.requested_height = Height::from(20);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSignedDealing(dealing_1),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                // Dealing 2: height <= current_height, !in_progress (purged)
                let mut dealing_2 = create_dealing(id_2, NODE_2);
                dealing_2.content.requested_height = Height::from(20);
                let key = dealing_2.key();
                let msg_id_2 = EcdsaSignedDealing::key_to_outer_hash(&key);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSignedDealing(dealing_2),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                // Dealing 3: height > current_height (not purged)
                let mut dealing_3 = create_dealing(id_3, NODE_2);
                dealing_3.content.requested_height = Height::from(200);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSignedDealing(dealing_3),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                let t = create_transcript_param(id_1, &[NODE_2], &[NODE_4]);
                let block_reader =
                    TestEcdsaBlockReader::for_pre_signer_test(Height::from(100), vec![t]);
                let change_set = pre_signer.purge_artifacts(&ecdsa_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_unvalidated(&change_set, &msg_id_2));
            })
        })
    }

    // Tests purging of dealings from validated pool
    #[test]
    fn test_ecdsa_purge_validated_dealings() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut ecdsa_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let (id_1, id_2, id_3) = (
                    create_transcript_id(1),
                    create_transcript_id(2),
                    create_transcript_id(3),
                );

                // Dealing 1: height <= current_height, in_progress (not purged)
                let mut dealing_1 = create_dealing(id_1, NODE_2);
                dealing_1.content.requested_height = Height::from(20);

                // Dealing 2: height <= current_height, !in_progress (purged)
                let mut dealing_2 = create_dealing(id_2, NODE_2);
                dealing_2.content.requested_height = Height::from(20);
                let key = dealing_2.key();
                let msg_id_2 = EcdsaSignedDealing::key_to_outer_hash(&key);

                // Dealing 3: height > current_height (not purged)
                let mut dealing_3 = create_dealing(id_3, NODE_2);
                dealing_3.content.requested_height = Height::from(200);

                let change_set = vec![
                    EcdsaChangeAction::AddToValidated(EcdsaMessage::EcdsaSignedDealing(dealing_1)),
                    EcdsaChangeAction::AddToValidated(EcdsaMessage::EcdsaSignedDealing(dealing_2)),
                    EcdsaChangeAction::AddToValidated(EcdsaMessage::EcdsaSignedDealing(dealing_3)),
                ];
                ecdsa_pool.apply_changes(change_set);

                let t = create_transcript_param(id_1, &[NODE_2], &[NODE_4]);
                let block_reader =
                    TestEcdsaBlockReader::for_pre_signer_test(Height::from(100), vec![t]);
                let change_set = pre_signer.purge_artifacts(&ecdsa_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_validated(&change_set, &msg_id_2));
            })
        })
    }

    // Tests purging of dealing support from unvalidated pool
    #[test]
    fn test_ecdsa_purge_unvalidated_dealing_support() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut ecdsa_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let time_source = FastForwardTimeSource::new();
                let (id_1, id_2, id_3) = (
                    create_transcript_id(1),
                    create_transcript_id(2),
                    create_transcript_id(3),
                );

                // Support 1: height <= current_height, in_progress (not purged)
                let mut support_1 = create_support(id_1, NODE_2, NODE_3);
                support_1.content.requested_height = Height::from(20);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaDealingSupport(support_1),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                // Dealing 2: height <= current_height, !in_progress (purged)
                let mut support_2 = create_support(id_2, NODE_2, NODE_3);
                support_2.content.requested_height = Height::from(20);
                let key = support_2.key();
                let msg_id_2 = EcdsaDealingSupport::key_to_outer_hash(&key);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaDealingSupport(support_2),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                // Dealing 3: height > current_height (not purged)
                let mut support_3 = create_support(id_3, NODE_2, NODE_3);
                support_3.content.requested_height = Height::from(200);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaDealingSupport(support_3),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                let t = create_transcript_param(id_1, &[NODE_2], &[NODE_4]);
                let block_reader =
                    TestEcdsaBlockReader::for_pre_signer_test(Height::from(100), vec![t]);
                let change_set = pre_signer.purge_artifacts(&ecdsa_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_unvalidated(&change_set, &msg_id_2));
            })
        })
    }

    // Tests purging of dealing support from validated pool
    #[test]
    fn test_ecdsa_purge_validated_dealing_support() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut ecdsa_pool, pre_signer) =
                    create_pre_signer_dependencies(pool_config, logger);
                let (id_1, id_2, id_3) = (
                    create_transcript_id(1),
                    create_transcript_id(2),
                    create_transcript_id(3),
                );

                // Support 1: height <= current_height, in_progress (not purged)
                let mut support_1 = create_support(id_1, NODE_2, NODE_3);
                support_1.content.requested_height = Height::from(20);

                // Dealing 2: height <= current_height, !in_progress (purged)
                let mut support_2 = create_support(id_2, NODE_2, NODE_3);
                support_2.content.requested_height = Height::from(20);
                let key = support_2.key();
                let msg_id_2 = EcdsaDealingSupport::key_to_outer_hash(&key);

                // Dealing 3: height > current_height (not purged)
                let mut support_3 = create_support(id_3, NODE_2, NODE_3);
                support_3.content.requested_height = Height::from(200);

                let change_set = vec![
                    EcdsaChangeAction::AddToValidated(EcdsaMessage::EcdsaDealingSupport(support_1)),
                    EcdsaChangeAction::AddToValidated(EcdsaMessage::EcdsaDealingSupport(support_2)),
                    EcdsaChangeAction::AddToValidated(EcdsaMessage::EcdsaDealingSupport(support_3)),
                ];
                ecdsa_pool.apply_changes(change_set);

                let t = create_transcript_param(id_1, &[NODE_2], &[NODE_4]);
                let block_reader =
                    TestEcdsaBlockReader::for_pre_signer_test(Height::from(100), vec![t]);
                let change_set = pre_signer.purge_artifacts(&ecdsa_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_validated(&change_set, &msg_id_2));
            })
        })
    }
}
