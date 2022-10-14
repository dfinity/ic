//! The signature process manager

use crate::consensus::{
    metrics::{timed_call, EcdsaPayloadMetrics, EcdsaSignerMetrics},
    utils::RoundRobin,
    ConsensusCrypto,
};
use crate::ecdsa::complaints::EcdsaTranscriptLoader;
use crate::ecdsa::utils::{load_transcripts, EcdsaBlockReaderImpl};
use ic_interfaces::consensus_pool::ConsensusBlockCache;
use ic_interfaces::crypto::{
    ErrorReproducibility, ThresholdEcdsaSigVerifier, ThresholdEcdsaSigner,
};
use ic_interfaces::ecdsa::{EcdsaChangeAction, EcdsaChangeSet, EcdsaPool};
use ic_logger::{debug, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_types::artifact::EcdsaMessageId;
use ic_types::consensus::ecdsa::{
    sig_share_prefix, EcdsaBlockReader, EcdsaMessage, EcdsaSigShare, EcdsaStats, RequestId,
    ThresholdEcdsaSigInputsRef,
};
use ic_types::crypto::canister_threshold_sig::{
    error::ThresholdEcdsaCombineSigSharesError, ThresholdEcdsaCombinedSignature,
    ThresholdEcdsaSigInputs, ThresholdEcdsaSigShare,
};
use ic_types::{Height, NodeId};

use prometheus::IntCounterVec;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

pub(crate) trait EcdsaSigner: Send {
    /// The on_state_change() called from the main ECDSA path.
    fn on_state_change(
        &self,
        ecdsa_pool: &dyn EcdsaPool,
        transcript_loader: &dyn EcdsaTranscriptLoader,
    ) -> EcdsaChangeSet;
}

pub(crate) struct EcdsaSignerImpl {
    node_id: NodeId,
    consensus_block_cache: Arc<dyn ConsensusBlockCache>,
    crypto: Arc<dyn ConsensusCrypto>,
    schedule: RoundRobin,
    metrics: EcdsaSignerMetrics,
    log: ReplicaLogger,
}

impl EcdsaSignerImpl {
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
            metrics: EcdsaSignerMetrics::new(metrics_registry),
            log,
        }
    }

    /// Generates signature shares for the newly added signature requests
    fn send_signature_shares(
        &self,
        ecdsa_pool: &dyn EcdsaPool,
        transcript_loader: &dyn EcdsaTranscriptLoader,
        block_reader: &dyn EcdsaBlockReader,
    ) -> EcdsaChangeSet {
        block_reader
            .requested_signatures()
            .filter(|(request_id, _)| {
                !self.signer_has_issued_signature_share(ecdsa_pool, &self.node_id, request_id)
            })
            .flat_map(|(request_id, sig_inputs_ref)| {
                self.resolve_ref(sig_inputs_ref, block_reader, "send_signature_shares")
                    .map_or(Default::default(), |sig_inputs| {
                        self.crypto_create_signature_share(
                            ecdsa_pool,
                            transcript_loader,
                            request_id,
                            &sig_inputs,
                        )
                    })
            })
            .collect()
    }

    /// Processes the received signature shares
    fn validate_signature_shares(
        &self,
        ecdsa_pool: &dyn EcdsaPool,
        block_reader: &dyn EcdsaBlockReader,
    ) -> EcdsaChangeSet {
        let sig_inputs_map = block_reader
            .requested_signatures()
            .map(|(request_id, sig_inputs)| (*request_id, sig_inputs))
            .collect::<BTreeMap<_, _>>();

        // Collection of validated shares
        let mut validated_sig_shares = BTreeSet::new();

        let mut ret = Vec::new();
        for (id, share) in ecdsa_pool.unvalidated().signature_shares() {
            // Remove the duplicate entries
            let key = (share.request_id, share.signer_id);
            if validated_sig_shares.contains(&key) {
                self.metrics
                    .sign_errors_inc("duplicate_sig_shares_in_batch");
                ret.push(EcdsaChangeAction::HandleInvalid(
                    id,
                    format!("Duplicate share in unvalidated batch: {}", share),
                ));
                continue;
            }

            match Action::action(block_reader, &sig_inputs_map, &share.request_id) {
                Action::Process(sig_inputs_ref) => {
                    if self.signer_has_issued_signature_share(
                        ecdsa_pool,
                        &share.signer_id,
                        &share.request_id,
                    ) {
                        // The node already sent a valid share for this request
                        self.metrics.sign_errors_inc("duplicate_sig_share");
                        ret.push(EcdsaChangeAction::HandleInvalid(
                            id,
                            format!("Duplicate share: {}", share),
                        ))
                    } else {
                        match self.resolve_ref(
                            sig_inputs_ref,
                            block_reader,
                            "validate_signature_shares",
                        ) {
                            Some(sig_inputs) => {
                                let action = self.crypto_verify_signature_share(
                                    &id,
                                    &sig_inputs,
                                    &share,
                                    ecdsa_pool.stats(),
                                );
                                if let Some(EcdsaChangeAction::MoveToValidated(_)) = action {
                                    validated_sig_shares.insert(key);
                                }
                                ret.append(&mut action.into_iter().collect());
                            }
                            None => {
                                ret.push(EcdsaChangeAction::HandleInvalid(
                                    id,
                                    format!(
                                        "validate_signature_shares(): failed to translate: {}",
                                        share
                                    ),
                                ));
                            }
                        }
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
        let in_progress = block_reader
            .requested_signatures()
            .map(|(request_id, _)| *request_id)
            .collect::<BTreeSet<_>>();

        let mut ret = Vec::new();
        let current_height = block_reader.tip_height();

        // Unvalidated signature shares.
        let mut action = ecdsa_pool
            .unvalidated()
            .signature_shares()
            .filter(|(_, share)| self.should_purge(share, current_height, &in_progress))
            .map(|(id, _)| EcdsaChangeAction::RemoveUnvalidated(id))
            .collect();
        ret.append(&mut action);

        // Validated signature shares.
        let mut action = ecdsa_pool
            .validated()
            .signature_shares()
            .filter(|(_, share)| self.should_purge(share, current_height, &in_progress))
            .map(|(id, _)| EcdsaChangeAction::RemoveValidated(id))
            .collect();
        ret.append(&mut action);

        ret
    }

    /// Load necessary transcripts for the inputs
    fn load_dependencies(
        &self,
        ecdsa_pool: &dyn EcdsaPool,
        transcript_loader: &dyn EcdsaTranscriptLoader,
        inputs: &ThresholdEcdsaSigInputs,
    ) -> Option<EcdsaChangeSet> {
        load_transcripts(
            ecdsa_pool,
            transcript_loader,
            &[
                inputs.presig_quadruple().kappa_unmasked(),
                inputs.presig_quadruple().lambda_masked(),
                inputs.presig_quadruple().kappa_times_lambda(),
                inputs.presig_quadruple().key_times_lambda(),
                inputs.key_transcript(),
            ],
        )
    }

    /// Helper to create the signature share
    fn crypto_create_signature_share(
        &self,
        ecdsa_pool: &dyn EcdsaPool,
        transcript_loader: &dyn EcdsaTranscriptLoader,
        request_id: &RequestId,
        sig_inputs: &ThresholdEcdsaSigInputs,
    ) -> EcdsaChangeSet {
        if let Some(changes) = self.load_dependencies(ecdsa_pool, transcript_loader, sig_inputs) {
            return changes;
        }

        ThresholdEcdsaSigner::sign_share(&*self.crypto, sig_inputs).map_or_else(
            |error| {
                warn!(
                    self.log,
                    "Failed to create share: request_id = {:?}, {:?}", request_id, error
                );
                self.metrics.sign_errors_inc("create_sig_share");
                Default::default()
            },
            |share| {
                let sig_share = EcdsaSigShare {
                    signer_id: self.node_id,
                    request_id: *request_id,
                    share,
                };
                self.metrics.sign_metrics_inc("sig_shares_sent");
                vec![EcdsaChangeAction::AddToValidated(
                    EcdsaMessage::EcdsaSigShare(sig_share),
                )]
            },
        )
    }

    /// Helper to verify the signature share
    fn crypto_verify_signature_share(
        &self,
        id: &EcdsaMessageId,
        sig_inputs: &ThresholdEcdsaSigInputs,
        share: &EcdsaSigShare,
        stats: &dyn EcdsaStats,
    ) -> Option<EcdsaChangeAction> {
        let start = std::time::Instant::now();
        let ret = ThresholdEcdsaSigVerifier::verify_sig_share(
            &*self.crypto,
            share.signer_id,
            sig_inputs,
            &share.share,
        );
        stats.record_sig_share_validation(&share.request_id, start.elapsed());

        ret.map_or_else(
            |error| {
                if error.is_reproducible() {
                    self.metrics.sign_errors_inc("verify_sig_share_permanent");
                    Some(EcdsaChangeAction::HandleInvalid(
                        id.clone(),
                        format!(
                            "Share validation(permanent error): {}, error = {:?}",
                            share, error
                        ),
                    ))
                } else {
                    // Defer in case of transient errors
                    debug!(
                        self.log,
                        "Share validation(permanent error): {}, error = {:?}", share, error
                    );
                    self.metrics.sign_errors_inc("verify_sig_share_transient");
                    None
                }
            },
            |()| {
                self.metrics.sign_metrics_inc("sig_shares_received");
                Some(EcdsaChangeAction::MoveToValidated(id.clone()))
            },
        )
    }

    /// Checks if the signer node has already issued a signature share for the
    /// request
    fn signer_has_issued_signature_share(
        &self,
        ecdsa_pool: &dyn EcdsaPool,
        signer_id: &NodeId,
        request_id: &RequestId,
    ) -> bool {
        let prefix = sig_share_prefix(request_id, signer_id);
        ecdsa_pool
            .validated()
            .signature_shares_by_prefix(prefix)
            .any(|(_, share)| share.request_id == *request_id && share.signer_id == *signer_id)
    }

    /// Checks if the signature share should be purged
    fn should_purge(
        &self,
        share: &EcdsaSigShare,
        current_height: Height,
        in_progress: &BTreeSet<RequestId>,
    ) -> bool {
        share.request_id.height <= current_height && !in_progress.contains(&share.request_id)
    }

    /// Resolves the ThresholdEcdsaSigInputsRef -> ThresholdEcdsaSigInputs
    fn resolve_ref(
        &self,
        sig_inputs_ref: &ThresholdEcdsaSigInputsRef,
        block_reader: &dyn EcdsaBlockReader,
        reason: &str,
    ) -> Option<ThresholdEcdsaSigInputs> {
        let _timer = self
            .metrics
            .on_state_change_duration
            .with_label_values(&["resolve_transcript_refs"])
            .start_timer();
        match sig_inputs_ref.translate(block_reader) {
            Ok(sig_inputs) => {
                self.metrics.sign_metrics_inc("resolve_transcript_refs");
                Some(sig_inputs)
            }
            Err(error) => {
                warn!(
                    self.log,
                    "Failed to resolve sig input ref: reason = {}, \
                     sig_inputs_ref = {:?}, error = {:?}",
                    reason,
                    sig_inputs_ref,
                    error
                );
                self.metrics.sign_errors_inc("resolve_transcript_refs");
                None
            }
        }
    }
}

impl EcdsaSigner for EcdsaSignerImpl {
    fn on_state_change(
        &self,
        ecdsa_pool: &dyn EcdsaPool,
        transcript_loader: &dyn EcdsaTranscriptLoader,
    ) -> EcdsaChangeSet {
        let block_reader = EcdsaBlockReaderImpl::new(self.consensus_block_cache.finalized_chain());
        let metrics = self.metrics.clone();
        ecdsa_pool
            .stats()
            .update_active_signature_requests(&block_reader);

        let send_signature_shares = || {
            timed_call(
                "send_signature_shares",
                || self.send_signature_shares(ecdsa_pool, transcript_loader, &block_reader),
                &metrics.on_state_change_duration,
            )
        };
        let validate_signature_shares = || {
            timed_call(
                "validate_signature_shares",
                || self.validate_signature_shares(ecdsa_pool, &block_reader),
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

        let calls: [&'_ dyn Fn() -> EcdsaChangeSet; 3] = [
            &send_signature_shares,
            &validate_signature_shares,
            &purge_artifacts,
        ];
        self.schedule.call_next(&calls)
    }
}

pub(crate) trait EcdsaSignatureBuilder {
    /// Returns the specified signature if it can be successfully
    /// built from the current sig shares in the ECDSA pool
    fn get_completed_signature(
        &self,
        request_id: &RequestId,
    ) -> Option<ThresholdEcdsaCombinedSignature>;
}

pub(crate) struct EcdsaSignatureBuilderImpl<'a> {
    block_reader: &'a dyn EcdsaBlockReader,
    crypto: &'a dyn ConsensusCrypto,
    ecdsa_pool: &'a dyn EcdsaPool,
    metrics: &'a EcdsaPayloadMetrics,
    log: ReplicaLogger,
}

impl<'a> EcdsaSignatureBuilderImpl<'a> {
    pub(crate) fn new(
        block_reader: &'a dyn EcdsaBlockReader,
        crypto: &'a dyn ConsensusCrypto,
        ecdsa_pool: &'a dyn EcdsaPool,
        metrics: &'a EcdsaPayloadMetrics,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            crypto,
            ecdsa_pool,
            block_reader,
            metrics,
            log,
        }
    }

    fn crypto_combine_signature_shares(
        &self,
        request_id: &RequestId,
        inputs: &ThresholdEcdsaSigInputs,
        shares: &BTreeMap<NodeId, ThresholdEcdsaSigShare>,
        stats: &dyn EcdsaStats,
    ) -> Option<ThresholdEcdsaCombinedSignature> {
        let start = std::time::Instant::now();
        let ret = ThresholdEcdsaSigVerifier::combine_sig_shares(&*self.crypto, inputs, shares);
        stats.record_sig_share_aggregation(request_id, start.elapsed());

        ret.map_or_else(
            |error| {
                match error {
                    ThresholdEcdsaCombineSigSharesError::UnsatisfiedReconstructionThreshold {
                        threshold: _,
                        share_count: _,
                    } => (),
                    _ => {
                        warn!(
                            self.log,
                            "Failed to combine signature shares: request_id = {:?}, {:?}",
                            request_id,
                            error
                        );
                        self.metrics.payload_errors_inc("combine_sig_share");
                    }
                };
                Default::default()
            },
            |combined_signature| {
                self.metrics.payload_metrics_inc("signatures_completed");
                Some(combined_signature)
            },
        )
    }
}

impl<'a> EcdsaSignatureBuilder for EcdsaSignatureBuilderImpl<'a> {
    fn get_completed_signature(
        &self,
        request_id: &RequestId,
    ) -> Option<ThresholdEcdsaCombinedSignature> {
        // Find the sig inputs for the request and translate the refs.
        let (request_id, sig_inputs_ref) = self
            .block_reader
            .requested_signatures()
            .find(|(cur_request_id, _)| **cur_request_id == *request_id)?;
        let sig_inputs = match sig_inputs_ref.translate(self.block_reader) {
            Ok(sig_inputs) => sig_inputs,
            Err(error) => {
                warn!(
                    self.log,
                    "get_completed_signature(): translate failed: sig_inputs_ref = {:?}, error = {:?}",
                    sig_inputs_ref,
                    error
                );
                self.metrics.payload_errors_inc("sig_inputs_translate");
                return None;
            }
        };

        // Collect the signature shares for the request.
        let mut sig_shares = BTreeMap::new();
        for (_, share) in self.ecdsa_pool.validated().signature_shares() {
            if share.request_id == *request_id {
                sig_shares.insert(share.signer_id, share.share.clone());
            }
        }

        // Combine the signatures.
        self.crypto_combine_signature_shares(
            request_id,
            &sig_inputs,
            &sig_shares,
            self.ecdsa_pool.stats(),
        )
    }
}

/// Specifies how to handle a received share
#[derive(Eq, PartialEq)]
enum Action<'a> {
    /// The message is relevant to our current state, process it
    /// immediately. The transcript params for this transcript
    /// (as specified by the finalized block) is the argument
    Process(&'a ThresholdEcdsaSigInputsRef),

    /// Keep it to be processed later (e.g) this is from a node
    /// ahead of us
    Defer,

    /// Don't need it
    Drop,
}

impl<'a> Action<'a> {
    /// Decides the action to take on a received message with the given
    /// height/RequestId
    #[allow(clippy::self_named_constructors)]
    fn action(
        block_reader: &'a dyn EcdsaBlockReader,
        requested_signatures: &'a BTreeMap<RequestId, &'a ThresholdEcdsaSigInputsRef>,
        msg_request_id: &RequestId,
    ) -> Action<'a> {
        let msg_height = msg_request_id.height;
        if msg_height > block_reader.tip_height() {
            // Message is from a node ahead of us, keep it to be
            // processed later
            return Action::Defer;
        }

        match requested_signatures.get(msg_request_id) {
            Some(sig_inputs_ref) => Action::Process(sig_inputs_ref),
            None => {
                // Its for a signature that has not been requested, drop it
                Action::Drop
            }
        }
    }
}

impl<'a> Debug for Action<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self {
            Self::Process(sig_inputs) => {
                write!(
                    f,
                    "Action::Process(): caller = {:?}",
                    sig_inputs.derivation_path.caller
                )
            }
            Self::Defer => write!(f, "Action::Defer"),
            Self::Drop => write!(f, "Action::Drop"),
        }
    }
}

/// Resolves the ThresholdEcdsaSigInputsRef -> ThresholdEcdsaSigInputs
fn resolve_sig_inputs_refs(
    block_reader: &dyn EcdsaBlockReader,
    reason: &str,
    metric: IntCounterVec,
    log: &ReplicaLogger,
) -> Vec<(RequestId, ThresholdEcdsaSigInputs)> {
    let mut ret = Vec::new();
    for (request_id, sig_inputs_ref) in block_reader.requested_signatures() {
        // Translate the ThresholdEcdsaSigInputsRef -> ThresholdEcdsaSigInputs
        match sig_inputs_ref.translate(block_reader) {
            Ok(sig_inputs) => {
                ret.push((*request_id, sig_inputs));
            }
            Err(error) => {
                warn!(
                    log,
                    "Failed to resolve sig input ref: reason = {}, \
                     sig_inputs_ref = {:?}, error = {:?}",
                    reason,
                    sig_inputs_ref,
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
    use ic_test_utilities::types::ids::{subnet_test_id, NODE_1, NODE_2, NODE_3};
    use ic_test_utilities::FastForwardTimeSource;
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_types::consensus::ecdsa::*;
    use ic_types::Height;

    fn create_request_id(generator: &mut EcdsaUIDGenerator, height: Height) -> RequestId {
        let quadruple_id = generator.next_quadruple_id();
        let pseudo_random_id = [0; 32];
        RequestId {
            quadruple_id,
            pseudo_random_id,
            height,
        }
    }

    // Tests the Action logic
    #[test]
    fn test_ecdsa_signer_action() {
        let mut uid_generator = EcdsaUIDGenerator::new(subnet_test_id(1), Height::new(0));
        let height = Height::from(100);
        let (id_1, id_2, id_3, id_4) = (
            create_request_id(&mut uid_generator, height),
            create_request_id(&mut uid_generator, Height::from(10)),
            create_request_id(&mut uid_generator, height),
            create_request_id(&mut uid_generator, Height::from(200)),
        );

        // The finalized block requests signatures 1, 2, 3
        let block_reader = TestEcdsaBlockReader::for_signer_test(
            height,
            vec![
                (id_1, create_sig_inputs(1)),
                (id_2, create_sig_inputs(2)),
                (id_3, create_sig_inputs(3)),
            ],
        );
        let mut requested = BTreeMap::new();
        for (request_id, sig_inputs_ref) in block_reader.requested_signatures() {
            requested.insert(*request_id, sig_inputs_ref);
        }

        // Message from a node ahead of us
        assert_eq!(
            Action::action(&block_reader, &requested, &id_4),
            Action::Defer
        );

        // Messages for transcripts not being currently requested
        assert_eq!(
            Action::action(
                &block_reader,
                &requested,
                &create_request_id(&mut uid_generator, Height::from(100),)
            ),
            Action::Drop
        );
        assert_eq!(
            Action::action(
                &block_reader,
                &requested,
                &create_request_id(&mut uid_generator, Height::from(10),)
            ),
            Action::Drop
        );

        // Messages for signatures currently requested
        let action = Action::action(&block_reader, &requested, &id_1);
        match action {
            Action::Process(_) => {}
            _ => panic!("Unexpected action: {:?}", action),
        }

        let action = Action::action(&block_reader, &requested, &id_2);
        match action {
            Action::Process(_) => {}
            _ => panic!("Unexpected action: {:?}", action),
        }
    }

    // Tests that signature shares are sent for new requests, and requests already
    // in progress are filtered out.
    #[test]
    fn test_ecdsa_send_signature_shares() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut ecdsa_pool, signer) = create_signer_dependencies(pool_config, logger);
                let mut uid_generator = EcdsaUIDGenerator::new(subnet_test_id(1), Height::new(0));
                let height = Height::from(100);
                let (id_1, id_2, id_3, id_4, id_5) = (
                    create_request_id(&mut uid_generator, height),
                    create_request_id(&mut uid_generator, height),
                    create_request_id(&mut uid_generator, height),
                    create_request_id(&mut uid_generator, height),
                    create_request_id(&mut uid_generator, height),
                );

                // Set up the ECDSA pool. Pool has shares for requests 1, 2, 3.
                // Only the share for request 1 is issued by us
                let share_1 = create_signature_share(NODE_1, id_1);
                let share_2 = create_signature_share(NODE_2, id_2);
                let share_3 = create_signature_share(NODE_3, id_3);
                let change_set = vec![
                    EcdsaChangeAction::AddToValidated(EcdsaMessage::EcdsaSigShare(share_1)),
                    EcdsaChangeAction::AddToValidated(EcdsaMessage::EcdsaSigShare(share_2)),
                    EcdsaChangeAction::AddToValidated(EcdsaMessage::EcdsaSigShare(share_3)),
                ];
                ecdsa_pool.apply_changes(change_set);

                // Set up the signature requests
                // The block requests signatures 1, 4, 5
                let block_reader = TestEcdsaBlockReader::for_signer_test(
                    Height::from(100),
                    vec![
                        (id_1, create_sig_inputs(1)),
                        (id_4, create_sig_inputs(4)),
                        (id_5, create_sig_inputs(5)),
                    ],
                );
                let transcript_loader: TestEcdsaTranscriptLoader = Default::default();

                // Since request 1 is already in progress, we should issue
                // shares only for transcripts 4, 5
                let change_set =
                    signer.send_signature_shares(&ecdsa_pool, &transcript_loader, &block_reader);
                assert_eq!(change_set.len(), 2);
                assert!(is_signature_share_added_to_validated(
                    &change_set,
                    &id_4,
                    block_reader.tip_height()
                ));
                assert!(is_signature_share_added_to_validated(
                    &change_set,
                    &id_5,
                    block_reader.tip_height()
                ));
            })
        })
    }

    // Tests that complaints are generated and added to the pool if loading transcript
    // results in complaints.
    #[test]
    fn test_ecdsa_send_signature_shares_with_complaints() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (ecdsa_pool, signer) = create_signer_dependencies(pool_config, logger);
                let mut uid_generator = EcdsaUIDGenerator::new(subnet_test_id(1), Height::new(0));
                let height = Height::from(100);
                let (id_1, id_2, id_3) = (
                    create_request_id(&mut uid_generator, height),
                    create_request_id(&mut uid_generator, height),
                    create_request_id(&mut uid_generator, height),
                );

                // Set up the signature requests
                // The block requests signatures 1, 2, 3
                let block_reader = TestEcdsaBlockReader::for_signer_test(
                    height,
                    vec![
                        (id_1, create_sig_inputs(1)),
                        (id_2, create_sig_inputs(2)),
                        (id_3, create_sig_inputs(3)),
                    ],
                );
                let transcript_loader =
                    TestEcdsaTranscriptLoader::new(TestTranscriptLoadStatus::Complaints);

                let change_set =
                    signer.send_signature_shares(&ecdsa_pool, &transcript_loader, &block_reader);
                let complaints = transcript_loader.returned_complaints();
                assert_eq!(change_set.len(), complaints.len());
                assert_eq!(change_set.len(), 15);
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

    // Tests that received dealings are accepted/processed for eligible signature
    // requests, and others dealings are either deferred or dropped.
    #[test]
    fn test_ecdsa_validate_signature_shares() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut ecdsa_pool, signer) = create_signer_dependencies(pool_config, logger);
                let mut uid_generator = EcdsaUIDGenerator::new(subnet_test_id(1), Height::new(0));
                let time_source = FastForwardTimeSource::new();
                let height = Height::from(100);
                let (id_1, id_2, id_3, id_4) = (
                    create_request_id(&mut uid_generator, Height::from(200)),
                    create_request_id(&mut uid_generator, height),
                    create_request_id(&mut uid_generator, Height::from(10)),
                    create_request_id(&mut uid_generator, Height::from(5)),
                );

                // Set up the transcript creation request
                // The block requests transcripts 2, 3
                let block_reader = TestEcdsaBlockReader::for_signer_test(
                    height,
                    vec![(id_2, create_sig_inputs(2)), (id_3, create_sig_inputs(3))],
                );

                // Set up the ECDSA pool
                // A share from a node ahead of us (deferred)
                let share = create_signature_share(NODE_2, id_1);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSigShare(share),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                // A share for a request in the finalized block (accepted)
                let share = create_signature_share(NODE_2, id_2);
                let msg_id_2 = share.message_id();
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSigShare(share),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                // A share for a request in the finalized block (accepted)
                let share = create_signature_share(NODE_2, id_3);
                let msg_id_3 = share.message_id();
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSigShare(share),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                // A share for a request not in the finalized block (dropped)
                let share = create_signature_share(NODE_2, id_4);
                let msg_id_4 = share.message_id();
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSigShare(share),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                let change_set = signer.validate_signature_shares(&ecdsa_pool, &block_reader);
                assert_eq!(change_set.len(), 3);
                assert!(is_moved_to_validated(&change_set, &msg_id_2));
                assert!(is_moved_to_validated(&change_set, &msg_id_3));
                assert!(is_removed_from_unvalidated(&change_set, &msg_id_4));
            })
        })
    }

    // Tests that duplicate shares from a signer for the same request
    // are dropped.
    #[test]
    fn test_ecdsa_duplicate_signature_shares() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut ecdsa_pool, signer) = create_signer_dependencies(pool_config, logger);
                let mut uid_generator = EcdsaUIDGenerator::new(subnet_test_id(1), Height::new(0));
                let time_source = FastForwardTimeSource::new();
                let id_2 = create_request_id(&mut uid_generator, Height::from(100));

                // Set up the ECDSA pool
                // Validated pool has: {signature share 2, signer = NODE_2}
                let share = create_signature_share(NODE_2, id_2);
                let change_set = vec![EcdsaChangeAction::AddToValidated(
                    EcdsaMessage::EcdsaSigShare(share),
                )];
                ecdsa_pool.apply_changes(change_set);

                // Unvalidated pool has: {signature share 2, signer = NODE_2, height = 100}
                let share = create_signature_share(NODE_2, id_2);
                let msg_id_2 = share.message_id();
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSigShare(share),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                let block_reader = TestEcdsaBlockReader::for_signer_test(
                    Height::from(100),
                    vec![(id_2, create_sig_inputs(2))],
                );

                let change_set = signer.validate_signature_shares(&ecdsa_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_handle_invalid(&change_set, &msg_id_2));
            })
        })
    }

    // Tests that duplicate shares from a signer for the same request
    // in the unvalidated pool are dropped.
    #[test]
    fn test_ecdsa_duplicate_signature_shares_in_batch() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut ecdsa_pool, signer) = create_signer_dependencies(pool_config, logger);
                let mut uid_generator = EcdsaUIDGenerator::new(subnet_test_id(1), Height::new(0));
                let time_source = FastForwardTimeSource::new();
                let id_1 = create_request_id(&mut uid_generator, Height::from(100));

                // Unvalidated pool has: {signature share 1, signer = NODE_2}
                let share = create_signature_share_with_nonce(NODE_2, id_1, 0);
                let msg_id_1 = share.message_id();
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSigShare(share),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                // Unvalidated pool has: {signature share 2, signer = NODE_2}
                let share = create_signature_share_with_nonce(NODE_2, id_1, 1);
                let msg_id_2 = share.message_id();
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSigShare(share),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                // Unvalidated pool has: {signature share 2, signer = NODE_3}
                let share = create_signature_share_with_nonce(NODE_3, id_1, 2);
                let msg_id_3 = share.message_id();
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSigShare(share),
                    peer_id: NODE_3,
                    timestamp: time_source.get_relative_time(),
                });

                let block_reader = TestEcdsaBlockReader::for_signer_test(
                    Height::from(100),
                    vec![(id_1, create_sig_inputs(2))],
                );

                let change_set = signer.validate_signature_shares(&ecdsa_pool, &block_reader);
                assert_eq!(change_set.len(), 3);
                // One is considered duplicate
                assert!(is_handle_invalid(&change_set, &msg_id_1));
                // One is considered validated
                assert!(is_moved_to_validated(&change_set, &msg_id_2));
                assert!(is_moved_to_validated(&change_set, &msg_id_3));
            })
        })
    }

    // Tests purging of signature shares from unvalidated pool
    #[test]
    fn test_ecdsa_purge_unvalidated_signature_shares() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut ecdsa_pool, signer) = create_signer_dependencies(pool_config, logger);
                let mut uid_generator = EcdsaUIDGenerator::new(subnet_test_id(1), Height::new(0));
                let time_source = FastForwardTimeSource::new();
                let (id_1, id_2, id_3) = (
                    create_request_id(&mut uid_generator, Height::from(10)),
                    create_request_id(&mut uid_generator, Height::from(20)),
                    create_request_id(&mut uid_generator, Height::from(200)),
                );

                // Set up the transcript creation request
                // The block requests transcripts 1, 3
                let block_reader = TestEcdsaBlockReader::for_signer_test(
                    Height::from(100),
                    vec![(id_1, create_sig_inputs(1)), (id_3, create_sig_inputs(3))],
                );

                // Share 1: height <= current_height, in_progress (not purged)
                let share = create_signature_share(NODE_2, id_1);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSigShare(share),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                // Share 2: height <= current_height, !in_progress (purged)
                let share = create_signature_share(NODE_2, id_2);
                let msg_id_2 = share.message_id();
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSigShare(share),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                // Share 3: height > current_height (not purged)
                let share = create_signature_share(NODE_2, id_3);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSigShare(share),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                let change_set = signer.purge_artifacts(&ecdsa_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_unvalidated(&change_set, &msg_id_2));
            })
        })
    }

    // Tests purging of signature shares from validated pool
    #[test]
    fn test_ecdsa_purge_validated_signature_shares() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut ecdsa_pool, signer) = create_signer_dependencies(pool_config, logger);
                let mut uid_generator = EcdsaUIDGenerator::new(subnet_test_id(1), Height::new(0));
                let (id_1, id_2, id_3) = (
                    create_request_id(&mut uid_generator, Height::from(10)),
                    create_request_id(&mut uid_generator, Height::from(20)),
                    create_request_id(&mut uid_generator, Height::from(200)),
                );

                // Set up the transcript creation request
                // The block requests transcripts 1, 3
                let block_reader = TestEcdsaBlockReader::for_signer_test(
                    Height::from(100),
                    vec![(id_1, create_sig_inputs(1)), (id_3, create_sig_inputs(3))],
                );

                // Share 1: height <= current_height, in_progress (not purged)
                let share = create_signature_share(NODE_2, id_1);
                let change_set = vec![EcdsaChangeAction::AddToValidated(
                    EcdsaMessage::EcdsaSigShare(share),
                )];
                ecdsa_pool.apply_changes(change_set);

                // Share 2: height <= current_height, !in_progress (purged)
                let share = create_signature_share(NODE_2, id_2);
                let msg_id_2 = share.message_id();
                let change_set = vec![EcdsaChangeAction::AddToValidated(
                    EcdsaMessage::EcdsaSigShare(share),
                )];
                ecdsa_pool.apply_changes(change_set);

                // Share 3: height > current_height (not purged)
                let share = create_signature_share(NODE_2, id_3);
                let change_set = vec![EcdsaChangeAction::AddToValidated(
                    EcdsaMessage::EcdsaSigShare(share),
                )];
                ecdsa_pool.apply_changes(change_set);

                let change_set = signer.purge_artifacts(&ecdsa_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_validated(&change_set, &msg_id_2));
            })
        })
    }
}
