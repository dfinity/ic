//! The signature process manager

use crate::idkg::complaints::IDkgTranscriptLoader;
use crate::idkg::metrics::{timed_call, IDkgPayloadMetrics, ThresholdSignerMetrics};
use crate::idkg::utils::{load_transcripts, IDkgBlockReaderImpl};
use ic_consensus_utils::crypto::ConsensusCrypto;
use ic_consensus_utils::RoundRobin;
use ic_interfaces::consensus_pool::ConsensusBlockCache;
use ic_interfaces::crypto::{
    ErrorReproducibility, ThresholdEcdsaSigVerifier, ThresholdEcdsaSigner,
    ThresholdSchnorrSigVerifier, ThresholdSchnorrSigner,
};
use ic_interfaces::idkg::{IDkgChangeAction, IDkgChangeSet, IDkgPool};
use ic_interfaces_state_manager::{CertifiedStateSnapshot, StateReader};
use ic_logger::{debug, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_replicated_state::metadata_state::subnet_call_context_manager::SignWithThresholdContext;
use ic_replicated_state::ReplicatedState;
use ic_types::artifact::IDkgMessageId;
use ic_types::consensus::idkg::common::{
    CombinedSignature, SignatureScheme, ThresholdSigInputs, ThresholdSigInputsRef,
};
use ic_types::consensus::idkg::{
    ecdsa_sig_share_prefix, EcdsaSigShare, IDkgBlockReader, IDkgMessage, IDkgStats, RequestId,
};
use ic_types::consensus::idkg::{schnorr_sig_share_prefix, SchnorrSigShare, SigShare};
use ic_types::crypto::canister_threshold_sig::error::ThresholdEcdsaCombineSigSharesError;
use ic_types::crypto::canister_threshold_sig::error::{
    ThresholdEcdsaCreateSigShareError, ThresholdEcdsaVerifySigShareError,
    ThresholdSchnorrCombineSigSharesError, ThresholdSchnorrCreateSigShareError,
    ThresholdSchnorrVerifySigShareError,
};
use ic_types::{Height, NodeId};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use super::utils::{build_signature_inputs, get_context_request_id, update_purge_height};

#[derive(Clone, Debug)]
#[allow(dead_code)]
enum CreateSigShareError {
    Ecdsa(ThresholdEcdsaCreateSigShareError),
    Schnorr(ThresholdSchnorrCreateSigShareError),
}

#[derive(Clone, Debug)]
enum VerifySigShareError {
    Ecdsa(ThresholdEcdsaVerifySigShareError),
    Schnorr(ThresholdSchnorrVerifySigShareError),
    ThresholdSchemeMismatch,
}

impl VerifySigShareError {
    fn is_reproducible(&self) -> bool {
        match self {
            VerifySigShareError::Ecdsa(err) => err.is_reproducible(),
            VerifySigShareError::Schnorr(err) => err.is_reproducible(),
            VerifySigShareError::ThresholdSchemeMismatch => true,
        }
    }
}

#[derive(Clone, Debug)]
enum CombineSigSharesError {
    Ecdsa(ThresholdEcdsaCombineSigSharesError),
    Schnorr(ThresholdSchnorrCombineSigSharesError),
}

impl CombineSigSharesError {
    fn is_unsatisfied_reconstruction_threshold(&self) -> bool {
        matches!(
            self,
            CombineSigSharesError::Ecdsa(
                ThresholdEcdsaCombineSigSharesError::UnsatisfiedReconstructionThreshold { .. }
            ) | CombineSigSharesError::Schnorr(
                ThresholdSchnorrCombineSigSharesError::UnsatisfiedReconstructionThreshold { .. }
            )
        )
    }
}

pub(crate) trait ThresholdSigner: Send {
    /// The on_state_change() called from the main IDKG path.
    fn on_state_change(
        &self,
        idkg_pool: &dyn IDkgPool,
        transcript_loader: &dyn IDkgTranscriptLoader,
    ) -> IDkgChangeSet;
}

pub(crate) struct ThresholdSignerImpl {
    node_id: NodeId,
    consensus_block_cache: Arc<dyn ConsensusBlockCache>,
    crypto: Arc<dyn ConsensusCrypto>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    schedule: RoundRobin,
    metrics: ThresholdSignerMetrics,
    log: ReplicaLogger,
    prev_certified_height: RefCell<Height>,
}

impl ThresholdSignerImpl {
    pub(crate) fn new(
        node_id: NodeId,
        consensus_block_cache: Arc<dyn ConsensusBlockCache>,
        crypto: Arc<dyn ConsensusCrypto>,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        metrics_registry: MetricsRegistry,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            node_id,
            consensus_block_cache,
            crypto,
            state_reader,
            schedule: RoundRobin::default(),
            metrics: ThresholdSignerMetrics::new(metrics_registry),
            log,
            prev_certified_height: RefCell::new(Height::from(0)),
        }
    }

    /// Generates signature shares for the newly added signature requests.
    /// The requests for new signatures come from the latest finalized block.
    fn send_signature_shares(
        &self,
        idkg_pool: &dyn IDkgPool,
        transcript_loader: &dyn IDkgTranscriptLoader,
        block_reader: &dyn IDkgBlockReader,
        state_snapshot: &dyn CertifiedStateSnapshot<State = ReplicatedState>,
    ) -> IDkgChangeSet {
        state_snapshot
            .get_state()
            .signature_request_contexts()
            .values()
            .flat_map(|context| {
                build_signature_inputs(context, block_reader).map_err(|err| {
                    if err.is_fatal() {
                        warn!(every_n_seconds => 15, self.log,
                            "send_signature_shares(): failed to build signature inputs: {:?}",
                            err
                        );
                        self.metrics.sign_errors_inc("signature_inputs_malformed");
                    }
                })
            })
            .filter(|(request_id, inputs_ref)| {
                !self.signer_has_issued_share(
                    idkg_pool,
                    &self.node_id,
                    request_id,
                    inputs_ref.scheme(),
                )
            })
            .flat_map(|(request_id, sig_inputs_ref)| {
                self.resolve_ref(&sig_inputs_ref, block_reader, "send_signature_shares")
                    .map(|sig_inputs| {
                        self.create_signature_share(
                            idkg_pool,
                            transcript_loader,
                            &request_id,
                            &sig_inputs,
                        )
                    })
                    .unwrap_or_default()
            })
            .collect()
    }

    /// Processes the received signature shares
    fn validate_signature_shares(
        &self,
        idkg_pool: &dyn IDkgPool,
        block_reader: &dyn IDkgBlockReader,
        state_snapshot: &dyn CertifiedStateSnapshot<State = ReplicatedState>,
    ) -> IDkgChangeSet {
        let sig_inputs_map = state_snapshot
            .get_state()
            .signature_request_contexts()
            .values()
            .map(|c| {
                let inputs = build_signature_inputs(c, block_reader).map_err(|err| if err.is_fatal() {
                    warn!(every_n_seconds => 15, self.log,
                        "validate_signature_shares(): failed to build signatures inputs: {:?}", 
                        err
                    );
                    self.metrics.sign_errors_inc("signature_inputs_malformed");
                }).ok();
                (c.pseudo_random_id, inputs)
            })
            .collect::<BTreeMap<_, _>>();

        // Collection of validated shares
        let mut validated_sig_shares = BTreeSet::new();

        let mut ret = Vec::new();
        // Iterate over all signature shares of all schemes
        for (id, share) in idkg_pool.unvalidated().signature_shares() {
            // Remove the duplicate entries
            let key = (share.request_id(), share.signer());
            if validated_sig_shares.contains(&key) {
                self.metrics
                    .sign_errors_inc("duplicate_sig_shares_in_batch");
                ret.push(IDkgChangeAction::HandleInvalid(
                    id,
                    format!("Duplicate share in unvalidated batch: {}", share),
                ));
                continue;
            }

            match Action::new(
                &sig_inputs_map,
                &share.request_id(),
                state_snapshot.get_height(),
            ) {
                Action::Process(sig_inputs_ref) => {
                    let action = self.validate_signature_share(
                        idkg_pool,
                        block_reader,
                        id,
                        share,
                        sig_inputs_ref,
                    );
                    if let Some(IDkgChangeAction::MoveToValidated(_)) = action {
                        validated_sig_shares.insert(key);
                    }
                    ret.append(&mut action.into_iter().collect());
                }
                Action::Drop => ret.push(IDkgChangeAction::RemoveUnvalidated(id)),
                Action::Defer => {}
            }
        }
        ret
    }

    fn validate_signature_share(
        &self,
        idkg_pool: &dyn IDkgPool,
        block_reader: &dyn IDkgBlockReader,
        id: IDkgMessageId,
        share: SigShare,
        inputs_ref: &ThresholdSigInputsRef,
    ) -> Option<IDkgChangeAction> {
        if self.signer_has_issued_share(
            idkg_pool,
            &share.signer(),
            &share.request_id(),
            share.scheme(),
        ) {
            // The node already sent a valid share for this request
            self.metrics.sign_errors_inc("duplicate_sig_share");
            return Some(IDkgChangeAction::HandleInvalid(
                id,
                format!("Duplicate signature share: {}", share),
            ));
        }

        let Some(inputs) = self.resolve_ref(inputs_ref, block_reader, "validate_sig_share") else {
            return Some(IDkgChangeAction::HandleInvalid(
                id,
                format!("validate_signature_share(): failed to translate: {}", share),
            ));
        };

        let share_string = share.to_string();
        match self.crypto_verify_sig_share(&inputs, share, idkg_pool.stats()) {
            Err(error) if error.is_reproducible() => {
                self.metrics.sign_errors_inc("verify_sig_share_permanent");
                Some(IDkgChangeAction::HandleInvalid(
                    id,
                    format!(
                        "Signature share validation(permanent error): {}, error = {:?}",
                        share_string, error
                    ),
                ))
            }
            Err(error) => {
                // Defer in case of transient errors
                debug!(
                    self.log,
                    "Signature share validation(transient error): {}, error = {:?}",
                    share_string,
                    error
                );
                self.metrics.sign_errors_inc("verify_sig_share_transient");
                None
            }
            Ok(share) => {
                self.metrics.sign_metrics_inc("sig_shares_received");
                Some(IDkgChangeAction::MoveToValidated(share))
            }
        }
    }

    /// Purges the entries no longer needed from the artifact pool
    fn purge_artifacts(
        &self,
        idkg_pool: &dyn IDkgPool,
        state_snapshot: &dyn CertifiedStateSnapshot<State = ReplicatedState>,
    ) -> IDkgChangeSet {
        let in_progress = state_snapshot
            .get_state()
            .signature_request_contexts()
            .values()
            .map(|context| context.pseudo_random_id)
            .collect::<BTreeSet<_>>();

        let mut ret = Vec::new();
        let current_height = state_snapshot.get_height();

        // Unvalidated signature shares.
        let mut action = idkg_pool
            .unvalidated()
            .signature_shares()
            .filter(|(_, share)| self.should_purge(share, current_height, &in_progress))
            .map(|(id, _)| IDkgChangeAction::RemoveUnvalidated(id))
            .collect();
        ret.append(&mut action);

        // Validated signature shares.
        let mut action = idkg_pool
            .validated()
            .signature_shares()
            .filter(|(_, share)| self.should_purge(share, current_height, &in_progress))
            .map(|(id, _)| IDkgChangeAction::RemoveValidated(id))
            .collect();
        ret.append(&mut action);

        ret
    }

    /// Load necessary transcripts for the signature inputs
    fn load_dependencies(
        &self,
        idkg_pool: &dyn IDkgPool,
        transcript_loader: &dyn IDkgTranscriptLoader,
        inputs: &ThresholdSigInputs,
    ) -> Option<IDkgChangeSet> {
        let transcripts = match inputs {
            ThresholdSigInputs::Ecdsa(inputs) => vec![
                inputs.presig_quadruple().kappa_unmasked(),
                inputs.presig_quadruple().lambda_masked(),
                inputs.presig_quadruple().kappa_times_lambda(),
                inputs.presig_quadruple().key_times_lambda(),
                inputs.key_transcript(),
            ],
            ThresholdSigInputs::Schnorr(inputs) => vec![
                inputs.presig_transcript().blinder_unmasked(),
                inputs.key_transcript(),
            ],
        };
        load_transcripts(idkg_pool, transcript_loader, &transcripts)
    }

    /// Helper to create the signature share
    fn create_signature_share(
        &self,
        idkg_pool: &dyn IDkgPool,
        transcript_loader: &dyn IDkgTranscriptLoader,
        request_id: &RequestId,
        sig_inputs: &ThresholdSigInputs,
    ) -> IDkgChangeSet {
        if let Some(changes) = self.load_dependencies(idkg_pool, transcript_loader, sig_inputs) {
            return changes;
        }

        match self.crypto_create_sig_share(request_id, sig_inputs) {
            Err(err) => {
                warn!(
                    self.log,
                    "Failed to create sig share: request_id = {:?}, {:?}", request_id, err
                );
                self.metrics.sign_errors_inc("create_sig_share");
                Default::default()
            }
            Ok(share) => {
                self.metrics.sign_metrics_inc("sig_shares_sent");
                vec![IDkgChangeAction::AddToValidated(share)]
            }
        }
    }

    fn crypto_create_sig_share(
        &self,
        request_id: &RequestId,
        sig_inputs: &ThresholdSigInputs,
    ) -> Result<IDkgMessage, CreateSigShareError> {
        match sig_inputs {
            ThresholdSigInputs::Ecdsa(inputs) => {
                ThresholdEcdsaSigner::create_sig_share(&*self.crypto, inputs).map_or_else(
                    |err| Err(CreateSigShareError::Ecdsa(err)),
                    |share| {
                        let sig_share = EcdsaSigShare {
                            signer_id: self.node_id,
                            request_id: request_id.clone(),
                            share,
                        };
                        Ok(IDkgMessage::EcdsaSigShare(sig_share))
                    },
                )
            }
            ThresholdSigInputs::Schnorr(inputs) => {
                ThresholdSchnorrSigner::create_sig_share(&*self.crypto, inputs).map_or_else(
                    |err| Err(CreateSigShareError::Schnorr(err)),
                    |share| {
                        let sig_share = SchnorrSigShare {
                            signer_id: self.node_id,
                            request_id: request_id.clone(),
                            share,
                        };
                        Ok(IDkgMessage::SchnorrSigShare(sig_share))
                    },
                )
            }
        }
    }

    /// Helper to verify the signature share
    fn crypto_verify_sig_share(
        &self,
        sig_inputs: &ThresholdSigInputs,
        share: SigShare,
        stats: &dyn IDkgStats,
    ) -> Result<IDkgMessage, VerifySigShareError> {
        let start = std::time::Instant::now();
        let request_id = share.request_id();
        let ret = match (sig_inputs, share) {
            (ThresholdSigInputs::Ecdsa(inputs), SigShare::Ecdsa(share)) => {
                ThresholdEcdsaSigVerifier::verify_sig_share(
                    &*self.crypto,
                    share.signer_id,
                    inputs,
                    &share.share,
                )
                .map_or_else(
                    |err| Err(VerifySigShareError::Ecdsa(err)),
                    |_| Ok(IDkgMessage::EcdsaSigShare(share)),
                )
            }
            (ThresholdSigInputs::Schnorr(inputs), SigShare::Schnorr(share)) => {
                ThresholdSchnorrSigVerifier::verify_sig_share(
                    &*self.crypto,
                    share.signer_id,
                    inputs,
                    &share.share,
                )
                .map_or_else(
                    |err| Err(VerifySigShareError::Schnorr(err)),
                    |_| Ok(IDkgMessage::SchnorrSigShare(share)),
                )
            }
            _ => Err(VerifySigShareError::ThresholdSchemeMismatch),
        };

        stats.record_sig_share_validation(&request_id, start.elapsed());
        ret
    }

    /// Checks if the signer node has already issued a signature share for the
    /// request
    fn signer_has_issued_share(
        &self,
        idkg_pool: &dyn IDkgPool,
        signer_id: &NodeId,
        request_id: &RequestId,
        scheme: SignatureScheme,
    ) -> bool {
        let validated = idkg_pool.validated();
        match scheme {
            SignatureScheme::Ecdsa => {
                let prefix = ecdsa_sig_share_prefix(request_id, signer_id);
                validated
                    .ecdsa_signature_shares_by_prefix(prefix)
                    .any(|(_, share)| {
                        share.request_id == *request_id && share.signer_id == *signer_id
                    })
            }
            SignatureScheme::Schnorr => {
                let prefix = schnorr_sig_share_prefix(request_id, signer_id);
                validated
                    .schnorr_signature_shares_by_prefix(prefix)
                    .any(|(_, share)| {
                        share.request_id == *request_id && share.signer_id == *signer_id
                    })
            }
        }
    }

    /// Checks if the signature share should be purged
    fn should_purge(
        &self,
        share: &SigShare,
        current_height: Height,
        in_progress: &BTreeSet<[u8; 32]>,
    ) -> bool {
        let request_id = share.request_id();
        request_id.height <= current_height && !in_progress.contains(&request_id.pseudo_random_id)
    }

    /// Resolves the ThresholdSigInputsRef -> ThresholdSigInputs
    fn resolve_ref(
        &self,
        sig_inputs_ref: &ThresholdSigInputsRef,
        block_reader: &dyn IDkgBlockReader,
        reason: &str,
    ) -> Option<ThresholdSigInputs> {
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

impl ThresholdSigner for ThresholdSignerImpl {
    fn on_state_change(
        &self,
        idkg_pool: &dyn IDkgPool,
        transcript_loader: &dyn IDkgTranscriptLoader,
    ) -> IDkgChangeSet {
        let Some(snapshot) = self.state_reader.get_certified_state_snapshot() else {
            idkg_pool.stats().update_active_signature_requests(vec![]);
            return IDkgChangeSet::new();
        };

        let block_reader = IDkgBlockReaderImpl::new(self.consensus_block_cache.finalized_chain());
        let metrics = self.metrics.clone();

        let active_requests = snapshot
            .get_state()
            .signature_request_contexts()
            .values()
            .flat_map(get_context_request_id)
            .collect();
        idkg_pool
            .stats()
            .update_active_signature_requests(active_requests);

        let mut changes = update_purge_height(&self.prev_certified_height, snapshot.get_height())
            .then(|| {
                timed_call(
                    "purge_artifacts",
                    || self.purge_artifacts(idkg_pool, snapshot.as_ref()),
                    &metrics.on_state_change_duration,
                )
            })
            .unwrap_or_default();

        let send_signature_shares = || {
            timed_call(
                "send_signature_shares",
                || {
                    self.send_signature_shares(
                        idkg_pool,
                        transcript_loader,
                        &block_reader,
                        snapshot.as_ref(),
                    )
                },
                &metrics.on_state_change_duration,
            )
        };
        let validate_signature_shares = || {
            timed_call(
                "validate_signature_shares",
                || self.validate_signature_shares(idkg_pool, &block_reader, snapshot.as_ref()),
                &metrics.on_state_change_duration,
            )
        };

        let calls: [&'_ dyn Fn() -> IDkgChangeSet; 2] =
            [&send_signature_shares, &validate_signature_shares];
        changes.append(&mut self.schedule.call_next(&calls));
        changes
    }
}

pub(crate) trait ThresholdSignatureBuilder {
    /// Returns the signature for the given context, if it can be successfully
    /// built from the current sig shares in the IDKG pool
    fn get_completed_signature(
        &self,
        context: &SignWithThresholdContext,
    ) -> Option<CombinedSignature>;
}

pub(crate) struct ThresholdSignatureBuilderImpl<'a> {
    block_reader: &'a dyn IDkgBlockReader,
    crypto: &'a dyn ConsensusCrypto,
    idkg_pool: &'a dyn IDkgPool,
    metrics: &'a IDkgPayloadMetrics,
    log: ReplicaLogger,
}

impl<'a> ThresholdSignatureBuilderImpl<'a> {
    pub(crate) fn new(
        block_reader: &'a dyn IDkgBlockReader,
        crypto: &'a dyn ConsensusCrypto,
        idkg_pool: &'a dyn IDkgPool,
        metrics: &'a IDkgPayloadMetrics,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            crypto,
            idkg_pool,
            block_reader,
            metrics,
            log,
        }
    }

    fn crypto_combine_sig_shares(
        &self,
        request_id: &RequestId,
        inputs: &ThresholdSigInputs,
        stats: &dyn IDkgStats,
    ) -> Result<CombinedSignature, CombineSigSharesError> {
        let start = std::time::Instant::now();
        let ret = match inputs {
            ThresholdSigInputs::Ecdsa(inputs) => {
                // Collect the signature shares for the request.
                let mut sig_shares = BTreeMap::new();
                for (_, share) in self.idkg_pool.validated().ecdsa_signature_shares() {
                    if share.request_id == *request_id {
                        sig_shares.insert(share.signer_id, share.share.clone());
                    }
                }
                ThresholdEcdsaSigVerifier::combine_sig_shares(self.crypto, inputs, &sig_shares)
                    .map_or_else(
                        |err| Err(CombineSigSharesError::Ecdsa(err)),
                        |share| Ok(CombinedSignature::Ecdsa(share)),
                    )
            }
            ThresholdSigInputs::Schnorr(inputs) => {
                // Collect the signature shares for the request.
                let mut sig_shares = BTreeMap::new();
                for (_, share) in self.idkg_pool.validated().schnorr_signature_shares() {
                    if share.request_id == *request_id {
                        sig_shares.insert(share.signer_id, share.share.clone());
                    }
                }
                ThresholdSchnorrSigVerifier::combine_sig_shares(self.crypto, inputs, &sig_shares)
                    .map_or_else(
                        |err| Err(CombineSigSharesError::Schnorr(err)),
                        |share| Ok(CombinedSignature::Schnorr(share)),
                    )
            }
        };
        stats.record_sig_share_aggregation(request_id, start.elapsed());
        ret
    }
}

impl<'a> ThresholdSignatureBuilder for ThresholdSignatureBuilderImpl<'a> {
    fn get_completed_signature(
        &self,
        context: &SignWithThresholdContext,
    ) -> Option<CombinedSignature> {
        // Find the sig inputs for the request and translate the refs.
        let (request_id, sig_inputs_ref) = build_signature_inputs(context, self.block_reader)
            .map_err(|err| {
                if err.is_fatal() {
                    warn!(every_n_seconds => 15, self.log,
                        "get_completed_signature(): failed to build signature inputs: {:?}",
                        err
                    );
                    self.metrics
                        .payload_errors_inc("signature_inputs_malformed");
                }
            })
            .ok()?;

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

        match self.crypto_combine_sig_shares(&request_id, &sig_inputs, self.idkg_pool.stats()) {
            Ok(signature) => {
                self.metrics
                    .payload_metrics_inc("signatures_completed", None);
                Some(signature)
            }
            Err(err) if err.is_unsatisfied_reconstruction_threshold() => None,
            Err(err) => {
                warn!(
                    self.log,
                    "Failed to combine signature shares: request_id = {:?}, {:?}", request_id, err
                );
                self.metrics.payload_errors_inc("combine_sig_share");
                None
            }
        }
    }
}

/// Specifies how to handle a received share
#[derive(Eq, PartialEq)]
enum Action<'a> {
    /// The message is relevant to our current state, process it
    /// immediately. The transcript params for this transcript
    /// (as specified by the finalized block) is the argument
    Process(&'a ThresholdSigInputsRef),

    /// Keep it to be processed later (e.g) this is from a node
    /// ahead of us
    Defer,

    /// Don't need it
    Drop,
}

impl<'a> Action<'a> {
    /// Decides the action to take on a received message with the given height/RequestId
    fn new(
        requested_signatures: &'a BTreeMap<[u8; 32], Option<(RequestId, ThresholdSigInputsRef)>>,
        request_id: &RequestId,
        certified_height: Height,
    ) -> Action<'a> {
        let msg_height = request_id.height;
        if msg_height > certified_height {
            // Message is from a node ahead of us, keep it to be
            // processed later
            return Action::Defer;
        }

        match requested_signatures.get(&request_id.pseudo_random_id) {
            Some(Some((own_request_id, sig_inputs))) => {
                if request_id == own_request_id {
                    Action::Process(sig_inputs)
                } else {
                    // A signature for the received ID was requested and the context was completed.
                    // However, the received share claims a different pre-signature was matched,
                    // therefore drop the message.
                    Action::Drop
                }
            }
            // The signature has been requested, but its context hasn't been completed yet.
            // Defer until the context is matched with a pre-signature and randomness is assigned.
            Some(None) => Action::Defer,
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
                write!(f, "Action::Process(): caller = {:?}", sig_inputs.caller())
            }
            Self::Defer => write!(f, "Action::Defer"),
            Self::Drop => write!(f, "Action::Drop"),
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
        generate_key_transcript, generate_tecdsa_protocol_inputs,
        generate_tschnorr_protocol_inputs, run_tecdsa_protocol, run_tschnorr_protocol,
        CanisterThresholdSigTestEnvironment, IDkgParticipants,
    };
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_interfaces::p2p::consensus::{MutablePool, UnvalidatedArtifact};
    use ic_management_canister_types::{MasterPublicKeyId, SchnorrAlgorithm};
    use ic_replicated_state::metadata_state::subnet_call_context_manager::{
        EcdsaArguments, SchnorrArguments, ThresholdArguments,
    };
    use ic_test_utilities_consensus::IDkgStatsNoOp;
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_types::ids::{
        canister_test_id, subnet_test_id, user_test_id, NODE_1, NODE_2, NODE_3,
    };
    use ic_test_utilities_types::messages::RequestBuilder;
    use ic_types::consensus::idkg::*;
    use ic_types::crypto::{canister_threshold_sig::ExtendedDerivationPath, AlgorithmId};
    use ic_types::time::UNIX_EPOCH;
    use ic_types::{Height, Randomness};
    use std::ops::Deref;
    use std::sync::RwLock;

    fn create_request_id(generator: &mut IDkgUIDGenerator, height: Height) -> RequestId {
        let pre_signature_id = generator.next_pre_signature_id();
        let pseudo_random_id = [pre_signature_id.id() as u8; 32];
        RequestId {
            pre_signature_id,
            pseudo_random_id,
            height,
        }
    }

    #[test]
    fn test_ecdsa_signer_action() {
        let key_id = fake_ecdsa_master_public_key_id();
        let mut uid_generator = IDkgUIDGenerator::new(subnet_test_id(1), Height::new(0));
        let height = Height::from(100);
        let (id_1, id_2, id_3, id_4, id_5) = (
            create_request_id(&mut uid_generator, height),
            create_request_id(&mut uid_generator, Height::from(10)),
            create_request_id(&mut uid_generator, height),
            create_request_id(&mut uid_generator, height),
            create_request_id(&mut uid_generator, Height::from(200)),
        );

        let requested = BTreeMap::from([
            (
                id_1.pseudo_random_id,
                Some((id_1.clone(), create_sig_inputs(1, &key_id).sig_inputs_ref)),
            ),
            (
                id_2.pseudo_random_id,
                Some((id_2.clone(), create_sig_inputs(2, &key_id).sig_inputs_ref)),
            ),
            (
                id_3.pseudo_random_id,
                Some((id_3.clone(), create_sig_inputs(3, &key_id).sig_inputs_ref)),
            ),
            (id_4.pseudo_random_id, None),
        ]);

        // Message from a node ahead of us
        assert_eq!(Action::new(&requested, &id_5, height), Action::Defer);

        // Messages for transcripts not being currently requested
        assert_eq!(
            Action::new(
                &requested,
                &create_request_id(&mut uid_generator, Height::from(100)),
                height,
            ),
            Action::Drop
        );
        assert_eq!(
            Action::new(
                &requested,
                &create_request_id(&mut uid_generator, Height::from(10)),
                height,
            ),
            Action::Drop
        );

        // Messages for signatures currently requested
        let action = Action::new(&requested, &id_1, height);
        assert_matches!(action, Action::Process(_));

        let action = Action::new(&requested, &id_2, height);
        assert_matches!(action, Action::Process(_));

        // Message for a signature currently requested but specifying wrong pre-signature
        let wrong_id_2 = RequestId {
            pre_signature_id: id_1.pre_signature_id,
            ..id_2.clone()
        };
        let action = Action::new(&requested, &wrong_id_2, height);
        assert_eq!(action, Action::Drop);

        // Message for a signature that is requested, but its context isn't complete yet
        let action = Action::new(&requested, &id_4, height);
        assert_eq!(action, Action::Defer);
    }

    // Tests that signature shares are purged once the certified height increases
    #[test]
    fn test_signature_shares_purging_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_signature_shares_purging(key_id);
        }
    }

    fn test_signature_shares_purging(key_id: MasterPublicKeyId) {
        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
                with_test_replica_logger(|logger| {
                    let (mut idkg_pool, signer, state_manager) =
                        create_signer_dependencies_and_state_manager(pool_config, logger);
                    let transcript_loader = TestIDkgTranscriptLoader::default();
                    let height_0 = Height::from(0);
                    let height_30 = Height::from(30);

                    let expected_state_snapshot =
                        Arc::new(RwLock::new(FakeCertifiedStateSnapshot {
                            height: height_0,
                            state: Arc::new(ic_test_utilities_state::get_initial_state(0, 0)),
                        }));
                    let expected_state_snapshot_clone = expected_state_snapshot.clone();
                    state_manager
                        .get_mut()
                        .expect_get_certified_state_snapshot()
                        .returning(move || {
                            Some(Box::new(
                                expected_state_snapshot_clone.read().unwrap().clone(),
                            ))
                        });

                    let mut uid_generator = IDkgUIDGenerator::new(subnet_test_id(1), height_0);
                    let id_1 = create_request_id(&mut uid_generator, height_0);
                    let id_2 = create_request_id(&mut uid_generator, height_30);

                    let share1 = create_signature_share(&key_id, NODE_1, id_1.clone());
                    let msg_id1 = share1.message_id();
                    let share2 = create_signature_share(&key_id, NODE_2, id_2.clone());
                    let msg_id2 = share2.message_id();
                    let change_set = vec![
                        IDkgChangeAction::AddToValidated(share1),
                        IDkgChangeAction::AddToValidated(share2),
                    ];
                    idkg_pool.apply_changes(change_set);

                    // Certified height doesn't increase, so share1 shouldn't be purged
                    let change_set = signer.on_state_change(&idkg_pool, &transcript_loader);
                    assert_eq!(*signer.prev_certified_height.borrow(), height_0);
                    assert!(change_set.is_empty());

                    // Certified height increases, so share1 is purged
                    let new_height = expected_state_snapshot.write().unwrap().inc_height_by(29);
                    let change_set = signer.on_state_change(&idkg_pool, &transcript_loader);
                    assert_eq!(*signer.prev_certified_height.borrow(), new_height);
                    assert_eq!(change_set.len(), 1);
                    assert!(is_removed_from_validated(&change_set, &msg_id1));
                    idkg_pool.apply_changes(change_set);

                    // Certified height increases above share2, so it is purged
                    let new_height = expected_state_snapshot.write().unwrap().inc_height_by(1);
                    let change_set = signer.on_state_change(&idkg_pool, &transcript_loader);
                    assert_eq!(*signer.prev_certified_height.borrow(), new_height);
                    assert_eq!(height_30, new_height);
                    assert_eq!(change_set.len(), 1);
                    assert!(is_removed_from_validated(&change_set, &msg_id2));
                })
            },
        )
    }

    // Tests that signature shares are sent for new requests, and requests already
    // in progress are filtered out.
    #[test]
    fn test_send_signature_shares_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_send_signature_shares(key_id);
        }
    }

    fn test_send_signature_shares(key_id: MasterPublicKeyId) {
        let mut uid_generator = IDkgUIDGenerator::new(subnet_test_id(1), Height::new(0));
        let height = Height::from(100);
        let (id_1, id_2, id_3, id_4, id_5) = (
            create_request_id(&mut uid_generator, height),
            create_request_id(&mut uid_generator, height),
            create_request_id(&mut uid_generator, height),
            create_request_id(&mut uid_generator, height),
            create_request_id(&mut uid_generator, height),
        );

        // Set up the IDKG pool. Pool has shares for requests 1, 2, 3.
        // Only the share for request 1 is issued by us
        let shares = vec![
            create_signature_share(&key_id, NODE_1, id_1.clone()),
            create_signature_share(&key_id, NODE_2, id_2.clone()),
            create_signature_share(&key_id, NODE_3, id_3.clone()),
        ];

        // Set up the signature requests
        // The block requests signatures 1, 4, 5
        let block_reader = TestIDkgBlockReader::for_signer_test(
            Height::from(100),
            vec![
                (id_1.clone(), create_sig_inputs(1, &key_id)),
                (id_4.clone(), create_sig_inputs(4, &key_id)),
                (id_5.clone(), create_sig_inputs(5, &key_id)),
            ],
        );
        let transcript_loader: TestIDkgTranscriptLoader = Default::default();

        let state = fake_state_with_signature_requests(
            height,
            block_reader.requested_signatures().map(|(request_id, _)| {
                fake_signature_request_context_from_id(key_id.clone(), request_id)
            }),
        );

        // Test using CryptoReturningOK
        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
                with_test_replica_logger(|logger| {
                    let (mut idkg_pool, signer) = create_signer_dependencies(pool_config, logger);

                    idkg_pool.apply_changes(
                        shares
                            .iter()
                            .map(|s| IDkgChangeAction::AddToValidated(s.clone()))
                            .collect(),
                    );

                    // Since request 1 is already in progress, we should issue
                    // shares only for transcripts 4, 5
                    let change_set = signer.send_signature_shares(
                        &idkg_pool,
                        &transcript_loader,
                        &block_reader,
                        &state,
                    );
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
            },
        );

        // Test using crypto without keys
        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
                with_test_replica_logger(|logger| {
                    let (mut idkg_pool, signer) = create_signer_dependencies_with_crypto(
                        pool_config,
                        logger,
                        Some(crypto_without_keys()),
                    );

                    idkg_pool.apply_changes(
                        shares
                            .iter()
                            .map(|s| IDkgChangeAction::AddToValidated(s.clone()))
                            .collect(),
                    );

                    // Crypto should return an error and no shares should be created.
                    let change_set = signer.send_signature_shares(
                        &idkg_pool,
                        &transcript_loader,
                        &block_reader,
                        &state,
                    );
                    assert!(change_set.is_empty());
                })
            },
        );
    }

    // Tests that no signature shares for incomplete contexts are created
    #[test]
    fn test_send_signature_shares_incomplete_contexts_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_send_signature_shares_incomplete_contexts(key_id);
        }
    }

    fn test_send_signature_shares_incomplete_contexts(key_id: MasterPublicKeyId) {
        let mut uid_generator = IDkgUIDGenerator::new(subnet_test_id(1), Height::new(0));
        let height = Height::from(100);
        let (id_1, id_2, id_3, id_4, id_5) = (
            create_request_id(&mut uid_generator, height),
            create_request_id(&mut uid_generator, height),
            create_request_id(&mut uid_generator, height),
            create_request_id(&mut uid_generator, height),
            create_request_id(&mut uid_generator, height),
        );
        let wrong_key_id = match key_id {
            MasterPublicKeyId::Ecdsa(_) => {
                fake_schnorr_master_public_key_id(SchnorrAlgorithm::Ed25519)
            }
            MasterPublicKeyId::Schnorr(_) => fake_ecdsa_master_public_key_id(),
        };

        // Set up the signature requests
        // The block contains pre-signatures for all requests except request 5
        let block_reader = TestIDkgBlockReader::for_signer_test(
            height,
            vec![
                (id_1.clone(), create_sig_inputs(1, &key_id)),
                (id_2.clone(), create_sig_inputs(2, &key_id)),
                (id_3.clone(), create_sig_inputs(3, &key_id)),
                (id_4.clone(), create_sig_inputs(4, &wrong_key_id)),
            ],
        );
        let transcript_loader: TestIDkgTranscriptLoader = Default::default();

        let state = fake_state_with_signature_requests(
            height,
            [
                // One context without matched pre-signature
                fake_signature_request_context_with_pre_sig(
                    id_1.pre_signature_id.id() as u8,
                    key_id.clone(),
                    None,
                ),
                // One context without nonce
                fake_signature_request_context_with_pre_sig(
                    id_2.pre_signature_id.id() as u8,
                    key_id.clone(),
                    Some(id_2.pre_signature_id),
                ),
                // One completed context
                fake_signature_request_context_from_id(key_id.clone(), &id_3),
                // One completed context matched to a pre-signature of the wrong scheme
                fake_completed_signature_request_context(
                    id_4.pre_signature_id.id() as u8,
                    key_id.clone(),
                    id_4.pre_signature_id,
                ),
                // One completed context matched to a pre-signature that doesn't exist
                fake_completed_signature_request_context(
                    id_5.pre_signature_id.id() as u8,
                    key_id.clone(),
                    id_5.pre_signature_id,
                ),
            ],
        );

        // Test using CryptoReturningOK
        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
                with_test_replica_logger(|logger| {
                    let (idkg_pool, signer) = create_signer_dependencies(pool_config, logger);

                    // We should issue shares only for completed request 3
                    let change_set = signer.send_signature_shares(
                        &idkg_pool,
                        &transcript_loader,
                        &block_reader,
                        &state,
                    );

                    assert_eq!(change_set.len(), 1);
                    assert!(is_signature_share_added_to_validated(
                        &change_set,
                        &id_3,
                        block_reader.tip_height()
                    ));
                })
            },
        );
    }

    #[test]
    fn test_send_signature_shares_when_failure_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_send_signature_shares_when_failure(key_id);
        }
    }

    fn test_send_signature_shares_when_failure(key_id: MasterPublicKeyId) {
        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
                with_test_replica_logger(|logger| {
                    let mut uid_generator =
                        IDkgUIDGenerator::new(subnet_test_id(1), Height::new(0));
                    let height = Height::from(100);
                    let (id_1, id_2, id_3) = (
                        create_request_id(&mut uid_generator, height),
                        create_request_id(&mut uid_generator, height),
                        create_request_id(&mut uid_generator, height),
                    );
                    // Set up the signature requests
                    // The block requests signatures 1, 2, 3
                    let block_reader = TestIDkgBlockReader::for_signer_test(
                        height,
                        vec![
                            (id_1, create_sig_inputs(1, &key_id)),
                            (id_2, create_sig_inputs(2, &key_id)),
                            (id_3, create_sig_inputs(3, &key_id)),
                        ],
                    );
                    let state = fake_state_with_signature_requests(
                        height,
                        block_reader.requested_signatures().map(|(request_id, _)| {
                            fake_signature_request_context_from_id(key_id.clone(), request_id)
                        }),
                    );

                    let (idkg_pool, signer) = create_signer_dependencies(pool_config, logger);

                    let transcript_loader =
                        TestIDkgTranscriptLoader::new(TestTranscriptLoadStatus::Failure);
                    let change_set = signer.send_signature_shares(
                        &idkg_pool,
                        &transcript_loader,
                        &block_reader,
                        &state,
                    );

                    // No shares should be created when transcripts fail to load
                    assert!(change_set.is_empty());

                    let transcript_loader =
                        TestIDkgTranscriptLoader::new(TestTranscriptLoadStatus::Success);
                    let change_set = signer.send_signature_shares(
                        &idkg_pool,
                        &transcript_loader,
                        &block_reader,
                        &state,
                    );

                    // Shares should be created when transcripts succeed to load
                    assert_eq!(change_set.len(), 3);
                })
            },
        )
    }

    // Tests that complaints are generated and added to the pool if loading transcript
    // results in complaints.
    #[test]
    fn test_send_signature_shares_with_complaints_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_send_signature_shares_with_complaints(key_id);
        }
    }

    fn test_send_signature_shares_with_complaints(key_id: MasterPublicKeyId) {
        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
                with_test_replica_logger(|logger| {
                    let mut uid_generator =
                        IDkgUIDGenerator::new(subnet_test_id(1), Height::new(0));
                    let height = Height::from(100);
                    let (id_1, id_2, id_3) = (
                        create_request_id(&mut uid_generator, height),
                        create_request_id(&mut uid_generator, height),
                        create_request_id(&mut uid_generator, height),
                    );

                    // Set up the signature requests
                    // The block requests signatures 1, 2, 3
                    let block_reader = TestIDkgBlockReader::for_signer_test(
                        height,
                        vec![
                            (id_1, create_sig_inputs(1, &key_id)),
                            (id_2, create_sig_inputs(2, &key_id)),
                            (id_3, create_sig_inputs(3, &key_id)),
                        ],
                    );
                    let state = fake_state_with_signature_requests(
                        height,
                        block_reader.requested_signatures().map(|(request_id, _)| {
                            fake_signature_request_context_from_id(key_id.clone(), request_id)
                        }),
                    );

                    let (idkg_pool, signer) = create_signer_dependencies(pool_config, logger);

                    let transcript_loader =
                        TestIDkgTranscriptLoader::new(TestTranscriptLoadStatus::Complaints);

                    let change_set = signer.send_signature_shares(
                        &idkg_pool,
                        &transcript_loader,
                        &block_reader,
                        &state,
                    );
                    let requested_signatures_count = block_reader.requested_signatures().count();
                    let expected_complaints_count = match key_id {
                        MasterPublicKeyId::Ecdsa(_) => requested_signatures_count * 5,
                        MasterPublicKeyId::Schnorr(_) => requested_signatures_count * 2,
                    };
                    let complaints = transcript_loader.returned_complaints();
                    assert_eq!(change_set.len(), complaints.len());
                    assert_eq!(change_set.len(), expected_complaints_count);
                    for complaint in complaints {
                        assert!(is_complaint_added_to_validated(
                            &change_set,
                            &complaint.content.idkg_complaint.transcript_id,
                            &NODE_1,
                            &NODE_1,
                        ));
                    }
                })
            },
        )
    }

    #[test]
    fn test_crypto_verify_sig_share_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_crypto_verify_sig_share(key_id);
        }
    }

    fn test_crypto_verify_sig_share(key_id: MasterPublicKeyId) {
        let mut rng = reproducible_rng();
        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
                with_test_replica_logger(|logger| {
                    let env = CanisterThresholdSigTestEnvironment::new(1, &mut rng);
                    let (dealers, receivers) = env.choose_dealers_and_receivers(
                        &IDkgParticipants::AllNodesAsDealersAndReceivers,
                        &mut rng,
                    );
                    let key_transcript = generate_key_transcript(
                        &env,
                        &dealers,
                        &receivers,
                        algorithm_for_key_id(&key_id),
                        &mut rng,
                    );
                    let derivation_path = ExtendedDerivationPath {
                        caller: user_test_id(1).get(),
                        derivation_path: vec![],
                    };
                    let (receivers, inputs) = match key_id {
                        MasterPublicKeyId::Ecdsa(_) => {
                            let inputs = generate_tecdsa_protocol_inputs(
                                &env,
                                &dealers,
                                &receivers,
                                &key_transcript,
                                &[0; 32],
                                Randomness::from([0; 32]),
                                &derivation_path,
                                algorithm_for_key_id(&key_id),
                                &mut rng,
                            );

                            (
                                inputs.receivers().clone(),
                                ThresholdSigInputs::Ecdsa(inputs),
                            )
                        }
                        MasterPublicKeyId::Schnorr(_) => {
                            let inputs = generate_tschnorr_protocol_inputs(
                                &env,
                                &dealers,
                                &receivers,
                                &key_transcript,
                                &[0; 32],
                                Randomness::from([0; 32]),
                                &derivation_path,
                                algorithm_for_key_id(&key_id),
                                &mut rng,
                            );
                            (
                                inputs.receivers().clone(),
                                ThresholdSigInputs::Schnorr(inputs),
                            )
                        }
                    };
                    let crypto = env
                        .nodes
                        .filter_by_receivers(&receivers)
                        .next()
                        .unwrap()
                        .crypto();
                    let (_, signer) =
                        create_signer_dependencies_with_crypto(pool_config, logger, Some(crypto));
                    let mut uid_generator =
                        IDkgUIDGenerator::new(subnet_test_id(1), Height::new(0));
                    let id = create_request_id(&mut uid_generator, Height::from(5));
                    let message = create_signature_share(&key_id, NODE_2, id);
                    let share = match message {
                        IDkgMessage::EcdsaSigShare(share) => SigShare::Ecdsa(share),
                        IDkgMessage::SchnorrSigShare(share) => SigShare::Schnorr(share),
                        _ => panic!("Unexpected message type"),
                    };
                    let result =
                        signer.crypto_verify_sig_share(&inputs, share, &(IDkgStatsNoOp {}));
                    // assert that the mock signature share does not pass real crypto check
                    assert!(result.is_err());
                })
            },
        )
    }

    // Tests that received dealings are accepted/processed for eligible signature
    // requests, and others dealings are either deferred or dropped.
    #[test]
    fn test_validate_signature_shares_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_validate_signature_shares(key_id);
        }
    }

    fn test_validate_signature_shares(key_id: MasterPublicKeyId) {
        let mut uid_generator = IDkgUIDGenerator::new(subnet_test_id(1), Height::new(0));
        let height = Height::from(100);
        let (id_1, id_2, id_3, id_4) = (
            create_request_id(&mut uid_generator, Height::from(200)),
            create_request_id(&mut uid_generator, height),
            create_request_id(&mut uid_generator, Height::from(10)),
            create_request_id(&mut uid_generator, Height::from(5)),
        );

        // Set up the transcript creation request
        // The block requests transcripts 2, 3
        let block_reader = TestIDkgBlockReader::for_signer_test(
            height,
            vec![
                (id_2.clone(), create_sig_inputs(2, &key_id)),
                (id_3.clone(), create_sig_inputs(3, &key_id)),
            ],
        );
        let state = fake_state_with_signature_requests(
            height,
            block_reader.requested_signatures().map(|(request_id, _)| {
                fake_signature_request_context_from_id(key_id.clone(), request_id)
            }),
        );

        // Set up the IDKG pool
        let mut artifacts = Vec::new();
        // A share from a node ahead of us (deferred)
        let message = create_signature_share(&key_id, NODE_2, id_1);
        artifacts.push(UnvalidatedArtifact {
            message,
            peer_id: NODE_2,
            timestamp: UNIX_EPOCH,
        });

        // A share for a request in the finalized block (accepted)
        let message = create_signature_share(&key_id, NODE_2, id_2);
        let msg_id_2 = message.message_id();
        artifacts.push(UnvalidatedArtifact {
            message,
            peer_id: NODE_2,
            timestamp: UNIX_EPOCH,
        });

        // A share for a request in the finalized block (accepted)
        let message = create_signature_share(&key_id, NODE_2, id_3);
        let msg_id_3 = message.message_id();
        artifacts.push(UnvalidatedArtifact {
            message,
            peer_id: NODE_2,
            timestamp: UNIX_EPOCH,
        });

        // A share for a request not in the finalized block (dropped)
        let message = create_signature_share(&key_id, NODE_2, id_4);
        let msg_id_4 = message.message_id();
        artifacts.push(UnvalidatedArtifact {
            message,
            peer_id: NODE_2,
            timestamp: UNIX_EPOCH,
        });

        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
                with_test_replica_logger(|logger| {
                    let (mut idkg_pool, signer) = create_signer_dependencies(pool_config, logger);
                    artifacts.iter().for_each(|a| idkg_pool.insert(a.clone()));

                    let change_set =
                        signer.validate_signature_shares(&idkg_pool, &block_reader, &state);
                    assert_eq!(change_set.len(), 3);
                    assert!(is_moved_to_validated(&change_set, &msg_id_2));
                    assert!(is_moved_to_validated(&change_set, &msg_id_3));
                    assert!(is_removed_from_unvalidated(&change_set, &msg_id_4));
                })
            },
        );

        // Simulate failure when resolving transcripts
        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
                with_test_replica_logger(|logger| {
                    let (mut idkg_pool, signer) = create_signer_dependencies(pool_config, logger);
                    artifacts.iter().for_each(|a| idkg_pool.insert(a.clone()));

                    let block_reader = block_reader.clone().with_fail_to_resolve();
                    // There are no transcripts in the block reader, shares created for transcripts
                    // that cannot be resolved should be handled invalid.
                    let change_set =
                        signer.validate_signature_shares(&idkg_pool, &block_reader, &state);
                    assert_eq!(change_set.len(), 3);
                    assert!(is_handle_invalid(&change_set, &msg_id_2));
                    assert!(is_handle_invalid(&change_set, &msg_id_3));
                    assert!(is_removed_from_unvalidated(&change_set, &msg_id_4));
                })
            },
        );
    }

    // Tests that signature shares for the wrong scheme are not validated
    #[test]
    fn test_validate_signature_shares_mismatching_schemes_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_validate_signature_shares_mismatching_schemes(key_id);
        }
    }

    fn test_validate_signature_shares_mismatching_schemes(key_id: MasterPublicKeyId) {
        let mut uid_generator = IDkgUIDGenerator::new(subnet_test_id(1), Height::new(0));
        let height = Height::from(100);
        let (id_1, id_2) = (
            create_request_id(&mut uid_generator, height),
            create_request_id(&mut uid_generator, height),
        );

        // Set up the signature requests
        // The block contains pre-signatures for requests 1, 2
        let block_reader = TestIDkgBlockReader::for_signer_test(
            height,
            vec![
                (id_1.clone(), create_sig_inputs(1, &key_id)),
                (id_2.clone(), create_sig_inputs(2, &key_id)),
            ],
        );
        let state = fake_state_with_signature_requests(
            height,
            block_reader.requested_signatures().map(|(request_id, _)| {
                fake_signature_request_context_from_id(key_id.clone(), request_id)
            }),
        );

        // Set up the IDKG pool
        let mut artifacts = Vec::new();
        // A valid share for the first context
        let message = create_signature_share(&key_id, NODE_2, id_1);
        let msg_id_1 = message.message_id();
        artifacts.push(UnvalidatedArtifact {
            message,
            peer_id: NODE_2,
            timestamp: UNIX_EPOCH,
        });

        // A share for the second context with mismatching schemes
        let key_id_wrong_scheme = match key_id {
            MasterPublicKeyId::Ecdsa(_) => {
                fake_schnorr_master_public_key_id(SchnorrAlgorithm::Ed25519)
            }
            MasterPublicKeyId::Schnorr(_) => fake_ecdsa_master_public_key_id(),
        };
        let message = create_signature_share(&key_id_wrong_scheme, NODE_2, id_2.clone());
        let msg_id_2 = message.message_id();
        artifacts.push(UnvalidatedArtifact {
            message,
            peer_id: NODE_2,
            timestamp: UNIX_EPOCH,
        });

        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
                with_test_replica_logger(|logger| {
                    let (mut idkg_pool, signer) = create_signer_dependencies(pool_config, logger);
                    artifacts.iter().for_each(|a| idkg_pool.insert(a.clone()));

                    let change_set =
                        signer.validate_signature_shares(&idkg_pool, &block_reader, &state);
                    assert_eq!(change_set.len(), 2);
                    assert!(is_moved_to_validated(&change_set, &msg_id_1));
                    assert!(is_handle_invalid(&change_set, &msg_id_2));
                })
            },
        );
    }

    // Tests that signature shares for incomplete contexts are not validated
    #[test]
    fn test_validate_signature_shares_incomplete_contexts_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_validate_signature_shares_incomplete_contexts(key_id);
        }
    }

    fn test_validate_signature_shares_incomplete_contexts(key_id: MasterPublicKeyId) {
        let mut uid_generator = IDkgUIDGenerator::new(subnet_test_id(1), Height::new(0));
        let height = Height::from(100);
        let (id_1, id_2, id_3) = (
            create_request_id(&mut uid_generator, height),
            create_request_id(&mut uid_generator, height),
            create_request_id(&mut uid_generator, height),
        );

        // Set up the signature requests
        // The block contains pre-signatures for requests 1, 2, 3
        let block_reader = TestIDkgBlockReader::for_signer_test(
            height,
            vec![
                (id_1.clone(), create_sig_inputs(1, &key_id)),
                (id_2.clone(), create_sig_inputs(2, &key_id)),
                (id_3.clone(), create_sig_inputs(3, &key_id)),
            ],
        );
        let state = fake_state_with_signature_requests(
            height,
            [
                // One context without matched pre-signature
                fake_signature_request_context_with_pre_sig(
                    id_1.pre_signature_id.id() as u8,
                    key_id.clone(),
                    None,
                ),
                // One context without nonce
                fake_signature_request_context_with_pre_sig(
                    id_2.pre_signature_id.id() as u8,
                    key_id.clone(),
                    Some(id_2.pre_signature_id),
                ),
                // One completed context
                fake_signature_request_context_from_id(key_id.clone(), &id_3),
            ],
        );

        // Set up the IDKG pool
        let mut artifacts = Vec::new();
        // A share for the first incomplete context (deferred)
        let message = create_signature_share(&key_id, NODE_2, id_1);
        artifacts.push(UnvalidatedArtifact {
            message,
            peer_id: NODE_2,
            timestamp: UNIX_EPOCH,
        });

        // A share for the second incomplete context (deferred)
        let message = create_signature_share(&key_id, NODE_2, id_2.clone());
        artifacts.push(UnvalidatedArtifact {
            message,
            peer_id: NODE_2,
            timestamp: UNIX_EPOCH,
        });

        // A share for a the completed context (accepted)
        let message = create_signature_share(&key_id, NODE_2, id_3.clone());
        let msg_id_3 = message.message_id();
        artifacts.push(UnvalidatedArtifact {
            message,
            peer_id: NODE_2,
            timestamp: UNIX_EPOCH,
        });

        // A share for a the completed context, but specifying wrong pre-signature (dropped)
        let mut wrong_id_3 = id_3.clone();
        wrong_id_3.pre_signature_id = id_2.pre_signature_id;
        let message = create_signature_share(&key_id, NODE_2, wrong_id_3);
        let msg_id_4 = message.message_id();
        artifacts.push(UnvalidatedArtifact {
            message,
            peer_id: NODE_2,
            timestamp: UNIX_EPOCH,
        });

        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
                with_test_replica_logger(|logger| {
                    let (mut idkg_pool, signer) = create_signer_dependencies(pool_config, logger);
                    artifacts.iter().for_each(|a| idkg_pool.insert(a.clone()));

                    let change_set =
                        signer.validate_signature_shares(&idkg_pool, &block_reader, &state);
                    assert_eq!(change_set.len(), 2);
                    assert!(is_moved_to_validated(&change_set, &msg_id_3));
                    assert!(is_removed_from_unvalidated(&change_set, &msg_id_4));
                })
            },
        );
    }

    // Tests that duplicate shares from a signer for the same request
    // are dropped.
    #[test]
    fn test_duplicate_signature_shares_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_duplicate_signature_shares(key_id);
        }
    }

    fn test_duplicate_signature_shares(key_id: MasterPublicKeyId) {
        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
                with_test_replica_logger(|logger| {
                    let height = Height::from(100);
                    let mut uid_generator =
                        IDkgUIDGenerator::new(subnet_test_id(1), Height::new(0));
                    let id_2 = create_request_id(&mut uid_generator, Height::from(100));

                    let block_reader = TestIDkgBlockReader::for_signer_test(
                        height,
                        vec![(id_2.clone(), create_sig_inputs(2, &key_id))],
                    );
                    let state = fake_state_with_signature_requests(
                        height,
                        block_reader.requested_signatures().map(|(request_id, _)| {
                            fake_signature_request_context_from_id(key_id.clone(), request_id)
                        }),
                    );

                    let (mut idkg_pool, signer) = create_signer_dependencies(pool_config, logger);

                    // Set up the IDKG pool
                    // Validated pool has: {signature share 2, signer = NODE_2}
                    let share = create_signature_share(&key_id, NODE_2, id_2.clone());
                    let change_set = vec![IDkgChangeAction::AddToValidated(share)];
                    idkg_pool.apply_changes(change_set);

                    // Unvalidated pool has: {signature share 2, signer = NODE_2, height = 100}
                    let message = create_signature_share(&key_id, NODE_2, id_2.clone());
                    let msg_id_2 = message.message_id();
                    idkg_pool.insert(UnvalidatedArtifact {
                        message,
                        peer_id: NODE_2,
                        timestamp: UNIX_EPOCH,
                    });

                    let change_set =
                        signer.validate_signature_shares(&idkg_pool, &block_reader, &state);
                    assert_eq!(change_set.len(), 1);
                    assert!(is_handle_invalid(&change_set, &msg_id_2));
                })
            },
        )
    }

    // Tests that duplicate shares from a signer for the same request
    // in the unvalidated pool are dropped.
    #[test]
    fn test_duplicate_signature_shares_in_batch_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_duplicate_signature_shares_in_batch(key_id);
        }
    }

    fn test_duplicate_signature_shares_in_batch(key_id: MasterPublicKeyId) {
        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
                with_test_replica_logger(|logger| {
                    let height = Height::from(100);
                    let mut uid_generator =
                        IDkgUIDGenerator::new(subnet_test_id(1), Height::new(0));
                    let id_1 = create_request_id(&mut uid_generator, Height::from(100));

                    let block_reader = TestIDkgBlockReader::for_signer_test(
                        height,
                        vec![(id_1.clone(), create_sig_inputs(2, &key_id))],
                    );
                    let state = fake_state_with_signature_requests(
                        height,
                        block_reader.requested_signatures().map(|(request_id, _)| {
                            fake_signature_request_context_from_id(key_id.clone(), request_id)
                        }),
                    );

                    let (mut idkg_pool, signer) = create_signer_dependencies(pool_config, logger);

                    // Unvalidated pool has: {signature share 1, signer = NODE_2}
                    let message =
                        create_signature_share_with_nonce(&key_id, NODE_2, id_1.clone(), 0);
                    let msg_id_1 = message.message_id();
                    idkg_pool.insert(UnvalidatedArtifact {
                        message,
                        peer_id: NODE_2,
                        timestamp: UNIX_EPOCH,
                    });

                    // Unvalidated pool has: {signature share 2, signer = NODE_2}
                    let message =
                        create_signature_share_with_nonce(&key_id, NODE_2, id_1.clone(), 1);
                    let msg_id_2 = message.message_id();
                    idkg_pool.insert(UnvalidatedArtifact {
                        message,
                        peer_id: NODE_2,
                        timestamp: UNIX_EPOCH,
                    });

                    // Unvalidated pool has: {signature share 2, signer = NODE_3}
                    let message =
                        create_signature_share_with_nonce(&key_id, NODE_3, id_1.clone(), 2);
                    let msg_id_3 = message.message_id();
                    idkg_pool.insert(UnvalidatedArtifact {
                        message,
                        peer_id: NODE_3,
                        timestamp: UNIX_EPOCH,
                    });

                    let change_set =
                        signer.validate_signature_shares(&idkg_pool, &block_reader, &state);
                    assert_eq!(change_set.len(), 3);
                    // One is considered duplicate
                    assert!(is_handle_invalid(&change_set, &msg_id_1));
                    // One is considered validated
                    assert!(is_moved_to_validated(&change_set, &msg_id_2));
                    assert!(is_moved_to_validated(&change_set, &msg_id_3));
                })
            },
        )
    }

    // Tests purging of signature shares from unvalidated pool
    #[test]
    fn test_purge_unvalidated_signature_shares_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_purge_unvalidated_signature_shares(key_id);
        }
    }

    fn test_purge_unvalidated_signature_shares(key_id: MasterPublicKeyId) {
        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
                with_test_replica_logger(|logger| {
                    let height = Height::from(100);
                    let mut uid_generator =
                        IDkgUIDGenerator::new(subnet_test_id(1), Height::new(0));
                    let (id_1, id_2, id_3) = (
                        create_request_id(&mut uid_generator, Height::from(10)),
                        create_request_id(&mut uid_generator, Height::from(20)),
                        create_request_id(&mut uid_generator, Height::from(200)),
                    );

                    // Set up the transcript creation request
                    // The block requests transcripts 1, 3
                    let block_reader = TestIDkgBlockReader::for_signer_test(
                        height,
                        vec![
                            (id_1.clone(), create_sig_inputs(1, &key_id)),
                            (id_3.clone(), create_sig_inputs(3, &key_id)),
                        ],
                    );
                    let state = fake_state_with_signature_requests(
                        height,
                        block_reader.requested_signatures().map(|(request_id, _)| {
                            fake_signature_request_context_from_id(key_id.clone(), request_id)
                        }),
                    );

                    let (mut idkg_pool, signer) = create_signer_dependencies(pool_config, logger);

                    // Share 1: height <= current_height, in_progress (not purged)
                    let message = create_signature_share(&key_id, NODE_2, id_1);
                    idkg_pool.insert(UnvalidatedArtifact {
                        message,
                        peer_id: NODE_2,
                        timestamp: UNIX_EPOCH,
                    });

                    // Share 2: height <= current_height, !in_progress (purged)
                    let message = create_signature_share(&key_id, NODE_2, id_2);
                    let msg_id_2 = message.message_id();
                    idkg_pool.insert(UnvalidatedArtifact {
                        message,
                        peer_id: NODE_2,
                        timestamp: UNIX_EPOCH,
                    });

                    // Share 3: height > current_height (not purged)
                    let message = create_signature_share(&key_id, NODE_2, id_3);
                    idkg_pool.insert(UnvalidatedArtifact {
                        message,
                        peer_id: NODE_2,
                        timestamp: UNIX_EPOCH,
                    });

                    let change_set = signer.purge_artifacts(&idkg_pool, &state);
                    assert_eq!(change_set.len(), 1);
                    assert!(is_removed_from_unvalidated(&change_set, &msg_id_2));
                })
            },
        )
    }

    // Tests purging of signature shares from validated pool
    #[test]
    fn test_purge_validated_signature_shares_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_purge_validated_signature_shares(key_id);
        }
    }

    fn test_purge_validated_signature_shares(key_id: MasterPublicKeyId) {
        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
                with_test_replica_logger(|logger| {
                    let height = Height::from(100);
                    let mut uid_generator =
                        IDkgUIDGenerator::new(subnet_test_id(1), Height::new(0));
                    let (id_1, id_2, id_3) = (
                        create_request_id(&mut uid_generator, Height::from(10)),
                        create_request_id(&mut uid_generator, Height::from(20)),
                        create_request_id(&mut uid_generator, Height::from(200)),
                    );

                    // Set up the transcript creation request
                    // The block requests transcripts 1, 3
                    let block_reader = TestIDkgBlockReader::for_signer_test(
                        height,
                        vec![
                            (id_1.clone(), create_sig_inputs(1, &key_id)),
                            (id_3.clone(), create_sig_inputs(3, &key_id)),
                        ],
                    );
                    let state = fake_state_with_signature_requests(
                        height,
                        block_reader.requested_signatures().map(|(request_id, _)| {
                            fake_signature_request_context_from_id(key_id.clone(), request_id)
                        }),
                    );

                    let (mut idkg_pool, signer) = create_signer_dependencies(pool_config, logger);

                    // Share 1: height <= current_height, in_progress (not purged)
                    let share = create_signature_share(&key_id, NODE_2, id_1);
                    let change_set = vec![IDkgChangeAction::AddToValidated(share)];
                    idkg_pool.apply_changes(change_set);

                    // Share 2: height <= current_height, !in_progress (purged)
                    let share = create_signature_share(&key_id, NODE_2, id_2);
                    let msg_id_2 = share.message_id();
                    let change_set = vec![IDkgChangeAction::AddToValidated(share)];
                    idkg_pool.apply_changes(change_set);

                    // Share 3: height > current_height (not purged)
                    let share = create_signature_share(&key_id, NODE_2, id_3);
                    let change_set = vec![IDkgChangeAction::AddToValidated(share)];
                    idkg_pool.apply_changes(change_set);

                    let change_set = signer.purge_artifacts(&idkg_pool, &state);
                    assert_eq!(change_set.len(), 1);
                    assert!(is_removed_from_validated(&change_set, &msg_id_2));
                })
            },
        )
    }

    // Tests aggregating ecdsa signature shares into a complete signature
    #[test]
    fn test_ecdsa_get_completed_signature() {
        let mut rng = reproducible_rng();
        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
                with_test_replica_logger(|logger| {
                    let (mut idkg_pool, _) =
                        create_signer_dependencies(pool_config, logger.clone());
                    let mut uid_generator =
                        IDkgUIDGenerator::new(subnet_test_id(1), Height::new(0));
                    let req_id = create_request_id(&mut uid_generator, Height::from(10));
                    let env = CanisterThresholdSigTestEnvironment::new(3, &mut rng);
                    let (dealers, receivers) = env.choose_dealers_and_receivers(
                        &IDkgParticipants::AllNodesAsDealersAndReceivers,
                        &mut rng,
                    );
                    let key_transcript = generate_key_transcript(
                        &env,
                        &dealers,
                        &receivers,
                        AlgorithmId::ThresholdEcdsaSecp256k1,
                        &mut rng,
                    );
                    let derivation_path = ExtendedDerivationPath {
                        caller: canister_test_id(1).get(),
                        derivation_path: vec![],
                    };
                    let pre_sig_id = req_id.pre_signature_id;
                    let message_hash = [0; 32];
                    let context = SignWithThresholdContext {
                        request: RequestBuilder::new().sender(canister_test_id(1)).build(),
                        args: ThresholdArguments::Ecdsa(EcdsaArguments {
                            key_id: fake_ecdsa_key_id(),
                            message_hash,
                        }),
                        pseudo_random_id: req_id.pseudo_random_id,
                        derivation_path: vec![],
                        batch_time: UNIX_EPOCH,
                        matched_pre_signature: Some((pre_sig_id, req_id.height)),
                        nonce: Some([2; 32]),
                    };
                    let sig_inputs = generate_tecdsa_protocol_inputs(
                        &env,
                        &dealers,
                        &receivers,
                        &key_transcript,
                        &message_hash,
                        Randomness::from(context.nonce.unwrap()),
                        &derivation_path,
                        AlgorithmId::ThresholdEcdsaSecp256k1,
                        &mut rng,
                    );

                    // Set up the transcript creation request
                    let block_reader = TestIDkgBlockReader::for_signer_test(
                        Height::from(100),
                        vec![(req_id.clone(), (&sig_inputs).into())],
                    );

                    let metrics = IDkgPayloadMetrics::new(MetricsRegistry::new());
                    let crypto: Arc<dyn ConsensusCrypto> = env
                        .nodes
                        .filter_by_receivers(&sig_inputs)
                        .next()
                        .unwrap()
                        .crypto();

                    {
                        let sig_builder = ThresholdSignatureBuilderImpl::new(
                            &block_reader,
                            crypto.deref(),
                            &idkg_pool,
                            &metrics,
                            logger.clone(),
                        );

                        // There are no signature shares yet, no signature can be completed
                        let result = sig_builder.get_completed_signature(&context);
                        assert_matches!(result, None);
                    }

                    // Generate signature shares and add to validated
                    let change_set = env
                        .nodes
                        .filter_by_receivers(&sig_inputs)
                        .map(|receiver| {
                            receiver.load_tecdsa_sig_transcripts(&sig_inputs);
                            let share =
                                ThresholdEcdsaSigner::create_sig_share(receiver, &sig_inputs)
                                    .expect("failed to create sig share");
                            EcdsaSigShare {
                                signer_id: receiver.id(),
                                request_id: req_id.clone(),
                                share,
                            }
                        })
                        .map(|share| {
                            IDkgChangeAction::AddToValidated(IDkgMessage::EcdsaSigShare(share))
                        })
                        .collect::<Vec<_>>();
                    idkg_pool.apply_changes(change_set);

                    let sig_builder = ThresholdSignatureBuilderImpl::new(
                        &block_reader,
                        crypto.deref(),
                        &idkg_pool,
                        &metrics,
                        logger.clone(),
                    );

                    // Signature completion should succeed now.
                    let r1 = sig_builder.get_completed_signature(&context);
                    // Compare to combined signature returned by crypto environment
                    let r2 =
                        CombinedSignature::Ecdsa(run_tecdsa_protocol(&env, &sig_inputs, &mut rng));
                    assert_matches!(r1, Some(ref s) if s == &r2);

                    // If the context's nonce hasn't been set yet, no signature should be completed
                    let mut context_without_nonce = context.clone();
                    context_without_nonce.nonce = None;
                    let res = sig_builder.get_completed_signature(&context_without_nonce);
                    assert_eq!(None, res);

                    // If resolving the transcript refs fails, no signature should be completed
                    let block_reader = block_reader.clone().with_fail_to_resolve();
                    let sig_builder = ThresholdSignatureBuilderImpl::new(
                        &block_reader,
                        crypto.deref(),
                        &idkg_pool,
                        &metrics,
                        logger,
                    );

                    let result = sig_builder.get_completed_signature(&context);
                    assert_matches!(result, None);
                });
            },
        )
    }

    // Tests aggregating schnorr signature shares into a complete signature
    #[test]
    fn test_schnorr_get_completed_signature_all_algorithms() {
        for algorithm in AlgorithmId::all_threshold_schnorr_algorithms() {
            println!("Running test for algorithm {algorithm}");
            test_schnorr_get_completed_signature(algorithm);
        }
    }

    fn test_schnorr_get_completed_signature(algorithm: AlgorithmId) {
        let mut rng = reproducible_rng();
        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
                with_test_replica_logger(|logger| {
                    let (mut idkg_pool, _) =
                        create_signer_dependencies(pool_config, logger.clone());
                    let mut uid_generator =
                        IDkgUIDGenerator::new(subnet_test_id(1), Height::new(0));
                    let req_id = create_request_id(&mut uid_generator, Height::from(10));
                    let env = CanisterThresholdSigTestEnvironment::new(3, &mut rng);
                    let (dealers, receivers) = env.choose_dealers_and_receivers(
                        &IDkgParticipants::AllNodesAsDealersAndReceivers,
                        &mut rng,
                    );
                    let key_transcript =
                        generate_key_transcript(&env, &dealers, &receivers, algorithm, &mut rng);
                    let derivation_path = ExtendedDerivationPath {
                        caller: canister_test_id(1).get(),
                        derivation_path: vec![],
                    };
                    let pre_sig_id = req_id.pre_signature_id;
                    let message = vec![0; 32];
                    let context = SignWithThresholdContext {
                        request: RequestBuilder::new().sender(canister_test_id(1)).build(),
                        args: ThresholdArguments::Schnorr(SchnorrArguments {
                            key_id: fake_schnorr_key_id(schnorr_algorithm(algorithm)),
                            message: Arc::new(message.clone()),
                        }),
                        pseudo_random_id: req_id.pseudo_random_id,
                        derivation_path: vec![],
                        batch_time: UNIX_EPOCH,
                        matched_pre_signature: Some((pre_sig_id, req_id.height)),
                        nonce: Some([2; 32]),
                    };
                    let sig_inputs = generate_tschnorr_protocol_inputs(
                        &env,
                        &dealers,
                        &receivers,
                        &key_transcript,
                        &message,
                        Randomness::from(context.nonce.unwrap()),
                        &derivation_path,
                        algorithm,
                        &mut rng,
                    );

                    // Set up the transcript creation request
                    let block_reader = TestIDkgBlockReader::for_signer_test(
                        Height::from(100),
                        vec![(req_id.clone(), (&sig_inputs).into())],
                    );

                    let metrics = IDkgPayloadMetrics::new(MetricsRegistry::new());
                    let crypto: Arc<dyn ConsensusCrypto> = env
                        .nodes
                        .filter_by_receivers(&sig_inputs)
                        .next()
                        .unwrap()
                        .crypto();

                    {
                        let sig_builder = ThresholdSignatureBuilderImpl::new(
                            &block_reader,
                            crypto.deref(),
                            &idkg_pool,
                            &metrics,
                            logger.clone(),
                        );

                        // There are no signature shares yet, no signature can be completed
                        let result = sig_builder.get_completed_signature(&context);
                        assert_matches!(result, None);
                    }

                    // Generate signature shares and add to validated
                    let change_set = env
                        .nodes
                        .filter_by_receivers(&sig_inputs)
                        .map(|receiver| {
                            receiver.load_tschnorr_sig_transcripts(&sig_inputs);
                            let share =
                                ThresholdSchnorrSigner::create_sig_share(receiver, &sig_inputs)
                                    .expect("failed to create sig share");
                            SchnorrSigShare {
                                signer_id: receiver.id(),
                                request_id: req_id.clone(),
                                share,
                            }
                        })
                        .map(|share| {
                            IDkgChangeAction::AddToValidated(IDkgMessage::SchnorrSigShare(share))
                        })
                        .collect::<Vec<_>>();
                    idkg_pool.apply_changes(change_set);

                    let sig_builder = ThresholdSignatureBuilderImpl::new(
                        &block_reader,
                        crypto.deref(),
                        &idkg_pool,
                        &metrics,
                        logger.clone(),
                    );

                    // Signature completion should succeed now.
                    let r1 = sig_builder.get_completed_signature(&context);
                    // Compare to combined signature returned by crypto environment
                    let r2 = CombinedSignature::Schnorr(run_tschnorr_protocol(
                        &env,
                        &sig_inputs,
                        &mut rng,
                    ));
                    assert_matches!(r1, Some(ref s) if s == &r2);

                    // If the context's nonce hasn't been set yet, no signature should be completed
                    let mut context_without_nonce = context.clone();
                    context_without_nonce.nonce = None;
                    let res = sig_builder.get_completed_signature(&context_without_nonce);
                    assert_eq!(None, res);

                    // If resolving the transcript refs fails, no signature should be completed
                    let block_reader = block_reader.clone().with_fail_to_resolve();
                    let sig_builder = ThresholdSignatureBuilderImpl::new(
                        &block_reader,
                        crypto.deref(),
                        &idkg_pool,
                        &metrics,
                        logger,
                    );

                    let result = sig_builder.get_completed_signature(&context);
                    assert_matches!(result, None);
                });
            },
        )
    }
}
