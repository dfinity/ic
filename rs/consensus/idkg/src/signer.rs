//! The signature process manager

use crate::{
    complaints::IDkgTranscriptLoader,
    metrics::{timed_call, IDkgPayloadMetrics, ThresholdSignerMetrics},
    utils::{
        build_signature_inputs, load_transcripts, update_purge_height, IDkgBlockReaderImpl,
        IDkgSchedule, MAX_PARALLELISM,
    },
};
use ic_consensus_utils::crypto::ConsensusCrypto;
use ic_interfaces::{
    consensus_pool::ConsensusBlockCache,
    crypto::{
        ErrorReproducibility, ThresholdEcdsaSigVerifier, ThresholdEcdsaSigner,
        ThresholdSchnorrSigVerifier, ThresholdSchnorrSigner, VetKdProtocol,
    },
    idkg::{IDkgChangeAction, IDkgChangeSet, IDkgPool},
};
use ic_interfaces_state_manager::{CertifiedStateSnapshot, StateReader};
use ic_logger::{debug, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_replicated_state::{
    metadata_state::subnet_call_context_manager::{SignWithThresholdContext, ThresholdArguments},
    ReplicatedState,
};
use ic_types::{
    artifact::IDkgMessageId,
    consensus::idkg::{
        common::{CombinedSignature, SignatureScheme, ThresholdSigInputs, ThresholdSigInputsRef},
        ecdsa_sig_share_prefix, schnorr_sig_share_prefix, vetkd_key_share_prefix, EcdsaSigShare,
        IDkgBlockReader, IDkgMessage, IDkgStats, RequestId, SchnorrSigShare, SigShare,
        VetKdKeyShare,
    },
    crypto::{
        canister_threshold_sig::error::{
            ThresholdEcdsaCombineSigSharesError, ThresholdEcdsaCreateSigShareError,
            ThresholdEcdsaVerifySigShareError, ThresholdSchnorrCombineSigSharesError,
            ThresholdSchnorrCreateSigShareError, ThresholdSchnorrVerifySigShareError,
        },
        vetkd::{VetKdKeyShareCreationError, VetKdKeyShareVerificationError},
    },
    messages::CallbackId,
    Height, NodeId,
};
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Debug, Formatter},
    sync::Arc,
};

#[derive(Clone, Debug)]
#[allow(dead_code)]
enum CreateSigShareError {
    Ecdsa(ThresholdEcdsaCreateSigShareError),
    Schnorr(ThresholdSchnorrCreateSigShareError),
    VetKd(Box<VetKdKeyShareCreationError>),
}

impl CreateSigShareError {
    fn is_nidkg_transcript_not_loaded(&self) -> bool {
        match self {
            CreateSigShareError::Ecdsa(_) => false,
            CreateSigShareError::Schnorr(_) => false,
            CreateSigShareError::VetKd(err) => {
                matches!(
                    err.as_ref(),
                    &VetKdKeyShareCreationError::ThresholdSigDataNotFound(_)
                )
            }
        }
    }
}

#[derive(Clone, Debug)]
enum VerifySigShareError {
    Ecdsa(ThresholdEcdsaVerifySigShareError),
    Schnorr(ThresholdSchnorrVerifySigShareError),
    VetKd(VetKdKeyShareVerificationError),
    ThresholdSchemeMismatch,
}

impl VerifySigShareError {
    fn is_reproducible(&self) -> bool {
        match self {
            VerifySigShareError::Ecdsa(err) => err.is_reproducible(),
            VerifySigShareError::Schnorr(err) => err.is_reproducible(),
            VerifySigShareError::VetKd(err) => err.is_reproducible(),
            VerifySigShareError::ThresholdSchemeMismatch => true,
        }
    }

    fn is_nidkg_transcript_not_loaded(&self) -> bool {
        match self {
            VerifySigShareError::Ecdsa(_) => false,
            VerifySigShareError::Schnorr(_) => false,
            VerifySigShareError::VetKd(err) => {
                matches!(
                    err,
                    &VetKdKeyShareVerificationError::ThresholdSigDataNotFound(_)
                )
            }
            VerifySigShareError::ThresholdSchemeMismatch => false,
        }
    }
}

#[derive(Clone, Debug)]
enum CombineSigSharesError {
    Ecdsa(ThresholdEcdsaCombineSigSharesError),
    Schnorr(ThresholdSchnorrCombineSigSharesError),
    VetKdUnexpected,
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
        schedule: &IDkgSchedule<Height>,
    ) -> IDkgChangeSet;
}

pub(crate) struct ThresholdSignerImpl {
    node_id: NodeId,
    consensus_block_cache: Arc<dyn ConsensusBlockCache>,
    crypto: Arc<dyn ConsensusCrypto>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    metrics: ThresholdSignerMetrics,
    log: ReplicaLogger,
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
            metrics: ThresholdSignerMetrics::new(metrics_registry),
            log,
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
        type Inputs = (RequestId, ThresholdSigInputsRef);
        let inputs: Vec<Inputs> = state_snapshot
            .get_state()
            .signature_request_contexts()
            .iter()
            .flat_map(|(id, context)| {
                build_signature_inputs(*id, context, block_reader).map_err(|err| {
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
            .collect();
        let chunk_size = (inputs.len().max(1) + MAX_PARALLELISM - 1) / MAX_PARALLELISM;
        inputs
            .par_chunks(chunk_size)
            .flat_map_iter(|chunk| {
                chunk
                    .iter()
                    .flat_map(|(request_id, sig_inputs_ref)| {
                        self.resolve_ref(sig_inputs_ref, block_reader, "send_signature_shares")
                            .map(|sig_inputs| (request_id, sig_inputs))
                    })
                    .flat_map(|(request_id, sig_inputs)| {
                        self.create_signature_share(
                            idkg_pool,
                            transcript_loader,
                            *request_id,
                            sig_inputs,
                        )
                    })
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
            .iter()
            .map(|(id, c)| {
                let inputs = build_signature_inputs(*id, c, block_reader).map_err(|err| if err.is_fatal() {
                    warn!(every_n_seconds => 15, self.log,
                        "validate_signature_shares(): failed to build signatures inputs: {:?}", 
                        err
                    );
                    self.metrics.sign_errors_inc("signature_inputs_malformed");
                }).ok();
                (*id, inputs)
            })
            .collect::<BTreeMap<_, _>>();

        // Collection of validated shares
        let mut inputs = Vec::new();
        let mut ret = Vec::new();
        // Iterate over all signature shares of all schemes
        for (id, share) in idkg_pool.unvalidated().signature_shares() {
            match Action::new(
                &sig_inputs_map,
                &share.request_id(),
                state_snapshot.get_height(),
            ) {
                Action::Process(sig_inputs_ref) => {
                    if self.signer_has_issued_share(
                        idkg_pool,
                        &share.signer(),
                        &share.request_id(),
                        share.scheme(),
                    ) {
                        // The node already sent a valid share for this request
                        self.metrics.sign_errors_inc("duplicate_sig_share");
                        ret.push(IDkgChangeAction::HandleInvalid(
                            id,
                            format!("Duplicate signature share: {}", share),
                        ));
                    } else {
                        inputs.push((id, share, sig_inputs_ref));
                    }
                }
                Action::Drop => ret.push(IDkgChangeAction::RemoveUnvalidated(id)),
                Action::Defer => {}
            }
        }
        let chunk_size = (inputs.len().max(1) + MAX_PARALLELISM - 1) / MAX_PARALLELISM;
        let results: Vec<_> = inputs
            .into_par_iter()
            .chunks(chunk_size)
            .flat_map_iter(|chunk| {
                chunk.into_iter().flat_map(|(id, share, sig_inputs_ref)| {
                    let key = (share.request_id(), share.signer());
                    self.validate_signature_share(
                        idkg_pool,
                        block_reader,
                        id.clone(),
                        share,
                        sig_inputs_ref,
                    )
                    .map(|action| (id, key, action))
                })
            })
            .collect();

        let mut validated_sig_shares = BTreeSet::new();
        for (id, key, action) in results.into_iter() {
            if matches!(&action, IDkgChangeAction::MoveToValidated(_)) {
                if validated_sig_shares.contains(&key) {
                    self.metrics
                        .sign_errors_inc("duplicate_sig_shares_in_batch");
                    ret.push(IDkgChangeAction::HandleInvalid(
                        id,
                        format!("Duplicate share in unvalidated batch: {:?}", action),
                    ));
                    continue;
                }
                validated_sig_shares.insert(key);
            }
            ret.push(action);
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
                let label = if error.is_nidkg_transcript_not_loaded() {
                    "verify_sig_share_nidkg_transcript_not_loaded"
                } else {
                    "verify_sig_share_transient"
                };
                self.metrics.sign_errors_inc(label);
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
            .keys()
            .cloned()
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
            // No dependencies for VetKd
            ThresholdSigInputs::VetKd(_) => vec![],
        };
        load_transcripts(idkg_pool, transcript_loader, &transcripts)
    }

    /// Helper to create the signature share
    fn create_signature_share(
        &self,
        idkg_pool: &dyn IDkgPool,
        transcript_loader: &dyn IDkgTranscriptLoader,
        request_id: RequestId,
        sig_inputs: ThresholdSigInputs,
    ) -> IDkgChangeSet {
        if let Some(changes) = self.load_dependencies(idkg_pool, transcript_loader, &sig_inputs) {
            return changes;
        }

        match self.crypto_create_sig_share(request_id, sig_inputs) {
            Err(err) => {
                warn!(
                    every_n_seconds => 15,
                    self.log,
                    "Failed to create sig share: request_id = {:?}, {:?}",
                    request_id,
                    err
                );
                let label = if err.is_nidkg_transcript_not_loaded() {
                    "create_sig_share_nidkg_transcript_not_loaded"
                } else {
                    "create_sig_share"
                };
                self.metrics.sign_errors_inc(label);
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
        request_id: RequestId,
        sig_inputs: ThresholdSigInputs,
    ) -> Result<IDkgMessage, CreateSigShareError> {
        match sig_inputs {
            ThresholdSigInputs::Ecdsa(inputs) => {
                ThresholdEcdsaSigner::create_sig_share(&*self.crypto, &inputs).map_or_else(
                    |err| Err(CreateSigShareError::Ecdsa(err)),
                    |share| {
                        let sig_share = EcdsaSigShare {
                            signer_id: self.node_id,
                            request_id,
                            share,
                        };
                        Ok(IDkgMessage::EcdsaSigShare(sig_share))
                    },
                )
            }
            ThresholdSigInputs::Schnorr(inputs) => {
                ThresholdSchnorrSigner::create_sig_share(&*self.crypto, &inputs).map_or_else(
                    |err| Err(CreateSigShareError::Schnorr(err)),
                    |share| {
                        let sig_share = SchnorrSigShare {
                            signer_id: self.node_id,
                            request_id,
                            share,
                        };
                        Ok(IDkgMessage::SchnorrSigShare(sig_share))
                    },
                )
            }
            ThresholdSigInputs::VetKd(inputs) => {
                VetKdProtocol::create_encrypted_key_share(&*self.crypto, inputs).map_or_else(
                    |err| Err(CreateSigShareError::VetKd(Box::new(err))),
                    |share| {
                        let sig_share = VetKdKeyShare {
                            signer_id: self.node_id,
                            request_id,
                            share,
                        };
                        Ok(IDkgMessage::VetKdKeyShare(sig_share))
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
            (ThresholdSigInputs::VetKd(inputs), SigShare::VetKd(share)) => {
                VetKdProtocol::verify_encrypted_key_share(
                    &*self.crypto,
                    share.signer_id,
                    &share.share,
                    inputs,
                )
                .map_or_else(
                    |err| Err(VerifySigShareError::VetKd(err)),
                    |_| Ok(IDkgMessage::VetKdKeyShare(share)),
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
            SignatureScheme::VetKd => {
                let prefix = vetkd_key_share_prefix(request_id, signer_id);
                validated
                    .vetkd_key_shares_by_prefix(prefix)
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
        in_progress: &BTreeSet<CallbackId>,
    ) -> bool {
        let request_id = share.request_id();
        request_id.height <= current_height && !in_progress.contains(&request_id.callback_id)
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
        schedule: &IDkgSchedule<Height>,
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
            .iter()
            .flat_map(|(callback_id, context)| match &context.args {
                ThresholdArguments::Ecdsa(_) | ThresholdArguments::Schnorr(_) => {
                    context.matched_pre_signature.map(|(_, height)| RequestId {
                        callback_id: *callback_id,
                        height,
                    })
                }
                ThresholdArguments::VetKd(args) => Some(RequestId {
                    callback_id: *callback_id,
                    height: args.height,
                }),
            })
            .collect();
        idkg_pool
            .stats()
            .update_active_signature_requests(active_requests);

        let mut changes = update_purge_height(&schedule.last_purge, snapshot.get_height())
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
        changes.append(&mut schedule.call_next(&calls));
        changes
    }
}

pub(crate) trait ThresholdSignatureBuilder {
    /// Returns the signature for the given context, if it can be successfully
    /// built from the current sig shares in the IDKG pool
    fn get_completed_signature(
        &self,
        id: CallbackId,
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
            // We don't expect to combine VetKD shares here
            // (this is done by the VetKD payload builder instead).
            ThresholdSigInputs::VetKd(_) => Err(CombineSigSharesError::VetKdUnexpected),
        };
        stats.record_sig_share_aggregation(request_id, start.elapsed());
        ret
    }
}

impl ThresholdSignatureBuilder for ThresholdSignatureBuilderImpl<'_> {
    fn get_completed_signature(
        &self,
        callback_id: CallbackId,
        context: &SignWithThresholdContext,
    ) -> Option<CombinedSignature> {
        // Find the sig inputs for the request and translate the refs.
        let (request_id, sig_inputs_ref) =
            build_signature_inputs(callback_id, context, self.block_reader)
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
        requested_signatures: &'a BTreeMap<CallbackId, Option<(RequestId, ThresholdSigInputsRef)>>,
        request_id: &RequestId,
        certified_height: Height,
    ) -> Action<'a> {
        let msg_height = request_id.height;
        if msg_height > certified_height {
            // Message is from a node ahead of us, keep it to be
            // processed later
            return Action::Defer;
        }

        match requested_signatures.get(&request_id.callback_id) {
            Some(Some((own_request_id, sig_inputs))) => {
                if request_id == own_request_id {
                    Action::Process(sig_inputs)
                } else {
                    // A signature for the received ID was requested and the context was completed.
                    // However, the received share claims a pre-signature was matched at a different
                    // height, therefore drop the message.
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

impl Debug for Action<'_> {
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
    use crate::{test_utils::*, utils::algorithm_for_key_id};
    use assert_matches::assert_matches;
    use ic_crypto_test_utils_canister_threshold_sigs::{
        generate_key_transcript, generate_tecdsa_protocol_inputs,
        generate_tschnorr_protocol_inputs, run_tecdsa_protocol, run_tschnorr_protocol,
        CanisterThresholdSigTestEnvironment, IDkgParticipants,
    };
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_interfaces::p2p::consensus::{MutablePool, UnvalidatedArtifact};
    use ic_management_canister_types_private::{MasterPublicKeyId, SchnorrAlgorithm};
    use ic_replicated_state::metadata_state::subnet_call_context_manager::{
        EcdsaArguments, SchnorrArguments, ThresholdArguments, VetKdArguments,
    };
    use ic_test_utilities::crypto::CryptoReturningOk;
    use ic_test_utilities_consensus::{idkg::*, IDkgStatsNoOp};
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_types::{
        ids::{canister_test_id, subnet_test_id, user_test_id, NODE_1, NODE_2, NODE_3},
        messages::RequestBuilder,
    };
    use ic_types::{
        consensus::idkg::*,
        crypto::{AlgorithmId, ExtendedDerivationPath},
        time::UNIX_EPOCH,
        Height, Randomness,
    };
    use std::{ops::Deref, sync::RwLock};

    #[test]
    fn test_ecdsa_signer_action() {
        let key_id = fake_ecdsa_idkg_master_public_key_id();
        let height = Height::from(100);
        let (id_1, id_2, id_3, id_4, id_5) = (
            request_id(1, height),
            request_id(2, Height::from(10)),
            request_id(3, height),
            request_id(4, height),
            request_id(5, Height::from(200)),
        );

        let requested = BTreeMap::from([
            (
                id_1.callback_id,
                Some((id_1, create_sig_inputs(1, &key_id).sig_inputs_ref)),
            ),
            (
                id_2.callback_id,
                Some((id_2, create_sig_inputs(2, &key_id).sig_inputs_ref)),
            ),
            (
                id_3.callback_id,
                Some((id_3, create_sig_inputs(3, &key_id).sig_inputs_ref)),
            ),
            (id_4.callback_id, None),
        ]);

        // Message from a node ahead of us
        assert_eq!(Action::new(&requested, &id_5, height), Action::Defer);

        // Messages for transcripts not being currently requested
        assert_eq!(
            Action::new(&requested, &request_id(6, Height::from(100)), height),
            Action::Drop
        );
        assert_eq!(
            Action::new(&requested, &request_id(7, Height::from(10)), height),
            Action::Drop
        );

        // Messages for signatures currently requested
        let action = Action::new(&requested, &id_1, height);
        assert_matches!(action, Action::Process(_));

        let action = Action::new(&requested, &id_2, height);
        assert_matches!(action, Action::Process(_));

        // Message for a signature currently requested but specifying wrong height
        let wrong_id_2 = RequestId {
            height: id_2.height.decrement(),
            ..id_2
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
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, signer, state_manager) =
                    create_signer_dependencies_and_state_manager(pool_config, logger);
                let transcript_loader = TestIDkgTranscriptLoader::default();
                let height_0 = Height::from(0);
                let height_30 = Height::from(30);

                let expected_state_snapshot = Arc::new(RwLock::new(FakeCertifiedStateSnapshot {
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

                let id_1 = request_id(1, height_0);
                let id_2 = request_id(2, height_30);

                let share1 = create_signature_share(&key_id, NODE_1, id_1);
                let msg_id1 = share1.message_id();
                let share2 = create_signature_share(&key_id, NODE_2, id_2);
                let msg_id2 = share2.message_id();
                let change_set = vec![
                    IDkgChangeAction::AddToValidated(share1),
                    IDkgChangeAction::AddToValidated(share2),
                ];
                idkg_pool.apply(change_set);

                let schedule = IDkgSchedule::new(Height::from(0));
                // Certified height doesn't increase, so share1 shouldn't be purged
                let change_set = signer.on_state_change(&idkg_pool, &transcript_loader, &schedule);
                assert_eq!(*schedule.last_purge.borrow(), height_0);
                assert!(change_set.is_empty());

                // Certified height increases, so share1 is purged
                let new_height = expected_state_snapshot.write().unwrap().inc_height_by(29);
                let change_set = signer.on_state_change(&idkg_pool, &transcript_loader, &schedule);
                assert_eq!(*schedule.last_purge.borrow(), new_height);
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_validated(&change_set, &msg_id1));
                idkg_pool.apply(change_set);

                // Certified height increases above share2, so it is purged
                let new_height = expected_state_snapshot.write().unwrap().inc_height_by(1);
                let change_set = signer.on_state_change(&idkg_pool, &transcript_loader, &schedule);
                assert_eq!(*schedule.last_purge.borrow(), new_height);
                assert_eq!(height_30, new_height);
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_validated(&change_set, &msg_id2));
            })
        })
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
        let mut generator = IDkgUIDGenerator::new(subnet_test_id(1), Height::new(0));
        let height = Height::from(100);
        let ids: Vec<_> = (0..5).map(|i| request_id(i, height)).collect();

        // Set up the IDKG pool. Pool has shares for requests 0, 1, 2.
        // Only the share for request 0 is issued by us
        let shares = vec![
            create_signature_share(&key_id, NODE_1, ids[0]),
            create_signature_share(&key_id, NODE_2, ids[1]),
            create_signature_share(&key_id, NODE_3, ids[2]),
        ];

        // The block has pre-signatures for requests 0, 3, 4
        let sig_inputs: Vec<_> = [0, 3, 4]
            .into_iter()
            .map(|i: usize| {
                (
                    ids[i],
                    generator.next_pre_signature_id(),
                    create_sig_inputs(i as u8, &key_id),
                )
            })
            .collect();

        let block_reader = TestIDkgBlockReader::for_signer_test(
            Height::from(100),
            sig_inputs
                .iter()
                .map(|(_, pid, inputs)| (*pid, inputs.clone()))
                .collect(),
        );
        let transcript_loader: TestIDkgTranscriptLoader = Default::default();

        let state = fake_state_with_signature_requests(
            height,
            sig_inputs.into_iter().map(|(request_id, pre_sig_id, _)| {
                fake_signature_request_context_from_id(key_id.clone(), pre_sig_id, request_id)
            }),
        );

        // Test using CryptoReturningOK
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, signer) = create_signer_dependencies(pool_config, logger);

                idkg_pool.apply(
                    shares
                        .iter()
                        .map(|s| IDkgChangeAction::AddToValidated(s.clone()))
                        .collect(),
                );

                // Since request 0 is already in progress, we should issue
                // shares only for transcripts 3, 4
                let change_set = signer.send_signature_shares(
                    &idkg_pool,
                    &transcript_loader,
                    &block_reader,
                    &state,
                );
                assert_eq!(change_set.len(), 2);
                assert!(is_signature_share_added_to_validated(
                    &change_set,
                    &ids[3],
                    block_reader.tip_height()
                ));
                assert!(is_signature_share_added_to_validated(
                    &change_set,
                    &ids[4],
                    block_reader.tip_height()
                ));
            })
        });

        // Test using crypto without keys
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, signer) = create_signer_dependencies_with_crypto(
                    pool_config,
                    logger,
                    Some(crypto_without_keys()),
                );

                idkg_pool.apply(
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
        });
    }

    // Tests that no signature shares for incomplete contexts are created
    #[test]
    fn test_send_signature_shares_incomplete_contexts_all_idkg_algorithms() {
        // Only test IDKG algorithms, as VetKD contexts don't require pre-signatures
        // and therefore cannot be "incomplete".
        for key_id in fake_master_public_key_ids_for_all_idkg_algorithms() {
            println!("Running test for key ID {key_id}");
            test_send_signature_shares_incomplete_contexts(key_id);
        }
    }

    fn test_send_signature_shares_incomplete_contexts(key_id: IDkgMasterPublicKeyId) {
        let mut generator = IDkgUIDGenerator::new(subnet_test_id(1), Height::new(0));
        let height = Height::from(100);
        let ids: Vec<_> = (0..5).map(|i| request_id(i, height)).collect();
        let pids: Vec<_> = (0..5).map(|_| generator.next_pre_signature_id()).collect();

        let wrong_key_id = match key_id.inner() {
            MasterPublicKeyId::Ecdsa(_) => {
                fake_schnorr_idkg_master_public_key_id(SchnorrAlgorithm::Ed25519)
            }
            MasterPublicKeyId::Schnorr(_) => fake_ecdsa_idkg_master_public_key_id(),
            MasterPublicKeyId::VetKd(_) => panic!("not applicable to vetKD"),
        };

        // Set up the signature requests
        // The block contains pre-signatures for all requests except request 4
        let block_reader = TestIDkgBlockReader::for_signer_test(
            height,
            vec![
                (pids[0], create_sig_inputs(0, &key_id)),
                (pids[1], create_sig_inputs(1, &key_id)),
                (pids[2], create_sig_inputs(2, &key_id)),
                (pids[3], create_sig_inputs(3, &wrong_key_id)),
            ],
        );
        let transcript_loader: TestIDkgTranscriptLoader = Default::default();

        let state = fake_state_with_signature_requests(
            height,
            [
                // One context without matched pre-signature
                fake_signature_request_context_with_pre_sig(ids[0], key_id.clone(), None),
                // One context without nonce
                fake_signature_request_context_with_pre_sig(ids[1], key_id.clone(), Some(pids[1])),
                // One completed context
                fake_signature_request_context_from_id(key_id.clone().into(), pids[2], ids[2]),
                // One completed context matched to a pre-signature of the wrong scheme
                fake_signature_request_context_from_id(key_id.clone().into(), pids[3], ids[3]),
                // One completed context matched to a pre-signature that doesn't exist
                fake_signature_request_context_from_id(key_id.clone().into(), pids[4], ids[4]),
            ],
        );

        // Test using CryptoReturningOK
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (idkg_pool, signer) = create_signer_dependencies(pool_config, logger);

                // We should issue shares only for completed request 2
                let change_set = signer.send_signature_shares(
                    &idkg_pool,
                    &transcript_loader,
                    &block_reader,
                    &state,
                );

                assert_eq!(change_set.len(), 1);
                assert!(is_signature_share_added_to_validated(
                    &change_set,
                    &ids[2],
                    block_reader.tip_height()
                ));
            })
        });
    }

    #[test]
    fn test_send_signature_shares_when_failure_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_send_signature_shares_when_failure(key_id);
        }
    }

    fn test_send_signature_shares_when_failure(key_id: MasterPublicKeyId) {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let mut generator = IDkgUIDGenerator::new(subnet_test_id(1), Height::new(0));
                let height = Height::from(100);
                let ids: Vec<_> = (0..3).map(|i| request_id(i, height)).collect();
                let pids: Vec<_> = (0..3).map(|_| generator.next_pre_signature_id()).collect();

                // Set up the signature requests
                let block_reader = TestIDkgBlockReader::for_signer_test(
                    height,
                    vec![
                        (pids[0], create_sig_inputs(0, &key_id)),
                        (pids[1], create_sig_inputs(1, &key_id)),
                        (pids[2], create_sig_inputs(2, &key_id)),
                    ],
                );
                let state = fake_state_with_signature_requests(
                    height,
                    (0..3).map(|i| {
                        fake_signature_request_context_from_id(key_id.clone(), pids[i], ids[i])
                    }),
                );

                let (mut idkg_pool, signer) = create_signer_dependencies(pool_config, logger);

                let transcript_loader =
                    TestIDkgTranscriptLoader::new(TestTranscriptLoadStatus::Failure);
                let change_set = signer.send_signature_shares(
                    &idkg_pool,
                    &transcript_loader,
                    &block_reader,
                    &state,
                );

                if key_id.is_idkg_key() {
                    // No shares should be created for IDKG keys when transcripts fail to load
                    assert!(change_set.is_empty());
                } else {
                    // NiDKG transcripts are loaded ahead of time, so creation should succeed, even if
                    // IDKG transcripts fail to load.
                    assert_eq!(change_set.len(), 3);
                }
                idkg_pool.apply(change_set);

                let transcript_loader =
                    TestIDkgTranscriptLoader::new(TestTranscriptLoadStatus::Success);
                let change_set = signer.send_signature_shares(
                    &idkg_pool,
                    &transcript_loader,
                    &block_reader,
                    &state,
                );

                if key_id.is_idkg_key() {
                    // IDKG key siganture shares should be created when transcripts succeed to load
                    assert_eq!(change_set.len(), 3);
                } else {
                    // No new shares should be created with NiDKG, as they were already created above
                    assert!(change_set.is_empty());
                }
            })
        })
    }

    // Tests that complaints are generated and added to the pool if loading transcript
    // results in complaints.
    #[test]
    fn test_send_signature_shares_with_complaints_all_idkg_algorithms() {
        // Only test IDKG algorithms, as there are no complaints for NiDKG
        for key_id in fake_master_public_key_ids_for_all_idkg_algorithms() {
            println!("Running test for key ID {key_id}");
            test_send_signature_shares_with_complaints(key_id);
        }
    }

    fn test_send_signature_shares_with_complaints(key_id: IDkgMasterPublicKeyId) {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let mut generator = IDkgUIDGenerator::new(subnet_test_id(1), Height::new(0));
                let height = Height::from(100);
                let ids: Vec<_> = (0..3).map(|i| request_id(i, height)).collect();
                let pids: Vec<_> = (0..3).map(|_| generator.next_pre_signature_id()).collect();

                // Set up the signature requests
                let block_reader = TestIDkgBlockReader::for_signer_test(
                    height,
                    vec![
                        (pids[0], create_sig_inputs(0, &key_id)),
                        (pids[1], create_sig_inputs(1, &key_id)),
                        (pids[2], create_sig_inputs(2, &key_id)),
                    ],
                );
                let state = fake_state_with_signature_requests(
                    height,
                    (0..3).map(|i| {
                        fake_signature_request_context_from_id(
                            key_id.clone().into(),
                            pids[i],
                            ids[i],
                        )
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
                let requested_signatures_count = ids.len();
                let expected_complaints_count = match key_id.inner() {
                    MasterPublicKeyId::Ecdsa(_) => requested_signatures_count * 5,
                    MasterPublicKeyId::Schnorr(_) => requested_signatures_count * 2,
                    MasterPublicKeyId::VetKd(_) => panic!("not applicable to vetKD"),
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
        })
    }

    #[test]
    fn test_crypto_verify_sig_share_all_idkg_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_idkg_algorithms() {
            println!("Running test for key ID {key_id}");
            test_crypto_verify_idkg_sig_share(key_id);
        }
    }

    fn test_crypto_verify_idkg_sig_share(key_id: IDkgMasterPublicKeyId) {
        let mut rng = reproducible_rng();
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
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
                let (receivers, inputs) = match key_id.inner() {
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
                            None,
                            &derivation_path,
                            algorithm_for_key_id(&key_id),
                            &mut rng,
                        );
                        (
                            inputs.receivers().clone(),
                            ThresholdSigInputs::Schnorr(inputs),
                        )
                    }
                    MasterPublicKeyId::VetKd(_) => panic!("not applicable to vetKD"),
                };
                let crypto = env
                    .nodes
                    .filter_by_receivers(&receivers)
                    .next()
                    .unwrap()
                    .crypto();
                let (_, signer) =
                    create_signer_dependencies_with_crypto(pool_config, logger, Some(crypto));
                let id = request_id(1, Height::from(5));
                let message = create_signature_share(&key_id, NODE_2, id);
                let share = match message {
                    IDkgMessage::EcdsaSigShare(share) => SigShare::Ecdsa(share),
                    IDkgMessage::SchnorrSigShare(share) => SigShare::Schnorr(share),
                    _ => panic!("Unexpected message type"),
                };
                let result = signer.crypto_verify_sig_share(&inputs, share, &(IDkgStatsNoOp {}));
                // assert that the mock signature share does not pass real crypto check
                assert!(result.is_err());
            })
        })
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
        let mut generator = IDkgUIDGenerator::new(subnet_test_id(1), Height::new(0));
        let height = Height::from(100);
        let (id_1, id_2, id_3, id_4) = (
            request_id(1, Height::from(200)),
            request_id(2, height),
            request_id(3, Height::from(10)),
            request_id(4, Height::from(5)),
        );
        let (pid_2, pid_3) = (
            generator.next_pre_signature_id(),
            generator.next_pre_signature_id(),
        );

        // Set up the transcript creation request
        // The block requests transcripts 2, 3
        let block_reader = TestIDkgBlockReader::for_signer_test(
            height,
            vec![
                (pid_2, create_sig_inputs(2, &key_id)),
                (pid_3, create_sig_inputs(3, &key_id)),
            ],
        );
        let state = fake_state_with_signature_requests(
            height,
            vec![
                fake_signature_request_context_from_id(key_id.clone(), pid_2, id_2),
                fake_signature_request_context_from_id(key_id.clone(), pid_3, id_3),
            ],
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

        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
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
        });

        // Simulate failure when resolving IDKG transcripts
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, signer) = create_signer_dependencies(pool_config, logger);
                artifacts.iter().for_each(|a| idkg_pool.insert(a.clone()));

                let block_reader = block_reader.clone().with_fail_to_resolve();

                let change_set =
                    signer.validate_signature_shares(&idkg_pool, &block_reader, &state);
                assert_eq!(change_set.len(), 3);
                if key_id.is_idkg_key() {
                    // There are no IDKG transcripts in the block reader, shares created for IDKG transcripts
                    // that cannot be resolved should be handled invalid.
                    assert!(is_handle_invalid(&change_set, &msg_id_2));
                    assert!(is_handle_invalid(&change_set, &msg_id_3));
                } else {
                    // IDKG transcripts should not affect NiDKG key share validation
                    assert!(is_moved_to_validated(&change_set, &msg_id_2));
                    assert!(is_moved_to_validated(&change_set, &msg_id_3));
                }
                assert!(is_removed_from_unvalidated(&change_set, &msg_id_4));
            })
        });
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
        let mut generator = IDkgUIDGenerator::new(subnet_test_id(1), Height::new(0));
        let height = Height::from(100);
        let (id_1, id_2) = (request_id(1, height), request_id(2, height));
        let (pid_1, pid_2) = (
            generator.next_pre_signature_id(),
            generator.next_pre_signature_id(),
        );

        // Set up the signature requests
        // The block contains pre-signatures for requests 1, 2
        let block_reader = TestIDkgBlockReader::for_signer_test(
            height,
            vec![
                (pid_1, create_sig_inputs(1, &key_id)),
                (pid_2, create_sig_inputs(2, &key_id)),
            ],
        );
        let state = fake_state_with_signature_requests(
            height,
            [
                fake_signature_request_context_from_id(key_id.clone(), pid_1, id_1),
                fake_signature_request_context_from_id(key_id.clone(), pid_2, id_2),
            ],
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
                fake_schnorr_idkg_master_public_key_id(SchnorrAlgorithm::Ed25519).into()
            }
            MasterPublicKeyId::Schnorr(_) => fake_vetkd_master_public_key_id(),
            MasterPublicKeyId::VetKd(_) => fake_ecdsa_idkg_master_public_key_id().into(),
        };
        let message = create_signature_share(&key_id_wrong_scheme, NODE_2, id_2);
        let msg_id_2 = message.message_id();
        artifacts.push(UnvalidatedArtifact {
            message,
            peer_id: NODE_2,
            timestamp: UNIX_EPOCH,
        });

        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, signer) = create_signer_dependencies(pool_config, logger);
                artifacts.iter().for_each(|a| idkg_pool.insert(a.clone()));

                let change_set =
                    signer.validate_signature_shares(&idkg_pool, &block_reader, &state);
                assert_eq!(change_set.len(), 2);
                assert!(is_moved_to_validated(&change_set, &msg_id_1));
                assert!(is_handle_invalid(&change_set, &msg_id_2));
            })
        });
    }

    // Tests that signature shares for incomplete contexts are not validated
    #[test]
    fn test_validate_signature_shares_incomplete_contexts_all_algorithms() {
        // Only test IDKG algorithms, as VetKD contexts don't require pre-signatures
        // and therefore cannot be "incomplete".
        for key_id in fake_master_public_key_ids_for_all_idkg_algorithms() {
            println!("Running test for key ID {key_id}");
            test_validate_signature_shares_incomplete_contexts(key_id);
        }
    }

    fn test_validate_signature_shares_incomplete_contexts(key_id: IDkgMasterPublicKeyId) {
        let mut generator = IDkgUIDGenerator::new(subnet_test_id(1), Height::new(0));
        let height = Height::from(100);
        let ids: Vec<_> = (0..3).map(|i| request_id(i, height)).collect();
        let pids: Vec<_> = (0..3).map(|_| generator.next_pre_signature_id()).collect();

        // Set up the signature requests
        // The block contains pre-signatures for requests 0, 1, 2
        let block_reader = TestIDkgBlockReader::for_signer_test(
            height,
            vec![
                (pids[0], create_sig_inputs(0, &key_id)),
                (pids[1], create_sig_inputs(1, &key_id)),
                (pids[2], create_sig_inputs(2, &key_id)),
            ],
        );
        let state = fake_state_with_signature_requests(
            height,
            [
                // One context without matched pre-signature
                fake_signature_request_context_with_pre_sig(ids[0], key_id.clone(), None),
                // One context without nonce
                fake_signature_request_context_with_pre_sig(ids[1], key_id.clone(), Some(pids[1])),
                // One completed context
                fake_signature_request_context_from_id(key_id.clone().into(), pids[2], ids[2]),
            ],
        );

        // Set up the IDKG pool
        let mut artifacts = Vec::new();
        // A share for the first incomplete context (deferred)
        let message = create_signature_share(&key_id, NODE_2, ids[0]);
        artifacts.push(UnvalidatedArtifact {
            message,
            peer_id: NODE_2,
            timestamp: UNIX_EPOCH,
        });

        // A share for the second incomplete context (deferred)
        let message = create_signature_share(&key_id, NODE_2, ids[1]);
        artifacts.push(UnvalidatedArtifact {
            message,
            peer_id: NODE_2,
            timestamp: UNIX_EPOCH,
        });

        // A share for a the completed context (accepted)
        let message = create_signature_share(&key_id, NODE_2, ids[2]);
        let msg_id_3 = message.message_id();
        artifacts.push(UnvalidatedArtifact {
            message,
            peer_id: NODE_2,
            timestamp: UNIX_EPOCH,
        });

        // A share for a the completed context, but specifying wrong pre-signature height (dropped)
        let mut wrong_id_3 = ids[2];
        wrong_id_3.height = ids[2].height.decrement();
        let message = create_signature_share(&key_id, NODE_2, wrong_id_3);
        let msg_id_4 = message.message_id();
        artifacts.push(UnvalidatedArtifact {
            message,
            peer_id: NODE_2,
            timestamp: UNIX_EPOCH,
        });

        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, signer) = create_signer_dependencies(pool_config, logger);
                artifacts.iter().for_each(|a| idkg_pool.insert(a.clone()));

                let change_set =
                    signer.validate_signature_shares(&idkg_pool, &block_reader, &state);
                assert_eq!(change_set.len(), 2);
                assert!(is_moved_to_validated(&change_set, &msg_id_3));
                assert!(is_removed_from_unvalidated(&change_set, &msg_id_4));
            })
        });
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
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let height = Height::from(100);
                let mut generator = IDkgUIDGenerator::new(subnet_test_id(1), Height::new(0));
                let id_2 = request_id(2, Height::from(100));
                let pid_2 = generator.next_pre_signature_id();

                let block_reader = TestIDkgBlockReader::for_signer_test(
                    height,
                    vec![(pid_2, create_sig_inputs(2, &key_id))],
                );
                let state = fake_state_with_signature_requests(
                    height,
                    [fake_signature_request_context_from_id(
                        key_id.clone(),
                        pid_2,
                        id_2,
                    )],
                );

                let (mut idkg_pool, signer) = create_signer_dependencies(pool_config, logger);

                // Set up the IDKG pool
                // Validated pool has: {signature share 2, signer = NODE_2}
                let share = create_signature_share(&key_id, NODE_2, id_2);
                let change_set = vec![IDkgChangeAction::AddToValidated(share)];
                idkg_pool.apply(change_set);

                // Unvalidated pool has: {signature share 2, signer = NODE_2, height = 100}
                let message = create_signature_share(&key_id, NODE_2, id_2);
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
        })
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
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let height = Height::from(100);
                let mut generator = IDkgUIDGenerator::new(subnet_test_id(1), Height::new(0));
                let id_1 = request_id(1, Height::from(100));
                let pid_1 = generator.next_pre_signature_id();

                let block_reader = TestIDkgBlockReader::for_signer_test(
                    height,
                    vec![(pid_1, create_sig_inputs(2, &key_id))],
                );
                let state = fake_state_with_signature_requests(
                    height,
                    [fake_signature_request_context_from_id(
                        key_id.clone(),
                        pid_1,
                        id_1,
                    )],
                );

                let (mut idkg_pool, signer) = create_signer_dependencies(pool_config, logger);

                // Unvalidated pool has: {signature share 1, signer = NODE_2}
                let message = create_signature_share_with_nonce(&key_id, NODE_2, id_1, 0);
                let msg_id_1 = message.message_id();
                idkg_pool.insert(UnvalidatedArtifact {
                    message,
                    peer_id: NODE_2,
                    timestamp: UNIX_EPOCH,
                });

                // Unvalidated pool has: {signature share 2, signer = NODE_2}
                let message = create_signature_share_with_nonce(&key_id, NODE_2, id_1, 1);
                let msg_id_2 = message.message_id();
                idkg_pool.insert(UnvalidatedArtifact {
                    message,
                    peer_id: NODE_2,
                    timestamp: UNIX_EPOCH,
                });

                // Unvalidated pool has: {signature share 2, signer = NODE_3}
                let message = create_signature_share_with_nonce(&key_id, NODE_3, id_1, 2);
                let msg_id_3 = message.message_id();
                idkg_pool.insert(UnvalidatedArtifact {
                    message,
                    peer_id: NODE_3,
                    timestamp: UNIX_EPOCH,
                });

                let change_set =
                    signer.validate_signature_shares(&idkg_pool, &block_reader, &state);
                assert_eq!(change_set.len(), 3);
                let msg_1_valid = is_moved_to_validated(&change_set, &msg_id_1)
                    && is_handle_invalid(&change_set, &msg_id_2);
                let msg_2_valid = is_moved_to_validated(&change_set, &msg_id_2)
                    && is_handle_invalid(&change_set, &msg_id_1);

                // One is considered duplicate
                assert!(msg_1_valid || msg_2_valid);
                assert!(is_moved_to_validated(&change_set, &msg_id_3));
            })
        })
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
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let height = Height::from(100);
                let mut generator = IDkgUIDGenerator::new(subnet_test_id(1), Height::new(0));
                let (id_1, id_2, id_3) = (
                    request_id(1, Height::from(10)),
                    request_id(2, Height::from(20)),
                    request_id(3, Height::from(200)),
                );
                let (pid_1, pid_3) = (
                    generator.next_pre_signature_id(),
                    generator.next_pre_signature_id(),
                );

                // Set up the transcript creation request
                let state = fake_state_with_signature_requests(
                    height,
                    [
                        fake_signature_request_context_from_id(key_id.clone(), pid_1, id_1),
                        fake_signature_request_context_from_id(key_id.clone(), pid_3, id_3),
                    ],
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
        })
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
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let height = Height::from(100);
                let mut generator = IDkgUIDGenerator::new(subnet_test_id(1), Height::new(0));
                let (id_1, id_2, id_3) = (
                    request_id(1, Height::from(10)),
                    request_id(2, Height::from(20)),
                    request_id(3, Height::from(200)),
                );
                let (pid_1, pid_3) = (
                    generator.next_pre_signature_id(),
                    generator.next_pre_signature_id(),
                );

                // Set up the transcript creation request
                let state = fake_state_with_signature_requests(
                    height,
                    [
                        fake_signature_request_context_from_id(key_id.clone(), pid_1, id_1),
                        fake_signature_request_context_from_id(key_id.clone(), pid_3, id_3),
                    ],
                );

                let (mut idkg_pool, signer) = create_signer_dependencies(pool_config, logger);

                // Share 1: height <= current_height, in_progress (not purged)
                let share = create_signature_share(&key_id, NODE_2, id_1);
                let change_set = vec![IDkgChangeAction::AddToValidated(share)];
                idkg_pool.apply(change_set);

                // Share 2: height <= current_height, !in_progress (purged)
                let share = create_signature_share(&key_id, NODE_2, id_2);
                let msg_id_2 = share.message_id();
                let change_set = vec![IDkgChangeAction::AddToValidated(share)];
                idkg_pool.apply(change_set);

                // Share 3: height > current_height (not purged)
                let share = create_signature_share(&key_id, NODE_2, id_3);
                let change_set = vec![IDkgChangeAction::AddToValidated(share)];
                idkg_pool.apply(change_set);

                let change_set = signer.purge_artifacts(&idkg_pool, &state);
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_validated(&change_set, &msg_id_2));
            })
        })
    }

    // Tests aggregating ecdsa signature shares into a complete signature
    #[test]
    fn test_ecdsa_get_completed_signature() {
        let mut rng = reproducible_rng();
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, _) = create_signer_dependencies(pool_config, logger.clone());
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
                let req_id = request_id(1, Height::from(10));
                let pre_sig_id = PreSigId(1);
                let message_hash = [0; 32];
                let callback_id = CallbackId::from(1);
                let context = SignWithThresholdContext {
                    request: RequestBuilder::new().sender(canister_test_id(1)).build(),
                    args: ThresholdArguments::Ecdsa(EcdsaArguments {
                        key_id: fake_ecdsa_key_id(),
                        message_hash,
                    }),
                    pseudo_random_id: [1; 32],
                    derivation_path: Arc::new(vec![]),
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
                    vec![(pre_sig_id, (&sig_inputs).into())],
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
                    let result = sig_builder.get_completed_signature(callback_id, &context);
                    assert_matches!(result, None);
                }

                // Generate signature shares and add to validated
                let change_set = env
                    .nodes
                    .filter_by_receivers(&sig_inputs)
                    .map(|receiver| {
                        receiver.load_tecdsa_sig_transcripts(&sig_inputs);
                        let share = ThresholdEcdsaSigner::create_sig_share(receiver, &sig_inputs)
                            .expect("failed to create sig share");
                        EcdsaSigShare {
                            signer_id: receiver.id(),
                            request_id: req_id,
                            share,
                        }
                    })
                    .map(|share| {
                        IDkgChangeAction::AddToValidated(IDkgMessage::EcdsaSigShare(share))
                    })
                    .collect::<Vec<_>>();
                idkg_pool.apply(change_set);

                let sig_builder = ThresholdSignatureBuilderImpl::new(
                    &block_reader,
                    crypto.deref(),
                    &idkg_pool,
                    &metrics,
                    logger.clone(),
                );

                // Signature completion should succeed now.
                let r1 = sig_builder.get_completed_signature(callback_id, &context);
                // Compare to combined signature returned by crypto environment
                let r2 = CombinedSignature::Ecdsa(run_tecdsa_protocol(&env, &sig_inputs, &mut rng));
                assert_matches!(r1, Some(ref s) if s == &r2);

                // If the context's nonce hasn't been set yet, no signature should be completed
                let mut context_without_nonce = context.clone();
                context_without_nonce.nonce = None;
                let res = sig_builder.get_completed_signature(callback_id, &context_without_nonce);
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

                let result = sig_builder.get_completed_signature(callback_id, &context);
                assert_matches!(result, None);
            });
        })
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
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, _) = create_signer_dependencies(pool_config, logger.clone());
                let req_id = request_id(1, Height::from(10));
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
                let pre_sig_id = PreSigId(1);
                let message = vec![0; 32];
                let callback_id = CallbackId::from(1);
                let context = SignWithThresholdContext {
                    request: RequestBuilder::new().sender(canister_test_id(1)).build(),
                    args: ThresholdArguments::Schnorr(SchnorrArguments {
                        key_id: fake_schnorr_key_id(schnorr_algorithm(algorithm)),
                        message: Arc::new(message.clone()),
                        taproot_tree_root: None,
                    }),
                    pseudo_random_id: [1; 32],
                    derivation_path: Arc::new(vec![]),
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
                    None,
                    &derivation_path,
                    algorithm,
                    &mut rng,
                );

                // Set up the transcript creation request
                let block_reader = TestIDkgBlockReader::for_signer_test(
                    Height::from(100),
                    vec![(pre_sig_id, (&sig_inputs).into())],
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
                    let result = sig_builder.get_completed_signature(callback_id, &context);
                    assert_matches!(result, None);
                }

                // Generate signature shares and add to validated
                let change_set = env
                    .nodes
                    .filter_by_receivers(&sig_inputs)
                    .map(|receiver| {
                        receiver.load_tschnorr_sig_transcripts(&sig_inputs);
                        let share = ThresholdSchnorrSigner::create_sig_share(receiver, &sig_inputs)
                            .expect("failed to create sig share");
                        SchnorrSigShare {
                            signer_id: receiver.id(),
                            request_id: req_id,
                            share,
                        }
                    })
                    .map(|share| {
                        IDkgChangeAction::AddToValidated(IDkgMessage::SchnorrSigShare(share))
                    })
                    .collect::<Vec<_>>();
                idkg_pool.apply(change_set);

                let sig_builder = ThresholdSignatureBuilderImpl::new(
                    &block_reader,
                    crypto.deref(),
                    &idkg_pool,
                    &metrics,
                    logger.clone(),
                );

                // Signature completion should succeed now.
                let r1 = sig_builder.get_completed_signature(callback_id, &context);
                // Compare to combined signature returned by crypto environment
                let r2 =
                    CombinedSignature::Schnorr(run_tschnorr_protocol(&env, &sig_inputs, &mut rng));
                assert_matches!(r1, Some(ref s) if s == &r2);

                // If the context's nonce hasn't been set yet, no signature should be completed
                let mut context_without_nonce = context.clone();
                context_without_nonce.nonce = None;
                let res = sig_builder.get_completed_signature(callback_id, &context_without_nonce);
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

                let result = sig_builder.get_completed_signature(callback_id, &context);
                assert_matches!(result, None);
            });
        })
    }

    #[test]
    fn test_vetkd_get_completed_signature_unexpected() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (idkg_pool, _) = create_signer_dependencies(pool_config, logger.clone());

                let callback_id = CallbackId::from(1);
                let key_id = fake_vetkd_key_id();
                let height = Height::from(100);
                let context = SignWithThresholdContext {
                    request: RequestBuilder::new().sender(canister_test_id(1)).build(),
                    args: ThresholdArguments::VetKd(VetKdArguments {
                        key_id: key_id.clone(),
                        input: Arc::new(vec![]),
                        transport_public_key: vec![],
                        ni_dkg_id: fake_dkg_id(key_id),
                        height,
                    }),
                    pseudo_random_id: [1; 32],
                    derivation_path: Arc::new(vec![]),
                    batch_time: UNIX_EPOCH,
                    matched_pre_signature: None,
                    nonce: None,
                };

                // Set up the block reader
                let block_reader = TestIDkgBlockReader::for_signer_test(height, vec![]);

                let metrics = IDkgPayloadMetrics::new(MetricsRegistry::new());
                let crypto: Arc<dyn ConsensusCrypto> = Arc::new(CryptoReturningOk::default());

                let sig_builder = ThresholdSignatureBuilderImpl::new(
                    &block_reader,
                    crypto.deref(),
                    &idkg_pool,
                    &metrics,
                    logger,
                );

                // We don't expect to combine VetKD shares using the ThresholdSignatureBuilder
                // (they are instead created by the VetKD payload builder).
                let (request_id, sig_inputs_ref) =
                    build_signature_inputs(callback_id, &context, &block_reader).unwrap();
                let sig_inputs = sig_inputs_ref.translate(&block_reader).unwrap();

                let result = sig_builder.crypto_combine_sig_shares(
                    &request_id,
                    &sig_inputs,
                    idkg_pool.stats(),
                );
                assert_matches!(result, Err(CombineSigSharesError::VetKdUnexpected));

                let result = sig_builder.get_completed_signature(callback_id, &context);
                assert_matches!(result, None);
            });
        })
    }
}
