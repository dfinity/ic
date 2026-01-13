//! The signature process manager

use crate::{
    complaints::IDkgTranscriptLoader,
    metrics::{IDkgPayloadMetrics, ThresholdSignerMetrics, timed_call},
    utils::{IDkgSchedule, build_signature_inputs, load_transcripts},
};
use ic_consensus_utils::crypto::ConsensusCrypto;
use ic_interfaces::{
    crypto::{
        ErrorReproducibility, ThresholdEcdsaSigVerifier, ThresholdEcdsaSigner,
        ThresholdSchnorrSigVerifier, ThresholdSchnorrSigner, VetKdProtocol,
    },
    idkg::{IDkgChangeAction, IDkgChangeSet, IDkgPool},
};
use ic_interfaces_state_manager::{CertifiedStateSnapshot, StateReader};
use ic_logger::{ReplicaLogger, debug, warn};
use ic_metrics::MetricsRegistry;
use ic_replicated_state::{
    ReplicatedState,
    metadata_state::subnet_call_context_manager::{SignWithThresholdContext, ThresholdArguments},
};
use ic_types::{
    Height, NodeId,
    artifact::IDkgMessageId,
    consensus::idkg::{
        EcdsaSigShare, IDkgMessage, IDkgStats, RequestId, SchnorrSigShare, SigShare, VetKdKeyShare,
        common::{CombinedSignature, SignatureScheme, ThresholdSigInputs},
        ecdsa_sig_share_prefix, schnorr_sig_share_prefix, vetkd_key_share_prefix,
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
};
use rayon::{
    ThreadPool,
    iter::{IntoParallelIterator, ParallelIterator},
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
    crypto: Arc<dyn ConsensusCrypto>,
    thread_pool: Arc<ThreadPool>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    metrics: ThresholdSignerMetrics,
    log: ReplicaLogger,
}

impl ThresholdSignerImpl {
    pub(crate) fn new(
        node_id: NodeId,
        crypto: Arc<dyn ConsensusCrypto>,
        thread_pool: Arc<ThreadPool>,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        metrics_registry: MetricsRegistry,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            node_id,
            crypto,
            thread_pool,
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
        state_snapshot: &dyn CertifiedStateSnapshot<State = ReplicatedState>,
    ) -> IDkgChangeSet {
        self.thread_pool.install(|| {
            state_snapshot
                .get_state()
                .signature_request_contexts()
                .into_par_iter()
                .filter_map(|(id, context)| {
                    build_signature_inputs(*id, context).inspect_err(|err| {
                        if err.is_fatal() {
                            warn!(every_n_seconds => 15, self.log,
                                "send_signature_shares(): failed to build signature inputs: {:?}",
                                err
                            );
                            self.metrics.sign_errors_inc("signature_inputs_malformed");
                        }
                    })
                    .ok()
                })
                .filter(|(request_id, inputs)| {
                    !self.signer_has_issued_share(
                        idkg_pool,
                        &self.node_id,
                        request_id,
                        inputs.scheme(),
                    )
                })
                .flat_map(|(request_id, sig_inputs)| {
                    self.create_signature_share(
                        idkg_pool,
                        transcript_loader,
                        request_id,
                        sig_inputs,
                    )
                })
                .collect()
        })
    }

    /// Processes the received signature shares
    fn validate_signature_shares(
        &self,
        idkg_pool: &dyn IDkgPool,
        state_snapshot: &dyn CertifiedStateSnapshot<State = ReplicatedState>,
    ) -> IDkgChangeSet {
        let sig_inputs_map = state_snapshot
            .get_state()
            .signature_request_contexts()
            .iter()
            .map(|(id, c)| {
                let inputs = build_signature_inputs(*id, c).map_err(|err| if err.is_fatal() {
                    warn!(every_n_seconds => 15, self.log,
                        "validate_signature_shares(): failed to build signatures inputs: {:?}",
                        err
                    );
                    self.metrics.sign_errors_inc("signature_inputs_malformed");
                }).ok();
                (*id, inputs)
            })
            .collect::<BTreeMap<_, _>>();

        let shares: Vec<_> = idkg_pool.unvalidated().signature_shares().collect();

        let results: Vec<_> = self.thread_pool.install(|| {
            // Iterate over all signature shares of all schemes
            shares
                .into_par_iter()
                .filter_map(|(id, share)| {
                    match Action::new(
                        &sig_inputs_map,
                        &share.request_id(),
                        state_snapshot.get_height(),
                    ) {
                        Action::Process(sig_inputs) => {
                            self.validate_signature_share(idkg_pool, id.clone(), share, sig_inputs)
                        }
                        Action::Drop => Some(IDkgChangeAction::RemoveUnvalidated(id)),
                        Action::Defer => None,
                    }
                })
                .collect()
        });

        let mut ret = Vec::new();
        // Collection of validated shares
        let mut validated_sig_shares = BTreeSet::new();
        for action in results {
            if let IDkgChangeAction::MoveToValidated(msg) = &action
                && let Some(key) = msg.sig_share_dedup_key()
                && !validated_sig_shares.insert(key)
            {
                self.metrics
                    .sign_errors_inc("duplicate_sig_shares_in_batch");
                ret.push(IDkgChangeAction::HandleInvalid(
                    msg.message_id(),
                    format!("Duplicate share in unvalidated batch: {msg:?}"),
                ));
                continue;
            }
            ret.push(action);
        }

        ret
    }

    fn validate_signature_share(
        &self,
        idkg_pool: &dyn IDkgPool,
        id: IDkgMessageId,
        share: SigShare,
        inputs: &ThresholdSigInputs,
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
                format!("Duplicate signature share: {share}"),
            ));
        }

        let share_string = share.to_string();
        match self.crypto_verify_sig_share(inputs, share, idkg_pool.stats()) {
            Err(error) if error.is_reproducible() => {
                self.metrics.sign_errors_inc("verify_sig_share_permanent");
                Some(IDkgChangeAction::HandleInvalid(
                    id,
                    format!(
                        "Signature share validation(permanent error): {share_string}, error = {error:?}"
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

        let metrics = self.metrics.clone();

        let active_requests = snapshot
            .get_state()
            .signature_request_contexts()
            .iter()
            .flat_map(|(callback_id, context)| match &context.args {
                ThresholdArguments::Ecdsa(args) => {
                    let matched_id = context.matched_pre_signature.map(|(id, _)| id);
                    let matched_full = args.pre_signature.as_ref().map(|pre_sig| pre_sig.id);
                    if matched_id != matched_full {
                        warn!(
                            every_n_seconds => 15,
                            self.log,
                            "ECDSA context {:?}, with different ID {:?} and full pre-sig {:?}",
                            callback_id,
                            matched_id,
                            matched_full
                        );
                    }
                    context.matched_pre_signature.map(|(_, height)| RequestId {
                        callback_id: *callback_id,
                        height,
                    })
                }
                ThresholdArguments::Schnorr(args) => {
                    let matched_id = context.matched_pre_signature.map(|(id, _)| id);
                    let matched_full = args.pre_signature.as_ref().map(|pre_sig| pre_sig.id);
                    if matched_id != matched_full {
                        warn!(
                            every_n_seconds => 15,
                            self.log,
                            "Schnorr context {:?}, with different ID {:?} and full pre-sig {:?}",
                            callback_id,
                            matched_id,
                            matched_full
                        );
                    }
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

        let mut changes = if schedule.update_last_purge(snapshot.get_height()) {
            timed_call(
                "purge_artifacts",
                || self.purge_artifacts(idkg_pool, snapshot.as_ref()),
                &metrics.on_state_change_duration,
            )
        } else {
            IDkgChangeSet::default()
        };

        let send_signature_shares = || {
            timed_call(
                "send_signature_shares",
                || self.send_signature_shares(idkg_pool, transcript_loader, snapshot.as_ref()),
                &metrics.on_state_change_duration,
            )
        };
        let validate_signature_shares = || {
            timed_call(
                "validate_signature_shares",
                || self.validate_signature_shares(idkg_pool, snapshot.as_ref()),
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
    crypto: &'a dyn ConsensusCrypto,
    idkg_pool: &'a dyn IDkgPool,
    metrics: &'a IDkgPayloadMetrics,
    log: ReplicaLogger,
}

impl<'a> ThresholdSignatureBuilderImpl<'a> {
    pub(crate) fn new(
        crypto: &'a dyn ConsensusCrypto,
        idkg_pool: &'a dyn IDkgPool,
        metrics: &'a IDkgPayloadMetrics,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            crypto,
            idkg_pool,
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
        let (request_id, sig_inputs) = build_signature_inputs(callback_id, context)
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
enum Action<'a> {
    /// The message is relevant to our current state, process it
    /// immediately. The transcript params for this transcript
    /// (as specified by the finalized block) is the argument
    Process(&'a ThresholdSigInputs<'a>),

    /// Keep it to be processed later (e.g) this is from a node
    /// ahead of us
    Defer,

    /// Don't need it
    Drop,
}

impl<'a> Action<'a> {
    /// Decides the action to take on a received message with the given height/RequestId
    fn new(
        requested_signatures: &'a BTreeMap<CallbackId, Option<(RequestId, ThresholdSigInputs)>>,
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
    use crate::test_utils::*;
    use assert_matches::assert_matches;
    use ic_config::artifact_pool::ArtifactPoolConfig;
    use ic_crypto_test_utils_canister_threshold_sigs::{
        CanisterThresholdSigTestEnvironment, IDkgParticipants, generate_key_transcript,
        generate_tecdsa_protocol_inputs, generate_tschnorr_protocol_inputs, run_tecdsa_protocol,
        run_tschnorr_protocol,
    };
    use ic_crypto_test_utils_crypto_returning_ok::CryptoReturningOk;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_interfaces::p2p::consensus::{MutablePool, UnvalidatedArtifact};
    use ic_management_canister_types_private::{MasterPublicKeyId, SchnorrAlgorithm};
    use ic_replicated_state::metadata_state::subnet_call_context_manager::{
        EcdsaArguments, EcdsaMatchedPreSignature, SchnorrArguments, SchnorrMatchedPreSignature,
        ThresholdArguments, VetKdArguments,
    };
    use ic_test_utilities_consensus::{IDkgStatsNoOp, idkg::*};
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_types::{
        ids::{NODE_1, NODE_2, NODE_3, canister_test_id, subnet_test_id, user_test_id},
        messages::RequestBuilder,
    };
    use ic_types::{
        Height, Randomness,
        consensus::idkg::*,
        crypto::{
            AlgorithmId, ExtendedDerivationPath, canister_threshold_sig::idkg::IDkgReceivers,
        },
        time::UNIX_EPOCH,
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

        let sig_inputs_1 = create_threshold_sig_inputs(1, &key_id);
        let sig_inputs_2 = create_threshold_sig_inputs(2, &key_id);
        let sig_inputs_3 = create_threshold_sig_inputs(3, &key_id);

        let requested = BTreeMap::from([
            (id_1.callback_id, Some((id_1, sig_inputs_1.as_ref()))),
            (id_2.callback_id, Some((id_2, sig_inputs_2.as_ref()))),
            (id_3.callback_id, Some((id_3, sig_inputs_3.as_ref()))),
            (id_4.callback_id, None),
        ]);

        // Message from a node ahead of us
        assert_matches!(Action::new(&requested, &id_5, height), Action::Defer);

        // Messages for transcripts not being currently requested
        assert_matches!(
            Action::new(&requested, &request_id(6, Height::from(100)), height),
            Action::Drop
        );
        assert_matches!(
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
        assert_matches!(action, Action::Drop);

        // Message for a signature that is requested, but its context isn't complete yet
        let action = Action::new(&requested, &id_4, height);
        assert_matches!(action, Action::Defer);
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
        let shares = [
            create_signature_share(&key_id, NODE_1, ids[0]),
            create_signature_share(&key_id, NODE_2, ids[1]),
            create_signature_share(&key_id, NODE_3, ids[2]),
        ];

        // The state has requests 0, 3, 4, each paired with a pre-signature ID.
        let requests: Vec<_> = [0, 3, 4]
            .into_iter()
            .map(|i: usize| (ids[i], generator.next_pre_signature_id()))
            .collect();

        let transcript_loader: TestIDkgTranscriptLoader = Default::default();

        let state = fake_state_with_signature_requests(
            height,
            requests.into_iter().map(|(request_id, pre_sig_id)| {
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
                let change_set =
                    signer.send_signature_shares(&idkg_pool, &transcript_loader, &state);
                assert_eq!(change_set.len(), 2);
                assert!(is_signature_share_added_to_validated(
                    &change_set,
                    &ids[3],
                    height,
                ));
                assert!(is_signature_share_added_to_validated(
                    &change_set,
                    &ids[4],
                    height,
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
                let change_set =
                    signer.send_signature_shares(&idkg_pool, &transcript_loader, &state);
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
        let ids: Vec<_> = (0..4).map(|i| request_id(i, height)).collect();
        let pids: Vec<_> = (0..4).map(|_| generator.next_pre_signature_id()).collect();

        // Set up the signature requests
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
                // One malformed context
                fake_malformed_signature_request_context_from_id(
                    key_id.clone().into(),
                    pids[3],
                    ids[3],
                ),
            ],
        );

        // Test using CryptoReturningOK
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (idkg_pool, signer) = create_signer_dependencies(pool_config, logger);

                // We should issue shares only for completed request 2
                let change_set =
                    signer.send_signature_shares(&idkg_pool, &transcript_loader, &state);

                assert_eq!(change_set.len(), 1);
                assert!(is_signature_share_added_to_validated(
                    &change_set,
                    &ids[2],
                    height,
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
                let state = fake_state_with_signature_requests(
                    height,
                    (0..3).map(|i| {
                        fake_signature_request_context_from_id(key_id.clone(), pids[i], ids[i])
                    }),
                );

                let (mut idkg_pool, signer) = create_signer_dependencies(pool_config, logger);

                let transcript_loader =
                    TestIDkgTranscriptLoader::new(TestTranscriptLoadStatus::Failure);
                let change_set =
                    signer.send_signature_shares(&idkg_pool, &transcript_loader, &state);

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
                let change_set =
                    signer.send_signature_shares(&idkg_pool, &transcript_loader, &state);

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

                let change_set =
                    signer.send_signature_shares(&idkg_pool, &transcript_loader, &state);
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
        fn create_sig_share_and_assert_that_verification_fails(
            key_id: &IDkgMasterPublicKeyId,
            pool_config: ArtifactPoolConfig,
            logger: ReplicaLogger,
            env: &CanisterThresholdSigTestEnvironment,
            receivers: &IDkgReceivers,
            inputs: &ThresholdSigInputs,
        ) {
            let crypto = env
                .nodes
                .filter_by_receivers(receivers)
                .next()
                .unwrap()
                .crypto();
            let (_, signer) =
                create_signer_dependencies_with_crypto(pool_config, logger, Some(crypto));
            let id = request_id(1, Height::from(5));
            let message = create_signature_share(key_id, NODE_2, id);
            let share = match message {
                IDkgMessage::EcdsaSigShare(share) => SigShare::Ecdsa(share),
                IDkgMessage::SchnorrSigShare(share) => SigShare::Schnorr(share),
                _ => panic!("Unexpected message type"),
            };
            let result = signer.crypto_verify_sig_share(inputs, share, &(IDkgStatsNoOp {}));
            // assert that the mock signature share does not pass real crypto check
            assert!(result.is_err());
        }

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
                    AlgorithmId::from(key_id.inner()),
                    &mut rng,
                );
                let derivation_path = ExtendedDerivationPath {
                    caller: user_test_id(1).get(),
                    derivation_path: vec![],
                };
                match key_id.inner() {
                    MasterPublicKeyId::Ecdsa(_) => {
                        let inputs = generate_tecdsa_protocol_inputs(
                            &env,
                            &dealers,
                            &receivers,
                            &key_transcript,
                            &[0; 32],
                            Randomness::from([0; 32]),
                            &derivation_path,
                            AlgorithmId::from(key_id.inner()),
                            &mut rng,
                        );
                        create_sig_share_and_assert_that_verification_fails(
                            &key_id,
                            pool_config,
                            logger,
                            &env,
                            inputs.as_ref().receivers(),
                            &ThresholdSigInputs::Ecdsa(inputs.as_ref()),
                        );
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
                            AlgorithmId::from(key_id.inner()),
                            &mut rng,
                        );
                        create_sig_share_and_assert_that_verification_fails(
                            &key_id,
                            pool_config,
                            logger,
                            &env,
                            &inputs.receivers().clone(),
                            &ThresholdSigInputs::Schnorr(inputs.as_ref()),
                        );
                    }
                    MasterPublicKeyId::VetKd(_) => panic!("not applicable to vetKD"),
                }
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

                let change_set = signer.validate_signature_shares(&idkg_pool, &state);
                assert_eq!(change_set.len(), 3);
                assert!(is_moved_to_validated(&change_set, &msg_id_2));
                assert!(is_moved_to_validated(&change_set, &msg_id_3));
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

                let change_set = signer.validate_signature_shares(&idkg_pool, &state);
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
        let ids: Vec<_> = (0..4).map(|i| request_id(i, height)).collect();
        let pids: Vec<_> = (0..4).map(|_| generator.next_pre_signature_id()).collect();

        // Set up the signature requests
        let state = fake_state_with_signature_requests(
            height,
            [
                // One context without matched pre-signature
                fake_signature_request_context_with_pre_sig(ids[0], key_id.clone(), None),
                // One context without nonce
                fake_signature_request_context_with_pre_sig(ids[1], key_id.clone(), Some(pids[1])),
                // One completed context
                fake_signature_request_context_from_id(key_id.clone().into(), pids[2], ids[2]),
                // One malformed context
                fake_malformed_signature_request_context_from_id(
                    key_id.clone().into(),
                    pids[3],
                    ids[3],
                ),
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

        // A share for a the malformed context (deferred)
        let message = create_signature_share(&key_id, NODE_2, ids[3]);
        artifacts.push(UnvalidatedArtifact {
            message,
            peer_id: NODE_2,
            timestamp: UNIX_EPOCH,
        });

        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, signer) = create_signer_dependencies(pool_config, logger);
                artifacts.iter().for_each(|a| idkg_pool.insert(a.clone()));

                let change_set = signer.validate_signature_shares(&idkg_pool, &state);
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

                let change_set = signer.validate_signature_shares(&idkg_pool, &state);
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

                let change_set = signer.validate_signature_shares(&idkg_pool, &state);
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
                let nonce = [2; 32];
                let sig_inputs = generate_tecdsa_protocol_inputs(
                    &env,
                    &dealers,
                    &receivers,
                    &key_transcript,
                    &message_hash,
                    Randomness::from(nonce),
                    &derivation_path,
                    AlgorithmId::ThresholdEcdsaSecp256k1,
                    &mut rng,
                );
                let context = SignWithThresholdContext {
                    request: RequestBuilder::new().sender(canister_test_id(1)).build(),
                    args: ThresholdArguments::Ecdsa(EcdsaArguments {
                        key_id: fake_ecdsa_key_id(),
                        message_hash,
                        pre_signature: Some(EcdsaMatchedPreSignature {
                            id: pre_sig_id,
                            height: req_id.height,
                            pre_signature: Arc::new(sig_inputs.presig_quadruple().clone()),
                            key_transcript: Arc::new(key_transcript.clone()),
                        }),
                    }),
                    pseudo_random_id: [1; 32],
                    derivation_path: Arc::new(vec![]),
                    batch_time: UNIX_EPOCH,
                    matched_pre_signature: Some((pre_sig_id, req_id.height)),
                    nonce: Some(nonce),
                };

                let metrics = IDkgPayloadMetrics::new(MetricsRegistry::new());
                let crypto: Arc<dyn ConsensusCrypto> = env
                    .nodes
                    .filter_by_receivers(&sig_inputs)
                    .next()
                    .unwrap()
                    .crypto();

                {
                    let sig_builder = ThresholdSignatureBuilderImpl::new(
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
                        receiver.load_tecdsa_sig_transcripts(&sig_inputs.as_ref());
                        let share =
                            ThresholdEcdsaSigner::create_sig_share(receiver, &sig_inputs.as_ref())
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
                    crypto.deref(),
                    &idkg_pool,
                    &metrics,
                    logger.clone(),
                );

                // Signature completion should succeed now.
                let r1 = sig_builder.get_completed_signature(callback_id, &context);
                // Compare to combined signature returned by crypto environment
                let r2 = CombinedSignature::Ecdsa(run_tecdsa_protocol(
                    &env,
                    &sig_inputs.as_ref(),
                    &mut rng,
                ));
                assert_matches!(r1, Some(ref s) if s == &r2);

                // If the context's nonce hasn't been set yet, no signature should be completed
                let mut context_without_nonce = context.clone();
                context_without_nonce.nonce = None;
                let res = sig_builder.get_completed_signature(callback_id, &context_without_nonce);
                assert_eq!(None, res);
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
                let nonce = [2; 32];
                let callback_id = CallbackId::from(1);
                let sig_inputs = generate_tschnorr_protocol_inputs(
                    &env,
                    &dealers,
                    &receivers,
                    &key_transcript,
                    &message,
                    Randomness::from(nonce),
                    None,
                    &derivation_path,
                    algorithm,
                    &mut rng,
                );
                let context = SignWithThresholdContext {
                    request: RequestBuilder::new().sender(canister_test_id(1)).build(),
                    args: ThresholdArguments::Schnorr(SchnorrArguments {
                        key_id: fake_schnorr_key_id(schnorr_algorithm(algorithm)),
                        message: Arc::new(message.clone()),
                        taproot_tree_root: None,
                        pre_signature: Some(SchnorrMatchedPreSignature {
                            id: pre_sig_id,
                            height: req_id.height,
                            pre_signature: Arc::new(sig_inputs.presig_transcript().clone()),
                            key_transcript: Arc::new(key_transcript.clone()),
                        }),
                    }),
                    pseudo_random_id: [1; 32],
                    derivation_path: Arc::new(vec![]),
                    batch_time: UNIX_EPOCH,
                    matched_pre_signature: Some((pre_sig_id, req_id.height)),
                    nonce: Some(nonce),
                };

                let metrics = IDkgPayloadMetrics::new(MetricsRegistry::new());
                let crypto: Arc<dyn ConsensusCrypto> = env
                    .nodes
                    .filter_by_receivers(&sig_inputs)
                    .next()
                    .unwrap()
                    .crypto();

                {
                    let sig_builder = ThresholdSignatureBuilderImpl::new(
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
                        receiver.load_tschnorr_sig_transcripts(&sig_inputs.as_ref());
                        let share = ThresholdSchnorrSigner::create_sig_share(
                            receiver,
                            &sig_inputs.as_ref(),
                        )
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
                    crypto.deref(),
                    &idkg_pool,
                    &metrics,
                    logger.clone(),
                );

                // Signature completion should succeed now.
                let r1 = sig_builder.get_completed_signature(callback_id, &context);
                // Compare to combined signature returned by crypto environment
                let r2 = CombinedSignature::Schnorr(run_tschnorr_protocol(
                    &env,
                    &sig_inputs.as_ref(),
                    &mut rng,
                ));
                assert_matches!(r1, Some(ref s) if s == &r2);

                // If the context's nonce hasn't been set yet, no signature should be completed
                let mut context_without_nonce = context.clone();
                context_without_nonce.nonce = None;
                let res = sig_builder.get_completed_signature(callback_id, &context_without_nonce);
                assert_eq!(None, res);
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
                    derivation_path: Arc::new(vec![vec![]]),
                    batch_time: UNIX_EPOCH,
                    matched_pre_signature: None,
                    nonce: None,
                };

                let metrics = IDkgPayloadMetrics::new(MetricsRegistry::new());
                let crypto: Arc<dyn ConsensusCrypto> = Arc::new(CryptoReturningOk::default());

                let sig_builder = ThresholdSignatureBuilderImpl::new(
                    crypto.deref(),
                    &idkg_pool,
                    &metrics,
                    logger,
                );

                // We don't expect to combine VetKD shares using the ThresholdSignatureBuilder
                // (they are instead created by the VetKD payload builder).
                let (request_id, sig_inputs) =
                    build_signature_inputs(callback_id, &context).unwrap();

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
