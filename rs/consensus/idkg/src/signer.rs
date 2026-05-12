//! The signature process manager

use crate::{
    complaints::IDkgTranscriptLoader,
    metrics::{ThresholdSignerMetrics, timed_call},
    utils::{IDkgSchedule, load_transcripts},
};
use ic_consensus_utils::{chain_key::build_signature_inputs, crypto::ConsensusCrypto};
use ic_interfaces::{
    crypto::{
        ErrorReproducibility, ThresholdEcdsaSigVerifier, ThresholdEcdsaSigner,
        ThresholdSchnorrSigVerifier, ThresholdSchnorrSigner, VetKdProtocol,
    },
    idkg::{IDkgChangeAction, IDkgChangeSet, IDkgPool},
};
use ic_interfaces_state_manager::{CertifiedStateSnapshot, StateReader};
use ic_logger::{ReplicaLogger, warn};
use ic_metrics::MetricsRegistry;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    Height, NodeId,
    artifact::IDkgMessageId,
    consensus::idkg::{
        EcdsaSigShare, IDkgMessage, IDkgStats, RequestId, SchnorrSigShare, SigShare, VetKdKeyShare,
        common::{SignatureScheme, ThresholdSigInputs},
        ecdsa_sig_share_prefix, schnorr_sig_share_prefix, vetkd_key_share_prefix,
    },
    crypto::{
        canister_threshold_sig::error::{
            ThresholdEcdsaCreateSigShareError, ThresholdEcdsaVerifySigShareError,
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
    sync::{Arc, RwLock},
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
    validated_sig_share_signers: RwLock<BTreeMap<RequestId, BTreeSet<NodeId>>>,
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
            validated_sig_share_signers: RwLock::new(BTreeMap::new()),
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
        let ret = self.thread_pool.install(|| {
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
                    !Self::signer_has_issued_share(
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
        });

        let mut valid_sig_share_signers = self.validated_sig_share_signers.write().unwrap();
        for action in &ret {
            #[allow(clippy::needless_borrowed_reference)] // This borrowed reference *is* needed
            if let &IDkgChangeAction::AddToValidated(ref share) = action
                && let Some((request_id, signer)) = share.sig_share_request_id_and_signer()
            {
                // Record our share in the map of validated signature share signers
                valid_sig_share_signers
                    .entry(request_id)
                    .or_default()
                    .insert(signer);
            }
        }

        ret
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

        self.thread_pool.install(|| {
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
        })
    }

    fn validate_signature_share(
        &self,
        idkg_pool: &dyn IDkgPool,
        id: IDkgMessageId,
        share: SigShare,
        inputs: &ThresholdSigInputs,
    ) -> Option<IDkgChangeAction> {
        {
            let valid_sig_share_signers = self.validated_sig_share_signers.read().unwrap();
            let maybe_signers = valid_sig_share_signers.get(&share.request_id());
            if maybe_signers.is_some_and(|signers| signers.contains(&share.signer())) {
                self.metrics
                    .sign_errors_inc("duplicate_sig_share_cache_hit");
                return Some(IDkgChangeAction::RemoveUnvalidated(id));
            }

            if Self::inputs_already_have_enough_shares(inputs, maybe_signers) {
                // We already have enough valid shares for this request
                return Some(IDkgChangeAction::RemoveUnvalidated(id));
            }
        }

        let signer = share.signer();
        let request_id = share.request_id();
        let scheme = share.scheme();
        if Self::signer_has_issued_share(idkg_pool, &signer, &request_id, scheme) {
            // The node already sent a valid share for this request
            self.metrics.sign_errors_inc("duplicate_sig_share");
            return Some(IDkgChangeAction::RemoveUnvalidated(id));
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
                warn!(
                    every_n_seconds => 10,
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

                // Although we already checked the cache for duplicate shares above, it could happen that a
                // different thread validated a share for the same request_id in the meantime, after we
                // released the read lock. Therefore, we acquire the write lock here to check again with
                // exclusive access.
                let mut valid_sig_share_signers = self.validated_sig_share_signers.write().unwrap();
                let signers = valid_sig_share_signers.entry(request_id).or_default();
                if !signers.insert(signer) {
                    self.metrics
                        .sign_errors_inc("duplicate_sig_share_cache_miss");
                    Some(IDkgChangeAction::RemoveUnvalidated(id))
                } else {
                    Some(IDkgChangeAction::MoveToValidated(share))
                }
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

        let current_height = state_snapshot.get_height();

        // Unvalidated signature shares.
        let ret = idkg_pool
            .unvalidated()
            .signature_shares()
            .filter(|(_, share)| {
                Self::should_purge(share.request_id(), current_height, &in_progress)
            })
            .map(|(id, _)| IDkgChangeAction::RemoveUnvalidated(id));

        // Validated signature shares.
        let mut valid_sig_share_signers = self.validated_sig_share_signers.write().unwrap();
        let action = idkg_pool
            .validated()
            .signature_shares()
            .filter(|(_, share)| {
                Self::should_purge(share.request_id(), current_height, &in_progress)
            })
            // Side-effect: remove from the validated_sig_share_signers map
            .map(|(id, share)| {
                valid_sig_share_signers.remove(&share.request_id());
                IDkgChangeAction::RemoveValidated(id)
            });
        let ret = ret.chain(action);

        ret.collect()
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

    fn inputs_already_have_enough_shares(
        inputs: &ThresholdSigInputs,
        maybe_signers: Option<&BTreeSet<NodeId>>,
    ) -> bool {
        let reconstruction_threshold = match inputs {
            ThresholdSigInputs::Ecdsa(inputs) => inputs.reconstruction_threshold().get() as usize,
            ThresholdSigInputs::Schnorr(inputs) => inputs.reconstruction_threshold().get() as usize,
            // VetKd's API does not expose the number of shares needed for reconstruction directly.
            // As this code path is an optimization, we conservatively assume that we do not have
            // enough shares if the inputs are for VetKd.
            // The worst thing that can happen is to validate a few extra shares.
            ThresholdSigInputs::VetKd(_inputs) => return false,
        };

        maybe_signers.as_ref().map_or(0, |signers| signers.len()) >= reconstruction_threshold
    }

    /// Checks if the signature share should be purged
    fn should_purge(
        request_id: RequestId,
        current_height: Height,
        in_progress: &BTreeSet<CallbackId>,
    ) -> bool {
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
            .flat_map(|(callback_id, context)| {
                context.height().map(|height| RequestId {
                    callback_id: *callback_id,
                    height,
                })
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
        generate_tecdsa_protocol_inputs, generate_tschnorr_protocol_inputs,
    };
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_interfaces::p2p::consensus::{MutablePool, UnvalidatedArtifact};
    use ic_management_canister_types_private::{MasterPublicKeyId, SchnorrAlgorithm};
    use ic_test_utilities_consensus::{IDkgStatsNoOp, idkg::*};
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_types::ids::{NODE_1, NODE_2, NODE_3, subnet_test_id, user_test_id};
    use ic_types::{
        Height, Randomness,
        consensus::{get_faults_tolerated, idkg::*},
        crypto::{
            AlgorithmId, ExtendedDerivationPath, canister_threshold_sig::idkg::IDkgReceivers,
        },
        time::UNIX_EPOCH,
    };
    use ic_types_test_utils::ids::node_test_id;
    use std::sync::RwLock;

    impl ThresholdSignerImpl {
        fn validated_sig_share_signers(&self) -> BTreeMap<RequestId, BTreeSet<NodeId>> {
            self.validated_sig_share_signers
                .read()
                .expect("ThresholdSignerImpl::validated_sig_share_signers(): RwLock poisoned")
                .clone()
        }
    }

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
                {
                    let mut valid_sig_share_signers =
                        signer.validated_sig_share_signers.write().unwrap();
                    valid_sig_share_signers.insert(id_1, BTreeSet::from([NODE_1]));
                    valid_sig_share_signers.insert(id_2, BTreeSet::from([NODE_2]));
                }

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
                assert_eq!(
                    signer.validated_sig_share_signers(),
                    BTreeMap::from([(id_2, BTreeSet::from([NODE_2]))])
                );
                idkg_pool.apply(change_set);

                // Certified height increases above share2, so it is purged
                let new_height = expected_state_snapshot.write().unwrap().inc_height_by(1);
                let change_set = signer.on_state_change(&idkg_pool, &transcript_loader, &schedule);
                assert_eq!(*schedule.last_purge.borrow(), new_height);
                assert_eq!(height_30, new_height);
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_validated(&change_set, &msg_id2));
                assert_eq!(signer.validated_sig_share_signers(), BTreeMap::new());
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
                assert_eq!(
                    signer.validated_sig_share_signers(),
                    BTreeMap::from([
                        (ids[3], BTreeSet::from([NODE_1])),
                        (ids[4], BTreeSet::from([NODE_1])),
                    ])
                );
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
                assert_eq!(signer.validated_sig_share_signers(), BTreeMap::new());
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
                assert_eq!(
                    signer.validated_sig_share_signers(),
                    BTreeMap::from([(ids[2], BTreeSet::from([NODE_1]))])
                );
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
                    assert_eq!(signer.validated_sig_share_signers(), BTreeMap::new());
                } else {
                    // NiDKG transcripts are loaded ahead of time, so creation should succeed, even if
                    // IDKG transcripts fail to load.
                    assert_eq!(change_set.len(), 3);
                    assert_eq!(
                        signer.validated_sig_share_signers(),
                        BTreeMap::from([
                            (ids[0], BTreeSet::from([NODE_1])),
                            (ids[1], BTreeSet::from([NODE_1])),
                            (ids[2], BTreeSet::from([NODE_1])),
                        ])
                    );
                }
                idkg_pool.apply(change_set);

                let transcript_loader =
                    TestIDkgTranscriptLoader::new(TestTranscriptLoadStatus::Success);
                let change_set =
                    signer.send_signature_shares(&idkg_pool, &transcript_loader, &state);

                if key_id.is_idkg_key() {
                    // IDKG key signature shares should be created when transcripts succeed to load
                    assert_eq!(change_set.len(), 3);
                } else {
                    // No new shares should be created with NiDKG, as they were already created above
                    assert!(change_set.is_empty());
                }
                assert_eq!(
                    signer.validated_sig_share_signers(),
                    BTreeMap::from([
                        (ids[0], BTreeSet::from([NODE_1])),
                        (ids[1], BTreeSet::from([NODE_1])),
                        (ids[2], BTreeSet::from([NODE_1])),
                    ])
                );
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
                assert_eq!(signer.validated_sig_share_signers(), BTreeMap::new());
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
                assert_eq!(
                    signer.validated_sig_share_signers(),
                    BTreeMap::from([
                        (id_2, BTreeSet::from([NODE_2])),
                        (id_3, BTreeSet::from([NODE_2])),
                    ])
                );
            })
        });
    }

    // Tests that signature shares are validated only until the reconstruction threshold is
    // reached, and shares received after that are not validated.
    #[test]
    fn test_validate_signature_shares_validates_only_necessary_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_validate_signature_shares_until_reconstruction_threshold(key_id);
        }
    }

    fn test_validate_signature_shares_until_reconstruction_threshold(key_id: MasterPublicKeyId) {
        let height = Height::from(100);
        let mut generator = IDkgUIDGenerator::new(subnet_test_id(1), Height::new(0));
        let id = request_id(1, height);
        let pid = generator.next_pre_signature_id();

        let state = fake_state_with_signature_requests(
            height,
            [fake_signature_request_context_from_id(
                key_id.clone(),
                pid,
                id,
            )],
        );

        let n = 4;
        let node_ids = (0..n)
            .map(|i| node_test_id(i.try_into().unwrap()))
            .collect::<Vec<_>>();
        let expected_nb_sig_shares = match key_id {
            MasterPublicKeyId::Ecdsa(_) => get_faults_tolerated(n) + 1,
            MasterPublicKeyId::Schnorr(_) => get_faults_tolerated(n) + 1,
            MasterPublicKeyId::VetKd(_) => n, // The optimization is disabled for VetKD for now
        };

        // Add unvalidated shares for all nodes
        let mut msg_ids = vec![];
        let mut artifacts = vec![];
        for node_id in &node_ids {
            let message = create_signature_share(&key_id, *node_id, id);
            msg_ids.push(message.message_id());
            artifacts.push(UnvalidatedArtifact {
                message,
                peer_id: *node_id,
                timestamp: UNIX_EPOCH,
            });
        }

        // In the single threaded case only f + 1 shares should be accepted, the rest dropped
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, signer) =
                    create_signer_dependencies_with_threads(pool_config, logger, 1);
                artifacts.iter().for_each(|a| idkg_pool.insert(a.clone()));

                let change_set = signer.validate_signature_shares(&idkg_pool, &state);
                assert_eq!(change_set.len(), n);
                let (accepted, dropped): (Vec<_>, Vec<_>) = msg_ids
                    .clone()
                    .into_iter()
                    .partition(|msg_id| is_moved_to_validated(&change_set, msg_id));
                assert!(
                    dropped
                        .iter()
                        .all(|msg_id| is_removed_from_unvalidated(&change_set, msg_id))
                );
                assert_eq!(accepted.len(), expected_nb_sig_shares);
                assert_eq!(dropped.len(), n - expected_nb_sig_shares);

                assert_eq!(signer.validated_sig_share_signers().len(), 1);
                assert!(
                    signer
                        .validated_sig_share_signers()
                        .get(&id)
                        .is_some_and(|signers| {
                            signers.len() == expected_nb_sig_shares
                                && signers.is_subset(&node_ids.iter().cloned().collect())
                        })
                );
            })
        });

        // In the multi threaded case at least f + 1 shares should be accepted, the rest dropped
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, signer) = create_signer_dependencies(pool_config, logger);
                artifacts.iter().for_each(|a| idkg_pool.insert(a.clone()));

                let change_set = signer.validate_signature_shares(&idkg_pool, &state);
                assert_eq!(change_set.len(), n);
                let (accepted, dropped): (Vec<_>, Vec<_>) = msg_ids
                    .clone()
                    .into_iter()
                    .partition(|msg_id| is_moved_to_validated(&change_set, msg_id));
                assert!(
                    dropped
                        .iter()
                        .all(|msg_id| is_removed_from_unvalidated(&change_set, msg_id))
                );
                assert!(accepted.len() >= expected_nb_sig_shares);
                assert_eq!(dropped.len(), n - accepted.len());

                assert_eq!(signer.validated_sig_share_signers().len(), 1);
                assert!(
                    signer
                        .validated_sig_share_signers()
                        .get(&id)
                        .is_some_and(|signers| {
                            signers.len() == accepted.len()
                                && signers.is_subset(&node_ids.iter().cloned().collect())
                        })
                );
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
                assert!(is_handle_invalid(
                    &change_set,
                    &msg_id_2,
                    "Signature share validation(permanent error)"
                ));
                assert_eq!(
                    signer.validated_sig_share_signers(),
                    BTreeMap::from([(id_1, BTreeSet::from([NODE_2]))])
                );
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
                assert_eq!(
                    signer.validated_sig_share_signers(),
                    BTreeMap::from([(ids[2], BTreeSet::from([NODE_2]))])
                );
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
                {
                    let mut valid_sig_share_signers =
                        signer.validated_sig_share_signers.write().unwrap();
                    valid_sig_share_signers.insert(id_2, BTreeSet::from([NODE_2]));
                }

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
                assert!(is_removed_from_unvalidated(&change_set, &msg_id_2));
                assert_eq!(
                    signer.validated_sig_share_signers(),
                    BTreeMap::from([(id_2, BTreeSet::from([NODE_2]))])
                );
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
                    && is_removed_from_unvalidated(&change_set, &msg_id_2);
                let msg_2_valid = is_moved_to_validated(&change_set, &msg_id_2)
                    && is_removed_from_unvalidated(&change_set, &msg_id_1);

                // One is considered duplicate
                assert!(msg_1_valid || msg_2_valid);
                assert!(is_moved_to_validated(&change_set, &msg_id_3));
                assert_eq!(
                    signer.validated_sig_share_signers(),
                    BTreeMap::from([(id_1, BTreeSet::from([NODE_2, NODE_3]))])
                );
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

                {
                    let mut valid_sig_share_signers =
                        signer.validated_sig_share_signers.write().unwrap();
                    valid_sig_share_signers.insert(id_1, BTreeSet::from([NODE_2]));
                    valid_sig_share_signers.insert(id_2, BTreeSet::from([NODE_2]));
                    valid_sig_share_signers.insert(id_3, BTreeSet::from([NODE_2]));
                }

                let change_set = signer.purge_artifacts(&idkg_pool, &state);
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_validated(&change_set, &msg_id_2));
                assert_eq!(
                    signer.validated_sig_share_signers(),
                    BTreeMap::from([
                        (id_1, BTreeSet::from([NODE_2])),
                        (id_3, BTreeSet::from([NODE_2])),
                    ])
                );
            })
        })
    }
}
