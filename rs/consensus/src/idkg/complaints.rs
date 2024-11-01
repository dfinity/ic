//! The complaint handling

use crate::idkg::metrics::{timed_call, IDkgComplaintMetrics};
use crate::idkg::utils::IDkgBlockReaderImpl;

use ic_consensus_utils::crypto::ConsensusCrypto;
use ic_consensus_utils::RoundRobin;
use ic_interfaces::consensus_pool::ConsensusBlockCache;
use ic_interfaces::crypto::{ErrorReproducibility, IDkgProtocol};
use ic_interfaces::idkg::{IDkgChangeAction, IDkgChangeSet, IDkgPool};
use ic_logger::{debug, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_types::artifact::IDkgMessageId;
use ic_types::consensus::idkg::{
    complaint_prefix, opening_prefix, IDkgBlockReader, IDkgComplaintContent, IDkgMessage,
    IDkgOpeningContent, SignedIDkgComplaint, SignedIDkgOpening, TranscriptRef,
};
use ic_types::crypto::canister_threshold_sig::error::IDkgLoadTranscriptError;
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgComplaint, IDkgOpening, IDkgTranscript, IDkgTranscriptId,
};
use ic_types::{Height, NodeId, RegistryVersion};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::utils::update_purge_height;

pub(crate) trait IDkgComplaintHandler: Send {
    /// The on_state_change() called from the main IDKG path.
    fn on_state_change(&self, idkg_pool: &dyn IDkgPool) -> IDkgChangeSet;

    /// Get a reference to the transcript loader.
    fn as_transcript_loader(&self) -> &dyn IDkgTranscriptLoader;
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
struct ComplaintKey {
    transcript_id: IDkgTranscriptId,
    dealer_id: NodeId,
    complainer_id: NodeId,
}

impl From<&SignedIDkgComplaint> for ComplaintKey {
    fn from(complaint: &SignedIDkgComplaint) -> Self {
        Self {
            transcript_id: complaint.content.idkg_complaint.transcript_id,
            dealer_id: complaint.content.idkg_complaint.dealer_id,
            complainer_id: complaint.signature.signer,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
struct OpeningKey {
    transcript_id: IDkgTranscriptId,
    dealer_id: NodeId,
    opener_id: NodeId,
}

impl From<&SignedIDkgOpening> for OpeningKey {
    fn from(opening: &SignedIDkgOpening) -> Self {
        Self {
            transcript_id: opening.content.idkg_opening.transcript_id,
            dealer_id: opening.content.idkg_opening.dealer_id,
            opener_id: opening.signature.signer,
        }
    }
}

pub(crate) struct IDkgComplaintHandlerImpl {
    node_id: NodeId,
    consensus_block_cache: Arc<dyn ConsensusBlockCache>,
    crypto: Arc<dyn ConsensusCrypto>,
    schedule: RoundRobin,
    metrics: IDkgComplaintMetrics,
    log: ReplicaLogger,
    prev_finalized_height: RefCell<Height>,
}

impl IDkgComplaintHandlerImpl {
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
            metrics: IDkgComplaintMetrics::new(metrics_registry),
            log,
            prev_finalized_height: RefCell::new(Height::from(0)),
        }
    }

    /// Processes the received complaints
    fn validate_complaints(
        &self,
        idkg_pool: &dyn IDkgPool,
        block_reader: &dyn IDkgBlockReader,
    ) -> IDkgChangeSet {
        let active_transcripts = self.active_transcripts(block_reader);
        let requested_transcripts = self.requested_transcripts(block_reader);

        // Collection of validated complaints <complainer Id, transcript Id, dealer Id>
        let mut validated_complaints = BTreeSet::new();

        let mut ret = Vec::new();
        for (id, signed_complaint) in idkg_pool.unvalidated().complaints() {
            let complaint = signed_complaint.get();
            // Remove the duplicate entries
            let key = ComplaintKey::from(&signed_complaint);
            if validated_complaints.contains(&key) {
                self.metrics
                    .complaint_errors_inc("duplicate_complaints_in_batch");
                ret.push(IDkgChangeAction::HandleInvalid(
                    id,
                    format!(
                        "Duplicate complaint in unvalidated batch: {}",
                        signed_complaint
                    ),
                ));
                continue;
            }

            match Action::action(
                block_reader,
                &active_transcripts,
                &requested_transcripts,
                complaint.idkg_complaint.transcript_id.source_height(),
                &complaint.idkg_complaint.transcript_id,
            ) {
                Action::Process(transcript_ref) => {
                    if self.has_complainer_issued_complaint(
                        idkg_pool,
                        &complaint.idkg_complaint,
                        &signed_complaint.signature.signer,
                    ) {
                        self.metrics.complaint_errors_inc("duplicate_complaint");
                        ret.push(IDkgChangeAction::HandleInvalid(
                            id,
                            format!("Duplicate complaint: {}", signed_complaint),
                        ));
                    } else {
                        match self.resolve_ref(transcript_ref, block_reader, "validate_complaints")
                        {
                            Some(transcript) => {
                                let action =
                                    self.crypto_verify_complaint(id, &transcript, signed_complaint);
                                if let Some(IDkgChangeAction::MoveToValidated(_)) = action {
                                    validated_complaints.insert(key);
                                }
                                ret.append(&mut action.into_iter().collect());
                            }
                            None => {
                                ret.push(IDkgChangeAction::HandleInvalid(
                                    id,
                                    format!(
                                        "validate_complaints(): failed to resolve: {}",
                                        signed_complaint
                                    ),
                                ));
                            }
                        }
                    }
                }
                Action::Drop => ret.push(IDkgChangeAction::RemoveUnvalidated(id)),
                Action::Defer => {}
            }
        }

        ret
    }

    /// Sends openings for complaints from peers
    fn send_openings(
        &self,
        idkg_pool: &dyn IDkgPool,
        block_reader: &dyn IDkgBlockReader,
    ) -> IDkgChangeSet {
        let active_transcripts = self.active_transcripts(block_reader);

        idkg_pool
            .validated()
            .complaints()
            .filter(|(_, signed_complaint)| {
                // Do not try to create openings for own complaints.
                if signed_complaint.signature.signer == self.node_id {
                    return false;
                }
                let complaint = signed_complaint.get();
                !self.has_node_issued_opening(
                    idkg_pool,
                    &complaint.idkg_complaint.transcript_id,
                    &complaint.idkg_complaint.dealer_id,
                    &self.node_id,
                )
            })
            .filter_map(|(_, signed_complaint)| {
                // Look up the transcript for the complained transcript Id.
                let complaint = signed_complaint.get();
                match active_transcripts.get(&complaint.idkg_complaint.transcript_id) {
                    Some(transcript_ref) => self
                        .resolve_ref(transcript_ref, block_reader, "send_openings")
                        .map(|transcript| (signed_complaint, transcript)),
                    None => {
                        self.metrics
                            .complaint_errors_inc("complaint_inactive_transcript");
                        None
                    }
                }
            })
            .flat_map(|(signed_complaint, transcript)| {
                self.crypto_create_opening(&signed_complaint, &transcript)
            })
            .collect()
    }

    /// Processes the received openings
    fn validate_openings(
        &self,
        idkg_pool: &dyn IDkgPool,
        block_reader: &dyn IDkgBlockReader,
    ) -> IDkgChangeSet {
        let active_transcripts = self.active_transcripts(block_reader);
        let requested_transcripts = self.requested_transcripts(block_reader);

        // Collection of validated openings <opener Id, transcript Id, dealer Id>
        let mut validated_openings = BTreeSet::new();

        let mut ret = Vec::new();
        for (id, signed_opening) in idkg_pool.unvalidated().openings() {
            let opening = signed_opening.get();

            // Remove duplicate entries
            let key = OpeningKey::from(&signed_opening);
            if validated_openings.contains(&key) {
                self.metrics
                    .complaint_errors_inc("duplicate_openings_in_batch");
                ret.push(IDkgChangeAction::HandleInvalid(
                    id,
                    format!("Duplicate opening in unvalidated batch: {}", signed_opening),
                ));
                continue;
            }

            match Action::action(
                block_reader,
                &active_transcripts,
                &requested_transcripts,
                opening.idkg_opening.transcript_id.source_height(),
                &opening.idkg_opening.transcript_id,
            ) {
                Action::Process(transcript_ref) => {
                    if self.has_node_issued_opening(
                        idkg_pool,
                        &opening.idkg_opening.transcript_id,
                        &opening.idkg_opening.dealer_id,
                        &signed_opening.signature.signer,
                    ) {
                        self.metrics.complaint_errors_inc("duplicate_opening");
                        ret.push(IDkgChangeAction::HandleInvalid(
                            id,
                            format!("Duplicate opening: {}", signed_opening),
                        ));
                    } else if let Some(signed_complaint) =
                        self.get_complaint_for_opening(idkg_pool, &signed_opening)
                    {
                        match self.resolve_ref(transcript_ref, block_reader, "validate_openings") {
                            Some(transcript) => {
                                let action = self.crypto_verify_opening(
                                    id,
                                    &transcript,
                                    signed_opening,
                                    &signed_complaint,
                                );
                                if let Some(IDkgChangeAction::MoveToValidated(_)) = action {
                                    validated_openings.insert(key);
                                }
                                ret.append(&mut action.into_iter().collect());
                            }
                            None => {
                                ret.push(IDkgChangeAction::HandleInvalid(
                                    id,
                                    format!(
                                        "validate_openings(): failed to resolve: {}",
                                        signed_opening
                                    ),
                                ));
                            }
                        }
                    } else {
                        // Defer handling the opening in case it was received
                        // before the complaint.
                        self.metrics
                            .complaint_errors_inc("opening_missing_complaint");
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
        let active_transcripts = block_reader
            .active_transcripts()
            .iter()
            .map(|transcript_ref| transcript_ref.transcript_id)
            .collect::<BTreeSet<_>>();

        let mut ret = Vec::new();
        let current_height = block_reader.tip_height();

        // Unvalidated complaints
        let mut action = idkg_pool
            .unvalidated()
            .complaints()
            .filter(|(_, signed_complaint)| {
                let complaint = signed_complaint.get();
                self.should_purge(
                    &complaint.idkg_complaint.transcript_id,
                    complaint.idkg_complaint.transcript_id.source_height(),
                    current_height,
                    &active_transcripts,
                )
            })
            .map(|(id, _)| IDkgChangeAction::RemoveUnvalidated(id))
            .collect();
        ret.append(&mut action);

        // Validated complaints
        let mut action = idkg_pool
            .validated()
            .complaints()
            .filter(|(_, signed_complaint)| {
                let complaint = signed_complaint.get();
                self.should_purge(
                    &complaint.idkg_complaint.transcript_id,
                    complaint.idkg_complaint.transcript_id.source_height(),
                    current_height,
                    &active_transcripts,
                )
            })
            .map(|(id, _)| IDkgChangeAction::RemoveValidated(id))
            .collect();
        ret.append(&mut action);

        // Unvalidated openings
        let mut action = idkg_pool
            .unvalidated()
            .openings()
            .filter(|(_, signed_opening)| {
                let opening = signed_opening.get();
                self.should_purge(
                    &opening.idkg_opening.transcript_id,
                    opening.idkg_opening.transcript_id.source_height(),
                    current_height,
                    &active_transcripts,
                )
            })
            .map(|(id, _)| IDkgChangeAction::RemoveUnvalidated(id))
            .collect();
        ret.append(&mut action);

        // Validated openings
        let mut action = idkg_pool
            .validated()
            .openings()
            .filter(|(_, signed_opening)| {
                let opening = signed_opening.get();
                self.should_purge(
                    &opening.idkg_opening.transcript_id,
                    opening.idkg_opening.transcript_id.source_height(),
                    current_height,
                    &active_transcripts,
                )
            })
            .map(|(id, _)| IDkgChangeAction::RemoveValidated(id))
            .collect();
        ret.append(&mut action);

        ret
    }

    /// Helper to create a signed complaint
    fn crypto_create_complaint(
        &self,
        idkg_complaint: IDkgComplaint,
        registry_version: RegistryVersion,
    ) -> Option<SignedIDkgComplaint> {
        let content = IDkgComplaintContent { idkg_complaint };
        match self.crypto.sign(&content, self.node_id, registry_version) {
            Ok(signature) => {
                let signed_complaint = SignedIDkgComplaint { content, signature };
                self.metrics.complaint_metrics_inc("complaints_sent");
                Some(signed_complaint)
            }
            Err(err) => {
                warn!(
                    self.log,
                    "Failed to sign complaint: transcript_id: {:?}, dealer_id: {:?}, error = {:?}",
                    content.idkg_complaint.transcript_id,
                    content.idkg_complaint.dealer_id,
                    err
                );
                self.metrics.complaint_errors_inc("sign_complaint");
                None
            }
        }
    }

    /// Helper to verify the complaint
    fn crypto_verify_complaint(
        &self,
        id: IDkgMessageId,
        transcript: &IDkgTranscript,
        signed_complaint: SignedIDkgComplaint,
    ) -> Option<IDkgChangeAction> {
        let complaint = signed_complaint.get();

        // Verify the signature
        if let Err(error) = self
            .crypto
            .verify(&signed_complaint, transcript.registry_version)
        {
            if error.is_reproducible() {
                self.metrics
                    .complaint_errors_inc("verify_complaint_signature_permanent");
                return Some(IDkgChangeAction::HandleInvalid(
                    id,
                    format!(
                        "Complaint signature validation(permanent error): {}, error = {:?}",
                        signed_complaint, error
                    ),
                ));
            } else {
                // Defer in case of transient errors
                debug!(
                    self.log,
                    "Complaint signature validation(transient error): {}, error = {:?}",
                    signed_complaint,
                    error
                );
                self.metrics
                    .complaint_errors_inc("verify_complaint_signature_transient");
                return None;
            }
        }

        match self.crypto.verify_complaint(
            transcript,
            signed_complaint.signature.signer,
            &complaint.idkg_complaint,
        ) {
            Err(error) if error.is_reproducible() => {
                self.metrics
                    .complaint_errors_inc("verify_complaint_permanent");
                Some(IDkgChangeAction::HandleInvalid(
                    id,
                    format!(
                        "Complaint validation(permanent error): {}, error = {:?}",
                        signed_complaint, error
                    ),
                ))
            }
            Err(error) => {
                debug!(
                    self.log,
                    "Complaint validation(transient error): {}, error = {:?}",
                    signed_complaint,
                    error
                );
                self.metrics
                    .complaint_errors_inc("verify_complaint_transient");
                None
            }
            Ok(()) => {
                self.metrics.complaint_metrics_inc("complaint_received");
                Some(IDkgChangeAction::MoveToValidated(IDkgMessage::Complaint(
                    signed_complaint,
                )))
            }
        }
    }

    /// Helper to create a signed opening
    fn crypto_create_opening(
        &self,
        signed_complaint: &SignedIDkgComplaint,
        transcript: &IDkgTranscript,
    ) -> IDkgChangeSet {
        let complaint = signed_complaint.get();

        // Create the opening
        let idkg_opening = match self.crypto.open_transcript(
            transcript,
            signed_complaint.signature.signer,
            &complaint.idkg_complaint,
        ) {
            Ok(opening) => opening,
            Err(err) => {
                warn!(
                    self.log,
                    "Failed to create opening for complaint {}, error = {:?}",
                    signed_complaint,
                    err
                );
                self.metrics.complaint_errors_inc("open_transcript");
                return Default::default();
            }
        };

        // Sign the opening
        let content = IDkgOpeningContent { idkg_opening };
        match self
            .crypto
            .sign(&content, self.node_id, transcript.registry_version)
        {
            Ok(signature) => {
                let opening = SignedIDkgOpening { content, signature };
                self.metrics.complaint_metrics_inc("openings_sent");
                vec![IDkgChangeAction::AddToValidated(IDkgMessage::Opening(
                    opening,
                ))]
            }
            Err(err) => {
                warn!(
                    self.log,
                    "Failed to sign opening for complaint {}, error = {:?}", signed_complaint, err
                );
                self.metrics.complaint_errors_inc("sign_opening");
                Default::default()
            }
        }
    }

    /// Helper to verify the opening
    fn crypto_verify_opening(
        &self,
        id: IDkgMessageId,
        transcript: &IDkgTranscript,
        signed_opening: SignedIDkgOpening,
        signed_complaint: &SignedIDkgComplaint,
    ) -> Option<IDkgChangeAction> {
        let opening = signed_opening.get();
        let complaint = signed_complaint.get();

        // Verify the signature
        if let Err(error) = self
            .crypto
            .verify(&signed_opening, transcript.registry_version)
        {
            if error.is_reproducible() {
                self.metrics
                    .complaint_errors_inc("verify_opening_signature_permanent");
                return Some(IDkgChangeAction::HandleInvalid(
                    id,
                    format!(
                        "Opening signature validation(permanent error): {}, error = {:?}",
                        signed_opening, error
                    ),
                ));
            } else {
                debug!(
                    self.log,
                    "Opening signature validation(transient error): {}, error = {:?}",
                    signed_opening,
                    error
                );
                self.metrics
                    .complaint_errors_inc("verify_opening_signature_transient");
                return None;
            }
        }

        // Verify the opening
        match self.crypto.verify_opening(
            transcript,
            signed_opening.signature.signer,
            &opening.idkg_opening,
            &complaint.idkg_complaint,
        ) {
            Err(error) if error.is_reproducible() => {
                self.metrics
                    .complaint_errors_inc("verify_opening_permanent");
                Some(IDkgChangeAction::HandleInvalid(
                    id,
                    format!(
                        "Opening validation(permanent error): {}, error = {:?}",
                        signed_opening, error
                    ),
                ))
            }
            Err(error) => {
                debug!(
                    self.log,
                    "Opening validation(transient error): {}, error = {:?}", signed_opening, error
                );
                self.metrics
                    .complaint_errors_inc("verify_opening_transient");
                None
            }
            Ok(()) => {
                self.metrics.complaint_metrics_inc("opening_received");
                Some(IDkgChangeAction::MoveToValidated(IDkgMessage::Opening(
                    signed_opening,
                )))
            }
        }
    }

    /// Checks if the complainer already issued a complaint for the given
    /// IDkgComplaint
    fn has_complainer_issued_complaint(
        &self,
        idkg_pool: &dyn IDkgPool,
        idkg_complaint: &IDkgComplaint,
        complainer_id: &NodeId,
    ) -> bool {
        let prefix = complaint_prefix(
            &idkg_complaint.transcript_id,
            &idkg_complaint.dealer_id,
            complainer_id,
        );
        idkg_pool
            .validated()
            .complaints_by_prefix(prefix)
            .any(|(_, signed_complaint)| {
                let complaint = signed_complaint.get();
                signed_complaint.signature.signer == *complainer_id
                    && complaint.idkg_complaint.transcript_id == idkg_complaint.transcript_id
                    && complaint.idkg_complaint.dealer_id == idkg_complaint.dealer_id
            })
    }

    /// Looks up the complaint for the given opening
    fn get_complaint_for_opening(
        &self,
        idkg_pool: &dyn IDkgPool,
        signed_opening: &SignedIDkgOpening,
    ) -> Option<SignedIDkgComplaint> {
        let opening = signed_opening.get();
        idkg_pool
            .validated()
            .complaints()
            .find(|(_, signed_complaint)| {
                let complaint = signed_complaint.get();
                complaint.idkg_complaint.transcript_id == opening.idkg_opening.transcript_id
                    && complaint.idkg_complaint.dealer_id == opening.idkg_opening.dealer_id
            })
            .map(|(_, signed_complaint)| signed_complaint)
    }

    /// Checks if the node has issued an opening for the complaint
    /// <transcript Id, dealer Id, opener Id>
    fn has_node_issued_opening(
        &self,
        idkg_pool: &dyn IDkgPool,
        transcript_id: &IDkgTranscriptId,
        dealer_id: &NodeId,
        opener_id: &NodeId,
    ) -> bool {
        let prefix = opening_prefix(transcript_id, dealer_id, opener_id);
        idkg_pool
            .validated()
            .openings_by_prefix(prefix)
            .any(|(_, signed_opening)| {
                let opening = signed_opening.get();
                opening.idkg_opening.transcript_id == *transcript_id
                    && opening.idkg_opening.dealer_id == *dealer_id
                    && signed_opening.signature.signer == *opener_id
            })
    }

    /// Looks up the valid openings for the given complaint (if any)
    fn get_openings_for_complaint(
        &self,
        idkg_pool: &dyn IDkgPool,
        complaint: &IDkgComplaint,
    ) -> BTreeMap<NodeId, IDkgOpening> {
        let mut openings = BTreeMap::new();
        for (_, signed_opening) in idkg_pool.validated().openings() {
            let opening = signed_opening.get();
            if opening.idkg_opening.transcript_id == complaint.transcript_id
                && opening.idkg_opening.dealer_id == complaint.dealer_id
                && signed_opening.signature.signer != self.node_id
            {
                openings.insert(
                    signed_opening.signature.signer,
                    opening.idkg_opening.clone(),
                );
            }
        }
        openings
    }

    /// Checks if the artifact should be purged
    fn should_purge(
        &self,
        transcript_id: &IDkgTranscriptId,
        requested_height: Height,
        current_height: Height,
        active_transcripts: &BTreeSet<IDkgTranscriptId>,
    ) -> bool {
        requested_height <= current_height && !active_transcripts.contains(transcript_id)
    }

    /// Resolves the active ref -> transcripts
    fn resolve_ref(
        &self,
        transcript_ref: &TranscriptRef,
        block_reader: &dyn IDkgBlockReader,
        reason: &str,
    ) -> Option<IDkgTranscript> {
        let _timer = self
            .metrics
            .on_state_change_duration
            .with_label_values(&["resolve_transcript_refs"])
            .start_timer();
        match block_reader.transcript(transcript_ref) {
            Ok(transcript) => {
                self.metrics
                    .complaint_metrics_inc("resolve_transcript_refs");
                Some(transcript)
            }
            Err(error) => {
                warn!(
                    self.log,
                    "Failed to resolve complaint ref: reason = {}, \
                     transcript_ref = {:?}, error = {:?}",
                    reason,
                    transcript_ref,
                    error
                );
                self.metrics.complaint_errors_inc("resolve_transcript_refs");
                None
            }
        }
    }

    /// Returns the active transcript map.
    fn active_transcripts(
        &self,
        block_reader: &dyn IDkgBlockReader,
    ) -> BTreeMap<IDkgTranscriptId, TranscriptRef> {
        block_reader
            .active_transcripts()
            .iter()
            .map(|transcript_ref| (transcript_ref.transcript_id, *transcript_ref))
            .collect::<BTreeMap<_, _>>()
    }

    /// Returns the requested transcript map.
    fn requested_transcripts(
        &self,
        block_reader: &dyn IDkgBlockReader,
    ) -> BTreeSet<IDkgTranscriptId> {
        block_reader
            .requested_transcripts()
            .map(|transcript_ref| transcript_ref.transcript_id)
            .collect::<BTreeSet<_>>()
    }
}

impl IDkgComplaintHandler for IDkgComplaintHandlerImpl {
    fn on_state_change(&self, idkg_pool: &dyn IDkgPool) -> IDkgChangeSet {
        let block_reader = IDkgBlockReaderImpl::new(self.consensus_block_cache.finalized_chain());
        let metrics = self.metrics.clone();

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

        let validate_complaints = || {
            timed_call(
                "validate_complaints",
                || self.validate_complaints(idkg_pool, &block_reader),
                &metrics.on_state_change_duration,
            )
        };
        let send_openings = || {
            timed_call(
                "send_openings",
                || self.send_openings(idkg_pool, &block_reader),
                &metrics.on_state_change_duration,
            )
        };
        let validate_openings = || {
            timed_call(
                "validate_openings",
                || self.validate_openings(idkg_pool, &block_reader),
                &metrics.on_state_change_duration,
            )
        };

        let calls: [&'_ dyn Fn() -> IDkgChangeSet; 3] =
            [&validate_complaints, &send_openings, &validate_openings];

        changes.append(&mut self.schedule.call_next(&calls));
        changes
    }

    fn as_transcript_loader(&self) -> &dyn IDkgTranscriptLoader {
        self
    }
}

pub(crate) trait IDkgTranscriptLoader: Send {
    /// Loads the given transcript
    fn load_transcript(
        &self,
        idkg_pool: &dyn IDkgPool,
        transcript: &IDkgTranscript,
    ) -> TranscriptLoadStatus;
}

#[derive(Debug)]
pub(crate) enum TranscriptLoadStatus {
    /// Transcript was loaded successfully
    Success,

    /// Failed to load the transcript
    Failure,

    /// Resulted in new complaints
    Complaints(Vec<SignedIDkgComplaint>),
}

impl IDkgTranscriptLoader for IDkgComplaintHandlerImpl {
    fn load_transcript(
        &self,
        idkg_pool: &dyn IDkgPool,
        transcript: &IDkgTranscript,
    ) -> TranscriptLoadStatus {
        // 1. Try loading the transcripts without openings
        let complaints = match IDkgProtocol::load_transcript(&*self.crypto, transcript) {
            Ok(complaints) => {
                if complaints.is_empty() {
                    self.metrics.complaint_metrics_inc("transcripts_loaded");
                    return TranscriptLoadStatus::Success;
                }
                complaints
            }
            Err(err) => {
                warn!(
                    self.log,
                    "Failed to load transcript: transcript_id: {:?}, error = {:?}",
                    transcript.transcript_id,
                    err
                );
                self.metrics.complaint_errors_inc("load_transcript");
                return TranscriptLoadStatus::Failure;
            }
        };

        // 2. Add any new complaints to the pool
        let mut new_complaints = Vec::new();
        let mut old_complaints = Vec::new();
        for complaint in complaints {
            if !self.has_complainer_issued_complaint(idkg_pool, &complaint, &self.node_id) {
                if let Some(idkg_complaint) =
                    self.crypto_create_complaint(complaint, transcript.registry_version)
                {
                    new_complaints.push(idkg_complaint);
                } else {
                    return TranscriptLoadStatus::Failure;
                }
            } else {
                old_complaints.push(complaint);
            }
        }
        if !new_complaints.is_empty() {
            return TranscriptLoadStatus::Complaints(new_complaints);
        }

        // 3. No new complaints. Collect the validated openings for the old complaints
        // and retry loading the transcript
        let mut openings = BTreeMap::new();
        for complaint in old_complaints {
            let complaint_openings = self.get_openings_for_complaint(idkg_pool, &complaint);
            openings.insert(complaint, complaint_openings);
        }
        match IDkgProtocol::load_transcript_with_openings(&*self.crypto, transcript, &openings) {
            Ok(()) => {
                self.metrics
                    .complaint_metrics_inc("transcripts_loaded_with_openings");
                TranscriptLoadStatus::Success
            }
            Err(IDkgLoadTranscriptError::InsufficientOpenings { .. }) => {
                self.metrics
                    .complaint_errors_inc("load_transcript_with_openings_threshold");
                TranscriptLoadStatus::Failure
            }
            Err(err) => {
                warn!(
                    self.log,
                    "Failed to load transcript with openings: transcript_id: {:?}, error = {:?}",
                    transcript.transcript_id,
                    err
                );
                self.metrics
                    .complaint_errors_inc("load_transcript_with_openings");
                TranscriptLoadStatus::Failure
            }
        }
    }
}

/// Specifies how to handle a received message
#[derive(Eq, PartialEq, Debug)]
enum Action<'a> {
    /// The message is relevant to our current state, process it
    /// immediately.
    Process(&'a TranscriptRef),

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
        active_transcripts: &'a BTreeMap<IDkgTranscriptId, TranscriptRef>,
        requested_transcripts: &'a BTreeSet<IDkgTranscriptId>,
        msg_height: Height,
        msg_transcript_id: &IDkgTranscriptId,
    ) -> Action<'a> {
        if msg_height > block_reader.tip_height() {
            // Message is from a node ahead of us, keep it to be
            // processed later
            return Action::Defer;
        }

        if let Some(transcript_ref) = active_transcripts.get(msg_transcript_id) {
            return Action::Process(transcript_ref);
        }

        // The transcript is not yet completed on this node, process
        // the message later when it is.
        if requested_transcripts.contains(msg_transcript_id) {
            return Action::Defer;
        }

        Action::Drop
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::idkg::test_utils::*;
    use crate::idkg::utils::algorithm_for_key_id;
    use assert_matches::assert_matches;
    use ic_consensus_utils::crypto::SignVerify;
    use ic_crypto_test_utils_canister_threshold_sigs::CanisterThresholdSigTestEnvironment;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_interfaces::p2p::consensus::{MutablePool, UnvalidatedArtifact};
    use ic_management_canister_types::MasterPublicKeyId;
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_types::ids::{NODE_1, NODE_2, NODE_3, NODE_4};
    use ic_types::consensus::idkg::{IDkgObject, TranscriptRef};
    use ic_types::crypto::AlgorithmId;
    use ic_types::time::UNIX_EPOCH;
    use ic_types::Height;

    // Tests the Action logic
    #[test]
    fn test_ecdsa_complaint_action() {
        let key_id = fake_ecdsa_master_public_key_id();
        let (id_1, id_2, id_3, id_4, id_5) = (
            create_transcript_id(1),
            create_transcript_id(2),
            create_transcript_id(3),
            create_transcript_id(4),
            create_transcript_id(5),
        );

        let ref_1 = TranscriptRef::new(Height::new(10), id_1);
        let ref_2 = TranscriptRef::new(Height::new(20), id_2);
        let block_reader =
            TestIDkgBlockReader::for_complainer_test(&key_id, Height::new(100), vec![ref_1, ref_2]);
        let mut active = BTreeMap::new();
        active.insert(id_1, ref_1);
        active.insert(id_2, ref_2);
        let mut requested = BTreeSet::new();
        requested.insert(id_5);

        // Message from a node ahead of us
        assert_eq!(
            Action::action(&block_reader, &active, &requested, Height::from(200), &id_3),
            Action::Defer
        );

        // Messages for transcripts not currently active
        assert_eq!(
            Action::action(&block_reader, &active, &requested, Height::from(10), &id_3),
            Action::Drop
        );
        assert_eq!(
            Action::action(&block_reader, &active, &requested, Height::from(20), &id_4),
            Action::Drop
        );

        // Messages for transcripts not currently active but requested
        assert_eq!(
            Action::action(&block_reader, &active, &requested, Height::from(10), &id_5),
            Action::Defer
        );

        // Messages for transcripts currently active
        assert_matches!(
            Action::action(&block_reader, &active, &requested, Height::from(10), &id_1),
            Action::Process(_)
        );
        assert_matches!(
            Action::action(&block_reader, &active, &requested, Height::from(20), &id_2),
            Action::Process(_)
        );
    }

    #[test]
    fn test_crypto_verify_complaint() {
        let mut rng = reproducible_rng();
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let key_id = fake_ecdsa_master_public_key_id();
                let env = CanisterThresholdSigTestEnvironment::new(1, &mut rng);
                let crypto = env.nodes.iter().next().unwrap().crypto();
                let (_, complaint_handler) =
                    create_complaint_dependencies_with_crypto(pool_config, logger, Some(crypto));
                let id = create_transcript_id_with_height(2, Height::from(20));
                let transcript = create_transcript(&key_id, id, &[NODE_2]);
                let complaint = create_complaint(id, NODE_2, NODE_3);
                let changeset: Vec<_> = complaint_handler
                    .crypto_verify_complaint(complaint.message_id(), &transcript, complaint.clone())
                    .into_iter()
                    .collect();
                // assert that the mock complaint does not pass real crypto check
                assert!(is_handle_invalid(&changeset, &complaint.message_id()));
            })
        })
    }

    // Tests validation of the received complaints
    #[test]
    fn test_validate_complaints_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_validate_complaints(key_id);
        }
    }

    fn test_validate_complaints(key_id: MasterPublicKeyId) {
        let (id_1, id_2, id_3) = (
            create_transcript_id_with_height(1, Height::from(200)),
            create_transcript_id_with_height(2, Height::from(20)),
            create_transcript_id_with_height(3, Height::from(30)),
        );

        // Set up the IDKG pool
        let mut artifacts = Vec::new();
        // Complaint from a node ahead of us (deferred)
        let complaint = create_complaint(id_1, NODE_2, NODE_3);
        artifacts.push(UnvalidatedArtifact {
            message: IDkgMessage::Complaint(complaint),
            peer_id: NODE_3,
            timestamp: UNIX_EPOCH,
        });

        // Complaint for a transcript not currently active (dropped)
        let complaint = create_complaint(id_2, NODE_2, NODE_3);
        let msg_id_2 = complaint.message_id();
        artifacts.push(UnvalidatedArtifact {
            message: IDkgMessage::Complaint(complaint),
            peer_id: NODE_3,
            timestamp: UNIX_EPOCH,
        });

        // Complaint for a transcript currently active (accepted)
        let complaint = create_complaint(id_3, NODE_2, NODE_3);
        let msg_id_3 = complaint.message_id();
        artifacts.push(UnvalidatedArtifact {
            message: IDkgMessage::Complaint(complaint),
            peer_id: NODE_3,
            timestamp: UNIX_EPOCH,
        });

        // Only id_3 is active
        let block_reader = TestIDkgBlockReader::for_complainer_test(
            &key_id,
            Height::new(100),
            vec![TranscriptRef::new(Height::new(10), id_3)],
        );

        // Test successful validation using CryptoReturningOk
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, complaint_handler) =
                    create_complaint_dependencies(pool_config, logger);

                artifacts.iter().for_each(|a| idkg_pool.insert(a.clone()));

                let change_set = complaint_handler.validate_complaints(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 2);
                assert!(is_removed_from_unvalidated(&change_set, &msg_id_2));
                assert!(is_moved_to_validated(&change_set, &msg_id_3));
            })
        });

        // Test transient crypto failure during validation
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, complaint_handler) = create_complaint_dependencies_with_crypto(
                    pool_config,
                    logger,
                    Some(crypto_without_keys()),
                );

                artifacts.iter().for_each(|a| idkg_pool.insert(a.clone()));

                // Crypto should return a transient error thus validation of msg_id_3 should be deferred.
                let change_set = complaint_handler.validate_complaints(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_unvalidated(&change_set, &msg_id_2));
            })
        });

        // Simulate failure when resolving transcript ref
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, complaint_handler) =
                    create_complaint_dependencies(pool_config, logger);

                artifacts.iter().for_each(|a| idkg_pool.insert(a.clone()));

                let block_reader = block_reader.clone().with_fail_to_resolve();
                let change_set = complaint_handler.validate_complaints(&idkg_pool, &block_reader);

                assert_eq!(change_set.len(), 2);
                assert!(is_removed_from_unvalidated(&change_set, &msg_id_2));
                assert!(is_handle_invalid(&change_set, &msg_id_3));
            })
        });
    }

    // Tests that duplicate complaint from the same complainer is dropped
    #[test]
    fn test_ecdsa_duplicate_complaints() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let key_id = fake_ecdsa_master_public_key_id();
                let (mut idkg_pool, complaint_handler) =
                    create_complaint_dependencies(pool_config, logger);
                let id_1 = create_transcript_id_with_height(1, Height::from(30));

                // Set up the IDKG pool
                // Complaint from NODE_3 for transcript id_1, dealer NODE_2
                let complaint = create_complaint(id_1, NODE_2, NODE_3);
                let msg_id = complaint.message_id();
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::Complaint(complaint.clone()),
                    peer_id: NODE_3,
                    timestamp: UNIX_EPOCH,
                });

                // Validated pool already has complaint from NODE_3 for
                // transcript id_1, dealer NODE_2
                let change_set = vec![IDkgChangeAction::AddToValidated(IDkgMessage::Complaint(
                    complaint,
                ))];
                idkg_pool.apply(change_set);

                let block_reader = TestIDkgBlockReader::for_complainer_test(
                    &key_id,
                    Height::new(30),
                    vec![TranscriptRef::new(Height::new(30), id_1)],
                );
                let change_set = complaint_handler.validate_complaints(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_handle_invalid(&change_set, &msg_id));
            })
        })
    }

    // Tests that complaints are purged once the finalized height increases
    #[test]
    fn test_ecdsa_complaints_purging() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, complaint_handler, mut consensus_pool) =
                    create_complaint_dependencies_and_pool(pool_config, logger);
                let transcript_height = Height::from(30);
                let id_1 = create_transcript_id_with_height(1, Height::from(0));
                let id_2 = create_transcript_id_with_height(2, transcript_height);

                let complaint1 = create_complaint(id_1, NODE_2, NODE_3);
                let msg_id1 = complaint1.message_id();
                let complaint2 = create_complaint(id_2, NODE_2, NODE_3);
                let msg_id2 = complaint2.message_id();
                let change_set = vec![
                    IDkgChangeAction::AddToValidated(IDkgMessage::Complaint(complaint1)),
                    IDkgChangeAction::AddToValidated(IDkgMessage::Complaint(complaint2)),
                ];
                idkg_pool.apply(change_set);

                // Finalized height doesn't increase, so complaint1 shouldn't be purged
                let change_set = complaint_handler.on_state_change(&idkg_pool);
                assert_eq!(
                    *complaint_handler.prev_finalized_height.borrow(),
                    Height::from(0)
                );
                assert!(change_set.is_empty());

                // Finalized height increases, so complaint1 is purged
                let new_height = consensus_pool.advance_round_normal_operation_n(29);
                let change_set = complaint_handler.on_state_change(&idkg_pool);
                assert_eq!(
                    *complaint_handler.prev_finalized_height.borrow(),
                    new_height
                );
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_validated(&change_set, &msg_id1));

                idkg_pool.apply(change_set);

                // Finalized height increases above complaint2, so it is purged
                let new_height = consensus_pool.advance_round_normal_operation();
                let change_set = complaint_handler.on_state_change(&idkg_pool);
                assert_eq!(
                    *complaint_handler.prev_finalized_height.borrow(),
                    new_height
                );
                assert_eq!(transcript_height, new_height);
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_validated(&change_set, &msg_id2));
            })
        })
    }

    // Tests that duplicate complaint from the same complainer in the unvalidated
    // pool  is dropped
    #[test]
    fn test_ecdsa_duplicate_complaints_in_batch() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let key_id = fake_ecdsa_master_public_key_id();
                let (mut idkg_pool, complaint_handler) =
                    create_complaint_dependencies(pool_config, logger);
                let id_1 = create_transcript_id_with_height(1, Height::from(30));

                // Set up the IDKG pool
                // Complaint from NODE_3 for transcript id_1, dealer NODE_2
                let complaint = create_complaint_with_nonce(id_1, NODE_2, NODE_3, 0);
                let msg_id_1 = complaint.message_id();
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::Complaint(complaint),
                    peer_id: NODE_3,
                    timestamp: UNIX_EPOCH,
                });

                // Complaint from NODE_3 for transcript id_1, dealer NODE_2
                let complaint = create_complaint_with_nonce(id_1, NODE_2, NODE_3, 1);
                let msg_id_2 = complaint.message_id();
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::Complaint(complaint),
                    peer_id: NODE_3,
                    timestamp: UNIX_EPOCH,
                });

                let block_reader = TestIDkgBlockReader::for_complainer_test(
                    &key_id,
                    Height::new(100),
                    vec![TranscriptRef::new(Height::new(30), id_1)],
                );
                let change_set = complaint_handler.validate_complaints(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 2);
                // One is considered duplicate
                assert!(is_handle_invalid(&change_set, &msg_id_1));
                // One is considered valid
                assert!(is_moved_to_validated(&change_set, &msg_id_2));
            })
        })
    }

    // Tests that openings are sent for eligible complaints
    #[test]
    fn test_send_openings_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_send_openings(key_id);
        }
    }

    fn test_send_openings(key_id: MasterPublicKeyId) {
        let (id_1, id_2, id_3) = (
            create_transcript_id(1),
            create_transcript_id(2),
            create_transcript_id(3),
        );
        let mut artifacts = Vec::new();

        // Complaint for which we haven't issued an opening. This should
        // result in opening sent out.
        let complaint = create_complaint(id_1, NODE_2, NODE_3);
        artifacts.push(IDkgMessage::Complaint(complaint));

        // Complaint for which we already issued an opening. This should
        // not result in an opening.
        let complaint = create_complaint(id_2, NODE_2, NODE_3);
        let opening = create_opening(id_2, NODE_2, NODE_3, NODE_1);
        artifacts.push(IDkgMessage::Complaint(complaint));
        artifacts.push(IDkgMessage::Opening(opening));

        // Complaint for transcript not in the active list
        let complaint = create_complaint(id_3, NODE_2, NODE_3);
        artifacts.push(IDkgMessage::Complaint(complaint));

        let block_reader = TestIDkgBlockReader::for_complainer_test(
            &key_id,
            Height::new(100),
            vec![
                TranscriptRef::new(Height::new(10), id_1),
                TranscriptRef::new(Height::new(20), id_2),
            ],
        );

        // Opening should be sent when using CryptoReturningOk
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, complaint_handler) =
                    create_complaint_dependencies(pool_config, logger);

                idkg_pool.apply(
                    artifacts
                        .iter()
                        .map(|a| IDkgChangeAction::AddToValidated(a.clone()))
                        .collect(),
                );
                let change_set = complaint_handler.send_openings(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_opening_added_to_validated(
                    &change_set,
                    &id_1,
                    &NODE_2,
                    &NODE_1
                ));
            })
        });

        // Opening should not be sent if crypto fails
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, complaint_handler) = create_complaint_dependencies_with_crypto(
                    pool_config,
                    logger,
                    Some(crypto_without_keys()),
                );

                idkg_pool.apply(
                    artifacts
                        .iter()
                        .map(|a| IDkgChangeAction::AddToValidated(a.clone()))
                        .collect(),
                );

                let change_set = complaint_handler.send_openings(&idkg_pool, &block_reader);
                assert!(change_set.is_empty());
            })
        });
    }

    #[test]
    fn test_crypto_verify_opening() {
        let mut rng = reproducible_rng();
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let key_id = fake_ecdsa_master_public_key_id();
                let env = CanisterThresholdSigTestEnvironment::new(1, &mut rng);
                let crypto = env.nodes.iter().next().unwrap().crypto();
                let (_, complaint_handler) =
                    create_complaint_dependencies_with_crypto(pool_config, logger, Some(crypto));
                let id = create_transcript_id_with_height(2, Height::from(20));
                let transcript = create_transcript(&key_id, id, &[NODE_2]);
                let complaint = create_complaint(id, NODE_2, NODE_3);
                let opening = create_opening(id, NODE_2, NODE_3, NODE_4);
                let changeset: Vec<_> = complaint_handler
                    .crypto_verify_opening(
                        opening.message_id(),
                        &transcript,
                        opening.clone(),
                        &complaint,
                    )
                    .into_iter()
                    .collect();
                // assert that the mock opening does not pass real crypto check
                assert!(is_handle_invalid(&changeset, &opening.message_id()));
            })
        })
    }

    // Tests the validation of received openings
    #[test]
    fn test_validate_openings_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_validate_openings(key_id);
        }
    }

    fn test_validate_openings(key_id: MasterPublicKeyId) {
        let (id_1, id_2, id_3, id_4) = (
            create_transcript_id_with_height(1, Height::from(400)),
            create_transcript_id_with_height(2, Height::from(20)),
            create_transcript_id_with_height(3, Height::from(30)),
            create_transcript_id_with_height(4, Height::from(40)),
        );

        // Set up the IDKG pool
        let mut artifacts = Vec::new();
        // Opening from a node ahead of us (deferred)
        let opening = create_opening(id_1, NODE_2, NODE_3, NODE_4);
        artifacts.push(UnvalidatedArtifact {
            message: IDkgMessage::Opening(opening),
            peer_id: NODE_4,
            timestamp: UNIX_EPOCH,
        });

        // Opening for a transcript not currently active(dropped)
        let opening = create_opening(id_2, NODE_2, NODE_3, NODE_4);
        let msg_id_1 = opening.message_id();
        artifacts.push(UnvalidatedArtifact {
            message: IDkgMessage::Opening(opening),
            peer_id: NODE_4,
            timestamp: UNIX_EPOCH,
        });

        // Opening for a transcript currently active,
        // with a matching complaint (accepted)
        let opening = create_opening(id_3, NODE_2, NODE_3, NODE_4);
        let msg_id_2 = opening.message_id();
        artifacts.push(UnvalidatedArtifact {
            message: IDkgMessage::Opening(opening),
            peer_id: NODE_4,
            timestamp: UNIX_EPOCH,
        });
        let complaint = IDkgMessage::Complaint(create_complaint(id_3, NODE_2, NODE_3));

        // Opening for a transcript currently active,
        // without a matching complaint (deferred)
        let opening = create_opening(id_4, NODE_2, NODE_3, NODE_4);
        artifacts.push(UnvalidatedArtifact {
            message: IDkgMessage::Opening(opening),
            peer_id: NODE_4,
            timestamp: UNIX_EPOCH,
        });

        let block_reader = TestIDkgBlockReader::for_complainer_test(
            &key_id,
            Height::new(100),
            vec![
                TranscriptRef::new(Height::new(10), id_3),
                TranscriptRef::new(Height::new(20), id_4),
            ],
        );

        // Opening should be moved to validated when using CryptoReturningOk
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, complaint_handler) =
                    create_complaint_dependencies(pool_config, logger);

                artifacts.iter().for_each(|a| idkg_pool.insert(a.clone()));
                idkg_pool.apply(vec![IDkgChangeAction::AddToValidated(complaint.clone())]);

                let change_set = complaint_handler.validate_openings(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 2);
                assert!(is_removed_from_unvalidated(&change_set, &msg_id_1));
                assert!(is_moved_to_validated(&change_set, &msg_id_2));
            })
        });

        // Opening should be deferred when crypto returns transient failure
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, complaint_handler) = create_complaint_dependencies_with_crypto(
                    pool_config,
                    logger,
                    Some(crypto_without_keys()),
                );

                artifacts.iter().for_each(|a| idkg_pool.insert(a.clone()));
                idkg_pool.apply(vec![IDkgChangeAction::AddToValidated(complaint.clone())]);

                // Crypto should return a transient error thus validation of msg_id_2 should be deferred.
                let change_set = complaint_handler.validate_openings(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_unvalidated(&change_set, &msg_id_1));
            })
        });

        // Opening should be handled invalid when corresponding transcript fails to be resolved
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut idkg_pool, complaint_handler) =
                    create_complaint_dependencies(pool_config, logger);

                artifacts.iter().for_each(|a| idkg_pool.insert(a.clone()));
                idkg_pool.apply(vec![IDkgChangeAction::AddToValidated(complaint.clone())]);

                let block_reader = block_reader.clone().with_fail_to_resolve();
                let change_set = complaint_handler.validate_openings(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 2);
                assert!(is_removed_from_unvalidated(&change_set, &msg_id_1));
                assert!(is_handle_invalid(&change_set, &msg_id_2));
            })
        });
    }

    // Tests that duplicate openings are dropped
    #[test]
    fn test_ecdsa_duplicate_openings() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let key_id = fake_ecdsa_master_public_key_id();
                let (mut idkg_pool, complaint_handler) =
                    create_complaint_dependencies(pool_config, logger);
                let id_1 = create_transcript_id_with_height(1, Height::from(20));

                // Set up the IDKG pool
                // Opening from NODE_4 for transcript id_1, dealer NODE_2, complainer NODE_3
                let opening = create_opening(id_1, NODE_2, NODE_3, NODE_4);
                let msg_id = opening.message_id();
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::Opening(opening.clone()),
                    peer_id: NODE_4,
                    timestamp: UNIX_EPOCH,
                });

                // Validated pool already has it
                let change_set = vec![IDkgChangeAction::AddToValidated(IDkgMessage::Opening(
                    opening,
                ))];
                idkg_pool.apply(change_set);

                let block_reader = TestIDkgBlockReader::for_complainer_test(
                    &key_id,
                    Height::new(100),
                    vec![TranscriptRef::new(Height::new(10), id_1)],
                );
                let change_set = complaint_handler.validate_openings(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_handle_invalid(&change_set, &msg_id));
            })
        })
    }

    // Tests that duplicate openings from the same opener in the unvalidated
    // pool is dropped
    #[test]
    fn test_ecdsa_duplicate_openings_in_batch() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let key_id = fake_ecdsa_master_public_key_id();
                let (mut idkg_pool, complaint_handler) =
                    create_complaint_dependencies(pool_config, logger);
                let id_1 = create_transcript_id_with_height(1, Height::from(20));

                // Set up the IDKG pool
                // Opening from NODE_4 for transcript id_1, dealer NODE_2, complainer NODE_3
                let opening = create_opening_with_nonce(id_1, NODE_2, NODE_3, NODE_4, 1);
                let msg_id_1 = opening.message_id();
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::Opening(opening),
                    peer_id: NODE_4,
                    timestamp: UNIX_EPOCH,
                });

                // Opening from NODE_4 for transcript id_1, dealer NODE_2, complainer NODE_3
                let opening = create_opening_with_nonce(id_1, NODE_2, NODE_3, NODE_4, 2);
                let msg_id_2 = opening.message_id();
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::Opening(opening),
                    peer_id: NODE_4,
                    timestamp: UNIX_EPOCH,
                });

                // Make sure we also have matching complaints
                let complaint = create_complaint(id_1, NODE_2, NODE_3);
                let message = IDkgMessage::Complaint(complaint);
                idkg_pool.insert(UnvalidatedArtifact {
                    message: message.clone(),
                    peer_id: NODE_3,
                    timestamp: UNIX_EPOCH,
                });
                let change_set = vec![IDkgChangeAction::AddToValidated(message)];
                idkg_pool.apply(change_set);

                let block_reader = TestIDkgBlockReader::for_complainer_test(
                    &key_id,
                    Height::new(100),
                    vec![TranscriptRef::new(Height::new(10), id_1)],
                );
                let change_set = complaint_handler.validate_openings(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 2);
                // One is considered duplicate
                assert!(is_handle_invalid(&change_set, &msg_id_2));
                // One is considered valid
                assert!(is_moved_to_validated(&change_set, &msg_id_1));
            })
        })
    }

    // Tests purging of complaints from unvalidated pool
    #[test]
    fn test_ecdsa_purge_unvalidated_complaints() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let key_id = fake_ecdsa_master_public_key_id();
                let (mut idkg_pool, complaint_handler) =
                    create_complaint_dependencies(pool_config, logger);
                let (id_1, id_2, id_3) = (
                    create_transcript_id_with_height(1, Height::from(20)),
                    create_transcript_id_with_height(2, Height::from(30)),
                    create_transcript_id_with_height(3, Height::from(200)),
                );

                // Complaint 1: height <= current_height, active transcripts (not purged)
                let complaint = create_complaint(id_1, NODE_2, NODE_3);
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::Complaint(complaint),
                    peer_id: NODE_3,
                    timestamp: UNIX_EPOCH,
                });

                // Complaint 2: height <= current_height, non-active transcripts (purged)
                let complaint = create_complaint(id_2, NODE_2, NODE_3);
                let msg_id = complaint.message_id();
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::Complaint(complaint),
                    peer_id: NODE_3,
                    timestamp: UNIX_EPOCH,
                });

                // Complaint 3: height > current_height (not purged)
                let complaint = create_complaint(id_3, NODE_2, NODE_3);
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::Complaint(complaint),
                    peer_id: NODE_3,
                    timestamp: UNIX_EPOCH,
                });

                // Only id_1 is active
                let block_reader = TestIDkgBlockReader::for_complainer_test(
                    &key_id,
                    Height::new(100),
                    vec![TranscriptRef::new(Height::new(10), id_1)],
                );
                let change_set = complaint_handler.purge_artifacts(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_unvalidated(&change_set, &msg_id));
            })
        })
    }

    // Tests purging of complaints from validated pool
    #[test]
    fn test_ecdsa_purge_validated_complaints() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let key_id = fake_ecdsa_master_public_key_id();
                let (mut idkg_pool, complaint_handler) =
                    create_complaint_dependencies(pool_config, logger);
                let (id_1, id_2, id_3) = (
                    create_transcript_id_with_height(1, Height::from(20)),
                    create_transcript_id_with_height(2, Height::from(30)),
                    create_transcript_id_with_height(3, Height::from(200)),
                );

                // Complaint 1: height <= current_height, active transcripts (not purged)
                let complaint = create_complaint(id_1, NODE_2, NODE_3);
                let change_set = vec![IDkgChangeAction::AddToValidated(IDkgMessage::Complaint(
                    complaint,
                ))];
                idkg_pool.apply(change_set);

                // Complaint 2: height <= current_height, non-active transcripts (purged)
                let complaint = create_complaint(id_2, NODE_2, NODE_3);
                let msg_id = complaint.message_id();
                let change_set = vec![IDkgChangeAction::AddToValidated(IDkgMessage::Complaint(
                    complaint,
                ))];
                idkg_pool.apply(change_set);

                // Complaint 3: height > current_height (not purged)
                let complaint = create_complaint(id_3, NODE_2, NODE_3);
                let change_set = vec![IDkgChangeAction::AddToValidated(IDkgMessage::Complaint(
                    complaint,
                ))];
                idkg_pool.apply(change_set);

                // Only id_1 is active
                let block_reader = TestIDkgBlockReader::for_complainer_test(
                    &key_id,
                    Height::new(100),
                    vec![TranscriptRef::new(Height::new(10), id_1)],
                );
                let change_set = complaint_handler.purge_artifacts(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_validated(&change_set, &msg_id));
            })
        })
    }

    // Tests purging of openings from unvalidated pool
    #[test]
    fn test_ecdsa_purge_unvalidated_openings() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let key_id = fake_ecdsa_master_public_key_id();
                let (mut idkg_pool, complaint_handler) =
                    create_complaint_dependencies(pool_config, logger);
                let (id_1, id_2, id_3) = (
                    create_transcript_id_with_height(1, Height::from(20)),
                    create_transcript_id_with_height(2, Height::from(30)),
                    create_transcript_id_with_height(3, Height::from(200)),
                );

                // Opening 1: height <= current_height, active transcripts (not purged)
                let opening = create_opening(id_1, NODE_2, NODE_3, NODE_4);
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::Opening(opening),
                    peer_id: NODE_4,
                    timestamp: UNIX_EPOCH,
                });

                // Opening 2: height <= current_height, non-active transcripts (purged)
                let opening = create_opening(id_2, NODE_2, NODE_3, NODE_4);
                let msg_id = opening.message_id();
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::Opening(opening),
                    peer_id: NODE_4,
                    timestamp: UNIX_EPOCH,
                });

                // Complaint 3: height > current_height (not purged)
                let opening = create_opening(id_3, NODE_2, NODE_3, NODE_4);
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::Opening(opening),
                    peer_id: NODE_4,
                    timestamp: UNIX_EPOCH,
                });

                // Only id_1 is active
                let block_reader = TestIDkgBlockReader::for_complainer_test(
                    &key_id,
                    Height::new(100),
                    vec![TranscriptRef::new(Height::new(10), id_1)],
                );
                let change_set = complaint_handler.purge_artifacts(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_unvalidated(&change_set, &msg_id));
            })
        })
    }

    // Tests purging of openings from validated pool
    #[test]
    fn test_ecdsa_purge_validated_openings() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let key_id = fake_ecdsa_master_public_key_id();
                let (mut idkg_pool, complaint_handler) =
                    create_complaint_dependencies(pool_config, logger);
                let (id_1, id_2, id_3) = (
                    create_transcript_id_with_height(1, Height::from(20)),
                    create_transcript_id_with_height(2, Height::from(30)),
                    create_transcript_id_with_height(3, Height::from(200)),
                );

                // Opening 1: height <= current_height, active transcripts (not purged)
                let opening = create_opening(id_1, NODE_2, NODE_3, NODE_4);
                let change_set = vec![IDkgChangeAction::AddToValidated(IDkgMessage::Opening(
                    opening,
                ))];
                idkg_pool.apply(change_set);

                // Opening 2: height <= current_height, non-active transcripts (purged)
                let opening = create_opening(id_2, NODE_2, NODE_3, NODE_4);
                let msg_id = opening.message_id();
                let change_set = vec![IDkgChangeAction::AddToValidated(IDkgMessage::Opening(
                    opening,
                ))];
                idkg_pool.apply(change_set);

                // Complaint 3: height > current_height (not purged)
                let opening = create_opening(id_3, NODE_2, NODE_3, NODE_4);
                let change_set = vec![IDkgChangeAction::AddToValidated(IDkgMessage::Opening(
                    opening,
                ))];
                idkg_pool.apply(change_set);

                // Only id_1 is active
                let block_reader = TestIDkgBlockReader::for_complainer_test(
                    &key_id,
                    Height::new(100),
                    vec![TranscriptRef::new(Height::new(10), id_1)],
                );
                let change_set = complaint_handler.purge_artifacts(&idkg_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_removed_from_validated(&change_set, &msg_id));
            })
        })
    }

    #[test]
    fn test_load_transcript_success_all_ecdsa_algorithms() {
        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            test_load_transcript_success(alg);
        }
    }

    #[test]
    fn test_load_transcript_success_all_schnorr_algorithms() {
        for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
            test_load_transcript_success(alg);
        }
    }

    // Tests loading of a valid transcript without complaints
    fn test_load_transcript_success(algorithm: AlgorithmId) {
        let mut rng = reproducible_rng();
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let env = CanisterThresholdSigTestEnvironment::new(3, &mut rng);
                let (_, _, idkg_transcript) = create_valid_transcript(&env, &mut rng, algorithm);

                let crypto = env
                    .nodes
                    .filter_by_receivers(&idkg_transcript)
                    .next()
                    .unwrap()
                    .crypto();
                let (idkg_pool, complaint_handler) =
                    create_complaint_dependencies_with_crypto(pool_config, logger, Some(crypto));

                let status = complaint_handler.load_transcript(&idkg_pool, &idkg_transcript);
                assert_matches!(status, TranscriptLoadStatus::Success);
            })
        })
    }

    // Tests that loading of an invalid transcript fails
    #[test]
    fn test_ecdsa_load_transcript_failure_invalid_transcript() {
        let mut rng = reproducible_rng();
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let key_id = fake_ecdsa_master_public_key_id();
                let env = CanisterThresholdSigTestEnvironment::new(3, &mut rng);
                let receivers: Vec<_> = env.nodes.ids();
                let t = create_transcript(&key_id, create_transcript_id(1), &receivers[..]);

                let crypto = env.nodes.iter().next().unwrap().crypto();
                let (idkg_pool, complaint_handler) =
                    create_complaint_dependencies_with_crypto(pool_config, logger, Some(crypto));

                let status = complaint_handler.load_transcript(&idkg_pool, &t);
                assert_matches!(status, TranscriptLoadStatus::Failure);
            })
        })
    }

    // Tests that crypto failure when creating complaint leads to transcript load failure
    #[test]
    fn test_load_transcript_failure_to_create_complaint_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_load_transcript_failure_to_create_complaint(key_id);
        }
    }

    fn test_load_transcript_failure_to_create_complaint(key_id: MasterPublicKeyId) {
        let mut rng = reproducible_rng();
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let env = CanisterThresholdSigTestEnvironment::new(3, &mut rng);
                let (_, _, transcript) =
                    create_corrupted_transcript(&env, &mut rng, algorithm_for_key_id(&key_id));

                let crypto = env
                    .nodes
                    .filter_by_receivers(&transcript)
                    .next()
                    .unwrap()
                    .crypto();
                let (idkg_pool, complaint_handler) =
                    create_complaint_dependencies_with_crypto(pool_config, logger, Some(crypto));

                // Will attempt to create a complaint but fail since node ID of crypto and
                // complaint_handler are different
                let status = complaint_handler.load_transcript(&idkg_pool, &transcript);
                assert_matches!(status, TranscriptLoadStatus::Failure);
            })
        })
    }

    #[test]
    fn test_load_transcripts_with_complaints_and_openings_all_ecdsa_algorithms() {
        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            test_load_transcripts_with_complaints_and_openings(alg);
        }
    }

    #[test]
    fn test_load_transcripts_with_complaints_and_openings_all_schnorr_algorithms() {
        for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
            test_load_transcripts_with_complaints_and_openings(alg);
        }
    }

    // Tests that attempt of loading a corrupted transcript leads to complaints and
    // loading succeeds after openings are generated.
    fn test_load_transcripts_with_complaints_and_openings(algorithm: AlgorithmId) {
        let mut rng = reproducible_rng();
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let env = CanisterThresholdSigTestEnvironment::new(3, &mut rng);
                let (complainer, _, t) = create_corrupted_transcript(&env, &mut rng, algorithm);

                let mut components = env.nodes.filter_by_receivers(&t);

                let complainer_crypto = components.next().unwrap().crypto();
                let remaining_nodes: Vec<_> = components.collect();
                let (mut idkg_pool, complaint_handler) =
                    create_complaint_dependencies_with_crypto_and_node_id(
                        pool_config,
                        logger,
                        Some(complainer_crypto),
                        complainer,
                    );

                let status = complaint_handler.load_transcript(&idkg_pool, &t);
                let complaint = match status {
                    TranscriptLoadStatus::Complaints(mut complaints) if complaints.len() == 1 => {
                        let complaint = complaints.remove(0);
                        idkg_pool.apply(vec![IDkgChangeAction::AddToValidated(
                            IDkgMessage::Complaint(complaint.clone()),
                        )]);
                        complaint
                    }
                    _ => panic!("Unexpected status: {status:?}"),
                };

                // should fail due to insufficient openings
                let status = complaint_handler.load_transcript(&idkg_pool, &t);
                assert_matches!(status, TranscriptLoadStatus::Failure);

                for node in remaining_nodes {
                    let idkg_opening = node
                        .crypto()
                        .open_transcript(&t, complainer, &complaint.content.idkg_complaint)
                        .expect("Failed to open transcript with complaint");
                    let content = IDkgOpeningContent { idkg_opening };
                    let signature = node
                        .crypto()
                        .sign(&content, node.id(), t.registry_version)
                        .expect("Failed to sign opening content");
                    let opening = SignedIDkgOpening { content, signature };
                    idkg_pool.apply(vec![IDkgChangeAction::AddToValidated(
                        IDkgMessage::Opening(opening),
                    )]);
                }

                // should now be successful
                let status = complaint_handler.load_transcript(&idkg_pool, &t);
                assert_matches!(status, TranscriptLoadStatus::Success);
            })
        })
    }
}
