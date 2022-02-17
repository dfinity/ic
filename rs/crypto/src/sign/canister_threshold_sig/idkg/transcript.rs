//! Implementations of IDkgProtocol related to transcripts
use crate::sign::canister_threshold_sig::idkg::utils::get_mega_pubkey;
use crate::sign::multi_sig::MultiSigVerifierInternal;
use ic_crypto_internal_csp::api::CspIDkgProtocol;
use ic_crypto_internal_csp::api::CspSigner;
use ic_crypto_internal_threshold_sig_ecdsa::{
    CommitmentOpening, IDkgComplaintInternal, IDkgDealingInternal, IDkgTranscriptInternal,
    IDkgTranscriptOperationInternal,
};
use ic_interfaces::registry::RegistryClient;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateTranscriptError, IDkgLoadTranscriptError,
};
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgComplaint, IDkgDealers, IDkgMultiSignedDealing, IDkgOpening, IDkgReceivers, IDkgTranscript,
    IDkgTranscriptOperation, IDkgTranscriptParams, IDkgTranscriptType,
};
use ic_types::{NodeId, NodeIndex, RegistryVersion};
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::sync::Arc;

pub fn create_transcript<C: CspIDkgProtocol + CspSigner>(
    csp_client: &C,
    registry: &Arc<dyn RegistryClient>,
    params: &IDkgTranscriptParams,
    dealings: &BTreeMap<NodeId, IDkgMultiSignedDealing>,
) -> Result<IDkgTranscript, IDkgCreateTranscriptError> {
    ensure_sufficient_dealings_collected(params, dealings)?;
    ensure_dealers_allowed_by_params(params, dealings)?;
    ensure_signers_allowed_by_params(params, dealings)?;
    ensure_sufficient_signatures_collected(params, dealings)?;
    verify_multisignatures(csp_client, registry, dealings, params.registry_version())?;

    let internal_dealings = internal_dealings_by_index_from_dealings(
        dealings,
        params.dealers(),
        params.operation_type(),
    )?;

    let internal_operation_type =
        IDkgTranscriptOperationInternal::try_from(params.operation_type()).map_err(|e| {
            IDkgCreateTranscriptError::SerializationError {
                internal_error: format!("{:?}", e),
            }
        })?;

    let internal_transcript = csp_client.idkg_create_transcript(
        params.algorithm_id(),
        params.reconstruction_threshold(),
        &internal_dealings,
        &internal_operation_type,
    )?;

    let internal_transcript_raw = internal_transcript.serialize().map_err(|e| {
        IDkgCreateTranscriptError::SerializationError {
            internal_error: format!("{:?}", e),
        }
    })?;

    let transcript_type = IDkgTranscriptType::from(params.operation_type());

    let dealings_by_index =
        dealings_by_index_from_dealings(dealings, params.dealers(), params.operation_type())?;

    Ok(IDkgTranscript {
        transcript_id: params.transcript_id(),
        receivers: params.receivers().clone(),
        registry_version: params.registry_version(),
        verified_dealings: dealings_by_index,
        transcript_type,
        algorithm_id: params.algorithm_id(),
        internal_transcript_raw,
    })
}

pub fn load_transcript<C: CspIDkgProtocol>(
    csp_client: &C,
    self_node_id: &NodeId,
    registry: &Arc<dyn RegistryClient>,
    transcript: &IDkgTranscript,
) -> Result<Vec<IDkgComplaint>, IDkgLoadTranscriptError> {
    let self_index = match transcript.receivers.position(*self_node_id) {
        Some(index) => index,
        None => {
            return Ok(vec![]); // This is not a receiver: nothing to do.
        }
    };

    let self_mega_pubkey = get_mega_pubkey(self_node_id, registry, transcript.registry_version)?;

    let internal_dealings =
        internal_dealings_from_verified_dealings(&transcript.verified_dealings)?;
    let internal_transcript = IDkgTranscriptInternal::try_from(transcript).map_err(|e| {
        IDkgLoadTranscriptError::SerializationError {
            internal_error: format!("{:?}", e),
        }
    })?;
    let internal_complaints = csp_client.idkg_load_transcript(
        &internal_dealings,
        &transcript.context_data(),
        self_index,
        &self_mega_pubkey,
        &internal_transcript,
    )?;
    let complaints = complaints_from_internal_complaints(&internal_complaints, transcript)?;

    Ok(complaints)
}

pub fn load_transcript_with_openings<C: CspIDkgProtocol>(
    csp_client: &C,
    self_node_id: &NodeId,
    registry: &Arc<dyn RegistryClient>,
    transcript: &IDkgTranscript,
    openings: &BTreeMap<IDkgComplaint, BTreeMap<NodeId, IDkgOpening>>,
) -> Result<(), IDkgLoadTranscriptError> {
    let self_index = match transcript.receivers.position(*self_node_id) {
        Some(index) => index,
        None => {
            return Ok(()); // This is not a receiver: nothing to do.
        }
    };
    ensure_sufficient_openings(openings, transcript)?;
    ensure_matching_transcript_ids_and_dealer_ids(openings, transcript)?;

    let self_mega_pubkey = get_mega_pubkey(self_node_id, registry, transcript.registry_version)?;

    let internal_dealings =
        internal_dealings_from_verified_dealings(&transcript.verified_dealings)?;
    let internal_transcript = IDkgTranscriptInternal::try_from(transcript).map_err(|e| {
        IDkgLoadTranscriptError::SerializationError {
            internal_error: format!("{:?}", e),
        }
    })?;

    let mut internal_openings = BTreeMap::new();
    for (complaint, openings_by_opener_id) in openings {
        let mut internal_openings_by_opener_index = BTreeMap::new();
        for (opener_id, opening) in openings_by_opener_id {
            let opener_index = transcript.receivers.position(*opener_id).ok_or_else(|| {
                IDkgLoadTranscriptError::InvalidArguments {
                    internal_error: format!(
                        "invalid opener: node with ID {:?} is not a receiver",
                        *opener_id
                    ),
                }
            })?;
            let internal_opening = CommitmentOpening::try_from(opening).map_err(|e| {
                IDkgLoadTranscriptError::SerializationError {
                    internal_error: format!("{:?}", e),
                }
            })?;
            internal_openings_by_opener_index.insert(opener_index, internal_opening);
        }
        let dealer_index = transcript
            .index_for_dealer_id(complaint.dealer_id)
            .ok_or_else(|| IDkgLoadTranscriptError::InvalidArguments {
                internal_error: format!(
                    "invalid complaint: node with ID {:?} is not a dealer",
                    complaint.dealer_id
                ),
            })?;
        internal_openings.insert(dealer_index, internal_openings_by_opener_index);
    }

    csp_client.idkg_load_transcript_with_openings(
        &internal_dealings,
        &internal_openings,
        &transcript.context_data(),
        self_index,
        &self_mega_pubkey,
        &internal_transcript,
    )
}

fn ensure_sufficient_dealings_collected(
    params: &IDkgTranscriptParams,
    dealings: &BTreeMap<NodeId, IDkgMultiSignedDealing>,
) -> Result<(), IDkgCreateTranscriptError> {
    if dealings.len() < params.collection_threshold().get() as usize {
        Err(IDkgCreateTranscriptError::UnsatisfiedCollectionThreshold {
            threshold: params.collection_threshold().get(),
            dealing_count: dealings.len(),
        })
    } else {
        Ok(())
    }
}

fn ensure_dealers_allowed_by_params(
    params: &IDkgTranscriptParams,
    dealings: &BTreeMap<NodeId, IDkgMultiSignedDealing>,
) -> Result<(), IDkgCreateTranscriptError> {
    for id in dealings.keys() {
        if !params.dealers().get().contains(id) {
            return Err(IDkgCreateTranscriptError::DealerNotAllowed { node_id: *id });
        }
    }

    Ok(())
}

fn ensure_signers_allowed_by_params(
    params: &IDkgTranscriptParams,
    dealings: &BTreeMap<NodeId, IDkgMultiSignedDealing>,
) -> Result<(), IDkgCreateTranscriptError> {
    for dealing in dealings.values() {
        for signer in &dealing.signers {
            if !params.receivers().get().contains(signer) {
                return Err(IDkgCreateTranscriptError::SignerNotAllowed { node_id: *signer });
            }
        }
    }

    Ok(())
}

fn ensure_sufficient_signatures_collected(
    params: &IDkgTranscriptParams,
    dealings: &BTreeMap<NodeId, IDkgMultiSignedDealing>,
) -> Result<(), IDkgCreateTranscriptError> {
    for (dealer, dealing) in dealings {
        if dealing.signers.len() < params.verification_threshold().get() as usize {
            return Err(
                IDkgCreateTranscriptError::UnsatisfiedVerificationThreshold {
                    threshold: params.verification_threshold().get(),
                    signature_count: dealing.signers.len(),
                    dealer_id: *dealer,
                },
            );
        }
    }

    Ok(())
}

fn verify_multisignatures<C: CspIDkgProtocol + CspSigner>(
    csp_client: &C,
    registry: &Arc<dyn RegistryClient>,
    dealings: &BTreeMap<NodeId, IDkgMultiSignedDealing>,
    registry_version: RegistryVersion,
) -> Result<(), IDkgCreateTranscriptError> {
    for dealing in dealings.values() {
        MultiSigVerifierInternal::verify_multi_sig_combined(
            csp_client,
            Arc::clone(registry),
            &dealing.signature,
            &dealing.dealing,
            dealing.signers.clone(),
            registry_version,
        )
        .map_err(|e| IDkgCreateTranscriptError::InvalidMultisignature { crypto_error: e })?;
    }

    Ok(())
}

/// Convert IDkgDealings to IDkgDealingInternals, and re-key the map to use
/// indices rather than ids
///
/// The indices are such that they allow the previous transcript(s) (if any)
/// to be properly recombined (i.e. the indices are for the previous sharing,
/// if this is a resharing or multiplication).
fn internal_dealings_by_index_from_dealings(
    dealings: &BTreeMap<NodeId, IDkgMultiSignedDealing>,
    dealers: &IDkgDealers,
    op_type: &IDkgTranscriptOperation,
) -> Result<BTreeMap<NodeIndex, IDkgDealingInternal>, IDkgCreateTranscriptError> {
    fn deserialize_internal_dealing(
        raw: &[u8],
    ) -> Result<IDkgDealingInternal, IDkgCreateTranscriptError> {
        IDkgDealingInternal::deserialize(raw).map_err(|e| {
            IDkgCreateTranscriptError::SerializationError {
                internal_error: format!("{:?}", e),
            }
        })
    }

    dealings
        .iter()
        .map(|(id, d)| {
            let internal_dealing =
                deserialize_internal_dealing(&d.dealing.idkg_dealing.internal_dealing_raw)?;
            let index = id_to_index(*id, dealers, op_type)?;
            Ok((index, internal_dealing))
        })
        .collect()
}

/// Convert a NodeId to the correct NodeIndex, based on the transcript operation
///
/// The NodeIndex is such that it allows the previous transcript(s) (if any)
/// to be properly recombined (i.e. the indices are for the previous sharing,
/// if this is a resharing or multiplication).
fn id_to_index(
    id: NodeId,
    dealers: &IDkgDealers,
    op_type: &IDkgTranscriptOperation,
) -> Result<NodeIndex, IDkgCreateTranscriptError> {
    fn dealer_id_to_index(
        id: NodeId,
        dealers: &IDkgDealers,
    ) -> Result<NodeIndex, IDkgCreateTranscriptError> {
        dealers
            .position(id)
            .ok_or(IDkgCreateTranscriptError::DealerNotAllowed { node_id: id })
        // this should already have been checked by
        // `ensure_dealers_allowed_by_params`
    }

    fn receiver_id_to_index(
        id: NodeId,
        receivers: &IDkgReceivers,
    ) -> Result<NodeIndex, IDkgCreateTranscriptError> {
        receivers
            .position(id)
            .ok_or(IDkgCreateTranscriptError::DealerNotAllowed { node_id: id })
        // this should already have been checked by
        // IDkgTranscriptParams::new
    }

    match op_type {
        IDkgTranscriptOperation::Random => dealer_id_to_index(id, dealers),
        IDkgTranscriptOperation::ReshareOfMasked(transcript) => {
            receiver_id_to_index(id, &transcript.receivers)
        }
        IDkgTranscriptOperation::ReshareOfUnmasked(transcript) => {
            receiver_id_to_index(id, &transcript.receivers)
        }
        IDkgTranscriptOperation::UnmaskedTimesMasked(transcript, _) => {
            // transcript_1.receivers == transcript_2.receivers already checked by
            // IDkgTranscriptParams::new
            receiver_id_to_index(id, &transcript.receivers)
        }
    }
}

/// Re-key the map to use indices rather than ids
///
/// The indices are such that they allow the previous transcript(s) (if any)
/// to be properly recombined (i.e. the indices are for the previous sharing,
/// if this is a resharing or multiplication).
fn dealings_by_index_from_dealings(
    dealings: &BTreeMap<NodeId, IDkgMultiSignedDealing>,
    dealers: &IDkgDealers,
    op_type: &IDkgTranscriptOperation,
) -> Result<BTreeMap<NodeIndex, IDkgMultiSignedDealing>, IDkgCreateTranscriptError> {
    dealings
        .iter()
        .map(|(id, d)| {
            let index = id_to_index(*id, dealers, op_type)?;
            Ok((index, d.clone()))
        })
        .collect()
}

fn internal_dealings_from_verified_dealings(
    verified_dealings: &BTreeMap<NodeIndex, IDkgMultiSignedDealing>,
) -> Result<BTreeMap<NodeIndex, IDkgDealingInternal>, IDkgLoadTranscriptError> {
    verified_dealings
        .iter()
        .map(|(index, signed_dealing)| {
            let dealing = IDkgDealingInternal::try_from(signed_dealing).map_err(|e| {
                IDkgLoadTranscriptError::SerializationError {
                    internal_error: format!("{:?}", e),
                }
            })?;
            Ok((*index, dealing))
        })
        .collect()
}

/// Builds IDkgComplaint's from IDkgComplaintInternal's
/// (which translates a dealer's NodeIndex to a NodeId)
fn complaints_from_internal_complaints(
    internal_complaints: &BTreeMap<NodeIndex, IDkgComplaintInternal>,
    transcript: &IDkgTranscript,
) -> Result<Vec<IDkgComplaint>, IDkgLoadTranscriptError> {
    internal_complaints
        .iter()
        .map(|(dealer_index, internal_complaint)| {
            let internal_complaint_raw = internal_complaint.serialize().map_err(|e| {
                IDkgLoadTranscriptError::SerializationError {
                    internal_error: format!("{:?}", e),
                }
            })?;
            let dealer_id = transcript
                .dealer_id_for_index(*dealer_index)
                .ok_or_else(|| IDkgLoadTranscriptError::InternalError {
                    internal_error: format!("failed to get dealer ID for index {}", dealer_index),
                })?;

            Ok(IDkgComplaint {
                transcript_id: transcript.transcript_id,
                dealer_id,
                internal_complaint_raw,
            })
        })
        .collect()
}

fn ensure_sufficient_openings(
    openings: &BTreeMap<IDkgComplaint, BTreeMap<NodeId, IDkgOpening>>,
    transcript: &IDkgTranscript,
) -> Result<(), IDkgLoadTranscriptError> {
    let reconstruction_threshold_usize =
        usize::try_from(transcript.reconstruction_threshold().get()).map_err(|e| {
            IDkgLoadTranscriptError::InternalError {
                internal_error: format!(
                    "failed to convert reconstruction threshold to usize: {:?}",
                    e
                ),
            }
        })?;
    if openings.values().len() < reconstruction_threshold_usize {
        return Err(IDkgLoadTranscriptError::InvalidArguments {
            internal_error: format!(
                "insufficient number of openings: got {}, but required {}",
                openings.len(),
                reconstruction_threshold_usize
            ),
        });
    }
    Ok(())
}

fn ensure_matching_transcript_ids_and_dealer_ids(
    openings: &BTreeMap<IDkgComplaint, BTreeMap<NodeId, IDkgOpening>>,
    transcript: &IDkgTranscript,
) -> Result<(), IDkgLoadTranscriptError> {
    for (complaint, openings_by_opener_id) in openings {
        if complaint.transcript_id != transcript.transcript_id {
            return Err(IDkgLoadTranscriptError::InvalidArguments {
                internal_error: format!(
                    "mismatching transcript IDs in complaint ({:?}) and transcript ({:?})",
                    complaint.transcript_id, transcript.transcript_id
                ),
            });
        }
        for opening in openings_by_opener_id.values() {
            if opening.transcript_id != transcript.transcript_id {
                return Err(IDkgLoadTranscriptError::InvalidArguments {
                    internal_error: format!(
                        "mismatching transcript IDs in opening ({:?}) and transcript ({:?})",
                        opening.transcript_id, transcript.transcript_id
                    ),
                });
            }
            if opening.dealer_id != complaint.dealer_id {
                return Err(IDkgLoadTranscriptError::InvalidArguments {
                    internal_error: format!(
                        "mismatching dealer IDs in opening ({:?}) and the complaint ({:?})",
                        opening.dealer_id, complaint.dealer_id
                    ),
                });
            }
        }
    }
    Ok(())
}
