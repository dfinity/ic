use ic_crypto_internal_types::sign::canister_threshold_sig::{CspIDkgDealing, CspIDkgOpening};
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgComplaintVerificationError, IDkgDealingError, IDkgDealingVerificationError,
    IDkgOpeningVerificationError, IDkgTranscriptCreationError, IDkgTranscriptLoadError,
    IDkgTranscriptOpeningError, IDkgTranscriptVerificationError,
};
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgComplaint, IDkgDealing, IDkgMaskedTranscriptOrigin, IDkgOpening, IDkgTranscript,
    IDkgTranscriptId, IDkgTranscriptParams, IDkgTranscriptType, VerifiedIDkgDealing,
};
use ic_types::NodeId;
use std::collections::BTreeMap;

pub fn create_dealing(_params: &IDkgTranscriptParams) -> Result<IDkgDealing, IDkgDealingError> {
    Ok(IDkgDealing {
        internal_dealing: CspIDkgDealing {},
    })
}

pub fn verify_dealing_public(
    _params: &IDkgTranscriptParams,
    _dealing: &IDkgDealing,
) -> Result<(), IDkgDealingVerificationError> {
    Ok(())
}

pub fn verify_dealing_private(
    _params: &IDkgTranscriptParams,
    _dealing: &IDkgDealing,
) -> Result<(), IDkgDealingVerificationError> {
    Ok(())
}

pub fn create_transcript(
    params: &IDkgTranscriptParams,
    dealings: &BTreeMap<NodeId, VerifiedIDkgDealing>,
) -> Result<IDkgTranscript, IDkgTranscriptCreationError> {
    Ok(IDkgTranscript {
        transcript_id: params.transcript_id,
        receivers: params.receivers.clone(),
        registry_version: params.registry_version,
        verified_dealings: dealings.clone(),
        transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
    })
}

pub fn verify_transcript(
    _transcript: &IDkgTranscript,
) -> Result<(), IDkgTranscriptVerificationError> {
    Ok(())
}

pub fn load_transcript(
    _transcript: &IDkgTranscript,
) -> Result<Vec<IDkgComplaint>, IDkgTranscriptLoadError> {
    Ok(vec![])
}

pub fn verify_complaint(
    _transcript_id: IDkgTranscriptId,
    _complainer: NodeId,
    _complaint: &IDkgComplaint,
) -> Result<(), IDkgComplaintVerificationError> {
    Ok(())
}

pub fn open_transcript(
    transcript_id: IDkgTranscriptId,
    complaint: &IDkgComplaint,
) -> Result<IDkgOpening, IDkgTranscriptOpeningError> {
    Ok(IDkgOpening {
        transcript_id,
        dealer_id: complaint.dealer_id,
        internal_opening: CspIDkgOpening {},
    })
}

pub fn verify_opening(
    _transcript_id: IDkgTranscriptId,
    _opener: NodeId,
    _opening: &IDkgOpening,
    _complaint: &IDkgComplaint,
) -> Result<(), IDkgOpeningVerificationError> {
    Ok(())
}

pub fn load_transcript_with_openings(
    _transcript: IDkgTranscript,
    _opening: BTreeMap<IDkgComplaint, BTreeMap<NodeId, IDkgOpening>>,
) -> Result<(), IDkgTranscriptLoadError> {
    Ok(())
}

pub fn retain_active_transcripts(_active_transcripts: &[IDkgTranscriptId]) {}
