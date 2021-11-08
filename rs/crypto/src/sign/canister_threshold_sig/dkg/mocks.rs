use ic_crypto_internal_types::sign::canister_threshold_sig::{CspIDkgDealing, CspIDkgOpening};
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgCreateTranscriptError, IDkgLoadTranscriptError,
    IDkgLoadTranscriptWithOpeningsError, IDkgOpenTranscriptError, IDkgVerifyComplaintError,
    IDkgVerifyDealingPrivateError, IDkgVerifyDealingPublicError, IDkgVerifyOpeningError,
    IDkgVerifyTranscriptError,
};
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgComplaint, IDkgDealing, IDkgMaskedTranscriptOrigin, IDkgMultiSignedDealing, IDkgOpening,
    IDkgTranscript, IDkgTranscriptParams, IDkgTranscriptType,
};
use ic_types::crypto::AlgorithmId;
use ic_types::NodeId;
use std::collections::BTreeMap;

pub fn create_dealing(
    _params: &IDkgTranscriptParams,
) -> Result<IDkgDealing, IDkgCreateDealingError> {
    Ok(IDkgDealing {
        internal_dealing: CspIDkgDealing {},
    })
}

pub fn verify_dealing_public(
    _params: &IDkgTranscriptParams,
    _dealing: &IDkgDealing,
) -> Result<(), IDkgVerifyDealingPublicError> {
    Ok(())
}

pub fn verify_dealing_private(
    _params: &IDkgTranscriptParams,
    _dealing: &IDkgDealing,
) -> Result<(), IDkgVerifyDealingPrivateError> {
    Ok(())
}

pub fn create_transcript(
    params: &IDkgTranscriptParams,
    dealings: &BTreeMap<NodeId, IDkgMultiSignedDealing>,
) -> Result<IDkgTranscript, IDkgCreateTranscriptError> {
    Ok(IDkgTranscript {
        transcript_id: params.transcript_id,
        receivers: params.receivers.clone(),
        registry_version: params.registry_version,
        verified_dealings: dealings.clone(),
        transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
    })
}

pub fn verify_transcript(
    _params: &IDkgTranscriptParams,
    _transcript: &IDkgTranscript,
) -> Result<(), IDkgVerifyTranscriptError> {
    Ok(())
}

pub fn load_transcript(
    _transcript: &IDkgTranscript,
) -> Result<Vec<IDkgComplaint>, IDkgLoadTranscriptError> {
    Ok(vec![])
}

pub fn verify_complaint(
    _transcript: &IDkgTranscript,
    _complainer: NodeId,
    _complaint: &IDkgComplaint,
) -> Result<(), IDkgVerifyComplaintError> {
    Ok(())
}

pub fn open_transcript(
    transcript: &IDkgTranscript,
    complaint: &IDkgComplaint,
) -> Result<IDkgOpening, IDkgOpenTranscriptError> {
    Ok(IDkgOpening {
        transcript_id: transcript.transcript_id,
        dealer_id: complaint.dealer_id,
        internal_opening: CspIDkgOpening {},
    })
}

pub fn verify_opening(
    _transcript: &IDkgTranscript,
    _opener: NodeId,
    _opening: &IDkgOpening,
    _complaint: &IDkgComplaint,
) -> Result<(), IDkgVerifyOpeningError> {
    Ok(())
}

pub fn load_transcript_with_openings(
    _transcript: IDkgTranscript,
    _openings: BTreeMap<IDkgComplaint, BTreeMap<NodeId, IDkgOpening>>,
) -> Result<(), IDkgLoadTranscriptWithOpeningsError> {
    Ok(())
}

pub fn retain_active_transcripts(_active_transcripts: &[IDkgTranscript]) {}
