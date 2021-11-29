use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgCreateTranscriptError, IDkgLoadTranscriptError,
    IDkgLoadTranscriptWithOpeningsError, IDkgOpenTranscriptError, IDkgVerifyComplaintError,
    IDkgVerifyDealingPrivateError, IDkgVerifyDealingPublicError, IDkgVerifyOpeningError,
    IDkgVerifyTranscriptError,
};
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgComplaint, IDkgDealing, IDkgMaskedTranscriptOrigin, IDkgMultiSignedDealing, IDkgOpening,
    IDkgTranscript, IDkgTranscriptOperation, IDkgTranscriptParams, IDkgTranscriptType,
    IDkgUnmaskedTranscriptOrigin,
};
use ic_types::{crypto::AlgorithmId, NodeId};
use std::collections::BTreeMap;

#[allow(dead_code)]
pub fn create_dealing(
    params: &IDkgTranscriptParams,
    self_id: &NodeId,
) -> Result<IDkgDealing, IDkgCreateDealingError> {
    Ok(IDkgDealing {
        transcript_id: params.transcript_id,
        dealer_id: *self_id,
        internal_dealing_raw: vec![],
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

pub fn verify_transcript(
    _params: &IDkgTranscriptParams,
    _transcript: &IDkgTranscript,
) -> Result<(), IDkgVerifyTranscriptError> {
    Ok(())
}

#[allow(dead_code)]
pub fn create_transcript(
    params: &IDkgTranscriptParams,
    dealings: &BTreeMap<NodeId, IDkgMultiSignedDealing>,
) -> Result<IDkgTranscript, IDkgCreateTranscriptError> {
    let dealings_by_index = dealings
        .iter()
        .map(|(id, d)| (params.dealers.position(*id).expect("mock"), d.clone()))
        .collect();

    Ok(IDkgTranscript {
        transcript_id: params.transcript_id,
        receivers: params.receivers.clone(),
        registry_version: params.registry_version,
        verified_dealings: dealings_by_index,
        transcript_type: match &params.operation_type {
            IDkgTranscriptOperation::Random => {
                IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random)
            }
            IDkgTranscriptOperation::ReshareOfMasked(x) => IDkgTranscriptType::Unmasked(
                IDkgUnmaskedTranscriptOrigin::ReshareMasked(x.transcript_id),
            ),
            IDkgTranscriptOperation::ReshareOfUnmasked(x) => IDkgTranscriptType::Unmasked(
                IDkgUnmaskedTranscriptOrigin::ReshareUnmasked(x.transcript_id),
            ),
            IDkgTranscriptOperation::UnmaskedTimesMasked(x, y) => IDkgTranscriptType::Masked(
                IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(x.transcript_id, y.transcript_id),
            ),
        },
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    })
}

#[allow(dead_code)]
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
        internal_opening_raw: vec![],
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
