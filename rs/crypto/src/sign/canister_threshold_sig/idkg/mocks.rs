use ic_types::crypto::canister_threshold_sig::error::{
    IDkgVerifyDealingPublicError, IDkgVerifyOpeningError,
};
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgComplaint, IDkgDealing, IDkgOpening, IDkgTranscript, IDkgTranscriptParams,
};
use ic_types::NodeId;

pub fn verify_dealing_public(
    _params: &IDkgTranscriptParams,
    _dealing: &IDkgDealing,
) -> Result<(), IDkgVerifyDealingPublicError> {
    Ok(())
}

pub fn verify_opening(
    _transcript: &IDkgTranscript,
    _opener: NodeId,
    _opening: &IDkgOpening,
    _complaint: &IDkgComplaint,
) -> Result<(), IDkgVerifyOpeningError> {
    Ok(())
}

pub fn retain_active_transcripts(_active_transcripts: &[IDkgTranscript]) {}
