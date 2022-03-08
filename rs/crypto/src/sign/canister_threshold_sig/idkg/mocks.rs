use ic_types::crypto::canister_threshold_sig::error::IDkgVerifyOpeningError;
use ic_types::crypto::canister_threshold_sig::idkg::{IDkgComplaint, IDkgOpening, IDkgTranscript};
use ic_types::NodeId;

pub fn verify_opening(
    _transcript: &IDkgTranscript,
    _opener: NodeId,
    _opening: &IDkgOpening,
    _complaint: &IDkgComplaint,
) -> Result<(), IDkgVerifyOpeningError> {
    Ok(())
}

pub fn retain_active_transcripts(_active_transcripts: &[IDkgTranscript]) {}
