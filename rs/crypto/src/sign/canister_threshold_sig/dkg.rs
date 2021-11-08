use crate::sign::log_err;
use crate::CryptoComponentFatClient;
use ic_crypto_internal_csp::CryptoServiceProvider;
use ic_interfaces::crypto::IDkgTranscriptGenerator;
use ic_logger::{debug, new_logger};
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgComplaintVerificationError, IDkgDealingError, IDkgDealingVerificationError,
    IDkgOpeningVerificationError, IDkgTranscriptCreationError, IDkgTranscriptLoadError,
    IDkgTranscriptOpeningError, IDkgTranscriptVerificationError,
};
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgComplaint, IDkgDealing, IDkgOpening, IDkgTranscript, IDkgTranscriptId,
    IDkgTranscriptParams, VerifiedIDkgDealing,
};
use ic_types::NodeId;
use std::collections::BTreeMap;

mod mocks;

/// Currently, these are implemented with noop stubs,
/// while the true implementation is in progress.
impl<C: CryptoServiceProvider> IDkgTranscriptGenerator for CryptoComponentFatClient<C> {
    fn create_dealing(
        &self,
        params: &IDkgTranscriptParams,
    ) -> Result<IDkgDealing, IDkgDealingError> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "IDkgTranscriptGenerator",
            crypto.method_name => "create_dealing",
        );
        debug!(logger;
            crypto.description => "start",
        );
        let result = mocks::create_dealing(params);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn verify_dealing_public(
        &self,
        params: &IDkgTranscriptParams,
        dealing: &IDkgDealing,
    ) -> Result<(), IDkgDealingVerificationError> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "IDkgTranscriptGenerator",
            crypto.method_name => "verify_dealing_public",
        );
        debug!(logger;
            crypto.description => "start",
        );
        let result = mocks::verify_dealing_public(params, dealing);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn verify_dealing_private(
        &self,
        params: &IDkgTranscriptParams,
        dealing: &IDkgDealing,
    ) -> Result<(), IDkgDealingVerificationError> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "IDkgTranscriptGenerator",
            crypto.method_name => "verify_dealing_private",
        );
        debug!(logger;
            crypto.description => "start",
        );
        let result = mocks::verify_dealing_private(params, dealing);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn create_transcript(
        &self,
        params: &IDkgTranscriptParams,
        dealings: &BTreeMap<NodeId, VerifiedIDkgDealing>,
    ) -> Result<IDkgTranscript, IDkgTranscriptCreationError> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "IDkgTranscriptGenerator",
            crypto.method_name => "create_transcript",
        );
        debug!(logger;
            crypto.description => "start",
        );
        let result = mocks::create_transcript(params, dealings);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn verify_transcript(
        &self,
        transcript: &IDkgTranscript,
    ) -> Result<(), IDkgTranscriptVerificationError> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "IDkgTranscriptGenerator",
            crypto.method_name => "verify_transcript",
        );
        debug!(logger;
            crypto.description => "start",
        );
        let result = mocks::verify_transcript(transcript);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn load_transcript(
        &self,
        transcript: &IDkgTranscript,
    ) -> Result<Vec<IDkgComplaint>, IDkgTranscriptLoadError> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "IDkgTranscriptGenerator",
            crypto.method_name => "load_transcript",
        );
        debug!(logger;
            crypto.description => "start",
        );
        let result = mocks::load_transcript(transcript);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn verify_complaint(
        &self,
        transcript_id: IDkgTranscriptId,
        complainer: NodeId,
        complaint: &IDkgComplaint,
    ) -> Result<(), IDkgComplaintVerificationError> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "IDkgTranscriptGenerator",
            crypto.method_name => "verify_complaint",
        );
        debug!(logger;
            crypto.description => "start",
        );
        let result = mocks::verify_complaint(transcript_id, complainer, complaint);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn open_transcript(
        &self,
        transcript_id: IDkgTranscriptId,
        complaint: &IDkgComplaint,
    ) -> Result<IDkgOpening, IDkgTranscriptOpeningError> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "IDkgTranscriptGenerator",
            crypto.method_name => "open_transcript",
        );
        debug!(logger;
            crypto.description => "start",
        );
        let result = mocks::open_transcript(transcript_id, complaint);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn verify_opening(
        &self,
        transcript_id: IDkgTranscriptId,
        opener: NodeId,
        opening: &IDkgOpening,
        complaint: &IDkgComplaint,
    ) -> Result<(), IDkgOpeningVerificationError> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "IDkgTranscriptGenerator",
            crypto.method_name => "verify_opening",
        );
        debug!(logger;
            crypto.description => "start",
        );
        let result = mocks::verify_opening(transcript_id, opener, opening, complaint);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn load_transcript_with_openings(
        &self,
        transcript: IDkgTranscript,
        opening: BTreeMap<IDkgComplaint, BTreeMap<NodeId, IDkgOpening>>,
    ) -> Result<(), IDkgTranscriptLoadError> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "IDkgTranscriptGenerator",
            crypto.method_name => "load_transcript_with_openings",
        );
        debug!(logger;
            crypto.description => "start",
        );
        let result = mocks::load_transcript_with_openings(transcript, opening);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn retain_active_transcripts(&self, active_transcripts: &[IDkgTranscriptId]) {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "IDkgTranscriptGenerator",
            crypto.method_name => "retain_active_transcripts",
        );
        debug!(logger;
            crypto.description => "start",
        );
        mocks::retain_active_transcripts(active_transcripts);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => true,
            crypto.error => "none".to_string(),
        );
    }
}
