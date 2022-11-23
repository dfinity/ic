use crate::sign::{get_log_id, log_err, log_ok_content};
use crate::CryptoComponentFatClient;
use ic_crypto_internal_csp::CryptoServiceProvider;
use ic_interfaces::crypto::IDkgProtocol;
use ic_logger::{debug, new_logger};
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgCreateTranscriptError, IDkgLoadTranscriptError,
    IDkgOpenTranscriptError, IDkgRetainThresholdKeysError, IDkgVerifyComplaintError,
    IDkgVerifyDealingPrivateError, IDkgVerifyDealingPublicError, IDkgVerifyInitialDealingsError,
    IDkgVerifyOpeningError, IDkgVerifyTranscriptError,
};
use ic_types::crypto::canister_threshold_sig::idkg::{
    BatchSignedIDkgDealing, IDkgComplaint, IDkgDealing, IDkgOpening, IDkgTranscript,
    IDkgTranscriptId, IDkgTranscriptParams, InitialIDkgDealings, SignedIDkgDealing,
};
use ic_types::NodeId;
use std::collections::{BTreeMap, BTreeSet, HashSet};

mod complaint;
mod dealing;
mod retain_active_keys;
mod transcript;
mod utils;

#[cfg(test)]
mod tests;

use ic_crypto_internal_logmon::metrics::{MetricsDomain, MetricsResult, MetricsScope};
pub use utils::{
    fetch_idkg_dealing_encryption_public_key_from_registry, get_mega_pubkey,
    MegaKeyFromRegistryError,
};

/// Currently, these are implemented with noop stubs,
/// while the true implementation is in progress.
impl<C: CryptoServiceProvider> IDkgProtocol for CryptoComponentFatClient<C> {
    fn create_dealing(
        &self,
        params: &IDkgTranscriptParams,
    ) -> Result<IDkgDealing, IDkgCreateDealingError> {
        let log_id = get_log_id(&self.logger, module_path!());
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "IDkgProtocol",
            crypto.method_name => "create_dealing",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_config => format!("{:?}", params),
        );
        let start_time = self.metrics.now();
        let result =
            dealing::create_dealing(&self.csp, &self.node_id, &self.registry_client, params);
        self.metrics.observe_duration_seconds(
            MetricsDomain::IDkgProtocol,
            MetricsScope::Full,
            "create_dealing",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
            crypto.dkg_dealing => log_ok_content(&result),
        );
        result
    }

    fn verify_dealing_public(
        &self,
        params: &IDkgTranscriptParams,
        signed_dealing: &SignedIDkgDealing,
    ) -> Result<(), IDkgVerifyDealingPublicError> {
        let log_id = get_log_id(&self.logger, module_path!());
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "IDkgProtocol",
            crypto.method_name => "verify_dealing_public",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_config => format!("{:?}", params),
            crypto.dkg_dealing => format!("{:?}", signed_dealing),
        );
        let start_time = self.metrics.now();
        let result = dealing::verify_dealing_public(
            &self.csp,
            &self.registry_client,
            params,
            signed_dealing,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::IDkgProtocol,
            MetricsScope::Full,
            "verify_dealing_public",
            MetricsResult::from(&result),
            start_time,
        );
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
        signed_dealing: &SignedIDkgDealing,
    ) -> Result<(), IDkgVerifyDealingPrivateError> {
        let log_id = get_log_id(&self.logger, module_path!());
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "IDkgProtocol",
            crypto.method_name => "verify_dealing_private",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_config => format!("{:?}", params),
            crypto.dkg_dealing => format!("{:?}", signed_dealing),
        );
        let start_time = self.metrics.now();
        let result = dealing::verify_dealing_private(
            &self.csp,
            &self.node_id,
            &self.registry_client,
            params,
            signed_dealing,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::IDkgProtocol,
            MetricsScope::Full,
            "verify_dealing_private",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn verify_initial_dealings(
        &self,
        params: &IDkgTranscriptParams,
        initial_dealings: &InitialIDkgDealings,
    ) -> Result<(), IDkgVerifyInitialDealingsError> {
        let log_id = get_log_id(&self.logger, module_path!());
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "IDkgProtocol",
            crypto.method_name => "verify_initial_dealings",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_config => format!("{:?}", params),
            crypto.dkg_dealing => format!("{:?}", initial_dealings),
        );
        let start_time = self.metrics.now();
        let result = dealing::verify_initial_dealings(
            &self.csp,
            &self.registry_client,
            params,
            initial_dealings,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::IDkgProtocol,
            MetricsScope::Full,
            "verify_initial_dealings",
            MetricsResult::from(&result),
            start_time,
        );
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
        dealings: &BTreeMap<NodeId, BatchSignedIDkgDealing>,
    ) -> Result<IDkgTranscript, IDkgCreateTranscriptError> {
        let log_id = get_log_id(&self.logger, module_path!());
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "IDkgProtocol",
            crypto.method_name => "create_transcript",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_config => format!("{:?}", params),
            crypto.dkg_dealing => format!("dealings: {{ {:?} }}", dealings.keys()),
        );
        let start_time = self.metrics.now();
        let result =
            transcript::create_transcript(&self.csp, &self.registry_client, params, dealings);
        self.metrics.observe_duration_seconds(
            MetricsDomain::IDkgProtocol,
            MetricsScope::Full,
            "create_transcript",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
            crypto.dkg_transcript => log_ok_content(&result),
        );
        result
    }

    fn verify_transcript(
        &self,
        params: &IDkgTranscriptParams,
        transcript: &IDkgTranscript,
    ) -> Result<(), IDkgVerifyTranscriptError> {
        let log_id = get_log_id(&self.logger, module_path!());
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "IDkgProtocol",
            crypto.method_name => "verify_transcript",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_config => format!("{:?}", params),
            crypto.dkg_transcript => format!("{:?}", transcript),
        );
        let start_time = self.metrics.now();
        let result =
            transcript::verify_transcript(&self.csp, &self.registry_client, params, transcript);
        self.metrics.observe_duration_seconds(
            MetricsDomain::IDkgProtocol,
            MetricsScope::Full,
            "verify_transcript",
            MetricsResult::from(&result),
            start_time,
        );
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
    ) -> Result<Vec<IDkgComplaint>, IDkgLoadTranscriptError> {
        let log_id = get_log_id(&self.logger, module_path!());
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "IDkgProtocol",
            crypto.method_name => "load_transcript",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_transcript => format!("{:?}", transcript),
        );
        let start_time = self.metrics.now();
        let result = transcript::load_transcript(
            &self.csp,
            &self.node_id,
            &self.registry_client,
            transcript,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::IDkgProtocol,
            MetricsScope::Full,
            "load_transcript",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
            crypto.complaint => if let Ok(ref content) = result {
                Some(format!("{:?}", content))
            } else {
                None
            },
        );
        result
    }

    fn verify_complaint(
        &self,
        transcript: &IDkgTranscript,
        complainer_id: NodeId,
        complaint: &IDkgComplaint,
    ) -> Result<(), IDkgVerifyComplaintError> {
        let log_id = get_log_id(&self.logger, module_path!());
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "IDkgProtocol",
            crypto.method_name => "verify_complaint",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_transcript => format!("{:?}", transcript),
            crypto.complainer => format!("{:?}", complainer_id),
            crypto.complaint => format!("{:?}", complaint),
        );
        let start_time = self.metrics.now();
        let result = complaint::verify_complaint(
            &self.csp,
            &self.registry_client,
            transcript,
            complaint,
            complainer_id,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::IDkgProtocol,
            MetricsScope::Full,
            "verify_complaint",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn open_transcript(
        &self,
        transcript: &IDkgTranscript,
        complainer_id: NodeId,
        complaint: &IDkgComplaint,
    ) -> Result<IDkgOpening, IDkgOpenTranscriptError> {
        let log_id = get_log_id(&self.logger, module_path!());
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "IDkgProtocol",
            crypto.method_name => "open_transcript",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_transcript => format!("{:?}", transcript),
            crypto.complainer => format!("{:?}", complainer_id),
            crypto.complaint => format!("{:?}", complaint),
        );
        let start_time = self.metrics.now();
        let result = transcript::open_transcript(
            &self.csp,
            &self.node_id,
            &self.registry_client,
            transcript,
            complainer_id,
            complaint,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::IDkgProtocol,
            MetricsScope::Full,
            "open_transcript",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
            crypto.opening => log_ok_content(&result),
        );
        result
    }

    fn verify_opening(
        &self,
        transcript: &IDkgTranscript,
        opener: NodeId,
        opening: &IDkgOpening,
        complaint: &IDkgComplaint,
    ) -> Result<(), IDkgVerifyOpeningError> {
        let log_id = get_log_id(&self.logger, module_path!());
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "IDkgProtocol",
            crypto.method_name => "verify_opening",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_transcript => format!("{:?}", transcript),
            crypto.opener => format!("{:?}", opener),
            crypto.opening => format!("{:?}", opening),
            crypto.complaint => format!("{:?}", complaint),
        );
        let start_time = self.metrics.now();
        let result = transcript::verify_opening(&self.csp, transcript, opener, opening, complaint);
        self.metrics.observe_duration_seconds(
            MetricsDomain::IDkgProtocol,
            MetricsScope::Full,
            "verify_opening",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn load_transcript_with_openings(
        &self,
        transcript: &IDkgTranscript,
        openings: &BTreeMap<IDkgComplaint, BTreeMap<NodeId, IDkgOpening>>,
    ) -> Result<(), IDkgLoadTranscriptError> {
        let log_id = get_log_id(&self.logger, module_path!());
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "IDkgProtocol",
            crypto.method_name => "load_transcript_with_openings",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_transcript => format!("{:?}", transcript),
            crypto.opening => format!("{:?}", openings),
        );
        let start_time = self.metrics.now();
        let result = transcript::load_transcript_with_openings(
            &self.csp,
            &self.node_id,
            &self.registry_client,
            transcript,
            openings,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::IDkgProtocol,
            MetricsScope::Full,
            "load_transcript_with_openings",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn retain_active_transcripts(
        &self,
        active_transcripts: &HashSet<IDkgTranscript>,
    ) -> Result<(), IDkgRetainThresholdKeysError> {
        let log_id = get_log_id(&self.logger, module_path!());
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "IDkgProtocol",
            crypto.method_name => "retain_active_transcripts",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_transcript => format!("{:?}",
                active_transcripts
                .iter()
                .map(|transcript| transcript.transcript_id)
                .collect::<BTreeSet<IDkgTranscriptId>>()
            ),
        );
        let start_time = self.metrics.now();
        let result = retain_active_keys::retain_keys_for_transcripts(
            &self.csp,
            &self.node_id,
            &self.registry_client,
            active_transcripts,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::IDkgProtocol,
            MetricsScope::Full,
            "retain_active_transcripts",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }
}
