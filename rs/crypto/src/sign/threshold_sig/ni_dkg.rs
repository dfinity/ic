//! Implements `NiDkgAlgorithm`.

use super::*;
use ic_crypto_internal_csp::CryptoServiceProvider;
use ic_interfaces::crypto::{LoadTranscriptResult, NiDkgAlgorithm};
use ic_logger::{debug, new_logger};
use ic_types::crypto::threshold_sig::ni_dkg::errors::create_dealing_error::DkgCreateDealingError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::create_transcript_error::DkgCreateTranscriptError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::key_removal_error::DkgKeyRemovalError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::load_transcript_error::DkgLoadTranscriptError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::verify_dealing_error::DkgVerifyDealingError;
use ic_types::crypto::threshold_sig::ni_dkg::transcripts_to_retain::TranscriptsToRetain;
use ic_types::crypto::threshold_sig::ni_dkg::{config::NiDkgConfig, NiDkgDealing, NiDkgTranscript};
use std::collections::HashSet;

mod dealing;
mod retain_active_keys;
mod transcript;
mod utils;

#[cfg(test)]
mod test_utils;

impl<C: CryptoServiceProvider> NiDkgAlgorithm for CryptoComponentFatClient<C> {
    fn create_dealing(&self, config: &NiDkgConfig) -> Result<NiDkgDealing, DkgCreateDealingError> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "NiDkgAlgorithm",
            crypto.method_name => "create_dealing",
            crypto.registry_version => config.registry_version().get(),
            crypto.dkg_id => format!("{}", config.dkg_id()),
            crypto.dkg_config => format!("{}", config),
        );
        debug!(logger; crypto.description => "start",);
        let start_time = self.metrics.now();
        let result =
            dealing::create_dealing(&self.node_id, &self.csp, &self.registry_client, config);
        self.metrics
            .observe_ni_dkg_method_duration_seconds("create_dealing", start_time);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
            crypto.dkg_dealing => log_ok_content(&result),
        );
        result
    }

    fn verify_dealing(
        &self,
        config: &NiDkgConfig,
        dealer: NodeId,
        dealing: &NiDkgDealing,
    ) -> Result<(), DkgVerifyDealingError> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "NiDkgAlgorithm",
            crypto.method_name => "verify_dealing",
            crypto.registry_version => config.registry_version().get(),
            crypto.dkg_id => format!("{}", config.dkg_id()),
            crypto.dkg_config => format!("{}", config),
            crypto.dkg_dealer => format!("{}", dealer),
            crypto.dkg_dealing => format!("{}", dealing),
        );
        debug!(logger; crypto.description => "start",);
        let start_time = self.metrics.now();
        let result =
            dealing::verify_dealing(&self.csp, &self.registry_client, config, &dealer, dealing);
        self.metrics
            .observe_ni_dkg_method_duration_seconds("verify_dealing", start_time);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn create_transcript(
        &self,
        config: &NiDkgConfig,
        verified_dealings: &BTreeMap<NodeId, NiDkgDealing>,
    ) -> Result<NiDkgTranscript, DkgCreateTranscriptError> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "NiDkgAlgorithm",
            crypto.method_name => "create_transcript",
            crypto.registry_version => config.registry_version().get(),
            crypto.dkg_id => format!("{}", config.dkg_id()),
            crypto.dkg_config => format!("{}", config),
        );
        debug!(logger; crypto.description => "start",);
        let start_time = self.metrics.now();
        let result = transcript::create_transcript(&self.csp, config, verified_dealings);
        self.metrics
            .observe_ni_dkg_method_duration_seconds("create_transcript", start_time);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
            crypto.dkg_transcript => log_ok_content(&result),
        );
        result
    }

    fn load_transcript(
        &self,
        transcript: &NiDkgTranscript,
    ) -> Result<LoadTranscriptResult, DkgLoadTranscriptError> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "NiDkgAlgorithm",
            crypto.method_name => "load_transcript",
            crypto.registry_version => transcript.registry_version.get(),
            crypto.dkg_id => format!("{}", transcript.dkg_id),
            crypto.dkg_transcript => format!("{}", transcript),
        );
        debug!(logger; crypto.description => "start",);
        let start_time = self.metrics.now();
        let result = transcript::load_transcript(
            &self.node_id,
            &self.lockable_threshold_sig_data_store,
            &self.csp,
            transcript,
            &logger,
        );
        self.metrics
            .observe_ni_dkg_method_duration_seconds("load_transcript", start_time);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn retain_only_active_keys(
        &self,
        transcripts: HashSet<NiDkgTranscript>,
    ) -> Result<(), DkgKeyRemovalError> {
        let transcripts = TranscriptsToRetain::new(transcripts)
            .map_err(DkgKeyRemovalError::InputValidationError)?;
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "NiDkgAlgorithm",
            crypto.method_name => "retain_only_active_keys",
            crypto.description => transcripts.display_dkg_ids_and_registry_versions(),
        );
        debug!(logger; crypto.description => "start",);
        let start_time = self.metrics.now();
        let result = retain_active_keys::retain_only_active_keys(&self.csp, transcripts);
        self.metrics
            .observe_ni_dkg_method_duration_seconds("retain_only_active_keys", start_time);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }
}
