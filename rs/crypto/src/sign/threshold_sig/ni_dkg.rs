//! Implements `NiDkgAlgorithm`.

use super::*;
use ic_crypto_internal_csp::CryptoServiceProvider;
use ic_crypto_internal_logmon::metrics::{MetricsDomain, MetricsScope};
use ic_interfaces::crypto::{LoadTranscriptResult, NiDkgAlgorithm};
use ic_logger::{debug, new_logger};
use ic_types::crypto::threshold_sig::ni_dkg::errors::create_dealing_error::DkgCreateDealingError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::create_transcript_error::DkgCreateTranscriptError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::key_removal_error::DkgKeyRemovalError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::load_transcript_error::DkgLoadTranscriptError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::verify_dealing_error::DkgVerifyDealingError;
use ic_types::crypto::threshold_sig::ni_dkg::transcripts_to_retain::TranscriptsToRetain;
use ic_types::crypto::threshold_sig::ni_dkg::{NiDkgDealing, NiDkgTranscript, config::NiDkgConfig};
use std::collections::HashSet;

mod dealing;
mod retain_active_keys;
mod transcript;
mod utils;

#[cfg(test)]
mod test_utils;

impl<C: CryptoServiceProvider> NiDkgAlgorithm for CryptoComponentImpl<C> {
    fn create_dealing(&self, config: &NiDkgConfig) -> Result<NiDkgDealing, DkgCreateDealingError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "NiDkgAlgorithm",
            crypto.method_name => "create_dealing",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_config => format!("{}", config),
        );
        let start_time = self.metrics.now();
        let result = dealing::create_dealing(
            &self.node_id,
            &self.csp,
            self.registry_client.as_ref(),
            config,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::NiDkgAlgorithm,
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

    fn verify_dealing(
        &self,
        config: &NiDkgConfig,
        dealer: NodeId,
        dealing: &NiDkgDealing,
    ) -> Result<(), DkgVerifyDealingError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "NiDkgAlgorithm",
            crypto.method_name => "verify_dealing",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_config => format!("{}", config),
            crypto.dkg_dealer => format!("{}", dealer),
            crypto.dkg_dealing => format!("{}", dealing),
        );
        let start_time = self.metrics.now();
        let result = dealing::verify_dealing(
            &self.csp,
            self.registry_client.as_ref(),
            config,
            &dealer,
            dealing,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::NiDkgAlgorithm,
            MetricsScope::Full,
            "verify_dealing",
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
        config: &NiDkgConfig,
        verified_dealings: &BTreeMap<NodeId, NiDkgDealing>,
    ) -> Result<NiDkgTranscript, DkgCreateTranscriptError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "NiDkgAlgorithm",
            crypto.method_name => "create_transcript",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_config => format!("{}", config),
            crypto.dkg_dealing => format!("{:?}",
                verified_dealings
                .keys()
                .cloned()
                .collect::<BTreeSet<NodeId>>()
            ),
        );
        let start_time = self.metrics.now();
        let result = transcript::create_transcript(&self.csp, config, verified_dealings);
        self.metrics.observe_parameter_size(
            MetricsDomain::NiDkgAlgorithm,
            "create_transcript",
            "transcript",
            result.as_ref().map_or(0, |transcript| {
                bincode::serialize(transcript).map_or(0, |bytes| bytes.len())
            }),
            MetricsResult::from(&result),
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::NiDkgAlgorithm,
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

    fn load_transcript(
        &self,
        transcript: &NiDkgTranscript,
    ) -> Result<LoadTranscriptResult, DkgLoadTranscriptError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "NiDkgAlgorithm",
            crypto.method_name => "load_transcript",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_transcript => format!("{}", transcript),
        );
        let start_time = self.metrics.now();
        let result = transcript::load_transcript(
            &self.node_id,
            &self.lockable_threshold_sig_data_store,
            &self.csp,
            transcript,
            &logger,
        );

        // Processing of the cache statistics for metrics is deliberately
        // part of the load transcript run time metric. It is expected to take
        // very little time, but if something goes wrong, e.g., due to a mutex
        // locking congestion or similar, we should be able to notice that.
        let stats = ic_crypto_internal_bls12_381_type::G2Affine::deserialize_cached_statistics();
        self.metrics
            .observe_bls12_381_sig_cache_stats(stats.size, stats.hits, stats.misses);

        self.metrics.observe_parameter_size(
            MetricsDomain::NiDkgAlgorithm,
            "load_transcript",
            "transcript",
            bincode::serialize(transcript).map_or(0, |bytes| bytes.len()),
            MetricsResult::from(&result),
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::NiDkgAlgorithm,
            MetricsScope::Full,
            "load_transcript",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
            crypto.dkg_transcript => debug_ok_content(&result),
        );
        result
    }

    fn retain_only_active_keys(
        &self,
        transcripts: HashSet<NiDkgTranscript>,
    ) -> Result<(), DkgKeyRemovalError> {
        let mut transcripts_len = 0;
        for transcript in &transcripts {
            transcripts_len += bincode::serialize(transcript).map_or(0, |bytes| bytes.len());
        }
        let transcripts = TranscriptsToRetain::new(transcripts)
            .map_err(DkgKeyRemovalError::InputValidationError)?;
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "NiDkgAlgorithm",
            crypto.method_name => "retain_only_active_keys",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_transcript => transcripts.display_dkg_ids_and_registry_versions(),
        );
        let start_time = self.metrics.now();
        let result = retain_active_keys::retain_only_active_keys(&self.csp, transcripts);
        self.metrics.observe_parameter_size(
            MetricsDomain::NiDkgAlgorithm,
            "load_transcript",
            "transcript",
            transcripts_len,
            MetricsResult::from(&result),
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::NiDkgAlgorithm,
            MetricsScope::Full,
            "retain_only_active_keys",
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
