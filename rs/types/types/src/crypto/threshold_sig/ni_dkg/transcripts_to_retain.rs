//! Types related to transcripts that should be retained during NI-DKG key
//! deletion. See `NiDkgAlgorithm::retain_only_active_keys`.
use super::*;
use crate::crypto::threshold_sig::ni_dkg::errors::transcripts_to_retain_validation_error::TranscriptsToRetainValidationError;
use std::collections::HashSet;

#[cfg(test)]
mod tests;

/// Transcripts that should be retained when using
/// `NiDkgAlgorithm::retain_only_active_keys`. See the invariants in
/// `TranscriptsToRetain::new`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranscriptsToRetain {
    // fields must be private to avoid invariant violations
    transcripts: HashSet<NiDkgTranscript>,
}

impl TranscriptsToRetain {
    /// Creates `TranscriptsToRetain`. See the errors listed below describing
    /// invariants that are checked upon creation.
    ///
    /// # Errors
    /// * `TranscriptsToRetainValidationError::NoLowTranscripts`: if there are
    ///   no low transcripts.
    /// * `TranscriptsToRetainValidationError::NoHighTranscripts`: if there are
    ///   no high transcripts.
    pub fn new(
        transcripts: HashSet<NiDkgTranscript>,
    ) -> Result<Self, TranscriptsToRetainValidationError> {
        let result = Self { transcripts };
        result.ensure_at_least_one_low_transcript()?;
        result.ensure_at_least_one_high_transcript()?;
        Ok(result)
    }

    /// Returns the public keys corresponding to the transcripts.
    pub fn public_keys(&self) -> BTreeSet<CspPublicCoefficients> {
        self.transcripts.iter().map(pub_coeffs).collect()
    }

    /// Returns the minimum registry version of all transcripts
    pub fn min_registry_version(&self) -> RegistryVersion {
        self.transcripts
            .iter()
            .map(|t| t.registry_version)
            .min()
            .unwrap() // This never panics because the invariants ensure that
                      // there are at least two elements in `transcripts`.
    }

    /// Returns a string representation of `TranscriptsToRetain`. Can be used
    /// for logging.
    pub fn display_dkg_ids_and_registry_versions(&self) -> String {
        let mut display_msg = "TranscriptsToRetain: [ ".to_string();
        for transcript in &self.transcripts {
            display_msg += format!(
                "[dkg_id {}, registry version {}] ",
                transcript.dkg_id, transcript.registry_version
            )
            .as_str()
        }
        display_msg += "]";
        display_msg
    }

    fn ensure_at_least_one_low_transcript(&self) -> Result<(), TranscriptsToRetainValidationError> {
        let num_low_transcripts = self
            .transcripts
            .iter()
            .filter(|t| t.dkg_id.dkg_tag == NiDkgTag::LowThreshold)
            .count();
        if num_low_transcripts == 0 {
            return Err(TranscriptsToRetainValidationError::NoLowTranscripts);
        }
        Ok(())
    }

    fn ensure_at_least_one_high_transcript(
        &self,
    ) -> Result<(), TranscriptsToRetainValidationError> {
        let num_high_transcripts = self
            .transcripts
            .iter()
            .filter(|t| t.dkg_id.dkg_tag == NiDkgTag::HighThreshold)
            .count();
        if num_high_transcripts == 0 {
            return Err(TranscriptsToRetainValidationError::NoHighTranscripts);
        }
        Ok(())
    }
}

fn pub_coeffs(transcript: &NiDkgTranscript) -> CspPublicCoefficients {
    let CspNiDkgTranscript::Groth20_Bls12_381(transcript) = &transcript.internal_csp_transcript;
    CspPublicCoefficients::Bls12_381(transcript.public_coefficients.clone())
}
