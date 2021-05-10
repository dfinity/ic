use crate::sign::threshold_sig::ni_dkg::utils::epoch;
use ic_crypto_internal_csp::api::NiDkgCspClient;
use ic_types::crypto::threshold_sig::ni_dkg::errors::key_removal_error::DkgKeyRemovalError;
use ic_types::crypto::threshold_sig::ni_dkg::transcripts_to_retain::TranscriptsToRetain;
use ic_types::crypto::AlgorithmId;

mod error_conversions;

#[cfg(test)]
mod tests;

pub fn retain_only_active_keys<C: NiDkgCspClient>(
    ni_dkg_csp_client: &C,
    transcripts: TranscriptsToRetain,
) -> Result<(), DkgKeyRemovalError> {
    ni_dkg_csp_client.retain_threshold_keys_if_present(transcripts.public_keys());
    ni_dkg_csp_client.update_forward_secure_epoch(
        AlgorithmId::NiDkg_Groth20_Bls12_381,
        epoch(transcripts.min_registry_version()),
    )?;
    Ok(())
}
