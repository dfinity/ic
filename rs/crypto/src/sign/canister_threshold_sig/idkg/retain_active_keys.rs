use crate::sign::get_mega_pubkey;
use ic_base_types::{NodeId, RegistryVersion};
use ic_crypto_internal_csp::api::CspIDkgProtocol;
use ic_crypto_internal_threshold_sig_ecdsa::{IDkgTranscriptInternal, MEGaPublicKey};
use ic_interfaces::crypto::ErrorReproducibility;
use ic_interfaces_registry::RegistryClient;
use ic_types::crypto::canister_threshold_sig::error::IDkgRetainThresholdKeysError;
use ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscript;
use std::collections::{BTreeSet, HashSet};
use std::convert::TryFrom;
use std::sync::Arc;

#[cfg(test)]
mod tests;

pub fn retain_keys_for_transcripts<C: CspIDkgProtocol>(
    csp_client: &C,
    node_id: &NodeId,
    registry: &Arc<dyn RegistryClient>,
    active_transcripts: &HashSet<IDkgTranscript>,
) -> Result<(), IDkgRetainThresholdKeysError> {
    if active_transcripts.is_empty() {
        return Ok(());
    }
    let oldest_public_key = oldest_public_key(node_id, registry, active_transcripts)
        .expect("at least one public key since there is at least one transcript")?;

    let internal_transcripts: Result<BTreeSet<_>, _> = active_transcripts
        .iter()
        .map(|transcript| {
            IDkgTranscriptInternal::try_from(transcript).map_err(|e| {
                IDkgRetainThresholdKeysError::SerializationError {
                    internal_error: format!("failed to deserialize internal transcript: {:?}", e),
                }
            })
        })
        .collect();
    csp_client.idkg_retain_active_keys(&internal_transcripts?, oldest_public_key)
}

fn oldest_public_key(
    node_id: &NodeId,
    registry: &Arc<dyn RegistryClient>,
    transcripts: &HashSet<IDkgTranscript>,
) -> Option<Result<MEGaPublicKey, IDkgRetainThresholdKeysError>> {
    minimum_registry_version(transcripts).map(|version| {
        get_mega_pubkey(node_id, registry.as_ref(), version).map_err(|err| {
            if err.is_reproducible() {
                IDkgRetainThresholdKeysError::InternalError {
                    internal_error: format!(
                        "Internal error while searching for iDKG public key: {:?}",
                        err
                    ),
                }
            } else {
                IDkgRetainThresholdKeysError::TransientInternalError {
                    internal_error: format!(
                        "Transient error while searching for iDKG public key: {:?}",
                        err
                    ),
                }
            }
        })
    })
}

fn minimum_registry_version(transcripts: &HashSet<IDkgTranscript>) -> Option<RegistryVersion> {
    transcripts
        .iter()
        .map(|transcript| transcript.registry_version)
        .min()
}
