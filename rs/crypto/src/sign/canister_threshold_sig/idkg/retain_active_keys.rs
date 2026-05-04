use crate::sign::retrieve_mega_public_key_from_registry;
use ic_base_types::{NodeId, RegistryVersion};
use ic_crypto_internal_csp::key_id::KeyId;
use ic_crypto_internal_csp::vault::api::CspVault;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_internal_threshold_sig_canister_threshold_sig::{
    IDkgTranscriptInternal, MEGaPublicKey,
};
use ic_interfaces::crypto::ErrorReproducibility;
use ic_interfaces_registry::RegistryClient;
use ic_types::crypto::canister_threshold_sig::error::IDkgRetainKeysError;
use ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscript;
use std::collections::{BTreeSet, HashSet};
use std::convert::TryFrom;
use std::sync::Arc;

#[cfg(test)]
mod tests;

pub fn retain_keys_for_transcripts(
    vault: &Arc<dyn CspVault>,
    node_id: &NodeId,
    registry: &dyn RegistryClient,
    metrics: &Arc<CryptoMetrics>,
    active_transcripts: &HashSet<IDkgTranscript>,
) -> Result<(), IDkgRetainKeysError> {
    if active_transcripts.is_empty() {
        return Ok(());
    }
    let oldest_public_key: MEGaPublicKey =
        match oldest_public_key(node_id, registry, metrics, active_transcripts) {
            None => return Ok(()),
            Some(oldest_public_key) => oldest_public_key?,
        };

    let internal_transcripts: Result<BTreeSet<_>, _> = active_transcripts
        .iter()
        .map(|transcript| {
            IDkgTranscriptInternal::try_from(transcript).map_err(|e| {
                IDkgRetainKeysError::SerializationError {
                    internal_error: format!("failed to deserialize internal transcript: {e:?}"),
                }
            })
        })
        .collect();

    let active_key_ids = internal_transcripts?
        .iter()
        .map(|active_transcript| KeyId::from(active_transcript.combined_commitment.commitment()))
        .collect();

    vault.idkg_retain_active_keys(active_key_ids, oldest_public_key)
}

fn oldest_public_key(
    node_id: &NodeId,
    registry: &dyn RegistryClient,
    metrics: &Arc<CryptoMetrics>,
    transcripts: &HashSet<IDkgTranscript>,
) -> Option<Result<MEGaPublicKey, IDkgRetainKeysError>> {
    minimum_registry_version_for_node(transcripts, *node_id).map(|version| {
        match retrieve_mega_public_key_from_registry(node_id, registry, version) {
            Ok(oldest_public_key) => {
                metrics.observe_minimum_registry_version_in_active_idkg_transcripts(version.get());
                Ok(oldest_public_key)
            }
            Err(err) => Err(if err.is_reproducible() {
                IDkgRetainKeysError::InternalError {
                    internal_error: format!(
                        "Internal error while searching for iDKG public key: {err:?}"
                    ),
                }
            } else {
                IDkgRetainKeysError::TransientInternalError {
                    internal_error: format!(
                        "Transient error while searching for iDKG public key: {err:?}"
                    ),
                }
            }),
        }
    })
}

fn minimum_registry_version_for_node(
    transcripts: &HashSet<IDkgTranscript>,
    node_id: NodeId,
) -> Option<RegistryVersion> {
    transcripts
        .iter()
        .filter_map(|t| t.has_receiver(node_id).then_some(t.registry_version))
        .min()
}
