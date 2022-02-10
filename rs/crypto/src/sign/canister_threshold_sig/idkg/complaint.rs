use super::*;
use crate::sign::canister_threshold_sig::idkg::utils::{get_mega_pubkey, MegaKeyFromRegistryError};
use ic_crypto_internal_csp::api::CspIDkgProtocol;
use ic_interfaces::registry::RegistryClient;
use ic_types::NodeIndex;
use std::convert::TryFrom;
use std::sync::Arc;
use tecdsa::{IDkgComplaintInternal, IDkgDealingInternal};

#[cfg(test)]
mod tests;

pub fn verify_complaint<C: CspIDkgProtocol>(
    csp_idkg_client: &C,
    registry: &Arc<dyn RegistryClient>,
    transcript: &IDkgTranscript,
    complaint: &IDkgComplaint,
    complainer_id: NodeId,
) -> Result<(), IDkgVerifyComplaintError> {
    if transcript.transcript_id != complaint.transcript_id {
        return Err(IDkgVerifyComplaintError::InvalidArgumentMismatchingTranscriptIDs);
    }
    let complainer_mega_pubkey =
        get_mega_pubkey(&complainer_id, registry, transcript.registry_version)?;
    let complainer_index = index_of_complainer(complainer_id, transcript)?;
    let internal_complaint = IDkgComplaintInternal::try_from(complaint).map_err(|e| {
        IDkgVerifyComplaintError::SerializationError {
            internal_error: format!("failed to deserialize complaint: {:?}", e),
        }
    })?;
    let (dealer_index, signed_dealing) =
        index_and_dealing_of_dealer(complaint.dealer_id, transcript)?;
    let internal_dealing = IDkgDealingInternal::try_from(signed_dealing).map_err(|e| {
        IDkgVerifyComplaintError::SerializationError {
            internal_error: format!("failed to deserialize dealing: {:?}", e),
        }
    })?;

    csp_idkg_client.idkg_verify_complaint(
        &internal_complaint,
        complainer_index,
        &complainer_mega_pubkey,
        &internal_dealing,
        *dealer_index,
        &transcript.context_data(),
    )
}

fn index_and_dealing_of_dealer(
    dealer_id: NodeId,
    transcript: &IDkgTranscript,
) -> Result<(&NodeIndex, &IDkgMultiSignedDealing), IDkgVerifyComplaintError> {
    transcript
        .verified_dealings
        .iter()
        .find(|(_index, signed_dealing)| signed_dealing.dealing.idkg_dealing.dealer_id == dealer_id)
        .ok_or(IDkgVerifyComplaintError::InvalidArgumentMissingDealingInTranscript { dealer_id })
}

fn index_of_complainer(
    complainer_id: NodeId,
    transcript: &IDkgTranscript,
) -> Result<NodeIndex, IDkgVerifyComplaintError> {
    transcript.receivers.position(complainer_id).ok_or(
        IDkgVerifyComplaintError::InvalidArgumentMissingComplainerInTranscript { complainer_id },
    )
}

impl From<MegaKeyFromRegistryError> for IDkgVerifyComplaintError {
    fn from(mega_key_from_registry_error: MegaKeyFromRegistryError) -> Self {
        match mega_key_from_registry_error {
            MegaKeyFromRegistryError::RegistryError(e) => IDkgVerifyComplaintError::Registry(e),
            MegaKeyFromRegistryError::PublicKeyNotFound {
                node_id,
                registry_version,
            } => IDkgVerifyComplaintError::ComplainerPublicKeyNotInRegistry {
                node_id,
                registry_version,
            },
            MegaKeyFromRegistryError::UnsupportedAlgorithm { algorithm_id } => {
                IDkgVerifyComplaintError::UnsupportedComplainerPublicKeyAlgorithm { algorithm_id }
            }
            MegaKeyFromRegistryError::MalformedPublicKey { node_id, key_bytes } => {
                IDkgVerifyComplaintError::MalformedComplainerPublicKey { node_id, key_bytes }
            }
        }
    }
}
