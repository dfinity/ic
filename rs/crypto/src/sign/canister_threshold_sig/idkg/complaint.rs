use super::*;
use crate::sign::canister_threshold_sig::idkg::utils::{
    MegaKeyFromRegistryError, index_and_dealing_of_dealer, retrieve_mega_public_key_from_registry,
};
use ic_crypto_internal_threshold_sig_canister_threshold_sig::IDkgComplaintInternal;
use ic_crypto_internal_threshold_sig_canister_threshold_sig::verify_complaint as idkg_verify_complaint;
use ic_interfaces_registry::RegistryClient;
use ic_types::NodeIndex;
use std::convert::TryFrom;

#[cfg(test)]
mod tests;

pub fn verify_complaint(
    registry: &dyn RegistryClient,
    transcript: &IDkgTranscript,
    complaint: &IDkgComplaint,
    complainer_id: NodeId,
) -> Result<(), IDkgVerifyComplaintError> {
    if transcript.transcript_id != complaint.transcript_id {
        return Err(IDkgVerifyComplaintError::InvalidArgumentMismatchingTranscriptIDs);
    }
    let complainer_mega_pubkey = retrieve_mega_public_key_from_registry(
        &complainer_id,
        registry,
        transcript.registry_version,
    )?;
    let complainer_index = index_of_complainer(complainer_id, transcript)?;
    let internal_complaint = IDkgComplaintInternal::try_from(complaint).map_err(|e| {
        IDkgVerifyComplaintError::SerializationError {
            internal_error: format!("failed to deserialize complaint: {e:?}"),
        }
    })?;
    let (dealer_index, internal_dealing) =
        index_and_dealing_of_dealer(complaint.dealer_id, transcript)?;

    Ok(idkg_verify_complaint(
        transcript.algorithm_id,
        &internal_complaint,
        complainer_index,
        &complainer_mega_pubkey,
        &internal_dealing,
        dealer_index,
        &transcript.context_data(),
    )?)
}

fn index_of_complainer(
    complainer_id: NodeId,
    transcript: &IDkgTranscript,
) -> Result<NodeIndex, IDkgVerifyComplaintError> {
    transcript.index_for_signer_id(complainer_id).ok_or(
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
