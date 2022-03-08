//! Implementations of IDkgProtocol related to dealings

use crate::sign::canister_threshold_sig::idkg::utils::{
    get_mega_pubkey, idkg_encryption_keys_from_registry, MegaKeyFromRegistryError,
};
use ic_crypto_internal_csp::api::CspIDkgProtocol;
use ic_crypto_internal_threshold_sig_ecdsa::{
    IDkgDealingInternal, IDkgTranscriptOperationInternal,
};
use ic_interfaces::registry::RegistryClient;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgVerifyDealingPrivateError, IDkgVerifyDealingPublicError,
};
use ic_types::crypto::canister_threshold_sig::idkg::{IDkgDealing, IDkgTranscriptParams};
use ic_types::NodeId;
use std::convert::TryFrom;
use std::sync::Arc;

pub fn create_dealing<C: CspIDkgProtocol>(
    csp_client: &C,
    self_node_id: &NodeId,
    registry: &Arc<dyn RegistryClient>,
    params: &IDkgTranscriptParams,
) -> Result<IDkgDealing, IDkgCreateDealingError> {
    let self_index =
        params
            .dealer_index(*self_node_id)
            .ok_or(IDkgCreateDealingError::NotADealer {
                node_id: *self_node_id,
            })?;

    let receiver_keys = idkg_encryption_keys_from_registry(
        params.receivers(),
        registry,
        params.registry_version(),
    )?;
    let receiver_keys_vec = receiver_keys.iter().map(|(_, k)| *k).collect::<Vec<_>>();

    let csp_operation_type = IDkgTranscriptOperationInternal::try_from(params.operation_type())
        .map_err(|e| IDkgCreateDealingError::SerializationError {
            internal_error: format!("{:?}", e),
        })?;

    let internal_dealing = csp_client.idkg_create_dealing(
        params.algorithm_id(),
        &params.context_data(),
        self_index,
        params.reconstruction_threshold(),
        &receiver_keys_vec,
        &csp_operation_type,
    )?;

    let internal_dealing_raw =
        internal_dealing
            .serialize()
            .map_err(|e| IDkgCreateDealingError::SerializationError {
                internal_error: format!("{:?}", e),
            })?;

    Ok(IDkgDealing {
        transcript_id: params.transcript_id(),
        dealer_id: *self_node_id,
        internal_dealing_raw,
    })
}

pub fn verify_dealing_private<C: CspIDkgProtocol>(
    csp_client: &C,
    self_node_id: &NodeId,
    registry: &Arc<dyn RegistryClient>,
    params: &IDkgTranscriptParams,
    dealer_id: NodeId,
    dealing: &IDkgDealing,
) -> Result<(), IDkgVerifyDealingPrivateError> {
    if dealing.transcript_id != params.transcript_id() {
        return Err(IDkgVerifyDealingPrivateError::InvalidArgument(format!(
            "mismatching transcript IDs in dealing ({:?}) and params ({:?})",
            dealing.transcript_id,
            params.transcript_id(),
        )));
    }
    let internal_dealing = IDkgDealingInternal::deserialize(&dealing.internal_dealing_raw)
        .map_err(|e| {
            IDkgVerifyDealingPrivateError::InvalidArgument(format!(
                "failed to deserialize internal dealing: {:?}",
                e
            ))
        })?;
    let dealer_index = params.dealer_index(dealer_id).ok_or_else(|| {
        IDkgVerifyDealingPrivateError::InvalidArgument(format!(
            "failed to determine dealer index: node {:?} is not a dealer",
            dealer_id
        ))
    })?;
    let self_receiver_index = params
        .receiver_index(*self_node_id)
        .ok_or(IDkgVerifyDealingPrivateError::NotAReceiver)?;
    let self_mega_pubkey = get_mega_pubkey(self_node_id, registry, params.registry_version())?;

    csp_client.idkg_verify_dealing_private(
        params.algorithm_id(),
        &internal_dealing,
        dealer_index,
        self_receiver_index,
        &self_mega_pubkey,
        &params.context_data(),
    )
}

impl From<MegaKeyFromRegistryError> for IDkgVerifyDealingPrivateError {
    fn from(mega_key_from_registry_error: MegaKeyFromRegistryError) -> Self {
        type Mkfre = MegaKeyFromRegistryError;
        type Ivdpe = IDkgVerifyDealingPrivateError;
        match mega_key_from_registry_error {
            Mkfre::RegistryError(e) => Ivdpe::RegistryError(e),
            Mkfre::PublicKeyNotFound {
                node_id,
                registry_version,
            } => Ivdpe::PublicKeyNotInRegistry {
                node_id,
                registry_version,
            },
            Mkfre::UnsupportedAlgorithm { algorithm_id } => {
                Ivdpe::UnsupportedAlgorithm { algorithm_id }
            }
            Mkfre::MalformedPublicKey { node_id, key_bytes } => {
                Ivdpe::MalformedPublicKey { node_id, key_bytes }
            }
        }
    }
}

pub fn verify_dealing_public<C: CspIDkgProtocol>(
    csp_client: &C,
    params: &IDkgTranscriptParams,
    dealer_id: NodeId,
    dealing: &IDkgDealing,
) -> Result<(), IDkgVerifyDealingPublicError> {
    // Check the dealing is for the correct transcript ID
    if params.transcript_id() != dealing.transcript_id {
        return Err(IDkgVerifyDealingPublicError::TranscriptIdMismatch);
    }

    let internal_dealing = IDkgDealingInternal::deserialize(&dealing.internal_dealing_raw)
        .map_err(|e| IDkgVerifyDealingPublicError::InvalidDealing {
            reason: format!("{:?}", e),
        })?;

    // Compute CSP operation. Same of IDKM operation type, but wrapping the polynomial commitment from the transcripts.

    let internal_operation = IDkgTranscriptOperationInternal::try_from(params.operation_type())
        .map_err(|e| IDkgVerifyDealingPublicError::InvalidDealing {
            reason: format!("{:?}", e),
        })?;

    let dealer_index =
        params
            .dealer_index(dealer_id)
            .ok_or(IDkgVerifyDealingPublicError::InvalidDealing {
                reason: "No such dealer".to_string(),
            })?;

    let number_of_receivers = params.receivers().count();

    csp_client.idkg_verify_dealing_public(
        params.algorithm_id(),
        &internal_dealing,
        &internal_operation,
        params.reconstruction_threshold(),
        dealer_index,
        number_of_receivers,
        &params.context_data(),
    )
}
