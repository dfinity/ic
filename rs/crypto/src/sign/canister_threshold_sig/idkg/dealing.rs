//! Implementations of IDkgProtocol related to dealings

use crate::sign::canister_threshold_sig::idkg::utils::idkg_encryption_keys_from_registry;
use ic_crypto_internal_csp::api::CspIDkgProtocol;
use ic_crypto_internal_threshold_sig_ecdsa::IDkgTranscriptOperationInternal;
use ic_interfaces::registry::RegistryClient;
use ic_types::crypto::canister_threshold_sig::error::IDkgCreateDealingError;
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
