//! Utilities useful for implementations of IDkgProtocol

mod errors;
pub use errors::*;

use ic_crypto_internal_csp::key_id::KeyId;
use ic_crypto_internal_csp::keygen::utils::{
    MEGaPublicKeyFromProtoError, mega_public_key_from_proto,
};
use ic_crypto_internal_threshold_sig_canister_threshold_sig::{IDkgDealingInternal, MEGaPublicKey};
use ic_interfaces_registry::RegistryClient;
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_registry_client_helpers::crypto::CryptoRegistry;
use ic_types::crypto::KeyPurpose;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgOpenTranscriptError, IDkgVerifyComplaintError, IDkgVerifyOpeningError,
};
use ic_types::crypto::canister_threshold_sig::idkg::{BatchSignedIDkgDealing, IDkgTranscript};
use ic_types::{NodeId, NodeIndex, RegistryVersion};
use std::convert::TryFrom;

#[cfg(test)]
mod tests;

pub fn key_id_from_mega_public_key_or_panic(public_key: &MEGaPublicKey) -> KeyId {
    KeyId::try_from(public_key).unwrap_or_else(|err| panic!("{}", err))
}

/// Query the registry for the MEGa public key of `node_id` receiver.
pub fn retrieve_mega_public_key_from_registry(
    node_id: &NodeId,
    registry: &dyn RegistryClient,
    registry_version: RegistryVersion,
) -> Result<MEGaPublicKey, MegaKeyFromRegistryError> {
    let pk_proto = fetch_idkg_dealing_encryption_public_key_from_registry(
        node_id,
        registry,
        registry_version,
    )?;
    let mega_pubkey = mega_public_key_from_proto(&pk_proto).map_err(|e| match e {
        MEGaPublicKeyFromProtoError::UnsupportedAlgorithm { algorithm_id } => {
            MegaKeyFromRegistryError::UnsupportedAlgorithm { algorithm_id }
        }
        MEGaPublicKeyFromProtoError::MalformedPublicKey { key_bytes } => {
            MegaKeyFromRegistryError::MalformedPublicKey {
                node_id: *node_id,
                key_bytes,
            }
        }
    })?;
    Ok(mega_pubkey)
}

/// Query the registry for the proto of the MEGa public key of `node_id` receiver.
pub fn fetch_idkg_dealing_encryption_public_key_from_registry(
    node_id: &NodeId,
    registry: &dyn RegistryClient,
    registry_version: RegistryVersion,
) -> Result<PublicKey, MegaKeyFromRegistryError> {
    registry
        .get_crypto_key_for_node(*node_id, KeyPurpose::IDkgMEGaEncryption, registry_version)
        .map_err(MegaKeyFromRegistryError::RegistryError)?
        .ok_or(MegaKeyFromRegistryError::PublicKeyNotFound {
            registry_version,
            node_id: *node_id,
        })
}

#[derive(Debug)]
pub enum IDkgDealingExtractionError {
    MissingDealingInTranscript { dealer_id: NodeId },
    SerializationError { internal_error: String },
}

impl From<IDkgDealingExtractionError> for IDkgVerifyComplaintError {
    fn from(e: IDkgDealingExtractionError) -> Self {
        match e {
            IDkgDealingExtractionError::MissingDealingInTranscript { dealer_id } => {
                IDkgVerifyComplaintError::InvalidArgumentMissingDealingInTranscript { dealer_id }
            }
            IDkgDealingExtractionError::SerializationError { internal_error } => {
                IDkgVerifyComplaintError::SerializationError { internal_error }
            }
        }
    }
}

impl From<IDkgDealingExtractionError> for IDkgOpenTranscriptError {
    fn from(e: IDkgDealingExtractionError) -> Self {
        match e {
            IDkgDealingExtractionError::MissingDealingInTranscript { dealer_id } => {
                IDkgOpenTranscriptError::MissingDealingInTranscript { dealer_id }
            }
            IDkgDealingExtractionError::SerializationError { internal_error } => {
                IDkgOpenTranscriptError::InternalError { internal_error }
            }
        }
    }
}

impl From<IDkgDealingExtractionError> for IDkgVerifyOpeningError {
    fn from(e: IDkgDealingExtractionError) -> Self {
        match e {
            IDkgDealingExtractionError::MissingDealingInTranscript { dealer_id } => {
                IDkgVerifyOpeningError::MissingDealingInTranscript { dealer_id }
            }
            IDkgDealingExtractionError::SerializationError { internal_error } => {
                IDkgVerifyOpeningError::InternalError { internal_error }
            }
        }
    }
}

/// Finds in `transcript` the dealing of the dealer `dealer_id` and converts it
/// to internal representation, and returns this dealing together with the index
/// that corresponds to the dealer.
pub(crate) fn index_and_dealing_of_dealer(
    dealer_id: NodeId,
    transcript: &IDkgTranscript,
) -> Result<(NodeIndex, IDkgDealingInternal), IDkgDealingExtractionError> {
    let (index, signed_dealing) = index_and_batch_signed_dealing_of_dealer(dealer_id, transcript)?;
    let internal_dealing = IDkgDealingInternal::try_from(signed_dealing).map_err(|e| {
        IDkgDealingExtractionError::SerializationError {
            internal_error: format!(
                "Error deserializing a signed dealing: {e:?} of dealer {dealer_id:?}"
            ),
        }
    })?;
    Ok((index, internal_dealing))
}

/// Finds in `transcript` the dealing of the dealer `dealer_id`, and returns
/// this dealing together with the index that corresponds to the dealer.
pub(crate) fn index_and_batch_signed_dealing_of_dealer(
    dealer_id: NodeId,
    transcript: &IDkgTranscript,
) -> Result<(NodeIndex, &BatchSignedIDkgDealing), IDkgDealingExtractionError> {
    let (index, signed_dealing) = transcript
        .verified_dealings
        .iter()
        .find(|(_index, signed_dealing)| signed_dealing.dealer_id() == dealer_id)
        .ok_or(IDkgDealingExtractionError::MissingDealingInTranscript { dealer_id })?;
    Ok((*index, signed_dealing))
}
