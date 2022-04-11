//! Utilities useful for implementations of IDkgProtocol
#[cfg(test)]
mod tests;

mod errors;
pub use errors::*;

use ic_crypto_internal_threshold_sig_ecdsa::{EccCurveType, IDkgDealingInternal, MEGaPublicKey};
use ic_interfaces::registry::RegistryClient;
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_registry_client_helpers::crypto::CryptoRegistry;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgOpenTranscriptError, IDkgVerifyComplaintError, IDkgVerifyOpeningError,
};
use ic_types::crypto::canister_threshold_sig::idkg::{IDkgReceivers, IDkgTranscript};
use ic_types::crypto::KeyPurpose;
use ic_types::{NodeId, NodeIndex, RegistryVersion};
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::sync::Arc;

/// Query the registry for the MEGa public keys of all receivers.
///
/// The returned map is keyed by the index of the receiver.
pub fn idkg_encryption_keys_from_registry(
    receivers: &IDkgReceivers,
    registry: &Arc<dyn RegistryClient>,
    registry_version: RegistryVersion,
) -> Result<BTreeMap<NodeIndex, MEGaPublicKey>, MegaKeyFromRegistryError> {
    receivers
        .iter()
        .map(|(index, receiver)| {
            let enc_pubkey = get_mega_pubkey(&receiver, registry, registry_version)?;
            Ok((index, enc_pubkey))
        })
        .collect()
}

/// Query the registry for the MEGa public key of `node_id` receiver.
pub fn get_mega_pubkey(
    node_id: &NodeId,
    registry: &Arc<dyn RegistryClient>,
    registry_version: RegistryVersion,
) -> Result<MEGaPublicKey, MegaKeyFromRegistryError> {
    let pk_proto = registry
        .get_crypto_key_for_node(*node_id, KeyPurpose::IDkgMEGaEncryption, registry_version)
        .map_err(MegaKeyFromRegistryError::RegistryError)?
        .ok_or_else(|| MegaKeyFromRegistryError::PublicKeyNotFound {
            registry_version,
            node_id: *node_id,
        })?;
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

pub enum MEGaPublicKeyFromProtoError {
    UnsupportedAlgorithm {
        algorithm_id: Option<AlgorithmIdProto>,
    },
    MalformedPublicKey {
        key_bytes: Vec<u8>,
    },
}

/// Deserialize a Protobuf public key to a MEGaPublicKey.
pub fn mega_public_key_from_proto(
    proto: &PublicKeyProto,
) -> Result<MEGaPublicKey, MEGaPublicKeyFromProtoError> {
    let curve_type = match AlgorithmIdProto::from_i32(proto.algorithm) {
        Some(AlgorithmIdProto::MegaSecp256k1) => Ok(EccCurveType::K256),
        alg_id => Err(MEGaPublicKeyFromProtoError::UnsupportedAlgorithm {
            algorithm_id: alg_id,
        }),
    }?;

    MEGaPublicKey::deserialize(curve_type, &proto.key_value).map_err(|_| {
        MEGaPublicKeyFromProtoError::MalformedPublicKey {
            key_bytes: proto.key_value.clone(),
        }
    })
}

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

/// Finds in `transcript` the dealing of the dealer `dealer_id`, and returns
/// this dealing together with the index that corresponds to the dealer.
pub fn index_and_dealing_of_dealer(
    dealer_id: NodeId,
    transcript: &IDkgTranscript,
) -> Result<(NodeIndex, IDkgDealingInternal), IDkgDealingExtractionError> {
    let (index, signed_dealing) = transcript
        .verified_dealings
        .iter()
        .find(|(_index, signed_dealing)| signed_dealing.dealing.idkg_dealing.dealer_id == dealer_id)
        .ok_or(IDkgDealingExtractionError::MissingDealingInTranscript { dealer_id })?;
    let internal_dealing = IDkgDealingInternal::try_from(signed_dealing).map_err(|e| {
        IDkgDealingExtractionError::SerializationError {
            internal_error: format!(
                "Error deserializing a signed dealing: {:?} of dealer {:?}",
                e, dealer_id
            ),
        }
    })?;
    Ok((*index, internal_dealing))
}
