use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgLoadTranscriptError, IDkgOpenTranscriptError,
};
use ic_types::registry::RegistryClientError;
use ic_types::{NodeId, RegistryVersion};

/// Errors encountered while looking-up a MEGa public key from the registry
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MegaKeyFromRegistryError {
    RegistryError(RegistryClientError),
    PublicKeyNotFound {
        node_id: NodeId,
        registry_version: RegistryVersion,
    },
    UnsupportedAlgorithm {
        algorithm_id: Option<AlgorithmIdProto>,
    },
    MalformedPublicKey {
        node_id: NodeId,
        key_bytes: Vec<u8>,
    },
}

impl From<MegaKeyFromRegistryError> for IDkgCreateDealingError {
    fn from(error: MegaKeyFromRegistryError) -> Self {
        match error {
            MegaKeyFromRegistryError::RegistryError(e) => IDkgCreateDealingError::RegistryError(e),
            MegaKeyFromRegistryError::PublicKeyNotFound {
                node_id,
                registry_version,
            } => IDkgCreateDealingError::PublicKeyNotFound {
                node_id,
                registry_version,
            },
            MegaKeyFromRegistryError::UnsupportedAlgorithm { algorithm_id } => {
                IDkgCreateDealingError::UnsupportedAlgorithm { algorithm_id }
            }
            MegaKeyFromRegistryError::MalformedPublicKey { node_id, key_bytes } => {
                IDkgCreateDealingError::MalformedPublicKey { node_id, key_bytes }
            }
        }
    }
}

impl From<MegaKeyFromRegistryError> for IDkgLoadTranscriptError {
    fn from(error: MegaKeyFromRegistryError) -> Self {
        match error {
            MegaKeyFromRegistryError::RegistryError(e) => IDkgLoadTranscriptError::RegistryError(e),
            MegaKeyFromRegistryError::PublicKeyNotFound {
                node_id,
                registry_version,
            } => IDkgLoadTranscriptError::PublicKeyNotFound {
                node_id,
                registry_version,
            },
            MegaKeyFromRegistryError::UnsupportedAlgorithm { algorithm_id } => {
                IDkgLoadTranscriptError::UnsupportedAlgorithm { algorithm_id }
            }
            MegaKeyFromRegistryError::MalformedPublicKey { node_id, key_bytes } => {
                IDkgLoadTranscriptError::MalformedPublicKey { node_id, key_bytes }
            }
        }
    }
}

impl From<MegaKeyFromRegistryError> for IDkgOpenTranscriptError {
    fn from(e: MegaKeyFromRegistryError) -> Self {
        IDkgOpenTranscriptError::InternalError {
            internal_error: format!("Error retrieving public key: {:?}", e),
        }
    }
}
