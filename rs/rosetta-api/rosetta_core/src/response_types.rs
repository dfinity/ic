use crate::identifiers::NetworkIdentifier;
use serde::{Deserialize, Serialize};

/// A NetworkListResponse contains all NetworkIdentifiers that the node can
/// serve information for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct NetworkListResponse {
    pub network_identifiers: Vec<NetworkIdentifier>,
}

impl NetworkListResponse {
    pub fn new(network_identifiers: Vec<NetworkIdentifier>) -> NetworkListResponse {
        NetworkListResponse {
            network_identifiers,
        }
    }
}
