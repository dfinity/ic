use candid::Deserialize;

use ic_base_types::CanisterId;
use serde::Serialize;

const DEFAULT_BLOCKCHAIN: &str = "Internet Computer";

pub type Object = serde_json::map::Map<String, serde_json::Value>;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct MetadataRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Object>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkListResponse {
    pub network_identifiers: Vec<NetworkIdentifier>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkIdentifier {
    pub blockchain: String,

    pub network: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_network_identifier: Option<SubNetworkIdentifier>,
}

impl NetworkIdentifier {
    pub fn for_ledger_id(ledger_id: CanisterId) -> Self {
        let network = hex::encode(ledger_id.get().into_vec());
        NetworkIdentifier {
            blockchain: DEFAULT_BLOCKCHAIN.to_string(),
            network,
            sub_network_identifier: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubNetworkIdentifier {
    pub network: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Object>,
}
