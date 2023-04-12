use axum::{http::StatusCode, response::IntoResponse, Json};
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkOptionsResponse {
    pub version: Version,

    pub allow: Allow,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Version {
    pub rosetta_version: String,

    pub node_version: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub middleware_version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Object>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Allow {
    pub operation_statuses: Vec<OperationStatus>,

    pub operation_types: Vec<String>,

    pub errors: Vec<Error>,

    pub historical_balance_lookup: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperationStatus {
    pub status: String,

    pub successful: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Error {
    pub code: u32,

    pub message: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    pub retriable: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Object>,
}

const ERROR_CODE_INVALID_NETWORK_ID: u32 = 1;

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(self)).into_response()
    }
}

impl Error {
    pub fn invalid_network_id(expected: &NetworkIdentifier) -> Self {
        Self {
            code: ERROR_CODE_INVALID_NETWORK_ID,
            message: "Invalid network identifier".into(),
            description: Some(format!(
                "Invalid network identifier. Expected {}",
                serde_json::to_string(expected).unwrap()
            )),
            retriable: false,
            details: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkRequest {
    pub network_identifier: NetworkIdentifier,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Object>,
}
