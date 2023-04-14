use axum::{http::StatusCode, response::IntoResponse, Json};
use candid::Deserialize;

use ic_base_types::CanisterId;
use serde::Serialize;

// Generated from the [Rosetta API specification v1.4.13](https://github.com/coinbase/rosetta-specifications/blob/v1.4.13/api.json)
// Documentation for the Rosetta API can be found at https://www.rosetta-api.org/docs/1.4.13/welcome.html

const DEFAULT_BLOCKCHAIN: &str = "Internet Computer";

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct MetadataRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
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
    pub metadata: Option<serde_json::Value>,
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
    pub metadata: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Allow {
    pub operation_statuses: Vec<OperationStatus>,

    pub operation_types: Vec<String>,

    pub errors: Vec<Error>,

    pub historical_balance_lookup: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_start_index: Option<i64>,

    pub call_methods: Vec<String>,

    pub balance_exemptions: Vec<BalanceExemption>,

    pub mempool_coins: bool,

    #[serde(
        default,
        with = "::serde_with::rust::double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub block_hash_case: Option<Option<Case>>,

    #[serde(
        default,
        with = "::serde_with::rust::double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub transaction_hash_case: Option<Option<Case>>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BalanceExemption {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_account_address: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<Box<Currency>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub exemption_type: Option<ExemptionType>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Currency {
    pub symbol: String,

    pub decimals: i32,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum ExemptionType {
    GreaterOrEqual,
    LessOrEqual,
    Dynamic,
}

impl Default for ExemptionType {
    fn default() -> ExemptionType {
        Self::GreaterOrEqual
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Case {
    UpperCase,
    LowerCase,
    CaseSensitive,
    Null,
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
    pub details: Option<serde_json::Value>,
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
    pub metadata: Option<serde_json::Value>,
}
