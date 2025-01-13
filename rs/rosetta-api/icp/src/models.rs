pub mod amount;
pub mod operation;
pub mod seconds;
pub mod timestamp;

use crate::errors::convert_to_error;
use crate::{convert::from_hex, errors, errors::ApiError, request_types::RequestType};
use ic_types::messages::{
    HttpCallContent, HttpCanisterUpdate, HttpReadStateContent, HttpRequestEnvelope,
};
pub use rosetta_core::identifiers::*;
pub use rosetta_core::miscellaneous::*;
pub use rosetta_core::models::Ed25519KeyPair as EdKeypair;
pub use rosetta_core::objects::*;
pub use rosetta_core::request_types::*;
pub use rosetta_core::response_types::*;
use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};
use std::str::FromStr;

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct ConstructionHashResponse {
    pub transaction_identifier: TransactionIdentifier,
    pub metadata: ObjectMap,
}

/// The type (encoded as CBOR) returned by /construction/combine, containing the
/// IC calls to submit the transaction and to check the result.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct SignedTransaction {
    pub requests: Vec<Request>,
}

impl FromStr for SignedTransaction {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_cbor::from_slice(
            hex::decode(s)
                .map_err(|err| format!("{:?}", err))?
                .as_slice(),
        )
        .map_err(|err| format!("{:?}", err))
    }
}
impl std::fmt::Display for SignedTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(serde_cbor::to_vec(self).unwrap()))
    }
}
/// A vector of update/read-state calls for different ingress windows
/// of the same call.
pub type Request = (RequestType, Vec<EnvelopePair>);

/// A signed IC update call and the corresponding read-state call for
/// a particular ingress window.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct EnvelopePair {
    pub update: HttpRequestEnvelope<HttpCallContent>,
    pub read_state: HttpRequestEnvelope<HttpReadStateContent>,
}

impl EnvelopePair {
    pub fn update_content(&self) -> &HttpCanisterUpdate {
        match self.update.content {
            HttpCallContent::Call { ref update } => update,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "account_type")]
pub enum AccountType {
    Ledger,
    Neuron {
        #[serde(default)]
        neuron_index: u64,
    },
}

impl Default for AccountType {
    fn default() -> Self {
        Self::Ledger
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct ConstructionDeriveRequestMetadata {
    #[serde(flatten)]
    pub account_type: AccountType,
}

impl TryFrom<ConstructionDeriveRequestMetadata> for ObjectMap {
    type Error = ApiError;
    fn try_from(d: ConstructionDeriveRequestMetadata) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(serde_json::Value::Object(o)) => Ok(o),
            Ok(o) => Err(ApiError::internal_error(format!("Could not convert ConstructionDeriveRequestMetadata to ObjectMap. Expected type Object but received: {:?}",o))),
            Err(err) => Err(ApiError::internal_error(format!("Could not convert ConstructionDeriveRequestMetadata to ObjectMap: {:?}",err))),
        }
    }
}

impl TryFrom<Option<ObjectMap>> for ConstructionDeriveRequestMetadata {
    type Error = ApiError;
    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse ConstructionDeriveRequestMetadata metadata from metadata JSON object: {}",
                e
            ))
        })
    }
}

#[test]
fn test_construction_derive_request_metadata() {
    let r0 = ConstructionDeriveRequestMetadata {
        account_type: AccountType::Neuron { neuron_index: 1 },
    };

    let s = serde_json::to_string(&r0).unwrap();
    let r1 = serde_json::from_str(s.as_str()).unwrap();

    assert_eq!(s, r#"{"account_type":"neuron","neuron_index":1}"#);
    assert_eq!(r0, r1);
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct ConstructionMetadataRequestOptions {
    pub request_types: Vec<RequestType>,
}

impl TryFrom<ConstructionMetadataRequestOptions> for ObjectMap {
    type Error = ApiError;
    fn try_from(d: ConstructionMetadataRequestOptions) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(serde_json::Value::Object(o)) => Ok(o),
            Ok(o) => Err(ApiError::internal_error(format!("Could not convert ConstructionMetadataRequestOptions to ObjectMap. Expected type Object but received: {:?}",o))),
            Err(err) => Err(ApiError::internal_error(format!("Could not convert ConstructionMetadataRequestOptions to ObjectMap: {:?}",err))),
        }
    }
}

impl TryFrom<ObjectMap> for ConstructionMetadataRequestOptions {
    type Error = ApiError;
    fn try_from(o: ObjectMap) -> Result<Self, ApiError> {
        serde_json::from_value(serde_json::Value::Object(o)).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse ConstructionMetadataRequestOptions from Object: {}",
                e
            ))
        })
    }
}

impl TryFrom<Option<ObjectMap>> for ConstructionMetadataRequestOptions {
    type Error = ApiError;
    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse ConstructionMetadataRequestOptions metadata from metadata JSON object: {}",
                e
            ))
        })
    }
}

pub enum ParsedTransaction {
    Signed(SignedTransaction),
    Unsigned(UnsignedTransaction),
}

impl TryFrom<ConstructionParseRequest> for ParsedTransaction {
    type Error = ApiError;
    fn try_from(value: ConstructionParseRequest) -> Result<Self, Self::Error> {
        if value.signed {
            Ok(ParsedTransaction::Signed(
                serde_cbor::from_slice(&from_hex(&value.transaction)?).map_err(|e| {
                    ApiError::invalid_request(format!("Could not decode signed transaction: {}", e))
                })?,
            ))
        } else {
            Ok(ParsedTransaction::Unsigned(
                serde_cbor::from_slice(&from_hex(&value.transaction)?).map_err(|e| {
                    ApiError::invalid_request(format!(
                        "Could not decode unsigned transaction: {}",
                        e
                    ))
                })?,
            ))
        }
    }
}

/// Typed metadata of ConstructionPayloadsRequest.
#[derive(Clone, Eq, PartialEq, Debug, Default, Deserialize, Serialize)]
pub struct ConstructionPayloadsRequestMetadata {
    /// The memo to use for a ledger transfer.
    /// A random number is used by default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<u64>,

    /// The earliest acceptable expiry date for a ledger transfer.
    /// Must be within 24 hours from created_at_time.
    /// Represents number of nanoseconds since UNIX epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress_start: Option<u64>,

    /// The latest acceptable expiry date for a ledger transfer.
    /// Must be within 24 hours from created_at_time.
    /// Represents number of nanoseconds since UNIX epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress_end: Option<u64>,

    /// If present, overrides ledger transaction creation time.
    /// Represents number of nanoseconds since UNIX epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at_time: Option<u64>,
}

impl TryFrom<ConstructionPayloadsRequestMetadata> for ObjectMap {
    type Error = ApiError;
    fn try_from(d: ConstructionPayloadsRequestMetadata) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(serde_json::Value::Object(o)) => Ok(o),
            Ok(o) => Err(ApiError::internal_error(format!("Could not convert ConstructionPayloadsRequestMetadata to ObjectMap. Expected type Object but received: {:?}",o))),
            Err(err) => Err(ApiError::internal_error(format!("Could not convert ConstructionPayloadsRequestMetadata to ObjectMap: {:?}",err))),
        }
    }
}

impl TryFrom<ObjectMap> for ConstructionPayloadsRequestMetadata {
    type Error = ApiError;
    fn try_from(o: ObjectMap) -> Result<Self, ApiError> {
        serde_json::from_value(serde_json::Value::Object(o)).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse ConstructionPayloadsRequestMetadata from Object: {}",
                e
            ))
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UnsignedTransaction {
    pub updates: Vec<(RequestType, HttpCanisterUpdate)>,
    pub ingress_expiries: Vec<u64>,
}

impl std::fmt::Display for UnsignedTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(serde_cbor::to_vec(self).unwrap()))
    }
}

impl FromStr for UnsignedTransaction {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_cbor::from_slice(
            hex::decode(s)
                .map_err(|err| format!("{:?}", err))?
                .as_slice(),
        )
        .map_err(|err| format!("{:?}", err))
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct Error(pub rosetta_core::miscellaneous::Error);

impl From<Error> for rosetta_core::miscellaneous::Error {
    fn from(value: Error) -> Self {
        value.0
    }
}
impl From<rosetta_core::miscellaneous::Error> for Error {
    fn from(value: rosetta_core::miscellaneous::Error) -> Self {
        Error(value)
    }
}
impl ::std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Error {
    pub fn new(err_type: &ApiError) -> Self {
        errors::convert_to_error(err_type)
    }

    pub fn serialization_error_json_str() -> String {
        "{\"code\":700,\"message\":\"Internal server error\",\"retriable\":true,\"details\":null}"
            .to_string()
    }
}

impl From<ApiError> for Error {
    fn from(error: ApiError) -> Self {
        convert_to_error(&error)
    }
}

impl actix_web::ResponseError for Error {
    fn status_code(&self) -> actix_web::http::StatusCode {
        self.0
            .code
            .try_into()
            .ok()
            .and_then(|c| actix_web::http::StatusCode::from_u16(c).ok())
            .unwrap_or_default()
    }
}

/// A MempoolTransactionRequest is utilized to retrieve a transaction from the
/// mempool.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct MempoolTransactionRequest {
    #[serde(rename = "network_identifier")]
    pub network_identifier: NetworkIdentifier,

    #[serde(rename = "transaction_identifier")]
    pub transaction_identifier: TransactionIdentifier,
}

impl MempoolTransactionRequest {
    pub fn new(
        network_identifier: NetworkIdentifier,
        transaction_identifier: TransactionIdentifier,
    ) -> MempoolTransactionRequest {
        MempoolTransactionRequest {
            network_identifier,
            transaction_identifier,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct NeuronSubaccountComponents {
    #[serde(rename = "public_key")]
    pub public_key: PublicKey,

    #[serde(rename = "neuron_index")]
    #[serde(default)]
    pub neuron_index: u64,
}

/// We use this type to make query to the governance
/// canister about the current neuron information.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
#[serde(tag = "account_type")]
pub enum BalanceAccountType {
    #[serde(rename = "ledger")]
    Ledger,
    #[serde(rename = "neuron")]
    Neuron {
        #[serde(rename = "neuron_id")]
        neuron_id: Option<u64>,

        #[serde(flatten)]
        subaccount_components: Option<NeuronSubaccountComponents>,

        /// If is set to true, the information is
        /// retrieved through an IC update call which may take significantly
        /// longer to execute, but gives strong guarantees that the received
        /// data has not been tampered with.
        /// Otherwise the information is retrieved through a fast query call.
        #[serde(rename = "verified_query")]
        #[serde(skip_serializing_if = "Option::is_none")]
        verified_query: Option<bool>,
    },
}

impl Default for BalanceAccountType {
    fn default() -> Self {
        Self::Ledger
    }
}

/// The type of metadata for the /account/balance endpoint.
#[derive(Clone, Eq, PartialEq, Debug, Default, Deserialize, Serialize)]
pub struct AccountBalanceMetadata {
    #[serde(rename = "account_type")]
    #[serde(flatten)]
    #[serde(default)]
    pub account_type: BalanceAccountType,
}

impl From<AccountBalanceMetadata> for ObjectMap {
    fn from(p: AccountBalanceMetadata) -> Self {
        match serde_json::to_value(p) {
            Ok(serde_json::Value::Object(o)) => o,
            _ => unreachable!(),
        }
    }
}

impl TryFrom<Option<ObjectMap>> for AccountBalanceMetadata {
    type Error = ApiError;
    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse AccountBalanceMetadata metadata from metadata JSON object: {}",
                e
            ))
        })
    }
}

#[test]
fn test_neuron_info_request_parsing() {
    let r1: AccountBalanceMetadata =
        serde_json::from_str(r#"{ "account_type": "neuron", "neuron_id": 5 }"#).unwrap();
    assert_eq!(
        r1,
        AccountBalanceMetadata {
            account_type: BalanceAccountType::Neuron {
                neuron_id: Some(5),
                subaccount_components: None,
                verified_query: None,
            }
        }
    );
    let r2: AccountBalanceMetadata = serde_json::from_str(
        r#"{
            "account_type": "neuron",
            "neuron_index": 5,
            "public_key": {
              "hex_bytes": "1b400d60aaf34eaf6dcbab9bba46001a23497886cf11066f7846933d30e5ad3f",
              "curve_type": "edwards25519"
            }
        }"#,
    )
    .unwrap();
    assert_eq!(
        r2,
        AccountBalanceMetadata {
            account_type: BalanceAccountType::Neuron {
                neuron_id: None,
                subaccount_components: Some(NeuronSubaccountComponents {
                    neuron_index: 5,
                    public_key: PublicKey {
                        hex_bytes:
                            "1b400d60aaf34eaf6dcbab9bba46001a23497886cf11066f7846933d30e5ad3f"
                                .to_string(),
                        curve_type: CurveType::Edwards25519
                    }
                }),
                verified_query: None,
            }
        }
    );

    let r3: AccountBalanceMetadata = serde_json::from_str(
        r#"{
            "account_type": "neuron",
            "public_key": {
              "hex_bytes": "1b400d60aaf34eaf6dcbab9bba46001a23497886cf11066f7846933d30e5ad3f",
              "curve_type": "edwards25519"
            }
        }"#,
    )
    .unwrap();
    assert_eq!(
        r3,
        AccountBalanceMetadata {
            account_type: BalanceAccountType::Neuron {
                neuron_id: None,
                subaccount_components: Some(NeuronSubaccountComponents {
                    neuron_index: 0,
                    public_key: PublicKey {
                        hex_bytes:
                            "1b400d60aaf34eaf6dcbab9bba46001a23497886cf11066f7846933d30e5ad3f"
                                .to_string(),
                        curve_type: CurveType::Edwards25519
                    }
                }),
                verified_query: None,
            }
        }
    );
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum NeuronState {
    #[serde(rename = "NOT_DISSOLVING")]
    NotDissolving,
    #[serde(rename = "SPAWNING")]
    Spawning,
    #[serde(rename = "DISSOLVING")]
    Dissolving,
    #[serde(rename = "DISSOLVED")]
    Dissolved,
}

/// Response for neuron public information.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct NeuronInfoResponse {
    #[serde(rename = "verified_query")]
    pub verified_query: bool,

    #[serde(rename = "retrieved_at_timestamp_seconds")]
    pub retrieved_at_timestamp_seconds: u64,

    /// The current state of the neuron.
    #[serde(rename = "state")]
    pub state: NeuronState,

    /// The current age of the neuron.
    #[serde(rename = "age_seconds")]
    pub age_seconds: u64,

    /// The current dissolve delay of the neuron.
    #[serde(rename = "dissolve_delay_seconds")]
    pub dissolve_delay_seconds: u64,

    /// Current voting power of the neuron.
    #[serde(rename = "voting_power")]
    pub voting_power: u64,

    /// When the Neuron was created. A neuron can only vote on proposals
    /// submitted after its creation date.
    #[serde(rename = "created_timestamp_seconds")]
    pub created_timestamp_seconds: u64,

    /// Current stake of the neuron, in e8s.
    #[serde(rename = "stake_e8s")]
    pub stake_e8s: u64,
}

impl From<NeuronInfoResponse> for ObjectMap {
    fn from(p: NeuronInfoResponse) -> Self {
        match serde_json::to_value(p) {
            Ok(serde_json::Value::Object(o)) => o,
            _ => unreachable!(),
        }
    }
}

impl TryFrom<Option<ObjectMap>> for NeuronInfoResponse {
    type Error = ApiError;
    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse NeuronInfoResponse metadata from metadata JSON object: {}",
                e
            ))
        })
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct QueryBlockRangeRequest {
    pub highest_block_index: u64,
    pub number_of_blocks: u64,
}

impl TryFrom<QueryBlockRangeRequest> for ObjectMap {
    type Error = ApiError;
    fn try_from(d: QueryBlockRangeRequest) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(v) => match v {
                serde_json::Value::Object(ob) => Ok(ob),
                _ => Err(ApiError::internal_error(format!("Could not convert QueryBlockRangeRequest to ObjectMap. Expected type Object but received: {:?}",v)))
            },Err(err) => Err(ApiError::internal_error(format!("Could not convert QueryBlockRangeRequest to ObjectMap: {:?}",err))),
        }
    }
}

impl TryFrom<ObjectMap> for QueryBlockRangeRequest {
    type Error = ApiError;
    fn try_from(o: ObjectMap) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o)).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse QueryBlockRangeRequest from JSON object: {}",
                e
            ))
        })
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct QueryBlockRangeResponse {
    pub blocks: Vec<rosetta_core::objects::Block>,
}

impl TryFrom<QueryBlockRangeResponse> for ObjectMap {
    type Error = ApiError;
    fn try_from(d: QueryBlockRangeResponse) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(v) => match v {
                serde_json::Value::Object(ob) => Ok(ob),
                _ => Err(ApiError::internal_error(format!("Could not convert QueryBlockRangeResponse to ObjectMap. Expected type Object but received: {:?}",v)))
            },Err(err) =>Err(ApiError::internal_error(format!("Could not convert QueryBlockRangeResponse to ObjectMap: {:?}",err))),
        }
    }
}

impl TryFrom<ObjectMap> for QueryBlockRangeResponse {
    type Error = ApiError;
    fn try_from(o: ObjectMap) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o)).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse QueryBlockRangeResponse from JSON object: {}",
                e
            ))
        })
    }
}
