pub mod amount;
pub mod operation;
pub mod seconds;
pub mod timestamp;

use crate::errors::convert_to_error;
use crate::{convert::from_hex, errors, errors::ApiError, request_types::RequestType};
pub use ic_canister_client_sender::Ed25519KeyPair as EdKeypair;
use ic_types::messages::{
    HttpCallContent, HttpCanisterUpdate, HttpReadStateContent, HttpRequestEnvelope,
};
pub use rosetta_core::identifiers::*;
pub use rosetta_core::miscellaneous::*;
pub use rosetta_core::objects::*;
pub use rosetta_core::request_types::*;
pub use rosetta_core::response_types::*;
use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};
use std::str::FromStr;

/// An AccountBalanceRequest is utilized to make a balance request on the
/// /account/balance endpoint. If the block_identifier is populated, a
/// historical balance query should be performed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct AccountBalanceRequest {
    #[serde(rename = "network_identifier")]
    pub network_identifier: NetworkIdentifier,

    #[serde(rename = "account_identifier")]
    pub account_identifier: AccountIdentifier,

    #[serde(rename = "block_identifier")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_identifier: Option<PartialBlockIdentifier>,

    #[serde(rename = "metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<AccountBalanceMetadata>,
}

impl AccountBalanceRequest {
    pub fn new(
        network_identifier: NetworkIdentifier,
        account_identifier: AccountIdentifier,
    ) -> AccountBalanceRequest {
        AccountBalanceRequest {
            network_identifier,
            account_identifier,
            block_identifier: None,
            metadata: None,
        }
    }
}

/// An AccountBalanceResponse is returned on the /account/balance endpoint. If
/// an account has a balance for each AccountIdentifier describing it (ex: an
/// ERC-20 token balance on a few smart contracts), an account balance request
/// must be made with each AccountIdentifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct AccountBalanceResponse {
    #[serde(rename = "block_identifier")]
    pub block_identifier: BlockIdentifier,

    /// A single account may have a balance in multiple currencies.
    #[serde(rename = "balances")]
    pub balances: Vec<Amount>,

    /// Account-based blockchains that utilize a nonce or sequence number should
    /// include that number in the metadata. This number could be unique to the
    /// identifier or global across the account address.
    #[serde(rename = "metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<NeuronInfoResponse>,
}

impl AccountBalanceResponse {
    pub fn new(block_identifier: BlockIdentifier, balances: Vec<Amount>) -> AccountBalanceResponse {
        AccountBalanceResponse {
            block_identifier,
            balances,
            metadata: None,
        }
    }
}

/// CallRequest is the input to the `/call`
/// endpoint. It contains the method name the user wants to call and some parameters specific for the method call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct CallRequest {
    #[serde(rename = "network_identifier")]
    pub network_identifier: NetworkIdentifier,

    #[serde(rename = "method_name")]
    pub method_name: String,

    #[serde(rename = "parameters")]
    pub parameters: ObjectMap,
}

impl CallRequest {
    pub fn new(
        network_identifier: NetworkIdentifier,
        method_name: String,
        parameters: ObjectMap,
    ) -> CallRequest {
        CallRequest {
            network_identifier,
            method_name,
            parameters,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct CallResponse {
    #[serde(rename = "result")]
    pub result: ObjectMap,
}

impl CallResponse {
    pub fn new(result: ObjectMap) -> CallResponse {
        CallResponse { result }
    }
}

/// The type (encoded as CBOR) returned by /construction/combine, containing the
/// IC calls to submit the transaction and to check the result.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
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
impl ToString for SignedTransaction {
    fn to_string(&self) -> String {
        hex::encode(serde_cbor::to_vec(self).unwrap())
    }
}
/// A vector of update/read-state calls for different ingress windows
/// of the same call.
pub type Request = (RequestType, Vec<EnvelopePair>);

/// A signed IC update call and the corresponding read-state call for
/// a particular ingress window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstructionDeriveRequestMetadata {
    #[serde(flatten)]
    pub account_type: AccountType,
}

impl From<ConstructionDeriveRequestMetadata> for ObjectMap {
    fn from(p: ConstructionDeriveRequestMetadata) -> Self {
        match serde_json::to_value(p) {
            Ok(serde_json::Value::Object(o)) => o,
            _ => unreachable!(),
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstructionMetadataRequestOptions {
    pub request_types: Vec<RequestType>,
}

impl From<ConstructionMetadataRequestOptions> for ObjectMap {
    fn from(p: ConstructionMetadataRequestOptions) -> Self {
        match serde_json::to_value(p) {
            Ok(serde_json::Value::Object(o)) => o,
            _ => unreachable!(),
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
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
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

impl From<ConstructionPayloadsRequestMetadata> for ObjectMap {
    fn from(p: ConstructionPayloadsRequestMetadata) -> Self {
        match serde_json::to_value(p) {
            Ok(serde_json::Value::Object(o)) => o,
            _ => unreachable!(),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedTransaction {
    pub updates: Vec<(RequestType, HttpCanisterUpdate)>,
    pub ingress_expiries: Vec<u64>,
}

impl ToString for UnsignedTransaction {
    fn to_string(&self) -> String {
        hex::encode(serde_cbor::to_vec(self).unwrap())
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
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

/// TransactionIdentifierResponse contains the transaction_identifier of a
/// transaction that was submitted to either `/construction/hash` or
/// `/construction/submit`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct TransactionIdentifierResponse {
    #[serde(rename = "transaction_identifier")]
    pub transaction_identifier: TransactionIdentifier,

    #[serde(rename = "metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ObjectMap>,
}

impl TransactionIdentifierResponse {
    pub fn new(transaction_identifier: TransactionIdentifier) -> TransactionIdentifierResponse {
        TransactionIdentifierResponse {
            transaction_identifier,
            metadata: None,
        }
    }
}

/// Operator is used by query-related endpoints to determine how to apply
/// conditions. If this field is not populated, the default and value will be
/// used.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGenericEnum))]
pub enum Operator {
    #[serde(rename = "or")]
    Or,
    #[serde(rename = "and")]
    And,
}

impl ::std::fmt::Display for Operator {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Operator::Or => write!(f, "or"),
            Operator::And => write!(f, "and"),
        }
    }
}

/// SearchTransactionsRequest models a small subset of the /search/transactions
/// endpoint. Currently we only support looking up a transaction given its hash;
/// this functionality is desired by our crypto exchanges partners.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct SearchTransactionsRequest {
    #[serde(rename = "network_identifier")]
    pub network_identifier: NetworkIdentifier,

    #[serde(rename = "operator")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator: Option<Operator>,

    #[serde(rename = "max_block")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_block: Option<i64>,

    #[serde(rename = "offset")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,

    #[serde(rename = "limit")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,

    #[serde(rename = "transaction_identifier")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_identifier: Option<TransactionIdentifier>,

    #[serde(rename = "account_identifier")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_identifier: Option<AccountIdentifier>,

    #[serde(rename = "coin_identifier")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coin_identifier: Option<CoinIdentifier>,

    #[serde(rename = "currency")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<Currency>,

    #[serde(rename = "status")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,

    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub _type: Option<String>,

    #[serde(rename = "address")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,

    #[serde(rename = "success")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success: Option<bool>,
}

impl SearchTransactionsRequest {
    pub fn new(
        network_identifier: NetworkIdentifier,
        transaction_identifier: Option<TransactionIdentifier>,
        account_identifier: Option<AccountIdentifier>,
    ) -> SearchTransactionsRequest {
        SearchTransactionsRequest {
            network_identifier,
            operator: None,
            max_block: None,
            offset: None,
            limit: None,
            transaction_identifier,
            account_identifier,
            coin_identifier: None,
            currency: None,
            status: None,
            _type: None,
            address: None,
            success: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct BlockTransaction {
    #[serde(rename = "block_identifier")]
    pub block_identifier: BlockIdentifier,

    #[serde(rename = "transaction")]
    pub transaction: Transaction,
}

impl BlockTransaction {
    pub fn new(block_identifier: BlockIdentifier, transaction: Transaction) -> BlockTransaction {
        BlockTransaction {
            block_identifier,
            transaction,
        }
    }
}

/// SearchTransactionsResponse contains an ordered collection of
/// BlockTransactions that match the query in SearchTransactionsRequest. These
/// BlockTransactions are sorted from most recent block to oldest block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct SearchTransactionsResponse {
    #[serde(rename = "transactions")]
    pub transactions: Vec<BlockTransaction>,

    #[serde(rename = "total_count")]
    pub total_count: i64,

    #[serde(rename = "next_offset")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<i64>,
}

impl SearchTransactionsResponse {
    pub fn new(
        transactions: Vec<BlockTransaction>,
        total_count: i64,
        next_offset: Option<i64>,
    ) -> SearchTransactionsResponse {
        SearchTransactionsResponse {
            transactions,
            total_count,
            next_offset,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct NeuronSubaccountComponents {
    #[serde(rename = "public_key")]
    pub public_key: PublicKey,

    #[serde(rename = "neuron_index")]
    #[serde(default)]
    pub neuron_index: u64,
}

/// We use this type to make query to the governance
/// canister about the current neuron information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
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
#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct AccountBalanceMetadata {
    #[serde(rename = "account_type")]
    #[serde(flatten)]
    #[serde(default)]
    pub account_type: BalanceAccountType,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
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
