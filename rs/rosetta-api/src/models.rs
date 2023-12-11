pub mod amount;
pub mod operation;
pub mod seconds;
pub mod timestamp;

use crate::errors::convert_to_error;
use crate::request::transaction_operation_results::TransactionOperationResults;
use crate::{convert::from_hex, errors, errors::ApiError, request_types::RequestType};
pub use ic_canister_client_sender::Ed25519KeyPair as EdKeypair;
use ic_canister_client_sender::{ed25519_public_key_from_der, Secp256k1KeyPair};
use ic_crypto_ecdsa_secp256k1;
use ic_types::PrincipalId;
use ic_types::{
    messages::{HttpCallContent, HttpCanisterUpdate, HttpReadStateContent, HttpRequestEnvelope},
    CanisterId,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
pub use rosetta_core::identifiers::*;
pub use rosetta_core::miscellaneous::*;
pub use rosetta_core::objects::*;
pub use rosetta_core::request_types::*;
pub use rosetta_core::response_types::*;
use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};
use std::sync::Arc;

// This file is generated from https://github.com/coinbase/rosetta-specifications using openapi-generator
// Then heavily tweaked because openapi-generator no longer generates valid rust
// code
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstructionSubmitResponse {
    /// Transfers produce a real transaction identifier,
    /// Neuron management requests produce a constant (pseudo) identifier.
    ///
    /// This field contains the transaction id of the last transfer operation.
    /// If a transaction only contains neuron management operations
    /// the constant identifier will be returned.
    pub transaction_identifier: TransactionIdentifier,
    pub metadata: TransactionOperationResults,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstructionHashResponse {
    pub transaction_identifier: TransactionIdentifier,
    pub metadata: ObjectMap,
}

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

/// ConstructionCombineRequest is the input to the `/construction/combine`
/// endpoint. It contains the unsigned transaction blob returned by
/// `/construction/payloads` and all required signatures to create a network
/// transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct ConstructionCombineRequest {
    #[serde(rename = "network_identifier")]
    pub network_identifier: NetworkIdentifier,

    #[serde(rename = "unsigned_transaction")]
    pub unsigned_transaction: String, // = CBOR+hex-encoded 'UnsignedTransaction'

    #[serde(rename = "signatures")]
    pub signatures: Vec<Signature>,
}

impl ConstructionCombineRequest {
    pub fn new(
        network_identifier: NetworkIdentifier,
        unsigned_transaction: String,
        signatures: Vec<Signature>,
    ) -> ConstructionCombineRequest {
        ConstructionCombineRequest {
            network_identifier,
            unsigned_transaction,
            signatures,
        }
    }

    pub fn unsigned_transaction(&self) -> Result<UnsignedTransaction, ApiError> {
        serde_cbor::from_slice(&from_hex(&self.unsigned_transaction)?).map_err(|e| {
            ApiError::invalid_request(format!("Could not deserialize unsigned transaction: {}", e))
        })
    }
}

/// ConstructionCombineResponse is returned by `/construction/combine`. The
/// network payload will be sent directly to the `construction/submit` endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct ConstructionCombineResponse {
    #[serde(rename = "signed_transaction")]
    pub signed_transaction: String, // = CBOR+hex-encoded 'SignedTransaction'
}

impl ConstructionCombineResponse {
    pub fn new(signed_transaction: String) -> ConstructionCombineResponse {
        ConstructionCombineResponse { signed_transaction }
    }

    pub fn signed_transaction(&self) -> Result<SignedTransaction, ApiError> {
        serde_cbor::from_slice(&from_hex(&self.signed_transaction)?).map_err(|e| {
            ApiError::invalid_request(format!(
                "Cannot deserialize signed transaction in /construction/combine response: {}",
                e
            ))
        })
    }
}

/// The type (encoded as CBOR) returned by /construction/combine, containing the
/// IC calls to submit the transaction and to check the result.
pub type SignedTransaction = Vec<Request>;

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

/// ConstructionHashRequest is the input to the `/construction/hash` endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct ConstructionHashRequest {
    #[serde(rename = "network_identifier")]
    pub network_identifier: NetworkIdentifier,

    #[serde(rename = "signed_transaction")]
    pub signed_transaction: String,
}

impl ConstructionHashRequest {
    pub fn new(
        network_identifier: NetworkIdentifier,
        signed_transaction: String,
    ) -> ConstructionHashRequest {
        ConstructionHashRequest {
            network_identifier,
            signed_transaction,
        }
    }

    pub fn signed_transaction(&self) -> Result<SignedTransaction, ApiError> {
        serde_cbor::from_slice(&from_hex(&self.signed_transaction)?).map_err(|e| {
            ApiError::invalid_request(format!(
                "Cannot deserialize the hash request in CBOR format because of: {}",
                e
            ))
        })
    }
}

/// A ConstructionMetadataRequest is utilized to get information required to
/// construct a transaction. The Options object used to specify which metadata
/// to return is left purposely unstructured to allow flexibility for
/// implementers.  Optionally, the request can also include an array of
/// PublicKeys associated with the AccountIdentifiers returned in
/// ConstructionPreprocessResponse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct ConstructionMetadataRequest {
    #[serde(rename = "network_identifier")]
    pub network_identifier: NetworkIdentifier,

    /// Some blockchains require different metadata for different types of
    /// transaction construction (ex: delegation versus a transfer). Instead of
    /// requiring a blockchain node to return all possible types of metadata for
    /// construction (which may require multiple node fetches), the client can
    /// populate an options object to limit the metadata returned to only the
    /// subset required.
    #[serde(rename = "options")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub options: Option<ConstructionMetadataRequestOptions>,

    #[serde(rename = "public_keys")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_keys: Option<Vec<PublicKey>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstructionMetadataRequestOptions {
    pub request_types: Vec<RequestType>,
}

impl ConstructionMetadataRequest {
    pub fn new(network_identifier: NetworkIdentifier) -> ConstructionMetadataRequest {
        ConstructionMetadataRequest {
            network_identifier,
            options: None,
            public_keys: None,
        }
    }
}

/// The ConstructionMetadataResponse returns network-specific metadata used for
/// transaction construction.  Optionally, the implementer can return the
/// suggested fee associated with the transaction being constructed. The caller
/// may use this info to adjust the intent of the transaction or to create a
/// transaction with a different account that can pay the suggested fee.
/// Suggested fee is an array in case fee payment must occur in multiple
/// currencies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct ConstructionMetadataResponse {
    #[serde(rename = "metadata")]
    pub metadata: ConstructionPayloadsRequestMetadata,

    #[serde(rename = "suggested_fee")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub suggested_fee: Option<Vec<Amount>>,
}

/// ConstructionParseRequest is the input to the `/construction/parse` endpoint.
/// It allows the caller to parse either an unsigned or signed transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct ConstructionParseRequest {
    #[serde(rename = "network_identifier")]
    pub network_identifier: NetworkIdentifier,

    /// Signed is a boolean indicating whether the transaction is signed.
    #[serde(rename = "signed")]
    pub signed: bool,

    /// This must be either the unsigned transaction blob returned by
    /// `/construction/payloads` or the signed transaction blob returned by
    /// `/construction/combine`.
    #[serde(rename = "transaction")]
    pub transaction: String,
}

pub enum ParsedTransaction {
    Signed(SignedTransaction),
    Unsigned(UnsignedTransaction),
}

impl ConstructionParseRequest {
    pub fn new(
        network_identifier: NetworkIdentifier,
        signed: bool,
        transaction: String,
    ) -> ConstructionParseRequest {
        ConstructionParseRequest {
            network_identifier,
            signed,
            transaction,
        }
    }

    pub fn transaction(&self) -> Result<ParsedTransaction, ApiError> {
        if self.signed {
            Ok(ParsedTransaction::Signed(
                serde_cbor::from_slice(&from_hex(&self.transaction)?).map_err(|e| {
                    ApiError::invalid_request(format!("Could not decode signed transaction: {}", e))
                })?,
            ))
        } else {
            Ok(ParsedTransaction::Unsigned(
                serde_cbor::from_slice(&from_hex(&self.transaction)?).map_err(|e| {
                    ApiError::invalid_request(format!(
                        "Could not decode unsigned transaction: {}",
                        e
                    ))
                })?,
            ))
        }
    }
}

/// ConstructionParseResponse contains an array of operations that occur in a
/// transaction blob. This should match the array of operations provided to
/// `/construction/preprocess` and `/construction/payloads`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct ConstructionParseResponse {
    #[serde(rename = "operations")]
    pub operations: Vec<Operation>,

    /// [DEPRECATED by `account_identifier_signers` in `v1.4.4`] All signers
    /// (addresses) of a particular transaction. If the transaction is unsigned,
    /// it should be empty.
    #[serde(rename = "signers")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signers: Option<Vec<String>>,

    #[serde(rename = "account_identifier_signers")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_identifier_signers: Option<Vec<AccountIdentifier>>,

    #[serde(rename = "metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ObjectMap>,
}

impl ConstructionParseResponse {
    pub fn new(operations: Vec<Operation>) -> ConstructionParseResponse {
        ConstructionParseResponse {
            operations,
            signers: None,
            account_identifier_signers: None,
            metadata: None,
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

/// ConstructionPayloadsRequest is the request to `/construction/payloads`. It
/// contains the network, a slice of operations, and arbitrary metadata that was
/// returned by the call to `/construction/metadata`.  Optionally, the request
/// can also include an array of PublicKeys associated with the
/// AccountIdentifiers returned in ConstructionPreprocessResponse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct ConstructionPayloadsRequest {
    #[serde(rename = "network_identifier")]
    pub network_identifier: NetworkIdentifier,

    #[serde(rename = "operations")]
    pub operations: Vec<Operation>,

    #[serde(rename = "metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ConstructionPayloadsRequestMetadata>,

    #[serde(rename = "public_keys")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_keys: Option<Vec<PublicKey>>,
}

impl ConstructionPayloadsRequest {
    pub fn new(
        network_identifier: NetworkIdentifier,
        operations: Vec<Operation>,
    ) -> ConstructionPayloadsRequest {
        ConstructionPayloadsRequest {
            network_identifier,
            operations,
            metadata: None,
            public_keys: None,
        }
    }
}

/// ConstructionTransactionResponse is returned by `/construction/payloads`. It
/// contains an unsigned transaction blob (that is usually needed to construct
/// the a network transaction from a collection of signatures) and an array of
/// payloads that must be signed by the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct ConstructionPayloadsResponse {
    #[serde(rename = "unsigned_transaction")]
    pub unsigned_transaction: String, // = CBOR+hex-encoded 'UnsignedTransaction'

    #[serde(rename = "payloads")]
    pub payloads: Vec<SigningPayload>,
}

impl ConstructionPayloadsResponse {
    pub fn new(
        unsigned_transaction: &UnsignedTransaction,
        payloads: Vec<SigningPayload>,
    ) -> ConstructionPayloadsResponse {
        ConstructionPayloadsResponse {
            unsigned_transaction: hex::encode(serde_cbor::to_vec(unsigned_transaction).unwrap()),
            payloads,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedTransaction {
    pub updates: Vec<(RequestType, HttpCanisterUpdate)>,
    pub ingress_expiries: Vec<u64>,
}

/// ConstructionPreprocessRequest is passed to the `/construction/preprocess`
/// endpoint so that a Rosetta implementation can determine which metadata it
/// needs to request for construction.  Metadata provided in this object should
/// NEVER be a product of live data (i.e. the caller must follow some
/// network-specific data fetching strategy outside of the Construction API to
/// populate required Metadata). If live data is required for construction, it
/// MUST be fetched in the call to `/construction/metadata`.  The caller can
/// provide a max fee they are willing to pay for a transaction. This is an
/// array in the case fees must be paid in multiple currencies.  The caller can
/// also provide a suggested fee multiplier to indicate that the suggested fee
/// should be scaled. This may be used to set higher fees for urgent
/// transactions or to pay lower fees when there is less urgency. It is assumed
/// that providing a very low multiplier (like 0.0001) will never lead to a
/// transaction being created with a fee less than the minimum network fee (if
/// applicable).  In the case that the caller provides both a max fee and a
/// suggested fee multiplier, the max fee will set an upper bound on the
/// suggested fee (regardless of the multiplier provided).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct ConstructionPreprocessRequest {
    #[serde(rename = "network_identifier")]
    pub network_identifier: NetworkIdentifier,

    #[serde(rename = "operations")]
    pub operations: Vec<Operation>,

    #[serde(rename = "metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ObjectMap>,

    #[serde(rename = "max_fee")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fee: Option<Vec<Amount>>,

    #[serde(rename = "suggested_fee_multiplier")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_fee_multiplier: Option<f64>,
}

impl ConstructionPreprocessRequest {
    pub fn new(
        network_identifier: NetworkIdentifier,
        operations: Vec<Operation>,
    ) -> ConstructionPreprocessRequest {
        ConstructionPreprocessRequest {
            network_identifier,
            operations,
            metadata: None,
            max_fee: None,
            suggested_fee_multiplier: None,
        }
    }
}

/// ConstructionPreprocessResponse contains `options` that will be sent
/// unmodified to `/construction/metadata`. If it is not necessary to make a
/// request to `/construction/metadata`, `options` should be omitted.   Some
/// blockchains require the PublicKey of particular AccountIdentifiers to
/// construct a valid transaction. To fetch these PublicKeys, populate
/// `required_public_keys` with the AccountIdentifiers associated with the
/// desired PublicKeys. If it is not necessary to retrieve any PublicKeys for
/// construction, `required_public_keys` should be omitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct ConstructionPreprocessResponse {
    /// The options that will be sent directly to `/construction/metadata` by
    /// the caller.
    #[serde(rename = "options")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<ConstructionMetadataRequestOptions>,

    #[serde(rename = "required_public_keys")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_public_keys: Option<Vec<AccountIdentifier>>,
}

impl ConstructionPreprocessResponse {
    pub fn new() -> ConstructionPreprocessResponse {
        ConstructionPreprocessResponse {
            options: None,
            required_public_keys: None,
        }
    }
}

/// The transaction submission request includes a signed transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct ConstructionSubmitRequest {
    #[serde(rename = "network_identifier")]
    pub network_identifier: NetworkIdentifier,

    #[serde(rename = "signed_transaction")]
    pub signed_transaction: String, // = CBOR+hex-encoded 'SignedTransaction'
}

impl ConstructionSubmitRequest {
    pub fn new(
        network_identifier: NetworkIdentifier,
        signed_transaction: SignedTransaction,
    ) -> ConstructionSubmitRequest {
        ConstructionSubmitRequest {
            network_identifier,
            signed_transaction: hex::encode(serde_cbor::to_vec(&signed_transaction).unwrap()),
        }
    }

    pub fn signed_transaction(&self) -> Result<SignedTransaction, ApiError> {
        serde_cbor::from_slice(&from_hex(&self.signed_transaction)?).map_err(|e| {
            ApiError::invalid_request(format!(
                "Cannot deserialize the submit request in CBOR format because of: {}",
                e
            ))
        })
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkIdentifier(pub rosetta_core::identifiers::NetworkIdentifier);
impl TryInto<CanisterId> for &NetworkIdentifier {
    type Error = ApiError;
    fn try_into(self) -> Result<CanisterId, Self::Error> {
        let principal_bytes = hex::decode(&self.0.network)
            .map_err(|_| ApiError::InvalidNetworkId(false, "not hex".into()))?;
        let principal_id = PrincipalId::try_from(&principal_bytes)
            .map_err(|_| ApiError::InvalidNetworkId(false, "invalid principal id".into()))?;
        CanisterId::try_from(principal_id)
            .map_err(|_| ApiError::InvalidNetworkId(false, "invalid canister id".into()))
    }
}

impl From<rosetta_core::identifiers::NetworkIdentifier> for NetworkIdentifier {
    fn from(value: rosetta_core::identifiers::NetworkIdentifier) -> Self {
        Self(value)
    }
}

impl From<NetworkIdentifier> for rosetta_core::identifiers::NetworkIdentifier {
    fn from(value: NetworkIdentifier) -> Self {
        value.0
    }
}

impl NetworkIdentifier {
    pub fn new(blockchain: String, network: String) -> NetworkIdentifier {
        Self(rosetta_core::identifiers::NetworkIdentifier::new(
            blockchain, network,
        ))
    }
}

/// Signature contains the payload that was signed, the public keys of the
/// keypairs used to produce the signature, the signature (encoded in hex), and
/// the SignatureType.  PublicKey is often times not known during construction
/// of the signing payloads but may be needed to combine signatures properly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct Signature {
    #[serde(rename = "signing_payload")]
    pub signing_payload: SigningPayload,

    #[serde(rename = "public_key")]
    pub public_key: PublicKey,

    #[serde(rename = "signature_type")]
    pub signature_type: SignatureType,

    #[serde(rename = "hex_bytes")]
    pub hex_bytes: String,
}

impl Signature {
    pub fn new(
        signing_payload: SigningPayload,
        public_key: PublicKey,
        signature_type: SignatureType,
        hex_bytes: String,
    ) -> Signature {
        Signature {
            signing_payload,
            public_key,
            signature_type,
            hex_bytes,
        }
    }
}

/// SignatureType is the type of a cryptographic signature.  * ecdsa: `r (32-bytes) || s (32-bytes)` - `64 bytes` * ecdsa_recovery: `r (32-bytes) || s (32-bytes) || v (1-byte)` - `65 bytes` * ed25519: `R (32-byte) || s (32-bytes)` - `64 bytes` * schnorr_1: `r (32-bytes) || s (32-bytes)` - `64 bytes`  (schnorr signature implemented by Zilliqa where both `r` and `s` are scalars encoded as `32-bytes` values, most significant byte first.) * schnorr_poseidon: `r (32-bytes) || s (32-bytes)` where s = Hash(1st pk || 2nd pk || r) - `64 bytes`  (schnorr signature w/ Poseidon hash function implemented by O(1) Labs where both `r` and `s` are scalars encoded as `32-bytes` values, least significant byte first. https://github.com/CodaProtocol/signer-reference/blob/master/schnorr.ml )
/// Enumeration of values.
/// Since this enum's variants do not hold data, we can easily define them them
/// as `#[repr(C)]` which helps with FFI.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGenericEnum))]
pub enum SignatureType {
    #[serde(rename = "ecdsa")]
    Ecdsa,
    #[serde(rename = "ecdsa_recovery")]
    EcdsaRecovery,
    #[serde(rename = "ed25519")]
    Ed25519,
    #[serde(rename = "schnorr_1")]
    Schnorr1,
    #[serde(rename = "schnorr_poseidon")]
    SchnorrPoseidon,
}

impl ::std::fmt::Display for SignatureType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            SignatureType::Ecdsa => write!(f, "ecdsa"),
            SignatureType::EcdsaRecovery => write!(f, "ecdsa_recovery"),
            SignatureType::Ed25519 => write!(f, "ed25519"),
            SignatureType::Schnorr1 => write!(f, "schnorr_1"),
            SignatureType::SchnorrPoseidon => write!(f, "schnorr_poseidon"),
        }
    }
}

impl ::std::str::FromStr for SignatureType {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ecdsa" => Ok(SignatureType::Ecdsa),
            "ecdsa_recovery" => Ok(SignatureType::EcdsaRecovery),
            "ed25519" => Ok(SignatureType::Ed25519),
            "schnorr_1" => Ok(SignatureType::Schnorr1),
            "schnorr_poseidon" => Ok(SignatureType::SchnorrPoseidon),
            _ => Err(()),
        }
    }
}

/// SigningPayload is signed by the client with the keypair associated with an
/// AccountIdentifier using the specified SignatureType.  SignatureType can be
/// optionally populated if there is a restriction on the signature scheme that
/// can be used to sign the payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct SigningPayload {
    /// [DEPRECATED by `account_identifier` in `v1.4.4`] The network-specific
    /// address of the account that should sign the payload.
    #[serde(rename = "address")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,

    #[serde(rename = "account_identifier")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_identifier: Option<AccountIdentifier>,

    #[serde(rename = "hex_bytes")]
    pub hex_bytes: String,

    #[serde(rename = "signature_type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_type: Option<SignatureType>,
}

impl SigningPayload {
    pub fn new(hex_bytes: String) -> SigningPayload {
        SigningPayload {
            address: None,
            account_identifier: None,
            hex_bytes,
            signature_type: None,
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

pub trait RosettaSupportedKeyPair {
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
    fn generate_from_u64(seed: u64) -> Self;
    fn get_pb_key(&self) -> Vec<u8>;
    fn get_curve_type(&self) -> CurveType;
    fn generate_principal_id(&self) -> Result<PrincipalId, ApiError>;
    fn hex_encode_pk(&self) -> String;
    fn hex_decode_pk(pk_encoded: &str) -> Result<Vec<u8>, ApiError>;
    fn get_principal_id(pk_encoded: &str) -> Result<PrincipalId, ApiError>;
    fn der_encode_pk(pk: Vec<u8>) -> Result<Vec<u8>, ApiError>;
    fn der_decode_pk(pk_encoded: Vec<u8>) -> Result<Vec<u8>, ApiError>;
}

impl RosettaSupportedKeyPair for EdKeypair {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.sign(msg).to_vec()
    }
    fn generate_from_u64(seed: u64) -> EdKeypair {
        let mut rng = StdRng::seed_from_u64(seed);
        EdKeypair::generate(&mut rng)
    }
    fn get_pb_key(&self) -> Vec<u8> {
        self.public_key.to_vec()
    }
    fn get_curve_type(&self) -> CurveType {
        CurveType::Edwards25519
    }

    fn generate_principal_id(&self) -> Result<PrincipalId, ApiError> {
        let public_key_der =
            ic_canister_client_sender::ed25519_public_key_to_der(self.public_key.to_vec());
        let pid = PrincipalId::new_self_authenticating(&public_key_der);
        Ok(pid)
    }
    fn hex_encode_pk(&self) -> String {
        hex::encode(self.public_key)
    }
    fn hex_decode_pk(pk_encoded: &str) -> Result<Vec<u8>, ApiError> {
        hex::decode(pk_encoded)
            .map_err(|e| ApiError::invalid_request(format!("Hex could not be decoded {}", e)))
    }

    fn get_principal_id(pk_encoded: &str) -> Result<PrincipalId, ApiError> {
        match EdKeypair::hex_decode_pk(pk_encoded) {
            Ok(pk_decoded) => {
                let pub_der = ic_canister_client_sender::ed25519_public_key_to_der(pk_decoded);
                Ok(PrincipalId::new_self_authenticating(&pub_der))
            }
            Err(e) => Err(e),
        }
    }
    fn der_encode_pk(pk: Vec<u8>) -> Result<Vec<u8>, ApiError> {
        Ok(ic_canister_client_sender::ed25519_public_key_to_der(pk))
    }
    fn der_decode_pk(pk_encoded: Vec<u8>) -> Result<Vec<u8>, ApiError> {
        Ok(ed25519_public_key_from_der(pk_encoded))
    }
}

impl RosettaSupportedKeyPair for Secp256k1KeyPair {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        Secp256k1KeyPair::sign(self, msg)
    }
    fn generate_from_u64(seed: u64) -> Secp256k1KeyPair {
        let mut rng = StdRng::seed_from_u64(seed);
        Secp256k1KeyPair::generate(&mut rng)
    }
    //The default serialization version for the Public Key is sec1
    fn get_pb_key(&self) -> Vec<u8> {
        self.get_public_key().serialize_sec1(false)
    }
    fn get_curve_type(&self) -> CurveType {
        CurveType::Secp256K1
    }
    fn generate_principal_id(&self) -> Result<PrincipalId, ApiError> {
        let public_key_der = self.get_public_key().serialize_der();
        let pid = PrincipalId::new_self_authenticating(&public_key_der);
        Ok(pid)
    }
    fn hex_encode_pk(&self) -> String {
        hex::encode(self.get_public_key().serialize_sec1(false))
    }
    fn hex_decode_pk(pk_hex_encoded: &str) -> Result<Vec<u8>, ApiError> {
        hex::decode(pk_hex_encoded)
            .map_err(|e| ApiError::invalid_request(format!("Hex could not be decoded {}", e)))
    }
    fn get_principal_id(pk_hex_encoded: &str) -> Result<PrincipalId, ApiError> {
        match Secp256k1KeyPair::hex_decode_pk(pk_hex_encoded) {
            Ok(pk_decoded) => {
                let public_key_der =
                    ic_crypto_ecdsa_secp256k1::PublicKey::deserialize_sec1(&pk_decoded)
                        .map_err(|e| {
                            ApiError::invalid_request(format!("Hex could not be decoded {:?}", e))
                        })?
                        .serialize_der();
                Ok(PrincipalId::new_self_authenticating(&public_key_der))
            }
            Err(e) => Err(e),
        }
    }
    fn der_encode_pk(pk_sec1: Vec<u8>) -> Result<Vec<u8>, ApiError> {
        Ok(
            ic_crypto_ecdsa_secp256k1::PublicKey::deserialize_sec1(&pk_sec1)
                .map_err(|e| {
                    ApiError::invalid_request(format!("Hex could not be decoded {:?}", e))
                })?
                .serialize_der(),
        )
    }
    fn der_decode_pk(pk_der: Vec<u8>) -> Result<Vec<u8>, ApiError> {
        Ok(
            ic_crypto_ecdsa_secp256k1::PublicKey::deserialize_der(&pk_der)
                .map_err(|e| {
                    ApiError::invalid_request(format!("Hex could not be decoded {:?}", e))
                })?
                .serialize_sec1(false),
        )
    }
}

impl RosettaSupportedKeyPair for Arc<EdKeypair> {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        EdKeypair::sign(self, msg).to_vec()
    }
    fn generate_from_u64(seed: u64) -> Arc<EdKeypair> {
        let mut rng = StdRng::seed_from_u64(seed);
        Arc::new(EdKeypair::generate(&mut rng))
    }
    fn get_pb_key(&self) -> Vec<u8> {
        self.public_key.to_vec()
    }
    fn get_curve_type(&self) -> CurveType {
        CurveType::Edwards25519
    }
    fn generate_principal_id(&self) -> Result<PrincipalId, ApiError> {
        let public_key_der =
            ic_canister_client_sender::ed25519_public_key_to_der(self.public_key.to_vec());
        let pid = PrincipalId::new_self_authenticating(&public_key_der);
        Ok(pid)
    }
    fn hex_encode_pk(&self) -> String {
        hex::encode(self.public_key)
    }
    fn hex_decode_pk(pk_encoded: &str) -> Result<Vec<u8>, ApiError> {
        hex::decode(pk_encoded)
            .map_err(|e| ApiError::invalid_request(format!("Hex could not be decoded {}", e)))
    }
    fn der_encode_pk(pk: Vec<u8>) -> Result<Vec<u8>, ApiError> {
        Ok(ic_canister_client_sender::ed25519_public_key_to_der(pk))
    }
    fn der_decode_pk(pk_encoded: Vec<u8>) -> Result<Vec<u8>, ApiError> {
        Ok(ed25519_public_key_from_der(pk_encoded))
    }
    fn get_principal_id(pk_encoded: &str) -> Result<PrincipalId, ApiError> {
        match EdKeypair::hex_decode_pk(pk_encoded) {
            Ok(pk_decoded) => {
                let pub_der = ic_canister_client_sender::ed25519_public_key_to_der(pk_decoded);
                Ok(PrincipalId::new_self_authenticating(&pub_der))
            }
            Err(e) => Err(e),
        }
    }
}

impl RosettaSupportedKeyPair for Arc<Secp256k1KeyPair> {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        Secp256k1KeyPair::sign(self, msg)
    }
    fn generate_from_u64(seed: u64) -> Arc<Secp256k1KeyPair> {
        let mut rng = StdRng::seed_from_u64(seed);
        Arc::new(Secp256k1KeyPair::generate(&mut rng))
    }
    //The default serialization version for the Public Key is sec1
    fn get_pb_key(&self) -> Vec<u8> {
        self.get_public_key().serialize_sec1(false)
    }
    fn get_curve_type(&self) -> CurveType {
        CurveType::Secp256K1
    }
    fn generate_principal_id(&self) -> Result<PrincipalId, ApiError> {
        let public_key_der = self.get_public_key().serialize_der();
        let pid = PrincipalId::new_self_authenticating(&public_key_der);
        Ok(pid)
    }
    fn hex_encode_pk(&self) -> String {
        hex::encode(self.get_public_key().serialize_sec1(false))
    }
    fn hex_decode_pk(pk_hex_encoded: &str) -> Result<Vec<u8>, ApiError> {
        hex::decode(pk_hex_encoded)
            .map_err(|e| ApiError::invalid_request(format!("Hex could not be decoded {}", e)))
    }
    fn get_principal_id(pk_hex_encoded: &str) -> Result<PrincipalId, ApiError> {
        match Secp256k1KeyPair::hex_decode_pk(pk_hex_encoded) {
            Ok(pk_decoded) => {
                let public_key_der =
                    ic_crypto_ecdsa_secp256k1::PublicKey::deserialize_sec1(&pk_decoded)
                        .map_err(|e| {
                            ApiError::invalid_request(format!("Hex could not be decoded {:?}", e))
                        })?
                        .serialize_der();
                Ok(PrincipalId::new_self_authenticating(&public_key_der))
            }
            Err(e) => Err(e),
        }
    }
    fn der_encode_pk(pk_sec1: Vec<u8>) -> Result<Vec<u8>, ApiError> {
        Ok(
            ic_crypto_ecdsa_secp256k1::PublicKey::deserialize_sec1(&pk_sec1)
                .map_err(|e| {
                    ApiError::invalid_request(format!("Hex could not be decoded {:?}", e))
                })?
                .serialize_der(),
        )
    }
    fn der_decode_pk(pk_der: Vec<u8>) -> Result<Vec<u8>, ApiError> {
        Ok(
            ic_crypto_ecdsa_secp256k1::PublicKey::deserialize_der(&pk_der)
                .map_err(|e| {
                    ApiError::invalid_request(format!("Hex could not be decoded {:?}", e))
                })?
                .serialize_sec1(false),
        )
    }
}
