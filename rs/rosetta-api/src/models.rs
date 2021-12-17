use crate::{
    convert::from_hex, errors::ApiError, request_types::RequestType,
    transaction_id::TransactionIdentifier,
};
use ic_types::{
    messages::{HttpCanisterUpdate, HttpReadStateContent, HttpRequestEnvelope, HttpSubmitContent},
    CanisterId,
};
use serde::{Deserialize, Serialize};
use std::{
    convert::{TryFrom, TryInto},
    fmt::Display,
};

// This file is generated from https://github.com/coinbase/rosetta-specifications using openapi-generator
// Then heavily tweaked because openapi-generator no longer generates valid rust
// code

pub type Object = serde_json::map::Map<String, serde_json::Value>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConstructionSubmitResponse {
    /// Transfers produce a real transaction identifier,
    /// Neuron management requests produce a constant (pseudo) identifier.
    ///
    /// This field contains the transaction id of the last transfer operation.
    /// If a transaction only contains neuron management operations
    /// the constant identifier will be returned.
    pub transaction_identifier: TransactionIdentifier,

    pub metadata: Object,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConstructionHashResponse {
    pub transaction_identifier: TransactionIdentifier,
    pub metadata: Object,
}

/// An AccountBalanceRequest is utilized to make a balance request on the
/// /account/balance endpoint. If the block_identifier is populated, a
/// historical balance query should be performed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// The account_identifier uniquely identifies an account within a network. All
/// fields in the account_identifier are utilized to determine this uniqueness
/// (including the metadata field, if populated).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct AccountIdentifier {
    /// The address may be a cryptographic public key (or some encoding of it)
    /// or a provided username.
    #[serde(rename = "address")]
    pub address: String,

    #[serde(rename = "sub_account")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_account: Option<SubAccountIdentifier>,

    /// Blockchains that utilize a username model (where the address is not a
    /// derivative of a cryptographic public key) should specify the public
    /// key(s) owned by the address in metadata.
    #[serde(rename = "metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Object>,
}

impl AccountIdentifier {
    pub fn new(address: String) -> AccountIdentifier {
        AccountIdentifier {
            address,
            sub_account: None,
            metadata: None,
        }
    }
}

/// Allow specifies supported Operation status, Operation types, and all
/// possible error statuses. This Allow object is used by clients to validate
/// the correctness of a Rosetta Server implementation. It is expected that
/// these clients will error if they receive some response that contains any of
/// the above information that is not specified here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct Allow {
    /// All Operation.Status this implementation supports. Any status that is
    /// returned during parsing that is not listed here will cause client
    /// validation to error.
    #[serde(rename = "operation_statuses")]
    pub operation_statuses: Vec<OperationStatus>,

    /// All Operation.Type this implementation supports. Any type that is
    /// returned during parsing that is not listed here will cause client
    /// validation to error.
    #[serde(rename = "operation_types")]
    pub operation_types: Vec<String>,

    /// All Errors that this implementation could return. Any error that is
    /// returned during parsing that is not listed here will cause client
    /// validation to error.
    #[serde(rename = "errors")]
    pub errors: Vec<Error>,

    /// Any Rosetta implementation that supports querying the balance of an
    /// account at any height in the past should set this to true.
    #[serde(rename = "historical_balance_lookup")]
    pub historical_balance_lookup: bool,
}

impl Allow {
    pub fn new(
        operation_statuses: Vec<OperationStatus>,
        operation_types: Vec<String>,
        errors: Vec<Error>,
        historical_balance_lookup: bool,
    ) -> Allow {
        Allow {
            operation_statuses,
            operation_types,
            errors,
            historical_balance_lookup,
        }
    }
}

/// Amount is some Value of a Currency. It is considered invalid to specify a
/// Value without a Currency.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct Amount {
    /// Value of the transaction in atomic units represented as an
    /// arbitrary-sized signed integer.  For example, 1 BTC would be represented
    /// by a value of 100000000.
    #[serde(rename = "value")]
    pub value: String,

    #[serde(rename = "currency")]
    pub currency: Currency,

    #[serde(rename = "metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Object>,
}

impl Amount {
    pub fn new(value: String, currency: Currency) -> Amount {
        Amount {
            value,
            currency,
            metadata: None,
        }
    }
}

/// Blocks contain an array of Transactions that occurred at a particular
/// BlockIdentifier.  A hard requirement for blocks returned by Rosetta
/// implementations is that they MUST be _inalterable_: once a client has
/// requested and received a block identified by a specific BlockIndentifier,
/// all future calls for that same BlockIdentifier must return the same block
/// contents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct Block {
    #[serde(rename = "block_identifier")]
    pub block_identifier: BlockIdentifier,

    #[serde(rename = "parent_block_identifier")]
    pub parent_block_identifier: BlockIdentifier,

    #[serde(rename = "timestamp")]
    pub timestamp: Timestamp,

    #[serde(rename = "transactions")]
    pub transactions: Vec<Transaction>,

    #[serde(rename = "metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Object>,
}

impl Block {
    pub fn new(
        block_identifier: BlockIdentifier,
        parent_block_identifier: BlockIdentifier,
        timestamp: Timestamp,
        transactions: Vec<Transaction>,
    ) -> Block {
        Block {
            block_identifier,
            parent_block_identifier,
            timestamp,
            transactions,
            metadata: None,
        }
    }
}

/// The block_identifier uniquely identifies a block in a particular network.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct BlockIdentifier {
    /// This is also known as the block height.
    #[serde(rename = "index")]
    pub index: i64,

    #[serde(rename = "hash")]
    pub hash: String,
}

impl BlockIdentifier {
    pub fn new(index: i64, hash: String) -> BlockIdentifier {
        BlockIdentifier { index, hash }
    }
}

/// A BlockRequest is utilized to make a block request on the /block endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct BlockRequest {
    #[serde(rename = "network_identifier")]
    pub network_identifier: NetworkIdentifier,

    #[serde(rename = "block_identifier")]
    pub block_identifier: PartialBlockIdentifier,
}

impl BlockRequest {
    pub fn new(
        network_identifier: NetworkIdentifier,
        block_identifier: PartialBlockIdentifier,
    ) -> BlockRequest {
        BlockRequest {
            network_identifier,
            block_identifier,
        }
    }
}

/// A BlockResponse includes a fully-populated block or a partially-populated
/// block with a list of other transactions to fetch (other_transactions).  As a
/// result of the consensus algorithm of some blockchains, blocks can be omitted
/// (i.e. certain block indexes can be skipped). If a query for one of these
/// omitted indexes is made, the response should not include a `Block` object.
/// It is VERY important to note that blocks MUST still form a canonical,
/// connected chain of blocks where each block has a unique index. In other
/// words, the `PartialBlockIdentifier` of a block after an omitted block should
/// reference the last non-omitted block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct BlockResponse {
    #[serde(rename = "block")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block: Option<Block>,

    /// Some blockchains may require additional transactions to be fetched that
    /// weren't returned in the block response (ex: block only returns
    /// transaction hashes). For blockchains with a lot of transactions in each
    /// block, this can be very useful as consumers can concurrently fetch all
    /// transactions returned.
    #[serde(rename = "other_transactions")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other_transactions: Option<Vec<TransactionIdentifier>>,
}

impl BlockResponse {
    pub fn new() -> BlockResponse {
        BlockResponse {
            block: None,
            other_transactions: None,
        }
    }
}

/// A BlockTransactionRequest is used to fetch a Transaction included in a block
/// that is not returned in a BlockResponse.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct BlockTransactionRequest {
    #[serde(rename = "network_identifier")]
    pub network_identifier: NetworkIdentifier,

    #[serde(rename = "block_identifier")]
    pub block_identifier: BlockIdentifier,

    #[serde(rename = "transaction_identifier")]
    pub transaction_identifier: TransactionIdentifier,
}

impl BlockTransactionRequest {
    pub fn new(
        network_identifier: NetworkIdentifier,
        block_identifier: BlockIdentifier,
        transaction_identifier: TransactionIdentifier,
    ) -> BlockTransactionRequest {
        BlockTransactionRequest {
            network_identifier,
            block_identifier,
            transaction_identifier,
        }
    }
}

/// A BlockTransactionResponse contains information about a block transaction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct BlockTransactionResponse {
    #[serde(rename = "transaction")]
    pub transaction: Transaction,
}

impl BlockTransactionResponse {
    pub fn new(transaction: Transaction) -> BlockTransactionResponse {
        BlockTransactionResponse { transaction }
    }
}

/// Coin contains its unique identifier and the amount it represents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct Coin {
    #[serde(rename = "coin_identifier")]
    pub coin_identifier: CoinIdentifier,

    #[serde(rename = "amount")]
    pub amount: Amount,
}

impl Coin {
    pub fn new(coin_identifier: CoinIdentifier, amount: Amount) -> Coin {
        Coin {
            coin_identifier,
            amount,
        }
    }
}

/// CoinActions are different state changes that a Coin can undergo. When a Coin
/// is created, it is coin_created. When a Coin is spent, it is coin_spent. It
/// is assumed that a single Coin cannot be created or spent more than once.
/// Enumeration of values.
/// Since this enum's variants do not hold data, we can easily define them them
/// as `#[repr(C)]` which helps with FFI.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGenericEnum))]
pub enum CoinAction {
    #[serde(rename = "coin_created")]
    Created,
    #[serde(rename = "coin_spent")]
    Spent,
}

impl ::std::fmt::Display for CoinAction {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            CoinAction::Created => write!(f, "coin_created"),
            CoinAction::Spent => write!(f, "coin_spent"),
        }
    }
}

impl ::std::str::FromStr for CoinAction {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "coin_created" => Ok(CoinAction::Created),
            "coin_spent" => Ok(CoinAction::Spent),
            _ => Err(()),
        }
    }
}

/// CoinChange is used to represent a change in state of a some coin identified
/// by a coin_identifier. This object is part of the Operation model and must be
/// populated for UTXO-based blockchains.  Coincidentally, this abstraction of
/// UTXOs allows for supporting both account-based transfers and UTXO-based
/// transfers on the same blockchain (when a transfer is account-based, don't
/// populate this model).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct CoinChange {
    #[serde(rename = "coin_identifier")]
    pub coin_identifier: CoinIdentifier,

    #[serde(rename = "coin_action")]
    pub coin_action: CoinAction,
}

impl CoinChange {
    pub fn new(coin_identifier: CoinIdentifier, coin_action: CoinAction) -> CoinChange {
        CoinChange {
            coin_identifier,
            coin_action,
        }
    }
}

/// CoinIdentifier uniquely identifies a Coin.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct CoinIdentifier {
    /// Identifier should be populated with a globally unique identifier of a
    /// Coin. In Bitcoin, this identifier would be transaction_hash:index.
    #[serde(rename = "identifier")]
    pub identifier: String,
}

impl CoinIdentifier {
    pub fn new(identifier: String) -> CoinIdentifier {
        CoinIdentifier { identifier }
    }
}

/// ConstructionCombineRequest is the input to the `/construction/combine`
/// endpoint. It contains the unsigned transaction blob returned by
/// `/construction/payloads` and all required signatures to create a network
/// transaction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvelopePair {
    pub update: HttpRequestEnvelope<HttpSubmitContent>,
    pub read_state: HttpRequestEnvelope<HttpReadStateContent>,
}

impl EnvelopePair {
    pub fn update_content(&self) -> &HttpCanisterUpdate {
        match self.update.content {
            HttpSubmitContent::Call { ref update } => update,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "account_type")]
pub enum AccountType {
    Ledger,
    Neuron {
        #[serde(default)]
        neuron_identifier: u64,
    },
}

impl Default for AccountType {
    fn default() -> Self {
        Self::Ledger
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConstructionDeriveRequestMetadata {
    #[serde(flatten)]
    pub account_type: AccountType,
}

#[test]
fn test_construction_derive_request_metadata() {
    let r0 = ConstructionDeriveRequestMetadata {
        account_type: AccountType::Neuron {
            neuron_identifier: 1,
        },
    };

    let s = serde_json::to_string(&r0).unwrap();
    let r1 = serde_json::from_str(s.as_str()).unwrap();

    assert_eq!(s, r#"{"account_type":"neuron","neuron_identifier":1}"#);
    assert_eq!(r0, r1);
}

/// ConstructionDeriveRequest is passed to the `/construction/derive` endpoint.
/// Network is provided in the request because some blockchains have different
/// address formats for different networks. Metadata is provided in the request
/// because some blockchains allow for multiple address types (i.e. different
/// address for validators vs normal accounts).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct ConstructionDeriveRequest {
    #[serde(rename = "network_identifier")]
    pub network_identifier: NetworkIdentifier,

    #[serde(rename = "public_key")]
    pub public_key: PublicKey,

    #[serde(rename = "metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ConstructionDeriveRequestMetadata>,
}

impl ConstructionDeriveRequest {
    pub fn new(
        network_identifier: NetworkIdentifier,
        public_key: PublicKey,
    ) -> ConstructionDeriveRequest {
        ConstructionDeriveRequest {
            network_identifier,
            public_key,
            metadata: None,
        }
    }
}

/// ConstructionDeriveResponse is returned by the `/construction/derive`
/// endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct ConstructionDeriveResponse {
    /// [DEPRECATED by `account_identifier` in `v1.4.4`] Address in
    /// network-specific format.
    #[serde(rename = "address")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,

    #[serde(rename = "account_identifier")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_identifier: Option<AccountIdentifier>,

    #[serde(rename = "metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Object>,
}

impl ConstructionDeriveResponse {
    pub fn new() -> ConstructionDeriveResponse {
        ConstructionDeriveResponse {
            address: None,
            account_identifier: None,
            metadata: None,
        }
    }
}

/// ConstructionHashRequest is the input to the `/construction/hash` endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    pub metadata: Option<Object>,
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
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ConstructionPayloadsRequestMetadata {
    /// The memo to use for a ledger transfer.
    /// A random number is used by default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<u64>,

    /// The earliest acceptable expiry date for a ledger transfer.
    /// Must be withing 24 hours from created_at_time.
    /// Represents number of nanoseconds since UNIX epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress_start: Option<u64>,

    /// The latest acceptable expiry date for a ledger transfer.
    /// Must be withing 24 hours from created_at_time.
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    pub metadata: Option<Object>,

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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// Currency is composed of a canonical Symbol and Decimals. This Decimals value
/// is used to convert an Amount.Value from atomic units (Satoshis) to standard
/// units (Bitcoins).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct Currency {
    /// Canonical symbol associated with a currency.
    #[serde(rename = "symbol")]
    pub symbol: String,

    /// Number of decimal places in the standard unit representation of the
    /// amount.  For example, BTC has 8 decimals. Note that it is not possible
    /// to represent the value of some currency in atomic units that is not base
    /// 10.
    #[serde(rename = "decimals")]
    pub decimals: u32,

    /// Any additional information related to the currency itself.  For example,
    /// it would be useful to populate this object with the contract address of
    /// an ERC-20 token.
    #[serde(rename = "metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Object>,
}

impl Currency {
    pub fn new(symbol: String, decimals: u32) -> Currency {
        Currency {
            symbol,
            decimals,
            metadata: None,
        }
    }
}

/// CurveType is the type of cryptographic curve associated with a PublicKey.  * secp256k1: SEC compressed - `33 bytes` (https://secg.org/sec1-v2.pdf#subsubsection.2.3.3) * secp256r1: SEC compressed - `33 bytes` (https://secg.org/sec1-v2.pdf#subsubsection.2.3.3) * edwards25519: `y (255-bits) || x-sign-bit (1-bit)` - `32 bytes` (https://ed25519.cr.yp.to/ed25519-20110926.pdf) * tweedle: 1st pk : Fq.t (32 bytes) || 2nd pk : Fq.t (32 bytes) (https://github.com/CodaProtocol/coda/blob/develop/rfcs/0038-rosetta-construction-api.md#marshal-keys)
/// Enumeration of values.
/// Since this enum's variants do not hold data, we can easily define them them
/// as `#[repr(C)]` which helps with FFI.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGenericEnum))]
pub enum CurveType {
    #[serde(rename = "secp256k1")]
    Secp256K1,
    #[serde(rename = "secp256r1")]
    Secp256R1,
    #[serde(rename = "edwards25519")]
    Edwards25519,
    #[serde(rename = "tweedle")]
    Tweedle,
}

impl ::std::fmt::Display for CurveType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            CurveType::Secp256K1 => write!(f, "secp256k1"),
            CurveType::Secp256R1 => write!(f, "secp256r1"),
            CurveType::Edwards25519 => write!(f, "edwards25519"),
            CurveType::Tweedle => write!(f, "tweedle"),
        }
    }
}

impl ::std::str::FromStr for CurveType {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "secp256k1" => Ok(CurveType::Secp256K1),
            "secp256r1" => Ok(CurveType::Secp256R1),
            "edwards25519" => Ok(CurveType::Edwards25519),
            "tweedle" => Ok(CurveType::Tweedle),
            _ => Err(()),
        }
    }
}

/// Instead of utilizing HTTP status codes to describe node errors (which often
/// do not have a good analog), rich errors are returned using this object.
/// Both the code and message fields can be individually used to correctly
/// identify an error. Implementations MUST use unique values for both fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct Error {
    /// Code is a network-specific error code. If desired, this code can be
    /// equivalent to an HTTP status code.
    #[serde(rename = "code")]
    pub code: u32,

    /// Message is a network-specific error message.  The message MUST NOT
    /// change for a given code. In particular, this means that any contextual
    /// information should be included in the details field.
    #[serde(rename = "message")]
    pub message: String,

    /// An error is retriable if the same request may succeed if submitted
    /// again.
    #[serde(rename = "retriable")]
    pub retriable: bool,

    /// Often times it is useful to return context specific to the request that
    /// caused the error (i.e. a sample of the stack trace or impacted account)
    /// in addition to the standard error message.
    #[serde(rename = "details")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Object>,
}

impl Error {
    pub fn new(err_type: &ApiError) -> Self {
        Self::from(err_type)
    }

    pub fn serialization_error_json_str() -> String {
        "{\"code\":700,\"message\":\"Internal server error\",\"retriable\":true,\"details\":null}"
            .to_string()
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            serde_json::to_string(self)
                .expect("This should be impossible, all errors must be serializable")
        )
    }
}

impl actix_web::ResponseError for Error {
    fn status_code(&self) -> ic_canister_client::HttpStatusCode {
        self.code
            .try_into()
            .ok()
            .and_then(|c| actix_web::http::StatusCode::from_u16(c).ok())
            .unwrap_or_default()
    }
}

/// A MempoolResponse contains all transaction identifiers in the mempool for a
/// particular network_identifier.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct MempoolResponse {
    #[serde(rename = "transaction_identifiers")]
    pub transaction_identifiers: Vec<TransactionIdentifier>,
}

impl MempoolResponse {
    pub fn new(transaction_identifiers: Vec<TransactionIdentifier>) -> MempoolResponse {
        MempoolResponse {
            transaction_identifiers,
        }
    }
}

/// A MempoolTransactionRequest is utilized to retrieve a transaction from the
/// mempool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// A MempoolTransactionResponse contains an estimate of a mempool transaction.
/// It may not be possible to know the full impact of a transaction in the
/// mempool (ex: fee paid).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct MempoolTransactionResponse {
    #[serde(rename = "transaction")]
    pub transaction: Transaction,

    #[serde(rename = "metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Object>,
}

impl MempoolTransactionResponse {
    pub fn new(transaction: Transaction) -> MempoolTransactionResponse {
        MempoolTransactionResponse {
            transaction,
            metadata: None,
        }
    }
}

/// A MetadataRequest is utilized in any request where the only argument is
/// optional metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct MetadataRequest {
    #[serde(rename = "metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Object>,
}

impl MetadataRequest {
    pub fn new() -> MetadataRequest {
        MetadataRequest { metadata: None }
    }
}

/// The network_identifier specifies which network a particular object is
/// associated with.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct NetworkIdentifier {
    #[serde(rename = "blockchain")]
    pub blockchain: String,

    /// If a blockchain has a specific chain-id or network identifier, it should
    /// go in this field. It is up to the client to determine which
    /// network-specific identifier is mainnet or testnet.
    #[serde(rename = "network")]
    pub network: String,

    #[serde(rename = "sub_network_identifier")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_network_identifier: Option<SubNetworkIdentifier>,
}

impl NetworkIdentifier {
    pub fn new(blockchain: String, network: String) -> NetworkIdentifier {
        NetworkIdentifier {
            blockchain,
            network,
            sub_network_identifier: None,
        }
    }
}

impl TryInto<CanisterId> for &NetworkIdentifier {
    type Error = ApiError;
    fn try_into(self) -> Result<CanisterId, Self::Error> {
        use ic_types::PrincipalId;

        let principal_bytes = hex::decode(&self.network)
            .map_err(|_| ApiError::InvalidNetworkId(false, "not hex".into()))?;
        let principal_id = PrincipalId::try_from(&principal_bytes)
            .map_err(|_| ApiError::InvalidNetworkId(false, "invalid principal id".into()))?;
        CanisterId::try_from(principal_id)
            .map_err(|_| ApiError::InvalidNetworkId(false, "invalid canister id".into()))
    }
}

/// A NetworkListResponse contains all NetworkIdentifiers that the node can
/// serve information for.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct NetworkListResponse {
    #[serde(rename = "network_identifiers")]
    pub network_identifiers: Vec<NetworkIdentifier>,
}

impl NetworkListResponse {
    pub fn new(network_identifiers: Vec<NetworkIdentifier>) -> NetworkListResponse {
        NetworkListResponse {
            network_identifiers,
        }
    }
}

/// NetworkOptionsResponse contains information about the versioning of the node
/// and the allowed operation statuses, operation types, and errors.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct NetworkOptionsResponse {
    #[serde(rename = "version")]
    pub version: Version,

    #[serde(rename = "allow")]
    pub allow: Allow,
}

impl NetworkOptionsResponse {
    pub fn new(version: Version, allow: Allow) -> NetworkOptionsResponse {
        NetworkOptionsResponse { version, allow }
    }
}

/// A NetworkRequest is utilized to retrieve some data specific exclusively to a
/// NetworkIdentifier.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct NetworkRequest {
    #[serde(rename = "network_identifier")]
    pub network_identifier: NetworkIdentifier,

    #[serde(rename = "metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Object>,
}

impl NetworkRequest {
    pub fn new(network_identifier: NetworkIdentifier) -> NetworkRequest {
        NetworkRequest {
            network_identifier,
            metadata: None,
        }
    }
}

/// NetworkStatusResponse contains basic information about the node's view of a
/// blockchain network. It is assumed that any BlockIdentifier.Index less than
/// or equal to CurrentBlockIdentifier.Index can be queried.  If a Rosetta
/// implementation prunes historical state, it should populate the optional
/// `oldest_block_identifier` field with the oldest block available to query. If
/// this is not populated, it is assumed that the `genesis_block_identifier` is
/// the oldest queryable block.  If a Rosetta implementation performs some
/// pre-sync before it is possible to query blocks, sync_status should be
/// populated so that clients can still monitor healthiness. Without this field,
/// it may appear that the implementation is stuck syncing and needs to be
/// terminated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct NetworkStatusResponse {
    #[serde(rename = "current_block_identifier")]
    pub current_block_identifier: BlockIdentifier,

    /// The timestamp of the block in milliseconds since the Unix Epoch. The
    /// timestamp is stored in milliseconds because some blockchains produce
    /// blocks more often than once a second.
    #[serde(rename = "current_block_timestamp")]
    pub current_block_timestamp: Timestamp,

    #[serde(rename = "genesis_block_identifier")]
    pub genesis_block_identifier: BlockIdentifier,

    #[serde(rename = "oldest_block_identifier")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_block_identifier: Option<BlockIdentifier>,

    #[serde(rename = "sync_status")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_status: Option<SyncStatus>,

    #[serde(rename = "peers")]
    pub peers: Vec<Peer>,
}

impl NetworkStatusResponse {
    pub fn new(
        current_block_identifier: BlockIdentifier,
        current_block_timestamp: Timestamp,
        genesis_block_identifier: BlockIdentifier,
        oldest_block_identifier: Option<BlockIdentifier>,
        sync_status: SyncStatus,
        peers: Vec<Peer>,
    ) -> NetworkStatusResponse {
        NetworkStatusResponse {
            current_block_identifier,
            current_block_timestamp,
            genesis_block_identifier,
            oldest_block_identifier,
            sync_status: Some(sync_status),
            peers,
        }
    }
}

/// Operations contain all balance-changing information within a transaction.
/// They are always one-sided (only affect 1 AccountIdentifier) and can succeed
/// or fail independently from a Transaction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct Operation {
    #[serde(rename = "operation_identifier")]
    pub operation_identifier: OperationIdentifier,

    /// Restrict referenced related_operations to identifier indexes < the
    /// current operation_identifier.index. This ensures there exists a clear
    /// DAG-structure of relations.  Since operations are one-sided, one could
    /// imagine relating operations in a single transfer or linking operations
    /// in a call tree.
    #[serde(rename = "related_operations")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_operations: Option<Vec<OperationIdentifier>>,

    /// The network-specific type of the operation. Ensure that any type that
    /// can be returned here is also specified in the NetworkOptionsResponse.
    /// This can be very useful to downstream consumers that parse all block
    /// data.
    #[serde(rename = "type")]
    pub _type: String,

    /// The network-specific status of the operation. Status is not defined on
    /// the transaction object because blockchains with smart contracts may have
    /// transactions that partially apply.  Blockchains with atomic transactions
    /// (all operations succeed or all operations fail) will have the same
    /// status for each operation.
    #[serde(rename = "status")]
    pub status: Option<String>,

    #[serde(rename = "account")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<AccountIdentifier>,

    #[serde(rename = "amount")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<Amount>,

    #[serde(rename = "coin_change")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coin_change: Option<CoinChange>,

    #[serde(rename = "metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Object>,
}

impl Operation {
    pub fn new(
        op_id: i64,
        _type: String,
        status: Option<String>,
        account: Option<AccountIdentifier>,
        amount: Option<Amount>,
        metadata: Option<Object>,
    ) -> Operation {
        Operation {
            operation_identifier: OperationIdentifier::new(op_id),
            related_operations: None,
            _type,
            status,
            account,
            amount,
            coin_change: None,
            metadata,
        }
    }
}

/// The operation_identifier uniquely identifies an operation within a
/// transaction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct OperationIdentifier {
    /// The operation index is used to ensure each operation has a unique
    /// identifier within a transaction. This index is only relative to the
    /// transaction and NOT GLOBAL. The operations in each transaction should
    /// start from index 0.  To clarify, there may not be any notion of an
    /// operation index in the blockchain being described.
    #[serde(rename = "index")]
    pub index: i64,

    /// Some blockchains specify an operation index that is essential for client
    /// use. For example, Bitcoin uses a network_index to identify which UTXO
    /// was used in a transaction.  network_index should not be populated if
    /// there is no notion of an operation index in a blockchain (typically most
    /// account-based blockchains).
    #[serde(rename = "network_index")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_index: Option<i64>,
}

impl OperationIdentifier {
    pub fn new(index: i64) -> OperationIdentifier {
        OperationIdentifier {
            index,
            network_index: None,
        }
    }
}

/// OperationStatus is utilized to indicate which Operation status are
/// considered successful.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct OperationStatus {
    /// The status is the network-specific status of the operation.
    #[serde(rename = "status")]
    pub status: String,

    /// An Operation is considered successful if the Operation.Amount should
    /// affect the Operation.Account. Some blockchains (like Bitcoin) only
    /// include successful operations in blocks but other blockchains (like
    /// Ethereum) include unsuccessful operations that incur a fee.  To
    /// reconcile the computed balance from the stream of Operations, it is
    /// critical to understand which Operation.Status indicate an Operation is
    /// successful and should affect an Account.
    #[serde(rename = "successful")]
    pub successful: bool,
}

impl OperationStatus {
    pub fn new(status: String, successful: bool) -> OperationStatus {
        OperationStatus { status, successful }
    }
}

/// When fetching data by BlockIdentifier, it may be possible to only specify
/// the index or hash. If neither property is specified, it is assumed that the
/// client is making a request at the current block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct PartialBlockIdentifier {
    #[serde(rename = "index")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<i64>,

    #[serde(rename = "hash")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

impl PartialBlockIdentifier {
    pub fn new() -> PartialBlockIdentifier {
        PartialBlockIdentifier {
            index: None,
            hash: None,
        }
    }
}

/// A Peer is a representation of a node's peer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct Peer {
    #[serde(rename = "peer_id")]
    pub peer_id: String,

    #[serde(rename = "metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Object>,
}

impl Peer {
    pub fn new(peer_id: String) -> Peer {
        Peer {
            peer_id,
            metadata: None,
        }
    }
}

/// PublicKey contains a public key byte array for a particular CurveType
/// encoded in hex.  Note that there is no PrivateKey struct as this is NEVER
/// the concern of an implementation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct PublicKey {
    /// Hex-encoded public key bytes in the format specified by the CurveType.
    #[serde(rename = "hex_bytes")]
    pub hex_bytes: String,

    #[serde(rename = "curve_type")]
    pub curve_type: CurveType,
}

impl PublicKey {
    pub fn new(hex_bytes: String, curve_type: CurveType) -> PublicKey {
        PublicKey {
            hex_bytes,
            curve_type,
        }
    }
}

/// Signature contains the payload that was signed, the public keys of the
/// keypairs used to produce the signature, the signature (encoded in hex), and
/// the SignatureType.  PublicKey is often times not known during construction
/// of the signing payloads but may be needed to combine signatures properly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// An account may have state specific to a contract address (ERC-20 token)
/// and/or a stake (delegated balance). The sub_account_identifier should
/// specify which state (if applicable) an account instantiation refers to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct SubAccountIdentifier {
    /// The SubAccount address may be a cryptographic value or some other
    /// identifier (ex: bonded) that uniquely specifies a SubAccount.
    #[serde(rename = "address")]
    pub address: String,

    /// If the SubAccount address is not sufficient to uniquely specify a
    /// SubAccount, any other identifying information can be stored here.  It is
    /// important to note that two SubAccounts with identical addresses but
    /// differing metadata will not be considered equal by clients.
    #[serde(rename = "metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Object>,
}

impl SubAccountIdentifier {
    pub fn new(address: String) -> SubAccountIdentifier {
        SubAccountIdentifier {
            address,
            metadata: None,
        }
    }
}

/// In blockchains with sharded state, the SubNetworkIdentifier is required to
/// query some object on a specific shard. This identifier is optional for all
/// non-sharded blockchains.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct SubNetworkIdentifier {
    #[serde(rename = "network")]
    pub network: String,

    #[serde(rename = "metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Object>,
}

impl SubNetworkIdentifier {
    pub fn new(network: String) -> SubNetworkIdentifier {
        SubNetworkIdentifier {
            network,
            metadata: None,
        }
    }
}

/// SyncStatus is used to provide additional context about an implementation's
/// sync status. It is often used to indicate that an implementation is healthy
/// when it cannot be queried  until some sync phase occurs.  If an
/// implementation is immediately queryable, this model is often not populated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct SyncStatus {
    /// CurrentIndex is the index of the last synced block in the current stage.
    #[serde(rename = "current_index")]
    pub current_index: i64,

    /// TargetIndex is the index of the block that the implementation is
    /// attempting to sync to in the current stage.
    #[serde(rename = "target_index")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_index: Option<i64>,

    /// Stage is the phase of the sync process.
    #[serde(rename = "stage")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,

    /// Stage is the phase of the sync process.
    #[serde(rename = "synced")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub synced: Option<bool>,
}

impl SyncStatus {
    pub fn new(current_index: i64, synced: Option<bool>) -> SyncStatus {
        SyncStatus {
            current_index,
            target_index: None,
            stage: None,
            synced,
        }
    }
}

/// The timestamp of the block in milliseconds since the Unix Epoch. The
/// timestamp is stored in milliseconds because some blockchains produce blocks
/// more often than once a second.
#[derive(Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct Timestamp(i64);

impl ::std::convert::From<i64> for Timestamp {
    fn from(x: i64) -> Self {
        Timestamp(x)
    }
}

impl ::std::convert::From<Timestamp> for i64 {
    fn from(x: Timestamp) -> Self {
        x.0
    }
}

impl ::std::ops::Deref for Timestamp {
    type Target = i64;
    fn deref(&self) -> &i64 {
        &self.0
    }
}

impl ::std::ops::DerefMut for Timestamp {
    fn deref_mut(&mut self) -> &mut i64 {
        &mut self.0
    }
}

/// Transactions contain an array of Operations that are attributable to the
/// same TransactionIdentifier.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct Transaction {
    #[serde(rename = "transaction_identifier")]
    pub transaction_identifier: TransactionIdentifier,

    #[serde(rename = "operations")]
    pub operations: Vec<Operation>,

    /// Transactions that are related to other transactions (like a cross-shard
    /// transaction) should include the tranaction_identifier of these
    /// transactions in the metadata.
    #[serde(rename = "metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Object>,
}

impl Transaction {
    pub fn new(
        transaction_identifier: TransactionIdentifier,
        operations: Vec<Operation>,
    ) -> Transaction {
        Transaction {
            transaction_identifier,
            operations,
            metadata: None,
        }
    }
}

/// TransactionIdentifierResponse contains the transaction_identifier of a
/// transaction that was submitted to either `/construction/hash` or
/// `/construction/submit`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct TransactionIdentifierResponse {
    #[serde(rename = "transaction_identifier")]
    pub transaction_identifier: TransactionIdentifier,

    #[serde(rename = "metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Object>,
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// The Version object is utilized to inform the client of the versions of
/// different components of the Rosetta implementation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct Version {
    /// The rosetta_version is the version of the Rosetta interface the
    /// implementation adheres to. This can be useful for clients looking to
    /// reliably parse responses.
    #[serde(rename = "rosetta_version")]
    pub rosetta_version: String,

    /// The node_version is the canonical version of the node runtime. This can
    /// help clients manage deployments.
    #[serde(rename = "node_version")]
    pub node_version: String,

    /// When a middleware server is used to adhere to the Rosetta interface, it
    /// should return its version here. This can help clients manage
    /// deployments.
    #[serde(rename = "middleware_version")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middleware_version: Option<String>,

    /// Any other information that may be useful about versioning of dependent
    /// services should be returned here.
    #[serde(rename = "metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Object>,
}

impl Version {
    pub fn new(
        rosetta_version: String,
        node_version: String,
        middleware_version: Option<String>,
        metadata: Option<Object>,
    ) -> Version {
        Version {
            rosetta_version,
            node_version,
            middleware_version,
            metadata,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub enum NeuronState {
    #[serde(rename = "NOT_DISSOLVING")]
    NotDissolving,
    #[serde(rename = "DISSOLVING")]
    Dissolving,
    #[serde(rename = "DISSOLVED")]
    Dissolved,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct NeuronInfoResponse {
    //    #[serde(rename = "neuron_id")]
    //    pub neuron_id: u64,
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
}
