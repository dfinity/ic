use crate::identifiers::*;
use crate::miscellaneous::*;
use crate::objects::*;
use serde::{Deserialize, Serialize};

/// A NetworkListResponse contains all NetworkIdentifiers that the node can
/// serve information for.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
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

/// NetworkOptionsResponse contains information about the versioning of the node and the allowed operation statuses, operation types, and errors.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct NetworkOptionsResponse {
    /// The Version object is utilized to inform the client of the versions of different components of the Rosetta implementation.
    pub version: Version,

    /// Allow specifies supported Operation status, Operation types, and all possible error statuses. This Allow object is used by clients to validate the correctness of a Rosetta Server implementation. It is expected that these clients will error if they receive some response that contains any of the above information that is not specified here.
    pub allow: Allow,
}

impl NetworkOptionsResponse {
    pub fn new(version: Version, allow: Allow) -> NetworkOptionsResponse {
        NetworkOptionsResponse { version, allow }
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
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct NetworkStatusResponse {
    /// The block_identifier uniquely identifies a block in a particular network.
    pub current_block_identifier: BlockIdentifier,

    /// The timestamp of the block in milliseconds since the Unix Epoch. The
    /// timestamp is stored in milliseconds because some blockchains produce
    /// blocks more often than once a second.
    pub current_block_timestamp: u64,

    /// The block_identifier uniquely identifies a block in a particular network.
    pub genesis_block_identifier: BlockIdentifier,

    /// The block_identifier uniquely identifies a block in a particular network.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_block_identifier: Option<BlockIdentifier>,

    /// SyncStatus is used to provide additional context about an implementation's sync status. This object is often used by implementations to indicate healthiness when block data cannot be queried until some sync phase completes or cannot be determined by comparing the timestamp of the most recent block with the current time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_status: Option<SyncStatus>,

    pub peers: Vec<Peer>,
}

impl NetworkStatusResponse {
    pub fn new(
        current_block_identifier: BlockIdentifier,
        current_block_timestamp: u64,
        genesis_block_identifier: BlockIdentifier,
        oldest_block_identifier: Option<BlockIdentifier>,
        sync_status: Option<SyncStatus>,
        peers: Vec<Peer>,
    ) -> NetworkStatusResponse {
        NetworkStatusResponse {
            current_block_identifier,
            current_block_timestamp,
            genesis_block_identifier,
            oldest_block_identifier,
            sync_status,
            peers,
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
#[derive(Clone, Eq, PartialEq, Debug, Default, Deserialize, Serialize)]
pub struct BlockResponse {
    /// Blocks contain an array of Transactions that occurred at a particular BlockIdentifier. A hard requirement for blocks returned by Rosetta implementations is that they MUST be inalterable: once a client has requested and received a block identified by a specific BlockIndentifier, all future calls for that same BlockIdentifier must return the same block contents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block: Option<Block>,

    /// Some blockchains may require additional transactions to be fetched that
    /// weren't returned in the block response (ex: block only returns
    /// transaction hashes). For blockchains with a lot of transactions in each
    /// block, this can be very useful as consumers can concurrently fetch all
    /// transactions returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other_transactions: Option<Vec<TransactionIdentifier>>,
}

impl BlockResponse {
    pub fn new(block: Option<Block>) -> BlockResponse {
        BlockResponse {
            block,
            other_transactions: None,
        }
    }
}

/// A BlockTransactionResponse contains information about a block transaction.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct BlockTransactionResponse {
    /// Transactions contain an array of Operations that are attributable to the same TransactionIdentifier.
    pub transaction: Transaction,
}

impl BlockTransactionResponse {
    pub fn new(transaction: Transaction) -> BlockTransactionResponse {
        BlockTransactionResponse { transaction }
    }
}

/// A MempoolResponse contains all transaction identifiers in the mempool for a
/// particular network_identifier.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
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

/// A MempoolTransactionResponse contains an estimate of a mempool transaction.
/// It may not be possible to know the full impact of a transaction in the
/// mempool (ex: fee paid).
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct MempoolTransactionResponse {
    #[serde(rename = "transaction")]
    pub transaction: Transaction,
}

impl MempoolTransactionResponse {
    pub fn new(transaction: Transaction) -> MempoolTransactionResponse {
        MempoolTransactionResponse { transaction }
    }
}

/// ConstructionDeriveResponse is returned by the `/construction/derive`
/// endpoint.
#[derive(Clone, Eq, PartialEq, Debug, Default, Deserialize, Serialize)]
pub struct ConstructionDeriveResponse {
    /// [DEPRECATED by `account_identifier` in `v1.4.4`] Address in
    /// network-specific format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,

    /// The account_identifier uniquely identifies an account within a network. All fields in the account_identifier are utilized to determine this uniqueness (including the metadata field, if populated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_identifier: Option<AccountIdentifier>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ObjectMap>,
}

impl ConstructionDeriveResponse {
    pub fn new(
        address: Option<String>,
        account_identifier: Option<AccountIdentifier>,
    ) -> ConstructionDeriveResponse {
        ConstructionDeriveResponse {
            address,
            account_identifier,
            metadata: None,
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
#[derive(Clone, Eq, PartialEq, Debug, Default, Deserialize, Serialize)]
pub struct ConstructionPreprocessResponse {
    /// The options that will be sent directly to `/construction/metadata` by
    /// the caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<ObjectMap>,

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

/// The ConstructionMetadataResponse returns network-specific metadata used for
/// transaction construction.  Optionally, the implementer can return the
/// suggested fee associated with the transaction being constructed. The caller
/// may use this info to adjust the intent of the transaction or to create a
/// transaction with a different account that can pay the suggested fee.
/// Suggested fee is an array in case fee payment must occur in multiple
/// currencies.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct ConstructionMetadataResponse {
    pub metadata: ObjectMap,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_fee: Option<Vec<Amount>>,
}

/// ConstructionTransactionResponse is returned by `/construction/payloads`. It
/// contains an unsigned transaction blob (that is usually needed to construct
/// the a network transaction from a collection of signatures) and an array of
/// payloads that must be signed by the caller.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct ConstructionPayloadsResponse {
    /// CBOR+hex-encoded 'UnsignedTransaction'
    pub unsigned_transaction: String,

    pub payloads: Vec<SigningPayload>,
}

impl ConstructionPayloadsResponse {
    pub fn new(
        unsigned_transaction: String,
        payloads: Vec<SigningPayload>,
    ) -> ConstructionPayloadsResponse {
        ConstructionPayloadsResponse {
            unsigned_transaction,
            payloads,
        }
    }
}

/// ConstructionParseResponse contains an array of operations that occur in a
/// transaction blob. This should match the array of operations provided to
/// `/construction/preprocess` and `/construction/payloads`.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct ConstructionParseResponse {
    pub operations: Vec<Operation>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_identifier_signers: Option<Vec<AccountIdentifier>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ObjectMap>,
}

impl ConstructionParseResponse {
    pub fn new(operations: Vec<Operation>) -> ConstructionParseResponse {
        ConstructionParseResponse {
            operations,
            account_identifier_signers: None,
            metadata: None,
        }
    }
}

/// ConstructionCombineResponse is returned by `/construction/combine`. The
/// network payload will be sent directly to the `construction/submit` endpoint.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct ConstructionCombineResponse {
    /// CBOR+hex-encoded 'SignedTransaction'
    pub signed_transaction: String,
}

// This file is generated from https://github.com/coinbase/rosetta-specifications using openapi-generator
// Then heavily tweaked because openapi-generator no longer generates valid rust
// code
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct ConstructionSubmitResponse {
    /// Transfers produce a real transaction identifier,
    /// Neuron management requests produce a constant (pseudo) identifier.
    ///
    /// This field contains the transaction id of the last transfer operation.
    /// If a transaction only contains neuron management operations
    /// the constant identifier will be returned.
    pub transaction_identifier: TransactionIdentifier,
    pub metadata: Option<ObjectMap>,
}

/// An AccountBalanceResponse is returned on the /account/balance endpoint. If
/// an account has a balance for each AccountIdentifier describing it (ex: an
/// ERC-20 token balance on a few smart contracts), an account balance request
/// must be made with each AccountIdentifier.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
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
    pub metadata: Option<ObjectMap>,
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct ConstructionHashResponse {
    pub transaction_identifier: TransactionIdentifier,
    pub metadata: ObjectMap,
}

/// SearchTransactionsResponse contains an ordered collection of
/// BlockTransactions that match the query in SearchTransactionsRequest. These
/// BlockTransactions are sorted from most recent block to oldest block.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct SearchTransactionsResponse {
    /// transactions is an array of BlockTransactions sorted by most recent BlockIdentifier (meaning that transactions in recent blocks appear first).
    /// If there are many transactions for a particular search, transactions may not contain all matching transactions. It is up to the caller to paginate these transactions using the max_block field.
    pub transactions: Vec<BlockTransaction>,

    /// total_count is the number of results for a given search. Callers typically use this value to concurrently fetch results by offset or to display a virtual page number associated with results.
    #[serde(rename = "total_count")]
    pub total_count: i64,

    /// next_offset is the next offset to use when paginating through transaction results. If this field is not populated, there are no more transactions to query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<i64>,
}

#[derive(Clone, Eq, PartialEq, Debug, Default, Deserialize, Serialize)]
pub struct CallResponse {
    /// Result contains the result of the `/call` invocation. This result will not be inspected or interpreted by Rosetta tooling and is left to the caller to decode.
    #[serde(rename = "result")]
    pub result: ObjectMap,

    /// Idempotent indicates that if `/call` is invoked with the same CallRequest again, at any point in time, it will return the same CallResponse. Integrators may cache the CallResponse if this is set to true to avoid making unnecessary calls to the Rosetta implementation. For this reason, implementers should be very conservative about returning true here or they could cause issues for the caller.
    pub idempotent: bool,
}

impl CallResponse {
    pub fn new(result: ObjectMap, idempotent: bool) -> CallResponse {
        CallResponse { result, idempotent }
    }
}
