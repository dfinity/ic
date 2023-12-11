use crate::identifiers::*;
use crate::miscellaneous::*;
use crate::objects::*;
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

/// NetworkOptionsResponse contains information about the versioning of the node and the allowed operation statuses, operation types, and errors.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
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

/// A BlockResponse includes a fully-populated block or a partially-populated
/// block with a list of other transactions to fetch (other_transactions).  As a
/// result of the consensus algorithm of some blockchains, blocks can be omitted
/// (i.e. certain block indexes can be skipped). If a query for one of these
/// omitted indexes is made, the response should not include a `Block` object.
/// It is VERY important to note that blocks MUST still form a canonical,
/// connected chain of blocks where each block has a unique index. In other
/// words, the `PartialBlockIdentifier` of a block after an omitted block should
/// reference the last non-omitted block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct BlockTransactionResponse {
    /// Transactions contain an array of Operations that are attributable to the same TransactionIdentifier.
    pub transaction: Transaction,
}

impl BlockTransactionResponse {
    pub fn new(transaction: Transaction) -> BlockTransactionResponse {
        BlockTransactionResponse { transaction }
    }
}

/// ConstructionDeriveResponse is returned by the `/construction/derive`
/// endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
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
