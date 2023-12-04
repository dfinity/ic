use crate::identifiers::BlockIdentifier;
use crate::identifiers::NetworkIdentifier;
use crate::objects::Currency;
use crate::objects::Error;
use crate::objects::Object;
use crate::objects::ObjectMap;
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

/// The Version object is utilized to inform the client of the versions of different components of the Rosetta implementation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Version {
    /// The rosetta_version is the version of the Rosetta interface
    /// the implementation adheres to. This can be useful for clients looking to reliably parse responses.
    pub rosetta_version: String,

    /// The node_version is the canonical version of the node runtime. This can help clients manage deployments.
    pub node_version: String,

    /// When a middleware server is used to adhere to the Rosetta interface, it should return its version here.
    /// This can help clients manage deployments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middleware_version: Option<String>,

    /// Any other information that may be useful about versioning of dependent services should be returned here.
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

/// Allow specifies supported Operation status, Operation types, and all possible error statuses.
/// This Allow object is used by clients to validate the correctness of a Rosetta Server implementation.
/// It is expected that these clients will error if they receive some response that contains any of
/// the above information that is not specified here.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Allow {
    /// All Operation.Status this implementation supports. Any status that is returned during parsing
    /// that is not listed here will cause client validation to error.
    pub operation_statuses: Vec<OperationStatus>,

    /// All Operation.Type this implementation supports. Any type that is returned during parsing
    /// that is not listed here will cause client validation to error.
    pub operation_types: Vec<String>,

    /// All Errors that this implementation could return. Any error that is returned during parsing
    /// that is not listed here will cause client validation to error.
    pub errors: Vec<Error>,

    /// Any Rosetta implementation that supports querying the balance of an account at any height in
    /// the past should set this to true.
    pub historical_balance_lookup: bool,

    /// If populated, timestamp_start_index indicates the first block index where block timestamps
    /// are considered valid (i.e. all blocks less than timestamp_start_index could have invalid timestamps).
    /// This is useful when the genesis block (or blocks) of a network have timestamp 0. If not populated,
    /// block timestamps are assumed to be valid for all available blocks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_start_index: Option<i64>,

    /// All methods that are supported by the /call endpoint. Communicating which parameters should be provided
    /// to /call is the responsibility of the implementer (this is en lieu of defining an entire type system
    /// and requiring the implementer to define that in Allow).
    pub call_methods: Vec<String>,

    /// BalanceExemptions is an array of BalanceExemption indicating which account balances could change without
    /// a corresponding Operation. BalanceExemptions should be used sparingly as they may introduce significant
    /// complexity for integrators that attempt to reconcile all account balance changes. If your implementation
    /// relies on any BalanceExemptions, you MUST implement historical balance lookup (the ability to query an
    /// account balance at any BlockIdentifier).
    pub balance_exemptions: Vec<BalanceExemption>,

    /// Any Rosetta implementation that can update an AccountIdentifier's unspent coins based on the contents
    /// of the mempool should populate this field as true. If false, requests to /account/coins that set
    /// include_mempool as true will be automatically rejected.
    pub mempool_coins: bool,

    /// Case specifies the expected case for strings and hashes.
    #[serde(
        default,
        with = "::serde_with::rust::double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub block_hash_case: Option<Option<Case>>,

    /// Case specifies the expected case for strings and hashes.
    #[serde(
        default,
        with = "::serde_with::rust::double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub transaction_hash_case: Option<Option<Case>>,
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
            timestamp_start_index: None,
            call_methods: vec![],
            balance_exemptions: vec![],
            mempool_coins: false,
            block_hash_case: None,
            transaction_hash_case: None,
        }
    }
}

/// BalanceExemption indicates that the balance for an exempt account could change without a corresponding Operation.
/// This typically occurs with staking rewards, vesting balances, and Currencies with a dynamic supply.
/// Currently, it is possible to exempt an account from strict reconciliation by SubAccountIdentifier.Address or by Currency.
/// This means that any account with SubAccountIdentifier.Address would be exempt or any balance of a particular Currency would
/// be exempt, respectively. BalanceExemptions should be used sparingly as they may introduce significant complexity for
/// integrators that attempt to reconcile all account balance changes. If your implementation relies on any BalanceExemptions,
/// you MUST implement historical balance lookup (the ability to query an account balance at any BlockIdentifier).
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BalanceExemption {
    /// SubAccountAddress is the SubAccountIdentifier.Address that the BalanceExemption applies
    /// to (regardless of the value of SubAccountIdentifier.Metadata).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_account_address: Option<String>,

    /// Currency is composed of a canonical Symbol and Decimals. This Decimals value is used to
    /// convert an Amount.Value from atomic units (Satoshis) to standard units (Bitcoins).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<Box<Currency>>,

    /// ExemptionType is used to indicate if the live balance for an account subject to a BalanceExemption
    /// could increase above, decrease below, or equal the computed balance. * greater_or_equal:
    /// The live balance may increase above or equal the computed balance. This typically occurs with staking
    /// rewards that accrue on each block. * less_or_equal: The live balance may decrease below or equal the computed balance.
    /// This typically occurs as balance moves from locked to spendable on a vesting account. * dynamic:
    /// The live balance may increase above, decrease below, or equal the computed balance.
    /// This typically occurs with tokens that have a dynamic supply.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exemption_type: Option<ExemptionType>,
}

/// ExemptionType is used to indicate if the live balance for an account subject to a BalanceExemption could increase above,
/// decrease below, or equal the computed balance.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum ExemptionType {
    /// The live balance may increase above or equal the computed balance. This typically occurs with staking rewards that accrue on each block.
    GreaterOrEqual,
    /// The live balance may decrease below or equal the computed balance. This typically occurs as balance moves from locked to spendable on a vesting account.
    LessOrEqual,
    /// The live balance may increase above, decrease below, or equal the computed balance. This typically occurs with tokens that have a dynamic supply.
    Dynamic,
}

impl Default for ExemptionType {
    fn default() -> ExemptionType {
        Self::GreaterOrEqual
    }
}

/// Case specifies the expected case for strings and hashes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Case {
    /// Lower Case hash
    UpperCase,
    /// Upper Case hash
    LowerCase,
    /// Case sensitive hash
    CaseSensitive,
    /// Case insensitive hash
    Null,
}

/// OperationStatus is utilized to indicate which Operation status are considered successful.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperationStatus {
    /// The status is the network-specific status of the operation.
    pub status: String,

    /// An Operation is considered successful if the Operation.Amount should affect the Operation.Account.
    /// Some blockchains (like Bitcoin) only include successful operations in blocks but other blockchains
    /// (like Ethereum) include unsuccessful operations that incur a fee. To reconcile the computed balance
    /// from the stream of Operations, it is critical to understand which Operation.
    /// Status indicate an Operation is successful and should affect an Account.
    pub successful: bool,
}

impl OperationStatus {
    pub fn new(status: String, successful: bool) -> OperationStatus {
        OperationStatus { status, successful }
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
    #[serde(rename = "current_block_identifier")]
    pub current_block_identifier: BlockIdentifier,

    /// The timestamp of the block in milliseconds since the Unix Epoch. The
    /// timestamp is stored in milliseconds because some blockchains produce
    /// blocks more often than once a second.
    #[serde(rename = "current_block_timestamp")]
    pub current_block_timestamp: u64,

    /// The block_identifier uniquely identifies a block in a particular network.
    #[serde(rename = "genesis_block_identifier")]
    pub genesis_block_identifier: BlockIdentifier,

    /// The block_identifier uniquely identifies a block in a particular network.
    #[serde(rename = "oldest_block_identifier")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_block_identifier: Option<BlockIdentifier>,

    /// SyncStatus is used to provide additional context about an implementation's sync status. This object is often used by implementations to indicate healthiness when block data cannot be queried until some sync phase completes or cannot be determined by comparing the timestamp of the most recent block with the current time.
    #[serde(rename = "sync_status")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_status: Option<SyncStatus>,

    #[serde(rename = "peers")]
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

/// SyncStatus is used to provide additional context about an implementation's
/// sync status. It is often used to indicate that an implementation is healthy
/// when it cannot be queried  until some sync phase occurs.  If an
/// implementation is immediately queryable, this model is often not populated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct SyncStatus {
    /// CurrentIndex is the index of the last synced block in the current stage. This is a separate field from current_block_identifier in NetworkStatusResponse because blocks with indices up to and including the current_index may not yet be queryable by the caller. To reiterate, all indices up to and including current_block_identifier in NetworkStatusResponse must be queryable via the /block endpoint (excluding indices less than oldest_block_identifier).
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

    /// synced is a boolean that indicates if an implementation has synced up to the most recent block. If this field is not populated, the caller should rely on a traditional tip timestamp comparison to determine if an implementation is synced. This field is particularly useful for quiescent blockchains (blocks only produced when there are pending transactions). In these blockchains, the most recent block could have a timestamp far behind the current time but the node could be healthy and at tip.
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

/// A Peer is a representation of a node's peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct Peer {
    #[serde(rename = "peer_id")]
    pub peer_id: String,

    #[serde(rename = "metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ObjectMap>,
}

impl Peer {
    pub fn new(peer_id: String) -> Peer {
        Peer {
            peer_id,
            metadata: None,
        }
    }
}
