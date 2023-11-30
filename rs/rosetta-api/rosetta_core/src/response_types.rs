use crate::identifiers::NetworkIdentifier;
use crate::objects::Currency;
use crate::objects::Error;
use crate::objects::Object;
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
