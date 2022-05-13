use crate::models::amount::Amount;
use crate::models::{AccountIdentifier, CoinChange, Object};

use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumIter};

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
    #[serde(default)]
    pub related_operations: Option<Vec<OperationIdentifier>>,

    /// The network-specific type of the operation. Ensure that any type that
    /// can be returned here is also specified in the NetworkOptionsResponse.
    /// This can be very useful to downstream consumers that parse all block
    /// data.
    #[serde(rename = "type")]
    pub _type: OperationType,

    /// The network-specific status of the operation. Status is not defined on
    /// the transaction object because blockchains with smart contracts may have
    /// transactions that partially apply.  Blockchains with atomic transactions
    /// (all operations succeed or all operations fail) will have the same
    /// status for each operation.
    #[serde(rename = "status")]
    pub status: Option<String>,

    #[serde(rename = "account")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub account: Option<AccountIdentifier>,

    #[serde(rename = "amount")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub amount: Option<Amount>,

    #[serde(rename = "coin_change")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub coin_change: Option<CoinChange>,

    #[serde(rename = "metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub metadata: Option<Object>,
}

impl Operation {
    pub fn new(
        op_id: i64,
        _type: OperationType,
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

#[derive(Display, Debug, Clone, PartialEq, EnumIter, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub enum OperationType {
    #[serde(rename = "TRANSACTION")]
    #[strum(serialize = "TRANSACTION")]
    Transaction,
    #[serde(rename = "MINT")]
    #[strum(serialize = "MINT")]
    Mint,
    #[serde(rename = "BURN")]
    #[strum(serialize = "BURN")]
    Burn,
    #[serde(rename = "FEE")]
    #[strum(serialize = "FEE")]
    Fee,
    #[serde(rename = "STAKE")]
    #[strum(serialize = "STAKE")]
    Stake,
    #[serde(rename = "START_DISSOLVING")]
    #[strum(serialize = "START_DISSOLVING")]
    StartDissolving,
    #[serde(rename = "STOP_DISSOLVING")]
    #[strum(serialize = "STOP_DISSOLVING")]
    StopDissolving,
    #[serde(rename = "SET_DISSOLVE_TIMESTAMP")]
    #[strum(serialize = "SET_DISSOLVE_TIMESTAMP")]
    SetDissolveTimestamp,
    #[serde(rename = "DISBURSE")]
    #[strum(serialize = "DISBURSE")]
    Disburse,
    #[serde(rename = "ADD_HOTKEY")]
    #[strum(serialize = "ADD_HOTKEY")]
    AddHotkey,
    #[serde(rename = "REMOVE_HOTKEY")]
    #[strum(serialize = "REMOVE_HOTKEY")]
    RemoveHotkey,
    #[serde(rename = "SPAWN")]
    #[strum(serialize = "SPAWN")]
    Spawn,
    #[serde(rename = "MERGE_MATURITY")]
    #[strum(serialize = "MERGE_MATURITY")]
    MergeMaturity,
    #[serde(rename = "NEURON_INFO")]
    #[strum(serialize = "NEURON_INFO")]
    NeuronInfo,
    #[serde(rename = "FOLLOW")]
    #[strum(serialize = "FOLLOW")]
    Follow,
}
