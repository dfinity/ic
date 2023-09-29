use crate::address::Address;
use crate::eth_rpc::{Hash, HttpResponsePayload, Quantity, ResponseTransform};
use crate::numeric::{BlockNumber, Wei};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TransactionReceipt {
    /// The hash of the block containing the transaction.
    pub block_hash: Hash,

    /// The number of the block containing the transaction.
    pub block_number: BlockNumber,

    /// The total base charge plus tip paid for each unit of gas
    pub effective_gas_price: Wei,

    /// The address of the sender.
    pub from: Address,

    /// The address of the receiver.
    /// `None` when the transaction is a contract creation transaction.
    pub to: Option<Address>,

    /// The contract address created if the transaction was a contract creation,
    /// otherwise `None`.
    pub contract_address: Option<Address>,

    /// The amount of gas used by this specific transaction alone
    pub gas_used: Quantity,

    /// Status of the transaction.
    pub status: TransactionStatus,

    /// The hash of the transaction
    pub transaction_hash: Hash,

    /// Index of the transaction within the block.
    /// A Block has a limit of 30 million gas and a transaction costs at least 21_000 gas,
    /// meaning that a block contains at most 1428 transactions, see
    /// <https://ethereum.org/en/developers/docs/gas/#block-size>
    pub transaction_index: Quantity,
}

impl HttpResponsePayload for TransactionReceipt {
    fn response_transform() -> Option<ResponseTransform> {
        Some(ResponseTransform::TransactionReceipt)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(try_from = "ethnum::u256")]
pub enum TransactionStatus {
    /// Transaction was mined and executed successfully.
    Success,

    /// Transaction was mined but execution failed (e.g., out-of-gas error).
    /// The amount of the transaction is returned to the sender but gas is consumed.
    /// Note that this is different from a transaction that is not mined at all: a failed transaction
    /// is part of the blockchain and the next transaction from the same sender should have an incremented
    /// transaction nonce.
    Failure,
}

impl TryFrom<ethnum::u256> for TransactionStatus {
    type Error = String;

    fn try_from(value: ethnum::u256) -> Result<Self, Self::Error> {
        match value {
            ethnum::u256::ZERO => Ok(TransactionStatus::Failure),
            ethnum::u256::ONE => Ok(TransactionStatus::Success),
            _ => Err(format!("invalid transaction status: {}", value)),
        }
    }
}
