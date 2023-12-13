use crate::checked_amount::CheckedAmountOf;
use crate::eth_rpc::{Hash, HttpResponsePayload, LogEntry, ResponseTransform};
use crate::numeric::{BlockNumber, GasAmount, Wei, WeiPerGas};
use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct TransactionReceipt {
    /// The hash of the block containing the transaction.
    #[serde(rename = "blockHash")]
    pub block_hash: Hash,

    /// The number of the block containing the transaction.
    #[serde(rename = "blockNumber")]
    pub block_number: BlockNumber,

    /// The total base charge plus tip paid for each unit of gas
    #[serde(rename = "effectiveGasPrice")]
    pub effective_gas_price: WeiPerGas,

    /// The amount of gas used by this specific transaction alone
    #[serde(rename = "gasUsed")]
    pub gas_used: GasAmount,

    /// Status of the transaction.
    pub status: TransactionStatus,

    /// The hash of the transaction
    #[serde(rename = "transactionHash")]
    pub transaction_hash: Hash,

    #[serde(rename = "contractAddress")]
    pub contract_address: Option<String>,

    pub from: String,
    pub logs: Vec<LogEntry>,
    #[serde(rename = "logsBloom")]
    pub logs_bloom: String,
    pub to: String,
    #[serde(rename = "transactionIndex")]
    pub transaction_index: CheckedAmountOf<()>,
    pub r#type: String,
}

impl<C> minicbor::Encode<C> for TransactionReceipt {
    fn encode<W: minicbor::encode::Write>(
        &self,
        _e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        unimplemented!("TransactionReceipt")
    }
}

impl<'b, C> minicbor::Decode<'b, C> for TransactionReceipt {
    fn decode(
        _d: &mut minicbor::Decoder<'b>,
        _ctx: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        unimplemented!("TransactionReceipt")
    }
}

impl TransactionReceipt {
    pub fn effective_transaction_fee(&self) -> Wei {
        self.effective_gas_price
            .transaction_cost(self.gas_used)
            .expect("ERROR: overflow during transaction fee calculation")
    }
}

impl HttpResponsePayload for TransactionReceipt {
    fn response_transform() -> Option<ResponseTransform> {
        Some(ResponseTransform::TransactionReceipt)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Encode, Decode)]
#[serde(try_from = "ethnum::u256", into = "ethnum::u256")]
pub enum TransactionStatus {
    /// Transaction was mined and executed successfully.
    #[n(0)]
    Success,

    /// Transaction was mined but execution failed (e.g., out-of-gas error).
    /// The amount of the transaction is returned to the sender but gas is consumed.
    /// Note that this is different from a transaction that is not mined at all: a failed transaction
    /// is part of the blockchain and the next transaction from the same sender should have an incremented
    /// transaction nonce.
    #[n(1)]
    Failure,
}

impl From<TransactionStatus> for ethnum::u256 {
    fn from(value: TransactionStatus) -> Self {
        match value {
            TransactionStatus::Success => ethnum::u256::ONE,
            TransactionStatus::Failure => ethnum::u256::ZERO,
        }
    }
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

impl Display for TransactionStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionStatus::Success => write!(f, "Success"),
            TransactionStatus::Failure => write!(f, "Failure"),
        }
    }
}
