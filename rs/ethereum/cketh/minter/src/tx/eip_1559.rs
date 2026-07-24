use super::{
    AccessList, GasFeeEstimate, ResubmissionStrategy, ResubmitTransactionError, Resubmittable,
    SignableTransaction, Signed, TransactionPrice,
};
use crate::{
    eth_rpc::Hash,
    eth_rpc_client::responses::{TransactionReceipt, TransactionStatus},
    numeric::{BlockNumber, GasAmount, TransactionNonce, Wei, WeiPerGas},
};
use ic_ethereum_types::Address;
use minicbor::{Decode, Encode};
use rlp::RlpStream;

const EIP1559_TX_ID: u8 = 2;

/// Immutable signed EIP-1559 transaction.
/// Use [`sign`](super::sign) to create a newly signed transaction or
/// `SignedEip1559TransactionRequest::from()` if the signature is already known.
pub type SignedEip1559TransactionRequest = Signed<Eip1559TransactionRequest>;

pub type TransactionRequest = Resubmittable<Eip1559TransactionRequest>;
pub type SignedTransactionRequest = Resubmittable<SignedEip1559TransactionRequest>;

/// <https://eips.ethereum.org/EIPS/eip-1559>
#[derive(Clone, Eq, PartialEq, Debug, Decode, Encode)]
pub struct Eip1559TransactionRequest {
    #[n(0)]
    pub chain_id: u64,
    #[n(1)]
    pub nonce: TransactionNonce,
    #[n(2)]
    pub max_priority_fee_per_gas: WeiPerGas,
    #[n(3)]
    pub max_fee_per_gas: WeiPerGas,
    #[n(4)]
    pub gas_limit: GasAmount,
    #[n(5)]
    pub destination: Address,
    #[n(6)]
    pub amount: Wei,
    #[cbor(n(7), with = "minicbor::bytes")]
    pub data: Vec<u8>,
    #[n(8)]
    pub access_list: AccessList,
}

impl AsRef<Eip1559TransactionRequest> for Eip1559TransactionRequest {
    fn as_ref(&self) -> &Eip1559TransactionRequest {
        self
    }
}

impl SignedTransactionRequest {
    pub fn resubmit(
        &self,
        new_gas_fee: GasFeeEstimate,
    ) -> Result<Option<Eip1559TransactionRequest>, ResubmitTransactionError> {
        let transaction_request = self.transaction.transaction();
        let last_tx_price = transaction_request.transaction_price();
        let new_tx_price = last_tx_price
            .clone()
            .resubmit_transaction_price(new_gas_fee);
        if new_tx_price == last_tx_price {
            return Ok(None);
        }

        if new_tx_price.max_transaction_fee() > self.resubmission.allowed_max_transaction_fee() {
            return Err(ResubmitTransactionError::InsufficientTransactionFee {
                allowed_max_transaction_fee: self.resubmission.allowed_max_transaction_fee(),
                actual_max_transaction_fee: new_tx_price.max_transaction_fee(),
            });
        }
        let new_amount = match self.resubmission {
            ResubmissionStrategy::ReduceEthAmount { withdrawal_amount } => {
                withdrawal_amount.checked_sub(new_tx_price.max_transaction_fee())
                    .expect("BUG: withdrawal_amount covers new transaction fee because it was checked before")
            }
            ResubmissionStrategy::GuaranteeEthAmount { .. } => transaction_request.amount,
        };
        Ok(Some(Eip1559TransactionRequest {
            max_priority_fee_per_gas: new_tx_price.max_priority_fee_per_gas,
            max_fee_per_gas: new_tx_price.max_fee_per_gas,
            gas_limit: new_tx_price.gas_limit,
            amount: new_amount,
            ..transaction_request.clone()
        }))
    }
}

impl rlp::Encodable for Eip1559TransactionRequest {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_unbounded_list();
        self.rlp_inner(s);
        s.finalize_unbounded_list();
    }
}

/// Immutable finalized transaction.
/// Use `SignedEip1559TransactionRequest::try_finalize()` to create a finalized transaction.
#[derive(Clone, Eq, PartialEq, Debug, Decode, Encode)]
pub struct FinalizedEip1559Transaction {
    #[n(0)]
    transaction: SignedEip1559TransactionRequest,
    #[n(1)]
    receipt: TransactionReceipt,
}

impl AsRef<Eip1559TransactionRequest> for FinalizedEip1559Transaction {
    fn as_ref(&self) -> &Eip1559TransactionRequest {
        self.transaction.as_ref()
    }
}

impl FinalizedEip1559Transaction {
    pub fn destination(&self) -> &Address {
        &self.transaction.transaction().destination
    }

    pub fn block_number(&self) -> &BlockNumber {
        &self.receipt.block_number
    }

    pub fn transaction_amount(&self) -> &Wei {
        &self.transaction.transaction().amount
    }

    pub fn transaction_hash(&self) -> &Hash {
        &self.receipt.transaction_hash
    }

    pub fn transaction_data(&self) -> &[u8] {
        &self.transaction.transaction().data
    }

    pub fn transaction(&self) -> &Eip1559TransactionRequest {
        self.transaction.transaction()
    }

    pub fn transaction_price(&self) -> TransactionPrice {
        self.transaction.transaction().transaction_price()
    }

    pub fn effective_transaction_fee(&self) -> Wei {
        self.receipt.effective_transaction_fee()
    }

    pub fn transaction_status(&self) -> &TransactionStatus {
        &self.receipt.status
    }
}

impl SignedEip1559TransactionRequest {
    pub fn try_finalize(
        self,
        receipt: TransactionReceipt,
    ) -> Result<FinalizedEip1559Transaction, String> {
        if self.hash() != receipt.transaction_hash {
            return Err(format!(
                "transaction hash mismatch: expected {}, got {}",
                self.hash(),
                receipt.transaction_hash
            ));
        }
        if self.transaction().max_fee_per_gas < receipt.effective_gas_price {
            return Err(format!(
                "transaction max_fee_per_gas {} is smaller than effective_gas_price {}",
                self.transaction().max_fee_per_gas,
                receipt.effective_gas_price
            ));
        }
        if self.transaction().gas_limit < receipt.gas_used {
            return Err(format!(
                "transaction gas limit {} is smaller than gas used {}",
                self.transaction().gas_limit,
                receipt.gas_used
            ));
        }
        Ok(FinalizedEip1559Transaction {
            transaction: self,
            receipt,
        })
    }
}

impl SignableTransaction for Eip1559TransactionRequest {
    fn transaction_type(&self) -> u8 {
        EIP1559_TX_ID
    }

    fn rlp_inner(&self, rlp: &mut RlpStream) {
        rlp.append(&self.chain_id);
        rlp.append(&self.nonce);
        rlp.append(&self.max_priority_fee_per_gas);
        rlp.append(&self.max_fee_per_gas);
        rlp.append(&self.gas_limit);
        rlp.append(&self.destination.as_ref());
        rlp.append(&self.amount);
        rlp.append(&self.data);
        rlp.append(&self.access_list);
    }

    fn nonce(&self) -> TransactionNonce {
        self.nonce
    }

    fn gas_limit(&self) -> GasAmount {
        self.gas_limit
    }

    fn max_fee_per_gas(&self) -> WeiPerGas {
        self.max_fee_per_gas
    }

    fn max_priority_fee_per_gas(&self) -> WeiPerGas {
        self.max_priority_fee_per_gas
    }
}
