use super::{AccessList, Finalized, Resubmittable, SignableTransaction, Signed, TransactionPrice};
use crate::numeric::{GasAmount, TransactionNonce, Wei, WeiPerGas};
use ic_ethereum_types::Address;
use minicbor::{Decode, Encode};
use rlp::RlpStream;

const EIP1559_TX_ID: u8 = 2;

/// Immutable signed EIP-1559 transaction.
/// Use [`sign`](super::sign) to create a newly signed transaction or
/// `SignedEip1559TransactionRequest::from()` if the signature is already known.
pub type SignedEip1559TransactionRequest = Signed<Eip1559TransactionRequest>;

/// Immutable finalized EIP-1559 transaction.
/// Use [`Signed::try_finalize`] to create a finalized transaction.
pub type FinalizedEip1559Transaction = Finalized<Eip1559TransactionRequest>;

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

impl rlp::Encodable for Eip1559TransactionRequest {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_unbounded_list();
        self.rlp_inner(s);
        s.finalize_unbounded_list();
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

    fn chain_id(&self) -> u64 {
        self.chain_id
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

    fn destination(&self) -> &Address {
        &self.destination
    }

    fn amount(&self) -> &Wei {
        &self.amount
    }

    fn data(&self) -> &[u8] {
        &self.data
    }

    fn access_list(&self) -> &AccessList {
        &self.access_list
    }

    fn with_price_and_amount(&self, price: TransactionPrice, amount: Wei) -> Self {
        Self {
            max_priority_fee_per_gas: price.max_priority_fee_per_gas,
            max_fee_per_gas: price.max_fee_per_gas,
            gas_limit: price.gas_limit,
            amount,
            ..self.clone()
        }
    }
}
