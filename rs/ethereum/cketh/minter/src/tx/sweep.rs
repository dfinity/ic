use super::{
    AccessList, Eip1559TransactionRequest, Eip7702TransactionRequest, SignableTransaction, Signed,
    SignedAuthorization, TransactionPrice,
};
use crate::numeric::{GasAmount, TransactionNonce, Wei, WeiPerGas};
use ic_ethereum_types::Address;
use minicbor::{Decode, Encode};
use rlp::RlpStream;

/// Immutable signed sweep transaction.
/// Use [`sign`](super::sign) to create a newly signed transaction or
/// `SignedSweepTransaction::from()` if the signature is already known.
pub type SignedSweepTransaction = Signed<SweepTransaction>;

/// A transaction sent from the minter's dedicated sweeper address: a plain EIP-1559 transaction
/// (`0x02`), or an EIP-7702 one (`0x04`) whose authorization list additionally installs the
/// delegation to the sweeper contract of every deposit address it sweeps.
///
/// A deposit address is delegated once and stays delegated, so only the first sweep touching it
/// needs type `0x04`. The [`SweepTransaction::Eip7702`] variant therefore always carries a
/// non-empty authorization list: [`SweepTransaction::new`] is what decides the variant, and it
/// decides on exactly that.
#[derive(Clone, Eq, PartialEq, Debug, Decode, Encode)]
pub enum SweepTransaction {
    #[n(0)]
    Eip1559(#[n(0)] Eip1559TransactionRequest),
    #[n(1)]
    Eip7702(#[n(0)] Eip7702TransactionRequest),
}

impl SweepTransaction {
    /// The sweep `transaction`, installing the delegations `authorizations` attests to: type
    /// `0x04` if there are any to install, and type `0x02` if there are none.
    pub fn new(
        transaction: Eip1559TransactionRequest,
        authorizations: Vec<SignedAuthorization>,
    ) -> Self {
        if authorizations.is_empty() {
            return Self::Eip1559(transaction);
        }
        Self::Eip7702(Eip7702TransactionRequest {
            chain_id: transaction.chain_id,
            nonce: transaction.nonce,
            max_priority_fee_per_gas: transaction.max_priority_fee_per_gas,
            max_fee_per_gas: transaction.max_fee_per_gas,
            gas_limit: transaction.gas_limit,
            destination: transaction.destination,
            amount: transaction.amount,
            data: transaction.data,
            access_list: transaction.access_list,
            authorization_list: authorizations,
        })
    }

    /// The delegations this transaction installs, empty for a plain EIP-1559 sweep.
    pub fn authorizations(&self) -> &[SignedAuthorization] {
        match self {
            Self::Eip1559(_) => &[],
            Self::Eip7702(transaction) => &transaction.authorization_list,
        }
    }

    /// The transaction in whichever shape it takes, for everything both shapes have in common.
    fn as_signable(&self) -> &dyn SignableTransaction {
        match self {
            Self::Eip1559(transaction) => transaction,
            Self::Eip7702(transaction) => transaction,
        }
    }
}

impl rlp::Encodable for SweepTransaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        self.as_signable().rlp_append(s)
    }
}

impl SignableTransaction for SweepTransaction {
    fn transaction_type(&self) -> u8 {
        self.as_signable().transaction_type()
    }

    fn rlp_inner(&self, rlp: &mut RlpStream) {
        self.as_signable().rlp_inner(rlp)
    }

    fn chain_id(&self) -> u64 {
        self.as_signable().chain_id()
    }

    fn nonce(&self) -> TransactionNonce {
        self.as_signable().nonce()
    }

    fn gas_limit(&self) -> GasAmount {
        self.as_signable().gas_limit()
    }

    fn max_fee_per_gas(&self) -> WeiPerGas {
        self.as_signable().max_fee_per_gas()
    }

    fn max_priority_fee_per_gas(&self) -> WeiPerGas {
        self.as_signable().max_priority_fee_per_gas()
    }

    fn destination(&self) -> &Address {
        self.as_signable().destination()
    }

    fn amount(&self) -> &Wei {
        self.as_signable().amount()
    }

    fn data(&self) -> &[u8] {
        self.as_signable().data()
    }

    fn access_list(&self) -> &AccessList {
        self.as_signable().access_list()
    }

    fn with_price_and_amount(&self, price: TransactionPrice, amount: Wei) -> Self {
        match self {
            Self::Eip1559(transaction) => {
                Self::Eip1559(transaction.with_price_and_amount(price, amount))
            }
            Self::Eip7702(transaction) => {
                Self::Eip7702(transaction.with_price_and_amount(price, amount))
            }
        }
    }
}
