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

/// A transaction sent from the minter's dedicated sweeper address: an EIP-7702 transaction
/// (`0x04`) whose authorization list carries one tuple per deposit address it sweeps, or a plain
/// EIP-1559 one (`0x02`) for a sweep that delegates nothing — the native-ETH deposit addresses are
/// deliberately never delegated, so their sweeps take that shape.
///
/// An address already delegated is not exempt from the list: the tuples are signed for nonce 0,
/// which installs a delegation that is missing and is skipped for an address that has one, so no
/// sweep has to know which is which. The [`SweepTransaction::Eip7702`] variant still always
/// carries a non-empty authorization list, a type-`0x04` transaction with an empty one being
/// invalid: [`SweepTransaction::new`] is what decides the variant, and it decides on exactly
/// whether there is anything to put in that list.
#[derive(Clone, Eq, PartialEq, Debug, Decode, Encode)]
pub enum SweepTransaction {
    #[n(0)]
    Eip1559(#[n(0)] Eip1559TransactionRequest),
    #[n(1)]
    Eip7702(#[n(0)] DelegatingSweep),
}

/// An EIP-7702 sweep, i.e. one whose authorization list installs at least one delegation. A
/// type-`0x04` transaction with an empty list is invalid, and encoding one traps, so the
/// transaction is private and reachable only through [`DelegatingSweep::new`] — including when it
/// comes back from the event log, where a trap would be an unupgradeable canister rather than a
/// failed operation.
#[derive(Clone, Eq, PartialEq, Debug, Encode)]
#[cbor(transparent)]
pub struct DelegatingSweep(#[n(0)] Eip7702TransactionRequest);

impl DelegatingSweep {
    /// The sweep `transaction`, or [`None`] if it installs no delegation.
    pub fn new(transaction: Eip7702TransactionRequest) -> Option<Self> {
        if transaction.authorization_list.is_empty() {
            return None;
        }
        Some(Self(transaction))
    }

    pub fn transaction(&self) -> &Eip7702TransactionRequest {
        &self.0
    }

    /// The same sweep at a different price: a fee bump leaves the authorization list alone, so what
    /// it installs is unchanged.
    fn with_price_and_amount(&self, price: TransactionPrice, amount: Wei) -> Self {
        Self(self.0.with_price_and_amount(price, amount))
    }
}

impl<'b, C> minicbor::Decode<'b, C> for DelegatingSweep {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        Self::new(d.decode_with(ctx)?).ok_or_else(|| {
            minicbor::decode::Error::message("EIP-7702 sweep with an empty authorization list")
        })
    }
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
        // EIP-7702 skips an authorization whose chain id is neither zero nor the chain the
        // transaction runs on, without failing the transaction: the sweep would pay for the
        // delegation, not install it, and then call an address with no code.
        assert!(
            authorizations
                .iter()
                .all(|a| a.chain_id == 0 || a.chain_id == transaction.chain_id),
            "BUG: authorization for another chain than {}",
            transaction.chain_id
        );
        let delegating = Eip7702TransactionRequest {
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
        };
        Self::Eip7702(
            DelegatingSweep::new(delegating).expect("BUG: the authorization list is not empty"),
        )
    }

    /// The delegations this transaction installs, empty for a plain EIP-1559 sweep.
    pub fn authorizations(&self) -> &[SignedAuthorization] {
        match self {
            Self::Eip1559(_) => &[],
            Self::Eip7702(sweep) => &sweep.transaction().authorization_list,
        }
    }

    /// The transaction in whichever shape it takes, for everything both shapes have in common.
    fn as_signable(&self) -> &dyn SignableTransaction {
        match self {
            Self::Eip1559(transaction) => transaction,
            Self::Eip7702(sweep) => sweep.transaction(),
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
            Self::Eip7702(sweep) => Self::Eip7702(sweep.with_price_and_amount(price, amount)),
        }
    }
}
