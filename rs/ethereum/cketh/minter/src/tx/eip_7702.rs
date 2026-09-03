use super::{
    AccessList, SignableTransaction, Signed, TransactionPrice, TransactionSignature, encode_u256,
};
use crate::{
    deposit_address::{DepositAddressSchema, deposit_derivation_path},
    eth_rpc::Hash,
    numeric::{GasAmount, TransactionNonce, Wei, WeiPerGas},
};
use ethnum::u256;
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use minicbor::{Decode, Encode};
use rlp::RlpStream;
use serde_bytes::ByteBuf;

const SET_CODE_TX_ID: u8 = 4;
const EIP7702_AUTHORIZATION_MAGIC: u8 = 5;

/// Immutable signed EIP-7702 transaction.
/// Use [`sign`](super::sign) to create a newly signed transaction or
/// `SignedEip7702TransactionRequest::from()` if the signature is already known.
pub type SignedEip7702TransactionRequest = Signed<Eip7702TransactionRequest>;

/// <https://eips.ethereum.org/EIPS/eip-7702>
#[derive(Clone, Eq, PartialEq, Debug, Decode, Encode)]
pub struct Eip7702TransactionRequest {
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
    #[n(9)]
    pub authorization_list: Vec<SignedAuthorization>,
}

impl AsRef<Eip7702TransactionRequest> for Eip7702TransactionRequest {
    fn as_ref(&self) -> &Eip7702TransactionRequest {
        self
    }
}

/// What a deposit address authorizes, and what a stored signature over it is valid for: the tuple
/// itself, plus the account whose deposit address signed it.
///
/// This is the key an authorization is cached under, so any change to what is authorized — another
/// chain, another sweeper contract, another nonce — misses the cache and is signed afresh instead
/// of reusing a tuple that no longer says what the minter means.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Decode, Encode)]
pub struct AuthorizationRequest {
    #[n(0)]
    account: Account,
    #[n(1)]
    chain_id: u64,
    #[n(2)]
    delegate: Address,
    #[n(3)]
    nonce: TransactionNonce,
}

impl AuthorizationRequest {
    pub fn new(
        account: Account,
        chain_id: u64,
        delegate: Address,
        nonce: TransactionNonce,
    ) -> Self {
        Self {
            account,
            chain_id,
            delegate,
            nonce,
        }
    }

    pub fn account(&self) -> Account {
        self.account
    }

    pub fn derivation_path(&self) -> Vec<ByteBuf> {
        deposit_derivation_path(DepositAddressSchema::CkErc20, &self.account)
    }

    pub fn authorization(&self) -> Authorization {
        Authorization {
            chain_id: self.chain_id,
            delegate: self.delegate,
            nonce: self.nonce,
        }
    }

    pub fn signed_with(&self, signature: TransactionSignature) -> SignedAuthorization {
        SignedAuthorization {
            chain_id: self.chain_id,
            delegate: self.delegate,
            nonce: self.nonce,
            y_parity: signature.signature_y_parity,
            r: signature.r,
            s: signature.s,
        }
    }
}

/// An unsigned EIP-7702 authorization signed over by an authority to delegate its code.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Authorization {
    pub chain_id: u64,
    pub delegate: Address,
    pub nonce: TransactionNonce,
}

impl rlp::Encodable for Authorization {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_unbounded_list();
        s.append(&self.chain_id);
        s.append(&self.delegate.as_ref());
        s.append(&self.nonce);
        s.finalize_unbounded_list();
    }
}

impl Authorization {
    /// The authority signs over
    /// keccak256(0x05 || rlp([chain_id, delegate, nonce])),
    /// where `||` denotes string concatenation.
    pub fn hash(&self) -> Hash {
        use rlp::Encodable;
        let mut bytes = self.rlp_bytes().to_vec();
        bytes.insert(0, EIP7702_AUTHORIZATION_MAGIC);
        Hash(ic_sha3::Keccak256::hash(bytes))
    }
}

/// A signed EIP-7702 authorization tuple `[chain_id, delegate, nonce, y_parity, r, s]`.
#[derive(Clone, Eq, PartialEq, Debug, Decode, Encode)]
pub struct SignedAuthorization {
    #[n(0)]
    pub chain_id: u64,
    #[n(1)]
    pub delegate: Address,
    #[n(2)]
    pub nonce: TransactionNonce,
    #[n(3)]
    pub y_parity: bool,
    #[cbor(n(4), with = "icrc_cbor::u256")]
    pub r: u256,
    #[cbor(n(5), with = "icrc_cbor::u256")]
    pub s: u256,
}

impl rlp::Encodable for SignedAuthorization {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_unbounded_list();
        s.append(&self.chain_id);
        s.append(&self.delegate.as_ref());
        s.append(&self.nonce);
        s.append(&self.y_parity);
        encode_u256(s, self.r);
        encode_u256(s, self.s);
        s.finalize_unbounded_list();
    }
}

impl rlp::Encodable for Eip7702TransactionRequest {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_unbounded_list();
        self.rlp_inner(s);
        s.finalize_unbounded_list();
    }
}

impl SignableTransaction for Eip7702TransactionRequest {
    fn transaction_type(&self) -> u8 {
        SET_CODE_TX_ID
    }

    fn rlp_inner(&self, rlp: &mut RlpStream) {
        assert!(
            !self.authorization_list.is_empty(),
            "BUG: EIP-7702 transaction must have a non-empty authorization_list"
        );
        rlp.append(&self.chain_id);
        rlp.append(&self.nonce);
        rlp.append(&self.max_priority_fee_per_gas);
        rlp.append(&self.max_fee_per_gas);
        rlp.append(&self.gas_limit);
        rlp.append(&self.destination.as_ref());
        rlp.append(&self.amount);
        rlp.append(&self.data);
        rlp.append(&self.access_list);
        rlp.append_list(&self.authorization_list);
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
