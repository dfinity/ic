use super::{
    AccessList, AccessListItem, SignableTransaction, Signed, StorageKey, TransactionPrice,
    TransactionSignature, compute_recovery_id, encode_u256, split_in_two,
};
use crate::{
    checked_amount::CheckedAmountOf,
    eth_rpc::Hash,
    numeric::{GasAmount, TransactionNonce, Wei, WeiPerGas},
    state::read_state,
};
use ethnum::u256;
use ic_ethereum_types::Address;
use ic_management_canister_types_private::DerivationPath;
use minicbor::{Decode, Encode};
use rlp::{Rlp, RlpStream};
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

    pub async fn sign(self, derivation_path: Vec<ByteBuf>) -> Result<SignedAuthorization, String> {
        if self.chain_id == 0 {
            return Err(
                "BUG: EIP-7702 authorization chain_id must be set explicitly and never 0"
                    .to_string(),
            );
        }
        let hash = self.hash();
        let key_name = read_state(|s| s.ecdsa_key_name.clone());
        let signature = crate::management::sign_with_ecdsa(
            key_name,
            DerivationPath::new(derivation_path.clone()),
            hash.0,
        )
        .await
        .map_err(|e| format!("failed to sign authorization: {e}"))?;
        let recid = compute_recovery_id(&hash, &signature, &derivation_path).await;
        if recid.is_x_reduced() {
            return Err("BUG: affine x-coordinate of r is reduced which is so unlikely to happen that it's probably a bug".to_string());
        }
        let (r_bytes, s_bytes) = split_in_two(signature);
        Ok(SignedAuthorization {
            chain_id: self.chain_id,
            delegate: self.delegate,
            nonce: self.nonce,
            y_parity: recid.is_y_odd(),
            r: u256::from_be_bytes(r_bytes),
            s: u256::from_be_bytes(s_bytes),
        })
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

// TODO(DEFI-2970): drop this decoder in favour of one from `alloy`, whose `TxEip7702` already
// implements it. It is hand-written because the only EIP-7702-aware library is not a dependency
// yet: `ethers-core`, which the replay tests use to decode EIP-1559 transactions, was archived
// before EIP-7702 and stops at transaction type `0x02`.
//
// It also sits in productive code although only tests call it, because no test-only home is
// reachable from all of its callers: `ic-cketh-test-utils` cannot serve this crate's own unit
// tests, since those compile this crate a second time under `cfg(test)` and would receive
// `Eip7702TransactionRequest` values of the other compilation, while the `dump_stable_memory`
// binary links this library and so cannot see `#[cfg(test)]` items either. Moving to `alloy`
// removes the decoder from here altogether, which settles both.
impl SignedEip7702TransactionRequest {
    /// Decodes the payload a signed EIP-7702 transaction is broadcast as, i.e.
    /// `0x04 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to,
    /// value, data, access_list, authorization_list, y_parity, r, s])`. The inverse of
    /// [`Signed::raw_transaction_bytes`].
    ///
    /// # Errors
    /// * a description of why `raw_transaction` is not such a payload.
    pub fn decode(raw_transaction: &[u8]) -> Result<Self, String> {
        let (transaction_type, payload) = raw_transaction
            .split_first()
            .ok_or_else(|| "empty transaction".to_string())?;
        if *transaction_type != SET_CODE_TX_ID {
            return Err(format!(
                "expected an EIP-7702 transaction (type {SET_CODE_TX_ID}), got type {transaction_type}"
            ));
        }
        let rlp = Rlp::new(payload);
        let authorization_list: Vec<SignedAuthorization> = decode_list(&rlp, 9)?
            .iter()
            .map(|item| {
                Ok(SignedAuthorization {
                    chain_id: decode_val(item, 0)?,
                    delegate: decode_address(item, 1)?,
                    nonce: decode_amount(item, 2)?,
                    y_parity: decode_val(item, 3)?,
                    r: decode_u256(item, 4)?,
                    s: decode_u256(item, 5)?,
                })
            })
            .collect::<Result<_, String>>()?;
        if authorization_list.is_empty() {
            return Err(format!(
                "an EIP-7702 transaction (type {SET_CODE_TX_ID}) must have a non-empty authorization list"
            ));
        }
        let transaction = Eip7702TransactionRequest {
            chain_id: decode_val(&rlp, 0)?,
            nonce: decode_amount(&rlp, 1)?,
            max_priority_fee_per_gas: decode_amount(&rlp, 2)?,
            max_fee_per_gas: decode_amount(&rlp, 3)?,
            gas_limit: decode_amount(&rlp, 4)?,
            destination: decode_address(&rlp, 5)?,
            amount: decode_amount(&rlp, 6)?,
            data: decode_bytes(&rlp, 7)?.to_vec(),
            access_list: AccessList(
                decode_list(&rlp, 8)?
                    .iter()
                    .map(|item| {
                        Ok(AccessListItem {
                            address: decode_address(item, 0)?,
                            storage_keys: decode_list(item, 1)?
                                .iter()
                                .map(|key| Ok(StorageKey(decode_be_bytes_of(key)?)))
                                .collect::<Result<_, String>>()?,
                        })
                    })
                    .collect::<Result<_, String>>()?,
            ),
            authorization_list,
        };
        let signature = TransactionSignature {
            signature_y_parity: decode_val(&rlp, 10)?,
            r: decode_u256(&rlp, 11)?,
            s: decode_u256(&rlp, 12)?,
        };
        Ok(Self::from((transaction, signature)))
    }
}

fn decode_bytes<'a>(rlp: &'a Rlp<'a>, index: usize) -> Result<&'a [u8], String> {
    decode_be_bytes_slice(&item_at(rlp, index)?)
}

fn item_at<'a>(rlp: &'a Rlp<'a>, index: usize) -> Result<Rlp<'a>, String> {
    rlp.at(index)
        .map_err(|e| format!("missing RLP item at index {index}: {e}"))
}

fn decode_be_bytes_slice<'a>(rlp: &Rlp<'a>) -> Result<&'a [u8], String> {
    rlp.data()
        .map_err(|e| format!("expected a byte string: {e}"))
}

fn decode_be_bytes_of(rlp: &Rlp) -> Result<[u8; 32], String> {
    let data = decode_be_bytes_slice(rlp)?;
    if data.len() > 32 {
        return Err(format!("expected at most 32 bytes, got {}", data.len()));
    }
    let mut bytes = [0_u8; 32];
    bytes[32 - data.len()..].copy_from_slice(data);
    Ok(bytes)
}

fn decode_amount<Unit>(rlp: &Rlp, index: usize) -> Result<CheckedAmountOf<Unit>, String> {
    Ok(CheckedAmountOf::from_be_bytes(decode_be_bytes_of(
        &item_at(rlp, index)?,
    )?))
}

fn decode_u256(rlp: &Rlp, index: usize) -> Result<u256, String> {
    Ok(u256::from_be_bytes(decode_be_bytes_of(&item_at(
        rlp, index,
    )?)?))
}

fn decode_val<T: rlp::Decodable>(rlp: &Rlp, index: usize) -> Result<T, String> {
    item_at(rlp, index)?
        .as_val()
        .map_err(|e| format!("malformed RLP item at index {index}: {e}"))
}

fn decode_address(rlp: &Rlp, index: usize) -> Result<Address, String> {
    let data = decode_bytes(rlp, index)?;
    Ok(Address::new(data.try_into().map_err(|_| {
        format!("expected a 20-byte address, got {} bytes", data.len())
    })?))
}

fn decode_list<'a>(rlp: &'a Rlp<'a>, index: usize) -> Result<Vec<Rlp<'a>>, String> {
    Ok(item_at(rlp, index)?.iter().collect())
}
