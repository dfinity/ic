use super::{TransactionPrice, compute_recovery_id, encode_u256, split_in_two};
use crate::{
    eth_rpc::Hash,
    numeric::{GasAmount, TransactionNonce, WeiPerGas},
    state::read_state,
};
use ethnum::u256;
use ic_management_canister_types_private::DerivationPath;
use minicbor::{Decode, Encode};
use rlp::RlpStream;

#[derive(Clone, Eq, PartialEq, Hash, Debug, Default, Decode, Encode)]
pub struct TransactionSignature {
    #[n(0)]
    pub signature_y_parity: bool,
    #[cbor(n(1), with = "icrc_cbor::u256")]
    pub r: u256,
    #[cbor(n(2), with = "icrc_cbor::u256")]
    pub s: u256,
}

impl rlp::Encodable for TransactionSignature {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append(&self.signature_y_parity);
        encode_u256(s, self.r);
        encode_u256(s, self.s);
    }
}

/// A transaction request that can be signed and wrapped into a [`Signed`] transaction.
pub trait SignableTransaction: rlp::Encodable {
    /// The [EIP-2718](https://eips.ethereum.org/EIPS/eip-2718) transaction type identifier,
    /// e.g. `0x02` for EIP-1559.
    fn transaction_type(&self) -> u8;

    /// RLP-encode the transaction payload, i.e. without the type prefix nor the signature.
    fn rlp_inner(&self, rlp: &mut RlpStream);

    fn nonce(&self) -> TransactionNonce;

    fn gas_limit(&self) -> GasAmount;

    fn max_fee_per_gas(&self) -> WeiPerGas;

    fn max_priority_fee_per_gas(&self) -> WeiPerGas;

    /// The signing digest `keccak256(transaction_type || rlp([..payload fields..]))`,
    /// i.e. the hash signed over to authorize the transaction, where `||` denotes string
    /// concatenation. Note this differs from [`Signed::hash`], which additionally covers the
    /// signature.
    fn hash(&self) -> Hash {
        let mut bytes = self.rlp_bytes().to_vec();
        bytes.insert(0, self.transaction_type());
        Hash(ic_sha3::Keccak256::hash(bytes))
    }

    fn transaction_price(&self) -> TransactionPrice {
        TransactionPrice {
            gas_limit: self.gas_limit(),
            max_fee_per_gas: self.max_fee_per_gas(),
            max_priority_fee_per_gas: self.max_priority_fee_per_gas(),
        }
    }
}

/// Immutable signed transaction.
/// Use [`sign`](sign) to create a newly signed transaction or
/// `Signed::from((transaction, signature))` if the signature is already known.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Signed<T> {
    inner: InnerSigned<T>,
    /// Hash of the signed transaction. Since computation of the hash is an expensive operation,
    /// which involves RLP encoding and Keccak256, the value is computed once upon instantiation
    /// and memoized. It is safe to memoize the hash because the transaction is immutable.
    /// Note: Serialization should ignore this field and deserialization should call
    /// the constructor to create the correct value.
    memoized_hash: Hash,
}

#[derive(Clone, Eq, PartialEq, Debug, Decode, Encode)]
struct InnerSigned<T> {
    #[n(0)]
    transaction: T,
    #[n(1)]
    signature: TransactionSignature,
}

impl<T: SignableTransaction> InnerSigned<T> {
    /// An EIP-2718 transaction is encoded as
    /// `transaction_type || rlp([..transaction fields.., signature_y_parity, signature_r, signature_s])`,
    /// where `||` denotes string concatenation.
    fn raw_bytes(&self) -> Vec<u8> {
        use rlp::Encodable;
        let mut rlp = self.rlp_bytes().to_vec();
        rlp.insert(0, self.transaction.transaction_type());
        rlp
    }
}

impl<T: SignableTransaction> rlp::Encodable for InnerSigned<T> {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_unbounded_list();
        self.transaction.rlp_inner(s);
        s.append(&self.signature);
        //ignore memoized_hash
        s.finalize_unbounded_list();
    }
}

impl<T> AsRef<T> for Signed<T> {
    fn as_ref(&self) -> &T {
        &self.inner.transaction
    }
}

impl<T: SignableTransaction> From<(T, TransactionSignature)> for Signed<T> {
    fn from((transaction, signature): (T, TransactionSignature)) -> Self {
        Self::new(transaction, signature)
    }
}

impl<T: SignableTransaction> rlp::Encodable for Signed<T> {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append(&self.inner);
    }
}

impl<T, C> minicbor::Encode<C> for Signed<T>
where
    T: minicbor::Encode<C>,
{
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.encode_with(&self.inner, ctx)?;
        Ok(())
    }
}

impl<'b, T, C> minicbor::Decode<'b, C> for Signed<T>
where
    T: SignableTransaction + minicbor::Decode<'b, C>,
{
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        d.decode_with(ctx)
            .map(|inner: InnerSigned<T>| Self::new(inner.transaction, inner.signature))
    }
}

impl<T: SignableTransaction> Signed<T> {
    pub fn new(transaction: T, signature: TransactionSignature) -> Self {
        let inner = InnerSigned {
            transaction,
            signature,
        };
        let hash = Hash(ic_sha3::Keccak256::hash(inner.raw_bytes()));
        Self {
            inner,
            memoized_hash: hash,
        }
    }

    pub fn raw_transaction_bytes(&self) -> Vec<u8> {
        self.inner.raw_bytes()
    }

    pub fn raw_transaction_hex_string(&self) -> String {
        format!("0x{}", hex::encode(self.raw_transaction_bytes()))
    }

    /// If included in a block, this hash value is used as reference to this transaction.
    pub fn hash(&self) -> Hash {
        self.memoized_hash
    }

    pub fn transaction(&self) -> &T {
        &self.inner.transaction
    }

    pub fn nonce(&self) -> TransactionNonce {
        self.inner.transaction.nonce()
    }
}

/// Sign `transaction` with the minter's ECDSA key at `derivation_path` and wrap it into a
/// [`Signed`] transaction.
pub async fn sign<T: SignableTransaction>(
    transaction: T,
    derivation_path: DerivationPath,
) -> Result<Signed<T>, String> {
    let hash = transaction.hash();
    let key_name = read_state(|s| s.ecdsa_key_name.clone());
    let signature = crate::management::sign_with_ecdsa(key_name, derivation_path, hash.0)
        .await
        .map_err(|e| format!("failed to sign tx: {e}"))?;
    let recid = compute_recovery_id(&hash, &signature).await;
    if recid.is_x_reduced() {
        return Err("BUG: affine x-coordinate of r is reduced which is so unlikely to happen that it's probably a bug".to_string());
    }
    let (r_bytes, s_bytes) = split_in_two(signature);
    let signature = TransactionSignature {
        signature_y_parity: recid.is_y_odd(),
        r: u256::from_be_bytes(r_bytes),
        s: u256::from_be_bytes(s_bytes),
    };
    Ok(Signed::new(transaction, signature))
}
