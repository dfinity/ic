use super::eip_1559::Eip1559Signature;
use crate::{eth_rpc::Hash, numeric::TransactionNonce};
use minicbor::{Decode, Encode};
use rlp::RlpStream;

/// A transaction request that can be signed and wrapped into a [`Signed`] transaction.
pub trait SignableTransaction {
    /// The [EIP-2718](https://eips.ethereum.org/EIPS/eip-2718) transaction type identifier,
    /// e.g. `0x02` for EIP-1559.
    fn transaction_type(&self) -> u8;

    /// RLP-encode the transaction payload, i.e. without the type prefix nor the signature.
    fn rlp_inner(&self, rlp: &mut RlpStream);

    fn nonce(&self) -> TransactionNonce;
}

/// Immutable signed transaction.
/// Use `<request>.sign()` to create a newly signed transaction or
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
    signature: Eip1559Signature,
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

impl<T: SignableTransaction> From<(T, Eip1559Signature)> for Signed<T> {
    fn from((transaction, signature): (T, Eip1559Signature)) -> Self {
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
    pub fn new(transaction: T, signature: Eip1559Signature) -> Self {
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

    pub fn raw_transaction_hex(&self) -> Vec<u8> {
        self.inner.raw_bytes()
    }

    pub fn raw_transaction_hex_string(&self) -> String {
        format!("0x{}", hex::encode(self.raw_transaction_hex()))
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
