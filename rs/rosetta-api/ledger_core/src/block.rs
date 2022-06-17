use crate::timestamp::TimeStamp;
use candid::types::internal::Type;
use candid::CandidType;
use serde::{
    de::{Deserializer, Visitor},
    Deserialize, Serialize, Serializer,
};
use serde_bytes::ByteBuf;
use std::convert::TryInto;
use std::{fmt, marker::PhantomData, str::FromStr};

/// Position of a block in the chain. The first block has position 0.
pub type BlockHeight = u64;

/// The length of a block/transaction hash in bytes.
pub const HASH_LENGTH: usize = 32;

#[derive(Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct HashOf<T> {
    inner: [u8; HASH_LENGTH],
    _marker: PhantomData<T>,
}

impl<T> CandidType for HashOf<T> {
    fn _ty() -> Type {
        Type::Vec(Box::new(Type::Nat8))
    }

    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
        S: candid::types::Serializer,
    {
        serializer.serialize_blob(self.as_slice())
    }
}

impl<T: std::clone::Clone> Copy for HashOf<T> {}

impl<T> HashOf<T> {
    pub fn into_bytes(self) -> [u8; HASH_LENGTH] {
        self.inner
    }

    pub fn new(bs: [u8; HASH_LENGTH]) -> Self {
        HashOf {
            inner: bs,
            _marker: PhantomData,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }
}

impl<T> fmt::Display for HashOf<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let res = hex::encode(self.as_slice());
        write!(f, "{}", res)
    }
}

impl<T> FromStr for HashOf<T> {
    type Err = String;
    fn from_str(s: &str) -> Result<HashOf<T>, String> {
        let v = hex::decode(s).map_err(|e| e.to_string())?;
        let slice = v.as_slice();
        match slice.try_into() {
            Ok(ba) => Ok(HashOf::new(ba)),
            Err(_) => Err(format!(
                "Expected a Vec of length {} but it was {}",
                HASH_LENGTH,
                v.len(),
            )),
        }
    }
}

impl<T> Serialize for HashOf<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            serializer.serialize_bytes(self.as_slice())
        }
    }
}

impl<'de, T> Deserialize<'de> for HashOf<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HashOfVisitor<T> {
            phantom: PhantomData<T>,
        }

        impl<'de, T> Visitor<'de> for HashOfVisitor<T> {
            type Value = HashOf<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "a hash of type {}: a blob with at most {} bytes",
                    std::any::type_name::<T>(),
                    HASH_LENGTH
                )
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(HashOf::new(
                    v.try_into().expect("hash does not have correct length"),
                ))
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                HashOf::from_str(s).map_err(E::custom)
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(HashOfVisitor {
                phantom: PhantomData,
            })
        } else {
            deserializer.deserialize_bytes(HashOfVisitor {
                phantom: PhantomData,
            })
        }
    }
}

#[derive(
    Serialize, Deserialize, CandidType, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
#[serde(transparent)]
pub struct EncodedBlock(pub ByteBuf);

impl From<Vec<u8>> for EncodedBlock {
    fn from(bytes: Vec<u8>) -> Self {
        Self::from_vec(bytes)
    }
}

impl EncodedBlock {
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self(ByteBuf::from(bytes))
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn size_bytes(&self) -> usize {
        self.0.len()
    }
}

pub trait BlockType: Sized {
    type Transaction;

    /// Constructs a new block containing the given transaction.
    ///
    /// Law:
    ///
    /// ```text
    /// forall PH, TX, TS:
    ///     from_transaction(PH, TX, TS).parent_hash() = PH
    ///   ∧ from_transaction(PH, TX, TS).timestamp() = TS
    /// ```
    fn from_transaction(
        parent_hash: Option<HashOf<EncodedBlock>>,
        tx: Self::Transaction,
        block_timestamp: TimeStamp,
    ) -> Self;

    /// Encodes this block into a binary representation.
    ///
    /// NB. the binary representation is not guaranteed to be stable over time.
    /// I.e., there is no guarantee that
    ///
    /// ```text
    /// forall B: encode(B) == encode(decode(encode(B))).unwrap()
    /// ```
    ///
    /// One practical implication is that we can encode each block at most once before appending it
    /// to a blockchain.
    fn encode(self) -> EncodedBlock;

    /// Decodes a block from a binary representation.
    ///
    /// Law: forall B: decode(encode(B)) == Ok(B)
    fn decode(encoded: EncodedBlock) -> Result<Self, String>;

    /// Returns the hash of the encoded block.
    ///
    /// NB. it feels more natural and safe to compute the hash of typed blocks, i.e.,
    /// define `fn block_hash(&self) -> HashOf<EncodedBlock>`.
    /// This does not work in practice because the hash is usually defined only on the encoded
    /// representation, and the encoding is not guaranteed to be stable.
    ///
    /// # Panics
    ///
    /// This method can panic if the `encoded` block was not obtained
    /// by calling [encode] on the same block type.
    fn block_hash(encoded: &EncodedBlock) -> HashOf<EncodedBlock>;

    /// Returns the hash of the parent block.
    ///
    /// NB. Only the first block in a chain can miss a parent block hash.
    fn parent_hash(&self) -> Option<HashOf<EncodedBlock>>;

    /// Returns the time at which the ledger constructed this block.
    fn timestamp(&self) -> TimeStamp;
}
