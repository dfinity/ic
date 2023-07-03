use crate::timestamp::TimeStamp;

use candid::CandidType;
use ic_ledger_hash_of::HashOf;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

/// Position of a block in the chain. The first block has position 0.
pub type BlockIndex = u64;

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

#[derive(Clone, Debug, Deserialize, Hash, PartialEq, Serialize)]
pub struct FeeCollector<Account> {
    pub fee_collector: Account,
    /// The block index of the block where the fee_collector has
    /// been written.
    pub block_index: Option<BlockIndex>,
}

impl<Account> From<Account> for FeeCollector<Account> {
    fn from(fee_collector: Account) -> Self {
        Self {
            fee_collector,
            block_index: None,
        }
    }
}

pub trait BlockType: Sized + Clone {
    type Transaction;
    type AccountId;
    type Tokens;

    /// Constructs a new block containing the given transaction.
    ///
    /// Law:
    ///
    /// ```text
    /// forall PH, TX, TS, FEE:
    ///     from_transaction(PH, TX, TS, FEE).parent_hash() = PH
    ///   ∧ from_transaction(PH, TX, TS, FEE).timestamp() = TS
    /// ```
    fn from_transaction(
        parent_hash: Option<HashOf<EncodedBlock>>,
        tx: Self::Transaction,
        block_timestamp: TimeStamp,
        effective_fee: Self::Tokens,
        fee_collector: Option<FeeCollector<Self::AccountId>>,
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
