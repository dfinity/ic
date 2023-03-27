use std::fmt;

use candid::{CandidType, Deserialize, Nat};
use serde::Serialize;
use serde_bytes::ByteBuf;

pub type BlockIndex = Nat;

use super::account::{Account, Subaccount};

pub type NumTokens = Nat;

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TransferArg {
    #[serde(default)]
    pub from_subaccount: Option<Subaccount>,
    pub to: Account,
    #[serde(default)]
    pub fee: Option<NumTokens>,
    #[serde(default)]
    pub created_at_time: Option<u64>,
    #[serde(default)]
    pub memo: Option<Memo>,
    pub amount: NumTokens,
}

pub const MAX_MEMO_LENGTH: usize = 32;

#[derive(Debug, PartialEq, Eq)]
pub struct MemoTooLarge(usize);

impl fmt::Display for MemoTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Memo field is {} bytes long, max allowed length is {}",
            self.0, MAX_MEMO_LENGTH
        )
    }
}

#[derive(
    Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord, Default,
)]
#[serde(transparent)]
pub struct Memo(#[serde(deserialize_with = "deserialize_memo_bytes")] pub ByteBuf);

fn deserialize_memo_bytes<'de, D>(d: D) -> Result<ByteBuf, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    use serde::de::Error;
    let bytes = ByteBuf::deserialize(d)?;
    let memo = Memo::try_from(bytes).map_err(D::Error::custom)?;
    Ok(memo.into())
}

impl From<[u8; MAX_MEMO_LENGTH]> for Memo {
    fn from(memo: [u8; MAX_MEMO_LENGTH]) -> Self {
        Self(ByteBuf::from(memo.to_vec()))
    }
}

impl From<u64> for Memo {
    fn from(num: u64) -> Self {
        Self(ByteBuf::from(num.to_be_bytes().to_vec()))
    }
}

impl TryFrom<ByteBuf> for Memo {
    type Error = MemoTooLarge;

    fn try_from(b: ByteBuf) -> Result<Self, MemoTooLarge> {
        if b.len() > MAX_MEMO_LENGTH {
            return Err(MemoTooLarge(b.len()));
        }
        Ok(Self(b))
    }
}

impl TryFrom<Vec<u8>> for Memo {
    type Error = MemoTooLarge;

    fn try_from(v: Vec<u8>) -> Result<Self, MemoTooLarge> {
        Self::try_from(ByteBuf::from(v))
    }
}

impl From<Memo> for ByteBuf {
    fn from(memo: Memo) -> Self {
        memo.0
    }
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum TransferError {
    BadFee { expected_fee: NumTokens },
    BadBurn { min_burn_amount: NumTokens },
    InsufficientFunds { balance: NumTokens },
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    TemporarilyUnavailable,
    Duplicate { duplicate_of: BlockIndex },
    GenericError { error_code: Nat, message: String },
}
