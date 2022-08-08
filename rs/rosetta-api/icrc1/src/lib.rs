pub mod endpoints;
pub mod hash;

use candid::CandidType;
use ciborium::tag::Required;
use ic_base_types::PrincipalId;
use ic_ledger_canister_core::ledger::LedgerTransaction;
use ic_ledger_core::{
    balances::{BalanceError, Balances, BalancesStore},
    block::{BlockType, EncodedBlock, HashOf},
    timestamp::TimeStamp,
    tokens::Tokens,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt;

pub type Subaccount = [u8; 32];

pub const DEFAULT_SUBACCOUNT: &Subaccount = &[0; 32];
pub const MAX_MEMO_LENGTH: usize = 32;

#[derive(Serialize, Deserialize, CandidType, Clone, Debug)]
pub struct Account {
    pub of: PrincipalId,
    pub subaccount: Option<Subaccount>,
}

impl Account {
    #[inline]
    pub fn effective_subaccount(&self) -> &Subaccount {
        self.subaccount.as_ref().unwrap_or(DEFAULT_SUBACCOUNT)
    }
}

impl PartialEq for Account {
    fn eq(&self, other: &Self) -> bool {
        self.of == other.of && self.effective_subaccount() == other.effective_subaccount()
    }
}

impl Eq for Account {}

impl std::cmp::PartialOrd for Account {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for Account {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.of.cmp(&other.of).then_with(|| {
            self.effective_subaccount()
                .cmp(other.effective_subaccount())
        })
    }
}

impl std::hash::Hash for Account {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.of.hash(state);
        self.effective_subaccount().hash(state);
    }
}

impl fmt::Display for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.subaccount {
            None => write!(f, "{}", self.of),
            Some(subaccount) => write!(f, "({}, {})", self.of, hex::encode(&subaccount[..])),
        }
    }
}

impl From<PrincipalId> for Account {
    fn from(of: PrincipalId) -> Self {
        Self {
            of,
            subaccount: None,
        }
    }
}

fn ser_compact_account<S>(acc: &Account, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::ser::Serializer,
{
    CompactAccount::from(acc.clone()).serialize(s)
}

fn de_compact_account<'de, D>(d: D) -> Result<Account, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    use serde::de::Error;
    let compact_account = CompactAccount::deserialize(d)?;
    Account::try_from(compact_account).map_err(D::Error::custom)
}

/// A compact representation of an Account.
///
/// Instead of encoding accounts as structs with named fields,
/// we encode them as tuples with variables number of elements.
/// ```text
/// [bytes] <=> Account { of: bytes, subaccount : None }
/// [x: bytes, y: bytes] <=> Account { of: x, subaccount: Some(y) }
/// ```
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
struct CompactAccount(Vec<ByteBuf>);

impl From<Account> for CompactAccount {
    fn from(acc: Account) -> Self {
        let mut components = vec![ByteBuf::from(acc.of.to_vec())];
        if let Some(sub) = acc.subaccount {
            components.push(ByteBuf::from(sub.to_vec()))
        }
        CompactAccount(components)
    }
}

impl TryFrom<CompactAccount> for Account {
    type Error = String;
    fn try_from(compact: CompactAccount) -> Result<Account, String> {
        let elems = compact.0;
        if elems.is_empty() {
            return Err("account tuple must have at least one element".to_string());
        }
        if elems.len() > 2 {
            return Err(format!(
                "account tuple must have at most two elements, got {}",
                elems.len()
            ));
        }

        let principal = PrincipalId::try_from(&elems[0][..])
            .map_err(|e| format!("invalid principal: {}", e))?;
        let subaccount = if elems.len() > 1 {
            Some(Subaccount::try_from(&elems[1][..]).map_err(|_| {
                format!(
                    "invalid subaccount: expected 32 bytes, got {}",
                    elems[1].len()
                )
            })?)
        } else {
            None
        };

        Ok(Account {
            of: principal,
            subaccount,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "op")]
pub enum Operation {
    #[serde(rename = "mint")]
    Mint {
        #[serde(serialize_with = "ser_compact_account")]
        #[serde(deserialize_with = "de_compact_account")]
        to: Account,
        #[serde(rename = "amt")]
        amount: u64,
    },
    #[serde(rename = "xfer")]
    Transfer {
        #[serde(serialize_with = "ser_compact_account")]
        #[serde(deserialize_with = "de_compact_account")]
        from: Account,
        #[serde(serialize_with = "ser_compact_account")]
        #[serde(deserialize_with = "de_compact_account")]
        to: Account,
        #[serde(rename = "amt")]
        amount: u64,
        fee: u64,
    },
    #[serde(rename = "burn")]
    Burn {
        #[serde(serialize_with = "ser_compact_account")]
        #[serde(deserialize_with = "de_compact_account")]
        from: Account,
        #[serde(rename = "amt")]
        amount: u64,
    },
}

/// Like [Operation], but designed for a public Candid interface.
#[derive(CandidType, Deserialize, Debug, PartialEq)]
pub enum CandidOperation {
    Mint {
        to: Account,
        amount: u64,
    },
    Transfer {
        from: Account,
        to: Account,
        amount: u64,
        fee: u64,
    },
    Burn {
        from: Account,
        amount: u64,
    },
}

impl From<Operation> for CandidOperation {
    fn from(op: Operation) -> Self {
        match op {
            Operation::Mint { to, amount } => Self::Mint { to, amount },
            Operation::Transfer {
                from,
                to,
                amount,
                fee,
            } => Self::Transfer {
                from,
                to,
                amount,
                fee,
            },
            Operation::Burn { from, amount } => Self::Burn { from, amount },
        }
    }
}

/// Like [Transaction], but designed for a public Candid interface.
#[derive(CandidType, Deserialize, Debug, PartialEq)]
pub struct CandidTransaction {
    pub operation: CandidOperation,
    pub created_at_time: Option<u64>,
    pub memo: Option<Memo>,
}

impl From<Transaction> for CandidTransaction {
    fn from(
        Transaction {
            operation,
            created_at_time,
            memo,
        }: Transaction,
    ) -> Self {
        Self {
            operation: operation.into(),
            created_at_time,
            memo,
        }
    }
}

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
pub struct Memo(#[serde(deserialize_with = "deserialize_memo_bytes")] ByteBuf);

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

#[derive(Serialize, Deserialize, Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Transaction {
    #[serde(flatten)]
    pub operation: Operation,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ts")]
    pub created_at_time: Option<u64>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<Memo>,
}

impl LedgerTransaction for Transaction {
    type AccountId = Account;

    fn burn(
        from: Account,
        amount: Tokens,
        created_at_time: Option<TimeStamp>,
        memo: Option<u64>,
    ) -> Self {
        Self {
            operation: Operation::Burn {
                from,
                amount: amount.get_e8s(),
            },
            created_at_time: created_at_time.map(|t| t.as_nanos_since_unix_epoch()),
            memo: memo.map(Memo::from),
        }
    }

    fn created_at_time(&self) -> Option<TimeStamp> {
        self.created_at_time
            .map(TimeStamp::from_nanos_since_unix_epoch)
    }

    fn hash(&self) -> HashOf<Self> {
        let mut cbor_bytes = vec![];
        ciborium::ser::into_writer(self, &mut cbor_bytes)
            .expect("bug: failed to encode a transaction");
        hash::hash_cbor(&cbor_bytes)
            .map(HashOf::new)
            .unwrap_or_else(|err| {
                panic!(
                    "bug: transaction CBOR {} is not hashable: {}",
                    hex::encode(&cbor_bytes),
                    err
                )
            })
    }

    fn apply<S>(&self, balances: &mut Balances<Self::AccountId, S>) -> Result<(), BalanceError>
    where
        S: Default + BalancesStore<Self::AccountId>,
    {
        match &self.operation {
            Operation::Transfer {
                from,
                to,
                amount,
                fee,
            } => balances.transfer(from, to, Tokens::from_e8s(*amount), Tokens::from_e8s(*fee)),
            Operation::Burn { from, amount } => balances.burn(from, Tokens::from_e8s(*amount)),
            Operation::Mint { to, amount } => balances.mint(to, Tokens::from_e8s(*amount)),
        }
    }
}

impl Transaction {
    pub fn mint(
        to: Account,
        amount: Tokens,
        created_at_time: Option<TimeStamp>,
        memo: Option<Memo>,
    ) -> Self {
        Self {
            operation: Operation::Mint {
                to,
                amount: amount.get_e8s(),
            },
            created_at_time: created_at_time.map(|t| t.as_nanos_since_unix_epoch()),
            memo,
        }
    }

    pub fn transfer(
        from: Account,
        to: Account,
        amount: Tokens,
        fee: Tokens,
        created_at_time: Option<TimeStamp>,
        memo: Option<Memo>,
    ) -> Self {
        Self {
            operation: Operation::Transfer {
                from,
                to,
                amount: amount.get_e8s(),
                fee: fee.get_e8s(),
            },
            created_at_time: created_at_time.map(|t| t.as_nanos_since_unix_epoch()),
            memo,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Block {
    #[serde(rename = "phash")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_hash: Option<HashOf<EncodedBlock>>,
    #[serde(rename = "tx")]
    pub transaction: Transaction,
    #[serde(rename = "ts")]
    pub timestamp: u64,
}

type TaggedBlock = Required<Block, 55799>;

impl BlockType for Block {
    type Transaction = Transaction;

    fn encode(self) -> EncodedBlock {
        let mut bytes = vec![];
        let value: TaggedBlock = Required(self);
        ciborium::ser::into_writer(&value, &mut bytes).expect("bug: failed to encode a block");
        EncodedBlock::from_vec(bytes)
    }

    fn decode(encoded_block: EncodedBlock) -> Result<Self, String> {
        let bytes = encoded_block.into_vec();
        let tagged_block: TaggedBlock = ciborium::de::from_reader(&bytes[..])
            .map_err(|e| format!("failed to decode a block: {}", e))?;
        Ok(tagged_block.0)
    }

    fn block_hash(encoded_block: &EncodedBlock) -> HashOf<EncodedBlock> {
        hash::hash_cbor(encoded_block.as_slice())
            .map(HashOf::new)
            .unwrap_or_else(|err| {
                panic!(
                    "bug: encoded block {} is not hashable cbor: {}",
                    hex::encode(encoded_block.as_slice()),
                    err
                )
            })
    }

    fn parent_hash(&self) -> Option<HashOf<EncodedBlock>> {
        self.parent_hash
    }

    fn timestamp(&self) -> TimeStamp {
        TimeStamp::from_nanos_since_unix_epoch(self.timestamp)
    }

    fn from_transaction(
        parent_hash: Option<HashOf<EncodedBlock>>,
        transaction: Self::Transaction,
        timestamp: TimeStamp,
    ) -> Self {
        Self {
            parent_hash,
            transaction,
            timestamp: timestamp.as_nanos_since_unix_epoch(),
        }
    }
}

/// Like [Block], but designed for a public Candid interface.
#[derive(CandidType, Deserialize, Debug, PartialEq)]
pub struct CandidBlock {
    pub parent_hash: Option<HashOf<EncodedBlock>>,
    pub transaction: CandidTransaction,
    pub timestamp: u64,
}

impl From<Block> for CandidBlock {
    fn from(
        Block {
            parent_hash,
            transaction,
            timestamp,
        }: Block,
    ) -> Self {
        Self {
            parent_hash,
            transaction: transaction.into(),
            timestamp,
        }
    }
}

pub type LedgerBalances = Balances<Account, HashMap<Account, Tokens>>;
