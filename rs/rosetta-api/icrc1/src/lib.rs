pub mod hash;

use candid::CandidType;
use ciborium::tag::Required;
use ic_base_types::PrincipalId;
use ic_ledger_core::{
    balances::{BalanceError, Balances, BalancesStore},
    block::{BlockType, EncodedBlock, HashOf},
    ledger::LedgerTransaction,
    timestamp::TimeStamp,
    tokens::Tokens,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt;

pub type Subaccount = [u8; 32];

#[derive(
    Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct Account {
    pub of: PrincipalId,
    pub subaccount: Option<Subaccount>,
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
    pub created_at_time: u64,
}

impl From<Transaction> for CandidTransaction {
    fn from(
        Transaction {
            operation,
            created_at_time,
        }: Transaction,
    ) -> Self {
        Self {
            operation: operation.into(),
            created_at_time,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Transaction {
    #[serde(flatten)]
    pub operation: Operation,
    #[serde(rename = "ts")]
    pub created_at_time: u64,
}

impl LedgerTransaction for Transaction {
    type AccountId = Account;

    fn burn(from: Account, amount: Tokens, created_at_time: TimeStamp) -> Self {
        Self {
            operation: Operation::Burn {
                from,
                amount: amount.get_e8s(),
            },
            created_at_time: created_at_time.as_nanos_since_unix_epoch(),
        }
    }

    fn created_at_time(&self) -> TimeStamp {
        TimeStamp::from_nanos_since_unix_epoch(self.created_at_time)
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
    pub fn mint(to: Account, amount: Tokens, created_at_time: TimeStamp) -> Self {
        Self {
            operation: Operation::Mint {
                to,
                amount: amount.get_e8s(),
            },
            created_at_time: created_at_time.as_nanos_since_unix_epoch(),
        }
    }

    pub fn transfer(
        from: Account,
        to: Account,
        amount: Tokens,
        fee: Tokens,
        created_at_time: TimeStamp,
    ) -> Self {
        Self {
            operation: Operation::Transfer {
                from,
                to,
                amount: amount.get_e8s(),
                fee: fee.get_e8s(),
            },
            created_at_time: created_at_time.as_nanos_since_unix_epoch(),
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
