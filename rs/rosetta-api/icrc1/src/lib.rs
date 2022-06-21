pub mod cdk_runtime;
pub mod endpoints;
pub mod hash;

use crate::cdk_runtime::CdkRuntime;
use candid::CandidType;
use ciborium::tag::Required;
use ic_base_types::PrincipalId;
use ic_ledger_core::{
    archive::ArchiveCanisterWasm,
    balances::{BalanceError, Balances, BalancesStore},
    block::{BlockHeight, BlockType, EncodedBlock, HashOf},
    blockchain::Blockchain,
    ledger::{apply_transaction, LedgerData, LedgerTransaction, TransactionInfo},
    timestamp::TimeStamp,
    tokens::Tokens,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::convert::TryFrom;
use std::fmt;
use std::time::Duration;

const TRANSACTION_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_ACCOUNTS: usize = 28_000_000;
const ACCOUNTS_OVERFLOW_TRIM_QUANTITY: usize = 100_000;
const MAX_TRANSACTIONS_IN_WINDOW: usize = 3_000_000;
const MAX_TRANSACTIONS_TO_PURGE: usize = 100_000;

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

#[derive(
    Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord,
)]
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

#[derive(
    Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord,
)]
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

#[derive(
    Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord,
)]
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

pub type LedgerBalances = Balances<Account, HashMap<Account, Tokens>>;

#[derive(Debug, Clone)]
pub struct Icrc1ArchiveWasm;

impl ArchiveCanisterWasm for Icrc1ArchiveWasm {
    fn archive_wasm() -> Cow<'static, [u8]> {
        unimplemented!("archiving not supported yet")
    }
}

#[derive(Deserialize, CandidType, Clone, Debug, PartialEq)]
pub struct InitArgs {
    pub minting_account: Account,
    pub initial_balances: Vec<(Account, u64)>,
    pub transfer_fee: Tokens,
    pub token_name: String,
    pub token_symbol: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Ledger {
    balances: LedgerBalances,
    blockchain: Blockchain<CdkRuntime, Icrc1ArchiveWasm>,

    minting_account: Account,

    transactions_by_hash: BTreeMap<HashOf<Transaction>, BlockHeight>,
    transactions_by_height: VecDeque<TransactionInfo<Transaction>>,
    transfer_fee: Tokens,

    token_symbol: String,
    token_name: String,
}

impl Ledger {
    pub fn from_init_args(
        InitArgs {
            minting_account,
            initial_balances,
            transfer_fee,
            token_name,
            token_symbol,
        }: InitArgs,
        now: TimeStamp,
    ) -> Self {
        let mut ledger = Self {
            balances: LedgerBalances::default(),
            blockchain: Blockchain::default(),
            transactions_by_hash: BTreeMap::new(),
            transactions_by_height: VecDeque::new(),
            minting_account,
            transfer_fee,
            token_symbol,
            token_name,
        };

        for (account, balance) in initial_balances.into_iter() {
            apply_transaction(
                &mut ledger,
                Transaction::mint(account.clone(), Tokens::from_e8s(balance), now),
                now,
            )
            .unwrap_or_else(|err| {
                panic!("failed to mint {} e8s to {}: {:?}", balance, account, err)
            });
        }

        ledger
    }
}

impl LedgerData for Ledger {
    type AccountId = Account;
    type Runtime = CdkRuntime;
    type ArchiveWasm = Icrc1ArchiveWasm;
    type Transaction = Transaction;
    type Block = Block;

    fn transaction_window(&self) -> Duration {
        TRANSACTION_WINDOW
    }

    fn max_transactions_in_window(&self) -> usize {
        MAX_TRANSACTIONS_IN_WINDOW
    }

    fn max_transactions_to_purge(&self) -> usize {
        MAX_TRANSACTIONS_TO_PURGE
    }

    fn max_number_of_accounts(&self) -> usize {
        MAX_ACCOUNTS
    }

    fn accounts_overflow_trim_quantity(&self) -> usize {
        ACCOUNTS_OVERFLOW_TRIM_QUANTITY
    }

    fn token_name(&self) -> &str {
        &self.token_name
    }

    fn token_symbol(&self) -> &str {
        &self.token_symbol
    }

    fn balances(&self) -> &Balances<Self::AccountId, HashMap<Self::AccountId, Tokens>> {
        &self.balances
    }

    fn balances_mut(&mut self) -> &mut Balances<Self::AccountId, HashMap<Self::AccountId, Tokens>> {
        &mut self.balances
    }

    fn blockchain(&self) -> &Blockchain<Self::Runtime, Self::ArchiveWasm> {
        &self.blockchain
    }

    fn blockchain_mut(&mut self) -> &mut Blockchain<Self::Runtime, Self::ArchiveWasm> {
        &mut self.blockchain
    }

    fn transactions_by_hash(&self) -> &BTreeMap<HashOf<Self::Transaction>, BlockHeight> {
        &self.transactions_by_hash
    }

    fn transactions_by_hash_mut(
        &mut self,
    ) -> &mut BTreeMap<HashOf<Self::Transaction>, BlockHeight> {
        &mut self.transactions_by_hash
    }

    fn transactions_by_height(&self) -> &VecDeque<TransactionInfo<Self::Transaction>> {
        &self.transactions_by_height
    }

    fn transactions_by_height_mut(&mut self) -> &mut VecDeque<TransactionInfo<Self::Transaction>> {
        &mut self.transactions_by_height
    }

    fn on_purged_transaction(&mut self, _height: BlockHeight) {}
}

impl Ledger {
    pub fn minting_account(&self) -> &Account {
        &self.minting_account
    }

    pub fn transfer_fee(&self) -> Tokens {
        self.transfer_fee
    }
}
