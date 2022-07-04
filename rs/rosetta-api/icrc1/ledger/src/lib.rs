pub mod cdk_runtime;

use crate::cdk_runtime::CdkRuntime;
use candid::{
    types::number::{Int, Nat},
    CandidType,
};
use ic_icrc1::endpoints::Value;
use ic_icrc1::{Account, Block, LedgerBalances, Transaction};
use ic_ledger_canister_core::{
    archive::{ArchiveCanisterWasm, ArchiveOptions},
    blockchain::Blockchain,
    ledger::{apply_transaction, LedgerData, TransactionInfo},
};
use ic_ledger_core::{
    balances::Balances,
    block::{BlockHeight, HashOf},
    timestamp::TimeStamp,
    tokens::Tokens,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::Duration;

const TRANSACTION_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_ACCOUNTS: usize = 28_000_000;
const ACCOUNTS_OVERFLOW_TRIM_QUANTITY: usize = 100_000;
const MAX_TRANSACTIONS_IN_WINDOW: usize = 3_000_000;
const MAX_TRANSACTIONS_TO_PURGE: usize = 100_000;

#[derive(Debug, Clone)]
pub struct Icrc1ArchiveWasm;

impl ArchiveCanisterWasm for Icrc1ArchiveWasm {
    fn archive_wasm() -> Cow<'static, [u8]> {
        Cow::Borrowed(include_bytes!(env!("IC_ICRC1_ARCHIVE_WASM_PATH")))
    }
}

/// Like [endpoints::Value], but can be serialized to CBOR.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum StoredValue {
    NatBytes(ByteBuf),
    IntBytes(ByteBuf),
    Text(String),
    Blob(ByteBuf),
}

impl From<StoredValue> for Value {
    fn from(v: StoredValue) -> Self {
        match v {
            StoredValue::NatBytes(num_bytes) => Self::Nat(
                Nat::decode(&mut &num_bytes[..])
                    .unwrap_or_else(|e| panic!("bug: invalid Nat encoding {:?}: {}", num_bytes, e)),
            ),
            StoredValue::IntBytes(int_bytes) => Self::Int(
                Int::decode(&mut &int_bytes[..])
                    .unwrap_or_else(|e| panic!("bug: invalid Int encoding {:?}: {}", int_bytes, e)),
            ),
            StoredValue::Text(text) => Self::Text(text),
            StoredValue::Blob(bytes) => Self::Blob(bytes),
        }
    }
}

impl From<Value> for StoredValue {
    fn from(v: Value) -> Self {
        match v {
            Value::Nat(num) => {
                let mut buf = vec![];
                num.encode(&mut buf).expect("bug: failed to encode nat");
                Self::NatBytes(ByteBuf::from(buf))
            }
            Value::Int(int) => {
                let mut buf = vec![];
                int.encode(&mut buf).expect("bug: failed to encode nat");
                Self::IntBytes(ByteBuf::from(buf))
            }
            Value::Text(text) => Self::Text(text),
            Value::Blob(bytes) => Self::Blob(bytes),
        }
    }
}

#[derive(Deserialize, CandidType, Clone, Debug, PartialEq)]
pub struct InitArgs {
    pub minting_account: Account,
    pub initial_balances: Vec<(Account, u64)>,
    pub transfer_fee: Tokens,
    pub token_name: String,
    pub token_symbol: String,
    pub metadata: Vec<(String, Value)>,
    pub archive_options: ArchiveOptions,
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
    metadata: Vec<(String, StoredValue)>,
}

impl Ledger {
    pub fn from_init_args(
        InitArgs {
            minting_account,
            initial_balances,
            transfer_fee,
            token_name,
            token_symbol,
            metadata,
            archive_options,
        }: InitArgs,
        now: TimeStamp,
    ) -> Self {
        let mut ledger = Self {
            balances: LedgerBalances::default(),
            blockchain: Blockchain::new_with_archive(archive_options),
            transactions_by_hash: BTreeMap::new(),
            transactions_by_height: VecDeque::new(),
            minting_account,
            transfer_fee,
            token_symbol,
            token_name,
            metadata: metadata
                .into_iter()
                .map(|(k, v)| (k, StoredValue::from(v)))
                .collect(),
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

    pub fn metadata(&self) -> Vec<(String, Value)> {
        let mut records: Vec<(String, Value)> = self
            .metadata
            .clone()
            .into_iter()
            .map(|(k, v)| (k, StoredValue::into(v)))
            .collect();
        let decimals = ic_ledger_core::tokens::DECIMAL_PLACES as u64;
        records.push(Value::entry("icrc1:decimals", decimals));
        records.push(Value::entry("icrc1:name", self.token_name()));
        records.push(Value::entry("icrc1:symbol", self.token_symbol()));
        records
    }

    /// Returns the root hash of the certified ledger state.
    /// The canister code must call set_certified_data with the value this function returns after
    /// each successful modification of the ledger.
    pub fn root_hash(&self) -> [u8; 32] {
        use ic_crypto_tree_hash::{Label, MixedHashTree as T};
        let tree = match self.blockchain().last_hash {
            Some(hash) => T::Labeled(
                Label::from("tip_hash"),
                Box::new(T::Leaf(hash.as_slice().to_vec())),
            ),
            None => T::Empty,
        };
        tree.digest().0
    }
}
