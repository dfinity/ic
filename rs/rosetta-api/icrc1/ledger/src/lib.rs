pub mod cdk_runtime;
pub mod endpoints;

use crate::cdk_runtime::CdkRuntime;
use candid::CandidType;
use ic_icrc1::{Account, Block, LedgerBalances, Transaction};
use ic_ledger_core::{
    archive::{ArchiveCanisterWasm, ArchiveOptions},
    balances::Balances,
    block::{BlockHeight, HashOf},
    blockchain::Blockchain,
    ledger::{apply_transaction, LedgerData, TransactionInfo},
    timestamp::TimeStamp,
    tokens::Tokens,
};
use serde::{Deserialize, Serialize};
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

#[derive(Deserialize, CandidType, Clone, Debug, PartialEq)]
pub struct InitArgs {
    pub minting_account: Account,
    pub initial_balances: Vec<(Account, u64)>,
    pub transfer_fee: Tokens,
    pub token_name: String,
    pub token_symbol: String,
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
}

impl Ledger {
    pub fn from_init_args(
        InitArgs {
            minting_account,
            initial_balances,
            transfer_fee,
            token_name,
            token_symbol,
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
