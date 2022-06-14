use candid::CandidType;
use ic_base_types::PrincipalId;
use ic_ledger_core::{
    archive::ArchiveCanisterWasm,
    balances::{BalanceError, Balances, BalancesStore},
    block::{BlockHeight, BlockType, EncodedBlock, HashOf},
    blockchain::Blockchain,
    ledger::{LedgerData, LedgerTransaction, TransactionInfo},
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

pub type Subaccount = [u8; 32];

#[derive(
    Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct Account {
    pub owner: PrincipalId,
    pub subaccount: Option<Subaccount>,
}

#[derive(
    Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord,
)]
pub enum Operation {
    Mint {
        to: Account,
        amount: Tokens,
    },
    Transfer {
        from: Account,
        to: Account,
        amount: Tokens,
        fee: Tokens,
    },
    Burn {
        from: Account,
        amount: Tokens,
    },
}

#[derive(
    Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct Transaction {
    operation: Operation,
    created_at_time: TimeStamp,
}

impl LedgerTransaction for Transaction {
    type AccountId = Account;

    fn burn(from: Account, amount: Tokens, created_at_time: TimeStamp) -> Self {
        Self {
            operation: Operation::Burn { from, amount },
            created_at_time,
        }
    }

    fn created_at_time(&self) -> TimeStamp {
        self.created_at_time
    }

    fn hash(&self) -> HashOf<Self> {
        // FIXME
        HashOf::new([0u8; 32])
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
            } => balances.transfer(from, to, *amount, *fee),
            Operation::Burn { from, amount } => balances.burn(from, *amount),
            Operation::Mint { to, amount } => balances.mint(to, *amount),
        }
    }
}

#[derive(
    Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct Block {
    pub parent_hash: Option<HashOf<EncodedBlock>>,
    pub transaction: Transaction,
    pub timestamp: TimeStamp,
}

impl BlockType for Block {
    type Transaction = Transaction;

    fn encode(self) -> EncodedBlock {
        unimplemented!("block encoding is not decided yet")
    }

    fn decode(_encoded_block: EncodedBlock) -> Result<Self, String> {
        unimplemented!("block encoding is not decided yet")
    }

    fn parent_hash(&self) -> Option<HashOf<EncodedBlock>> {
        self.parent_hash
    }

    fn timestamp(&self) -> TimeStamp {
        self.timestamp
    }

    fn from_transaction(
        parent_hash: Option<HashOf<EncodedBlock>>,
        transaction: Self::Transaction,
        timestamp: TimeStamp,
    ) -> Self {
        Self {
            parent_hash,
            transaction,
            timestamp,
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
    pub transfer_fee: Tokens,
    pub token_name: String,
    pub token_symbol: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Ledger {
    balances: LedgerBalances,
    blockchain: Blockchain<Icrc1ArchiveWasm>,

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
            transfer_fee,
            token_name,
            token_symbol,
        }: InitArgs,
    ) -> Self {
        Self {
            balances: LedgerBalances::default(),
            blockchain: Blockchain::default(),
            transactions_by_hash: BTreeMap::new(),
            transactions_by_height: VecDeque::new(),
            minting_account,
            transfer_fee,
            token_symbol,
            token_name,
        }
    }
}

impl LedgerData for Ledger {
    type AccountId = Account;
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

    fn blockchain(&self) -> &Blockchain<Self::ArchiveWasm> {
        &self.blockchain
    }

    fn blockchain_mut(&mut self) -> &mut Blockchain<Self::ArchiveWasm> {
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
