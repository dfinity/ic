use candid::CandidType;
use dfn_core::api::{now, trap_with};
use ic_base_types::{CanisterId, PrincipalId};
use ic_canister_log::{log, Sink};
use ic_ledger_canister_core::archive::ArchiveCanisterWasm;
use ic_ledger_canister_core::blockchain::Blockchain;
use ic_ledger_canister_core::ledger::{
    self as core_ledger, LedgerContext, LedgerData, TransactionInfo,
};
use ic_ledger_core::tokens::{CheckedSub, Zero};
use ic_ledger_core::{
    approvals::{
        remote_future, Allowance, AllowanceTable, Approvals, ApproveError, InsufficientAllowance,
        PrunableApprovals,
    },
    balances::Balances,
    block::EncodedBlock,
    timestamp::TimeStamp,
};
use ic_ledger_core::{block::BlockIndex, tokens::Tokens};
use ic_ledger_hash_of::HashOf;
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Bound,
    RestrictedMemory, Storable, MAX_PAGES,
};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use icp_ledger::{
    AccountIdentifier, ApprovalKey, Block, FeatureFlags, LedgerBalances, Memo, Operation,
    PaymentError, Transaction, TransferError, TransferFee, UpgradeArgs, DEFAULT_TRANSFER_FEE,
};
use icrc_ledger_types::icrc1::account::Account;
use intmap::IntMap;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::RwLock;
use std::time::Duration;
use std::{
    borrow::Cow,
    io::{Cursor, Read},
};

mod dfn_runtime;

#[cfg(test)]
mod tests;

lazy_static! {
    pub static ref LEDGER: RwLock<Ledger> = RwLock::new(Ledger::default());
    // Maximum inter-canister message size in bytes.
    pub static ref MAX_MESSAGE_SIZE_BYTES: RwLock<usize> = RwLock::new(1024 * 1024);
}

const WASM_PAGE_SIZE: u64 = 65_536;
const UPGRADE_PAGES_SIZE: u64 = 2 * 1024 * 1024 * 1024;
const UPGRADE_PAGES: u64 = UPGRADE_PAGES_SIZE / WASM_PAGE_SIZE;

const ALLOWANCES_MEMORY_ID: MemoryId = MemoryId::new(1);
const ALLOWANCES_EXPIRATIONS_MEMORY_ID: MemoryId = MemoryId::new(2);
const ALLOWANCES_ARRIVALS_MEMORY_ID: MemoryId = MemoryId::new(3);

type CanisterRestrictedMemory = RestrictedMemory<DefaultMemoryImpl>;
type CanisterVirtualMemory = VirtualMemory<CanisterRestrictedMemory>;

thread_local! {

    static MEMORY_MANAGER: RefCell<MemoryManager<CanisterRestrictedMemory>> = RefCell::new(
        MemoryManager::init(RestrictedMemory::new(DefaultMemoryImpl::default(), UPGRADE_PAGES..MAX_PAGES))
    );

    // allowances: BTreeMap<K, Allowance<Tokens>>,
    pub static ALLOWANCES_MEMORY: RefCell<StableBTreeMap<ApprovalKey, Allowance<Tokens>, CanisterVirtualMemory>> =
        MEMORY_MANAGER.with(|memory_manager| RefCell::new(StableBTreeMap::init(memory_manager.borrow().get(ALLOWANCES_MEMORY_ID))));

    // expiration_queue: BTreeSet<(TimeStamp, K)>,
    pub static ALLOWANCES_EXPIRATIONS_MEMORY: RefCell<StableBTreeMap<(TimeStamp, ApprovalKey), (), CanisterVirtualMemory>> =
        MEMORY_MANAGER.with(|memory_manager| RefCell::new(StableBTreeMap::init(memory_manager.borrow().get(ALLOWANCES_EXPIRATIONS_MEMORY_ID))));

    // arrival_queue: BTreeSet<(TimeStamp, K)>,
    pub static ALLOWANCES_ARRIVALS_MEMORY: RefCell<StableBTreeMap<(TimeStamp, ApprovalKey), (), CanisterVirtualMemory>> =
        MEMORY_MANAGER.with(|memory_manager| RefCell::new(StableBTreeMap::init(memory_manager.borrow().get(ALLOWANCES_ARRIVALS_MEMORY_ID))));
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum AllowanceTableField {
    Allowances,
    Expirations,
    Arrivals,
}

impl AllowanceTableField {
    pub fn first() -> Self {
        Self::Allowances
    }

    // move to the beginning of the next field
    pub fn next(&self) -> Option<Self> {
        match self {
            Self::Allowances => Some(Self::Expirations),
            Self::Expirations => Some(Self::Arrivals),
            Self::Arrivals => None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum LedgerField {
    AllowanceTable(AllowanceTableField),
}

impl LedgerField {
    pub fn first() -> Self {
        Self::AllowanceTable(AllowanceTableField::first())
    }

    pub fn next_field(&self) -> Option<Self> {
        match self {
            Self::AllowanceTable(field) => field.next().map(Self::AllowanceTable),
        }
    }
}

#[derive(CandidType, Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub enum LedgerStateType {
    Migrating,
    Ready,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum LedgerState {
    Migrating(LedgerField),
    Ready,
}

impl LedgerState {
    pub fn type_(&self) -> LedgerStateType {
        match self {
            Self::Migrating(..) => LedgerStateType::Migrating,
            Self::Ready => LedgerStateType::Ready,
        }
    }
}

impl Default for LedgerState {
    fn default() -> Self {
        Self::Ready
    }
}

// Wasm bytecode of an Archive Node.
pub const ARCHIVE_NODE_BYTECODE: &[u8] =
    std::include_bytes!(std::env!("LEDGER_ARCHIVE_NODE_CANISTER_WASM_PATH"));

#[derive(Debug)]
pub struct IcpLedgerArchiveWasm;

impl ArchiveCanisterWasm for IcpLedgerArchiveWasm {
    fn archive_wasm() -> Cow<'static, [u8]> {
        Cow::Borrowed(ARCHIVE_NODE_BYTECODE)
    }
}

fn default_max_transactions_in_window() -> usize {
    Ledger::DEFAULT_MAX_TRANSACTIONS_IN_WINDOW
}

fn default_transfer_fee() -> Tokens {
    DEFAULT_TRANSFER_FEE
}

// This is only for deserialization from previous version of the ledger.
fn unknown_token() -> String {
    "???".to_string()
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Ledger {
    pub balances: LedgerBalances,
    #[serde(default)]
    pub approvals: AllowanceTable<ApprovalKey, AccountIdentifier, Tokens>,
    #[serde(default)]
    pub stable_approvals: StableApprovals,
    pub blockchain: Blockchain<dfn_runtime::DfnRuntime, IcpLedgerArchiveWasm>,
    // A cap on the maximum number of accounts.
    pub maximum_number_of_accounts: usize,
    // When maximum number of accounts is exceeded, a specified number of
    // accounts with lowest balances are removed.
    accounts_overflow_trim_quantity: usize,
    pub minting_account_id: Option<AccountIdentifier>,
    pub icrc1_minting_account: Option<Account>,
    // This is a set of BlockIndices that have been notified.
    #[serde(default)]
    pub blocks_notified: IntMap<()>,
    /// How long transactions are remembered to detect duplicates.
    pub transaction_window: Duration,
    /// For each transaction, record the block in which the
    /// transaction was created. This only contains transactions from
    /// the last `transaction_window` period.
    transactions_by_hash: BTreeMap<HashOf<Transaction>, BlockIndex>,
    /// The transactions in the transaction window, sorted by block
    /// index / block timestamp. (Block timestamps are monotonically
    /// non-decreasing, so this is the same.)
    transactions_by_height: VecDeque<TransactionInfo<Transaction>>,
    /// Used to prevent non-whitelisted canisters from sending tokens.
    send_whitelist: HashSet<CanisterId>,
    /// Maximum number of transactions which ledger will accept
    /// within the transaction_window.
    #[serde(default = "default_max_transactions_in_window")]
    max_transactions_in_window: usize,
    /// The fee to pay to perform a transfer.
    #[serde(default = "default_transfer_fee")]
    pub transfer_fee: Tokens,

    /// Token symbol
    #[serde(default = "unknown_token")]
    pub token_symbol: String,
    /// Token name
    #[serde(default = "unknown_token")]
    pub token_name: String,

    #[serde(default)]
    pub feature_flags: FeatureFlags,

    #[serde(default)]
    pub state: LedgerState,

    #[serde(default)]
    pub rounds: u64,
}

impl LedgerContext for Ledger {
    type AccountId = AccountIdentifier;
    type Approvals = StableApprovals;
    type BalancesStore = BTreeMap<AccountIdentifier, Tokens>;
    type Tokens = Tokens;

    fn balances(&self) -> &Balances<Self::BalancesStore> {
        &self.balances
    }

    fn balances_mut(&mut self) -> &mut Balances<Self::BalancesStore> {
        &mut self.balances
    }

    fn approvals(&self) -> &Self::Approvals {
        &self.stable_approvals
    }

    fn approvals_mut(&mut self) -> &mut Self::Approvals {
        &mut self.stable_approvals
    }

    fn fee_collector(&self) -> Option<&ic_ledger_core::block::FeeCollector<Self::AccountId>> {
        None
    }
}

impl LedgerData for Ledger {
    type Runtime = dfn_runtime::DfnRuntime;
    type ArchiveWasm = IcpLedgerArchiveWasm;
    type Transaction = Transaction;
    type Block = Block;

    fn transaction_window(&self) -> Duration {
        self.transaction_window
    }

    fn max_transactions_in_window(&self) -> usize {
        self.max_transactions_in_window
    }

    fn max_transactions_to_purge(&self) -> usize {
        Self::MAX_TRANSACTIONS_TO_PURGE
    }

    fn max_number_of_accounts(&self) -> usize {
        self.maximum_number_of_accounts
    }

    fn accounts_overflow_trim_quantity(&self) -> usize {
        self.accounts_overflow_trim_quantity
    }

    fn token_name(&self) -> &str {
        &self.token_name
    }

    fn token_symbol(&self) -> &str {
        &self.token_symbol
    }

    fn blockchain(&self) -> &Blockchain<Self::Runtime, Self::ArchiveWasm> {
        &self.blockchain
    }

    fn blockchain_mut(&mut self) -> &mut Blockchain<Self::Runtime, Self::ArchiveWasm> {
        &mut self.blockchain
    }

    fn transactions_by_hash(&self) -> &BTreeMap<HashOf<Self::Transaction>, BlockIndex> {
        &self.transactions_by_hash
    }

    fn transactions_by_hash_mut(&mut self) -> &mut BTreeMap<HashOf<Self::Transaction>, BlockIndex> {
        &mut self.transactions_by_hash
    }

    fn transactions_by_height(&self) -> &VecDeque<TransactionInfo<Self::Transaction>> {
        &self.transactions_by_height
    }

    fn transactions_by_height_mut(&mut self) -> &mut VecDeque<TransactionInfo<Self::Transaction>> {
        &mut self.transactions_by_height
    }

    fn on_purged_transaction(&mut self, height: BlockIndex) {
        self.blocks_notified.remove(height);
    }

    fn fee_collector_mut(
        &mut self,
    ) -> Option<&mut ic_ledger_core::block::FeeCollector<Self::AccountId>> {
        None
    }
}

impl Default for Ledger {
    fn default() -> Self {
        Self {
            approvals: Default::default(),
            stable_approvals: Default::default(),
            balances: LedgerBalances::default(),
            blockchain: Blockchain::default(),
            maximum_number_of_accounts: 28_000_000,
            accounts_overflow_trim_quantity: 100_000,
            minting_account_id: None,
            icrc1_minting_account: None,
            blocks_notified: IntMap::new(),
            transaction_window: Duration::from_secs(24 * 60 * 60),
            transactions_by_hash: BTreeMap::new(),
            transactions_by_height: VecDeque::new(),
            send_whitelist: HashSet::new(),
            max_transactions_in_window: Self::DEFAULT_MAX_TRANSACTIONS_IN_WINDOW,
            transfer_fee: DEFAULT_TRANSFER_FEE,
            token_symbol: unknown_token(),
            token_name: unknown_token(),
            feature_flags: FeatureFlags::default(),
            state: LedgerState::Ready,
            rounds: 0,
        }
    }
}

impl Ledger {
    /// The maximum number of transactions that we attempt to purge in one go.
    /// If there are many transactions in the buffer, purging them all in one go
    /// might require more instructions than one message execution allows.
    /// Hence, we purge old transactions incrementally, up to
    /// MAX_TRANSACTIONS_TO_PURGE at a time.
    const MAX_TRANSACTIONS_TO_PURGE: usize = 100_000;
    /// See Ledger::max_transactions_in_window
    const DEFAULT_MAX_TRANSACTIONS_IN_WINDOW: usize = 3_000_000;

    /// This creates a block and adds it to the ledger.
    pub fn add_payment(
        &mut self,
        memo: Memo,
        operation: Operation,
        created_at_time: Option<TimeStamp>,
    ) -> Result<(BlockIndex, HashOf<EncodedBlock>), PaymentError> {
        let now = TimeStamp::from(dfn_core::api::now());
        self.add_payment_with_timestamp(memo, operation, created_at_time, now)
    }

    pub fn add_payment_with_timestamp(
        &mut self,
        memo: Memo,
        operation: Operation,
        created_at_time: Option<TimeStamp>,
        now: TimeStamp,
    ) -> Result<(BlockIndex, HashOf<EncodedBlock>), PaymentError> {
        let effective_fee = match &operation {
            Operation::Transfer { .. } => self.transfer_fee,
            Operation::Mint { .. } => Tokens::from_e8s(0),
            Operation::Burn { .. } => Tokens::from_e8s(0),
            Operation::Approve { .. } => self.transfer_fee,
        };
        core_ledger::apply_transaction(
            self,
            Transaction {
                operation,
                memo,
                icrc1_memo: None,
                // TODO(FI-349): preserve created_at_time and memo the caller specified.
                created_at_time: created_at_time.or(Some(now)),
            },
            now,
            effective_fee,
        )
        .map_err(|e| {
            use ic_ledger_canister_core::ledger::TransferError as CTE;
            use PaymentError::TransferError as PTE;
            use TransferError as TE;

            match e {
                CTE::BadFee { expected_fee } => PTE(TE::BadFee { expected_fee }),
                CTE::InsufficientFunds { balance } => PTE(TE::InsufficientFunds { balance }),
                CTE::TxTooOld {
                    allowed_window_nanos,
                } => PTE(TE::TxTooOld {
                    allowed_window_nanos,
                }),
                CTE::TxCreatedInFuture { .. } => PTE(TE::TxCreatedInFuture),
                CTE::TxDuplicate { duplicate_of } => PTE(TE::TxDuplicate { duplicate_of }),
                CTE::InsufficientAllowance { .. } => todo!(),
                CTE::ExpiredApproval { .. } => todo!(),
                CTE::TxThrottled => PaymentError::Reject(
                    concat!(
                        "Too many transactions in replay prevention window, ",
                        "ledger is throttling, please retry later"
                    )
                    .to_string(),
                ),
                CTE::AllowanceChanged { .. } => todo!(),
                CTE::SelfApproval { .. } => todo!(),
                CTE::BadBurn { .. } => todo!(),
            }
        })
    }

    /// This adds a pre created block to the ledger. This should only be used
    /// during canister migration or upgrade.
    pub fn add_block(&mut self, block: Block) -> Result<BlockIndex, String> {
        icp_ledger::apply_operation(self, &block.transaction.operation, block.timestamp)
            .map_err(|e| format!("failed to execute transfer {:?}: {:?}", block, e))?;
        self.blockchain.add_block(block)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_init(
        &mut self,
        initial_values: HashMap<AccountIdentifier, Tokens>,
        minting_account: AccountIdentifier,
        icrc1_minting_account: Option<Account>,
        timestamp: TimeStamp,
        transaction_window: Option<Duration>,
        send_whitelist: HashSet<CanisterId>,
        transfer_fee: Option<Tokens>,
        token_symbol: Option<String>,
        token_name: Option<String>,
        feature_flags: Option<FeatureFlags>,
        maximum_number_of_accounts: Option<usize>,
        accounts_overflow_trim_quantity: Option<usize>,
    ) {
        self.token_symbol = token_symbol.unwrap_or_else(|| "ICP".to_string());
        self.token_name = token_name.unwrap_or_else(|| "Internet Computer".to_string());
        self.balances.token_pool = Tokens::MAX;
        self.minting_account_id = Some(minting_account);
        self.icrc1_minting_account = icrc1_minting_account;
        if let Some(t) = transaction_window {
            self.transaction_window = t;
        }

        for (to, amount) in initial_values.into_iter() {
            self.add_payment_with_timestamp(
                Memo::default(),
                Operation::Mint { to, amount },
                None,
                timestamp,
            )
            .expect(&format!("Creating account {:?} failed", to)[..]);
        }

        self.send_whitelist = send_whitelist;
        if let Some(transfer_fee) = transfer_fee {
            self.transfer_fee = transfer_fee;
        }
        if let Some(feature_flags) = feature_flags {
            self.feature_flags = feature_flags;
        }
        if let Some(maximum_number_of_accounts) = maximum_number_of_accounts {
            self.maximum_number_of_accounts = maximum_number_of_accounts;
        }
        if let Some(accounts_overflow_trim_quantity) = accounts_overflow_trim_quantity {
            self.accounts_overflow_trim_quantity = accounts_overflow_trim_quantity;
        }
    }

    pub fn change_notification_state(
        &mut self,
        height: BlockIndex,
        block_timestamp: TimeStamp,
        new_state: bool,
        now: TimeStamp,
    ) -> Result<(), String> {
        if block_timestamp + self.transaction_window <= now {
            return Err(format!(
                "You cannot send a notification for a transaction that is more than {} seconds old",
                self.transaction_window.as_secs(),
            ));
        }

        let is_notified = self.blocks_notified.get(height).is_some();

        match (is_notified, new_state) {
            (true, true) | (false, false) => {
                Err(format!("The notification state is already {}", is_notified))
            }
            (true, false) => {
                self.blocks_notified.remove(height);
                Ok(())
            }
            (false, true) => {
                self.blocks_notified.insert(height, ());
                Ok(())
            }
        }
    }

    pub fn remove_archived_blocks(&mut self, len: usize) {
        self.blockchain.remove_archived_blocks(len);
    }

    pub fn get_blocks_for_archiving(
        &self,
        trigger_threshold: usize,
        num_blocks: usize,
    ) -> VecDeque<EncodedBlock> {
        self.blockchain
            .get_blocks_for_archiving(trigger_threshold, num_blocks)
    }

    pub fn can_send(&self, principal_id: &PrincipalId) -> bool {
        !principal_id.is_anonymous()
    }

    /// Check if it's allowed to notify this canister.
    /// Currently we reuse whitelist for that.
    pub fn can_be_notified(&self, canister_id: &CanisterId) -> bool {
        LEDGER.read().unwrap().send_whitelist.contains(canister_id)
    }

    pub fn transactions_by_hash_len(&self) -> usize {
        self.transactions_by_hash.len()
    }

    pub fn transactions_by_height_len(&self) -> usize {
        self.transactions_by_height.len()
    }

    pub fn transfer_fee(&self) -> TransferFee {
        TransferFee {
            transfer_fee: self.transfer_fee,
        }
    }

    pub fn upgrade(&mut self, args: UpgradeArgs) {
        if let Some(maximum_number_of_accounts) = args.maximum_number_of_accounts {
            self.maximum_number_of_accounts = maximum_number_of_accounts;
        }
        if let Some(icrc1_minting_account) = args.icrc1_minting_account {
            if Some(AccountIdentifier::from(icrc1_minting_account)) != self.minting_account_id {
                trap_with(
                    "The icrc1 minting account is not the same as the minting account set during initialization",
                );
            }
            self.icrc1_minting_account = Some(icrc1_minting_account);
        }
        if let Some(feature_flags) = args.feature_flags {
            self.feature_flags = feature_flags;
        }
    }

    pub fn compute_ledger_state(&mut self, sink: impl Sink + Clone) {
        if let LedgerState::Ready = self.state {
            // check whether there is state to migrate
            // and begin the migration from the next field
            if let Some(field) = self.next_field_to_migrate() {
                log!(sink, "[ledger] Starting migration from {field:?}");
                self.state = LedgerState::Migrating(field);
            }
        }
    }

    pub fn is_migrating(&self) -> bool {
        match self.state {
            LedgerState::Migrating(..) => true,
            LedgerState::Ready => false,
        }
    }

    pub fn is_ready(&self) -> bool {
        match self.state {
            LedgerState::Migrating(..) => false,
            LedgerState::Ready => true,
        }
    }

    pub fn next_field_to_migrate(&self) -> Option<LedgerField> {
        use AllowanceTableField::*;
        use LedgerField::*;

        if !self.approvals.allowances.is_empty() {
            Some(AllowanceTable(Allowances))
        } else if !self.approvals.expiration_queue.is_empty() {
            Some(AllowanceTable(Expirations))
        } else if !self.approvals.arrival_queue.is_empty() {
            Some(AllowanceTable(Arrivals))
        } else {
            None
        }
    }
}

pub fn add_payment(
    memo: Memo,
    payment: Operation,
    created_at_time: Option<TimeStamp>,
) -> (BlockIndex, HashOf<EncodedBlock>) {
    LEDGER
        .write()
        .unwrap()
        .add_payment(memo, payment, created_at_time)
        .expect("Transfer failed")
}

pub fn change_notification_state(
    height: BlockIndex,
    block_timestamp: TimeStamp,
    new_state: bool,
) -> Result<(), String> {
    LEDGER.write().unwrap().change_notification_state(
        height,
        block_timestamp,
        new_state,
        TimeStamp::from(now()),
    )
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct StableApprovals {}

impl Approvals for StableApprovals {
    type AccountId = AccountIdentifier;
    type Tokens = Tokens;

    /// Returns the current spender's allowance for the account.
    fn allowance(
        &self,
        account: &Self::AccountId,
        spender: &Self::AccountId,
        now: TimeStamp,
    ) -> Allowance<Self::Tokens> {
        let key = ApprovalKey(*account, *spender);
        ALLOWANCES_MEMORY.with_borrow(|allowances| match allowances.get(&key) {
            Some(allowance) if allowance.expires_at.unwrap_or_else(remote_future) > now => {
                allowance
            }
            _ => Allowance::default(),
        })
    }

    /// Increases the spender's allowance for the account by the specified amount.
    fn approve(
        &mut self,
        account: &Self::AccountId,
        spender: &Self::AccountId,
        amount: Self::Tokens,
        expires_at: Option<TimeStamp>,
        now: TimeStamp,
        expected_allowance: Option<Self::Tokens>,
    ) -> Result<Self::Tokens, ApproveError<Self::Tokens>> {
        // TODO: implement self.with_postconditions_check
        if account == spender {
            return Err(ApproveError::SelfApproval);
        }

        if expires_at.unwrap_or_else(remote_future) <= now {
            return Err(ApproveError::ExpiredApproval { now });
        }

        let key = ApprovalKey(*account, *spender);

        ALLOWANCES_MEMORY.with_borrow_mut(|allowances| match allowances.get(&key) {
            None => {
                if let Some(expected_allowance) = expected_allowance {
                    if !expected_allowance.is_zero() {
                        return Err(ApproveError::AllowanceChanged {
                            current_allowance: Tokens::zero(),
                        });
                    }
                }
                if amount == Tokens::zero() {
                    return Ok(amount);
                }
                if let Some(expires_at) = expires_at {
                    ALLOWANCES_EXPIRATIONS_MEMORY.with_borrow_mut(|expirations| {
                        expirations.insert((expires_at, key.clone()), ());
                    });
                }
                ALLOWANCES_ARRIVALS_MEMORY
                    .with_borrow_mut(|arrivals| arrivals.insert((now, key.clone()), ()));
                let allowance = Allowance {
                    amount: amount.clone(),
                    expires_at,
                    arrived_at: now,
                };
                allowances.insert(key, allowance);
                Ok(amount)
            }
            Some(mut allowance) => {
                if let Some(expected_allowance) = expected_allowance {
                    let current_allowance = if let Some(expires_at) = allowance.expires_at {
                        if expires_at <= now {
                            Tokens::zero()
                        } else {
                            allowance.amount.clone()
                        }
                    } else {
                        allowance.amount.clone()
                    };
                    if expected_allowance != current_allowance {
                        return Err(ApproveError::AllowanceChanged { current_allowance });
                    }
                }
                ALLOWANCES_ARRIVALS_MEMORY.with_borrow_mut(|arrivals| {
                    arrivals.remove(&(allowance.arrived_at, key.clone()))
                });
                if amount == Tokens::zero() {
                    if let Some(expires_at) = allowance.expires_at {
                        ALLOWANCES_EXPIRATIONS_MEMORY.with_borrow_mut(|expirations| {
                            expirations.remove(&(expires_at, key.clone()))
                        });
                    }
                    allowances.remove(&key);
                    return Ok(amount);
                }
                ALLOWANCES_ARRIVALS_MEMORY.with_borrow_mut(|arrivals| {
                    arrivals.insert((now, key.clone()), ());
                });
                allowance.amount = amount;
                allowance.arrived_at = now;
                let old_expiration = std::mem::replace(&mut allowance.expires_at, expires_at);
                allowances.insert(key.clone(), allowance);

                if expires_at != old_expiration {
                    if let Some(old_expiration) = old_expiration {
                        ALLOWANCES_EXPIRATIONS_MEMORY.with_borrow_mut(|expirations| {
                            expirations.remove(&(old_expiration, key.clone()));
                        })
                    }
                    if let Some(expires_at) = expires_at {
                        ALLOWANCES_EXPIRATIONS_MEMORY.with_borrow_mut(|expirations| {
                            expirations.insert((expires_at, key.clone()), ());
                        })
                    }
                }
                Ok(amount)
            }
        })
    }

    /// Returns the number of approvals.
    fn get_num_approvals(&self) -> usize {
        ALLOWANCES_MEMORY
            .with_borrow(|allowances| (usize::MAX as u64).min(allowances.len()) as usize)
    }

    /// Consumes amount from the spender's allowance for the account.
    ///
    /// This method behaves like [decrease_amount] but bails out if the
    /// allowance goes negative.
    fn use_allowance(
        &mut self,
        account: &Self::AccountId,
        spender: &Self::AccountId,
        amount: Self::Tokens,
        now: TimeStamp,
    ) -> Result<Self::Tokens, InsufficientAllowance<Self::Tokens>> {
        let key = ApprovalKey(*account, *spender);

        ALLOWANCES_MEMORY.with_borrow_mut(|allowances| match allowances.get(&key) {
            None => Err(InsufficientAllowance(Tokens::zero())),
            Some(mut allowance) => {
                if allowance.expires_at.unwrap_or_else(remote_future) <= now {
                    Err(InsufficientAllowance(Tokens::zero()))
                } else {
                    if allowance.amount < amount {
                        return Err(InsufficientAllowance(allowance.amount.clone()));
                    }
                    allowance.amount = allowance
                        .amount
                        .checked_sub(&amount)
                        .expect("Underflow when using allowance");
                    let amount = allowance.amount.clone();
                    if amount.is_zero() {
                        if let Some(expires_at) = allowance.expires_at {
                            ALLOWANCES_EXPIRATIONS_MEMORY.with_borrow_mut(|expirations| {
                                expirations.remove(&(expires_at, key.clone()));
                            });
                        }
                        ALLOWANCES_ARRIVALS_MEMORY.with_borrow_mut(|arrivals| {
                            arrivals.remove(&(allowance.arrived_at, key.clone()));
                        });
                        allowances.remove(&key);
                    } else {
                        allowances.insert(key, allowance);
                    }
                    Ok(amount)
                }
            }
        })
    }

    /// Returns a vector of pairs (account, spender) of size min(n, approvals_size)
    /// that represent approvals selected for trimming.
    fn select_approvals_to_trim(&self, n: usize) -> Vec<(Self::AccountId, Self::AccountId)> {
        ALLOWANCES_ARRIVALS_MEMORY.with_borrow(|arrivals| {
            arrivals
                .iter()
                .map(|((_, key), ())| (key.0, key.1))
                .take(n)
                .collect()
        })
    }
}

impl PrunableApprovals for StableApprovals {
    fn len(&self) -> usize {
        ALLOWANCES_MEMORY.with_borrow(|allowances| allowances.len()) as usize
    }

    fn prune(&mut self, now: TimeStamp, limit: usize) -> usize {
        // TODO: implement self.with_postconditions_check
        let mut pruned = 0;
        for _ in 0..limit {
            let first_expiration = ALLOWANCES_EXPIRATIONS_MEMORY
                .with_borrow(|expirations| expirations.first_key_value());
            let key = match first_expiration {
                None => break,
                Some(((expires_at, _), _)) if expires_at > now => break,
                Some(((_, key), _)) => key,
            };
            ALLOWANCES_EXPIRATIONS_MEMORY.with_borrow_mut(|expirations| expirations.pop_first());
            let allowance = ALLOWANCES_MEMORY
                .with_borrow_mut(|allowances| allowances.remove(&key))
                .unwrap_or_else(|| panic!("Unable to find allowance {key:?}"));
            ALLOWANCES_ARRIVALS_MEMORY
                .with_borrow_mut(|arrivals| arrivals.remove(&(allowance.arrived_at, key)));
            pruned += 1;
        }
        pruned
    }
}

// #[test]
// fn test_allowance_storable() {
//     let allowance = Allowance {
//         amount: Tokens::new(12u64, 12u64),
//         expires_at: Some(TimeStamp::from_nanos_since_unix_epoch(123u64)),
//         arrived_at: TimeStamp::from_nanos_since_unix_epoch(123u64),
//     };
//     let actual = Allowance::from_bytes(allowance.to_bytes());
//     assert_eq!(allowance, actual);
// }

// #[test]
// fn test_approvakey_storable() {
//     use proptest::collection::vec;
//     use proptest::strategy::Strategy;
//     use proptest::{option, prelude::any, prop_assert_eq, proptest};

//     fn account_strategy() -> impl Strategy<Value = Account> {
//         (
//             vec(any::<u8>(), 0..30).prop_map(|v| Principal::from_slice(&v)),
//             option::of(any::<[u8; 32]>()),
//         )
//             .prop_map(|(owner, subaccount)| Account { owner, subaccount })
//     }

//     proptest!(|(
//         account0 in account_strategy(),
//         account1 in account_strategy()
//     )| {
//         let approval_key = ApprovalKey(account0, account1);
//         let actual = ApprovalKey::from_bytes(approval_key.to_bytes());
//         prop_assert_eq!(approval_key, actual)
//     })
// }
