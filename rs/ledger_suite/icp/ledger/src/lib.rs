use dfn_core::api::{now, trap_with};
use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_canister_core::archive::ArchiveCanisterWasm;
use ic_ledger_canister_core::blockchain::Blockchain;
use ic_ledger_canister_core::ledger::{
    self as core_ledger, LedgerContext, LedgerData, TransactionInfo,
};
use ic_ledger_core::{
    approvals::AllowanceTable, approvals::HeapAllowancesData, balances::Balances,
    block::EncodedBlock, timestamp::TimeStamp,
};
use ic_ledger_core::{block::BlockIndex, tokens::Tokens};
use ic_ledger_hash_of::HashOf;
use icp_ledger::{
    AccountIdentifier, Block, FeatureFlags, LedgerAllowances, LedgerBalances, Memo, Operation,
    PaymentError, Transaction, TransferError, TransferFee, UpgradeArgs, DEFAULT_TRANSFER_FEE,
};
use icrc_ledger_types::icrc1::account::Account;
use intmap::IntMap;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::RwLock;
use std::time::Duration;

mod dfn_runtime;

#[cfg(test)]
mod tests;

lazy_static! {
    pub static ref LEDGER: RwLock<Ledger> = RwLock::new(Ledger::default());
    // Maximum inter-canister message size in bytes.
    pub static ref MAX_MESSAGE_SIZE_BYTES: RwLock<usize> = RwLock::new(1024 * 1024);
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

#[derive(Debug, Deserialize, Serialize)]
pub struct Ledger {
    pub balances: LedgerBalances,
    #[serde(default)]
    pub approvals: LedgerAllowances,
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
}

impl LedgerContext for Ledger {
    type AccountId = AccountIdentifier;
    type AllowancesData = HeapAllowancesData<AccountIdentifier, Tokens>;
    type BalancesStore = BTreeMap<AccountIdentifier, Tokens>;
    type Tokens = Tokens;

    fn balances(&self) -> &Balances<Self::BalancesStore> {
        &self.balances
    }

    fn balances_mut(&mut self) -> &mut Balances<Self::BalancesStore> {
        &mut self.balances
    }

    fn approvals(&self) -> &AllowanceTable<Self::AllowancesData> {
        &self.approvals
    }

    fn approvals_mut(&mut self) -> &mut AllowanceTable<Self::AllowancesData> {
        &mut self.approvals
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
