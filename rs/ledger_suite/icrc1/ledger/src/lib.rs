#[cfg(test)]
mod tests;

use candid::{
    CandidType, Principal,
    types::number::{Int, Nat},
};
use ic_base_types::PrincipalId;
use ic_canister_log::{Sink, log};
use ic_certification::{
    HashTree,
    hash_tree::{Label, empty, fork, label, leaf},
};
use ic_icrc1::blocks::encoded_block_to_generic_block;
use ic_icrc1::{Block, LedgerAllowances, LedgerBalances, Transaction};
pub use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_canister_core::runtime::{CdkRuntime, Runtime};
use ic_ledger_canister_core::{archive::Archive, blockchain::BlockDataContainer};
use ic_ledger_canister_core::{
    archive::ArchiveCanisterWasm,
    blockchain::Blockchain,
    ledger::{LedgerContext, LedgerData, TransactionInfo, apply_transaction, block_locations},
    range_utils,
};
use ic_ledger_core::balances::BalancesStore;
use ic_ledger_core::{
    approvals::{Allowance, AllowanceTable, AllowancesData},
    balances::Balances,
    block::{BlockIndex, BlockType, EncodedBlock, FeeCollector},
    timestamp::TimeStamp,
};
use ic_ledger_hash_of::HashOf;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use ic_stable_structures::{Storable, storable::Bound};
use icrc_ledger_types::{
    icrc::generic_metadata_value::MetadataValue as Value,
    icrc3::archive::{ArchivedRange, QueryBlockArchiveFn, QueryTxArchiveFn},
};
use icrc_ledger_types::{
    icrc::generic_value::ICRC3Value,
    icrc1::account::Account,
    icrc3::{
        archive::{GetArchivesArgs, GetArchivesResult, ICRC3ArchiveInfo, QueryArchiveFn},
        blocks::{ArchivedBlocks, GetBlocksRequest, GetBlocksResult},
    },
};
use icrc_ledger_types::{
    icrc3::transactions::Transaction as Tx, icrc103::get_allowances::Allowances,
};
use icrc_ledger_types::{
    icrc3::{blocks::GetBlocksResponse, transactions::GetTransactionsResponse},
    icrc103::get_allowances::Allowance as Allowance103,
};
use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::ops::DerefMut;
use std::time::Duration;

const TRANSACTION_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);
/// The maximum number of transactions the ledger should return for a single
/// get_transactions request.
const MAX_TRANSACTIONS_PER_REQUEST: usize = 2_000;
const MAX_TRANSACTIONS_IN_WINDOW: usize = 3_000_000;
const MAX_TRANSACTIONS_TO_PURGE: usize = 100_000;
#[allow(dead_code)]
const MAX_U64_ENCODING_BYTES: usize = 10;
const DEFAULT_MAX_MEMO_LENGTH: u16 = 32;
const METADATA_DECIMALS: &str = "icrc1:decimals";
const METADATA_NAME: &str = "icrc1:name";
const METADATA_SYMBOL: &str = "icrc1:symbol";
const METADATA_FEE: &str = "icrc1:fee";
const METADATA_MAX_MEMO_LENGTH: &str = "icrc1:max_memo_length";
const METADATA_PUBLIC_ALLOWANCES: &str = "icrc103:public_allowances";
const METADATA_MAX_TAKE_ALLOWANCES: &str = "icrc103:max_take_value";
const MAX_TAKE_ALLOWANCES: u64 = 500;

#[cfg(not(feature = "u256-tokens"))]
pub type Tokens = ic_icrc1_tokens_u64::U64;

#[cfg(feature = "u256-tokens")]
pub type Tokens = ic_icrc1_tokens_u256::U256;

/// The ledger versions represent backwards incompatible versions of the ledger.
/// Downgrading to a lower ledger version is never suppported.
/// Upgrading from version N to version N+1 should always be possible.
/// We have the following ledger versions:
///   * 0 - the whole ledger state is stored on the heap.
///   * 1 - the allowances are stored in stable structures.
///   * 2 - the balances are stored in stable structures.
///   * 3 - the blocks are stored in stable structures.
#[cfg(not(feature = "next-ledger-version"))]
pub const LEDGER_VERSION: u64 = 3;

#[cfg(feature = "next-ledger-version")]
pub const LEDGER_VERSION: u64 = 4;

#[derive(Clone, Debug)]
pub struct Icrc1ArchiveWasm;

impl ArchiveCanisterWasm for Icrc1ArchiveWasm {
    fn archive_wasm() -> Cow<'static, [u8]> {
        Cow::Borrowed(include_bytes!(env!("IC_ICRC1_ARCHIVE_WASM_PATH")))
    }
}

/// Like [endpoints::Value], but can be serialized to CBOR.
#[derive(Clone, Debug, Deserialize, Serialize)]
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
                    .unwrap_or_else(|e| panic!("bug: invalid Nat encoding {num_bytes:?}: {e}")),
            ),
            StoredValue::IntBytes(int_bytes) => Self::Int(
                Int::decode(&mut &int_bytes[..])
                    .unwrap_or_else(|e| panic!("bug: invalid Int encoding {int_bytes:?}: {e}")),
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

#[derive(Clone, Debug)]
pub struct InitArgsBuilder(InitArgs);

impl InitArgsBuilder {
    pub fn with_symbol_and_name(symbol: impl ToString, name: impl ToString) -> Self {
        let mut args = Self::for_tests();
        args.0.token_symbol = symbol.to_string();
        args.0.token_name = name.to_string();
        args
    }

    pub fn for_tests() -> Self {
        let default_owner = Principal::anonymous();
        Self(InitArgs {
            minting_account: Account {
                owner: default_owner,
                subaccount: None,
            },
            fee_collector_account: None,
            initial_balances: vec![],
            transfer_fee: 10_000_u32.into(),
            decimals: None,
            token_name: "Test Token".to_string(),
            token_symbol: "XTK".to_string(),
            metadata: vec![],
            archive_options: ArchiveOptions {
                trigger_threshold: 1000,
                num_blocks_to_archive: 1000,
                node_max_memory_size_bytes: None,
                max_message_size_bytes: None,
                controller_id: default_owner.into(),
                more_controller_ids: None,
                cycles_for_archive_creation: Some(0),
                max_transactions_per_response: None,
            },
            max_memo_length: None,
            feature_flags: None,
            index_principal: None,
        })
    }

    pub fn with_minting_account(mut self, account: impl Into<Account>) -> Self {
        self.0.minting_account = account.into();
        self
    }

    pub fn with_fee_collector_account(mut self, account: impl Into<Account>) -> Self {
        self.0.fee_collector_account = Some(account.into());
        self
    }

    pub fn with_transfer_fee(mut self, fee: impl Into<Nat>) -> Self {
        self.0.transfer_fee = fee.into();
        self
    }

    pub fn with_decimals(mut self, decimals: u8) -> Self {
        self.0.decimals = Some(decimals);
        self
    }

    pub fn with_archive_options(mut self, options: ArchiveOptions) -> Self {
        self.0.archive_options = options;
        self
    }

    pub fn with_token_symbol(mut self, symbol: impl ToString) -> Self {
        self.0.token_symbol = symbol.to_string();
        self
    }

    pub fn with_token_name(mut self, name: impl ToString) -> Self {
        self.0.token_name = name.to_string();
        self
    }

    pub fn with_metadata_entry(mut self, name: impl ToString, value: impl Into<Value>) -> Self {
        self.0.metadata.push((name.to_string(), value.into()));
        self
    }

    pub fn with_initial_balance(
        mut self,
        account: impl Into<Account>,
        amount: impl Into<Nat>,
    ) -> Self {
        self.0
            .initial_balances
            .push((account.into(), amount.into()));
        self
    }

    pub fn with_max_memo_length(mut self, limit: u16) -> Self {
        self.0.max_memo_length = Some(limit);
        self
    }

    pub fn with_index_principal(mut self, index_principal: Principal) -> Self {
        self.0.index_principal = Some(index_principal);
        self
    }

    pub fn with_feature_flags(mut self, flags: FeatureFlags) -> Self {
        self.0.feature_flags = Some(flags);
        self
    }

    pub fn build(self) -> InitArgs {
        self.0
    }
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct InitArgs {
    pub minting_account: Account,
    pub fee_collector_account: Option<Account>,
    pub initial_balances: Vec<(Account, Nat)>,
    pub transfer_fee: Nat,
    pub decimals: Option<u8>,
    pub token_name: String,
    pub token_symbol: String,
    pub metadata: Vec<(String, Value)>,
    pub archive_options: ArchiveOptions,
    pub max_memo_length: Option<u16>,
    pub feature_flags: Option<FeatureFlags>,
    pub index_principal: Option<Principal>,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub enum ChangeFeeCollector {
    Unset,
    SetTo(Account),
}

impl From<ChangeFeeCollector> for Option<FeeCollector<Account>> {
    fn from(value: ChangeFeeCollector) -> Self {
        match value {
            ChangeFeeCollector::Unset => None,
            ChangeFeeCollector::SetTo(account) => Some(FeeCollector::from(account)),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize)]
pub struct ChangeArchiveOptions {
    pub trigger_threshold: Option<usize>,
    pub num_blocks_to_archive: Option<usize>,
    pub node_max_memory_size_bytes: Option<u64>,
    pub max_message_size_bytes: Option<u64>,
    pub controller_id: Option<PrincipalId>,
    pub more_controller_ids: Option<Vec<PrincipalId>>,
    pub cycles_for_archive_creation: Option<u64>,
    pub max_transactions_per_response: Option<u64>,
}

impl ChangeArchiveOptions {
    pub fn apply<Rt: Runtime, Wasm: ArchiveCanisterWasm>(self, archive: &mut Archive<Rt, Wasm>) {
        if let Some(trigger_threshold) = self.trigger_threshold {
            archive.trigger_threshold = trigger_threshold;
        }
        if let Some(num_blocks_to_archive) = self.num_blocks_to_archive {
            archive.num_blocks_to_archive = num_blocks_to_archive;
        }
        if let Some(node_max_memory_size_bytes) = self.node_max_memory_size_bytes {
            archive.node_max_memory_size_bytes = node_max_memory_size_bytes;
        }
        if let Some(max_message_size_bytes) = self.max_message_size_bytes {
            archive.max_message_size_bytes = max_message_size_bytes;
        }
        if let Some(controller_id) = self.controller_id {
            archive.controller_id = controller_id;
        }
        if let Some(more_controller_ids) = self.more_controller_ids {
            archive.more_controller_ids = Some(more_controller_ids);
        }
        if let Some(cycles_for_archive_creation) = self.cycles_for_archive_creation {
            archive.cycles_for_archive_creation = cycles_for_archive_creation;
        }
        if let Some(max_transactions_per_response) = self.max_transactions_per_response {
            archive.max_transactions_per_response = Some(max_transactions_per_response);
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize)]
pub struct UpgradeArgs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Vec<(String, Value)>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_symbol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfer_fee: Option<Nat>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_fee_collector: Option<ChangeFeeCollector>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_memo_length: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feature_flags: Option<FeatureFlags>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_archive_options: Option<ChangeArchiveOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index_principal: Option<Principal>,
}

#[derive(Clone, Eq, PartialEq, Debug, Encode, Decode)]
struct AccountSpender {
    #[n(0)]
    account: Account,
    #[n(1)]
    spender: Account,
}

impl std::cmp::PartialOrd for AccountSpender {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for AccountSpender {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.account
            .cmp(&other.account)
            .then_with(|| self.spender.cmp(&other.spender))
    }
}

impl Storable for AccountSpender {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut buf = vec![];
        minicbor::encode(self, &mut buf).expect("AccountSpender encoding should always succeed");
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        minicbor::decode(bytes.as_ref()).unwrap_or_else(|e| {
            panic!(
                "failed to decode AccountSpender bytes {}: {e}",
                hex::encode(bytes)
            )
        })
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl From<&(Account, Account)> for AccountSpender {
    fn from(pair: &(Account, Account)) -> Self {
        Self {
            account: pair.0,
            spender: pair.1,
        }
    }
}

impl From<AccountSpender> for (Account, Account) {
    fn from(val: AccountSpender) -> Self {
        (val.account, val.spender)
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Encode, Decode)]
struct Expiration {
    #[n(0)]
    timestamp: TimeStamp,
    #[n(1)]
    account_spender: AccountSpender,
}

impl std::cmp::PartialOrd for Expiration {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for Expiration {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.timestamp
            .cmp(&other.timestamp)
            .then_with(|| self.account_spender.cmp(&other.account_spender))
    }
}

impl Storable for Expiration {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut buf = vec![];
        minicbor::encode(self, &mut buf).expect("Expiration encoding should always succeed");
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        minicbor::decode(bytes.as_ref()).unwrap_or_else(|e| {
            panic!(
                "failed to decode Expiration bytes {}: {e}",
                hex::encode(bytes)
            )
        })
    }

    const BOUND: Bound = Bound::Unbounded;
}

#[derive(Clone, Debug, Encode, Decode)]
struct StorableAllowance {
    #[n(0)]
    amount: Tokens,
    #[n(1)]
    expires_at: Option<TimeStamp>,
}

impl Storable for StorableAllowance {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut buf = vec![];
        minicbor::encode(self, &mut buf).expect("StorableAllowance encoding should always succeed");
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        minicbor::decode(bytes.as_ref()).unwrap_or_else(|e| {
            panic!(
                "failed to decode StorableAllowance bytes {}: {e}",
                hex::encode(bytes)
            )
        })
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl From<Allowance<Tokens>> for StorableAllowance {
    fn from(val: Allowance<Tokens>) -> Self {
        Self {
            amount: val.amount,
            expires_at: val.expires_at,
        }
    }
}

impl From<StorableAllowance> for Allowance<Tokens> {
    fn from(val: StorableAllowance) -> Self {
        Self {
            amount: val.amount,
            expires_at: val.expires_at,
            // This field is not used and will be removed in subsequent PR.
            arrived_at: TimeStamp::from_nanos_since_unix_epoch(0),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum LedgerArgument {
    Init(InitArgs),
    Upgrade(Option<UpgradeArgs>),
}

const UPGRADES_MEMORY_ID: MemoryId = MemoryId::new(0);
const ALLOWANCES_MEMORY_ID: MemoryId = MemoryId::new(1);
const ALLOWANCES_EXPIRATIONS_MEMORY_ID: MemoryId = MemoryId::new(2);
const BALANCES_MEMORY_ID: MemoryId = MemoryId::new(3);
const BLOCKS_MEMORY_ID: MemoryId = MemoryId::new(4);

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
        MemoryManager::init(DefaultMemoryImpl::default())
    );

    // The memory where the ledger must write and read its state during an upgrade.
    pub static UPGRADES_MEMORY: RefCell<VirtualMemory<DefaultMemoryImpl>> = MEMORY_MANAGER.with(|memory_manager|
        RefCell::new(memory_manager.borrow().get(UPGRADES_MEMORY_ID)));

    pub static LEDGER_STATE: RefCell<LedgerState> = const { RefCell::new(LedgerState::Ready) };

    // (from, spender) -> allowance - map storing ledger allowances.
    #[allow(clippy::type_complexity)]
    pub static ALLOWANCES_MEMORY: RefCell<StableBTreeMap<AccountSpender, StorableAllowance, VirtualMemory<DefaultMemoryImpl>>> =
        MEMORY_MANAGER.with(|memory_manager| RefCell::new(StableBTreeMap::init(memory_manager.borrow().get(ALLOWANCES_MEMORY_ID))));

    // (timestamp, (from, spender)) - expiration set used for removing expired allowances.
    #[allow(clippy::type_complexity)]
    pub static ALLOWANCES_EXPIRATIONS_MEMORY: RefCell<StableBTreeMap<Expiration, (), VirtualMemory<DefaultMemoryImpl>>> =
        MEMORY_MANAGER.with(|memory_manager| RefCell::new(StableBTreeMap::init(memory_manager.borrow().get(ALLOWANCES_EXPIRATIONS_MEMORY_ID))));

    // account -> tokens - map storing ledger balances.
    pub static BALANCES_MEMORY: RefCell<StableBTreeMap<Account, Tokens, VirtualMemory<DefaultMemoryImpl>>> =
        MEMORY_MANAGER.with(|memory_manager| RefCell::new(StableBTreeMap::init(memory_manager.borrow().get(BALANCES_MEMORY_ID))));

    // block_index -> block
    pub static BLOCKS_MEMORY: RefCell<StableBTreeMap<u64, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>> =
        MEMORY_MANAGER.with(|memory_manager| RefCell::new(StableBTreeMap::init(memory_manager.borrow().get(BLOCKS_MEMORY_ID))));

    static ARCHIVING_FAILURES: Cell<u64> = Cell::default();
}

#[derive(Copy, Clone, Serialize, Deserialize, Debug)]
pub enum LedgerField {
    Allowances,
    AllowancesExpirations,
    Balances,
    Blocks,
}

#[derive(Copy, Clone, Serialize, Deserialize, Debug)]
pub enum LedgerState {
    Migrating(LedgerField),
    Ready,
}

impl Default for LedgerState {
    fn default() -> Self {
        Self::Ready
    }
}

type StableLedgerBalances = Balances<StableBalances>;

#[derive(Debug, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct Ledger {
    balances: LedgerBalances<Tokens>,
    #[serde(default)]
    stable_balances: StableLedgerBalances,
    #[serde(default)]
    approvals: LedgerAllowances<Tokens>,
    #[serde(default)]
    stable_approvals: AllowanceTable<StableAllowancesData>,
    blockchain: Blockchain<CdkRuntime, Icrc1ArchiveWasm, StableBlockDataContainer>,

    minting_account: Account,
    fee_collector: Option<FeeCollector<Account>>,

    transactions_by_hash: BTreeMap<HashOf<Transaction<Tokens>>, BlockIndex>,
    transactions_by_height: VecDeque<TransactionInfo<Transaction<Tokens>>>,
    transfer_fee: Tokens,

    token_symbol: String,
    token_name: String,
    metadata: Vec<(String, StoredValue)>,
    #[serde(default = "default_max_memo_length")]
    max_memo_length: u16,

    #[serde(default = "default_decimals")]
    decimals: u8,

    #[serde(default)]
    feature_flags: FeatureFlags,

    // DEPRECATED
    #[serde(default)]
    maximum_number_of_accounts: usize,
    // DEPRECATED
    #[serde(default)]
    accounts_overflow_trim_quantity: usize,

    #[serde(default)]
    pub ledger_version: u64,

    #[serde(default)]
    index_principal: Option<Principal>,

    #[serde(default = "wasm_token_type")]
    pub token_type: String,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct FeatureFlags {
    pub icrc2: bool,
}

impl FeatureFlags {
    const fn const_default() -> Self {
        Self { icrc2: true }
    }
}

impl Default for FeatureFlags {
    fn default() -> Self {
        Self::const_default()
    }
}

fn default_max_memo_length() -> u16 {
    DEFAULT_MAX_MEMO_LENGTH
}

fn default_decimals() -> u8 {
    ic_ledger_core::tokens::DECIMAL_PLACES as u8
}

pub fn wasm_token_type() -> String {
    Tokens::TYPE.to_string()
}

fn map_metadata_or_trap(arg_metadata: Vec<(String, Value)>) -> Vec<(String, StoredValue)> {
    const DISALLOWED_METADATA_FIELDS: [&str; 7] = [
        METADATA_DECIMALS,
        METADATA_NAME,
        METADATA_SYMBOL,
        METADATA_FEE,
        METADATA_MAX_MEMO_LENGTH,
        METADATA_PUBLIC_ALLOWANCES,
        METADATA_MAX_TAKE_ALLOWANCES,
    ];
    arg_metadata
        .into_iter()
        .map(|(k, v)| {
            if DISALLOWED_METADATA_FIELDS.contains(&k.as_str()) {
                ic_cdk::trap(format!("Metadata field {k} is reserved and cannot be set"));
            }
            (k, StoredValue::from(v))
        })
        .collect()
}

impl Ledger {
    pub fn from_init_args(
        sink: impl Sink + Clone,
        InitArgs {
            minting_account,
            initial_balances,
            transfer_fee,
            token_name,
            token_symbol,
            decimals,
            metadata,
            archive_options,
            fee_collector_account,
            max_memo_length,
            feature_flags,
            index_principal,
        }: InitArgs,
        now: TimeStamp,
    ) -> Self {
        if feature_flags.as_ref().map(|ff| ff.icrc2) == Some(false) {
            log!(
                sink,
                "[ledger] feature flag icrc2 is deprecated and won't disable ICRC-2 anymore"
            );
        }
        let mut ledger = Self {
            balances: LedgerBalances::default(),
            stable_balances: StableLedgerBalances::default(),
            approvals: Default::default(),
            stable_approvals: Default::default(),
            blockchain: Blockchain::new_with_archive(archive_options),
            transactions_by_hash: BTreeMap::new(),
            transactions_by_height: VecDeque::new(),
            minting_account,
            fee_collector: fee_collector_account.map(FeeCollector::from),
            transfer_fee: Tokens::try_from(transfer_fee.clone()).unwrap_or_else(|e| {
                panic!("failed to convert transfer fee {transfer_fee} to tokens: {e}")
            }),
            token_symbol,
            token_name,
            decimals: decimals.unwrap_or_else(default_decimals),
            metadata: map_metadata_or_trap(metadata),
            max_memo_length: max_memo_length.unwrap_or(DEFAULT_MAX_MEMO_LENGTH),
            feature_flags: feature_flags.unwrap_or_default(),
            maximum_number_of_accounts: 0,
            accounts_overflow_trim_quantity: 0,
            ledger_version: LEDGER_VERSION,
            index_principal,
            token_type: wasm_token_type(),
        };

        if ledger.fee_collector.as_ref().map(|fc| fc.fee_collector) == Some(ledger.minting_account)
        {
            ic_cdk::trap("The fee collector account cannot be the same as the minting account");
        }

        for (account, balance) in initial_balances.into_iter() {
            let amount = Tokens::try_from(balance.clone()).unwrap_or_else(|e| {
                panic!("failed to convert initial balance {balance} to tokens: {e}")
            });
            let mint = Transaction::mint(account, amount, Some(now), None);
            apply_transaction(&mut ledger, mint, now, Tokens::ZERO).unwrap_or_else(|err| {
                panic!("failed to mint {balance} tokens to {account}: {err:?}")
            });
        }

        ledger
    }

    pub fn migrate_one_allowance(&mut self) -> bool {
        match self.approvals.allowances_data.pop_first_allowance() {
            Some((account_spender, allowance)) => {
                self.stable_approvals
                    .allowances_data
                    .set_allowance(account_spender, allowance);
                true
            }
            None => false,
        }
    }

    pub fn migrate_one_expiration(&mut self) -> bool {
        match self.approvals.allowances_data.pop_first_expiry() {
            Some((timestamp, account_spender)) => {
                self.stable_approvals
                    .allowances_data
                    .insert_expiry(timestamp, account_spender);
                true
            }
            None => false,
        }
    }

    pub fn migrate_one_balance(&mut self) -> bool {
        match self.balances.store.pop_first() {
            Some((account, tokens)) => {
                self.stable_balances.credit(&account, tokens);
                true
            }
            None => false,
        }
    }

    pub fn migrate_one_block(&mut self) -> bool {
        self.blockchain.migrate_one_block()
    }

    pub fn clear_arrivals(&mut self) {
        self.approvals.allowances_data.clear_arrivals();
    }

    pub fn copy_token_pool(&mut self) {
        self.stable_balances.token_pool = self.balances.token_pool;
    }
}

impl LedgerContext for Ledger {
    type AccountId = Account;
    type AllowancesData = StableAllowancesData;
    type BalancesStore = StableBalances;
    type Tokens = Tokens;

    fn balances(&self) -> &Balances<Self::BalancesStore> {
        panic_if_not_ready();
        &self.stable_balances
    }

    fn balances_mut(&mut self) -> &mut Balances<Self::BalancesStore> {
        panic_if_not_ready();
        &mut self.stable_balances
    }

    fn approvals(&self) -> &AllowanceTable<Self::AllowancesData> {
        panic_if_not_ready();
        &self.stable_approvals
    }

    fn approvals_mut(&mut self) -> &mut AllowanceTable<Self::AllowancesData> {
        panic_if_not_ready();
        &mut self.stable_approvals
    }

    fn fee_collector(&self) -> Option<&FeeCollector<Self::AccountId>> {
        self.fee_collector.as_ref()
    }
}

impl LedgerData for Ledger {
    type Runtime = CdkRuntime;
    type ArchiveWasm = Icrc1ArchiveWasm;
    type Transaction = Transaction<Tokens>;
    type Block = Block<Tokens>;
    type BlockDataContainer = StableBlockDataContainer;

    fn transaction_window(&self) -> Duration {
        TRANSACTION_WINDOW
    }

    fn max_transactions_in_window(&self) -> usize {
        MAX_TRANSACTIONS_IN_WINDOW
    }

    fn max_transactions_to_purge(&self) -> usize {
        MAX_TRANSACTIONS_TO_PURGE
    }

    fn token_name(&self) -> &str {
        &self.token_name
    }

    fn token_symbol(&self) -> &str {
        &self.token_symbol
    }

    fn blockchain(
        &self,
    ) -> &Blockchain<Self::Runtime, Self::ArchiveWasm, Self::BlockDataContainer> {
        &self.blockchain
    }

    fn blockchain_mut(
        &mut self,
    ) -> &mut Blockchain<Self::Runtime, Self::ArchiveWasm, Self::BlockDataContainer> {
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

    fn on_purged_transaction(&mut self, _height: BlockIndex) {}

    fn fee_collector_mut(&mut self) -> Option<&mut FeeCollector<Self::AccountId>> {
        self.fee_collector.as_mut()
    }

    fn increment_archiving_failure_metric(&mut self) {
        ARCHIVING_FAILURES.with(|cell| cell.set(cell.get() + 1));
    }

    fn get_archiving_failure_metric(&self) -> u64 {
        ARCHIVING_FAILURES.get()
    }
}

impl Ledger {
    pub fn minting_account(&self) -> &Account {
        &self.minting_account
    }

    pub fn transfer_fee(&self) -> Tokens {
        self.transfer_fee
    }

    pub fn max_memo_length(&self) -> u16 {
        self.max_memo_length
    }

    pub fn decimals(&self) -> u8 {
        self.decimals
    }

    pub fn index_principal(&self) -> Option<Principal> {
        self.index_principal
    }

    pub fn max_take_allowances(&self) -> u64 {
        MAX_TAKE_ALLOWANCES
    }

    pub fn metadata(&self) -> Vec<(String, Value)> {
        let mut records: Vec<(String, Value)> = self
            .metadata
            .clone()
            .into_iter()
            .map(|(k, v)| (k, StoredValue::into(v)))
            .collect();
        records.push(Value::entry(METADATA_DECIMALS, self.decimals() as u64));
        records.push(Value::entry(METADATA_NAME, self.token_name()));
        records.push(Value::entry(METADATA_SYMBOL, self.token_symbol()));
        records.push(Value::entry(METADATA_FEE, Nat::from(self.transfer_fee())));
        records.push(Value::entry(
            METADATA_MAX_MEMO_LENGTH,
            self.max_memo_length() as u64,
        ));
        records.push(Value::entry(METADATA_PUBLIC_ALLOWANCES, "true"));
        records.push(Value::entry(
            METADATA_MAX_TAKE_ALLOWANCES,
            Nat::from(self.max_take_allowances()),
        ));
        // When adding new entries that cannot be set by the user
        // (e.g. because they are fixed or computed dynamically)
        // please also add them to `map_metadata_or_trap` to prevent
        // the entry being set using init or upgrade arguments.
        if let Some(index_principal) = self.index_principal() {
            records.push(Value::entry(
                "icrc106:index_principal",
                index_principal.to_text(),
            ));
        }
        records
    }

    pub fn feature_flags(&self) -> &FeatureFlags {
        &self.feature_flags
    }

    pub fn upgrade(&mut self, sink: impl Sink + Clone, args: UpgradeArgs) {
        if let Some(upgrade_metadata_args) = args.metadata {
            self.metadata = map_metadata_or_trap(upgrade_metadata_args);
        }
        if let Some(token_name) = args.token_name {
            self.token_name = token_name;
        }
        if let Some(token_symbol) = args.token_symbol {
            self.token_symbol = token_symbol;
        }
        if let Some(transfer_fee) = args.transfer_fee {
            self.transfer_fee = Tokens::try_from(transfer_fee.clone()).unwrap_or_else(|e| {
                ic_cdk::trap(format!(
                    "failed to convert transfer fee {transfer_fee} to tokens: {e}"
                ))
            });
        }
        if let Some(max_memo_length) = args.max_memo_length {
            if self.max_memo_length > max_memo_length {
                ic_cdk::trap(format!(
                    "The max len of the memo can be changed only to be bigger or equal than the current size. Current size: {}",
                    self.max_memo_length
                ));
            }
            self.max_memo_length = max_memo_length;
        }
        if let Some(change_fee_collector) = args.change_fee_collector {
            self.fee_collector = change_fee_collector.into();
            if self.fee_collector.as_ref().map(|fc| fc.fee_collector) == Some(self.minting_account)
            {
                ic_cdk::trap(
                    "The fee collector account cannot be the same account as the minting account",
                );
            }
        }
        if let Some(feature_flags) = args.feature_flags {
            if !feature_flags.icrc2 {
                log!(
                    sink,
                    "[ledger] feature flag icrc2 is deprecated and won't disable ICRC-2 anymore"
                );
            }
            self.feature_flags = feature_flags;
        }
        if let Some(change_archive_options) = args.change_archive_options {
            let mut maybe_archive = self.blockchain.archive.write().expect(
                "BUG: should be unreachable since upgrade has exclusive write access to the ledger",
            );
            if maybe_archive.is_none() {
                ic_cdk::trap(
                    "[ERROR]: Archive options cannot be changed, since there is no archive!",
                );
            }
            if let Some(archive) = maybe_archive.deref_mut() {
                change_archive_options.apply(archive);
            }
        }
        if let Some(index_principal) = args.index_principal {
            self.index_principal = Some(index_principal);
        }
    }

    /// Returns the root hash of the certified ledger state.
    /// The canister code must call set_certified_data with the value this function returns after
    /// each successful modification of the ledger.
    pub fn root_hash(&self) -> [u8; 32] {
        self.construct_hash_tree().digest()
    }

    pub fn construct_hash_tree(&self) -> HashTree {
        match self.blockchain().last_hash {
            Some(last_block_hash) => {
                let last_block_index = self.blockchain().chain_length().checked_sub(1).unwrap();
                let last_block_index_label = Label::from("last_block_index");

                let last_block_hash_label = Label::from("last_block_hash");
                let mut last_block_index_encoded = Vec::with_capacity(MAX_U64_ENCODING_BYTES);
                leb128::write::unsigned(&mut last_block_index_encoded, last_block_index)
                    .expect("Failed to write LEB128");
                fork(
                    label(
                        last_block_hash_label,
                        leaf(last_block_hash.as_slice().to_vec()),
                    ),
                    label(last_block_index_label, leaf(last_block_index_encoded)),
                )
            }
            None => empty(),
        }
    }

    fn query_blocks<ArchiveFn, B>(
        &self,
        start: BlockIndex,
        length: usize,
        decode: impl Fn(&EncodedBlock) -> B,
        make_callback: impl Fn(Principal) -> ArchiveFn,
    ) -> (u64, Vec<B>, Vec<ArchivedRange<ArchiveFn>>) {
        let locations = block_locations(self, start, length);

        let local_blocks_range =
            range_utils::take(&locations.local_blocks, MAX_TRANSACTIONS_PER_REQUEST);

        let local_blocks: Vec<B> = self
            .blockchain
            .get_blocks(local_blocks_range)
            .iter()
            .map(decode)
            .collect();

        let archived_blocks = locations
            .archived_blocks
            .into_iter()
            .map(|(canister_id, slice)| ArchivedRange {
                start: Nat::from(slice.start),
                length: Nat::from(range_utils::range_len(&slice)),
                callback: make_callback(canister_id.get().0),
            })
            .collect();

        (locations.local_blocks.start, local_blocks, archived_blocks)
    }

    /// Returns transactions in the specified range.
    pub fn get_transactions(&self, start: BlockIndex, length: usize) -> GetTransactionsResponse {
        let (first_index, local_transactions, archived_transactions) = self.query_blocks(
            start,
            length,
            |enc_block| -> Tx {
                let decoded_block: Block<Tokens> =
                    Block::decode(enc_block.clone()).expect("bug: failed to decode encoded block");
                decoded_block.into()
            },
            |canister_id| QueryTxArchiveFn::new(canister_id, "get_transactions"),
        );

        GetTransactionsResponse {
            first_index: Nat::from(first_index),
            log_length: Nat::from(self.blockchain.chain_length()),
            transactions: local_transactions,
            archived_transactions,
        }
    }

    /// Returns blocks in the specified range.
    pub fn get_blocks(&self, start: BlockIndex, length: usize) -> GetBlocksResponse {
        let (first_index, local_blocks, archived_blocks) = self.query_blocks(
            start,
            length,
            encoded_block_to_generic_block,
            |canister_id| QueryBlockArchiveFn::new(canister_id, "get_blocks"),
        );

        GetBlocksResponse {
            first_index: Nat::from(first_index),
            chain_length: self.blockchain.chain_length(),
            certificate: ic_cdk::api::data_certificate().map(serde_bytes::ByteBuf::from),
            blocks: local_blocks,
            archived_blocks,
        }
    }

    pub fn icrc3_get_archives(&self, args: GetArchivesArgs) -> GetArchivesResult {
        self.blockchain()
            .archive
            .read()
            .expect("Unable to access the archives")
            .iter()
            .flat_map(|archive| {
                archive
                    .index()
                    .into_iter()
                    .filter_map(|((start, end), canister_id)| {
                        let canister_id = Principal::from(canister_id);
                        if let Some(from) = args.from
                            && canister_id <= from
                        {
                            return None;
                        }
                        Some(ICRC3ArchiveInfo {
                            canister_id,
                            start: Nat::from(start),
                            end: Nat::from(end),
                        })
                    })
            })
            .collect()
    }

    // TODO(FI-1268): extend MAX_BLOCKS_PER_RESPONSE to include archives
    pub fn icrc3_get_blocks(&self, args: Vec<GetBlocksRequest>) -> GetBlocksResult {
        const MAX_BLOCKS_PER_RESPONSE: u64 = 100;

        let mut blocks = vec![];
        let mut archived_blocks_by_callback = BTreeMap::new();
        for arg in args {
            let (start, length) = arg
                .as_start_and_length()
                .unwrap_or_else(|msg| ic_cdk::api::trap(&msg));
            let max_length = MAX_BLOCKS_PER_RESPONSE.saturating_sub(blocks.len() as u64);
            if max_length == 0 {
                break;
            }
            let length = max_length.min(length).min(usize::MAX as u64) as usize;
            let (first_index, local_blocks, archived_ranges) = self.query_blocks(
                start,
                length,
                |block| ICRC3Value::from(encoded_block_to_generic_block(block)),
                |canister_id| {
                    QueryArchiveFn::<Vec<GetBlocksRequest>, GetBlocksResult>::new(
                        canister_id,
                        "icrc3_get_blocks",
                    )
                },
            );
            for (id, block) in (first_index..).zip(local_blocks) {
                blocks.push(icrc_ledger_types::icrc3::blocks::BlockWithId {
                    id: Nat::from(id),
                    block,
                });
            }
            for ArchivedRange {
                start,
                length,
                callback,
            } in archived_ranges
            {
                let request = GetBlocksRequest { start, length };
                archived_blocks_by_callback
                    .entry(callback)
                    .or_insert(vec![])
                    .push(request);
            }
            if blocks.len() as u64 >= MAX_BLOCKS_PER_RESPONSE {
                break;
            }
        }
        let mut archived_blocks = vec![];
        for (callback, args) in archived_blocks_by_callback {
            archived_blocks.push(ArchivedBlocks { args, callback });
        }
        GetBlocksResult {
            log_length: Nat::from(self.blockchain.chain_length()),
            blocks,
            archived_blocks,
        }
    }
}

pub fn is_ready() -> bool {
    LEDGER_STATE.with(|s| matches!(*s.borrow(), LedgerState::Ready))
}

pub fn panic_if_not_ready() {
    if !is_ready() {
        ic_cdk::trap("The Ledger is not ready");
    }
}

pub fn ledger_state() -> LedgerState {
    LEDGER_STATE.with(|s| *s.borrow())
}

pub fn set_ledger_state(ledger_state: LedgerState) {
    LEDGER_STATE.with(|s| *s.borrow_mut() = ledger_state);
}

pub fn clear_stable_allowance_data() {
    ALLOWANCES_MEMORY.with_borrow_mut(|allowances| {
        allowances.clear_new();
    });
    ALLOWANCES_EXPIRATIONS_MEMORY.with_borrow_mut(|expirations| {
        expirations.clear_new();
    });
}

pub fn clear_stable_balances_data() {
    BALANCES_MEMORY.with_borrow_mut(|balances| {
        balances.clear_new();
    });
}

pub fn clear_stable_blocks_data() {
    BLOCKS_MEMORY.with_borrow_mut(|blocks| {
        blocks.clear_new();
    });
}

pub fn balances_len() -> u64 {
    BALANCES_MEMORY.with_borrow(|balances| balances.len())
}

pub fn read_first_balance() {
    BALANCES_MEMORY.with_borrow(|balances| balances.first_key_value());
}

pub fn get_allowances(
    from: Account,
    spender: Option<Account>,
    max_results: u64,
    now: u64,
) -> Allowances {
    let mut result = vec![];
    let start_account_spender = match spender {
        Some(spender) => AccountSpender {
            account: from,
            spender,
        },
        None => AccountSpender {
            account: from,
            spender: Account {
                owner: Principal::from_slice(&[0u8; 0]),
                subaccount: None,
            },
        },
    };
    ALLOWANCES_MEMORY.with_borrow(|allowances| {
        for (account_spender, storable_allowance) in
            allowances.range(start_account_spender.clone()..)
        {
            if spender.is_some() && account_spender == start_account_spender {
                continue;
            }
            if result.len() >= max_results as usize {
                break;
            }
            if account_spender.account.owner != from.owner {
                break;
            }
            if let Some(expires_at) = storable_allowance.expires_at
                && expires_at.as_nanos_since_unix_epoch() <= now
            {
                continue;
            }
            result.push(Allowance103 {
                from_account: account_spender.account,
                to_spender: account_spender.spender,
                allowance: Nat::from(storable_allowance.amount),
                expires_at: storable_allowance
                    .expires_at
                    .map(|t| t.as_nanos_since_unix_epoch()),
            });
        }
    });
    result
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct StableAllowancesData {}

impl AllowancesData for StableAllowancesData {
    type AccountId = Account;
    type Tokens = Tokens;

    fn get_allowance(
        &self,
        account_spender: &(Self::AccountId, Self::AccountId),
    ) -> Option<Allowance<Self::Tokens>> {
        let account_spender = account_spender.into();
        ALLOWANCES_MEMORY
            .with_borrow(|allowances| allowances.get(&account_spender))
            .map(|a| a.into())
    }

    fn set_allowance(
        &mut self,
        account_spender: (Self::AccountId, Self::AccountId),
        allowance: Allowance<Self::Tokens>,
    ) {
        let account_spender = (&account_spender).into();
        ALLOWANCES_MEMORY
            .with_borrow_mut(|allowances| allowances.insert(account_spender, allowance.into()));
    }

    fn remove_allowance(&mut self, account_spender: &(Self::AccountId, Self::AccountId)) {
        let account_spender = account_spender.into();
        ALLOWANCES_MEMORY.with_borrow_mut(|allowances| allowances.remove(&account_spender));
    }

    fn insert_expiry(
        &mut self,
        timestamp: TimeStamp,
        account_spender: (Self::AccountId, Self::AccountId),
    ) {
        let account_spender = (&account_spender).into();
        let expiration = Expiration {
            timestamp,
            account_spender,
        };
        ALLOWANCES_EXPIRATIONS_MEMORY.with_borrow_mut(|expirations| {
            expirations.insert(expiration, ());
        });
    }

    fn remove_expiry(
        &mut self,
        timestamp: TimeStamp,
        account_spender: (Self::AccountId, Self::AccountId),
    ) {
        let account_spender = (&account_spender).into();
        let expiration = Expiration {
            timestamp,
            account_spender,
        };
        ALLOWANCES_EXPIRATIONS_MEMORY.with_borrow_mut(|expirations| {
            expirations.remove(&expiration);
        });
    }

    fn first_expiry(&self) -> Option<(TimeStamp, (Self::AccountId, Self::AccountId))> {
        let result = ALLOWANCES_EXPIRATIONS_MEMORY
            .with_borrow(|expirations| expirations.first_key_value().map(|kv| kv.0));
        result.map(|e| (e.timestamp, e.account_spender.into()))
    }

    fn pop_first_expiry(&mut self) -> Option<(TimeStamp, (Self::AccountId, Self::AccountId))> {
        let result = ALLOWANCES_EXPIRATIONS_MEMORY
            .with_borrow_mut(|expirations| expirations.pop_first().map(|kv| kv.0));
        result.map(|e| (e.timestamp, e.account_spender.into()))
    }

    fn pop_first_allowance(
        &mut self,
    ) -> Option<((Self::AccountId, Self::AccountId), Allowance<Self::Tokens>)> {
        panic!("The method `pop_first_allowance` should not be called for StableAllowancesData")
    }

    fn len_allowances(&self) -> usize {
        ALLOWANCES_MEMORY
            .with_borrow(|allowances| allowances.len())
            .try_into()
            .unwrap()
    }

    fn len_expirations(&self) -> usize {
        ALLOWANCES_EXPIRATIONS_MEMORY
            .with_borrow(|expirations| expirations.len())
            .try_into()
            .unwrap()
    }

    fn clear_arrivals(&mut self) {
        panic!("The method `clear_arrivals` should not be called for StableAllowancesData")
    }
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct StableBalances {}

impl BalancesStore for StableBalances {
    type AccountId = Account;
    type Tokens = Tokens;

    fn get_balance(&self, k: &Account) -> Option<Tokens> {
        BALANCES_MEMORY.with_borrow(|balances| balances.get(k))
    }

    fn update<F, E>(&mut self, k: Account, mut f: F) -> Result<Tokens, E>
    where
        F: FnMut(Option<&Tokens>) -> Result<Tokens, E>,
    {
        let entry = BALANCES_MEMORY.with_borrow(|balances| balances.get(&k));
        match entry {
            Some(v) => {
                let new_v = f(Some(&v))?;
                if new_v != Tokens::ZERO {
                    BALANCES_MEMORY.with_borrow_mut(|balances| balances.insert(k, new_v));
                } else {
                    BALANCES_MEMORY.with_borrow_mut(|balances| balances.remove(&k));
                }
                Ok(new_v)
            }
            None => {
                let new_v = f(None)?;
                if new_v != Tokens::ZERO {
                    BALANCES_MEMORY.with_borrow_mut(|balances| balances.insert(k, new_v));
                }
                Ok(new_v)
            }
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct StableBlockDataContainer {}

impl BlockDataContainer for StableBlockDataContainer {
    fn with_blocks<R>(
        f: impl FnOnce(&StableBTreeMap<u64, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>) -> R,
    ) -> R {
        BLOCKS_MEMORY.with(|cell| f(&cell.borrow()))
    }

    fn with_blocks_mut<R>(
        f: impl FnOnce(&mut StableBTreeMap<u64, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>) -> R,
    ) -> R {
        BLOCKS_MEMORY.with(|cell| f(&mut cell.borrow_mut()))
    }
}
