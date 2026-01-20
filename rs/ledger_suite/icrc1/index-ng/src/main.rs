#![allow(deprecated)]
use candid::{CandidType, Decode, Encode, Nat, Principal};
use ic_canister_log::{export as export_logs, log};
use ic_canister_profiler::{SpanName, SpanStats, measure_span};
use ic_cdk::trap;
use ic_cdk::{init, post_upgrade, query};
use ic_cdk_timers::TimerId;
use ic_crypto_sha2::Sha256;
use ic_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_icrc1::blocks::{encoded_block_to_generic_block, generic_block_to_encoded_block};
use ic_icrc1::endpoints::StandardRecord;
use ic_icrc1::{Block, Operation};
use ic_icrc1_index_ng::{
    DEFAULT_MAX_BLOCKS_PER_RESPONSE, FeeCollectorRanges, GetAccountTransactionsArgs,
    GetAccountTransactionsResponse, GetAccountTransactionsResult, GetBlocksMethod, IndexArg,
    InitArg, ListSubaccountsArgs, Log, LogEntry, Status, TransactionWithId, UpgradeArg,
};
use ic_ledger_canister_core::runtime::heap_memory_size_bytes;
use ic_ledger_core::block::{BlockIndex as BlockIndex64, BlockType, EncodedBlock};
use ic_ledger_core::tokens::{CheckedAdd, CheckedSub, Zero};
use ic_stable_structures::memory_manager::{MemoryId, VirtualMemory};
use ic_stable_structures::storable::{Blob, Bound};
use ic_stable_structures::{
    DefaultMemoryImpl, StableBTreeMap, StableCell, StableLog, Storable,
    memory_manager::MemoryManager,
};
use icrc_ledger_types::icrc::generic_value::Value;
use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use icrc_ledger_types::icrc3::archive::{ArchivedRange, QueryBlockArchiveFn};
use icrc_ledger_types::icrc3::blocks::{
    ArchivedBlocks, BlockRange, BlockWithId, GenericBlock, GetBlocksRequest, GetBlocksResponse,
    GetBlocksResult,
};
use icrc_ledger_types::icrc3::transactions::Transaction;
use num_traits::ToPrimitive;
use scopeguard::guard;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::cell::RefCell;
use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap};
use std::convert::TryFrom;
use std::fmt::Debug;
use std::hash::Hash;
use std::io::Read;
use std::ops::Bound::{Excluded, Included};
use std::ops::Range;
use std::time::Duration;

pub mod logs;

use crate::logs::{P0, P1};

const STATE_MEMORY_ID: MemoryId = MemoryId::new(0);
const BLOCK_LOG_INDEX_MEMORY_ID: MemoryId = MemoryId::new(1);
const BLOCK_LOG_DATA_MEMORY_ID: MemoryId = MemoryId::new(2);
const ACCOUNT_BLOCK_IDS_MEMORY_ID: MemoryId = MemoryId::new(3);
const ACCOUNT_DATA_MEMORY_ID: MemoryId = MemoryId::new(4);

const DEFAULT_RETRIEVE_BLOCKS_FROM_LEDGER_INTERVAL: Duration = Duration::from_secs(1);

#[cfg(not(feature = "u256-tokens"))]
type Tokens = ic_icrc1_tokens_u64::U64;

#[cfg(feature = "u256-tokens")]
type Tokens = ic_icrc1_tokens_u256::U256;

type VM = VirtualMemory<DefaultMemoryImpl>;
type StateCell = StableCell<State, VM>;
type BlockLog = StableLog<Vec<u8>, VM, VM>;
// The block indexes are stored in reverse order because the blocks/transactions
// are returned in reversed order.
type AccountBlockIdsMapKey = ([u8; Sha256::DIGEST_LEN], Reverse<u64>);
type AccountBlockIdsMap = StableBTreeMap<AccountBlockIdsMapKey, (), VM>;

// The second element of this tuple is the account represented
// as principal of type Blob<29> and the effective subaccount
type AccountDataMapKey = (AccountDataType, (Blob<29>, [u8; 32]));
type AccountDataMap = StableBTreeMap<AccountDataMapKey, Tokens, VM>;

thread_local! {
    /// Static memory manager to manage the memory available for stable structures.
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    /// Scalar state of the index.
    static STATE: RefCell<StateCell> = with_memory_manager(|memory_manager| {
        RefCell::new(StateCell::init(memory_manager.get(STATE_MEMORY_ID), State::default())
            .expect("failed to initialize stable cell"))
    });

    /// Append-only list of encoded blocks stored in stable memory.
    static BLOCKS: RefCell<BlockLog> = with_memory_manager(|memory_manager| {
        RefCell::new(BlockLog::init(memory_manager.get(BLOCK_LOG_INDEX_MEMORY_ID), memory_manager.get(BLOCK_LOG_DATA_MEMORY_ID))
            .expect("failed to initialize stable log"))
    });

    /// Map that contains the block ids of an account.
    /// The account is hashed to save space.
    static ACCOUNT_BLOCK_IDS: RefCell<AccountBlockIdsMap> = with_memory_manager(|memory_manager| {
        RefCell::new(AccountBlockIdsMap::init(memory_manager.get(ACCOUNT_BLOCK_IDS_MEMORY_ID)))
    });

    /// Map that contains account aggregated data.
    static ACCOUNT_DATA: RefCell<AccountDataMap> = with_memory_manager(|memory_manager| {
        RefCell::new(AccountDataMap::init(memory_manager.get(ACCOUNT_DATA_MEMORY_ID)))
    });

    /// Profiling data to understand cycles usage
    static PROFILING_DATA: RefCell<SpanStats> = RefCell::new(SpanStats::default());

    /// Cache of the canister, i.e. ephemeral data that doesn't need to be
    /// persistent between upgrades
    static CACHE: RefCell<Cache> = RefCell::new(Cache::default());

    /// The ID of the block sync timer.
    static TIMER_ID: RefCell<TimerId> = RefCell::new(TimerId::default());
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct State {
    /// Equals to `true` while the [build_index] task runs.
    is_build_index_running: bool,

    /// The principal of the ledger canister that is indexed by this index.
    ledger_id: Principal,

    /// The maximum number of transactions returned by [get_blocks].
    max_blocks_per_response: u64,

    /// Last wait time in nanoseconds.
    pub last_wait_time: Duration,

    /// The fees collectors with the ranges of blocks for which they collected the fee.
    fee_collectors: HashMap<Account, Vec<Range<BlockIndex64>>>,

    /// This fee is used if no fee nor effetive_fee is found in Approve blocks.
    pub last_fee: Option<Tokens>,

    /// The interval for retrieving blocks from the ledger and archive(s) for (re)building the
    /// index. Lower values will result in a more responsive UI, but higher costs due to increased
    /// cycle burn for the index, ledger and archive(s).
    retrieve_blocks_from_ledger_interval: Option<Duration>,

    /// The ICRC-107 fee collector. Example values:
    /// - `None` - legacy fee collector is used.
    /// - `Some(None)` - 107 fee collector is enabled but fees are burned.
    /// - `Some(Some(account1))` - 107 fee collector is enabled, `account1` collects the fees.
    fee_collector_107: Option<Option<Account>>,
}

impl State {
    pub fn retrieve_blocks_from_ledger_interval(&self) -> Duration {
        self.retrieve_blocks_from_ledger_interval
            .unwrap_or(DEFAULT_RETRIEVE_BLOCKS_FROM_LEDGER_INTERVAL)
    }
}

// NOTE: the default configuration is dysfunctional, but it's convenient to have
// a Default impl for the initialization of the [STATE] variable above.
impl Default for State {
    fn default() -> Self {
        Self {
            is_build_index_running: false,
            ledger_id: Principal::management_canister(),
            max_blocks_per_response: DEFAULT_MAX_BLOCKS_PER_RESPONSE,
            last_wait_time: Duration::from_secs(0),
            fee_collectors: Default::default(),
            last_fee: None,
            retrieve_blocks_from_ledger_interval: None,
            fee_collector_107: None,
        }
    }
}

impl Storable for State {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut buf = vec![];
        ciborium::ser::into_writer(self, &mut buf).expect("failed to encode index config");
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        ciborium::de::from_reader(&bytes[..]).expect("failed to decode index options")
    }

    const BOUND: Bound = Bound::Unbounded;
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Default, Deserialize, Serialize)]
enum AccountDataType {
    #[default]
    Balance = 0,
}

impl Storable for AccountDataType {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        match self {
            Self::Balance => Cow::Borrowed(&[0x00]),
        }
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        if bytes.len() != 1 {
            panic!(
                "Expected a single byte for AccountDataType but found {}",
                bytes.len()
            );
        }
        if bytes[0] == 0x00 {
            Self::Balance
        } else {
            panic!("Unknown AccountDataType {}", bytes[0]);
        }
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 1,
        is_fixed_size: true,
    };
}

// Ephemeral data that doesn't need to be saved between upgrades
#[derive(Clone, Debug, Default)]
struct Cache {
    pub get_blocks_method: Option<GetBlocksMethod>,
}

struct SyncError {
    message: String,
    retriable: bool,
}

#[test]
fn test_account_data_type_storable() {
    assert_eq!(
        AccountDataType::Balance,
        AccountDataType::from_bytes(AccountDataType::Balance.to_bytes())
    );
}

/// A helper function to access the scalar state.
fn with_state<R>(f: impl FnOnce(&State) -> R) -> R {
    STATE.with(|cell| f(cell.borrow().get()))
}

/// A helper function to change the scalar state.
fn mutate_state(f: impl FnOnce(&mut State)) {
    STATE
        .with(|cell| {
            let mut borrowed = cell.borrow_mut();
            let mut state = borrowed.get().clone();
            f(&mut state);
            borrowed.set(state)
        })
        .expect("failed to set index state");
}

/// A helper function to access the memory manager.
fn with_memory_manager<R>(f: impl FnOnce(&MemoryManager<DefaultMemoryImpl>) -> R) -> R {
    MEMORY_MANAGER.with(|cell| f(&cell.borrow()))
}

/// A helper function to access the block list.
fn with_blocks<R>(f: impl FnOnce(&BlockLog) -> R) -> R {
    BLOCKS.with(|cell| f(&cell.borrow()))
}

/// A helper function to access the account block ids.
fn with_account_block_ids<R>(f: impl FnOnce(&mut AccountBlockIdsMap) -> R) -> R {
    ACCOUNT_BLOCK_IDS.with(|cell| f(&mut cell.borrow_mut()))
}

/// A helper function to access the account data.
fn with_account_data<R>(f: impl FnOnce(&mut AccountDataMap) -> R) -> R {
    ACCOUNT_DATA.with(|cell| f(&mut cell.borrow_mut()))
}

/// A helper function that returns a decoded block stored in the
/// block log at the given index or None if there is no block at that index.
/// This function can trap if the index at the given block cannot be decoded
/// because all blocks stored in the transaction log should be decodable
/// (see [append_blocks]). If not then something is wrong with the log.
fn get_decoded_block(block_index: BlockIndex64) -> Option<Block<Tokens>> {
    with_blocks(|blocks| blocks.get(block_index))
        .map(EncodedBlock::from)
        .map(|block| decode_encoded_block_or_trap(block_index, block))
}

/// A helper function to access the balance of an account.
fn get_balance(account: Account) -> Tokens {
    with_account_data(|account_data| {
        account_data
            .get(&balance_key(account))
            .unwrap_or_else(Tokens::zero)
    })
}

/// A helper function to change the balance of an account.
fn change_balance(account: Account, f: impl FnOnce(Tokens) -> Tokens) {
    let key = balance_key(account);
    let new_balance = f(get_balance(account));
    with_account_data(|account_data| account_data.insert(key, new_balance));
}

fn balance_key(account: Account) -> (AccountDataType, (Blob<29>, [u8; 32])) {
    let owner = Blob::try_from(account.owner.as_slice()).unwrap();
    (
        AccountDataType::Balance,
        (owner, *account.effective_subaccount()),
    )
}

#[init]
fn init(index_arg: Option<IndexArg>) {
    let InitArg {
        ledger_id,
        retrieve_blocks_from_ledger_interval_seconds,
    } = match index_arg {
        Some(IndexArg::Init(arg)) => arg,
        _ => trap("Index initialization must take in input an InitArg argument"),
    };

    // stable memory initialization
    mutate_state(|state| {
        state.ledger_id = ledger_id;
        state.retrieve_blocks_from_ledger_interval =
            retrieve_blocks_from_ledger_interval_seconds.map(Duration::from_secs);
    });

    // set the first build_index to be called after init
    set_build_index_timer(with_state(|state| {
        state.retrieve_blocks_from_ledger_interval()
    }));
}

// The part of the legacy index (//rs/ledger_suite/icrc1/index) state
// that reads the ledger_id. This struct is used to deserialize
// the state of the legacy index during post_upgrade in case
// the upgrade is from the legacy index to the index-ng.
#[derive(Debug, Deserialize, Serialize)]
struct LegacyIndexState {
    pub ledger_id: ic_base_types::CanisterId,
}

const MAX_LEGACY_STATE_BYTES: u64 = 100_000_000;

#[post_upgrade]
fn post_upgrade(index_arg: Option<IndexArg>) {
    // Attempts to read the ledger_id using the legacy index
    // storage scheme. This trick allows SNSes to update the legacy
    // index to index-ng.
    if let Ok(old_state) = ciborium::de::from_reader::<LegacyIndexState, _>(
        ic_cdk::api::stable::StableReader::default().take(MAX_LEGACY_STATE_BYTES),
    ) {
        log!(
            P1,
            "Found the state of the old index. ledger-id: {}",
            old_state.ledger_id
        );
        mutate_state(|state| {
            state.ledger_id = old_state.ledger_id.into();
        })
    }

    match index_arg {
        Some(IndexArg::Upgrade(upgrade)) => {
            log!(P1, "Possible upgrade configuration changes: {:#?}", upgrade,);

            let UpgradeArg {
                ledger_id,
                retrieve_blocks_from_ledger_interval_seconds,
            } = upgrade;

            mutate_state(|state| {
                if let Some(new_value) = ledger_id {
                    state.ledger_id = new_value;
                }

                if let Some(new_value) = retrieve_blocks_from_ledger_interval_seconds {
                    state.retrieve_blocks_from_ledger_interval =
                        Some(Duration::from_secs(new_value));
                }
            });
        }
        Some(IndexArg::Init(..)) => trap("Index upgrade argument cannot be of variant Init"),
        _ => (),
    };

    with_account_data(|account_data| {
        // Try to read the first key-value from the account data map. This will fail (and the
        // canister will trap, i.e., the upgrade will fail) if:
        // - the map is non-empty, i.e., there is at least one balance
        // - the token type of the account data map does not match the one of this wasm, e.g.,
        //   if the balances are stored using `u256` tokens and this wasm uses `u64` tokens, or
        //   vice versa.
        let _maybe_first_key_value = account_data.first_key_value();
    });

    // set the first build_index to be called after init
    set_build_index_timer(with_state(|state| {
        state.retrieve_blocks_from_ledger_interval()
    }));
}

async fn get_supported_standards_from_ledger() -> Vec<String> {
    let ledger_id = with_state(|state| state.ledger_id);
    log!(
        P1,
        "[get_supported_standards_from_ledger]: making the call..."
    );
    let res = ic_cdk::api::call::call::<_, (Vec<StandardRecord>,)>(
        ledger_id,
        "icrc1_supported_standards",
        (),
    )
    .await;
    match res {
        Ok((res,)) => {
            let supported_standard_names = res.into_iter().map(|s| s.name).collect::<Vec<_>>();
            log!(
                P1,
                "[get_supported_standards_from_ledger]: ledger {} supports {:?}",
                ledger_id,
                supported_standard_names,
            );
            supported_standard_names
        }
        Err((code, msg)) => {
            // log the error but do not propagate it
            log!(
                P0,
                "[get_supported_standards_from_ledger]: failed to call get_supported_standards_from_ledger on ledger {}. Error code: {:?} message: {}",
                ledger_id,
                code,
                msg
            );
            vec![]
        }
    }
}

async fn measured_call<I, O>(
    encode_span_name: SpanName,
    decode_span_name: SpanName,
    id: Principal,
    method: &str,
    i: &I,
) -> Result<O, String>
where
    I: CandidType + Debug,
    O: CandidType + Debug + for<'a> Deserialize<'a>,
{
    let req = measure_span(&PROFILING_DATA, encode_span_name, || Encode!(i))
        .map_err(|err| format!("failed to candid encode the input {i:?}: {err}"))?;
    let res = ic_cdk::api::call::call_raw(id, method, &req, 0)
        .await
        .map_err(|(code, str)| format!("code: {code:#?} message: {str}"))?;
    measure_span(&PROFILING_DATA, decode_span_name, || Decode!(&res, O))
        .map_err(|err| format!("failed to candid decode the output: {err}"))
}

async fn get_blocks_from_ledger(start: u64) -> Result<GetBlocksResponse, SyncError> {
    let (ledger_id, length) = with_state(|state| (state.ledger_id, state.max_blocks_per_response));
    let req = GetBlocksRequest {
        start: Nat::from(start),
        length: Nat::from(length),
    };
    log!(P1, "[get_blocks_from_ledger]: making the call...");
    let res = measured_call(
        "build_index.get_blocks_from_ledger.encode",
        "build_index.get_blocks_from_ledger.decode",
        ledger_id,
        "get_blocks",
        &req,
    )
    .await;
    match res {
        Ok(res) => Ok(res),
        Err(err) => {
            let message = format!("[get_blocks_from_ledger] failed to get blocks: {}", err);
            Err(SyncError {
                message,
                retriable: true,
            })
        }
    }
}

async fn get_blocks_from_archive(
    archived: &ArchivedRange<QueryBlockArchiveFn>,
) -> Result<BlockRange, SyncError> {
    let req = GetBlocksRequest {
        start: archived.start.clone(),
        length: archived.length.clone(),
    };
    let res = measured_call(
        "build_index.get_blocks_from_archive.encode",
        "build_index.get_blocks_from_archive.decode",
        archived.callback.canister_id,
        &archived.callback.method,
        &req,
    )
    .await;
    match res {
        Ok(res) => Ok(res),
        Err(err) => {
            let message = format!("[get_blocks_from_archive] failed to get blocks: {}", err);
            Err(SyncError {
                message,
                retriable: true,
            })
        }
    }
}

async fn icrc3_get_blocks_from_ledger(start: u64) -> Result<GetBlocksResult, SyncError> {
    let (ledger_id, length) = with_state(|state| (state.ledger_id, state.max_blocks_per_response));
    let req = vec![GetBlocksRequest {
        start: Nat::from(start),
        length: Nat::from(length),
    }];
    log!(P1, "[icrc3_get_blocks_from_ledger]: making the call...");
    let res = measured_call(
        "build_index.icrc3_get_blocks_from_ledger.encode",
        "build_index.icrc3_get_blocks_from_ledger.decode",
        ledger_id,
        "icrc3_get_blocks",
        &req,
    )
    .await;
    match res {
        Ok(res) => Ok(res),
        Err(err) => {
            let message = format!(
                "[icrc3_get_blocks_from_ledger] failed to get blocks: {}",
                err
            );
            Err(SyncError {
                message,
                retriable: true,
            })
        }
    }
}

async fn icrc3_get_blocks_from_archive(
    archived: &ArchivedBlocks,
) -> Result<GetBlocksResult, SyncError> {
    let res = measured_call(
        "build_index.icrc3_get_blocks_from_archive.encode",
        "build_index.icrc3_get_blocks_from_archive.decode",
        archived.callback.canister_id,
        &archived.callback.method,
        &archived.args,
    )
    .await;
    match res {
        Ok(res) => Ok(res),
        Err(err) => {
            let message = format!(
                "[icrc3_get_blocks_from_archive] failed to get blocks: {}",
                err
            );
            Err(SyncError {
                message,
                retriable: true,
            })
        }
    }
}

async fn find_get_blocks_method() -> GetBlocksMethod {
    if let Some(get_blocks_method) = CACHE.with(|cache| cache.borrow().get_blocks_method) {
        return get_blocks_method;
    }
    let standards = get_supported_standards_from_ledger().await;
    let get_blocks_method = if standards.into_iter().any(|standard| standard == "ICRC-3") {
        GetBlocksMethod::ICRC3GetBlocks
    } else {
        GetBlocksMethod::GetBlocks
    };
    CACHE.with(|cache| cache.borrow_mut().get_blocks_method = Some(get_blocks_method));
    get_blocks_method
}

pub async fn build_index() -> Option<()> {
    if with_state(|state| state.is_build_index_running) {
        return None;
    }
    mutate_state(|state| {
        state.is_build_index_running = true;
    });
    let _reset_is_build_index_running_flag_guard = guard((), |_| {
        mutate_state(|state| {
            state.is_build_index_running = false;
        });
    });
    let num_indexed = match find_get_blocks_method().await {
        GetBlocksMethod::GetBlocks => fetch_blocks_via_get_blocks().await,
        GetBlocksMethod::ICRC3GetBlocks => fetch_blocks_via_icrc3().await,
    };
    match num_indexed {
        Ok(num_indexed) => {
            let retrieve_blocks_from_ledger_interval =
                with_state(|state| state.retrieve_blocks_from_ledger_interval());
            log!(
                P1,
                "Indexed: {} waiting : {:?}",
                num_indexed,
                retrieve_blocks_from_ledger_interval
            );
        }
        Err(error) => {
            log!(P0, "{}", error.message);
            ic_cdk::eprintln!("{}", error.message);
            if !error.retriable {
                log!(P0, "Stopping the indexing timer.");
                ic_cdk::eprintln!("Stopping the indexing timer.");
                let timer_id = TIMER_ID.with(|tid| *tid.borrow());
                ic_cdk_timers::clear_timer(timer_id);
            }
        }
    };

    Some(())
}

async fn fetch_blocks_via_get_blocks() -> Result<u64, SyncError> {
    let mut num_indexed = 0;
    let next_id = with_blocks(|blocks| blocks.len());
    let res = get_blocks_from_ledger(next_id).await?;
    for archived in res.archived_blocks {
        let mut remaining = archived.length.clone();
        let mut next_archived_txid = archived.start.clone();
        while remaining > 0u32 {
            let archived = ArchivedRange::<QueryBlockArchiveFn> {
                start: next_archived_txid.clone(),
                length: remaining.clone(),
                callback: archived.callback.clone(),
            };
            let res = get_blocks_from_archive(&archived).await?;
            next_archived_txid += res.blocks.len();
            num_indexed += res.blocks.len();
            remaining -= res.blocks.len();
            append_blocks(res.blocks)?;
        }
    }
    num_indexed += res.blocks.len();
    append_blocks(res.blocks)?;
    Ok(num_indexed as u64)
}

async fn fetch_blocks_via_icrc3() -> Result<u64, SyncError> {
    // The current number of blocks is also the id of the next
    // block to query from the Ledger.
    let previous_num_blocks = with_blocks(|blocks| blocks.len());
    let res = icrc3_get_blocks_from_ledger(previous_num_blocks).await?;

    // The Ledger should return archives in order but there is
    // no guarantee of this. In order to avoid issues we sort
    // and rearrange the archived_blocks.
    let mut archived_blocks = BTreeMap::new();
    for ArchivedBlocks { args, callback } in res.archived_blocks {
        for arg in args {
            archived_blocks.insert(arg, callback.clone());
        }
    }

    for (mut arg, callback) in archived_blocks.into_iter() {
        // The archive can return less than arg.length blocks.
        // The client canister must make sure to call icrc3_get_blocks
        // until all blocks in `arg` have been retrieved.
        while arg.length != 0u64 {
            // sanity check that the next index to fetch is the correct
            // one, i.e. next_id + num_indexed
            let expected_id = with_blocks(|blocks| blocks.len());
            if arg.start != expected_id {
                let error = format!(
                    "[fetch_blocks_via_icrc3]: wrong start index in archive args. Expected: {} actual: {}",
                    expected_id, arg.start,
                );
                return Err(SyncError {
                    message: error,
                    retriable: false,
                });
            }

            let archived = ArchivedBlocks {
                args: vec![arg.clone()],
                callback: callback.clone(),
            };
            let res = icrc3_get_blocks_from_archive(&archived).await?;

            // sanity check: the index does not support nested archives
            if !res.archived_blocks.is_empty() {
                let error = format!(
                    "[fetch_blocks_via_icrc3]: The archive callback {:?} with arg {:?} returned one or more archived blocks and the index is currently not supporting nested archived blocks. Archived blocks returned are {:?}",
                    callback.clone(),
                    arg.clone(),
                    res.archived_blocks,
                );
                return Err(SyncError {
                    message: error,
                    retriable: false,
                });
            }

            // change `arg` for the next iteration
            arg.start += res.blocks.len();
            arg.length -= res.blocks.len();

            append_icrc3_blocks(res.blocks)?;
        }
    }

    append_icrc3_blocks(res.blocks)?;
    let num_blocks = with_blocks(|blocks| blocks.len());
    match num_blocks.checked_sub(previous_num_blocks) {
        None => panic!(
            "The number of blocks {} is smaller than the number of blocks before indexing {}. This is impossible. I'm trapping to reset the state",
            num_blocks, previous_num_blocks
        ),
        Some(new_blocks_indexed) => Ok(new_blocks_indexed),
    }
}

fn set_build_index_timer(after: Duration) {
    let timer_id = ic_cdk_timers::set_timer_interval(after, async || {
        let _ = build_index().await;
    });
    TIMER_ID.with(|tid| *tid.borrow_mut() = timer_id);
}

fn append_block(block_index: BlockIndex64, block: GenericBlock) -> Result<(), SyncError> {
    measure_span(&PROFILING_DATA, "append_blocks", move || {
        let original_block = block.clone();

        let block = match generic_block_to_encoded_block(block) {
            Ok(block) => block,
            Err(e) => {
                let message = format!(
                    "Unable to decode generic block at index {block_index}: {}. Error: {e}",
                    original_block
                );
                return Err(SyncError {
                    message,
                    retriable: false,
                });
            }
        };

        let decoded_block = match Block::<Tokens>::decode(block.clone()) {
            Ok(block) => block,
            Err(e) => {
                let message = format!(
                    "Unable to decode encoded block at index {block_index}: {}. Error: {e}",
                    original_block
                );
                return Err(SyncError {
                    message,
                    retriable: false,
                });
            }
        };
        let decoded_value = encoded_block_to_generic_block(&decoded_block.clone().encode());
        if original_block.hash() != decoded_value.hash() {
            let message = format!(
                "Block at index {block_index} has unknown fields. Original block: {}, decoded block: {}.",
                original_block, decoded_value
            );
            return Err(SyncError {
                message,
                retriable: false,
            });
        }

        // append the encoded block to the block log
        with_blocks(|blocks| {
            blocks
                .append(&block.0)
                .unwrap_or_else(|_| trap("no space left"))
        });

        // add the block idx to the indices
        with_account_block_ids(|account_block_ids| {
            for account in get_accounts(&decoded_block) {
                account_block_ids.insert(account_block_ids_key(account, block_index), ());
            }
        });

        // change the fee collector if block is a 107 block
        process_fee_collector_block(&decoded_block);

        // add the block to the fee_collector if one is set
        index_fee_collector(block_index);

        // change the balance of the involved accounts
        process_balance_changes(block_index, &decoded_block);

        Ok(())
    })
}

fn append_blocks(new_blocks: Vec<GenericBlock>) -> Result<(), SyncError> {
    // the index of the next block that we
    // are going to append
    let mut block_index = with_blocks(|blocks| blocks.len());
    for block in new_blocks {
        append_block(block_index, block)?;
        block_index += 1;
    }
    Ok(())
}

fn append_icrc3_blocks(new_blocks: Vec<BlockWithId>) -> Result<(), SyncError> {
    let mut blocks = vec![];
    let start_id = with_blocks(|blocks| blocks.len());
    for BlockWithId { id, block } in new_blocks {
        // sanity check
        let expected_id = start_id + blocks.len() as u64;
        if id != expected_id {
            let error = format!(
                "[fetch_blocks_via_icrc3]: wrong block index returned by ledger. Expected: {} actual: {}",
                expected_id, id
            );
            return Err(SyncError {
                message: error,
                retriable: false,
            });
        }
        // This conversion is safe as `Value`
        // can represent any `ICRC3Value`.
        blocks.push(Value::from(block));
    }
    append_blocks(blocks)?;
    Ok(())
}

fn process_fee_collector_block(block: &Block<Tokens>) {
    if let Operation::FeeCollector {
        fee_collector,
        caller: _,
        op: _,
    } = block.transaction.operation
    {
        mutate_state(|s| s.fee_collector_107 = Some(fee_collector));
    }
}

fn index_fee_collector(block_index: BlockIndex64) {
    if let Some(fee_collector) = get_fee_collector() {
        mutate_state(|s| {
            s.fee_collectors
                .entry(fee_collector)
                .and_modify(|blocks_ranges| push_block(blocks_ranges, block_index))
                .or_insert(vec![Range {
                    start: block_index,
                    end: block_index + 1,
                }]);
        });
    }
}

fn push_block(block_ranges: &mut Vec<Range<BlockIndex64>>, block_index: BlockIndex64) {
    if block_ranges.is_empty() {
        block_ranges.push(block_index..block_index + 1);
        return;
    }
    // if the block_index passed is the next block of the last range of block_ranges
    // then we extend the last range of block_range to include it, otherwise
    // we create a new range
    let last_id = block_ranges.len() - 1;
    if block_ranges[last_id].end == block_index {
        block_ranges[last_id].end = block_index + 1;
    } else {
        block_ranges.push(block_index..block_index + 1)
    }
}

fn process_balance_changes(block_index: BlockIndex64, block: &Block<Tokens>) {
    measure_span(
        &PROFILING_DATA,
        "append_blocks.process_balance_changes",
        move || match block.transaction.operation {
            Operation::Burn {
                from, amount, fee, ..
            } => {
                let mut amount_with_fee = amount;
                let effective_fee = block.effective_fee.or(fee);
                if let Some(fee) = effective_fee {
                    amount_with_fee = amount.checked_add(&fee).unwrap_or_else(|| {
                        trap(format!(
                            "token amount overflow while indexing block {block_index}"
                        ))
                    });
                    mutate_state(|s| s.last_fee = Some(fee));
                    if let Some(fee_collector) = get_fee_collector() {
                        credit(block_index, fee_collector, fee);
                    }
                }
                debit(block_index, from, amount_with_fee);
            }
            Operation::Mint { to, amount, fee } => {
                let mut amount_without_fee = amount;
                let effective_fee = block.effective_fee.or(fee);
                if let Some(fee) = effective_fee {
                    amount_without_fee = amount.checked_sub(&fee).unwrap_or_else(|| {
                        trap(format!(
                            "token amount underflow while indexing block {block_index}"
                        ))
                    });
                    mutate_state(|s| s.last_fee = Some(fee));
                    if let Some(fee_collector) = get_fee_collector() {
                        credit(block_index, fee_collector, fee);
                    }
                }
                credit(block_index, to, amount_without_fee)
            }
            Operation::Transfer {
                from,
                to,
                amount,
                fee,
                ..
            } => {
                let fee = block.effective_fee.or(fee).unwrap_or_else(|| {
                    ic_cdk::trap(format!(
                        "Block {block_index} is of type Transfer but has no fee or effective fee!"
                    ))
                });
                mutate_state(|s| s.last_fee = Some(fee));
                debit(
                    block_index,
                    from,
                    amount.checked_add(&fee).unwrap_or_else(|| {
                        ic_cdk::trap(format!(
                            "token amount overflow while indexing block {block_index}"
                        ))
                    }),
                );
                credit(block_index, to, amount);
                if let Some(fee_collector) = get_fee_collector() {
                    credit(block_index, fee_collector, fee);
                }
            }
            Operation::Approve {
                from, fee, spender, ..
            } => {
                let fee = match fee.or(block.effective_fee) {
                    Some(fee) => fee,
                    // NB. There was a bug in the ledger which would create
                    // approve blocks with the fee fields unset. The bug was
                    // quickly fixed, but there are a few blocks on the mainnet
                    // that don't have their fee fields populated.
                    None => match with_state(|state| state.last_fee) {
                        Some(last_fee) => {
                            log!(
                                P1,
                                "fee and effective_fee aren't set in block {block_index}, using last transfer fee {last_fee}"
                            );
                            last_fee
                        }
                        None => ic_cdk::trap(format!(
                            "bug: index is stuck because block with index {block_index} doesn't contain a fee and no fee has been recorded before"
                        )),
                    },
                };

                // It is possible that the spender account has not existed prior to this approve transaction.
                // Until a transfer_from transaction occurs such account would not show up in a `list_subaccounts` query as the spender is not involved in any credit or debit calls at this point.
                // To ensure that the account still shows up in the `list_subaccount` query we can simply call `change_balance` without actually changing the balance.
                // If the account is new, this will add it to the AccountDataMap with balance 0 and thus show up in a `list_subaccount` query.
                change_balance(spender, |balance| balance);

                debit(block_index, from, fee);

                if let Some(fee_collector_107) = get_fee_collector_107().flatten() {
                    credit(block_index, fee_collector_107, fee);
                }
            }
            Operation::FeeCollector {
                fee_collector: _,
                caller: _,
                op: _,
            } => {
                // Does not affect the balance
            }
        },
    );
}

fn debit(block_index: BlockIndex64, account: Account, amount: Tokens) {
    change_balance(account, |balance| {
        balance.checked_sub(&amount).unwrap_or_else(|| {
            ic_cdk::trap(format!("Block {block_index} caused an underflow for account {account} when calculating balance {balance} - amount {amount}"));
        })
    })
}

fn credit(block_index: BlockIndex64, account: Account, amount: Tokens) {
    change_balance(account, |balance| {
        balance.checked_add(&amount).unwrap_or_else(|| {
            ic_cdk::trap(format!("Block {block_index} caused an overflow for account {account} when calculating balance {balance} + amount {amount}"))
        })
    });
}

fn decode_encoded_block_or_trap(block_index: BlockIndex64, block: EncodedBlock) -> Block<Tokens> {
    Block::<Tokens>::decode(block).unwrap_or_else(|e| {
        trap(format!(
            "Unable to decode encoded block at index {block_index}. Error: {e}"
        ))
    })
}

/// Get the accounts whose balances are affected by the transaction in a block. Any affected
/// block is returned at most once - in particular, this applies to self-transfers.
fn get_accounts(block: &Block<Tokens>) -> Vec<Account> {
    match block.transaction.operation {
        Operation::Burn { from, .. } => vec![from],
        Operation::Mint { to, .. } => vec![to],
        Operation::Transfer { from, to, .. } => {
            match from == to {
                // For self-transfers, only return the affected account once.
                true => vec![from],
                false => vec![from, to],
            }
        }
        Operation::Approve { from, .. } => vec![from],
        Operation::FeeCollector { .. } => vec![],
    }
}

fn get_fee_collector() -> Option<Account> {
    get_fee_collector_107().unwrap_or_else(get_legacy_fee_collector)
}

fn get_fee_collector_107() -> Option<Option<Account>> {
    with_state(|s| s.fee_collector_107)
}

fn get_legacy_fee_collector() -> Option<Account> {
    let chain_length = with_blocks(|blocks| blocks.len());
    if chain_length == 0 {
        return None;
    }
    let last_block_index = chain_length - 1;
    let block = get_decoded_block(last_block_index)
        .expect("chain_length is positive, should have at least one block");
    if block.fee_collector.is_some() {
        block.fee_collector
    } else if let Some(fee_collector_block_index) = block.fee_collector_block_index {
        let block = get_decoded_block(fee_collector_block_index)
            .unwrap_or_else(||
                ic_cdk::trap(format!("Block at index {last_block_index} has fee_collector_block_index {fee_collector_block_index} but there is no block at that index")));
        if block.fee_collector.is_none() {
            ic_cdk::trap(format!(
                "Block at index {last_block_index} has fee_collector_block_index {fee_collector_block_index} but that block has no fee_collector set"
            ))
        } else {
            block.fee_collector
        }
    } else {
        None
    }
}

pub fn account_sha256(account: Account) -> [u8; Sha256::DIGEST_LEN] {
    let mut hasher = Sha256::new();
    account.hash(&mut hasher);
    hasher.finish()
}

fn account_block_ids_key(account: Account, block_index: BlockIndex64) -> AccountBlockIdsMapKey {
    (account_sha256(account), Reverse(block_index))
}

fn decode_icrc1_block(_txid: u64, bytes: Vec<u8>) -> GenericBlock {
    let encoded_block = EncodedBlock::from(bytes);
    encoded_block_to_generic_block(&encoded_block)
}

#[query]
fn get_blocks(req: GetBlocksRequest) -> ic_icrc1_index_ng::GetBlocksResponse {
    let chain_length = with_blocks(|blocks| blocks.len());
    let (start, length) = req
        .as_start_and_length()
        .unwrap_or_else(|msg| ic_cdk::api::trap(&msg));

    let blocks = decode_block_range(start, length, decode_icrc1_block);
    ic_icrc1_index_ng::GetBlocksResponse {
        chain_length,
        blocks,
    }
}

fn decode_block_range<R>(start: u64, length: u64, decoder: impl Fn(u64, Vec<u8>) -> R) -> Vec<R> {
    let length = length.min(with_state(|opts| opts.max_blocks_per_response));
    with_blocks(|blocks| {
        let limit = blocks.len().min(start.saturating_add(length));
        (start..limit)
            .map(|i| decoder(start + i, blocks.get(i).unwrap()))
            .collect()
    })
}

#[query]
fn ledger_id() -> Principal {
    with_state(|state| state.ledger_id)
}

#[query]
fn get_account_transactions(arg: GetAccountTransactionsArgs) -> GetAccountTransactionsResult {
    let length = arg
        .max_results
        .0
        .to_u64()
        .expect("The length must be a u64!")
        .min(with_state(|opts| opts.max_blocks_per_response))
        .min(usize::MAX as u64) as usize;
    // TODO: deal with the user setting start to u64::MAX
    let start = arg
        .start
        .map_or(u64::MAX, |n| n.0.to_u64().expect("start must be a u64!"));
    let key = account_block_ids_key(arg.account, start);
    let mut transactions = vec![];
    let indices = with_account_block_ids(|account_block_ids| {
        account_block_ids
            .range(key..)
            // old txs of the requested account and skip the start index
            .take_while(|(k, _)| k.0 == key.0)
            .filter(|(k, _)| k.1.0 < start)
            .take(length)
            .map(|(k, _)| k.1.0)
            .collect::<Vec<BlockIndex64>>()
    });
    for id in indices {
        let block = with_blocks(|blocks| {
            blocks.get(id).unwrap_or_else(|| {
                trap(format!(
                    "Block {id} not found in the block log, account blocks map is corrupted!"
                ))
            })
        });
        let transaction = encoded_block_bytes_to_flat_transaction(id, block);
        let transaction_with_idx = TransactionWithId {
            id: id.into(),
            transaction,
        };
        transactions.push(transaction_with_idx);
    }
    let oldest_tx_id = get_oldest_tx_id(arg.account).map(|tx_id| tx_id.into());
    let balance = get_balance(arg.account).into();
    Ok(GetAccountTransactionsResponse {
        balance,
        transactions,
        oldest_tx_id,
    })
}

fn encoded_block_bytes_to_flat_transaction(
    block_index: BlockIndex64,
    block: Vec<u8>,
) -> Transaction {
    let block = Block::<Tokens>::decode(EncodedBlock::from(block)).unwrap_or_else(|e| {
        trap(format!(
            "Unable to decode encoded block at index {block_index}. Error: {e}"
        ))
    });
    block.into()
}

fn get_oldest_tx_id(account: Account) -> Option<BlockIndex64> {
    // There is no easy way to get the oldest index for an account
    // in one step. Instead, we do it in two steps:
    // 1. check if index 0 is owned by the account
    // 2. if not then return the oldest index of the account that
    //    is not 0 via iter_upper_bound
    let last_key = account_block_ids_key(account, 0);
    with_account_block_ids(|account_block_ids| {
        account_block_ids.get(&last_key).map(|_| 0).or_else(|| {
            account_block_ids
                .iter_upper_bound(&last_key)
                .take_while(|(k, _)| k.0 == account_sha256(account))
                .next()
                .map(|(key, _)| key.1.0)
        })
    })
}

#[query]
fn icrc1_balance_of(account: Account) -> Nat {
    get_balance(account).into()
}

#[query]
fn status() -> Status {
    let num_blocks_synced = with_blocks(|blocks| blocks.len().into());
    Status { num_blocks_synced }
}

#[query]
fn list_subaccounts(args: ListSubaccountsArgs) -> Vec<Subaccount> {
    let start_key = balance_key(Account {
        owner: args.owner,
        subaccount: args.start,
    });
    let end_key = balance_key(Account {
        owner: args.owner,
        subaccount: Some([u8::MAX; 32]),
    });
    let range = (
        if args.start.is_none() {
            Included(start_key)
        } else {
            Excluded(start_key)
        },
        Included(end_key),
    );
    with_account_data(|data| {
        data.range(range)
            .take(DEFAULT_MAX_BLOCKS_PER_RESPONSE as usize)
            .map(|((_, (_, subaccount)), _)| subaccount)
            .collect()
    })
}

#[query(
    hidden = true,
    decode_with = "candid::decode_one_with_decoding_quota::<100000,_>"
)]
fn http_request(req: HttpRequest) -> HttpResponse {
    if req.path() == "/metrics" {
        let mut writer =
            ic_metrics_encoder::MetricsEncoder::new(vec![], ic_cdk::api::time() as i64 / 1_000_000);

        match encode_metrics(&mut writer) {
            Ok(()) => HttpResponseBuilder::ok()
                .header("Content-Type", "text/plain; version=0.0.4")
                .header("Cache-Control", "no-store")
                .with_body_and_content_length(writer.into_inner())
                .build(),
            Err(err) => {
                HttpResponseBuilder::server_error(format!("Failed to encode metrics: {err}"))
                    .build()
            }
        }
    } else if req.path() == "/logs" {
        use serde_json;
        let mut entries: Log = Default::default();
        for entry in export_logs(&P0) {
            entries.entries.push(LogEntry {
                timestamp: entry.timestamp,
                file: entry.file.to_string(),
                line: entry.line,
                message: entry.message,
            });
        }
        HttpResponseBuilder::ok()
            .header("Content-Type", "application/json; charset=utf-8")
            .with_body_and_content_length(serde_json::to_string(&entries).unwrap_or_default())
            .build()
    } else {
        HttpResponseBuilder::not_found().build()
    }
}

pub fn encode_metrics(w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    w.encode_gauge(
        "index_stable_memory_pages",
        ic_cdk::api::stable::stable_size() as f64,
        "Size of the stable memory allocated by this canister measured in 64K Wasm pages.",
    )?;
    w.encode_gauge(
        "stable_memory_bytes",
        (ic_cdk::api::stable::stable_size() * 64 * 1024) as f64,
        "Size of the stable memory allocated by this canister measured in bytes.",
    )?;
    w.encode_gauge(
        "heap_memory_bytes",
        heap_memory_size_bytes() as f64,
        "Size of the heap memory allocated by this canister measured in bytes.",
    )?;

    let cycle_balance = ic_cdk::api::canister_balance128() as f64;
    w.encode_gauge(
        "index_cycle_balance",
        cycle_balance,
        "Cycle balance on this canister.",
    )?;
    w.gauge_vec("cycle_balance", "Cycle balance on this canister.")?
        .value(&[("canister", "icrc1-index")], cycle_balance)?;

    w.encode_gauge(
        "index_number_of_blocks",
        with_blocks(|blocks| blocks.len()) as f64,
        "Total number of blocks stored in the stable memory.",
    )?;
    w.encode_gauge(
        "index_last_wait_time",
        with_state(|state| state.last_wait_time)
            .as_nanos()
            .min(f64::MAX as u128) as f64,
        "Last amount of time waited between two transactions fetch.",
    )?;
    PROFILING_DATA.with(|cell| -> std::io::Result<()> {
        cell.borrow().record_metrics(w.histogram_vec(
            "index_ng_profile_instructions",
            "Statistics for how many instructions index-ng operations require.",
        )?)?;
        Ok(())
    })?;
    Ok(())
}

#[query]
fn get_fee_collectors_ranges() -> FeeCollectorRanges {
    let ranges = with_state(|s| {
        let mut res = vec![];
        for (fee_collector, ranges) in &s.fee_collectors {
            let mut fee_collector_ranges = vec![];
            for range in ranges {
                fee_collector_ranges.push((range.start.into(), range.end.into()));
            }
            res.push((*fee_collector, fee_collector_ranges))
        }
        res
    });
    FeeCollectorRanges { ranges }
}

fn main() {}

#[cfg(test)]
candid::export_service!();

#[test]
fn check_candid_interface() {
    use candid_parser::utils::{CandidSource, service_equal};
    use std::path::PathBuf;

    let new_interface = __export_service();
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let old_interface = manifest_dir.join("index-ng.did");
    service_equal(
        CandidSource::Text(&new_interface),
        CandidSource::File(old_interface.as_path()),
    )
    .unwrap_or_else(|e| {
        panic!(
            "the index interface is not compatible with {}: {:?}",
            old_interface.display(),
            e
        )
    });
}

#[test]
fn check_index_and_ledger_block_equality() {
    // check that ledger.did and index-ng.did agree on the block format
    let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let ledger_did_file = manifest_dir.join("../ledger/ledger.did");
    let index_did_file = manifest_dir.join("index-ng.did");
    let mut ledger_env = candid_parser::utils::CandidSource::File(ledger_did_file.as_path())
        .load()
        .unwrap()
        .0;
    let index_env = candid_parser::utils::CandidSource::File(index_did_file.as_path())
        .load()
        .unwrap()
        .0;
    let ledger_block_type = ledger_env.find_type("Block").unwrap().to_owned();
    let index_block_type = index_env.find_type("Block").unwrap().to_owned();

    let mut gamma = std::collections::HashSet::new();
    let index_block_type = ledger_env.merge_type(index_env, index_block_type.clone());
    candid::types::subtype::equal(
        &mut gamma,
        &ledger_env,
        &ledger_block_type,
        &index_block_type,
    )
    .expect("Ledger and Index block types are different");
}
