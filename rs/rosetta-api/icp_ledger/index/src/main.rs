use candid::{candid_method, Principal};
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_cdk_macros::{init, query};
use ic_cdk_timers::TimerId;
use ic_icp_index::{
    GetAccountIdentifierTransactionsArgs, GetAccountIdentifierTransactionsResponse,
    GetAccountIdentifierTransactionsResult, InitArg, Status, TransactionWithId,
};
use ic_ledger_core::block::{BlockType, EncodedBlock};
use ic_stable_structures::memory_manager::{MemoryId, VirtualMemory};
use ic_stable_structures::{
    cell::Cell as StableCell, log::Log as StableLog, memory_manager::MemoryManager,
    DefaultMemoryImpl, Storable,
};
use ic_stable_structures::{BoundedStorable, StableBTreeMap};
use icp_ledger::{
    AccountIdentifier, ArchivedBlocksRange, Block, BlockIndex, CandidBlock, GetBlocksArgs,
    Operation, QueryBlocksResponse, MAX_BLOCKS_PER_REQUEST,
};
use scopeguard::{guard, ScopeGuard};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::cell::RefCell;
use std::cmp::Reverse;
use std::convert::TryFrom;
use std::time::Duration;

/// The maximum number of blocks to return in a single [get_blocks] request.
const DEFAULT_MAX_BLOCKS_PER_RESPONSE: usize = MAX_BLOCKS_PER_REQUEST;

/// Memory ids for stable structures used in the icp index canister
const STATE_MEMORY_ID: MemoryId = MemoryId::new(0);
const BLOCK_LOG_INDEX_MEMORY_ID: MemoryId = MemoryId::new(1);
const BLOCK_LOG_DATA_MEMORY_ID: MemoryId = MemoryId::new(2);
const ACCOUNTIDENTIFIER_BLOCK_IDS_MEMORY_ID: MemoryId = MemoryId::new(3);
const ACCOUNTIDENTIFIER_DATA_MEMORY_ID: MemoryId = MemoryId::new(4);

const DEFAULT_MAX_WAIT_TIME: Duration = Duration::from_secs(60);
const DEFAULT_RETRY_WAIT_TIME: Duration = Duration::from_secs(10);

type VM = VirtualMemory<DefaultMemoryImpl>;
type StateCell = StableCell<State, VM>;
type BlockLog = StableLog<Vec<u8>, VM, VM>;

// The block indexes are stored in reverse order because the blocks/transactions
// are returned in reversed order.
type AccountIdentifierBlockIdsMapKey = ([u8; 28], Reverse<u64>);
type AccountIdentifierBlockIdsMap = StableBTreeMap<AccountIdentifierBlockIdsMapKey, (), VM>;

// The second element of this tuple is the account represented
// as principal of type Blob<29> and the effective subaccount
type AccountIdentifierDataMapKey = (AccountIdentifierDataType, [u8; 28]);
type AccountIdentifierDataMap = StableBTreeMap<AccountIdentifierDataMapKey, u64, VM>;

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

    /// Map that contains the block ids of an account_identifier.
    static ACCOUNTIDENTIFIER_BLOCK_IDS: RefCell<AccountIdentifierBlockIdsMap> = with_memory_manager(|memory_manager| {
        RefCell::new(AccountIdentifierBlockIdsMap::init(memory_manager.get(ACCOUNTIDENTIFIER_BLOCK_IDS_MEMORY_ID)))
    });

    /// Map that contains account aggregated data.
    static ACCOUNTIDENTIFIER_DATA: RefCell<AccountIdentifierDataMap> = with_memory_manager(|memory_manager| {
        RefCell::new(AccountIdentifierDataMap::init(memory_manager.get(ACCOUNTIDENTIFIER_DATA_MEMORY_ID)))
    });
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct State {
    // Equals to `true` while the [build_index] task runs.
    is_build_index_running: bool,

    /// The principal of the ledger canister that is indexed by this index.
    ledger_id: Principal,

    // Last wait time in nanoseconds.
    pub last_wait_time: Duration,
}

// NOTE: the default configuration is dysfunctional, but it's convenient to have
// a Default impl for the initialization of the [STATE] variable above.
impl Default for State {
    fn default() -> Self {
        Self {
            is_build_index_running: false,
            ledger_id: Principal::management_canister(),
            last_wait_time: Duration::from_secs(0),
        }
    }
}

impl Storable for State {
    fn to_bytes(&self) -> Cow<[u8]> {
        let mut buf = vec![];
        ciborium::ser::into_writer(self, &mut buf).expect("failed to encode index config");
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        ciborium::de::from_reader(&bytes[..]).expect("failed to decode index options")
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
enum AccountIdentifierDataType {
    #[default]
    Balance = 0,
}

impl Storable for AccountIdentifierDataType {
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
}

impl BoundedStorable for AccountIdentifierDataType {
    const MAX_SIZE: u32 = 1;
    const IS_FIXED_SIZE: bool = true;
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
            let mut state = *borrowed.get();
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

/// A helper function to access the account_identifier block ids.
fn with_account_identifier_block_ids<R>(
    f: impl FnOnce(&mut AccountIdentifierBlockIdsMap) -> R,
) -> R {
    ACCOUNTIDENTIFIER_BLOCK_IDS.with(|cell| f(&mut cell.borrow_mut()))
}

/// A helper function to access the account data.
fn with_account_identifier_data<R>(f: impl FnOnce(&mut AccountIdentifierDataMap) -> R) -> R {
    ACCOUNTIDENTIFIER_DATA.with(|cell| f(&mut cell.borrow_mut()))
}

/// A helper function to access the balance of an account.
fn get_balance(account_identifier: AccountIdentifier) -> u64 {
    with_account_identifier_data(|account_identifier_data| {
        account_identifier_data
            .get(&balance_key(account_identifier))
            .unwrap_or(0)
    })
}

/// A helper function to change the balance of an account.
/// It removes an account balance if the balance is 0.
fn change_balance(account_identifier: AccountIdentifier, f: impl FnOnce(u64) -> u64) {
    let key = balance_key(account_identifier);
    let new_balance = f(get_balance(account_identifier));
    if new_balance == 0 {
        with_account_identifier_data(|account_identifier_data| {
            account_identifier_data.remove(&key)
        });
    } else {
        with_account_identifier_data(|account_identifier_data| {
            account_identifier_data.insert(key, new_balance)
        });
    }
}

fn balance_key(account_identifier: AccountIdentifier) -> (AccountIdentifierDataType, [u8; 28]) {
    (AccountIdentifierDataType::Balance, account_identifier.hash)
}

#[init]
#[candid_method(init)]
fn init(init_arg: InitArg) {
    // stable memory initialization
    mutate_state(|state| {
        state.ledger_id = init_arg.ledger_id;
    });

    // set the first build_index to be called after init
    set_build_index_timer(Duration::from_secs(1));
}

async fn get_blocks_from_ledger(start: u64) -> Result<QueryBlocksResponse, String> {
    let ledger_id = with_state(|state| state.ledger_id);
    let req = GetBlocksArgs {
        start,
        length: DEFAULT_MAX_BLOCKS_PER_RESPONSE,
    };
    let (res,): (QueryBlocksResponse,) = ic_cdk::call(ledger_id, "query_blocks", (req,))
        .await
        .map_err(|(code, str)| format!("code: {:#?} message: {}", code, str))?;
    Ok(res)
}

async fn get_blocks_from_archive(
    block_range: &ArchivedBlocksRange,
) -> Result<Vec<icp_ledger::CandidBlock>, String> {
    let req = GetBlocksArgs {
        start: block_range.start,
        length: block_range.length as usize,
    };
    let (blocks_res,): (icp_ledger::GetBlocksResult,) = ic_cdk::call(
        block_range.callback.canister_id,
        &block_range.callback.method,
        (req,),
    )
    .await
    .map_err(|(code, str)| format!("code: {:#?} message: {}", code, str))?;
    let blocks = blocks_res.map_err(|err| match err {
        icp_ledger::GetBlocksError::BadFirstBlockIndex {
            requested_index,
            first_valid_index,
        } => format!(
            "First provided index is not valid: Requested Index:{} | First valid index: {}",
            requested_index, first_valid_index
        ),
        icp_ledger::GetBlocksError::Other {
            error_code,
            error_message,
        } => format!("code: {:#?} message: {}", error_code, error_message),
    })?;
    Ok(blocks.blocks)
}

pub async fn build_index() -> Result<(), String> {
    if with_state(|state| state.is_build_index_running) {
        return Err("build_index already running".to_string());
    }
    mutate_state(|state| {
        state.is_build_index_running = true;
    });
    let _reset_is_build_index_running_flag_guard = guard((), |_| {
        mutate_state(|state| {
            state.is_build_index_running = false;
        });
    });
    let failure_guard = guard((), |_| {
        set_build_index_timer(DEFAULT_RETRY_WAIT_TIME);
    });
    let next_txid = with_blocks(|blocks| blocks.len());
    let res = get_blocks_from_ledger(next_txid).await?;
    let mut tx_indexed_count: usize = 0;
    for archived in res.archived_blocks {
        let mut remaining = archived.length;
        let mut next_archived_txid = archived.start;
        while remaining > 0u64 {
            let archived = ArchivedBlocksRange {
                start: next_archived_txid,
                length: remaining,
                callback: archived.callback.clone(),
            };
            let candid_blocks = get_blocks_from_archive(&archived).await?;
            next_archived_txid += candid_blocks.len() as u64;
            tx_indexed_count += candid_blocks.len();
            remaining -= candid_blocks.len() as u64;
            append_blocks(candid_blocks);
        }
    }
    tx_indexed_count += res.blocks.len();
    append_blocks(res.blocks);
    let wait_time = compute_wait_time(tx_indexed_count);
    ic_cdk::eprintln!("Indexed: {} waiting : {:?}", tx_indexed_count, wait_time);
    mutate_state(|mut state| state.last_wait_time = wait_time);
    ScopeGuard::into_inner(failure_guard);
    set_build_index_timer(wait_time);
    Ok(())
}

fn set_build_index_timer(after: Duration) -> TimerId {
    ic_cdk_timers::set_timer(after, || {
        ic_cdk::spawn(async {
            let _ = build_index().await;
        })
    })
}

/// Compute the waiting time before next indexing
pub fn compute_wait_time(indexed_tx_count: usize) -> Duration {
    if indexed_tx_count >= DEFAULT_MAX_BLOCKS_PER_RESPONSE {
        // If we indexed more than max_blocks_per_response,
        // we index again on the next build_index call.
        return Duration::ZERO;
    }
    let numerator = 1f64 - (indexed_tx_count as f64 / DEFAULT_MAX_BLOCKS_PER_RESPONSE as f64);
    DEFAULT_MAX_WAIT_TIME * (100f64 * numerator) as u32 / 100
}

fn append_blocks(new_blocks: Vec<CandidBlock>) {
    // the index of the next block that we
    // are going to append
    let mut block_index = with_blocks(|blocks| blocks.len());
    for candid_block in new_blocks {
        let block = icp_ledger::Block::try_from(candid_block)
            .unwrap_or_else(|msg| ic_cdk::api::trap(&msg))
            .encode();

        // append the encoded block to the block log
        with_blocks(|blocks| {
            blocks
                .append(&block.0)
                .unwrap_or_else(|_| ic_cdk::trap("no space left"))
        });

        let decoded_block = decode_encoded_block_or_trap(block_index, block);

        // add the block idx to the indices
        with_account_identifier_block_ids(|account_identifier_block_ids| {
            for account_identifier in get_account_identifiers(&decoded_block) {
                account_identifier_block_ids.insert(
                    account_identifier_block_ids_key(account_identifier, block_index),
                    (),
                );
            }
        });
        // change the balance of the involved accounts
        process_balance_changes(block_index, &decoded_block);

        block_index += 1;
    }
}

fn process_balance_changes(block_index: BlockIndex, block: &Block) {
    match block.transaction.operation {
        Operation::Burn { from, amount } => debit(block_index, from, amount.get_e8s()),
        Operation::Mint { to, amount } => credit(block_index, to, amount.get_e8s()),
        Operation::Transfer {
            from,
            to,
            amount,
            fee,
        } => {
            debit(block_index, from, amount.get_e8s() + fee.get_e8s());
            credit(block_index, to, amount.get_e8s());
        }
        _ => ic_cdk::trap("Indexer only supports Burn, Mint and Transfer Operations"),
    }
}

fn debit(block_index: BlockIndex, account_identifier: AccountIdentifier, amount: u64) {
    change_balance(account_identifier, |balance| {
        if balance < amount {
            ic_cdk::trap(&format!("Block {} caused an underflow for account_identifier {} when calculating balance {} - amount {}",
                block_index, account_identifier, balance, amount));
        }
        balance - amount
    })
}

fn credit(block_index: BlockIndex, account_identifier: AccountIdentifier, amount: u64) {
    change_balance(account_identifier, |balance| {
        if u64::MAX - balance < amount {
            ic_cdk::trap(&format!("Block {} caused an overflow for account_identifier {} when calculating balance {} + amount {}",
                block_index, account_identifier, balance, amount));
        }
        balance + amount
    });
}

fn decode_encoded_block_or_trap(block_index: BlockIndex, block: EncodedBlock) -> Block {
    Block::decode(block).unwrap_or_else(|e| {
        ic_cdk::api::trap(&format!(
            "Unable to decode encoded block at index {}. Error: {}",
            block_index, e
        ))
    })
}

fn get_account_identifiers(block: &Block) -> Vec<AccountIdentifier> {
    match block.transaction.operation {
        Operation::Burn { from, .. } => vec![from],
        Operation::Mint { to, .. } => vec![to],
        Operation::Transfer { from, to, .. } => vec![from, to],
        _ => ic_cdk::trap("Indexer only supports Burn, Mint and Transfer Operations"),
    }
}

fn account_identifier_block_ids_key(
    account_identifier: AccountIdentifier,
    block_index: BlockIndex,
) -> AccountIdentifierBlockIdsMapKey {
    (account_identifier.hash, Reverse(block_index))
}

#[query]
#[candid_method(query)]
fn ledger_id() -> Principal {
    with_state(|state| state.ledger_id)
}

fn get_block_range_from_stable_memory(start: u64, length: u64) -> Vec<EncodedBlock> {
    let length = length.min(DEFAULT_MAX_BLOCKS_PER_RESPONSE as u64);
    with_blocks(|blocks| {
        let limit = blocks.len().min(start.saturating_add(length));
        (start..limit)
            .map(|i| {
                EncodedBlock::from_vec(blocks.get(i).unwrap_or_else(|| {
                    ic_cdk::api::trap(&format!(
                        "Cannot find index {} in icp ledger index canister storage",
                        i
                    ))
                }))
            })
            .collect()
    })
}

fn get_oldest_tx_id(account_identifier: AccountIdentifier) -> Option<BlockIndex> {
    // There is no easy way to get the oldest index for an account_identifier
    // in one step. Instead, we do it in two steps:
    // 1. check if index 0 is owned by the account_identifier
    // 2. if not then return the oldest index of the account_identifier that
    //    is not 0 via iter_upper_bound
    let last_key = account_identifier_block_ids_key(account_identifier, 0);
    with_account_identifier_block_ids(|account_identifier_block_ids| {
        account_identifier_block_ids
            .get(&last_key)
            .map(|_| 0)
            .or_else(|| {
                account_identifier_block_ids
                    .iter_upper_bound(&last_key)
                    .find(|((account_identifier, _), _)| account_identifier == &last_key.0)
                    .map(|(key, _)| key.1 .0)
            })
    })
}

pub fn encode_metrics(w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    w.encode_gauge(
        "index_stable_memory_pages",
        ic_cdk::api::stable::stable_size() as f64,
        "Size of the stable memory allocated by this canister measured in 64K Wasm pages.",
    )?;
    w.encode_gauge(
        "index_stable_memory_bytes",
        (ic_cdk::api::stable::stable_size() * 64 * 1024) as f64,
        "Size of the stable memory allocated by this canister.",
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
    Ok(())
}

#[query]
#[candid_method(query)]
fn get_blocks(
    req: icrc_ledger_types::icrc3::blocks::GetBlocksRequest,
) -> ic_icp_index::GetBlocksResponse {
    let chain_length = with_blocks(|blocks| blocks.len());
    let (start, length) = req
        .as_start_and_length()
        .unwrap_or_else(|msg| ic_cdk::api::trap(&msg));

    let blocks = get_block_range_from_stable_memory(start, length);
    ic_icp_index::GetBlocksResponse {
        chain_length,
        blocks,
    }
}

#[query]
#[candid_method(query)]
fn get_account_identifier_transactions(
    arg: GetAccountIdentifierTransactionsArgs,
) -> GetAccountIdentifierTransactionsResult {
    let length = arg
        .max_results
        .min(DEFAULT_MAX_BLOCKS_PER_RESPONSE as u64)
        .min(usize::MAX as u64) as usize;
    // TODO: deal with the user setting start to u64::MAX
    let start = arg.start.map_or(u64::MAX, |n| n);
    let key = account_identifier_block_ids_key(arg.account_identifier, start);
    let mut transactions = vec![];
    let indices = with_account_identifier_block_ids(|account_identifier_block_ids| {
        account_identifier_block_ids
            .range(key..)
            // old txs of the requested account_identifier and skip the start index
            .filter(|(k, _)| k.0 == key.0 && k.1 .0 != start)
            .take(length)
            .map(|(k, _)| k.1 .0)
            .collect::<Vec<BlockIndex>>()
    });
    for id in indices {
        let block = with_blocks(|blocks| {
            blocks.get(id).unwrap_or_else(|| {
                ic_cdk::api::trap(&format!(
                    "Block {} not found in the block log, account_identifier blocks map is corrupted!",
                    id
                ))
            })
        });
        let transaction = decode_encoded_block_or_trap(id, block.into()).transaction;
        let transaction_with_idx = TransactionWithId { id, transaction };
        transactions.push(transaction_with_idx);
    }
    let oldest_tx_id = get_oldest_tx_id(arg.account_identifier);
    let balance = get_balance(arg.account_identifier);
    Ok(GetAccountIdentifierTransactionsResponse {
        balance,
        transactions,
        oldest_tx_id,
    })
}

#[candid_method(query)]
#[query]
fn http_request(req: HttpRequest) -> HttpResponse {
    if req.path() == "/metrics" {
        let mut writer =
            ic_metrics_encoder::MetricsEncoder::new(vec![], ic_cdk::api::time() as i64 / 1_000_000);

        match encode_metrics(&mut writer) {
            Ok(()) => HttpResponseBuilder::ok()
                .header("Content-Type", "text/plain; version=0.0.4")
                .with_body_and_content_length(writer.into_inner())
                .build(),
            Err(err) => {
                HttpResponseBuilder::server_error(format!("Failed to encode metrics: {}", err))
                    .build()
            }
        }
    } else {
        HttpResponseBuilder::not_found().build()
    }
}

#[query]
#[candid_method(query)]
fn get_account_identifier_balance(account_identifier: AccountIdentifier) -> u64 {
    get_balance(account_identifier)
}

#[query]
#[candid_method(query)]
fn status() -> Status {
    let num_blocks_synced = with_blocks(|blocks| blocks.len());
    Status { num_blocks_synced }
}

fn main() {}

#[test]
fn test_account_identifier_data_type_storable() {
    assert_eq!(
        AccountIdentifierDataType::Balance,
        AccountIdentifierDataType::from_bytes(AccountIdentifierDataType::Balance.to_bytes())
    );
}

#[test]
fn check_candid_interface_compatibility() {
    use candid::utils::{service_compatible, CandidSource};

    candid::export_service!();

    let new_interface = __export_service();

    // check the public interface against the actual one
    let old_interface =
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("index.did");

    service_compatible(
        CandidSource::Text(&new_interface),
        CandidSource::File(old_interface.as_path()),
    )
    .unwrap();
}
