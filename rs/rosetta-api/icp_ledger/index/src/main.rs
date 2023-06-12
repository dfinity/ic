use candid::{candid_method, Principal};
use ic_cdk_macros::{init, query};
use ic_cdk_timers::TimerId;
use ic_icp_index::InitArg;
use ic_ledger_core::block::{BlockType, EncodedBlock};
use ic_stable_structures::memory_manager::{MemoryId, VirtualMemory};
use ic_stable_structures::{
    cell::Cell as StableCell, log::Log as StableLog, memory_manager::MemoryManager,
    DefaultMemoryImpl, Storable,
};
use icp_ledger::{
    ArchivedBlocksRange, CandidBlock, GetBlocksArgs, QueryBlocksResponse, MAX_BLOCKS_PER_REQUEST,
};
use scopeguard::{guard, ScopeGuard};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::cell::RefCell;
use std::convert::TryFrom;
use std::time::Duration;

/// The maximum number of blocks to return in a single [get_blocks] request.
const DEFAULT_MAX_BLOCKS_PER_RESPONSE: usize = MAX_BLOCKS_PER_REQUEST;

/// Memory ids for stable structures used in the icp index canister
const STATE_MEMORY_ID: MemoryId = MemoryId::new(0);
const BLOCK_LOG_INDEX_MEMORY_ID: MemoryId = MemoryId::new(1);
const BLOCK_LOG_DATA_MEMORY_ID: MemoryId = MemoryId::new(2);

const DEFAULT_MAX_WAIT_TIME: Duration = Duration::from_secs(60);
const DEFAULT_RETRY_WAIT_TIME: Duration = Duration::from_secs(10);

type StateCell = StableCell<State, VirtualMemory<DefaultMemoryImpl>>;
type BlockLog =
    StableLog<Vec<u8>, VirtualMemory<DefaultMemoryImpl>, VirtualMemory<DefaultMemoryImpl>>;

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
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct State {
    // Equals to `true` while the [build_index] task runs.
    is_build_index_running: bool,

    /// The principal of the ledger canister that is indexed by this index.
    ledger_id: Principal,
}

// NOTE: the default configuration is dysfunctional, but it's convenient to have
// a Default impl for the initialization of the [STATE] variable above.
impl Default for State {
    fn default() -> Self {
        Self {
            is_build_index_running: false,
            ledger_id: Principal::management_canister(),
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
        block_range.callback.canister_id.into(),
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
    with_blocks(|blocks| {
        for candid_block in new_blocks {
            let encoded_block = icp_ledger::Block::try_from(candid_block)
                .unwrap_or_else(|msg| ic_cdk::api::trap(&msg))
                .encode();
            blocks
                .append(&encoded_block.into_vec())
                .unwrap_or_else(|_| ic_cdk::api::trap("no space left"));
        }
    })
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

fn main() {}
