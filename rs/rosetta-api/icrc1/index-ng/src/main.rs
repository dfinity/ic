use candid::{candid_method, Nat, Principal};
use ic_cdk_macros::{init, query};
use ic_cdk_timers::TimerId;
use ic_icrc1::blocks::{encoded_block_to_generic_block, generic_block_to_encoded_block};
use ic_icrc1_index_ng::InitArg;
use ic_ledger_core::block::EncodedBlock;
use ic_stable_structures::memory_manager::{MemoryId, VirtualMemory};
use ic_stable_structures::{
    cell::Cell as StableCell, log::Log as StableLog, memory_manager::MemoryManager,
    DefaultMemoryImpl, Storable,
};
use icrc_ledger_types::icrc3::archive::{ArchivedRange, QueryBlockArchiveFn};
use icrc_ledger_types::icrc3::blocks::{
    BlockRange, GenericBlock, GetBlocksRequest, GetBlocksResponse,
};
use scopeguard::{guard, ScopeGuard};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::cell::RefCell;
use std::time::Duration;

/// The maximum number of blocks to return in a single [get_blocks] request.
const DEFAULT_MAX_BLOCKS_PER_RESPONSE: u64 = 2000;

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

    /// The maximum number of transactions returned by [get_blocks].
    max_blocks_per_response: u64,
}

// NOTE: the default configuration is dysfunctional, but it's convenient to have
// a Default impl for the initialization of the [STATE] variable above.
impl Default for State {
    fn default() -> Self {
        Self {
            is_build_index_running: false,
            ledger_id: Principal::management_canister(),
            max_blocks_per_response: DEFAULT_MAX_BLOCKS_PER_RESPONSE,
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
fn change_state(f: impl FnOnce(&mut State)) {
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
    change_state(|state| {
        state.ledger_id = init_arg.ledger_id;
    });

    // set the first build_index to be called after init
    set_build_index_timer(Duration::from_secs(1));
}

async fn get_blocks_from_ledger(start: u64) -> Result<GetBlocksResponse, String> {
    let (ledger_id, length) = with_state(|state| (state.ledger_id, state.max_blocks_per_response));
    let req = GetBlocksRequest {
        start: Nat::from(start),
        length: Nat::from(length),
    };
    let (res,): (GetBlocksResponse,) = ic_cdk::call(ledger_id, "get_blocks", (req,))
        .await
        .map_err(|(code, str)| format!("code: {:#?} message: {}", code, str))?;
    Ok(res)
}

async fn get_blocks_from_archive(
    archived: &ArchivedRange<QueryBlockArchiveFn>,
) -> Result<BlockRange, String> {
    let req = GetBlocksRequest {
        start: archived.start.clone(),
        length: archived.length.clone(),
    };
    let (res,): (BlockRange,) = ic_cdk::call(
        archived.callback.canister_id,
        &archived.callback.method,
        (req,),
    )
    .await
    .map_err(|(code, str)| format!("code: {:#?} message: {}", code, str))?;
    Ok(res)
}

pub async fn build_index() -> Result<(), String> {
    if with_state(|state| state.is_build_index_running) {
        return Err("build_index already running".to_string());
    }
    change_state(|state| {
        state.is_build_index_running = true;
    });
    let _reset_is_build_index_running_flag_guard = guard((), |_| {
        change_state(|state| {
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
            tx_indexed_count += res.blocks.len();
            remaining -= res.blocks.len();
            append_blocks(res.blocks);
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
    let max_blocks_per_response = with_state(|state| state.max_blocks_per_response);
    if indexed_tx_count as u64 >= max_blocks_per_response {
        // If we indexed more than max_blocks_per_response,
        // we index again on the next build_index call.
        return Duration::ZERO;
    }
    let numerator = 1f64 - (indexed_tx_count as f64 / max_blocks_per_response as f64);
    DEFAULT_MAX_WAIT_TIME * (100f64 * numerator) as u32 / 100
}

fn append_blocks(new_blocks: Vec<GenericBlock>) {
    with_blocks(|blocks| {
        for block in new_blocks {
            let block =
                generic_block_to_encoded_block(block).expect("Unable to encode generic block");
            blocks
                .append(&block.into_vec())
                .unwrap_or_else(|_| ic_cdk::api::trap("no space left"));
        }
    })
}

fn decode_icrc1_block(_txid: u64, bytes: Vec<u8>) -> GenericBlock {
    let encoded_block = EncodedBlock::from(bytes);
    encoded_block_to_generic_block(&encoded_block)
}

#[query]
#[candid_method(query)]
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

fn main() {}

#[test]
fn compute_wait_time_test() {
    fn blocks(n: u64) -> usize {
        let max_blocks = DEFAULT_MAX_BLOCKS_PER_RESPONSE as f64;
        (max_blocks * n as f64 / 100f64) as usize
    }

    fn wait_time(n: u64) -> Duration {
        let max_wait_time = DEFAULT_MAX_WAIT_TIME.as_secs() as f64;
        Duration::from_secs((max_wait_time * n as f64 / 100f64) as u64)
    }

    assert_eq!(wait_time(100), compute_wait_time(blocks(0)));
    assert_eq!(wait_time(75), compute_wait_time(blocks(25)));
    assert_eq!(wait_time(50), compute_wait_time(blocks(50)));
    assert_eq!(wait_time(25), compute_wait_time(blocks(75)));
    assert_eq!(wait_time(0), compute_wait_time(blocks(100)));
}
