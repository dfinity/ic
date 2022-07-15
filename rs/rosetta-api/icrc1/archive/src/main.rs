use candid::{candid_method, Principal};
use ic_cdk_macros::{init, post_upgrade, query, update};
use ic_icrc1::{Block, CandidBlock};
use ic_ledger_core::block::{BlockHeight, BlockType, EncodedBlock};
use serde::{Deserialize, Serialize};
use stable_structures::{
    cell::Cell as StableCell, log::Log as StableLog, DefaultMemoryImpl, RestrictedMemory, Storable,
};
use std::borrow::Cow;
use std::cell::RefCell;

const GIB: usize = 1024 * 1024 * 1024;

/// How much memory do we want to allocate for raw blocks.
const DEFAULT_MEMORY_LIMIT: usize = 3 * GIB;

/// The minimum block size in bytes, computed empirically.
const MIN_BLOCK_SIZE: usize = 90;

/// The expected number of blocks that fits into stable memory.
const MAX_BLOCKS: usize = DEFAULT_MEMORY_LIMIT / MIN_BLOCK_SIZE;

/// The maximum number of Wasm pages that we allow to use for the stable storage.
const NUM_WASM_PAGES: u64 = 4 * (GIB as u64) / 65536;

type Memory = RestrictedMemory<DefaultMemoryImpl>;
type BlockLog = StableLog<Memory>;
type ConfigCell = StableCell<ArchiveConfig, Memory>;

/// Creates a memory region for the configuration stable cell.
fn config_memory() -> Memory {
    RestrictedMemory::new(DefaultMemoryImpl::default(), 0..1)
}

/// Creates a memory region for the append-only block list.
fn blocks_memory() -> Memory {
    RestrictedMemory::new(DefaultMemoryImpl::default(), 1..NUM_WASM_PAGES)
}

thread_local! {
    /// Static configuration of the archive that init() sets once.
    static CONFIG: RefCell<ConfigCell> = RefCell::new(ConfigCell::init(
        config_memory(),
        ArchiveConfig::default(),
    ).expect("failed to initialize stable cell"));

    /// Append-only list of encoded blocks stored in stable memory.
    static BLOCKS: RefCell<BlockLog> = RefCell::new(BlockLog::init(
        blocks_memory(),
        MAX_BLOCKS as u32,
    ).expect("failed to initialize stable log"));
}

/// Configuration of the archive node.
#[derive(Serialize, Deserialize)]
struct ArchiveConfig {
    /// The maximum number of bytes archive can use to store encoded blocks.
    max_memory_size_bytes: usize,
    /// The index of the first block in the archive.
    block_index_offset: u64,
    /// The principal of the ledger canister that created this archive.
    /// The archive will accept blocks only from this principal.
    ledger_id: Principal,
}

// NOTE: the default configuration is dysfunctional, but it's convenient to have
// a Default impl for the initialization of the [CONFIG] variable above.
impl Default for ArchiveConfig {
    fn default() -> Self {
        Self {
            max_memory_size_bytes: 0,
            block_index_offset: 0,
            ledger_id: Principal::management_canister(),
        }
    }
}

impl Storable for ArchiveConfig {
    fn to_bytes(&self) -> Cow<[u8]> {
        let mut buf = vec![];
        ciborium::ser::into_writer(self, &mut buf).expect("failed to encode archive config");
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        ciborium::de::from_reader(&bytes[..]).expect("failed to decode archive options")
    }
}

/// A helper function to access the configuration.
fn with_archive_opts<R>(f: impl FnOnce(&ArchiveConfig) -> R) -> R {
    CONFIG.with(|cell| f(cell.borrow().get()))
}

/// A helper function to access the block list.
fn with_blocks<R>(f: impl FnOnce(&StableLog<Memory>) -> R) -> R {
    BLOCKS.with(|cell| f(&*cell.borrow()))
}

#[init]
#[candid_method(init)]
fn init(ledger_id: Principal, block_index_offset: u64, max_memory_size_bytes: Option<usize>) {
    let max_memory_size_bytes = CONFIG.with(|cell| {
        let max_memory_size_bytes = max_memory_size_bytes
            .unwrap_or(DEFAULT_MEMORY_LIMIT)
            .min(DEFAULT_MEMORY_LIMIT);
        cell.borrow_mut()
            .set(ArchiveConfig {
                max_memory_size_bytes,
                block_index_offset,
                ledger_id,
            })
            .expect("failed to set archive config");
        max_memory_size_bytes
    });

    BLOCKS.with(|cell| {
        *cell.borrow_mut() = BlockLog::new(
            blocks_memory(),
            (max_memory_size_bytes / MIN_BLOCK_SIZE).min(u32::MAX as usize) as u32,
        )
    });
}

#[post_upgrade]
fn post_upgrade() {
    // NB. we do not need to do anything to decode the values from the stable
    // memory: variable initializers take care of the decoding.  The only reason
    // we define the post_upgrade hook is to make sure that the first access to
    // stable variables happens in that hook.  This way the system will roll-back
    // the upgrade if the initialization traps.
    let max_memory_size_bytes = with_archive_opts(|opts| opts.max_memory_size_bytes);
    with_blocks(|blocks| assert!(blocks.size_bytes() <= max_memory_size_bytes));
}

#[update]
#[candid_method(update)]
fn append_blocks(new_blocks: Vec<EncodedBlock>) {
    let max_memory_size_bytes = with_archive_opts(|opts| {
        if ic_cdk::api::caller() != opts.ledger_id {
            ic_cdk::api::trap(&format!(
                "only {} can append blocks to this archive",
                opts.ledger_id
            ));
        }
        opts.max_memory_size_bytes
    });

    with_blocks(|blocks| {
        let bytes: usize = new_blocks.iter().map(|b| b.size_bytes()).sum();
        if max_memory_size_bytes < blocks.size_bytes().saturating_add(bytes) {
            ic_cdk::api::trap("no space left");
        }
        for block in new_blocks {
            blocks
                .append(block.as_slice())
                .unwrap_or_else(|_| ic_cdk::api::trap("no space left"));
        }
    })
}

#[query]
#[candid_method(query)]
fn remaining_capacity() -> usize {
    let total_block_size = with_blocks(|blocks| blocks.size_bytes());
    with_archive_opts(|opts| {
        opts.max_memory_size_bytes
            .checked_sub(total_block_size)
            .expect("bug: archive capacity underflow")
    })
}

#[query]
#[candid_method(query)]
fn get_block(index: BlockHeight) -> Option<CandidBlock> {
    let idx_offset = with_archive_opts(|opts| opts.block_index_offset);
    let relative_idx = (idx_offset < index).then(|| (index - idx_offset) as usize)?;

    let block = with_blocks(|blocks| blocks.get(relative_idx))?;
    Some(
        Block::decode(EncodedBlock::from(block))
            .unwrap_or_else(|e| {
                ic_cdk::api::trap(&format!("failed to decode block {}: {}", index, e))
            })
            .into(),
    )
}

fn main() {}

#[test]
fn check_candid_interface() {
    use candid::utils::{service_compatible, CandidSource};
    use std::path::PathBuf;

    candid::export_service!();

    let new_interface = __export_service();

    // check the public interface against the actual one
    let old_interface =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("archive.did");

    service_compatible(
        CandidSource::Text(&new_interface),
        CandidSource::File(old_interface.as_path()),
    )
    .expect("the ledger interface is not compatible with archive.did");
}
