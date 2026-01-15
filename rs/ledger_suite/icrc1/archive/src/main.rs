use candid::Principal;
use ic_cdk::{init, post_upgrade, query, update};
use ic_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_icrc1::{Block, blocks::encoded_block_to_generic_block};
use ic_ledger_canister_core::runtime::heap_memory_size_bytes;
use ic_ledger_core::block::{BlockIndex, BlockType, EncodedBlock};
use ic_stable_structures::memory_manager::{MemoryId, VirtualMemory};
use ic_stable_structures::{
    DefaultMemoryImpl, RestrictedMemory, Storable, cell::Cell as StableCell, log::Log as StableLog,
    memory_manager::MemoryManager, storable::Bound,
};
use icrc_ledger_types::icrc3::archive::{GetArchivesArgs, GetArchivesResult};
use icrc_ledger_types::icrc3::blocks::{BlockRange, GetBlocksRequest, GetBlocksResult};
use icrc_ledger_types::icrc3::blocks::{
    GenericBlock as IcrcBlock, ICRC3DataCertificate, SupportedBlockType,
};
use icrc_ledger_types::icrc107::schema::BTYPE_107;
use icrc_ledger_types::{icrc::generic_value::ICRC3Value, icrc3::blocks::BlockWithId};

use icrc_ledger_types::icrc3::transactions::Transaction;
use icrc_ledger_types::icrc3::transactions::{GetTransactionsRequest, TransactionRange};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::cell::RefCell;

#[cfg(not(feature = "u256-tokens"))]
type Tokens = ic_icrc1_tokens_u64::U64;

#[cfg(feature = "u256-tokens")]
type Tokens = ic_icrc1_tokens_u256::U256;

const WASM_PAGE_SIZE: u64 = 65536;

const GIB: u64 = 1024 * 1024 * 1024;

/// How much memory do we want to allocate for raw blocks.
const DEFAULT_MEMORY_LIMIT: u64 = 3 * GIB;

/// The maximum number of blocks to return in a single get_transactions request.
const DEFAULT_MAX_TRANSACTIONS_PER_GET_TRANSACTION_RESPONSE: u64 = 2000;

/// The maximum number of Wasm pages that we allow to use for the stable storage.
const NUM_WASM_PAGES: u64 = 4 * GIB / WASM_PAGE_SIZE;

const BLOCK_LOG_INDEX_MEMORY_ID: MemoryId = MemoryId::new(0);
const BLOCK_LOG_DATA_MEMORY_ID: MemoryId = MemoryId::new(1);

type Memory = RestrictedMemory<DefaultMemoryImpl>;
type BlockLog = StableLog<Vec<u8>, VirtualMemory<Memory>, VirtualMemory<Memory>>;
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

    /// Static memory manager to manage the memory available for blocks.
    static MEMORY_MANAGER: RefCell<MemoryManager<Memory>> = RefCell::new(MemoryManager::init(blocks_memory()));

    /// Append-only list of encoded blocks stored in stable memory.
    static BLOCKS: RefCell<BlockLog> = with_memory_manager(|memory_manager| {
        RefCell::new(BlockLog::init(memory_manager.get(BLOCK_LOG_INDEX_MEMORY_ID), memory_manager.get(BLOCK_LOG_DATA_MEMORY_ID)).expect("failed to initialize stable log"))
    });
}

/// Configuration of the archive node.
#[derive(Deserialize, Serialize, Clone)]
struct ArchiveConfig {
    /// The maximum number of bytes archive can use to store encoded blocks.
    max_memory_size_bytes: u64,
    /// The index of the first block in the archive.
    block_index_offset: u64,
    /// The principal of the ledger canister that created this archive.
    /// The archive will accept blocks only from this principal.
    ledger_id: Principal,
    /// The maximum number of transactions returned by [get_transactions].
    max_transactions_per_response: u64,
    /// The type of tokens this archive supports (U64 or U256).
    #[serde(default = "undefined_token_type")]
    pub token_type: String,
}

pub fn wasm_token_type() -> String {
    Tokens::TYPE.to_string()
}

pub fn undefined_token_type() -> String {
    "UNDEFINED".to_string()
}

// NOTE: the default configuration is dysfunctional, but it's convenient to have
// a Default impl for the initialization of the [CONFIG] variable above.
impl Default for ArchiveConfig {
    fn default() -> Self {
        Self {
            max_memory_size_bytes: 0,
            block_index_offset: 0,
            ledger_id: Principal::management_canister(),
            max_transactions_per_response: DEFAULT_MAX_TRANSACTIONS_PER_GET_TRANSACTION_RESPONSE,
            token_type: wasm_token_type(),
        }
    }
}

impl Storable for ArchiveConfig {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut buf = vec![];
        ciborium::ser::into_writer(self, &mut buf).expect("failed to encode archive config");
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        ciborium::de::from_reader(&bytes[..]).expect("failed to decode archive options")
    }

    const BOUND: Bound = Bound::Unbounded;
}

/// A helper function to access the configuration.
fn with_archive_opts<R>(f: impl FnOnce(&ArchiveConfig) -> R) -> R {
    CONFIG.with(|cell| f(cell.borrow().get()))
}

/// A helper function to access the memory manager.
fn with_memory_manager<R>(f: impl FnOnce(&MemoryManager<Memory>) -> R) -> R {
    MEMORY_MANAGER.with(|cell| f(&cell.borrow()))
}

/// A helper function to access the block list.
fn with_blocks<R>(f: impl FnOnce(&BlockLog) -> R) -> R {
    BLOCKS.with(|cell| f(&cell.borrow()))
}

fn decode_transaction(txid: u64, bytes: Vec<u8>) -> Transaction {
    Block::<Tokens>::decode(EncodedBlock::from(bytes))
        .unwrap_or_else(|e| ic_cdk::api::trap(format!("failed to decode block {txid}: {e}")))
        .into()
}

fn decode_icrc1_block(_txid: u64, bytes: Vec<u8>) -> IcrcBlock {
    let encoded_block = EncodedBlock::from(bytes);
    encoded_block_to_generic_block(&encoded_block)
}

#[init]
fn init(
    ledger_id: Principal,
    block_index_offset: u64,
    max_memory_size_bytes: Option<u64>,
    max_transactions_per_response: Option<u64>,
) {
    CONFIG.with(|cell| {
        let max_memory_size_bytes = max_memory_size_bytes
            .unwrap_or(DEFAULT_MEMORY_LIMIT)
            .min(DEFAULT_MEMORY_LIMIT);
        let max_transactions_per_response = max_transactions_per_response
            .unwrap_or(DEFAULT_MAX_TRANSACTIONS_PER_GET_TRANSACTION_RESPONSE);
        cell.borrow_mut()
            .set(ArchiveConfig {
                max_memory_size_bytes,
                block_index_offset,
                ledger_id,
                max_transactions_per_response,
                token_type: wasm_token_type(),
            })
            .expect("failed to set archive config");
    });

    MEMORY_MANAGER.with(|cell| *cell.borrow_mut() = MemoryManager::init(blocks_memory()));

    with_memory_manager(|memory_manager| {
        BLOCKS.with(|cell| {
            *cell.borrow_mut() = BlockLog::new(
                memory_manager.get(BLOCK_LOG_INDEX_MEMORY_ID),
                memory_manager.get(BLOCK_LOG_DATA_MEMORY_ID),
            )
        });
    })
}

/// Verifies that the `token_type` stored in the archive state is the same as to
/// `token_type` of the current wasm. If the archive state's `token_type` is undefined
/// it is set to the current wasm's `token_type`.
fn verify_token_type() {
    CONFIG.with(|cell| {
        let curr_conf = cell.borrow().get().clone();
        if curr_conf.token_type == undefined_token_type() {
            let new_conf = ArchiveConfig {
                token_type: wasm_token_type(),
                ..curr_conf
            };
            assert!(cell.borrow_mut().set(new_conf).is_ok());
        } else if curr_conf.token_type != wasm_token_type() {
            panic!("Incompatible token type, the upgraded archive token type is {}, current wasm token type is {}", curr_conf.token_type, wasm_token_type());
        }
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
    with_blocks(|blocks| assert!(blocks.log_size_bytes() <= max_memory_size_bytes));

    // Ensure that the archive is upgraded with the correct wasm (U64 or U256).
    // The check does not work if the archive is older and does not have
    // the `token_type` set in its config. In that case, `token_type`
    // is set to the current wasm's token type.
    verify_token_type();
}

#[update]
fn append_blocks(new_blocks: Vec<EncodedBlock>) {
    let max_memory_size_bytes = with_archive_opts(|opts| {
        if ic_cdk::api::msg_caller() != opts.ledger_id {
            ic_cdk::api::trap(format!(
                "only {} can append blocks to this archive",
                opts.ledger_id
            ));
        }
        opts.max_memory_size_bytes
    });

    with_blocks(|blocks| {
        let bytes: u64 = new_blocks.iter().map(|b| b.size_bytes() as u64).sum();
        if max_memory_size_bytes < blocks.log_size_bytes().saturating_add(bytes) {
            ic_cdk::api::trap("no space left");
        }
        for block in new_blocks {
            blocks
                .append(&block.into_vec())
                .unwrap_or_else(|_| ic_cdk::api::trap("no space left"));
        }
    })
}

#[query]
fn remaining_capacity() -> u64 {
    let total_block_size = with_blocks(|blocks| blocks.log_size_bytes());
    with_archive_opts(|opts| {
        opts.max_memory_size_bytes
            .checked_sub(total_block_size)
            .expect("bug: archive capacity underflow")
    })
}

#[query]
fn get_transaction(index: BlockIndex) -> Option<Transaction> {
    let idx_offset = with_archive_opts(|opts| opts.block_index_offset);
    let relative_idx = (idx_offset <= index).then_some(index - idx_offset)?;

    let block = with_blocks(|blocks| blocks.get(relative_idx))?;
    Some(decode_transaction(index, block))
}

fn decode_block_range<R>(start: u64, length: u64, decoder: impl Fn(u64, Vec<u8>) -> R) -> Vec<R> {
    let offset = with_archive_opts(|opts| {
        if start < opts.block_index_offset {
            ic_cdk::api::trap(format!(
                "requested index {} is less than the minimal index {} this archive serves",
                start, opts.block_index_offset
            ));
        }
        start - opts.block_index_offset
    });

    let length = length.min(with_archive_opts(|opts| opts.max_transactions_per_response));
    with_blocks(|blocks| {
        let limit = blocks.len().min(offset.saturating_add(length));
        (offset..limit)
            .map(|i| decoder(start + i, blocks.get(i).unwrap()))
            .collect()
    })
}

#[query]
fn get_transactions(req: GetTransactionsRequest) -> TransactionRange {
    let (start, length) = req
        .as_start_and_length()
        .unwrap_or_else(|msg| ic_cdk::api::trap(&msg));

    let transactions = decode_block_range(start, length, decode_transaction);
    TransactionRange { transactions }
}

/// Get length Blocks starting at start BlockIndex.
#[query]
fn get_blocks(req: GetTransactionsRequest) -> BlockRange {
    let (start, length) = req
        .as_start_and_length()
        .unwrap_or_else(|msg| ic_cdk::api::trap(&msg));

    let blocks = decode_block_range(start, length, decode_icrc1_block);
    BlockRange { blocks }
}

#[query]
fn icrc3_get_archives(_arg: GetArchivesArgs) -> GetArchivesResult {
    vec![]
}

#[query]
fn icrc3_get_tip_certificate() -> Option<ICRC3DataCertificate> {
    // Only the Ledger certifies the tip of the chain.
    None
}

#[query]
fn icrc3_supported_block_types() -> Vec<SupportedBlockType> {
    vec![
        SupportedBlockType {
            block_type: "1burn".to_string(),
            url: "https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-1/README.md"
                .to_string(),
        },
        SupportedBlockType {
            block_type: "1mint".to_string(),
            url: "https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-1/README.md"
                .to_string(),
        },
        SupportedBlockType {
            block_type: "1xfer".to_string(),
            url: "https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-1/README.md"
                .to_string(),
        },
        SupportedBlockType {
            block_type: "2approve".to_string(),
            url: "https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-2/README.md"
                .to_string(),
        },
        SupportedBlockType {
            block_type: "2xfer".to_string(),
            url: "https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-2/README.md"
                .to_string(),
        },
        SupportedBlockType {
            block_type: BTYPE_107.to_string(),
            url: "https://github.com/dfinity/ICRC/pull/117".to_string(),
        },
    ]
}

#[query]
fn icrc3_get_blocks(reqs: Vec<GetBlocksRequest>) -> GetBlocksResult {
    const MAX_BLOCKS_PER_RESPONSE: u64 = 100;

    let mut blocks = vec![];
    for req in reqs {
        let mut id = req.start.clone();
        let (start, length) = req
            .as_start_and_length()
            .unwrap_or_else(|msg| ic_cdk::api::trap(&msg));
        let max_length = MAX_BLOCKS_PER_RESPONSE.saturating_sub(blocks.len() as u64);
        if max_length == 0 {
            break;
        }
        let length = length.min(max_length);
        let decoded_block_range = decode_block_range(start, length, decode_icrc1_block);
        for block in decoded_block_range {
            blocks.push(BlockWithId {
                id: id.clone(),
                block: ICRC3Value::from(block),
            });
            id += 1u64;
        }
    }
    GetBlocksResult {
        // We return the local log length because the archive
        // knows only about its local blocks.
        log_length: candid::Nat::from(with_blocks(|blocks| blocks.len())),
        blocks,
        archived_blocks: vec![],
    }
}

#[query(hidden = true)]
fn __get_candid_interface_tmp_hack() -> &'static str {
    include_str!(env!("ARCHIVE_DID_PATH"))
}

fn encode_metrics(w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    w.encode_gauge(
        "archive_stable_memory_pages",
        ic_cdk::stable::stable_size() as f64,
        "Size of the stable memory allocated by this canister measured in 64K Wasm pages.",
    )?;
    w.encode_gauge(
        "stable_memory_bytes",
        ic_cdk::stable::stable_size() as f64 * 65536f64,
        "Size of the stable memory allocated by this canister measured in bytes.",
    )?;
    w.encode_gauge(
        "heap_memory_bytes",
        heap_memory_size_bytes() as f64,
        "Size of the heap memory allocated by this canister measured in bytes.",
    )?;

    let cycle_balance = ic_cdk::api::canister_cycle_balance() as f64;

    w.encode_gauge(
        "archive_cycle_balance",
        cycle_balance,
        "Cycle balance on this canister.",
    )?;

    w.gauge_vec("cycle_balance", "Cycle balance on this canister.")?
        .value(&[("canister", "icrc1-archive")], cycle_balance)?;

    w.encode_gauge(
        "archive_stored_blocks",
        with_blocks(|blocks| blocks.len()) as f64,
        "Total number of blocks stored in the main memory.",
    )?;

    Ok(())
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
    } else {
        HttpResponseBuilder::not_found().build()
    }
}

fn main() {}

#[test]
fn check_candid_interface() {
    use candid_parser::utils::{CandidSource, service_equal};
    use std::path::PathBuf;

    candid::export_service!();

    let new_interface = __export_service();

    // check the public interface against the actual one
    let old_interface =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("archive.did");

    service_equal(
        CandidSource::Text(&new_interface),
        CandidSource::File(old_interface.as_path()),
    )
    .expect("the ledger interface is not compatible with archive.did");
}

#[test]
fn check_archive_and_ledger_block_equality() {
    // check that ledger.did and archive.did agree on the block format
    let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let ledger_did_file = manifest_dir.join("../ledger/ledger.did");
    let archive_did_file = manifest_dir.join("archive.did");
    let mut ledger_env = candid_parser::utils::CandidSource::File(ledger_did_file.as_path())
        .load()
        .unwrap()
        .0;
    let archive_env = candid_parser::utils::CandidSource::File(archive_did_file.as_path())
        .load()
        .unwrap()
        .0;
    let ledger_block_type = ledger_env.find_type("Block").unwrap().to_owned();
    let archive_block_type = archive_env.find_type("Block").unwrap().to_owned();

    let mut gamma = std::collections::HashSet::new();
    let archive_block_type = ledger_env.merge_type(archive_env, archive_block_type.clone());
    candid::types::subtype::equal(
        &mut gamma,
        &ledger_env,
        &ledger_block_type,
        &archive_block_type,
    )
    .expect("Ledger and Archive block types are different");
}
