use candid::{candid_method, Principal};
use ic_cdk::api::stable::{StableReader, StableWriter};
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};
use ic_ledger_core::block::EncodedBlock;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;

thread_local! {
    static STATE: RefCell<Option<ArchiveState>> = RefCell::new(None);
}

const DEFAULT_MEMORY_LIMIT: usize = 1024 * 1024 * 1024;

fn with_archive<R>(f: impl FnOnce(&ArchiveState) -> R) -> R {
    STATE.with(|cell| {
        f(cell
            .borrow()
            .as_ref()
            .expect("bug: archive state is not initialized"))
    })
}

fn with_archive_mut<R>(f: impl FnOnce(&mut ArchiveState) -> R) -> R {
    STATE.with(|cell| {
        f(cell
            .borrow_mut()
            .as_mut()
            .expect("bug: archive state is not initialized"))
    })
}

#[derive(Serialize, Deserialize)]
struct ArchiveState {
    max_memory_size_bytes: usize,
    block_index_offset: u64,
    blocks: Vec<EncodedBlock>,
    total_block_size: usize,
    ledger_id: Principal,
}

#[init]
#[candid_method(init)]
fn init(ledger_id: Principal, block_index_offset: u64, max_memory_size_bytes: Option<usize>) {
    STATE.with(|cell| {
        *cell.borrow_mut() = Some(ArchiveState {
            max_memory_size_bytes: max_memory_size_bytes.unwrap_or(DEFAULT_MEMORY_LIMIT),
            block_index_offset,
            blocks: vec![],
            total_block_size: 0,
            ledger_id,
        })
    });
}

#[pre_upgrade]
fn pre_upgrade() {
    with_archive(|archive| {
        ciborium::ser::into_writer(archive, StableWriter::default())
            .expect("failed to encode archive state")
    });
}

#[post_upgrade]
fn post_upgrade() {
    STATE.with(|cell| {
        *cell.borrow_mut() = Some(
            ciborium::de::from_reader(StableReader::default())
                .expect("failed to decode archive state"),
        );
    })
}

#[update]
#[candid_method(update)]
fn append_blocks(mut blocks: Vec<EncodedBlock>) {
    with_archive_mut(|state| {
        if ic_cdk::api::caller() != state.ledger_id {
            ic_cdk::api::trap(&format!(
                "only {} can append blocks to this archive",
                state.ledger_id
            ));
        }
        let bytes: usize = blocks.iter().map(|b| b.size_bytes()).sum();
        if state.max_memory_size_bytes < state.total_block_size.saturating_add(bytes) {
            ic_cdk::api::trap("no space left");
        }
        state.total_block_size += bytes;
        state.blocks.append(&mut blocks);
    })
}

#[query]
#[candid_method(query)]
fn remaining_capacity() -> usize {
    with_archive(|state| {
        state
            .max_memory_size_bytes
            .checked_sub(state.total_block_size)
            .expect("bug: archive capacity underflow")
    })
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
