use crate::state::GitCommitHash;
use crate::storage::{
    ArchiveWasm, IndexWasm, LedgerSuiteVersion, LedgerWasm, TaskQueue, WasmStore,
    record_icrc1_ledger_suite_wasms,
};
use ic_stable_structures::BTreeMap;
use ic_stable_structures::DefaultMemoryImpl;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager};

pub fn empty_wasm_store() -> WasmStore {
    WasmStore::init(MemoryManager::init(DefaultMemoryImpl::default()).get(MemoryId::new(0)))
}

pub fn wasm_store_with_icrc1_ledger_suite() -> WasmStore {
    const RECORDING_TIMESTAMP_NS: u64 = 1_620_328_630_000_000_000;
    let mut store = empty_wasm_store();
    assert_eq!(
        record_icrc1_ledger_suite_wasms(
            &mut store,
            RECORDING_TIMESTAMP_NS,
            GitCommitHash::default(),
        ),
        Ok(embedded_ledger_suite_version())
    );
    store
}

pub fn empty_task_queue() -> TaskQueue {
    TaskQueue {
        queue: BTreeMap::init(
            MemoryManager::init(DefaultMemoryImpl::default()).get(MemoryId::new(0)),
        ),
        deadline_by_task: BTreeMap::init(
            MemoryManager::init(DefaultMemoryImpl::default()).get(MemoryId::new(1)),
        ),
    }
}

pub fn embedded_ledger_suite_version() -> LedgerSuiteVersion {
    LedgerSuiteVersion {
        ledger_compressed_wasm_hash: LedgerWasm::from(crate::state::LEDGER_BYTECODE)
            .hash()
            .clone(),
        index_compressed_wasm_hash: IndexWasm::from(crate::state::INDEX_BYTECODE).hash().clone(),
        archive_compressed_wasm_hash: ArchiveWasm::from(crate::state::ARCHIVE_NODE_BYTECODE)
            .hash()
            .clone(),
    }
}
