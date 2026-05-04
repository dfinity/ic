#![no_main]
use arbitrary::Arbitrary;
use ic_stable_structures::Memory as OtherMemory;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, StableMinHeap, StableVec};
use libfuzzer_sys::fuzz_target;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::fs::File;
use std::io::Write;
use std::time::SystemTime;
use tempfile::{Builder, TempDir};

mod data;
use data::{BoundedFuzzStruct, MAX_VALUE_SIZE, UnboundedFuzzStruct};

const KEY_SIZE: usize = 4;
type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static BOUNDED_BTREEMAP: RefCell<StableBTreeMap<[u8; KEY_SIZE], BoundedFuzzStruct, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
        )
    );

    static UNBOUNDED_BTREEMAP: RefCell<StableBTreeMap<[u8; KEY_SIZE], UnboundedFuzzStruct, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))),
        )
    );

    static BOUNDED_MINHEAP: RefCell<StableMinHeap<BoundedFuzzStruct, Memory>> = RefCell::new(
        StableMinHeap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2))),
        )
        .expect("Unable to init bounded StableMinHeap")
    );

    static BOUNDED_VEC: RefCell<StableVec<BoundedFuzzStruct, Memory>> = RefCell::new(
        StableVec::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3))),
        )
        .expect("Unable to init bounded StableVec")
    );

    static DIR: TempDir = Builder::new().prefix("stable_structures_multiple_ops_persistent").tempdir().unwrap();
    static OPS: RefCell<Vec<StableStructOperation>>  = const { RefCell::new(vec![]) }
}

#[derive(Clone, Debug, Arbitrary, Deserialize, Serialize)]
enum StableStructOperation {
    BTreeMapInsert { key: [u8; KEY_SIZE], value: Vec<u8> },
    BTreeMapRemove { index: u16 },
    BTreeMapPopFirst,
    BTreeMapPopLast,
    MinHeapPush { value: Vec<u8> },
    MinHeapPop,
    VecPush { value: Vec<u8> },
    VecPop,
}

fuzz_target!(|ops: Vec<StableStructOperation>| {
    // A new panic hook is registered to override the one set by libfuzzer which
    // aborts by default. This is done because,
    //
    // The fuzzer maintains state via thread_local! store and on discovering a crash, AFL only
    // records the last set of operations that caused the crash. These operations are however
    // useless without the existing memory state.
    //
    // To overcome this, every operation performed is stored in another persisted store OPS and
    // are dumped to a file along with the memory on a panic. This allows us to reproduce the crash
    // by replaying the operations.
    //
    // Note: This method only works if the code panics. To record multiple inputs for all forms of
    // crash, look into AFL_PERSISTENT_RECORD. (https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.persistent_mode.md#6-persistent-record-and-replay)

    std::panic::set_hook(Box::new(move |panic_info| {
        eprintln!("{panic_info}");

        let duration_since_epoch = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        let timestamp_nanos = duration_since_epoch.as_nanos();

        // operations dump
        OPS.with(|store| {
            let buffer =
                serde_cbor::ser::to_vec::<Vec<StableStructOperation>>(store.borrow().as_ref())
                    .unwrap();
            let file_name = format!("ops_{}.txt", timestamp_nanos);
            DIR.with(|dir| {
                let file_path = dir.path().join(file_name);
                eprintln!("Creating operations dump at {}", file_path.display());

                let mut f = File::create(file_path).unwrap();
                f.write_all(&buffer).unwrap();
            });
        });

        // memory dump
        MEMORY_MANAGER.with(|m| {
            for memory_index in 0..=3 {
                let memory = m.borrow().get(MemoryId::new(memory_index));
                let mut buffer = vec![0; (memory.size() * 65536) as usize];
                memory.read(0, &mut buffer);

                let file_name = format!("memory{}_{}.txt", memory_index, timestamp_nanos);
                DIR.with(|dir| {
                    let file_path = dir.path().join(file_name);
                    eprintln!("Creating memory dump at {}", file_path.display());

                    let mut f = File::create(file_path).unwrap();
                    f.write_all(&buffer).unwrap();
                });
            }
        });

        std::process::abort();
    }));

    if ops.is_empty() {
        return;
    }

    OPS.with(|store| {
        store.borrow_mut().extend(ops.clone());
    });

    let mut remove_keys: Vec<[u8; KEY_SIZE]> = Vec::new();

    for op in ops {
        match op {
            StableStructOperation::BTreeMapInsert { key, value } => {
                let mut bounded_data = value.clone();
                bounded_data.truncate(MAX_VALUE_SIZE as usize);

                BOUNDED_BTREEMAP.with_borrow_mut(|stable_btree| {
                    stable_btree.insert(key, BoundedFuzzStruct { data: bounded_data });
                });

                UNBOUNDED_BTREEMAP.with_borrow_mut(|stable_btree| {
                    stable_btree.insert(key, UnboundedFuzzStruct { data: value });
                });

                remove_keys.push(key);
            }
            StableStructOperation::BTreeMapRemove { index } => {
                if remove_keys.is_empty() {
                    continue;
                }

                let key_index = index as usize % remove_keys.len();
                let key = remove_keys.remove(key_index);

                BOUNDED_BTREEMAP.with_borrow_mut(|stable_btree| {
                    stable_btree.remove(&key.clone());
                });

                UNBOUNDED_BTREEMAP.with_borrow_mut(|stable_btree| {
                    stable_btree.remove(&key.clone());
                });
            }
            StableStructOperation::BTreeMapPopFirst => {
                BOUNDED_BTREEMAP.with_borrow_mut(|stable_btree| {
                    stable_btree.pop_first();
                });

                UNBOUNDED_BTREEMAP.with_borrow_mut(|stable_btree| {
                    stable_btree.pop_first();
                });
            }
            StableStructOperation::BTreeMapPopLast => {
                BOUNDED_BTREEMAP.with_borrow_mut(|stable_btree| {
                    stable_btree.pop_last();
                });

                UNBOUNDED_BTREEMAP.with_borrow_mut(|stable_btree| {
                    stable_btree.pop_last();
                });
            }
            StableStructOperation::MinHeapPush { value } => {
                let mut bounded_data = value.clone();
                bounded_data.truncate(MAX_VALUE_SIZE as usize);

                BOUNDED_MINHEAP.with_borrow_mut(|stable_minheap| {
                    let _ = stable_minheap.push(&BoundedFuzzStruct { data: bounded_data });
                });
            }
            StableStructOperation::MinHeapPop => {
                BOUNDED_MINHEAP.with_borrow_mut(|stable_minheap| {
                    stable_minheap.pop();
                });
            }
            StableStructOperation::VecPush { value } => {
                let mut bounded_data = value.clone();
                bounded_data.truncate(MAX_VALUE_SIZE as usize);

                BOUNDED_VEC.with_borrow_mut(|stable_vec| {
                    let _ = stable_vec.push(&BoundedFuzzStruct { data: bounded_data });
                });
            }
            StableStructOperation::VecPop => {
                BOUNDED_VEC.with_borrow_mut(|stable_vec| {
                    stable_vec.pop();
                });
            }
        }
    }
});
