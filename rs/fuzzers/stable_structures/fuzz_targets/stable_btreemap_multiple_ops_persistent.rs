#![no_main]
use arbitrary::Arbitrary;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::Memory as OtherMemory;
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use libfuzzer_sys::fuzz_target;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::fs::File;
use std::io::Write;
use std::time::SystemTime;
use tempfile::{tempdir, TempDir};

mod data;
use data::{BoundedFuzzStruct, UnboundedFuzzStruct, MAX_VALUE_SIZE};

const KEY_SIZE: usize = 4;
type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static BOUNDED_MAP: RefCell<StableBTreeMap<[u8; KEY_SIZE], BoundedFuzzStruct, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
        )
    );

    static UNBOUNDED_MAP: RefCell<StableBTreeMap<[u8; KEY_SIZE], UnboundedFuzzStruct, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))),
        )
    );

    static DIR: TempDir = tempdir().unwrap();
    static OPS: RefCell<Vec<StableBTreeOperation>>  = const { RefCell::new(vec![]) }
}

#[derive(Arbitrary, Debug, Clone, Serialize, Deserialize)]
enum StableBTreeOperation {
    Insert { key: [u8; KEY_SIZE], value: Vec<u8> },
    Remove { index: u16 },
    PopFirst,
    PopLast,
}

fuzz_target!(|ops: Vec<StableBTreeOperation>| {
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
        println!("{panic_info}");

        let duration_since_epoch = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        let timestamp_nanos = duration_since_epoch.as_nanos();

        // operations dump
        OPS.with(|store| {
            let buffer =
                serde_cbor::ser::to_vec::<Vec<StableBTreeOperation>>(store.borrow().as_ref())
                    .unwrap();
            let file_name = format!(
                "stable_btreemap_multiple_ops_persistent_operations_{}.txt",
                timestamp_nanos
            );
            DIR.with(|dir| {
                let file_path = dir.path().join(file_name);
                println!("Creating operations dump at {}", file_path.display());

                let mut f = File::create(file_path).unwrap();
                f.write_all(&buffer).unwrap();
            });
        });

        // memory dump 0
        MEMORY_MANAGER.with(|m| {
            let memory_0 = m.borrow().get(MemoryId::new(0));
            let mut buffer = vec![0; (memory_0.size() * 65536) as usize];
            memory_0.read(0, &mut buffer);

            let file_name = format!(
                "stable_btreemap_multiple_ops_persistent_memory0_{}.txt",
                timestamp_nanos
            );
            DIR.with(|dir| {
                let file_path = dir.path().join(file_name);
                println!("Creating memory dump at {}", file_path.display());

                let mut f = File::create(file_path).unwrap();
                f.write_all(&buffer).unwrap();
            });
        });

        // memory dump 1
        MEMORY_MANAGER.with(|m| {
            let memory_1 = m.borrow().get(MemoryId::new(1));
            let mut buffer = vec![0; (memory_1.size() * 65536) as usize];
            memory_1.read(0, &mut buffer);

            let file_name = format!(
                "stable_btreemap_multiple_ops_persistent_memory1_{}.txt",
                timestamp_nanos
            );
            DIR.with(|dir| {
                let file_path = dir.path().join(file_name);
                println!("Creating memory dump at {}", file_path.display());

                let mut f = File::create(file_path).unwrap();
                f.write_all(&buffer).unwrap();
            });
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
            StableBTreeOperation::Insert { key, value } => {
                let mut bounded_data = value.clone();
                bounded_data.truncate(MAX_VALUE_SIZE as usize);

                BOUNDED_MAP.with(|stable_btree| {
                    stable_btree
                        .borrow_mut()
                        .insert(key, BoundedFuzzStruct { data: bounded_data });
                });

                UNBOUNDED_MAP.with(|stable_btree| {
                    stable_btree
                        .borrow_mut()
                        .insert(key, UnboundedFuzzStruct { data: value });
                });

                remove_keys.push(key);
            }
            StableBTreeOperation::Remove { index } => {
                if remove_keys.is_empty() {
                    continue;
                }

                let key_index = index as usize % remove_keys.len();
                let key = remove_keys.remove(key_index);

                BOUNDED_MAP.with(|stable_btree| {
                    stable_btree.borrow_mut().remove(&key.clone());
                });

                UNBOUNDED_MAP.with(|stable_btree| {
                    stable_btree.borrow_mut().remove(&key.clone());
                });
            }
            StableBTreeOperation::PopFirst => {
                BOUNDED_MAP.with(|stable_btree| {
                    stable_btree.borrow_mut().pop_first();
                });

                UNBOUNDED_MAP.with(|stable_btree| {
                    stable_btree.borrow_mut().pop_first();
                });
            }
            StableBTreeOperation::PopLast => {
                BOUNDED_MAP.with(|stable_btree| {
                    stable_btree.borrow_mut().pop_last();
                });

                UNBOUNDED_MAP.with(|stable_btree| {
                    stable_btree.borrow_mut().pop_last();
                });
            }
        }
    }
});
