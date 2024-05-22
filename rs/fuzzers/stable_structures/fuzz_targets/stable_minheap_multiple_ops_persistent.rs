#![no_main]
use arbitrary::Arbitrary;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::Memory as OtherMemory;
use ic_stable_structures::{DefaultMemoryImpl, StableMinHeap};
use libfuzzer_sys::fuzz_target;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::fs::File;
use std::io::Write;
use std::time::SystemTime;
use tempfile::{tempdir, TempDir};

mod data;
// Unbouned is not supported for MinHeap
use data::{BoundedFuzzStruct, MAX_VALUE_SIZE};

type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static BOUNDED_MAP: RefCell<StableMinHeap<BoundedFuzzStruct, Memory>> = RefCell::new(
        StableMinHeap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
        )
        .expect("Unable to init Bounded StableMinHeap")
    );

    static DIR: TempDir = tempdir().unwrap();
    static OPS: RefCell<Vec<StableMinHeapOperation>>  = const { RefCell::new(vec![]) };
}

#[derive(Arbitrary, Debug, Serialize, Deserialize, Clone)]
enum StableMinHeapOperation {
    Push { value: Vec<u8> },
    Pop,
}

fuzz_target!(|ops: Vec<StableMinHeapOperation>| {
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
                serde_cbor::ser::to_vec::<Vec<StableMinHeapOperation>>(store.borrow().as_ref())
                    .unwrap();
            let file_name = format!(
                "stable_minheap_multiple_ops_persistent_operations_{}.txt",
                timestamp_nanos
            );
            DIR.with(|dir| {
                let file_path = dir.path().join(file_name);
                println!("Creating operations dump at {}", file_path.display());

                let mut f = File::create(file_path).unwrap();
                f.write_all(&buffer).unwrap();
            });
        });

        // memory dump
        MEMORY_MANAGER.with(|m| {
            let memory_0 = m.borrow().get(MemoryId::new(0));
            let mut buffer = vec![0; (memory_0.size() * 65536) as usize];
            memory_0.read(0, &mut buffer);

            let file_name = format!(
                "stable_minheap_multiple_ops_persistent_memory0_{}.txt",
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

    for op in ops {
        match op {
            StableMinHeapOperation::Push { value } => {
                let mut bounded_data = value.clone();
                bounded_data.truncate(MAX_VALUE_SIZE as usize);

                BOUNDED_MAP.with(|stable_minheap| {
                    let _ = stable_minheap
                        .borrow_mut()
                        .push(&BoundedFuzzStruct { data: bounded_data });
                });
            }
            StableMinHeapOperation::Pop => {
                BOUNDED_MAP.with(|stable_minheap| {
                    stable_minheap.borrow_mut().pop();
                });
            }
        }
    }
});
