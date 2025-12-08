use criterion::Criterion;
use ic_base_types::{CanisterId, NumSeconds, PrincipalId};
use ic_replicated_state::{
    Memory,
    canister_state::{
        CanisterState, ExecutionState, ExportedFunctions, SchedulerState,
        execution_state::{WasmBinary, WasmMetadata},
        system_state::SystemState,
    },
};
use ic_state_machine_tests::StateMachine;
use ic_test_utilities_types::ids::canister_test_id;
use ic_types::Cycles;
use ic_wasm_types::CanisterModule;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::{
    collections::{BTreeMap, BTreeSet},
    hint::black_box,
};

const NUM_CREATOR_CANISTERS: usize = 10;
const NUM_CANISTERS_PER_CREATOR_CANISTER: usize = 10_000;

lazy_static::lazy_static! {
    static ref STATE_MACHINE: Arc<Mutex<StateMachine>> = {
        let env = StateMachine::new();
        let features = [];
        let wasm =
            canister_test::Project::cargo_bin_maybe_from_env("canister_creator_canister", &features);

        let mut canister_ids = vec![];
        for _ in 0..NUM_CREATOR_CANISTERS {
            let canister_id = env
                .install_canister_with_cycles(wasm.clone().bytes(), vec![], None, Cycles::new(1 << 64))
                .unwrap();
            canister_ids.push(canister_id);
        }

        println!("Creating 100k canisters. It may take a couple of minutes.");

        let mut ingress_ids = vec![];
        for canister_id in canister_ids.into_iter() {
            let ingress_id = env.send_ingress(
                PrincipalId::new_anonymous(),
                canister_id,
                "create_canisters",
                format!("{NUM_CANISTERS_PER_CREATOR_CANISTER}")
                    .as_bytes()
                    .to_vec(),
            );
            ingress_ids.push(ingress_id);
        }

        for ingress_id in ingress_ids.into_iter() {
            env.await_ingress(ingress_id, 1_000).unwrap();
        }
        Arc::new(Mutex::new(env))
    };
}

fn round(c: &mut Criterion) {
    c.bench_function("round", |bench| {
        let env = STATE_MACHINE.lock().unwrap();
        bench.iter_batched(
            || {
                env.set_checkpoints_enabled(false);
            },
            |_| {
                env.tick();
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn checkpoint(c: &mut Criterion) {
    c.bench_function("checkpoint", |bench| {
        let env = STATE_MACHINE.lock().unwrap();
        bench.iter_batched(
            || {
                env.set_checkpoints_enabled(true);
            },
            |_| {
                env.tick();
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn create_canister_state(canister_id: CanisterId) -> CanisterState {
    use ic_replicated_state::{NumWasmPages, page_map::PageMap};

    let controller = PrincipalId::new_user_test_id(1);
    let initial_cycles = Cycles::new(1_000_000_000);
    let freeze_threshold = NumSeconds::from(2592000); // 30 days

    let system_state = SystemState::new_running_for_testing(
        canister_id,
        controller,
        initial_cycles,
        freeze_threshold,
    );

    let wasm_binary = WasmBinary::new(CanisterModule::new(
        wat::parse_str("(module)").unwrap().into(),
    ));
    let exports = ExportedFunctions::new(BTreeSet::new());

    // Create wasm memory with some data (1 page of data with a pattern)
    let wasm_data = vec![0x42u8; 4096]; // 1 page (4KB) of data
    let wasm_page_map = PageMap::from(wasm_data.as_slice());
    let wasm_memory = Memory::new(wasm_page_map, NumWasmPages::from(1));

    // Create stable memory with some data (2 pages of data with a different pattern)
    let stable_data = vec![0xAAu8; 8192]; // 2 pages (8KB) of data
    let stable_page_map = PageMap::from(stable_data.as_slice());
    let stable_memory = Memory::new(stable_page_map, NumWasmPages::from(2));

    let exported_globals = vec![];
    let wasm_metadata = WasmMetadata::default();

    let execution_state = ExecutionState::new(
        PathBuf::from("/tmp"),
        wasm_binary,
        exports,
        wasm_memory,
        stable_memory,
        exported_globals,
        wasm_metadata,
    );

    let scheduler_state = SchedulerState::default();

    CanisterState::new(system_state, Some(execution_state), scheduler_state)
}

fn clone_100k_canisters(c: &mut Criterion) {
    let mut canisters = BTreeMap::new();

    c.bench_function("clone_100k_canisters", |bench| {
        if canisters.is_empty() {
            println!("Creating 100k canisters.");
            canisters = (0..100_000)
                .map(|i| {
                    (
                        canister_test_id(i),
                        create_canister_state(canister_test_id(i)),
                    )
                })
                .collect();
        }
        bench.iter(|| canisters.clone());
    });
}

fn clone_100k_memories(c: &mut Criterion) {
    use ic_replicated_state::{NumWasmPages, page_map::PageMap};

    let mut memories: Vec<Memory> = vec![];
    c.bench_function("clone_100k_memories", |bench| {
        if memories.is_empty() {
            println!("Creating 100k Memories.");
            // Create 100k Memories, each with 2 pages (8KB) of data
            memories = (0..100_000)
                .map(|_| {
                    let data = vec![0xAAu8; 8192]; // 2 pages (8KB) of data
                    let page_map = PageMap::from(data.as_slice());
                    Memory::new(page_map, NumWasmPages::from(2))
                })
                .collect();
        }

        bench.iter(|| {
            let _cloned = black_box(&memories).clone();
        });
    });
}

criterion::criterion_group! {
    name = bench_round;
    config = Criterion::default().sample_size(50);
    targets = round
}

criterion::criterion_group! {
    name = bench_checkpoint;
    config = Criterion::default().sample_size(10);
    targets = checkpoint
}

criterion::criterion_group! {
    name = bench_clone;
    config = Criterion::default().sample_size(10);
    targets = clone_100k_canisters, clone_100k_memories
}

criterion::criterion_main!(bench_round, bench_checkpoint, bench_clone);
