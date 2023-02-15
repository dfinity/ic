use std::cell::RefCell;

use candid::Encode;
use canister_test::{CanisterId, CanisterInstallMode, Cycles, InstallCodeArgs};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};

use ic_replicated_state::canister_state::WASM_PAGE_SIZE_IN_BYTES;
use ic_sys::PAGE_SIZE;
use ic_test_utilities_execution_environment::{ExecutionTest, ExecutionTestBuilder};
use ic_types::ingress::WasmResult;

const INITIAL_NUMBER_OF_ENTRIES: u64 = 128 * 1024;
const ENTRIES_TO_CHANGE: u64 = 8 * 1024;
const KB: usize = 1024;
const NUM_OS_PAGES: usize = (512 * KB * KB) / PAGE_SIZE;

lazy_static::lazy_static! {
    static ref STABLE_STRUCTURES_CANISTER: Vec<u8> =
        canister_test::Project::cargo_bin_maybe_from_env("stable_structures_canister", &[]).bytes();

}

fn stable_read_write_wat() -> String {
    format!(
        r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "stable_grow"
                (func $stable_grow (param $pages i32) (result i32)))
            (import "ic0" "stable64_read"
                (func $stable_read (param $dst i64) (param $offset i64) (param $size i64)))
            (import "ic0" "stable64_write"
                (func $stable_write (param $offset i64) (param $src i64) (param $size i64)))

            (func $init (export "canister_init")
                (drop (call $stable_grow (i32.const {wasm_pages})))
            )

            (func $test (local $counter i64) (local $val i32)
                (loop $main
                    ;; read i32 from stable memory to address 0
                    (call $stable_read (i64.const 0) (local.get $counter) (i64.const 4))
                    ;; increment the value at address 0
                    (i32.store (i32.const 0) (i32.add (i32.const 1) (i32.load (i32.const 0))))
                    ;; write it back to stable memory
                    (call $stable_write (local.get $counter) (i64.const 0) (i64.const 4))
                    ;; increment the counter by the OS page size
                    (local.set $counter (i64.add (i64.const {page_size}) (local.get $counter)))
                    ;; go back to loop if counter is less than bound.
                    (br_if $main (i64.lt_s (local.get $counter) (i64.const {last_address})))
                    ;; reply to message
                    (call $msg_reply)
                )
            )

            (func (export "canister_update update_test") (call $test))
            (func (export "canister_query query_test") (call $test))
            (memory (export "memory") 1)
        )
    "#,
        wasm_pages = NUM_OS_PAGES / (WASM_PAGE_SIZE_IN_BYTES / PAGE_SIZE),
        page_size = PAGE_SIZE,
        last_address = NUM_OS_PAGES * PAGE_SIZE - 1,
    )
}

fn stable_write_repeat() -> String {
    format!(
        r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "stable_grow"
                (func $stable_grow (param $pages i32) (result i32)))
            (import "ic0" "stable64_read"
                (func $stable_read (param $dst i64) (param $offset i64) (param $size i64)))
            (import "ic0" "stable64_write"
                (func $stable_write (param $offset i64) (param $src i64) (param $size i64)))

            (func $init (export "canister_init")
                (drop (call $stable_grow (i32.const {wasm_pages})))
                ;; store a constant value at address 0.
                (i32.store (i32.const 0) (i32.const 123))
            )

            (func $test (local $counter i64)
                (local.set $counter (i64.const 0))
                (loop $main
                    ;; write value at address 0 back to stable memory
                    (call $stable_write (i64.const 0) (i64.const 0) (i64.const 4))
                    ;; increment the counter by one
                    (local.set $counter (i64.add (i64.const 1) (local.get $counter)))
                    ;; go back to loop if counter is less than bound.
                    (br_if $main (i64.lt_s (local.get $counter) (i64.const {loop_count})))
                    ;; reply to message
                    (call $msg_reply)
                )
            )

            (func (export "canister_update update_test") (call $test))
            (func (export "canister_query query_test") (call $test))
            (memory (export "memory") 1)
        )
    "#,
        wasm_pages = 4,
        loop_count = 10_000_000,
    )
}

fn initialize_execution_test(wasm: &[u8], cell: &RefCell<Option<(ExecutionTest, CanisterId)>>) {
    const LARGE_INSTRUCTION_LIMIT: u64 = 1_000_000_000_000;

    let mut current = cell.borrow_mut();
    if current.is_some() {
        return;
    }

    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(LARGE_INSTRUCTION_LIMIT)
        .with_instruction_limit_without_dts(LARGE_INSTRUCTION_LIMIT)
        .with_slice_instruction_limit(LARGE_INSTRUCTION_LIMIT)
        .build();
    let canister_id = test.create_canister(Cycles::from(1_u128 << 64));
    let args = InstallCodeArgs::new(
        CanisterInstallMode::Install,
        canister_id,
        wasm.to_vec(),
        Encode!(&INITIAL_NUMBER_OF_ENTRIES).unwrap(),
        None,
        None,
        None,
    );
    let _result = test.install_code(args).unwrap();
    *current = Some((test, canister_id));
}

fn update_bench(c: &mut Criterion, wasm: Vec<u8>, name: &str, method: &str, payload: &[u8]) {
    let cell = RefCell::new(None);

    c.bench_function(name, |bench| {
        bench.iter_batched(
            || initialize_execution_test(&wasm, &cell),
            |()| {
                let mut setup = cell.borrow_mut();
                let (test, canister_id) = setup.as_mut().unwrap();
                let result = test
                    .ingress(*canister_id, method, payload.to_vec())
                    .unwrap();
                assert!(matches!(result, WasmResult::Reply(_)));
            },
            BatchSize::SmallInput,
        );
    });
}

fn query_bench(c: &mut Criterion, wasm: Vec<u8>, name: &str, method: &str, payload: &[u8]) {
    let cell = RefCell::new(None);

    c.bench_function(name, |bench| {
        bench.iter_batched(
            || initialize_execution_test(&wasm, &cell),
            |()| {
                let mut setup = cell.borrow_mut();
                let (test, canister_id) = setup.as_mut().unwrap();
                let result = test
                    .anonymous_query(*canister_id, method, payload.to_vec())
                    .unwrap();
                assert!(matches!(result, WasmResult::Reply(_)));
            },
            BatchSize::SmallInput,
        );
    });
}

fn update_direct_read_write(c: &mut Criterion) {
    let wasm = wat::parse_str(stable_read_write_wat()).unwrap();
    update_bench(c, wasm, "update_direct_read_write", "update_test", &[]);
}

fn update_direct_write_single(c: &mut Criterion) {
    let wasm = wat::parse_str(stable_write_repeat()).unwrap();
    update_bench(c, wasm, "update_direct_write_single", "update_test", &[]);
}

fn update_btree_seq(c: &mut Criterion) {
    update_bench(
        c,
        STABLE_STRUCTURES_CANISTER.clone(),
        "update_btree_seq",
        "update_increment_values_seq",
        &Encode!(&ENTRIES_TO_CHANGE).unwrap(),
    );
}

fn update_btree_sparse(c: &mut Criterion) {
    update_bench(
        c,
        STABLE_STRUCTURES_CANISTER.clone(),
        "update_btree_sparse",
        "update_increment_values_sparse",
        &Encode!(
            &ENTRIES_TO_CHANGE,
            &(INITIAL_NUMBER_OF_ENTRIES / ENTRIES_TO_CHANGE)
        )
        .unwrap(),
    );
}

fn update_btree_single(c: &mut Criterion) {
    update_bench(
        c,
        STABLE_STRUCTURES_CANISTER.clone(),
        "update_btree_single",
        "update_increment_one_value",
        &Encode!(&(ENTRIES_TO_CHANGE as u32)).unwrap(),
    );
}

fn update_empty(c: &mut Criterion) {
    update_bench(
        c,
        STABLE_STRUCTURES_CANISTER.clone(),
        "update_empty",
        "update_empty",
        &Encode!(&()).unwrap(),
    );
}

fn query_direct_read_write(c: &mut Criterion) {
    let wasm = wat::parse_str(stable_read_write_wat()).unwrap();
    query_bench(c, wasm, "query_direct_read_write", "query_test", &[]);
}

fn query_direct_write_single(c: &mut Criterion) {
    let wasm = wat::parse_str(stable_write_repeat()).unwrap();
    query_bench(c, wasm, "query_direct_write_single", "query_test", &[]);
}

fn query_btree_seq(c: &mut Criterion) {
    query_bench(
        c,
        STABLE_STRUCTURES_CANISTER.clone(),
        "query_btree_seq",
        "query_increment_values_seq",
        &Encode!(&ENTRIES_TO_CHANGE).unwrap(),
    );
}

fn query_btree_sparse(c: &mut Criterion) {
    update_bench(
        c,
        STABLE_STRUCTURES_CANISTER.clone(),
        "query_btree_sparse",
        "query_increment_values_sparse",
        &Encode!(
            &ENTRIES_TO_CHANGE,
            &(INITIAL_NUMBER_OF_ENTRIES / ENTRIES_TO_CHANGE)
        )
        .unwrap(),
    );
}

fn query_btree_single(c: &mut Criterion) {
    query_bench(
        c,
        STABLE_STRUCTURES_CANISTER.clone(),
        "query_btree_single",
        "query_increment_one_value",
        &Encode!(&(ENTRIES_TO_CHANGE as u32)).unwrap(),
    );
}

fn query_empty(c: &mut Criterion) {
    query_bench(
        c,
        STABLE_STRUCTURES_CANISTER.clone(),
        "query_empty",
        "query_empty",
        &Encode!(&()).unwrap(),
    );
}

criterion_group!(
    name = update_benches;
    config = Criterion::default().sample_size(10);
    targets = update_direct_read_write, update_direct_write_single, update_btree_single, update_btree_seq, update_btree_sparse, update_empty
);

criterion_group!(
    name = query_benches;
    config = Criterion::default().sample_size(10);
    targets = query_direct_read_write, query_direct_write_single, query_btree_single, query_btree_seq, query_btree_sparse, query_empty
);

criterion_main!(update_benches, query_benches);
