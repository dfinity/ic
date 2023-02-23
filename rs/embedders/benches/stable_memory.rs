use candid::Encode;
use criterion::{criterion_group, criterion_main, Criterion};
use embedders_bench::{query_bench, update_bench};
use ic_replicated_state::canister_state::WASM_PAGE_SIZE_IN_BYTES;
use ic_sys::PAGE_SIZE;

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

fn update_direct_read_write(c: &mut Criterion) {
    let wasm = wat::parse_str(stable_read_write_wat()).unwrap();
    update_bench(c, wasm, "direct_read_write", "update_test", &[], None);
}

fn update_direct_write_single(c: &mut Criterion) {
    let wasm = wat::parse_str(stable_write_repeat()).unwrap();
    update_bench(c, wasm, "direct_write_single", "update_test", &[], None);
}

fn update_btree_seq(c: &mut Criterion) {
    update_bench(
        c,
        STABLE_STRUCTURES_CANISTER.clone(),
        "btree_seq",
        "update_increment_values_seq",
        &Encode!(&ENTRIES_TO_CHANGE).unwrap(),
        None,
    );
}

fn update_btree_sparse(c: &mut Criterion) {
    update_bench(
        c,
        STABLE_STRUCTURES_CANISTER.clone(),
        "btree_sparse",
        "update_increment_values_sparse",
        &Encode!(
            &ENTRIES_TO_CHANGE,
            &(INITIAL_NUMBER_OF_ENTRIES / ENTRIES_TO_CHANGE)
        )
        .unwrap(),
        None,
    );
}

fn update_btree_single(c: &mut Criterion) {
    update_bench(
        c,
        STABLE_STRUCTURES_CANISTER.clone(),
        "btree_single",
        "update_increment_one_value",
        &Encode!(&(ENTRIES_TO_CHANGE as u32)).unwrap(),
        None,
    );
}

fn update_empty(c: &mut Criterion) {
    update_bench(
        c,
        STABLE_STRUCTURES_CANISTER.clone(),
        "empty",
        "update_empty",
        &Encode!(&()).unwrap(),
        None,
    );
}

fn query_direct_read_write(c: &mut Criterion) {
    let wasm = wat::parse_str(stable_read_write_wat()).unwrap();
    query_bench(c, wasm, "direct_read_write", "query_test", &[], None);
}

fn query_direct_write_single(c: &mut Criterion) {
    let wasm = wat::parse_str(stable_read_write_wat()).unwrap();
    query_bench(c, wasm, "direct_write_single", "query_test", &[], None);
}

fn query_btree_seq(c: &mut Criterion) {
    query_bench(
        c,
        STABLE_STRUCTURES_CANISTER.clone(),
        "btree_seq",
        "query_increment_values_seq",
        &Encode!(&ENTRIES_TO_CHANGE).unwrap(),
        None,
    );
}

fn query_btree_sparse(c: &mut Criterion) {
    update_bench(
        c,
        STABLE_STRUCTURES_CANISTER.clone(),
        "btree_sparse",
        "query_increment_values_sparse",
        &Encode!(
            &ENTRIES_TO_CHANGE,
            &(INITIAL_NUMBER_OF_ENTRIES / ENTRIES_TO_CHANGE)
        )
        .unwrap(),
        None,
    );
}

fn query_btree_single(c: &mut Criterion) {
    query_bench(
        c,
        STABLE_STRUCTURES_CANISTER.clone(),
        "btree_single",
        "query_increment_one_value",
        &Encode!(&(ENTRIES_TO_CHANGE as u32)).unwrap(),
        None,
    );
}

fn query_empty(c: &mut Criterion) {
    query_bench(
        c,
        STABLE_STRUCTURES_CANISTER.clone(),
        "empty",
        "query_empty",
        &Encode!(&()).unwrap(),
        None,
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
