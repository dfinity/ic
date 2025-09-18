//! This benchmark runs nightly in CI, and the results are available in Grafana.
//! See: `schedule-rust-bench.yml`
//!
//! To run the benchmark locally:
//!
//! ```shell
//! bazel run //rs/embedders:stable_memory_bench
//! ```

use candid::Encode;
use criterion::{Criterion, criterion_group, criterion_main};
use embedders_bench::SetupAction;
use ic_replicated_state::canister_state::WASM_PAGE_SIZE_IN_BYTES;
use ic_sys::PAGE_SIZE;

/// Each entry should have a pair of u64's for the key and value so that makes
/// 256 entries be 4KiB page. So with these numbers each new lookup should
/// roughly touch a new page.
const BTREE_U64_INITIAL_NUMBER_OF_ENTRIES: u32 = 256 * 1024;
const BTREE_U64_ENTRIES_TO_HANDLE: u32 = 1024;

/// Again this should let each entry touched trigger a new page fault.
const VEC_U64_INITIAL_NUMBER_OF_ENTRIES: u32 = 32 * 1024 * 1024;
const VEC_U64_ENTRIES_TO_HANDLE: u32 = 64 * 1024;

const DIRECT_U64_INITIAL_NUMBER_OF_PAGES: u32 = 128 * 1024;
const DIRECT_U64_ENTRIES_TO_HANDLE: u32 = 128 * 1024;

lazy_static::lazy_static! {
    static ref STABLE_STRUCTURES_CANISTER: Vec<u8> =
        canister_test::Project::cargo_bin_maybe_from_env("stable_structures_canister", &[]).bytes();

}

fn direct_wat() -> String {
    format!(
        r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "stable64_grow"
                (func $stable_grow (param $pages i64) (result i64)))
            (import "ic0" "stable64_read"
                (func $stable_read (param $dst i64) (param $offset i64) (param $size i64)))
            (import "ic0" "stable64_write"
                (func $stable_write (param $offset i64) (param $src i64) (param $size i64)))

            (func $sparse_write (local $counter i64)
                (local.set $counter (i64.const 0))
                (i64.store (i32.const 0) (i64.const 55))
                (loop $main
                    ;; write value at address 0 back to a new page in stable memory
                    (call $stable_write (i64.mul (local.get $counter) (i64.const {PAGE_SIZE})) (i64.const 0) (i64.const 8))
                    ;; increment the counter by one
                    (local.set $counter (i64.add (i64.const 1) (local.get $counter)))
                    ;; go back to loop if counter is less than bound.
                    (br_if $main (i64.lt_s (local.get $counter) (i64.const {loop_count})))
                )
            )

            (func $init (export "canister_init")
                (drop (call $stable_grow (i64.const {wasm_pages})))
                ;; initialize the pages we will access with some data.
                (call $sparse_write)
            )

            (func (export "canister_query single_read") (local $counter i64)
                (local.set $counter (i64.const 0))
                (loop $main
                    ;; read value at address 0 from stable memory
                    (call $stable_read (i64.const 0) (i64.const 0) (i64.const 8))
                    ;; increment the counter by one
                    (local.set $counter (i64.add (i64.const 1) (local.get $counter)))
                    ;; go back to loop if counter is less than bound.
                    (br_if $main (i64.lt_s (local.get $counter) (i64.const {loop_count})))
                    ;; reply to message
                    (call $msg_reply)
                )
            )

            (func (export "canister_query sparse_read") (local $counter i64)
                (local.set $counter (i64.const 0))
                (loop $main
                    ;; read value at address 0 from a new page in stable memory
                    (call $stable_read (i64.const 0) (i64.mul (local.get $counter) (i64.const {PAGE_SIZE})) (i64.const 8))
                    ;; increment the counter by one
                    (local.set $counter (i64.add (i64.const 1) (local.get $counter)))
                    ;; go back to loop if counter is less than bound.
                    (br_if $main (i64.lt_s (local.get $counter) (i64.const {loop_count})))
                    ;; reply to message
                    (call $msg_reply)
                )
            )

            (func (export "canister_update single_write") (local $counter i64)
                (local.set $counter (i64.const 0))
                (i64.store (i32.const 0) (i64.const 55))
                (loop $main
                    ;; write value at address 0 back to stable memory
                    (call $stable_write (i64.const 0) (i64.const 0) (i64.const 8))
                    ;; increment the counter by one
                    (local.set $counter (i64.add (i64.const 1) (local.get $counter)))
                    ;; go back to loop if counter is less than bound.
                    (br_if $main (i64.lt_s (local.get $counter) (i64.const {loop_count})))
                    ;; reply to message
                    (call $msg_reply)
                )
            )

            (func (export "canister_update sparse_write") (local $counter i64)
                (call $sparse_write)
                ;; reply to message
                (call $msg_reply)
            )

            (func (export "canister_query large_read")
                (call $stable_read (i64.const 0) (i64.const 0) (i64.const {large_read_data_size}))
                (call $msg_reply)
            )

            (func (export "canister_update large_write")
                (call $stable_write (i64.const 0) (i64.const 0) (i64.const {large_write_data_size}))
                (call $msg_reply)
            )

            (func (export "canister_update update_empty") (call $msg_reply))
            (memory (export "memory") {initial_memory})
        )
    "#,
        wasm_pages = DIRECT_U64_INITIAL_NUMBER_OF_PAGES / 16 + 1, // 16 OS pages in a wasm page
        loop_count = DIRECT_U64_ENTRIES_TO_HANDLE,
        large_write_data_size = 2 * 1024 * 1024, // 2 MiB
        large_read_data_size = 20 * 1024 * 1024, // 20 MiB
        initial_memory = 20 * 1024 * 1024 / WASM_PAGE_SIZE_IN_BYTES,
    )
}

fn query_bench(
    c: &mut Criterion,
    name: &str,
    wasm: &[u8],
    structure: &str,
    initial_count: u32,
    method: &str,
    payload: &[u8],
) {
    embedders_bench::query_bench(
        c,
        "embedders:stable_memory/query",
        name,
        wasm,
        &Encode!(&structure, &initial_count).unwrap(),
        method,
        payload,
        None,
        SetupAction::PerformCheckpoint,
    )
}

fn update_bench(
    c: &mut Criterion,
    name: &str,
    wasm: &[u8],
    structure: &str,
    initial_count: u32,
    method: &str,
    payload: &[u8],
) {
    embedders_bench::update_bench(
        c,
        "embedders:stable_memory/update",
        name,
        wasm,
        &Encode!(&structure, &initial_count).unwrap(),
        method,
        payload,
        None,
        SetupAction::PerformCheckpoint,
    )
}

fn direct_u64_single_read(c: &mut Criterion) {
    query_bench(
        c,
        "direct_u64_single_read",
        &wat::parse_str(direct_wat()).unwrap(),
        "",
        0,
        "single_read",
        &[],
    );
}

fn direct_u64_sparse_read(c: &mut Criterion) {
    query_bench(
        c,
        "direct_u64_sparse_read",
        &wat::parse_str(direct_wat()).unwrap(),
        "",
        0,
        "sparse_read",
        &[],
    );
}

fn direct_u64_single_write(c: &mut Criterion) {
    update_bench(
        c,
        "direct_u64_single_write",
        &wat::parse_str(direct_wat()).unwrap(),
        "",
        0,
        "single_write",
        &[],
    );
}

fn direct_u64_sparse_write(c: &mut Criterion) {
    update_bench(
        c,
        "direct_u64_sparse_write",
        &wat::parse_str(direct_wat()).unwrap(),
        "",
        0,
        "sparse_write",
        &[],
    );
}

fn direct_2mb_write(c: &mut Criterion) {
    update_bench(
        c,
        "direct_2mb_write",
        &wat::parse_str(direct_wat()).unwrap(),
        "",
        0,
        "large_write",
        &[],
    );
}

fn direct_20mb_read(c: &mut Criterion) {
    query_bench(
        c,
        "direct_20mb_read",
        &wat::parse_str(direct_wat()).unwrap(),
        "",
        0,
        "large_read",
        &[],
    );
}

fn btree_u64_single_read(c: &mut Criterion) {
    query_bench(
        c,
        "btree_u64_single_read",
        &STABLE_STRUCTURES_CANISTER.clone(),
        "btree_u64",
        BTREE_U64_INITIAL_NUMBER_OF_ENTRIES,
        "query_btree_u64_single_read",
        &Encode!(&BTREE_U64_ENTRIES_TO_HANDLE).unwrap(),
    );
}

fn btree_u64_sparse_read(c: &mut Criterion) {
    query_bench(
        c,
        "btree_u64_sparse_read",
        &STABLE_STRUCTURES_CANISTER.clone(),
        "btree_u64",
        BTREE_U64_INITIAL_NUMBER_OF_ENTRIES,
        "query_btree_u64_sparse_read",
        &Encode!(&BTREE_U64_ENTRIES_TO_HANDLE).unwrap(),
    );
}

fn btree_u64_single_write(c: &mut Criterion) {
    update_bench(
        c,
        "btree_u64_single_write",
        &STABLE_STRUCTURES_CANISTER.clone(),
        "btree_u64",
        BTREE_U64_INITIAL_NUMBER_OF_ENTRIES,
        "update_btree_u64_single_write",
        &Encode!(&BTREE_U64_ENTRIES_TO_HANDLE).unwrap(),
    );
}

fn btree_u64_sparse_write(c: &mut Criterion) {
    update_bench(
        c,
        "btree_u64_sparse_write",
        &STABLE_STRUCTURES_CANISTER.clone(),
        "btree_u64",
        BTREE_U64_INITIAL_NUMBER_OF_ENTRIES,
        "update_btree_u64_sparse_write",
        &Encode!(&BTREE_U64_ENTRIES_TO_HANDLE).unwrap(),
    );
}

fn vec_u64_single_read(c: &mut Criterion) {
    query_bench(
        c,
        "vec_u64_single_read",
        &STABLE_STRUCTURES_CANISTER.clone(),
        "vec_u64",
        VEC_U64_INITIAL_NUMBER_OF_ENTRIES,
        "query_vec_u64_single_read",
        &Encode!(&VEC_U64_ENTRIES_TO_HANDLE).unwrap(),
    );
}

fn vec_u64_sparse_read(c: &mut Criterion) {
    query_bench(
        c,
        "vec_u64_sparse_read",
        &STABLE_STRUCTURES_CANISTER.clone(),
        "vec_u64",
        VEC_U64_INITIAL_NUMBER_OF_ENTRIES,
        "query_vec_u64_sparse_read",
        &Encode!(&VEC_U64_ENTRIES_TO_HANDLE).unwrap(),
    );
}

fn vec_u64_single_write(c: &mut Criterion) {
    update_bench(
        c,
        "vec_u64_single_write",
        &STABLE_STRUCTURES_CANISTER.clone(),
        "vec_u64",
        VEC_U64_INITIAL_NUMBER_OF_ENTRIES,
        "update_vec_u64_single_write",
        &Encode!(&VEC_U64_ENTRIES_TO_HANDLE).unwrap(),
    );
}

fn vec_u64_sparse_write(c: &mut Criterion) {
    update_bench(
        c,
        "vec_u64_sparse_write",
        &STABLE_STRUCTURES_CANISTER.clone(),
        "vec_u64",
        VEC_U64_INITIAL_NUMBER_OF_ENTRIES,
        "update_vec_u64_sparse_write",
        &Encode!(&VEC_U64_ENTRIES_TO_HANDLE).unwrap(),
    );
}

criterion_group!(
    name = benches10;
    config = Criterion::default().sample_size(10);
    targets = direct_u64_sparse_write, vec_u64_sparse_write,
);

criterion_group!(
    name = benches100;
    config = Criterion::default().sample_size(100);
    targets = direct_u64_single_read, direct_u64_sparse_read, direct_u64_single_write, direct_20mb_read,
      direct_2mb_write, btree_u64_single_read, btree_u64_sparse_read, btree_u64_single_write, btree_u64_sparse_write,
      vec_u64_single_read, vec_u64_sparse_read, vec_u64_single_write,
);

criterion_main!(benches10, benches100);
