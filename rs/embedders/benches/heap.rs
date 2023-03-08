use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use ic_replicated_state::canister_state::WASM_PAGE_SIZE_IN_BYTES;
use ic_sys::PAGE_SIZE;

const KB: usize = 1024;
const GB: usize = KB * KB * KB;
// The total size of accessed memory in bytes to calculate the throughput.
const BYTES: Option<Throughput> = Some(Throughput::Bytes(
    (GB * core::mem::size_of::<i32>() / PAGE_SIZE) as u64,
));

fn query_bench(c: &mut Criterion, name: &str, wasm: &[u8], method: &str) {
    embedders_bench::query_bench(c, name, wasm, &[], method, &[], BYTES);
}

fn update_bench(c: &mut Criterion, name: &str, wasm: &[u8], method: &str) {
    embedders_bench::update_bench(c, name, wasm, &[], method, &[], BYTES);
}

////////////////////////////////////////////////////////////////////////
// WAT
////////////////////////////////////////////////////////////////////////

enum Operation {
    Read,
    Write,
    ReadWrite,
}

fn heap_wat(
    op: Operation,
    memory_footprint: usize,
    initial_address: usize,
    address_delta: i32,
) -> String {
    let op = match op {
        Operation::Read => "(drop (i32.load (local.get $address)))",
        Operation::Write => "(i32.store (local.get $address) (local.get $i))",
        Operation::ReadWrite => {
            "(drop (i32.load (local.get $address))) \
            (i32.store (local.get $address) (local.get $i))"
        }
    };
    format!(
        r#"
        (module
            (import "ic0" "msg_reply" (func $ic0_msg_reply))

            (func $test
                (local $address i32)
                (local $i i32)

                (local.set $address (i32.const {initial_address}))
                (local.set $i (i32.const {num_iterations}))

                (loop $loop
                    {op}
                    ;; mutate the address
                    (local.set $address (i32.add (local.get $address) (i32.const {address_delta})))

                    (local.tee $i (i32.sub (local.get $i) (i32.const 1)))
                    (br_if $loop)
                )
                (call $ic0_msg_reply)
            )

            (func (export "canister_update update_test") (call $test))
            (func (export "canister_query query_test") (call $test))
            (func (export "canister_update update_empty") (call $ic0_msg_reply))
            (memory (export "memory") {wasm_pages})
        )
    "#,
        num_iterations = memory_footprint / PAGE_SIZE,
        wasm_pages = memory_footprint / WASM_PAGE_SIZE_IN_BYTES + 1,
    )
}

////////////////////////////////////////////////////////////////////////
// Reads
////////////////////////////////////////////////////////////////////////

fn update_heap_read_1g_4k_fwd(c: &mut Criterion) {
    let wasm = wat::parse_str(heap_wat(Operation::Read, GB, 0, PAGE_SIZE as i32)).unwrap();
    update_bench(c, "heap_read_1g_4k_fwd", &wasm, "update_test");
}

fn query_heap_read_1g_4k_fwd(c: &mut Criterion) {
    let wasm = wat::parse_str(heap_wat(Operation::Read, GB, 0, PAGE_SIZE as i32)).unwrap();
    query_bench(c, "heap_read_1g_4k_fwd", &wasm, "query_test");
}

fn update_heap_read_1g_4k_bwd(c: &mut Criterion) {
    let wasm = wat::parse_str(heap_wat(Operation::Read, GB, GB, -(PAGE_SIZE as i32))).unwrap();
    update_bench(c, "heap_read_1g_4k_bwd", &wasm, "update_test");
}

fn query_heap_read_1g_4k_bwd(c: &mut Criterion) {
    let wasm = wat::parse_str(heap_wat(Operation::Read, GB, GB, -(PAGE_SIZE as i32))).unwrap();
    query_bench(c, "heap_read_1g_4k_bwd", &wasm, "query_test");
}

////////////////////////////////////////////////////////////////////////
// Writes
////////////////////////////////////////////////////////////////////////

fn update_heap_write_1g_4k_fwd(c: &mut Criterion) {
    let wasm = wat::parse_str(heap_wat(Operation::Write, GB, 0, PAGE_SIZE as i32)).unwrap();
    update_bench(c, "heap_write_1g_4k_fwd", &wasm, "update_test");
}

fn query_heap_write_1g_4k_fwd(c: &mut Criterion) {
    let wasm = wat::parse_str(heap_wat(Operation::Write, GB, 0, PAGE_SIZE as i32)).unwrap();
    query_bench(c, "heap_write_1g_4k_fwd", &wasm, "query_test");
}

fn update_heap_write_1g_4k_bwd(c: &mut Criterion) {
    let wasm = wat::parse_str(heap_wat(Operation::Write, GB, GB, -(PAGE_SIZE as i32))).unwrap();
    update_bench(c, "heap_write_1g_4k_bwd", &wasm, "update_test");
}

fn query_heap_write_1g_4k_bwd(c: &mut Criterion) {
    let wasm = wat::parse_str(heap_wat(Operation::Write, GB, GB, -(PAGE_SIZE as i32))).unwrap();
    query_bench(c, "heap_write_1g_4k_bwd", &wasm, "query_test");
}

////////////////////////////////////////////////////////////////////////
// Reads/Writes
////////////////////////////////////////////////////////////////////////

fn update_heap_rw_1g_4k_fwd(c: &mut Criterion) {
    let wasm = wat::parse_str(heap_wat(Operation::ReadWrite, GB, 0, PAGE_SIZE as i32)).unwrap();
    update_bench(c, "heap_rw_1g_4k_fwd", &wasm, "update_test");
}

fn query_heap_rw_1g_4k_fwd(c: &mut Criterion) {
    let wasm = wat::parse_str(heap_wat(Operation::ReadWrite, GB, 0, PAGE_SIZE as i32)).unwrap();
    query_bench(c, "heap_rw_1g_4k_fwd", &wasm, "query_test");
}

fn update_heap_rw_1g_4k_bwd(c: &mut Criterion) {
    let wasm = wat::parse_str(heap_wat(Operation::ReadWrite, GB, GB, -(PAGE_SIZE as i32))).unwrap();
    update_bench(c, "heap_rw_1g_4k_bwd", &wasm, "update_test");
}

fn query_heap_rw_1g_4k_bwd(c: &mut Criterion) {
    let wasm = wat::parse_str(heap_wat(Operation::ReadWrite, GB, GB, -(PAGE_SIZE as i32))).unwrap();
    query_bench(c, "heap_rw_1g_4k_bwd", &wasm, "query_test");
}

////////////////////////////////////////////////////////////////////////
// Main
////////////////////////////////////////////////////////////////////////

criterion_group!(
    name = heap_benches;
    config = Criterion::default().sample_size(10);
    targets =
        update_heap_read_1g_4k_fwd, query_heap_read_1g_4k_fwd,
        update_heap_read_1g_4k_bwd, query_heap_read_1g_4k_bwd,
        update_heap_write_1g_4k_fwd, query_heap_write_1g_4k_fwd,
        update_heap_write_1g_4k_bwd, query_heap_write_1g_4k_bwd,
        update_heap_rw_1g_4k_fwd, query_heap_rw_1g_4k_fwd,
        update_heap_rw_1g_4k_bwd, query_heap_rw_1g_4k_bwd,
);

criterion_main!(heap_benches);
