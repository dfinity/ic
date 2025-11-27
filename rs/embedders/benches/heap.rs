//! This benchmark runs nightly in CI, and the results are available in Grafana.
//! See: `schedule-rust-bench.yml`
//!
//! To run the benchmark locally:
//!
//! ```shell
//! bazel run //rs/embedders:heap_bench
//! ```

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use embedders_bench::SetupAction;
use ic_replicated_state::canister_state::WASM_PAGE_SIZE_IN_BYTES;
use ic_sys::PAGE_SIZE;
use strum::IntoEnumIterator;
use strum_macros::{Display, EnumIter};

#[derive(Copy, Clone, Display, EnumIter)]
enum Mem {
    #[strum(serialize = "32")]
    Wasm32,
    #[strum(serialize = "64")]
    Wasm64,
}

#[derive(Copy, Clone, Display, EnumIter)]
#[strum(serialize_all = "snake_case")]
enum Call {
    Query,
    Update,
}

#[derive(Copy, Clone, Display, EnumIter)]
#[strum(serialize_all = "snake_case")]
enum Op {
    Read,
    Write,
}

#[derive(Copy, Clone, Display, EnumIter)]
#[strum(serialize_all = "snake_case")]
enum Dir {
    Fwd,
    Bwd,
}

#[derive(Copy, Clone, Display, EnumIter)]
enum Size {
    // One tenth of a gigabyte.
    // The results do not scale linearly 10x to 1 GiB. Some benchmarks regress ~15x,
    // while others regress ~5x. Yet, it is still a good approximation for the sake of
    // benchmarking speed.
    #[strum(serialize = "102m")]
    TenthOfGigabyte = 102 * 1024 * 1024,
}

#[derive(Copy, Clone, Display, EnumIter)]
enum Step {
    #[strum(serialize = "step_1")]
    OneByte = 1,
    #[strum(serialize = "step_4k")]
    Page = PAGE_SIZE as isize,
    #[strum(serialize = "step_8k")]
    TwoPages = 2 * PAGE_SIZE as isize,
    #[strum(serialize = "step_64k")]
    WasmPage = WASM_PAGE_SIZE_IN_BYTES as isize,
    #[strum(serialize = "step_128k")]
    TwoWasmPages = 2 * WASM_PAGE_SIZE_IN_BYTES as isize,
    #[strum(serialize = "step_2m")]
    HugePage = 2 * 1024 * 1024,
    #[strum(serialize = "step_4m")]
    TwoHugePages = 2 * 2 * 1024 * 1024,
}

#[derive(Copy, Clone, Display, EnumIter)]
#[strum(serialize_all = "snake_case")]
enum Src {
    Checkpoint,
    PageDelta,
    Mix,
    NewAllocation,
}

// Returns the number of accessed pages for throughput computation.
fn throughput(size: Size, step: Step) -> Option<Throughput> {
    let size = size as usize;
    let step = step as usize;
    let pages_in_step = step.div_ceil(PAGE_SIZE);
    Some(Throughput::Elements(
        (size / PAGE_SIZE / pages_in_step) as u64,
    ))
}

fn setup_action(src: Src) -> SetupAction {
    match src {
        Src::Checkpoint => SetupAction::PerformCheckpoint,
        Src::Mix => SetupAction::PerformCheckpointCallSetup,
        Src::PageDelta | Src::NewAllocation => SetupAction::None,
    }
}

/// Generates a Wasm code snippet for the specified operation and memory type.
///
/// The operation is intended to read or write a single byte from heap memory
/// using a predefined 64-bit local variable `$address`.
fn heap_op(op: Op, mem: Mem) -> String {
    match (op, mem) {
        (Op::Read, Mem::Wasm32) => {
            // The `i64.load8_u` reads just one byte from the heap memory.
            // The `i32.wrap_i64` converts the 64-bit `$address` to 32-bit.
            "(global.set $data (i64.load8_u (i32.wrap_i64 (local.get $address))))"
        }
        (Op::Read, Mem::Wasm64) => "(global.set $data (i64.load8_u (local.get $address)))",
        (Op::Write, Mem::Wasm32) => {
            "(i64.store8 (i32.wrap_i64 (local.get $address)) (global.get $counter))"
        }
        (Op::Write, Mem::Wasm64) => "(i64.store8 (local.get $address) (global.get $counter))",
    }
    .into()
}

/// Wraps an operation `op` into a loop that iterates over the heap memory
/// of the specified size. The first iteration starts at the `offset` from
/// the beginning or the end of the memory depending on the direction.
///
/// Every iteration the operation is performed at the predefined 64-bit `$address`.
/// Then the `$address` is increased or decreased by the `step` bytes,
/// and the loop continues until the end or the beginning of the memory is reached.
fn loop_body(op: &str, dir: Dir, offset: usize, size: Size, step: Step) -> String {
    let step = step as usize;
    match dir {
        Dir::Fwd => {
            // Iterate forward starting from `offset` and up to (and including) address `size - 1`.
            let end = size as usize - 1;
            format!(
                r#"
                (local.set $address (i64.const {offset}))
                (loop $loop
                    {op}
                    (local.set $address (i64.add (local.get $address) (i64.const {step})))
                    (br_if $loop (i64.le_s (local.get $address) (i64.const {end})))
                )
            "#
            )
        }
        Dir::Bwd => {
            // Iterate backward from `size - 1 - offset` and down to (and including) address `0`.
            let end = size as usize - 1 - offset;
            format!(
                r#"
                (local.set $address (i64.const {end}))
                (loop $loop
                    {op}
                    (local.set $address (i64.sub (local.get $address) (i64.const {step})))
                    (br_if $loop (i64.ge_s (local.get $address) (i64.const 0)))
                )
            "#
            )
        }
    }
}

/// Returns a Wasm code snippet to initialize the heap benchmark.
///
/// The code is executed right before the main benchmark loop, and hence
/// its execution time is INCLUDED in the benchmark results.
fn bench_init_body(mem: Mem, size: Size, src: Src) -> String {
    let wasm_pages = (size as usize).div_ceil(WASM_PAGE_SIZE_IN_BYTES);
    match src {
        Src::Checkpoint | Src::PageDelta | Src::Mix => String::new(),
        // Grow (allocate) the heap memory by the specified number of pages.
        Src::NewAllocation => format!("(drop (memory.grow (i{mem}.const {wasm_pages})))"),
    }
}

/// Returns a Wasm code snippet to initialize the canister.
/// This code is executed during the canister installation,
/// and for some page sources may follow up with a checkpoint.
///
/// See `setup_action` for more details.
fn canister_init_body(mem: Mem, size: Size, src: Src) -> String {
    // Write into every page in the heap memory for all page sources but `new_allocation`.
    let op = heap_op(Op::Write, mem);
    let loop_body = loop_body(&op, Dir::Fwd, 0, size, Step::Page);
    match src {
        Src::Checkpoint | Src::PageDelta | Src::Mix => format!(
            r#"
                {loop_body}
            "#
        ),
        Src::NewAllocation => String::new(),
    }
}

/// Returns a Wasm code snippet to setup the benchmark.
/// This code is executed as an update call before the benchmark call,
/// and simulates pages coming from different sources (together with
/// the `canister_init_body` function).
///
/// The code execution time is NOT INCLUDED in the benchmark results.
///
/// See `setup_action` for more details.
fn bench_setup_body(mem: Mem, dir: Dir, size: Size, src: Src) -> String {
    // Write into every second page in the heap memory for `mixed` page source only.
    let op = heap_op(Op::Write, mem);
    let loop_body = loop_body(&op, dir, PAGE_SIZE, size, Step::TwoPages);
    match src {
        Src::Mix => format!(
            r#"
                {loop_body}
            "#
        ),
        Src::Checkpoint | Src::PageDelta | Src::NewAllocation => String::new(),
    }
}

/// Returns a Wasm code snippet to initialize heap memory.
fn heap_memory_body(mem: Mem, size: Size, src: Src) -> String {
    let wasm_pages = (size as usize).div_ceil(WASM_PAGE_SIZE_IN_BYTES);
    match src {
        Src::Checkpoint | Src::PageDelta | Src::Mix => format!("i{mem} {wasm_pages}"),
        // The `new_allocation` page source will grow the memory during the benchmark.
        Src::NewAllocation => format!("i{mem} 0"),
    }
}

type C = Criterion;

fn bench(c: &mut C, mem: Mem, call: Call, op: Op, dir: Dir, size: Size, step: Step, src: Src) {
    let name = format!("wasm{mem}_{call}_{op}_{dir}_{size}_{step}_{src}");
    let throughput = throughput(size, step);
    let setup_action = setup_action(src);

    let bench_init_body = bench_init_body(mem, size, src);
    let op = heap_op(op, mem);
    let bench_loop = loop_body(&op, dir, 0, size, step);
    let canister_init_body = canister_init_body(mem, size, src);
    let bench_setup_body = bench_setup_body(mem, dir, size, src);
    let memory_body = heap_memory_body(mem, size, src);
    // The overall benchmark structure is:
    // 1. The `canister_init` function is executed during canister installation.
    // 2. Optionally: A checkpoint is created.
    // 3. Optionally: The `canister_update setup` function is executed.
    // 4. The `canister_update update_empty` function is executed to sync the memory
    //    between the replica and the sandbox process.
    // 5. The `canister_{call} {name}` benchmark function is executed, and its total
    //    execution time is the benchmark result.
    let wat = format!(
        r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (global $counter (mut i64) (i64.const 42))
            (global $data (mut i64) (i64.const 0))
            (func (export "canister_init")
                (local $address i64)
                (global.set $counter (i64.add (global.get $counter) (i64.const 1)))
                {canister_init_body}
            )
            (func (export "canister_update setup")
                (local $address i64)
                (global.set $counter (i64.add (global.get $counter) (i64.const 1)))
                {bench_setup_body}
                (call $msg_reply)
            )
            (func (export "canister_update update_empty")
                (call $msg_reply)
            )
            (func (export "canister_{call} {name}")
                (local $address i64)
                (global.set $counter (i64.add (global.get $counter) (i64.const 1)))
                {bench_init_body}
                {bench_loop}
                (call $msg_reply)
            )
            (memory {memory_body})
        )"#
    );
    let wasm =
        wat::parse_str(&wat).unwrap_or_else(|err| panic!("Error parsing WAT: {err}\nWAT: {wat}"));
    match call {
        Call::Query => embedders_bench::query_bench(
            c,
            "embedders:heap/query",
            &name,
            &wasm,
            &[],
            &name,
            &[],
            throughput.clone(),
            setup_action,
        ),
        Call::Update => match src {
            // Running checkpoint benchmarks once or multiple times yields the same results.
            Src::Checkpoint => embedders_bench::update_bench(
                c,
                "embedders:heap/update",
                &name,
                &wasm,
                &[],
                &name,
                &[],
                throughput.clone(),
                setup_action,
            ),
            // Executing page delta benchmarks only once yields more consistent results,
            // as they depend on the page delta size.
            // New allocation benchmarks are only meaningful when run once.
            Src::PageDelta | Src::Mix | Src::NewAllocation => embedders_bench::update_bench_once(
                c,
                "embedders:heap/update",
                &name,
                &wasm,
                &[],
                &name,
                &[],
                throughput.clone(),
                setup_action,
            ),
        },
    }
}

fn all(c: &mut Criterion) {
    for op in Op::iter() {
        for call in Call::iter() {
            for dir in Dir::iter() {
                for size in Size::iter() {
                    for step in Step::iter() {
                        for src in Src::iter() {
                            for mem in Mem::iter() {
                                bench(c, mem, call, op, dir, size, step, src);
                            }
                        }
                    }
                }
            }
        }
    }
}

criterion_group!(
    name = heap_benches;
    config = Criterion::default().sample_size(10);
    targets = all
);

criterion_main!(heap_benches);
