use criterion::{criterion_group, criterion_main, Criterion, Throughput};
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
enum Dir {
    #[strum(serialize = "fwd")]
    Forward,
    #[strum(serialize = "bwd")]
    Backward,
}

#[derive(Copy, Clone, Display, EnumIter)]
enum Size {
    #[strum(serialize = "1gb")]
    Gigabyte = 1024 * 1024 * 1024,
}

#[derive(Copy, Clone, Display, EnumIter)]
enum Step {
    #[strum(serialize = "step_8")]
    Small = 8,
    #[strum(serialize = "step_4kb")]
    Page = 4096,
    #[strum(serialize = "step_16kb")]
    FourPages = 16384,
    #[strum(serialize = "step_2mb")]
    HugePage = 2 * 1024 * 1024,
    #[strum(serialize = "step_5mb")]
    FiveMegabytes = 5 * 1024 * 1024,
    #[strum(serialize = "step_500mb")]
    FiveHundredMegabytes = 500 * 1024 * 1024,
}

#[derive(Copy, Clone, Display, EnumIter)]
#[strum(serialize_all = "snake_case")]
enum Src {
    Checkpoint,
    PageDelta,
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
        Src::PageDelta | Src::NewAllocation => SetupAction::None,
    }
}

fn heap_op(op: Op) -> String {
    match op {
        Op::Read => "(drop (i64.load (local.get $address)))".into(),
        Op::Write => "(i64.store (local.get $address) (global.get $counter))".into(),
    }
}

fn heap_func_init_body(mem: Mem, size: Size, src: Src) -> String {
    let wasm_pages = (size as usize).div_ceil(WASM_PAGE_SIZE_IN_BYTES);
    match src {
        Src::Checkpoint | Src::PageDelta => String::new(),
        Src::NewAllocation => format!("(drop (memory.grow (i{mem}.const {wasm_pages})))"),
    }
}

fn loop_body(op: &str, mem: Mem, dir: Dir, size: Size, step: Step) -> String {
    let size = size as usize;
    let step = step as usize;
    match dir {
        Dir::Forward => format!(
            r#"
                (local.set $address (i{mem}.const 0))
                (loop $loop
                    {op}
                    (local.set $address (i{mem}.add (local.get $address) (i{mem}.const {step})))
                    (br_if $loop (i{mem}.lt_u (local.get $address) (i{mem}.const {size})))
                )
            "#
        ),
        Dir::Backward => format!(
            r#"
                (local.set $address (i{mem}.const {size}))
                (loop $loop
                    (local.set $address (i{mem}.sub (local.get $address) (i{mem}.const {step})))
                    {op}
                    (br_if $loop (i{mem}.gt_s (local.get $address) (i{mem}.const 0)))
                )
            "#
        ),
    }
}

fn heap_canister_init_body(mem: Mem, size: Size, src: Src) -> String {
    let op = "(i64.store (local.get $address) (i64.const 1))";
    let loop_body = loop_body(op, mem, Dir::Forward, size, Step::Page);
    match src {
        Src::Checkpoint | Src::PageDelta => format!(
            r#"
                {loop_body}
            "#
        ),
        Src::NewAllocation => String::new(),
    }
}

fn heap_memory_body(mem: Mem, size: Size, src: Src) -> String {
    let wasm_pages = (size as usize).div_ceil(WASM_PAGE_SIZE_IN_BYTES);
    match src {
        Src::Checkpoint | Src::PageDelta => format!("i{mem} {wasm_pages}"),
        Src::NewAllocation => format!("i{mem} 0"),
    }
}

type C = Criterion;

fn bench(c: &mut C, mem: Mem, call: Call, op: Op, dir: Dir, size: Size, step: Step, src: Src) {
    let name = format!("wasm{mem}_{call}_{op}_{dir}_{size}_{step}_{src}");
    let throughput = throughput(size, step);
    let setup_action = setup_action(src);

    let op = heap_op(op);
    let func_init_body = heap_func_init_body(mem, size, src);
    let loop_body = loop_body(&op, mem, dir, size, step);
    let canister_init_body = heap_canister_init_body(mem, size, src);
    let memory_body = heap_memory_body(mem, size, src);
    let wat = format!(
        r#"
        (module
            (import "ic0" "msg_reply" (func $ic0_msg_reply))
            (global $counter (mut i64) (i64.const 42))
            (func (export "canister_update update_empty")
                (call $ic0_msg_reply)
            )
            (func (export "canister_{call} {name}")
                (local $address i{mem})
                (global.set $counter (i64.add (global.get $counter) (i64.const 1)))
                {func_init_body}
                {loop_body}
                (call $ic0_msg_reply)
            )
            (func (export "canister_init")
                (local $address i{mem})
                {canister_init_body}
            )
            (memory {memory_body})
        )"#
    );
    let wasm = wat::parse_str(&wat).unwrap_or_else(|_| panic!("Error parsing WAT: {wat}"));
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
            Src::PageDelta | Src::NewAllocation => embedders_bench::update_bench_once(
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
