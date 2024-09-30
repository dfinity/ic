use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use embedders_bench::PostSetupAction;

const HEAP_WAT: &[u8] = include_bytes!("test-data/heap.wat");

#[derive(Copy, Clone)]
enum Source {
    Checkpoint,
    PageDelta,
}

// Returns the number of accessed pages for throughput computation.
fn accessed_pages(step: usize) -> Option<Throughput> {
    // The methods of `heap.wat` iterate over a 1GB memory region.
    let pages_in_step = (step + 4095) / 4096;
    Some(Throughput::Elements(
        ((1 << 30) / 4096 / pages_in_step) as u64,
    ))
}

fn bench_name(memory_type: &str, method: &str, source: Source) -> String {
    match source {
        Source::Checkpoint => {
            format!("{}_{}_checkpoint", memory_type, method)
        }
        Source::PageDelta => {
            format!("{}_{}_page_delta", memory_type, method)
        }
    }
}

fn load_wat_and_prepare(is_wasm64: bool) -> Vec<u8> {
    let wat_str = if is_wasm64 {
        let wat_str = std::str::from_utf8(HEAP_WAT).unwrap();
        // Replace all i32 with i64. This is sufficient to execute the canister in Wasm64 mode.
        let wat_str = wat_str.replace("i32", "i64");
        // Replace memory with memory 64 to enable Wasm64 mode.
        wat_str.replace(
            "(memory (export \"memory\") 16384)",
            "(memory (export \"memory\") i64 16384)",
        )
    } else {
        std::str::from_utf8(HEAP_WAT).unwrap().to_string()
    };
    wat::parse_str(wat_str).unwrap()
}

fn query_bench(c: &mut Criterion, method: &str, step: usize, source: Source) {
    let wasm32 = load_wat_and_prepare(false);
    let wasm64 = load_wat_and_prepare(true);
    let throughput = accessed_pages(step);
    let action = match source {
        Source::Checkpoint => PostSetupAction::PerformCheckpoint,
        Source::PageDelta => PostSetupAction::None,
    };
    let name_wasm32 = bench_name("wasm32", method, source);
    let name_wasm64 = bench_name("wasm64", method, source);
    embedders_bench::query_bench(
        c,
        &name_wasm32,
        &wasm32,
        &[],
        method,
        &[],
        throughput.clone(),
        action,
    );
    embedders_bench::query_bench(
        c,
        &name_wasm64,
        &wasm64,
        &[],
        method,
        &[],
        throughput,
        action,
    );
}

fn update_bench(c: &mut Criterion, method: &str, step: usize, source: Source) {
    let wasm32 = load_wat_and_prepare(false);
    let wasm64 = load_wat_and_prepare(true);
    let throughput = accessed_pages(step);
    let action = match source {
        Source::Checkpoint => PostSetupAction::PerformCheckpoint,
        Source::PageDelta => PostSetupAction::None,
    };
    let name_wasm32 = bench_name("wasm32", method, source);
    let name_wasm64 = bench_name("wasm64", method, source);
    embedders_bench::update_bench(
        c,
        &name_wasm32,
        &wasm32,
        &[],
        method,
        &[],
        throughput.clone(),
        action,
    );
    embedders_bench::update_bench(
        c,
        &name_wasm64,
        &wasm64,
        &[],
        method,
        &[],
        throughput,
        action,
    );
}

////////////////////////////////////////////////////////////////////////
// Query forward reads
////////////////////////////////////////////////////////////////////////

fn query_read_fwd_1gb_checkpoint(c: &mut Criterion) {
    query_bench(c, "query_read_fwd_1gb", 8, Source::Checkpoint);
}

fn query_read_fwd_1gb_page_delta(c: &mut Criterion) {
    query_bench(c, "query_read_fwd_1gb", 8, Source::PageDelta);
}

fn query_read_fwd_1gb_step_4kb_checkpoint(c: &mut Criterion) {
    query_bench(c, "query_read_fwd_1gb_step_4kb", 4096, Source::Checkpoint);
}

fn query_read_fwd_1gb_step_4kb_page_delta(c: &mut Criterion) {
    query_bench(c, "query_read_fwd_1gb_step_4kb", 4096, Source::PageDelta);
}

fn query_read_fwd_1gb_step_16kb_checkpoint(c: &mut Criterion) {
    query_bench(c, "query_read_fwd_1gb_step_16kb", 16384, Source::Checkpoint);
}

fn query_read_fwd_1gb_step_16kb_page_delta(c: &mut Criterion) {
    query_bench(c, "query_read_fwd_1gb_step_16kb", 16384, Source::PageDelta);
}

////////////////////////////////////////////////////////////////////////
// Query backward reads
////////////////////////////////////////////////////////////////////////

fn query_read_bwd_1gb_checkpoint(c: &mut Criterion) {
    query_bench(c, "query_read_bwd_1gb", 8, Source::Checkpoint);
}

fn query_read_bwd_1gb_page_delta(c: &mut Criterion) {
    query_bench(c, "query_read_bwd_1gb", 8, Source::PageDelta);
}

fn query_read_bwd_1gb_step_4kb_checkpoint(c: &mut Criterion) {
    query_bench(c, "query_read_bwd_1gb_step_4kb", 4096, Source::Checkpoint);
}

fn query_read_bwd_1gb_step_4kb_page_delta(c: &mut Criterion) {
    query_bench(c, "query_read_bwd_1gb_step_4kb", 4096, Source::PageDelta);
}

fn query_read_bwd_1gb_step_16kb_checkpoint(c: &mut Criterion) {
    query_bench(c, "query_read_bwd_1gb_step_16kb", 16384, Source::Checkpoint);
}

fn query_read_bwd_1gb_step_16kb_page_delta(c: &mut Criterion) {
    query_bench(c, "query_read_bwd_1gb_step_16kb", 16384, Source::PageDelta);
}

////////////////////////////////////////////////////////////////////////
// Update forward reads
////////////////////////////////////////////////////////////////////////

fn update_read_fwd_1gb_checkpoint(c: &mut Criterion) {
    update_bench(c, "update_read_fwd_1gb", 8, Source::Checkpoint);
}

fn update_read_fwd_1gb_page_delta(c: &mut Criterion) {
    update_bench(c, "update_read_fwd_1gb", 8, Source::PageDelta);
}

fn update_read_fwd_1gb_step_4kb_checkpoint(c: &mut Criterion) {
    update_bench(c, "update_read_fwd_1gb_step_4kb", 4096, Source::Checkpoint);
}

fn update_read_fwd_1gb_step_4kb_page_delta(c: &mut Criterion) {
    update_bench(c, "update_read_fwd_1gb_step_4kb", 4096, Source::PageDelta);
}

fn update_read_fwd_1gb_step_16kb_checkpoint(c: &mut Criterion) {
    update_bench(
        c,
        "update_read_fwd_1gb_step_16kb",
        16384,
        Source::Checkpoint,
    );
}

fn update_read_fwd_1gb_step_16kb_page_delta(c: &mut Criterion) {
    update_bench(c, "update_read_fwd_1gb_step_16kb", 16384, Source::PageDelta);
}

////////////////////////////////////////////////////////////////////////
// Update backward reads
////////////////////////////////////////////////////////////////////////

fn update_read_bwd_1gb_checkpoint(c: &mut Criterion) {
    update_bench(c, "update_read_bwd_1gb", 8, Source::Checkpoint);
}

fn update_read_bwd_1gb_page_delta(c: &mut Criterion) {
    update_bench(c, "update_read_bwd_1gb", 8, Source::PageDelta);
}

fn update_read_bwd_1gb_step_4kb_checkpoint(c: &mut Criterion) {
    update_bench(c, "update_read_bwd_1gb_step_4kb", 4096, Source::Checkpoint);
}

fn update_read_bwd_1gb_step_4kb_page_delta(c: &mut Criterion) {
    update_bench(c, "update_read_bwd_1gb_step_4kb", 4096, Source::PageDelta);
}

fn update_read_bwd_1gb_step_16kb_checkpoint(c: &mut Criterion) {
    update_bench(
        c,
        "update_read_bwd_1gb_step_16kb",
        16384,
        Source::Checkpoint,
    );
}

fn update_read_bwd_1gb_step_16kb_page_delta(c: &mut Criterion) {
    update_bench(c, "update_read_bwd_1gb_step_16kb", 16384, Source::PageDelta);
}

////////////////////////////////////////////////////////////////////////
// Query forward writes
////////////////////////////////////////////////////////////////////////

fn query_write_fwd_1gb_checkpoint(c: &mut Criterion) {
    query_bench(c, "query_write_fwd_1gb", 8, Source::Checkpoint);
}

fn query_write_fwd_1gb_page_delta(c: &mut Criterion) {
    query_bench(c, "query_write_fwd_1gb", 8, Source::PageDelta);
}

fn query_write_fwd_1gb_step_4kb_checkpoint(c: &mut Criterion) {
    query_bench(c, "query_write_fwd_1gb_step_4kb", 4096, Source::Checkpoint);
}

fn query_write_fwd_1gb_step_4kb_page_delta(c: &mut Criterion) {
    query_bench(c, "query_write_fwd_1gb_step_4kb", 4096, Source::PageDelta);
}

fn query_write_fwd_1gb_step_16kb_checkpoint(c: &mut Criterion) {
    query_bench(
        c,
        "query_write_fwd_1gb_step_16kb",
        16384,
        Source::Checkpoint,
    );
}

fn query_write_fwd_1gb_step_16kb_page_delta(c: &mut Criterion) {
    query_bench(c, "query_write_fwd_1gb_step_16kb", 16384, Source::PageDelta);
}

////////////////////////////////////////////////////////////////////////
// Query backward writes
////////////////////////////////////////////////////////////////////////

fn query_write_bwd_1gb_checkpoint(c: &mut Criterion) {
    query_bench(c, "query_write_bwd_1gb", 8, Source::Checkpoint);
}

fn query_write_bwd_1gb_page_delta(c: &mut Criterion) {
    query_bench(c, "query_write_bwd_1gb", 8, Source::PageDelta);
}

fn query_write_bwd_1gb_step_4kb_checkpoint(c: &mut Criterion) {
    query_bench(c, "query_write_bwd_1gb_step_4kb", 4096, Source::Checkpoint);
}

fn query_write_bwd_1gb_step_4kb_page_delta(c: &mut Criterion) {
    query_bench(c, "query_write_bwd_1gb_step_4kb", 4096, Source::PageDelta);
}

fn query_write_bwd_1gb_step_16kb_checkpoint(c: &mut Criterion) {
    query_bench(
        c,
        "query_write_bwd_1gb_step_16kb",
        16384,
        Source::Checkpoint,
    );
}

fn query_write_bwd_1gb_step_16kb_page_delta(c: &mut Criterion) {
    query_bench(c, "query_write_bwd_1gb_step_16kb", 16384, Source::PageDelta);
}

////////////////////////////////////////////////////////////////////////
// Update forward writes
////////////////////////////////////////////////////////////////////////

fn update_write_fwd_1gb_checkpoint(c: &mut Criterion) {
    update_bench(c, "update_write_fwd_1gb", 8, Source::Checkpoint);
}

fn update_write_fwd_1gb_page_delta(c: &mut Criterion) {
    update_bench(c, "update_write_fwd_1gb", 8, Source::PageDelta);
}

fn update_write_fwd_1gb_step_4kb_checkpoint(c: &mut Criterion) {
    update_bench(c, "update_write_fwd_1gb_step_4kb", 4096, Source::Checkpoint);
}

fn update_write_fwd_1gb_step_4kb_page_delta(c: &mut Criterion) {
    update_bench(c, "update_write_fwd_1gb_step_4kb", 4096, Source::PageDelta);
}

fn update_write_fwd_1gb_step_16kb_checkpoint(c: &mut Criterion) {
    update_bench(
        c,
        "update_write_fwd_1gb_step_16kb",
        16384,
        Source::Checkpoint,
    );
}

fn update_write_fwd_1gb_step_16kb_page_delta(c: &mut Criterion) {
    update_bench(
        c,
        "update_write_fwd_1gb_step_16kb",
        16384,
        Source::PageDelta,
    );
}

////////////////////////////////////////////////////////////////////////
// Update backward writes
////////////////////////////////////////////////////////////////////////

fn update_write_bwd_1gb_checkpoint(c: &mut Criterion) {
    update_bench(c, "update_write_bwd_1gb", 8, Source::Checkpoint);
}

fn update_write_bwd_1gb_page_delta(c: &mut Criterion) {
    update_bench(c, "update_write_bwd_1gb", 8, Source::PageDelta);
}

fn update_write_bwd_1gb_step_4kb_checkpoint(c: &mut Criterion) {
    update_bench(c, "update_write_bwd_1gb_step_4kb", 4096, Source::Checkpoint);
}

fn update_write_bwd_1gb_step_4kb_page_delta(c: &mut Criterion) {
    update_bench(c, "update_write_bwd_1gb_step_4kb", 4096, Source::PageDelta);
}

fn update_write_bwd_1gb_step_16kb_checkpoint(c: &mut Criterion) {
    update_bench(
        c,
        "update_write_bwd_1gb_step_16kb",
        16384,
        Source::Checkpoint,
    );
}

fn update_write_bwd_1gb_step_16kb_page_delta(c: &mut Criterion) {
    update_bench(
        c,
        "update_write_bwd_1gb_step_16kb",
        16384,
        Source::PageDelta,
    );
}

////////////////////////////////////////////////////////////////////////
// Main
////////////////////////////////////////////////////////////////////////

criterion_group!(
    name = heap_benches;
    config = Criterion::default().sample_size(10);
    targets =
        query_read_fwd_1gb_checkpoint,
        query_read_fwd_1gb_page_delta,
        query_read_fwd_1gb_step_4kb_checkpoint,
        query_read_fwd_1gb_step_4kb_page_delta,
        query_read_fwd_1gb_step_16kb_checkpoint,
        query_read_fwd_1gb_step_16kb_page_delta,
        query_read_bwd_1gb_checkpoint,
        query_read_bwd_1gb_page_delta,
        query_read_bwd_1gb_step_4kb_checkpoint,
        query_read_bwd_1gb_step_4kb_page_delta,
        query_read_bwd_1gb_step_16kb_checkpoint,
        query_read_bwd_1gb_step_16kb_page_delta,

        update_read_fwd_1gb_checkpoint,
        update_read_fwd_1gb_page_delta,
        update_read_fwd_1gb_step_4kb_checkpoint,
        update_read_fwd_1gb_step_4kb_page_delta,
        update_read_fwd_1gb_step_16kb_checkpoint,
        update_read_fwd_1gb_step_16kb_page_delta,
        update_read_bwd_1gb_checkpoint,
        update_read_bwd_1gb_page_delta,
        update_read_bwd_1gb_step_4kb_checkpoint,
        update_read_bwd_1gb_step_4kb_page_delta,
        update_read_bwd_1gb_step_16kb_checkpoint,
        update_read_bwd_1gb_step_16kb_page_delta,

        query_write_fwd_1gb_checkpoint,
        query_write_fwd_1gb_page_delta,
        query_write_fwd_1gb_step_4kb_checkpoint,
        query_write_fwd_1gb_step_4kb_page_delta,
        query_write_fwd_1gb_step_16kb_checkpoint,
        query_write_fwd_1gb_step_16kb_page_delta,
        query_write_bwd_1gb_checkpoint,
        query_write_bwd_1gb_page_delta,
        query_write_bwd_1gb_step_4kb_checkpoint,
        query_write_bwd_1gb_step_4kb_page_delta,
        query_write_bwd_1gb_step_16kb_checkpoint,
        query_write_bwd_1gb_step_16kb_page_delta,

        update_write_fwd_1gb_checkpoint,
        update_write_fwd_1gb_page_delta,
        update_write_fwd_1gb_step_4kb_checkpoint,
        update_write_fwd_1gb_step_4kb_page_delta,
        update_write_fwd_1gb_step_16kb_checkpoint,
        update_write_fwd_1gb_step_16kb_page_delta,
        update_write_bwd_1gb_checkpoint,
        update_write_bwd_1gb_page_delta,
        update_write_bwd_1gb_step_4kb_checkpoint,
        update_write_bwd_1gb_step_4kb_page_delta,
        update_write_bwd_1gb_step_16kb_checkpoint,
        update_write_bwd_1gb_step_16kb_page_delta,
);

criterion_main!(heap_benches);
