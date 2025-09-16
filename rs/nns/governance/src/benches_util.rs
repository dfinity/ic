use canbench_rs::BenchResult;

/// Checks that given instructions used by the benchmark, when scaled to production, do not exceed
/// the given limit. Note that it's only useful when it's clear that the benchmark scales (roughly) linearly
/// along the given dimension.
pub(crate) fn check_projected_instructions(
    bench_result: BenchResult,
    bench_scale: u64,
    production_scale: u64,
    instructions_limit: u64,
) -> BenchResult {
    let benchmark_instructions = bench_result.total.instructions;
    let projected_instructions = benchmark_instructions / bench_scale * production_scale;
    assert!(
        projected_instructions <= instructions_limit,
        "The instructions used by the benchmark ({benchmark_instructions}), when scaled to production from {bench_scale} to {production_scale}, \
        exceed the limit ({instructions_limit})."
    );
    bench_result
}
