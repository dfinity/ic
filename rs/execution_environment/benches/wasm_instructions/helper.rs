//! Helper Functions

use execution_environment_bench::{
    common,
    wat_builder::{
        Block, CONFIRMATION_LOOP_ITERATIONS, CONFIRMATION_REPEAT_TIMES, DEFAULT_LOOP_ITERATIONS,
        DEFAULT_REPEAT_TIMES,
    },
};

/// Create a benchmark with its confirmation for the specified `code` snippet.
///
/// Confirmation benchmark is to make sure there is no compiler optimization
/// for the repeated lines of code.
pub fn benchmark_with_confirmation(name: &str, code: &str) -> Vec<common::Benchmark> {
    let i = DEFAULT_LOOP_ITERATIONS;
    let r = DEFAULT_REPEAT_TIMES;
    let c = CONFIRMATION_REPEAT_TIMES;
    vec![
        benchmark(name, i, r, code),
        benchmark(&format!("{name}/confirmation"), i, c, code),
    ]
}

/// Create a benchmark with its confirmation for the specified `code` snippet.
///
/// Confirmation benchmark is to make sure there is no compiler optimization
/// for the loop.
pub fn benchmark_with_loop_confirmation(name: &str, code: &str) -> Vec<common::Benchmark> {
    let i = DEFAULT_LOOP_ITERATIONS;
    let c = CONFIRMATION_LOOP_ITERATIONS;
    let r = DEFAULT_REPEAT_TIMES;
    vec![
        benchmark(name, i, r, code),
        benchmark(&format!("{name}/confirmation"), c, r, code),
    ]
}

/// Create a benchmark with a code block repeated specified number of times in a loop.
pub fn benchmark(name: &str, i: usize, r: usize, repeat_code: &str) -> common::Benchmark {
    common::Benchmark(
        name.into(),
        Block::default()
            .repeat_n(r, repeat_code)
            .loop_n(i)
            .define_variables_and_functions(repeat_code)
            .into_update_func()
            .into_test_module_wat(),
        (i * r) as u64,
    )
}
