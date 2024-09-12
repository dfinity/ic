//! Helper Functions

use crate::common::Wasm64;
use execution_environment_bench::{
    common,
    wat_builder::{
        Block, CONFIRMATION_LOOP_ITERATIONS, CONFIRMATION_REPEAT_TIMES, DEFAULT_LOOP_ITERATIONS,
        DEFAULT_REPEAT_TIMES,
    },
};

/// Run all the benchmark or just the first in a group.
const RUN_ALL_BENCHMARKS: bool = true;

/// Returns either the first or all the benchmarks.
pub fn first_or_all<'a>(all: &'a [&'a str]) -> &'a [&'a str] {
    if RUN_ALL_BENCHMARKS {
        all
    } else {
        &all[..1]
    }
}

/// Creates a benchmark with its confirmation for the specified `code` snippet.
///
/// The confirmation benchmark is to make sure there is no compiler optimization
/// for the repeated lines of code.
pub fn benchmark_with_confirmation(name: &str, code: &str) -> Vec<common::Benchmark> {
    let i = DEFAULT_LOOP_ITERATIONS;
    let r = DEFAULT_REPEAT_TIMES;
    let c = CONFIRMATION_REPEAT_TIMES;

    // Certain opcodes benchmarks require parameters/addresses to be either i32 or i64
    // depending on the wasm64 flag.
    let mut wasm32_code = code.replace("memop_address_placeholder", "$address_i32");
    let mut wasm64_code = code.replace("memop_address_placeholder", "$address_i64");

    // Bulk memory opcodes require certain parameters to be either i32 or i64.
    wasm32_code = wasm32_code.replace("bulkmemop_x_placeholder", "$x_i32");
    wasm64_code = wasm64_code.replace("bulkmemop_x_placeholder", "$x_i64");
    wasm32_code = wasm32_code.replace("bulkmemop_zero_placeholder", "$zero_i32");
    wasm64_code = wasm64_code.replace("bulkmemop_zero_placeholder", "$zero_i64");

    // SIMD opcodes require certain parameters to be either i32 or i64.
    wasm32_code = wasm32_code.replace("simd_address_placeholder", "(local.get $address_i32)");
    wasm64_code = wasm64_code.replace("simd_address_placeholder", "(local.get $address_i64)");
    wasm32_code = wasm32_code.replace("unaligned_address_placeholder", "(local.get $one_i32)");
    wasm64_code = wasm64_code.replace("unaligned_address_placeholder", "(local.get $one_i64)");

    vec![
        benchmark(
            &format!("wasm32/{name}"),
            i,
            r,
            &wasm32_code,
            Wasm64::Disabled,
        ),
        benchmark(
            &format!("wasm32/{name}/confirmation"),
            i,
            c,
            &wasm32_code,
            Wasm64::Disabled,
        ),
        benchmark(
            &format!("wasm64/{name}"),
            i,
            r,
            &wasm64_code,
            Wasm64::Enabled,
        ),
        benchmark(
            &format!("wasm64/{name}/confirmation"),
            i,
            c,
            &wasm64_code,
            Wasm64::Enabled,
        ),
    ]
}

/// Creates a benchmark with its confirmation for the specified `code` snippet.
///
/// The confirmation benchmark is to make sure there is no compiler optimization
/// for the loop.
pub fn benchmark_with_loop_confirmation(name: &str, code: &str) -> Vec<common::Benchmark> {
    let i = DEFAULT_LOOP_ITERATIONS;
    let c = CONFIRMATION_LOOP_ITERATIONS;
    let r = DEFAULT_REPEAT_TIMES;
    vec![
        benchmark(&format!("wasm32/{name}"), i, r, code, Wasm64::Disabled),
        benchmark(
            &format!("wasm32/{name}/confirmation"),
            c,
            r,
            code,
            Wasm64::Disabled,
        ),
        benchmark(&format!("wasm64/{name}"), i, r, code, Wasm64::Enabled),
        benchmark(
            &format!("wasm64/{name}/confirmation"),
            c,
            r,
            code,
            Wasm64::Enabled,
        ),
    ]
}

/// Creates a benchmark with a code block repeated specified number of times in a loop.
pub fn benchmark(
    name: &str,
    i: usize,
    r: usize,
    repeat_code: &str,
    wasm64_enabled: Wasm64,
) -> common::Benchmark {
    common::Benchmark(
        name.into(),
        Block::default()
            .repeat_n(r, repeat_code)
            .loop_n(i)
            .define_variables_and_functions(repeat_code, wasm64_enabled)
            .into_update_func()
            .into_test_module_wat(wasm64_enabled),
        (i * r) as u64,
    )
}
