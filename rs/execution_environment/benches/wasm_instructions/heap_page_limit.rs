//! Benchmarks for the accessed heap page limit check injected before bulk
//! memory operations.
//!
//! The check has a Wasm-side fast path (a bound of `(len >> 16) + 2` pages per
//! heap range compared with the remaining page budget) and a slow path (a
//! host call that counts the not yet accessed pages of the operands exactly).
//! The benchmarks below run in two groups: with the default config, where the
//! budget is the whole heap and every operation takes the fast path, and with
//! [`config`], where the budget is a single page, so that every operation
//! takes the slow path. The latter is the adversarial worst case of a canister
//! that sits within a page of the limit and issues many tiny operations inside
//! already accessed pages, paying a host call for each.

use crate::helper::benchmark_with_confirmation;
use execution_environment_bench::common;
use ic_config::{embedders::MemoryPageLimit, execution_environment::Config};
use ic_types::NumOsPages;

/// Bulk memory operations on 8 bytes of the first heap page.
pub fn benchmarks() -> Vec<common::Benchmark> {
    let mut benchmarks = vec![];
    benchmarks.extend(benchmark_with_confirmation(
        "memop/memory.fill/8B",
        "(memory.fill (local.get $zero_memtype) (local.get $zero_i32) (memtype.const 8))",
    ));
    benchmarks.extend(benchmark_with_confirmation(
        "memop/memory.copy/8B",
        "(memory.copy (local.get $zero_memtype) (local.get $zero_memtype) (memtype.const 8))",
    ));
    benchmarks
}

/// A config whose accessed heap page limit is a single Wasm page: enough for
/// the operations above, but less than the fast path bound of any operation.
pub fn config() -> Config {
    const OS_PAGES_PER_WASM_PAGE: u64 = 65536 / 4096;
    let limit = NumOsPages::new(OS_PAGES_PER_WASM_PAGE);
    let mut config = Config::default();
    config.embedders_config.wasm_memory_accessed_page_limit = MemoryPageLimit {
        message: limit,
        upgrade: limit,
        query: limit,
    };
    config
}
