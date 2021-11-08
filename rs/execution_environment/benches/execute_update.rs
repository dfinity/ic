///
/// Compare `execute_update()` performance for messages with and without exit.
///
/// The most important metrics:
/// ```
/// BENCH: ic0.msg_caller_copy() loop/1M/1B
///     Instructions per bench iteration: 13000004  Per loop iteration: 13
/// -> how many Instructions it took      ^^^
///                         time:   [78.906 ms 79.071 ms 79.251 ms]
/// -> how long does the benchmark run         ^^^
///                         thrpt:  [164.04 Melem/s 164.41 Melem/s 164.75 Melem/s]
/// -> Instructions per second                      ^^^
/// ```
mod update;
mod wat;
use criterion::{criterion_group, criterion_main, Criterion};

pub fn bench_update(c: &mut Criterion) {
    for (id, wat, expected_instructions) in wat::ALL.iter() {
        println!("BENCH: {}", id);
        println!(
            "    Instructions per bench iteration: {} ({}M)",
            expected_instructions,
            *expected_instructions / 1_000_000
        );
        println!("    WAT: {}", wat);
        update::run_benchmark(Some(c), id, wat, *expected_instructions);
    }
}

criterion_group!(benches, bench_update);
criterion_main!(benches);
