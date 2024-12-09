use canbench_rs::bench;

#[bench(raw)]
fn bench_example() -> canbench_rs::BenchResult {
    fn example_function_to_benchmark(a: u64) {
        for _ in 0..a {
            // Use std::hint::black_box to prevent the compiler from optimizing out the loop.
            std::hint::black_box(a);
        }
    }

    let a = 1000;

    // The argument to bench_fn is the code to benchmark.
    canbench_rs::bench_fn(|| example_function_to_benchmark(a))
}
