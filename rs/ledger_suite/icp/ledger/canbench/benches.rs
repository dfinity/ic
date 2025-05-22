use canbench_rs::{bench, BenchResult};

#[bench(raw)]
fn bench_endpoints() -> BenchResult {
    canbench_rs::bench_fn(|| {
    })
}

fn main() {}