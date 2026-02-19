use canbench_rs::bench;

#[bench]
fn bench_with_debug_print() {
    // Run `canbench --show-canister-output` to see the output.
    ic_cdk::eprintln!("Hello from {}!", env!("CARGO_PKG_NAME"));
}

fn main() {}
