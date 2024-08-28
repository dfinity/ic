mod canister_snapshots;
mod create_canisters;
mod ecdsa;
mod http_request;
mod install_code;
mod update_settings;
mod utils;

use criterion::{criterion_group, criterion_main, Criterion};

fn all_benchmarks(c: &mut Criterion) {
    canister_snapshots::benchmark(c);
    create_canisters::create_canisters_benchmark(c);
    install_code::install_code_benchmark(c);
    update_settings::update_settings_benchmark(c);
    ecdsa::ecdsa_benchmark(c);
    http_request::http_request_benchmark(c);
}

criterion_group!(benchmarks, all_benchmarks);
criterion_main!(benchmarks);
