use criterion::*;
use ic_crypto_interfaces_sig_verification::CanisterSigVerifier;
use ic_crypto_test_utils_canister_sigs::new_valid_sig_and_crypto_component;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;

criterion_group!(benches, crypto_canister_sig_verify);
criterion_main!(benches);

const WARMUP_TIME: std::time::Duration = std::time::Duration::from_millis(300);

fn crypto_canister_sig_verify(criterion: &mut Criterion) {
    for group_suffix in ["cached", "uncached"] {
        crypto_canister_sig_verify_impl(criterion, group_suffix);
    }
}

fn crypto_canister_sig_verify_impl(criterion: &mut Criterion, group_suffix: &str) {
    let group = &mut criterion.benchmark_group(format!("crypto_canister_sig_{group_suffix}"));
    group.warm_up_time(WARMUP_TIME);

    let rng = &mut reproducible_rng();

    for benchmark_name in ["with_delegations", "without_delegations"] {
        group.bench_function(benchmark_name, |bench| {
            bench.iter_batched_ref(
                || {
                    let data = new_valid_sig_and_crypto_component(
                        rng,
                        benchmark_name == "with_delegations",
                    );
                    if group_suffix == "cached" {
                        // cache the signature verification before benchmarking
                        let result = data.crypto.verify_canister_sig(
                            &data.canister_sig,
                            &data.msg,
                            &data.canister_pk,
                            &data.root_of_trust,
                        );
                        assert!(result.is_ok());
                    }
                    data
                },
                |data| {
                    let result = data.crypto.verify_canister_sig(
                        &data.canister_sig,
                        &data.msg,
                        &data.canister_pk,
                        &data.root_of_trust,
                    );
                    assert!(result.is_ok());
                },
                BatchSize::SmallInput,
            )
        });
    }
}
