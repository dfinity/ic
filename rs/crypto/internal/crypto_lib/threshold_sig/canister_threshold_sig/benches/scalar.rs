use criterion::*;
use ic_crypto_internal_threshold_sig_canister_threshold_sig::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::{CryptoRng, Rng};

fn random_scalar<R: Rng + CryptoRng>(curve_type: EccCurveType, rng: &mut R) -> EccScalar {
    EccScalar::random(curve_type, rng)
}

fn random_scalar_pair<R: Rng + CryptoRng>(
    curve_type: EccCurveType,
    rng: &mut R,
) -> (EccScalar, EccScalar) {
    let x = EccScalar::random(curve_type, rng);
    let y = EccScalar::random(curve_type, rng);
    (x, y)
}

fn n_random_scalar<R: Rng + CryptoRng>(
    n: usize,
    curve_type: EccCurveType,
    rng: &mut R,
) -> Vec<EccScalar> {
    (0..n)
        .map(|_i| EccScalar::random(curve_type, rng))
        .collect()
}

fn scalar_math(c: &mut Criterion) {
    let rng = &mut reproducible_rng();

    for curve_type in EccCurveType::all() {
        let mut group = c.benchmark_group(format!("crypto_scalar_{curve_type}"));
        group.warm_up_time(std::time::Duration::from_millis(10));

        group.bench_function("add", |b| {
            b.iter_batched_ref(
                || random_scalar_pair(curve_type, rng),
                |(x, y)| x.add(y),
                BatchSize::SmallInput,
            )
        });

        group.bench_function("mul", |b| {
            b.iter_batched_ref(
                || random_scalar_pair(curve_type, rng),
                |(x, y)| x.mul(y),
                BatchSize::SmallInput,
            )
        });

        group.bench_function("invert", |b| {
            b.iter_batched_ref(
                || random_scalar(curve_type, rng),
                |x| x.invert(),
                BatchSize::SmallInput,
            )
        });

        group.bench_function("invert_vartime", |b| {
            b.iter_batched_ref(
                || random_scalar(curve_type, rng),
                |x| x.invert_vartime(),
                BatchSize::SmallInput,
            )
        });

        for n in [2, 4, 16, 32] {
            group.bench_function(format!("batch_invert_vartime_{}", n), |b| {
                b.iter_batched_ref(
                    || n_random_scalar(n, curve_type, rng),
                    |x| EccScalar::batch_invert_vartime(x),
                    BatchSize::SmallInput,
                )
            });
        }
    }
}

criterion_group!(benches, scalar_math,);
criterion_main!(benches);
