use criterion::*;
use ic_crypto_internal_threshold_sig_ecdsa::*;

fn hash2curve(c: &mut Criterion) {
    let input = "greetings humans".as_bytes();
    let dst = "domain sep".as_bytes();

    c.bench_function("hash to curve P256", |b| {
        b.iter(|| {
            let _pt =
                EccPoint::hash_to_point(EccCurveType::P256, input, dst).expect("hash2curve failed");
        })
    });

    c.bench_function("hash to curve K256", |b| {
        b.iter(|| {
            let _pt =
                EccPoint::hash_to_point(EccCurveType::K256, input, dst).expect("hash2curve failed");
        })
    });
}

criterion_group!(benches, hash2curve);
criterion_main!(benches);
