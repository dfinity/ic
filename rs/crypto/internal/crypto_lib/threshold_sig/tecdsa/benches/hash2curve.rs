use criterion::*;
use tecdsa::*;

fn hash2curve(c: &mut Criterion) {
    let curve = EccCurveType::P256;

    let input = "greetings humans".as_bytes();
    let dst = "domain sep".as_bytes();

    c.bench_function("hash to curve", |b| {
        b.iter(|| {
            let _pt = EccPoint::hash_to_point(curve, input, dst).expect("hash2curve failed");
        })
    });
}

criterion_group!(benches, hash2curve);
criterion_main!(benches);
