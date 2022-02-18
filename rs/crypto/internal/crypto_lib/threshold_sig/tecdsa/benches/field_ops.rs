use criterion::*;
use ic_crypto_internal_threshold_sig_ecdsa::*;

fn field_ops(c: &mut Criterion) {
    let curve_type = EccCurveType::K256;

    let input = [0xba; 32];
    let input_wide = [0xba; 64];

    let fe1 = EccFieldElement::from_bytes(curve_type, &input).expect("from_bytes failed");
    let fe2 =
        EccFieldElement::from_bytes_wide(curve_type, &input_wide).expect("from_bytes_wide failed");

    c.bench_function("field addition", |b| {
        b.iter(|| {
            let _ = fe1.add(&fe2).expect("Add failed");
        })
    });

    c.bench_function("field subtraction", |b| {
        b.iter(|| {
            let _ = fe1.sub(&fe2).expect("Sub failed");
        })
    });

    c.bench_function("field multiplication", |b| {
        b.iter(|| {
            let _ = fe1.mul(&fe2).expect("Mul failed");
        })
    });

    c.bench_function("field inversion", |b| {
        b.iter(|| {
            let _ = fe1.invert();
        })
    });

    c.bench_function("field sqrt", |b| {
        b.iter(|| {
            let _ = fe1.sqrt();
        })
    });

    c.bench_function("field from_bytes", |b| {
        b.iter(|| {
            let _ = EccFieldElement::from_bytes(curve_type, &input).expect("Deser failed");
        })
    });

    c.bench_function("field from_bytes_wide", |b| {
        b.iter(|| {
            let _ =
                EccFieldElement::from_bytes_wide(curve_type, &input_wide).expect("Deser failed");
        })
    });

    c.bench_function("field as_bytes", |b| {
        b.iter(|| {
            let _ = fe1.as_bytes();
        })
    });
}

criterion_group!(benches, field_ops);
criterion_main!(benches);
