use criterion::*;
use ic_crypto_internal_bls12_381_type::*;
use rand::Rng;

fn random_g1() -> G1Projective {
    let mut rng = rand::thread_rng();
    G1Projective::hash(b"domain_sep", &rng.gen::<[u8; 32]>())
}

fn random_g2() -> G2Projective {
    let mut rng = rand::thread_rng();
    G2Projective::hash(b"domain_sep", &rng.gen::<[u8; 32]>())
}

fn random_gt() -> Gt {
    Gt::pairing(&random_g1().into(), &random_g2().into())
}

fn random_scalar() -> Scalar {
    let mut rng = rand::thread_rng();
    Scalar::random(&mut rng)
}

fn bls12_381_g1_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_bls12_381_g1");

    group.bench_function("serialize", |b| {
        b.iter_batched_ref(|| random_g1(), |pt| pt.serialize(), BatchSize::SmallInput)
    });

    group.bench_function("deserialize", |b| {
        b.iter_batched_ref(
            || random_g1().serialize(),
            |bytes| G1Projective::deserialize(bytes.as_slice()),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("deserialize_unchecked", |b| {
        b.iter_batched_ref(
            || random_g1().serialize(),
            |bytes| G1Projective::deserialize_unchecked(bytes.as_slice()),
            BatchSize::SmallInput,
        )
    });

    let mut rng = rand::thread_rng();

    group.bench_function("hash_32_B", |b| {
        b.iter_batched_ref(
            || rng.gen::<[u8; 32]>(),
            |bytes| G1Projective::hash(b"dst", bytes.as_slice()),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("addition", |b| {
        b.iter_batched_ref(
            || (random_g1(), random_g1()),
            |(pt1, pt2)| *pt1 + *pt2,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiply", |b| {
        b.iter_batched_ref(
            || (random_g1(), random_scalar()),
            |(pt, scalar)| *pt * *scalar,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("to_affine", |b| {
        b.iter_batched_ref(
            || random_g1(),
            |pt| G1Affine::from(*pt),
            BatchSize::SmallInput,
        )
    });
}

fn bls12_381_g2_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_bls12_381_g2");

    group.bench_function("serialize", |b| {
        b.iter_batched_ref(|| random_g2(), |pt| pt.serialize(), BatchSize::SmallInput)
    });

    group.bench_function("deserialize", |b| {
        b.iter_batched_ref(
            || random_g2().serialize(),
            |bytes| G2Projective::deserialize(bytes.as_slice()),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("deserialize_unchecked", |b| {
        b.iter_batched_ref(
            || random_g2().serialize(),
            |bytes| G2Projective::deserialize_unchecked(bytes.as_slice()),
            BatchSize::SmallInput,
        )
    });

    let mut rng = rand::thread_rng();

    group.bench_function("hash_32_B", |b| {
        b.iter_batched_ref(
            || rng.gen::<[u8; 32]>(),
            |bytes| G2Projective::hash(b"dst", bytes.as_slice()),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("addition", |b| {
        b.iter_batched_ref(
            || (random_g2(), random_g2()),
            |(pt1, pt2)| *pt1 + *pt2,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiply", |b| {
        b.iter_batched_ref(
            || (random_g2(), random_scalar()),
            |(pt, scalar)| *pt * *scalar,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("to_affine", |b| {
        b.iter_batched_ref(
            || random_g2(),
            |pt| G2Affine::from(*pt),
            BatchSize::SmallInput,
        )
    });
}

fn pairing_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_bls12_381_gt");

    group.bench_function("addition", |b| {
        b.iter_batched_ref(
            || (random_gt(), random_gt()),
            |(gt1, gt2)| *gt1 + *gt2,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiply", |b| {
        b.iter_batched_ref(
            || (random_gt(), random_scalar()),
            |(gt, scalar)| *gt * *scalar,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("pairing", |b| {
        b.iter_batched_ref(
            || (random_g1().into(), random_g2().into()),
            |(g1, g2)| Gt::pairing(g1, g2),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("verify_bls_signature", |b| {
        b.iter_batched_ref(
            || (random_g1().into(), random_g2().into(), random_g1().into()),
            |(sig, pk, msg)| verify_bls_signature(sig, pk, msg),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, bls12_381_g1_ops, bls12_381_g2_ops, pairing_ops);
criterion_main!(benches);
