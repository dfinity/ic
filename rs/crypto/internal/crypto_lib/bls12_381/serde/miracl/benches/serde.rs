use criterion::*;
use ic_crypto_internal_bls12381_serde_miracl::*;
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

fn random_scalar() -> Scalar {
    let mut rng = rand::thread_rng();
    Scalar::random(&mut rng)
}

fn miracl_serde(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_bls12_381_serde_miracl");

    group.bench_function("miracl_fr_to_bytes", |b| {
        b.iter_batched_ref(
            || random_scalar().to_miracl(),
            |s| miracl_fr_to_bytes(s),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("miracl_fr_from_bytes", |b| {
        b.iter_batched_ref(
            || random_scalar().serialize(),
            |b| miracl_fr_from_bytes(b),
            BatchSize::SmallInput,
        )
    });
    group.bench_function("miracl_g1_to_bytes", |b| {
        b.iter_batched_ref(
            || G1Affine::from(random_g1()).to_miracl(),
            |pt| miracl_g1_to_bytes(pt),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("miracl_g1_from_bytes", |b| {
        b.iter_batched_ref(
            || random_g1().serialize(),
            |b| miracl_g1_from_bytes(b),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("miracl_g1_from_bytes_unchecked", |b| {
        b.iter_batched_ref(
            || random_g1().serialize(),
            |b| miracl_g1_from_bytes_unchecked(b),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("miracl_g2_to_bytes", |b| {
        b.iter_batched_ref(
            || G2Affine::from(random_g2()).to_miracl(),
            |pt| miracl_g2_to_bytes(pt),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("miracl_g2_from_bytes", |b| {
        b.iter_batched_ref(
            || random_g2().serialize(),
            |b| miracl_g2_from_bytes(b),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("miracl_g2_from_bytes_unchecked", |b| {
        b.iter_batched_ref(
            || random_g2().serialize(),
            |b| miracl_g2_from_bytes_unchecked(b),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, miracl_serde);
criterion_main!(benches);
