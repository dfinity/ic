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

fn random_g2_prepared() -> G2Prepared {
    G2Prepared::from(random_g2())
}

fn random_gt() -> Gt {
    Gt::pairing(&random_g1().into(), &random_g2().into())
}

fn random_scalar() -> Scalar {
    let mut rng = rand::thread_rng();
    Scalar::random(&mut rng)
}

fn list_of_random_scalars(size: usize) -> Vec<Scalar> {
    let mut r = Vec::with_capacity(size);
    for _ in 0..size {
        r.push(random_scalar())
    }
    r
}

fn scalar_muln_instance(terms: usize) -> (Vec<Scalar>, Vec<Scalar>) {
    (list_of_random_scalars(terms), list_of_random_scalars(terms))
}

fn g1_muln_instance(terms: usize) -> Vec<(G1Projective, Scalar)> {
    let mut r = Vec::with_capacity(terms);
    for _ in 0..terms {
        r.push((random_g1(), random_scalar()));
    }
    r
}

fn g2_muln_instance(terms: usize) -> Vec<(G2Projective, Scalar)> {
    let mut r = Vec::with_capacity(terms);
    for _ in 0..terms {
        r.push((random_g2(), random_scalar()));
    }
    r
}

fn scalar_multiexp_naive(lhs: &[Scalar], rhs: &[Scalar]) -> Scalar {
    let terms = std::cmp::min(lhs.len(), rhs.len());
    let mut accum = Scalar::zero();
    for i in 0..terms {
        accum += lhs[i] * rhs[i];
    }
    accum
}

fn g1_multiexp_naive(terms: &[(G1Projective, Scalar)]) -> G1Projective {
    let mut accum = *G1Projective::identity();
    for (pt, s) in terms {
        accum += *pt * s;
    }
    accum
}

fn bls12_381_scalar_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_bls12_381_scalar");

    group.bench_function("serialize", |b| {
        b.iter_batched_ref(random_scalar, |pt| pt.serialize(), BatchSize::SmallInput)
    });

    group.bench_function("deserialize", |b| {
        b.iter_batched_ref(
            || random_scalar().serialize(),
            |bytes| Scalar::deserialize(bytes),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("addition", |b| {
        b.iter_batched_ref(
            || (random_scalar(), random_scalar()),
            |(s1, s2)| *s1 + *s2,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiply", |b| {
        b.iter_batched_ref(
            || (random_scalar(), random_scalar()),
            |(s1, s2)| *s1 * *s2,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiexp_muln_32", |b| {
        b.iter_batched_ref(
            || scalar_muln_instance(32),
            |(lhs, rhs)| Scalar::muln_vartime(lhs, rhs),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiexp_naive32", |b| {
        b.iter_batched_ref(
            || scalar_muln_instance(32),
            |(lhs, rhs)| scalar_multiexp_naive(lhs, rhs),
            BatchSize::SmallInput,
        )
    });
}

fn bls12_381_g1_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_bls12_381_g1");

    group.bench_function("serialize", |b| {
        b.iter_batched_ref(random_g1, |pt| pt.serialize(), BatchSize::SmallInput)
    });

    group.bench_function("deserialize", |b| {
        b.iter_batched_ref(
            || random_g1().serialize(),
            |bytes| G1Projective::deserialize(bytes),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("deserialize_unchecked", |b| {
        b.iter_batched_ref(
            || random_g1().serialize(),
            |bytes| G1Projective::deserialize_unchecked(bytes),
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

    group.bench_function("mixed addition", |b| {
        b.iter_batched_ref(
            || (random_g1(), G1Affine::from(random_g1())),
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
        b.iter_batched_ref(random_g1, |pt| G1Affine::from(*pt), BatchSize::SmallInput)
    });

    group.bench_function("multiexp_naive2", |b| {
        b.iter_batched_ref(
            || g1_muln_instance(2),
            |terms| g1_multiexp_naive(terms),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiexp_naive8", |b| {
        b.iter_batched_ref(
            || g1_muln_instance(8),
            |terms| g1_multiexp_naive(terms),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiexp_naive32", |b| {
        b.iter_batched_ref(
            || g1_muln_instance(32),
            |terms| g1_multiexp_naive(terms),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiexp_mul2", |b| {
        b.iter_batched_ref(
            || (random_g1(), random_scalar(), random_g1(), random_scalar()),
            |(p1, s1, p2, s2)| G1Projective::mul2(p1, s1, p2, s2),
            BatchSize::SmallInput,
        )
    });
    group.bench_function("multiexp_muln_8", |b| {
        b.iter_batched_ref(
            || g1_muln_instance(8),
            |terms| G1Projective::muln_vartime(terms),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiexp_muln_32", |b| {
        b.iter_batched_ref(
            || g1_muln_instance(32),
            |terms| G1Projective::muln_vartime(terms),
            BatchSize::SmallInput,
        )
    });
}

fn bls12_381_g2_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_bls12_381_g2");

    group.bench_function("serialize", |b| {
        b.iter_batched_ref(random_g2, |pt| pt.serialize(), BatchSize::SmallInput)
    });

    group.bench_function("deserialize", |b| {
        b.iter_batched_ref(
            || random_g2().serialize(),
            |bytes| G2Projective::deserialize(bytes),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("deserialize_unchecked", |b| {
        b.iter_batched_ref(
            || random_g2().serialize(),
            |bytes| G2Projective::deserialize_unchecked(bytes),
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

    group.bench_function("mixed addition", |b| {
        b.iter_batched_ref(
            || (random_g2(), G2Affine::from(random_g2())),
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
        b.iter_batched_ref(random_g2, |pt| G2Affine::from(*pt), BatchSize::SmallInput)
    });

    group.bench_function("prepare", |b| {
        b.iter_batched_ref(
            || G2Affine::from(random_g2()),
            |pt| G2Prepared::from(*pt),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiexp_muln_8", |b| {
        b.iter_batched_ref(
            || g2_muln_instance(8),
            |terms| G2Projective::muln_vartime(terms),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiexp_muln_32", |b| {
        b.iter_batched_ref(
            || g2_muln_instance(32),
            |terms| G2Projective::muln_vartime(terms),
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

    group.bench_function("pairing-with-prep", |b| {
        b.iter_batched_ref(
            || (random_g1().into(), random_g2_prepared()),
            |(g1, g2)| Gt::multipairing(&[(g1, g2)]),
            BatchSize::SmallInput,
        )
    });

    // Simulates the pairing operation used in FS NI-DKG (2 prepared G2, 1 random)
    group.bench_function("fsnidkg-3-pairing", |b| {
        b.iter_batched_ref(
            || {
                (
                    random_g1().into(),
                    random_g2_prepared(),
                    random_g1().into(),
                    random_g2_prepared(),
                    random_g1().into(),
                    random_g2(),
                )
            },
            |(g1a, g2a, g1b, g2b, g1c, g2c)| {
                Gt::multipairing(&[(g1a, g2a), (g1b, g2b), (g1c, &G2Prepared::from(*g2c))])
            },
            BatchSize::SmallInput,
        )
    });

    fn n_pairing_instance(n: usize) -> Vec<(G1Affine, G2Prepared)> {
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push((random_g1().into(), random_g2_prepared()));
        }
        v
    }

    for n in [2, 3, 10, 20] {
        group.bench_function(format!("{}-pairing", n), |b| {
            b.iter_batched_ref(
                || n_pairing_instance(n),
                |terms| {
                    let terms_ref = terms.iter().map(|(g1, g2)| (g1, g2)).collect::<Vec<_>>();
                    Gt::multipairing(terms_ref.as_slice())
                },
                BatchSize::SmallInput,
            )
        });
    }

    group.bench_function("verify_bls_signature", |b| {
        b.iter_batched_ref(
            || (random_g1().into(), random_g2().into(), random_g1().into()),
            |(sig, pk, msg)| verify_bls_signature(sig, pk, msg),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(
    benches,
    bls12_381_scalar_ops,
    bls12_381_g1_ops,
    bls12_381_g2_ops,
    pairing_ops
);
criterion_main!(benches);
