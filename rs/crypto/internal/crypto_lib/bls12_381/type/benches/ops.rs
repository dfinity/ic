use criterion::*;
use ic_crypto_internal_bls12_381_type::*;
use paste::paste;
use rand::Rng;

fn random_g1() -> G1Projective {
    let mut rng = rand::thread_rng();
    G1Projective::hash(b"domain_sep", &rng.gen::<[u8; 32]>())
}

fn n_random_g1(n: usize) -> Vec<G1Projective> {
    let mut output = Vec::with_capacity(n);
    for _ in 0..n {
        output.push(random_g1());
    }
    output
}

fn random_g2() -> G2Projective {
    let mut rng = rand::thread_rng();
    G2Projective::hash(b"domain_sep", &rng.gen::<[u8; 32]>())
}

fn n_random_g2(n: usize) -> Vec<G2Projective> {
    let mut output = Vec::with_capacity(n);
    for _ in 0..n {
        output.push(random_g2());
    }
    output
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

fn n_random_scalar(size: usize) -> Vec<Scalar> {
    let mut r = Vec::with_capacity(size);
    for _ in 0..size {
        r.push(random_scalar())
    }
    r
}

fn scalar_muln_instance(terms: usize) -> (Vec<Scalar>, Vec<Scalar>) {
    (n_random_scalar(terms), n_random_scalar(terms))
}

fn g1_muln_instance(terms: usize) -> (Vec<G1Projective>, Vec<Scalar>) {
    let mut points = Vec::with_capacity(terms);
    let mut scalars = Vec::with_capacity(terms);
    for _ in 0..terms {
        points.push(random_g1());
        scalars.push(random_scalar());
    }
    (points, scalars)
}

fn g2_muln_instance(terms: usize) -> (Vec<G2Projective>, Vec<Scalar>) {
    let mut points = Vec::with_capacity(terms);
    let mut scalars = Vec::with_capacity(terms);
    for _ in 0..terms {
        points.push(random_g2());
        scalars.push(random_scalar());
    }
    (points, scalars)
}

fn scalar_multiexp_naive(lhs: &[Scalar], rhs: &[Scalar]) -> Scalar {
    let terms = std::cmp::min(lhs.len(), rhs.len());
    let mut accum = Scalar::zero();
    for i in 0..terms {
        accum += &lhs[i] * &rhs[i];
    }
    accum
}

fn g1_multiexp_naive(points: &[G1Projective], scalars: &[Scalar]) -> G1Projective {
    points
        .iter()
        .zip(scalars.iter())
        .fold(G1Projective::identity(), |accum, (p, s)| accum + p * s)
}

fn g2_multiexp_naive(points: &[G2Projective], scalars: &[Scalar]) -> G2Projective {
    points
        .iter()
        .zip(scalars.iter())
        .fold(G2Projective::identity(), |accum, (p, s)| accum + p * s)
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
            |(s1, s2)| s1.clone() + s2.clone(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiply", |b| {
        b.iter_batched_ref(
            || (random_scalar(), random_scalar()),
            |(s1, s2)| s1.clone() * s2.clone(),
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
            |(pt1, pt2)| pt1.clone() + pt2.clone(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("double", |b| {
        b.iter_batched_ref(random_g1, |g1| g1.double(), BatchSize::SmallInput)
    });

    group.bench_function("mixed addition", |b| {
        b.iter_batched_ref(
            || (random_g1(), G1Affine::from(random_g1())),
            |(pt1, pt2)| pt1.clone() + pt2.clone(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiply", |b| {
        b.iter_batched_ref(
            || (random_g1(), random_scalar()),
            |(pt, scalar)| pt.clone() * scalar.clone(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("batch_mul(32)", |b| {
        b.iter_batched_ref(
            || (random_g1().to_affine(), n_random_scalar(32)),
            |(pt, scalars)| G1Affine::batch_mul(pt, scalars),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("precompute", |b| {
        b.iter_batched_ref(
            || random_g1().to_affine(),
            |pt| pt.precompute(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiply with precompute", |b| {
        b.iter_batched_ref(
            || {
                (
                    {
                        let mut pt = random_g1().to_affine();
                        pt.precompute();
                        pt
                    },
                    random_scalar(),
                )
            },
            |(pt, scalar)| pt.clone() * scalar.clone(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("to_affine", |b| {
        b.iter_batched_ref(random_g1, |pt| pt.to_affine(), BatchSize::SmallInput)
    });

    group.bench_function("batch_normalize(32)", |b| {
        b.iter_batched_ref(
            || n_random_g1(32),
            |pts| G1Projective::batch_normalize(pts),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("batch_normalize(128)", |b| {
        b.iter_batched_ref(
            || n_random_g1(128),
            |pts| G1Projective::batch_normalize(pts),
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

    for n in [2, 4, 8, 12, 16, 24, 32, 48, 64, 96, 128, 256] {
        group.bench_function(format!("multiexp_naive_{}", n), |b| {
            b.iter_batched_ref(
                || g1_muln_instance(n),
                |(points, scalars)| g1_multiexp_naive(&points[..], &scalars[..]),
                BatchSize::SmallInput,
            )
        });

        group.bench_function(format!("multiexp_muln_{}", n), |b| {
            b.iter_batched_ref(
                || g1_muln_instance(n),
                |(points, scalars)| G1Projective::muln_vartime(&points[..], &scalars[..]),
                BatchSize::SmallInput,
            )
        });
    }
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
            |(pt1, pt2)| pt1.clone() + pt2.clone(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("double", |b| {
        b.iter_batched_ref(random_g2, |g2| g2.double(), BatchSize::SmallInput)
    });

    group.bench_function("mixed addition", |b| {
        b.iter_batched_ref(
            || (random_g2(), G2Affine::from(random_g2())),
            |(pt1, pt2)| pt1.clone() + pt2.clone(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiply", |b| {
        b.iter_batched_ref(
            || (random_g2(), random_scalar()),
            |(pt, scalar)| pt.clone() * scalar.clone(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("batch_mul(32)", |b| {
        b.iter_batched_ref(
            || (random_g2().to_affine(), n_random_scalar(32)),
            |(pt, scalars)| G2Affine::batch_mul(pt, scalars),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("precompute", |b| {
        b.iter_batched_ref(
            || random_g2().to_affine(),
            |pt| pt.precompute(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiply with precompute", |b| {
        b.iter_batched_ref(
            || {
                (
                    {
                        let mut pt = random_g2().to_affine();
                        pt.precompute();
                        pt
                    },
                    random_scalar(),
                )
            },
            |(pt, scalar)| pt.clone() * scalar.clone(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("to_affine", |b| {
        b.iter_batched_ref(random_g2, |pt| pt.to_affine(), BatchSize::SmallInput)
    });

    group.bench_function("batch_normalize(32)", |b| {
        b.iter_batched_ref(
            || n_random_g2(32),
            |pts| G2Projective::batch_normalize(pts),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("batch_normalize(128)", |b| {
        b.iter_batched_ref(
            || n_random_g2(128),
            |pts| G2Projective::batch_normalize(pts),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("prepare", |b| {
        b.iter_batched_ref(
            || G2Affine::from(random_g2()),
            |pt| G2Prepared::from(pt.clone()),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiexp_mul2", |b| {
        b.iter_batched_ref(
            || (random_g2(), random_scalar(), random_g2(), random_scalar()),
            |(p1, s1, p2, s2)| G2Projective::mul2(p1, s1, p2, s2),
            BatchSize::SmallInput,
        )
    });

    for n in [2, 4, 8, 12, 16, 24, 32, 48, 64, 96, 128, 256] {
        group.bench_function(format!("multiexp_naive_{}", n), |b| {
            b.iter_batched_ref(
                || g2_muln_instance(n),
                |(points, scalars)| g2_multiexp_naive(&points[..], &scalars[..]),
                BatchSize::SmallInput,
            )
        });

        group.bench_function(format!("multiexp_muln_{}", n), |b| {
            b.iter_batched_ref(
                || g2_muln_instance(n),
                |(points, scalars)| G2Projective::muln_vartime(&points[..], &scalars[..]),
                BatchSize::SmallInput,
            )
        });
    }
}

fn pairing_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_bls12_381_gt");

    group.bench_function("addition", |b| {
        b.iter_batched_ref(
            || (random_gt(), random_gt()),
            |(gt1, gt2)| gt1.clone() + gt2.clone(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("double", |b| {
        b.iter_batched_ref(random_gt, |gt| gt.double(), BatchSize::SmallInput)
    });

    group.bench_function("multiply", |b| {
        b.iter_batched_ref(
            || (random_gt(), random_scalar()),
            |(gt, scalar)| gt.clone() * scalar.clone(),
            BatchSize::SmallInput,
        )
    });

    let mut rng = rand::thread_rng();

    group.bench_function("multiply_u16", |b| {
        b.iter_batched_ref(
            || rng.gen::<u16>(),
            |s| Gt::g_mul_u16(*s),
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
                Gt::multipairing(&[
                    (g1a, g2a),
                    (g1b, g2b),
                    (g1c, &G2Prepared::from(g2c.clone())),
                ])
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

macro_rules! crypto_bls12_381_mul2_precomputation_init {
    ($group:ident, $projective:ty) => {
        paste! {
            fn [< mul2_precomputation_ $group >](c: &mut Criterion) {
                let mut group =
                    c.benchmark_group(format!("crypto_bls12_381_mul2_precomputation_{}", stringify!($group)));
                    let random = [< random_ $group >];

                // range of arguments for generic functions
                for num_args in (1..=101).step_by(10) {
                    group.bench_with_input(
                        BenchmarkId::new("naive", num_args),
                        &num_args,
                        |b, &size| {
                            b.iter_batched_ref(
                                || (scalar_muln_instance(size), random(), random()),
                                |((a, b), x, y)| {
                                    let mut result = Vec::<_>::with_capacity(size);
                                    for i in 0..a.len() {
                                        result.push(<$projective>::mul2(x, &a[i], y, &b[i]));
                                    }
                                    result
                                },
                                BatchSize::SmallInput,
                            )
                        },
                    );

                    group.bench_with_input(
                        BenchmarkId::new("precomputed", num_args),
                        &num_args,
                        |b, &size| {
                            b.iter_batched_ref(
                                || {
                                    (
                                        scalar_muln_instance(size),
                                        <$projective>::compute_mul2_tbl(&random(), &random()),
                                    )
                                },
                                |((a, b), tbl)| {
                                    let mut result = Vec::<_>::with_capacity(size);
                                    for i in 0..a.len() {
                                        result.push(tbl.mul2(
                                            &a[i],
                                            &b[i],
                                        ));
                                    }
                                    result
                                },
                                BatchSize::SmallInput,
                            )
                        },
                    );
                }

                group.finish()
            }
        }
    };
}

crypto_bls12_381_mul2_precomputation_init!(g1, G1Projective);
crypto_bls12_381_mul2_precomputation_init!(g2, G2Projective);

criterion_group!(
    benches,
    bls12_381_scalar_ops,
    bls12_381_g1_ops,
    bls12_381_g2_ops,
    pairing_ops,
    mul2_precomputation_g1,
    mul2_precomputation_g2,
);
criterion_main!(benches);
