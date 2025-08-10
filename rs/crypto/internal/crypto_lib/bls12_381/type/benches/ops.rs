use criterion::*;
use ic_crypto_internal_bls12_381_type::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use paste::paste;
use rand::{CryptoRng, Rng};
use std::sync::Arc;

fn random_g1<R: Rng + CryptoRng>(rng: &mut R) -> G1Projective {
    G1Projective::hash(b"domain_sep", &rng.gen::<[u8; 32]>())
}

fn n_random_g1<R: Rng + CryptoRng>(n: usize, rng: &mut R) -> Vec<G1Projective> {
    let mut output = Vec::with_capacity(n);
    for _ in 0..n {
        output.push(random_g1(rng));
    }
    output
}

fn random_g2<R: Rng + CryptoRng>(rng: &mut R) -> G2Projective {
    G2Projective::hash(b"domain_sep", &rng.gen::<[u8; 32]>())
}

fn n_random_g2<R: Rng + CryptoRng>(n: usize, rng: &mut R) -> Vec<G2Projective> {
    let mut output = Vec::with_capacity(n);
    for _ in 0..n {
        output.push(random_g2(rng));
    }
    output
}

fn random_g2_prepared<R: Rng + CryptoRng>(rng: &mut R) -> G2Prepared {
    G2Prepared::from(random_g2(rng))
}

fn random_gt<R: Rng + CryptoRng>(rng: &mut R) -> Gt {
    Gt::pairing(&random_g1(rng).into(), &random_g2(rng).into())
}

fn random_scalar<R: Rng + CryptoRng>(rng: &mut R) -> Scalar {
    Scalar::random(rng)
}

fn random_sparse_scalar<R: Rng + CryptoRng>(num_bits: u8, rng: &mut R) -> Scalar {
    Scalar::random_sparse(rng, num_bits)
}

fn n_random_scalar<R: Rng + CryptoRng>(size: usize, rng: &mut R) -> Vec<Scalar> {
    let mut r = Vec::with_capacity(size);
    for _ in 0..size {
        r.push(random_scalar(rng))
    }
    r
}

fn scalar_muln_instance<R: Rng + CryptoRng>(
    terms: usize,
    rng: &mut R,
) -> (Vec<Scalar>, Vec<Scalar>) {
    (n_random_scalar(terms, rng), n_random_scalar(terms, rng))
}

fn g1_muln_instance<R: Rng + CryptoRng>(
    terms: usize,
    rng: &mut R,
) -> (Vec<G1Projective>, Vec<Scalar>) {
    let mut points = Vec::with_capacity(terms);
    let mut scalars = Vec::with_capacity(terms);
    for _ in 0..terms {
        points.push(random_g1(rng));
        scalars.push(random_scalar(rng));
    }
    (points, scalars)
}

fn g1_sparse_muln_instance<R: Rng + CryptoRng>(
    terms: usize,
    num_bits: u8,
    rng: &mut R,
) -> Vec<(G1Affine, Scalar)> {
    (0..terms)
        .map(|_| {
            (
                random_g1(rng).to_affine(),
                random_sparse_scalar(num_bits, rng),
            )
        })
        .collect()
}

fn g2_muln_instance<R: Rng + CryptoRng>(
    terms: usize,
    rng: &mut R,
) -> (Vec<G2Projective>, Vec<Scalar>) {
    let mut points = Vec::with_capacity(terms);
    let mut scalars = Vec::with_capacity(terms);
    for _ in 0..terms {
        points.push(random_g2(rng));
        scalars.push(random_scalar(rng));
    }
    (points, scalars)
}

fn g2_sparse_muln_instance<R: Rng + CryptoRng>(
    terms: usize,
    num_bits: u8,
    rng: &mut R,
) -> Vec<(G2Affine, Scalar)> {
    (0..terms)
        .map(|_| {
            (
                random_g2(rng).to_affine(),
                random_sparse_scalar(num_bits, rng),
            )
        })
        .collect()
}

fn n_pairing_instance<R: Rng + CryptoRng>(n: usize, rng: &mut R) -> Vec<(G1Affine, G2Prepared)> {
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push((random_g1(rng).into(), random_g2_prepared(rng)));
    }
    v
}

fn n_batch_sig_verification_instances<R: Rng + CryptoRng>(
    n: usize,
    rng: &mut R,
) -> Vec<(G1Affine, G2Affine, G1Affine)> {
    let fake_sigs_pks_msgs: Vec<_> = n_random_g1(n, rng)
        .into_iter()
        .map(|g1| g1.into())
        .zip(n_random_g2(n, rng).into_iter().map(|g2| g2.into()))
        .zip(n_random_g1(n, rng).into_iter().map(|g1| g1.into()))
        .map(|((sig, pk), msg)| (sig, pk, msg))
        .collect();
    fake_sigs_pks_msgs
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

    let rng = &mut reproducible_rng();

    group.bench_function("serialize", |b| {
        b.iter_batched_ref(
            || random_scalar(rng),
            |pt| pt.serialize(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("deserialize", |b| {
        b.iter_batched_ref(
            || random_scalar(rng).serialize(),
            |bytes| Scalar::deserialize(bytes),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("addition", |b| {
        b.iter_batched_ref(
            || (random_scalar(rng), random_scalar(rng)),
            |(s1, s2)| s1.clone() + s2.clone(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiply", |b| {
        b.iter_batched_ref(
            || (random_scalar(rng), random_scalar(rng)),
            |(s1, s2)| s1.clone() * s2.clone(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiexp_muln_32", |b| {
        b.iter_batched_ref(
            || scalar_muln_instance(32, rng),
            |(lhs, rhs)| Scalar::muln_vartime(lhs, rhs),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiexp_naive32", |b| {
        b.iter_batched_ref(
            || scalar_muln_instance(32, rng),
            |(lhs, rhs)| scalar_multiexp_naive(lhs, rhs),
            BatchSize::SmallInput,
        )
    });
}

fn bls12_381_g1_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_bls12_381_g1");

    let rng = &mut reproducible_rng();

    group.bench_function("serialize", |b| {
        b.iter_batched_ref(
            || random_g1(rng),
            |pt| pt.serialize(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("deserialize", |b| {
        b.iter_batched_ref(
            || random_g1(rng).serialize(),
            |bytes| G1Projective::deserialize(bytes),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("deserialize_unchecked", |b| {
        b.iter_batched_ref(
            || random_g1(rng).serialize(),
            |bytes| G1Projective::deserialize_unchecked(bytes),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("hash_32_B", |b| {
        b.iter_batched_ref(
            || rng.gen::<[u8; 32]>(),
            |bytes| G1Projective::hash(b"dst", bytes.as_slice()),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("addition", |b| {
        b.iter_batched_ref(
            || (random_g1(rng), random_g1(rng)),
            |(pt1, pt2)| pt1.clone() + pt2.clone(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("double", |b| {
        b.iter_batched_ref(|| random_g1(rng), |g1| g1.double(), BatchSize::SmallInput)
    });

    group.bench_function("mixed addition", |b| {
        b.iter_batched_ref(
            || (random_g1(rng), G1Affine::from(random_g1(rng))),
            |(pt1, pt2)| pt1.clone() + pt2.clone(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiply", |b| {
        b.iter_batched_ref(
            || (random_g1(rng), random_scalar(rng)),
            |(pt, scalar)| pt.clone() * scalar.clone(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("batch_mul(32)", |b| {
        b.iter_batched_ref(
            || (random_g1(rng).to_affine(), n_random_scalar(32, rng)),
            |(pt, scalars)| G1Affine::batch_mul(pt, scalars),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("precompute", |b| {
        b.iter_batched_ref(
            || random_g1(rng).to_affine(),
            |pt| pt.precompute(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiply with precompute", |b| {
        b.iter_batched_ref(
            || {
                (
                    {
                        let mut pt = random_g1(rng).to_affine();
                        pt.precompute();
                        pt
                    },
                    random_scalar(rng),
                )
            },
            |(pt, scalar)| pt.clone() * scalar.clone(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("to_affine", |b| {
        b.iter_batched_ref(
            || random_g1(rng),
            |pt| pt.to_affine(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("batch_normalize(32)", |b| {
        b.iter_batched_ref(
            || n_random_g1(32, rng),
            |pts| G1Projective::batch_normalize(pts),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("batch_normalize(128)", |b| {
        b.iter_batched_ref(
            || n_random_g1(128, rng),
            |pts| G1Projective::batch_normalize(pts),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiexp_mul2", |b| {
        b.iter_batched_ref(
            || {
                (
                    random_g1(rng),
                    random_scalar(rng),
                    random_g1(rng),
                    random_scalar(rng),
                )
            },
            |(p1, s1, p2, s2)| G1Projective::mul2(p1, s1, p2, s2),
            BatchSize::SmallInput,
        )
    });

    for n in [2, 4, 8, 12, 16, 24, 32, 48, 64, 96, 128, 256] {
        group.bench_function(format!("multiexp_naive_{}", n), |b| {
            b.iter_batched_ref(
                || g1_muln_instance(n, rng),
                |(points, scalars)| g1_multiexp_naive(&points[..], &scalars[..]),
                BatchSize::SmallInput,
            )
        });
        group.bench_function(format!("multiexp_muln_{}", n), |b| {
            b.iter_batched_ref(
                || g1_muln_instance(n, rng),
                |(points, scalars)| G1Projective::muln_vartime(&points[..], &scalars[..]),
                BatchSize::SmallInput,
            )
        });
    }

    group.bench_function("multiexp_muln_sparse_32_inputs_16_bits", |b| {
        b.iter_batched_ref(
            || g1_sparse_muln_instance(32, 16, rng),
            |points_scalars| {
                let points_scalars_refs: Vec<_> =
                    points_scalars.iter().map(|(p, s)| (p, s)).collect();
                G1Projective::muln_affine_sparse_vartime(&points_scalars_refs[..]);
            },
            BatchSize::SmallInput,
        )
    });
}

fn bls12_381_g2_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_bls12_381_g2");

    let rng = &mut reproducible_rng();

    group.bench_function("serialize", |b| {
        b.iter_batched_ref(
            || random_g2(rng),
            |pt| pt.serialize(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("deserialize", |b| {
        b.iter_batched_ref(
            || random_g2(rng).serialize(),
            |bytes| G2Projective::deserialize(bytes),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("deserialize_unchecked", |b| {
        b.iter_batched_ref(
            || random_g2(rng).serialize(),
            |bytes| G2Projective::deserialize_unchecked(bytes),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("hash_32_B", |b| {
        b.iter_batched_ref(
            || rng.gen::<[u8; 32]>(),
            |bytes| G2Projective::hash(b"dst", bytes.as_slice()),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("addition", |b| {
        b.iter_batched_ref(
            || (random_g2(rng), random_g2(rng)),
            |(pt1, pt2)| pt1.clone() + pt2.clone(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("double", |b| {
        b.iter_batched_ref(|| random_g2(rng), |g2| g2.double(), BatchSize::SmallInput)
    });

    group.bench_function("mixed addition", |b| {
        b.iter_batched_ref(
            || (random_g2(rng), G2Affine::from(random_g2(rng))),
            |(pt1, pt2)| pt1.clone() + pt2.clone(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiply", |b| {
        b.iter_batched_ref(
            || (random_g2(rng), random_scalar(rng)),
            |(pt, scalar)| pt.clone() * scalar.clone(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("batch_mul(32)", |b| {
        b.iter_batched_ref(
            || (random_g2(rng).to_affine(), n_random_scalar(32, rng)),
            |(pt, scalars)| G2Affine::batch_mul(pt, scalars),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("precompute", |b| {
        b.iter_batched_ref(
            || random_g2(rng).to_affine(),
            |pt| pt.precompute(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiply with precompute", |b| {
        b.iter_batched_ref(
            || {
                (
                    {
                        let mut pt = random_g2(rng).to_affine();
                        pt.precompute();
                        pt
                    },
                    random_scalar(rng),
                )
            },
            |(pt, scalar)| pt.clone() * scalar.clone(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("to_affine", |b| {
        b.iter_batched_ref(
            || random_g2(rng),
            |pt| pt.to_affine(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("batch_normalize(32)", |b| {
        b.iter_batched_ref(
            || n_random_g2(32, rng),
            |pts| G2Projective::batch_normalize(pts),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("batch_normalize(128)", |b| {
        b.iter_batched_ref(
            || n_random_g2(128, rng),
            |pts| G2Projective::batch_normalize(pts),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("prepare", |b| {
        b.iter_batched_ref(
            || G2Affine::from(random_g2(rng)),
            |pt| G2Prepared::from(pt.clone()),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiexp_mul2", |b| {
        b.iter_batched_ref(
            || {
                (
                    random_g2(rng),
                    random_scalar(rng),
                    random_g2(rng),
                    random_scalar(rng),
                )
            },
            |(p1, s1, p2, s2)| G2Projective::mul2(p1, s1, p2, s2),
            BatchSize::SmallInput,
        )
    });

    for n in [2, 4, 8, 12, 16, 24, 32, 48, 64, 96, 128, 256] {
        group.bench_function(format!("multiexp_naive_{}", n), |b| {
            b.iter_batched_ref(
                || g2_muln_instance(n, rng),
                |(points, scalars)| g2_multiexp_naive(&points[..], &scalars[..]),
                BatchSize::SmallInput,
            )
        });

        group.bench_function(format!("multiexp_muln_{}", n), |b| {
            b.iter_batched_ref(
                || g2_muln_instance(n, rng),
                |(points, scalars)| G2Projective::muln_vartime(&points[..], &scalars[..]),
                BatchSize::SmallInput,
            )
        });
    }

    group.bench_function("multiexp_muln_sparse_32_inputs_16_bits", |b| {
        b.iter_batched_ref(
            || g2_sparse_muln_instance(32, 16, rng),
            |points_scalars| {
                let points_scalars_refs: Vec<_> =
                    points_scalars.iter().map(|(p, s)| (p, s)).collect();
                G2Projective::muln_affine_sparse_vartime(&points_scalars_refs[..]);
            },
            BatchSize::SmallInput,
        )
    });
}

fn pairing_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_bls12_381_gt");

    let rng = &mut reproducible_rng();

    group.bench_function("addition", |b| {
        b.iter_batched_ref(
            || (random_gt(rng), random_gt(rng)),
            |(gt1, gt2)| gt1.clone() + gt2.clone(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("double", |b| {
        b.iter_batched_ref(|| random_gt(rng), |gt| gt.double(), BatchSize::SmallInput)
    });

    group.bench_function("multiply", |b| {
        b.iter_batched_ref(
            || (random_gt(rng), random_scalar(rng)),
            |(gt, scalar)| gt.clone() * scalar.clone(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("multiply_u16", |b| {
        b.iter_batched_ref(
            || rng.gen::<u16>(),
            |s| Gt::g_mul_u16(*s),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("pairing", |b| {
        b.iter_batched_ref(
            || (random_g1(rng).into(), random_g2(rng).into()),
            |(g1, g2)| Gt::pairing(g1, g2),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("pairing-with-prep", |b| {
        b.iter_batched_ref(
            || (random_g1(rng).into(), random_g2_prepared(rng)),
            |(g1, g2)| Gt::multipairing(&[(g1, g2)]),
            BatchSize::SmallInput,
        )
    });

    // Simulates the pairing operation used in FS NI-DKG (2 prepared G2, 1 random)
    group.bench_function("fsnidkg-3-pairing", |b| {
        b.iter_batched_ref(
            || {
                (
                    random_g1(rng).into(),
                    random_g2_prepared(rng),
                    random_g1(rng).into(),
                    random_g2_prepared(rng),
                    random_g1(rng).into(),
                    random_g2(rng),
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

    for n in [2, 3, 10, 20] {
        group.bench_function(format!("{}-pairing", n), |b| {
            b.iter_batched_ref(
                || n_pairing_instance(n, rng),
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
            || {
                (
                    random_g1(rng).into(),
                    random_g2(rng).into(),
                    random_g1(rng).into(),
                )
            },
            |(sig, pk, msg)| verify_bls_signature(sig, pk, msg),
            BatchSize::SmallInput,
        )
    });
}

fn bls12_381_batch_sig_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_bls12_381_batch_sig_verification");

    let rng = &mut reproducible_rng();

    for num_args in [2usize, 4, 8, 16, 32, 64, 128] {
        group.throughput(Throughput::Elements(num_args as u64));
        group.bench_with_input(
            BenchmarkId::new("naive", num_args),
            &num_args,
            |b, &size| {
                b.iter_batched_ref(
                    || n_batch_sig_verification_instances(size, rng),
                    |sigs_pks_msgs| {
                        for (sig, pk, msg) in sigs_pks_msgs.iter() {
                            black_box(verify_bls_signature(sig, pk, msg));
                        }
                    },
                    BatchSize::SmallInput,
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("batched_distinct", num_args),
            &num_args,
            |b, &size| {
                b.iter_batched_ref(
                    || (n_batch_sig_verification_instances(size, rng), rng.fork()),
                    |(sigs_pks_msgs, rng_fork)| {
                        let sigs_pks_msgs_refs: Vec<_> = sigs_pks_msgs
                            .iter()
                            .map(|(sig, pk, msg)| (sig, pk, msg))
                            .collect();
                        black_box(verify_bls_signature_batch_distinct(
                            &sigs_pks_msgs_refs[..],
                            rng_fork,
                        ));
                    },
                    BatchSize::SmallInput,
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("batched_same_msg", num_args),
            &num_args,
            |b, &size| {
                b.iter_batched_ref(
                    || (n_batch_sig_verification_instances(size, rng), rng.fork()),
                    |(sigs_pks_msgs, rng_fork)| {
                        let sigs_pks_refs: Vec<_> = sigs_pks_msgs
                            .iter()
                            .map(|(sig, pk, _msg)| (sig, pk))
                            .collect();

                        black_box(verify_bls_signature_batch_same_msg(
                            &sigs_pks_refs[..],
                            &sigs_pks_msgs[0].2,
                            rng_fork,
                        ));
                    },
                    BatchSize::SmallInput,
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("batched_same_pk", num_args),
            &num_args,
            |b, &size| {
                b.iter_batched_ref(
                    || (n_batch_sig_verification_instances(size, rng), rng.fork()),
                    |(sigs_pks_msgs, rng_fork)| {
                        let sigs_msgs_refs: Vec<_> = sigs_pks_msgs
                            .iter()
                            .map(|(sig, _pk, msg)| (sig, msg))
                            .collect();
                        black_box(verify_bls_signature_batch_same_pk(
                            &sigs_msgs_refs[..],
                            &sigs_pks_msgs[0].1,
                            rng_fork,
                        ));
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    let plot_config = PlotConfiguration::default().summary_scale(AxisScale::Logarithmic);
    group.plot_config(plot_config);
    group.finish();
}

fn bls12_381_batch_sig_verification_multithreaded(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_bls12_381_batch_sig_verification_multithreaded");

    let rng = &mut reproducible_rng();

    const NUM_THREADS: usize = 8;

    for num_args in [80, 800] {
        group.throughput(Throughput::Elements(num_args as u64));
        group.bench_with_input(
            BenchmarkId::new("batched_distinct", num_args),
            &num_args,
            |b, &size| {
                b.iter_batched_ref(
                    || {
                        (
                            Arc::new(n_batch_sig_verification_instances(size, rng)),
                            rng.fork(),
                        )
                    },
                    |(sigs_pks_msgs, rng_fork)| {
                        let threads = (0..NUM_THREADS).map(|i| {
                            let size_c = size;
                            let sigs_pks_msgs_c = sigs_pks_msgs.clone();
                            let mut rng_for_thread = rng_fork.fork();
                            std::thread::spawn(move || {
                                let sigs_pks_msgs_refs = sigs_pks_msgs_c
                                    [i * size_c / NUM_THREADS..(i + 1) * size_c / NUM_THREADS]
                                    .iter()
                                    .map(|(sig, pk, msg)| (sig, pk, msg))
                                    .collect::<Vec<_>>();
                                black_box(verify_bls_signature_batch_distinct(
                                    &sigs_pks_msgs_refs,
                                    &mut rng_for_thread,
                                ));
                            })
                        });
                        for t in threads {
                            t.join().unwrap();
                        }
                    },
                    BatchSize::SmallInput,
                );
            },
        );
        group.bench_with_input(
            BenchmarkId::new("batched_same_msg", num_args),
            &num_args,
            |b, &size| {
                b.iter_batched_ref(
                    || {
                        (
                            Arc::new(n_batch_sig_verification_instances(size, rng)),
                            rng.fork(),
                        )
                    },
                    |(sigs_pks_msgs, rng_fork)| {
                        let mut threads = vec![];
                        for i in 0..NUM_THREADS {
                            let size_c = size;
                            let sigs_pks_msgs_c = sigs_pks_msgs.clone();
                            let mut rng_for_thread = rng_fork.fork();
                            threads.push(std::thread::spawn(move || {
                                let sigs_pks_refs: Vec<_> = sigs_pks_msgs_c
                                    [i * size_c / NUM_THREADS..(i + 1) * size_c / NUM_THREADS]
                                    .iter()
                                    .map(|(sig, pk, _msg)| (sig, pk))
                                    .collect();
                                black_box(verify_bls_signature_batch_same_msg(
                                    &sigs_pks_refs[..],
                                    &sigs_pks_msgs_c[0].2,
                                    &mut rng_for_thread,
                                ))
                            }));
                        }

                        for t in threads {
                            t.join().unwrap();
                        }
                    },
                    BatchSize::SmallInput,
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("batched_same_pk", num_args),
            &num_args,
            |b, &size| {
                b.iter_batched_ref(
                    || {
                        (
                            Arc::new(n_batch_sig_verification_instances(size, rng)),
                            rng.fork(),
                        )
                    },
                    |(sigs_pks_msgs, rng_fork)| {
                        let mut threads = vec![];
                        for i in 0..NUM_THREADS {
                            let size_c = size;
                            let sigs_pks_msgs_c = sigs_pks_msgs.clone();
                            let mut rng_for_thread = rng_fork.fork();
                            threads.push(std::thread::spawn(move || {
                                let sigs_msgs_refs: Vec<_> = sigs_pks_msgs_c
                                    [i * size_c / NUM_THREADS..(i + 1) * size_c / NUM_THREADS]
                                    .iter()
                                    .map(|(sig, _pk, msg)| (sig, msg))
                                    .collect();
                                black_box(verify_bls_signature_batch_same_pk(
                                    &sigs_msgs_refs,
                                    &sigs_pks_msgs_c[0].1,
                                    &mut rng_for_thread,
                                ))
                            }));
                        }
                        for t in threads {
                            t.join().unwrap();
                        }
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    let plot_config = PlotConfiguration::default().summary_scale(AxisScale::Logarithmic);
    group.plot_config(plot_config);
    group.finish();
}

macro_rules! crypto_bls12_381_mul2_precomputation_init {
    ($group:ident, $projective:ty) => {
        paste! {
            fn [< mul2_precomputation_ $group >](c: &mut Criterion) {
                let mut group =
                    c.benchmark_group(format!("crypto_bls12_381_mul2_precomputation_{}", stringify!($group)));
                let random = [< random_ $group >];

                let rng = &mut reproducible_rng();

                // range of arguments for generic functions
                for num_args in (1..=101).step_by(10) {
                    group.bench_with_input(
                        BenchmarkId::new("naive", num_args),
                        &num_args,
                        |b, &size| {
                            b.iter_batched_ref(
                                || (scalar_muln_instance(size, rng), random(rng), random(rng)),
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
                                        scalar_muln_instance(size, rng),
                                        <$projective>::compute_mul2_tbl(&random(rng), &random(rng)),
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
    bls12_381_batch_sig_verification,
    bls12_381_batch_sig_verification_multithreaded,
    mul2_precomputation_g1,
    mul2_precomputation_g2,
);
criterion_main!(benches);
