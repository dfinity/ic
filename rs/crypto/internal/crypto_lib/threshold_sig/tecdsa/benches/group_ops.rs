use criterion::*;
use ic_crypto_internal_threshold_sig_ecdsa::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::{CryptoRng, Rng};

fn random_point<R: Rng + CryptoRng>(curve_type: EccCurveType, rng: &mut R) -> EccPoint {
    EccPoint::mul_by_g(&EccScalar::random(curve_type, rng))
}

fn random_scalar<R: Rng + CryptoRng>(curve_type: EccCurveType, rng: &mut R) -> EccScalar {
    EccScalar::random(curve_type, rng)
}

fn gen_mul_n_instance<R: Rng + CryptoRng>(
    num_terms: usize,
    curve_type: EccCurveType,
    rng: &mut R,
) -> Vec<(EccPoint, EccScalar)> {
    (0..num_terms)
        .map(|_| {
            (
                random_point(curve_type, rng),
                random_scalar(curve_type, rng),
            )
        })
        .collect()
}

fn mul_n_naive(terms: &[(EccPoint, EccScalar)]) -> EccPoint {
    let mut accum = EccPoint::identity(terms[0].0.curve_type());
    for (p, s) in terms {
        accum = accum.add_points(&p.scalar_mul(s).unwrap()).unwrap();
    }
    accum
}

fn point_multiexp_vartime_total(c: &mut Criterion) {
    let rng = &mut reproducible_rng();

    for curve_type in EccCurveType::all() {
        let mut group = c.benchmark_group(format!("crypto_point_multiexp_total_{}", curve_type));

        {
            // fixed 2 arguments for special-purpose functions with a fixed number of arguments
            let num_args = 2;
            group.bench_with_input(
                BenchmarkId::new("consttime_lincomb", num_args),
                &num_args,
                |b, size| {
                    b.iter_batched_ref(
                        || gen_mul_n_instance(*size, curve_type, rng),
                        |terms| {
                            EccPoint::mul_2_points(
                                &terms[0].0,
                                &terms[0].1,
                                &terms[1].0,
                                &terms[1].1,
                            )
                        },
                        BatchSize::SmallInput,
                    )
                },
            );
        }

        // range of arguments for generic functions
        for num_args in [2, 4, 8, 16, 32, 64, 128].iter() {
            group.bench_with_input(
                BenchmarkId::new("consttime_naive", num_args),
                &num_args,
                |b, &size| {
                    b.iter_batched_ref(
                        || gen_mul_n_instance(*size, curve_type, rng),
                        |terms| mul_n_naive(&terms[..]),
                        BatchSize::SmallInput,
                    )
                },
            );

            for window_size in [3, 4, 5, 6, 7] {
                group.bench_with_input(
                    BenchmarkId::new(format!("vartime_naf_{window_size}_total"), num_args),
                    &num_args,
                    |b, &size| {
                        b.iter_batched_ref(
                            || gen_mul_n_instance(*size, curve_type, rng),
                            |terms| {
                                // create "deep" refs of pairs
                                for (p, _s) in terms.iter_mut() {
                                    p.precompute(window_size).unwrap();
                                }
                                // create refs of pairs
                                let refs_of_pairs: Vec<_> =
                                    terms.iter().map(|(p, s)| (p, s)).collect();

                                EccPoint::mul_n_points_vartime(&refs_of_pairs)
                            },
                            BatchSize::SmallInput,
                        )
                    },
                );
            }
        }
        let plot_config = PlotConfiguration::default().summary_scale(AxisScale::Logarithmic);
        group.plot_config(plot_config);
        group.finish();
    }
}

fn point_multiexp_vartime_online(c: &mut Criterion) {
    let rng = &mut reproducible_rng();

    for curve_type in EccCurveType::all() {
        let mut group = c.benchmark_group(format!("crypto_point_multiexp_online_{}", curve_type));

        {
            // fixed 2 arguments for special-purpose functions with a fixed number of arguments
            let num_args = 2;
            group.bench_with_input(
                BenchmarkId::new("consttime_lincomb", num_args),
                &num_args,
                |b, size| {
                    b.iter_batched_ref(
                        || gen_mul_n_instance(*size, curve_type, rng),
                        |terms| {
                            EccPoint::mul_2_points(
                                &terms[0].0,
                                &terms[0].1,
                                &terms[1].0,
                                &terms[1].1,
                            )
                        },
                        BatchSize::SmallInput,
                    )
                },
            );
        }

        // range of arguments for generic functions
        for num_args in [2, 4, 8, 16, 32, 64, 128].iter() {
            group.bench_with_input(
                BenchmarkId::new("consttime_naive", num_args),
                &num_args,
                |b, &size| {
                    b.iter_batched_ref(
                        || gen_mul_n_instance(*size, curve_type, rng),
                        |terms| mul_n_naive(&terms[..]),
                        BatchSize::SmallInput,
                    )
                },
            );

            for window_size in [3, 4, 5, 6, 7] {
                group.bench_with_input(
                    BenchmarkId::new(format!("vartime_naf_{window_size}_online"), num_args),
                    &num_args,
                    |b, &size| {
                        b.iter_batched_ref(
                            || {
                                let mut terms = gen_mul_n_instance(*size, curve_type, rng);
                                // create "deep" refs of pairs
                                for (p, _s) in terms.iter_mut() {
                                    p.precompute(window_size).unwrap();
                                }
                                terms
                            },
                            |terms| {
                                // create refs of pairs
                                let refs_of_pairs: Vec<_> =
                                    terms.iter().map(|(p, s)| (p, s)).collect();
                                EccPoint::mul_n_points_vartime(&refs_of_pairs)
                            },
                            BatchSize::SmallInput,
                        )
                    },
                );
            }
        }
        let plot_config = PlotConfiguration::default().summary_scale(AxisScale::Logarithmic);
        group.plot_config(plot_config);
        group.finish();
    }
}

fn point_multiexp_constant_time(c: &mut Criterion) {
    let rng = &mut reproducible_rng();

    for curve_type in EccCurveType::all() {
        let mut group = c.benchmark_group(format!(
            "crypto_point_multiexp_constant_time_{}",
            curve_type
        ));

        {
            // fixed 2 arguments for special-purpose functions with a fixed number of arguments
            let num_args = 2;
            group.bench_with_input(
                BenchmarkId::new("consttime_lincomb", num_args),
                &num_args,
                |b, size| {
                    b.iter_batched_ref(
                        || gen_mul_n_instance(*size, curve_type, rng),
                        |terms| {
                            EccPoint::mul_2_points(
                                &terms[0].0,
                                &terms[0].1,
                                &terms[1].0,
                                &terms[1].1,
                            )
                        },
                        BatchSize::SmallInput,
                    )
                },
            );
        }

        {
            // fixed 2 arguments for special-purpose functions with a fixed number of arguments
            let num_args = 2;
            group.bench_with_input(
                BenchmarkId::new("consttime_pedersen", num_args),
                &num_args,
                |b, _size| {
                    b.iter_batched_ref(
                        || {
                            (
                                random_scalar(curve_type, rng),
                                random_scalar(curve_type, rng),
                            )
                        },
                        |(x, y)| EccPoint::pedersen(x, y),
                        BatchSize::SmallInput,
                    )
                },
            );
        }

        // range of arguments for generic functions
        for num_args in [2, 4, 8, 16, 32, 64, 128].iter() {
            group.bench_with_input(
                BenchmarkId::new("consttime_naive", num_args),
                &num_args,
                |b, &size| {
                    b.iter_batched_ref(
                        || gen_mul_n_instance(*size, curve_type, rng),
                        |terms| mul_n_naive(&terms[..]),
                        BatchSize::SmallInput,
                    )
                },
            );

            group.bench_with_input(
                BenchmarkId::new("constant_time_pippenger", num_args),
                &num_args,
                |b, &size| {
                    b.iter_batched_ref(
                        || gen_mul_n_instance(*size, curve_type, rng),
                        |terms| {
                            // create refs of pairs
                            let refs_of_pairs: Vec<_> = terms.iter().map(|(p, s)| (p, s)).collect();
                            EccPoint::mul_n_points_pippenger(&refs_of_pairs)
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
}

fn point_double_vs_addition(c: &mut Criterion) {
    let rng = &mut reproducible_rng();

    for curve_type in EccCurveType::all() {
        let mut group =
            c.benchmark_group(format!("crypto_point_double_vs_addition_{}", curve_type));

        group.bench_function(BenchmarkId::new("double", 0), |b| {
            b.iter_with_setup(|| random_point(curve_type, rng), |p| p.double())
        });

        group.bench_function(BenchmarkId::new("add_points", 0), |b| {
            b.iter_with_setup(
                || (random_point(curve_type, rng), random_point(curve_type, rng)),
                |(p_0, p_1)| p_0.add_points(&p_1),
            )
        });

        group.finish();
    }
}

fn point_mul(c: &mut Criterion) {
    let rng = &mut reproducible_rng();

    for curve_type in EccCurveType::all() {
        let mut group = c.benchmark_group(format!("crypto_point_multiplication_{}", curve_type));

        group.bench_function("multiply_arbitrary_point", |b| {
            b.iter_batched_ref(
                || {
                    (
                        random_point(curve_type, rng),
                        random_scalar(curve_type, rng),
                    )
                },
                |(p, s)| p.scalar_mul(s),
                BatchSize::SmallInput,
            )
        });

        group.bench_function("multiply_generator", |b| {
            b.iter_batched_ref(
                || random_scalar(curve_type, rng),
                |s| EccPoint::mul_by_g(s),
                BatchSize::SmallInput,
            )
        });

        group.bench_function("multiply_vartime_online", |b| {
            b.iter_batched_ref(
                || {
                    let (mut p, s) = (
                        random_point(curve_type, rng),
                        random_scalar(curve_type, rng),
                    );
                    p.precompute(NafLut::DEFAULT_WINDOW_SIZE)
                        .expect("failed to precompute point");
                    (p, s)
                },
                |(p, s)| p.scalar_mul_vartime(s),
                BatchSize::SmallInput,
            )
        });

        group.bench_function("mul_by_node_index_0_to_50", |b| {
            b.iter_with_setup(
                || random_point(curve_type, rng),
                |p| {
                    for node_index in 0..50 {
                        p.mul_by_node_index_vartime(node_index).unwrap();
                    }
                },
            )
        });

        group.bench_function("multiply_vartime_total", |b| {
            b.iter_batched_ref(
                || {
                    (
                        random_point(curve_type, rng),
                        random_scalar(curve_type, rng),
                    )
                },
                |(p, s)| {
                    p.precompute(NafLut::DEFAULT_WINDOW_SIZE)
                        .expect("failed to precompute point");
                    p.scalar_mul_vartime(s)
                },
                BatchSize::SmallInput,
            )
        });

        for window_size in NafLut::MIN_WINDOW_SIZE..=NafLut::MAX_WINDOW_SIZE {
            group.bench_function(
                BenchmarkId::new("multiply_vartime_online", window_size),
                |b| {
                    b.iter_batched_ref(
                        || {
                            let (mut p, s) = (
                                random_point(curve_type, rng),
                                random_scalar(curve_type, rng),
                            );
                            p.precompute(window_size)
                                .expect("failed to precompute point");
                            (p, s)
                        },
                        |(p, s)| p.scalar_mul_vartime(s),
                        BatchSize::SmallInput,
                    )
                },
            );

            group.bench_function(
                BenchmarkId::new("multiply_vartime_total", window_size),
                |b| {
                    b.iter_batched_ref(
                        || {
                            (
                                random_point(curve_type, rng),
                                random_scalar(curve_type, rng),
                            )
                        },
                        |(p, s)| {
                            p.precompute(window_size)
                                .expect("failed to precompute point");
                            p.scalar_mul_vartime(s)
                        },
                        BatchSize::SmallInput,
                    )
                },
            );
        }

        group.finish();
    }
}

fn point_serialize(c: &mut Criterion) {
    let rng = &mut reproducible_rng();

    for curve_type in EccCurveType::all() {
        let mut group = c.benchmark_group(format!("crypto_point_serialization_{}", curve_type));

        group.bench_function(BenchmarkId::new("serialize_compressed", 0), |b| {
            b.iter_with_setup(|| random_point(curve_type, rng), |p| p.serialize())
        });

        group.bench_function(BenchmarkId::new("deserialize_compressed", 0), |b| {
            b.iter_with_setup(
                || random_point(curve_type, rng).serialize(),
                |p| EccPoint::deserialize(curve_type, &p),
            );
        });
    }
}

criterion_group!(
    benches,
    point_multiexp_constant_time,
    point_multiexp_vartime_total,
    point_multiexp_vartime_online,
    point_mul,
    point_double_vs_addition,
    point_serialize,
);
criterion_main!(benches);
