use std::time::Duration;

use criterion::*;
use ic_crypto_internal_threshold_sig_ecdsa::*;

fn random_point(curve_type: EccCurveType) -> EccPoint {
    let mut rng = rand::thread_rng();
    EccPoint::mul_by_g(&EccScalar::random(curve_type, &mut rng).unwrap()).unwrap()
}

fn random_scalar(curve_type: EccCurveType) -> EccScalar {
    let mut rng = rand::thread_rng();
    EccScalar::random(curve_type, &mut rng).unwrap()
}

fn gen_mul_n_instance(num_terms: usize, curve_type: EccCurveType) -> Vec<(EccPoint, EccScalar)> {
    (0..num_terms)
        .map(|_| (random_point(curve_type), random_scalar(curve_type)))
        .collect()
}

fn mul_n_naive(terms: &[(EccPoint, EccScalar)]) -> EccPoint {
    let mut accum = EccPoint::identity(terms[0].0.curve_type());
    for &(p, s) in terms {
        accum = accum.add_points(&p.scalar_mul(&s).unwrap()).unwrap();
    }
    accum
}

fn multiexp_total(c: &mut Criterion) {
    for curve_type in EccCurveType::all() {
        let mut group = c.benchmark_group(format!("crypto_multiexp_total_{}", curve_type));

        {
            // fixed 2 arguments for special-purpose functions with a fixed number of arguments
            let num_args = 2;
            group.bench_with_input(
                BenchmarkId::new("consttime_lincomb", num_args),
                &num_args,
                |b, size| {
                    b.iter_batched_ref(
                        || gen_mul_n_instance(*size, curve_type),
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
                        || gen_mul_n_instance(*size, curve_type),
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
                            || gen_mul_n_instance(*size, curve_type),
                            |terms| {
                                // create "deep" refs of pairs
                                let mut prec_points =
                                    Vec::<EccPointWithLut>::with_capacity(terms.len());

                                for (p, _s) in terms.iter() {
                                    prec_points.push(EccPointWithLut::new(p, window_size)?);
                                }

                                // create refs of pairs
                                let mut refs_of_pairs =
                                    Vec::<(&EccPointWithLut, &EccScalar)>::with_capacity(
                                        terms.len(),
                                    );
                                for i in 0..terms.len() {
                                    refs_of_pairs.push((&prec_points[i], &terms[i].1));
                                }
                                EccPointWithLut::mul_n_points_vartime_naf(&refs_of_pairs)
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

fn multiexp_online(c: &mut Criterion) {
    for curve_type in EccCurveType::all() {
        let mut group = c.benchmark_group(format!("crypto_multiexp_online_{}", curve_type));

        {
            // fixed 2 arguments for special-purpose functions with a fixed number of arguments
            let num_args = 2;
            group.bench_with_input(
                BenchmarkId::new("consttime_lincomb", num_args),
                &num_args,
                |b, size| {
                    b.iter_batched_ref(
                        || gen_mul_n_instance(*size, curve_type),
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
                        || gen_mul_n_instance(*size, curve_type),
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
                                let terms = gen_mul_n_instance(*size, curve_type);
                                let prec_points_scalars: Vec<(EccPointWithLut, EccScalar)> = terms
                                    .iter()
                                    .map(|(p, s)| {
                                        (
                                            EccPointWithLut::new(p, window_size).unwrap(),
                                            s.to_owned(),
                                        )
                                    })
                                    .collect();
                                prec_points_scalars
                            },
                            |terms| {
                                // create refs of pairs
                                let refs_of_pairs: Vec<(&EccPointWithLut, &EccScalar)> =
                                    terms.iter().map(|pair| (&pair.0, &pair.1)).collect();
                                EccPointWithLut::mul_n_points_vartime_naf(&refs_of_pairs)
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

fn double_vs_addition(c: &mut Criterion) {
    for curve_type in EccCurveType::all() {
        let mut group = c.benchmark_group(format!("crypto_double_vs_addition_{}", curve_type));

        group.bench_function(BenchmarkId::new("double", 0), move |b| {
            b.iter_with_setup(|| random_point(curve_type), |p| p.double())
        });

        group.bench_function(BenchmarkId::new("add_points", 0), move |b| {
            b.iter_with_setup(
                || (random_point(curve_type), random_point(curve_type)),
                |(p_0, p_1)| p_0.add_points(&p_1),
            )
        });

        group.finish();
    }
}

criterion_group! {
name = group_ops;
config = Criterion::default().measurement_time(Duration::from_secs(30));
targets = multiexp_total, multiexp_online, double_vs_addition
}
criterion_main!(group_ops);
