use criterion::*;
use ic_crypto_internal_threshold_sig_canister_threshold_sig::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::{CryptoRng, Rng};

fn poly_bench(c: &mut Criterion) {
    let rng = &mut reproducible_rng();

    let curve = EccCurveType::K256;

    for degree in [8, 16, 32] {
        let poly = Polynomial::random(curve, degree, rng);

        let x = EccScalar::random(curve, rng);

        c.bench_function(
            &format!("poly evaluate_at({curve}, degree {degree})"),
            |b| {
                b.iter(|| {
                    let _ = poly.evaluate_at(&x);
                })
            },
        );

        let mut samples = Vec::with_capacity(degree + 1);
        for _i in 0..degree + 1 {
            let r = EccScalar::random(curve, rng);
            let p_r = poly.evaluate_at(&r).unwrap();
            samples.push((r, p_r));
        }

        c.bench_function(
            &format!("poly interpolate({curve}, degree {degree})"),
            |b| {
                b.iter(|| {
                    let p = Polynomial::interpolate(curve, &samples).unwrap();
                    assert_eq!(p, poly);
                })
            },
        );

        let poly_b = Polynomial::random(curve, degree, rng);

        c.bench_function(
            &format!("poly simple commitment({curve}, degree {degree})"),
            |b| {
                b.iter(|| {
                    let _ = SimpleCommitment::create(&poly, degree).unwrap();
                })
            },
        );

        c.bench_function(
            &format!("poly Pedersen commitment({curve}, degree {degree})"),
            |b| {
                b.iter(|| {
                    let _ = PedersenCommitment::create(&poly, &poly_b, degree).unwrap();
                })
            },
        );
    }
}

fn random_point<R: Rng + CryptoRng>(curve_type: EccCurveType, rng: &mut R) -> EccPoint {
    EccPoint::mul_by_g(&EccScalar::random(curve_type, rng))
}

fn random_scalar<R: Rng + CryptoRng>(curve_type: EccCurveType, rng: &mut R) -> EccScalar {
    EccScalar::random(curve_type, rng)
}

fn random_lagrange_coeffs<R: Rng + CryptoRng>(
    curve_type: EccCurveType,
    num_terms: usize,
    rng: &mut R,
) -> LagrangeCoefficients {
    LagrangeCoefficients::new(
        (0..num_terms)
            .map(|_| random_scalar(curve_type, rng))
            .collect(),
    )
    .unwrap()
}

fn poly_compute_lagrange(c: &mut Criterion) {
    for curve in EccCurveType::all() {
        let mut group = c.benchmark_group(format!("crypto_lagrange_coefficients_{curve}"));
        group.warm_up_time(std::time::Duration::from_millis(100));

        for n in [13, 34, 40] {
            let node_indices = (0..n).collect::<Vec<NodeIndex>>();

            group.bench_function(format!("setup/{n}"), |b| {
                b.iter(|| {
                    let _ = LagrangeCoefficients::at_zero(curve, &node_indices);
                })
            });
        }
    }
}

fn poly_interpolate_point(c: &mut Criterion) {
    let rng = &mut reproducible_rng();

    for curve_type in EccCurveType::all() {
        let mut group = c.benchmark_group(format!("crypto_poly_interpolate_point_{curve_type}"));

        // range of arguments for generic functions
        for degree in (5..=100).step_by(5) {
            group.bench_with_input(
                BenchmarkId::new("using precompute", degree),
                &degree,
                |b, &size| {
                    b.iter_batched_ref(
                        || {
                            let points: Vec<_> =
                                (0..size).map(|_| random_point(curve_type, rng)).collect();
                            let coeffs = random_lagrange_coeffs(curve_type, degree, rng);
                            (points, coeffs)
                        },
                        |(points, coeffs)| {
                            // create refs of pairs
                            // create "deep" refs of pairs
                            for p in points.iter_mut() {
                                p.precompute(5).unwrap();
                            }
                            coeffs.interpolate_point(&points[..])
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

fn poly_interpolate_scalar(c: &mut Criterion) {
    let rng = &mut reproducible_rng();

    for curve_type in EccCurveType::all() {
        let mut group = c.benchmark_group(format!("crypto_poly_interpolate_scalar_{curve_type}"));
        // range of arguments for generic functions
        for degree in (5..=100).step_by(5) {
            group.bench_with_input(BenchmarkId::new("-", degree), &degree, |b, &size| {
                b.iter_batched_ref(
                    || {
                        let scalars: Vec<_> =
                            (0..size).map(|_| random_scalar(curve_type, rng)).collect();
                        let coeffs = random_lagrange_coeffs(curve_type, degree, rng);
                        (scalars, coeffs)
                    },
                    |(scalars, coeffs)| coeffs.interpolate_scalar(&scalars[..]),
                    BatchSize::SmallInput,
                )
            });
        }
        let plot_config = PlotConfiguration::default().summary_scale(AxisScale::Logarithmic);
        group.plot_config(plot_config);
        group.finish();
    }
}

criterion_group!(
    benches,
    poly_bench,
    poly_compute_lagrange,
    poly_interpolate_point,
    poly_interpolate_scalar
);
criterion_main!(benches);
