use core::time::Duration;
use criterion::*;
use ic_crypto_internal_threshold_sig_ecdsa::*;

fn poly_bench(c: &mut Criterion) {
    let curve = EccCurveType::K256;

    let mut rng = rand::thread_rng();

    for degree in [8, 16, 32] {
        let poly = Polynomial::random(curve, degree, &mut rng);

        let x = EccScalar::random(curve, &mut rng);

        c.bench_function(
            &format!("poly evaluate_at({}, degree {})", curve, degree),
            |b| {
                b.iter(|| {
                    let _ = poly.evaluate_at(&x);
                })
            },
        );

        let mut samples = Vec::with_capacity(degree + 1);
        for _i in 0..degree + 1 {
            let r = EccScalar::random(curve, &mut rng);
            let p_r = poly.evaluate_at(&r).unwrap();
            samples.push((r, p_r));
        }

        c.bench_function(
            &format!("poly interpolate({}, degree {})", curve, degree),
            |b| {
                b.iter(|| {
                    let p = Polynomial::interpolate(curve, &samples).unwrap();
                    assert_eq!(p, poly);
                })
            },
        );

        let poly_b = Polynomial::random(curve, degree, &mut rng);

        c.bench_function(
            &format!("poly simple commitment({}, degree {})", curve, degree),
            |b| {
                b.iter(|| {
                    let _ = SimpleCommitment::create(&poly, degree).unwrap();
                })
            },
        );

        c.bench_function(
            &format!("poly Pedersen commitment({}, degree {})", curve, degree),
            |b| {
                b.iter(|| {
                    let _ = PedersenCommitment::create(&poly, &poly_b, degree).unwrap();
                })
            },
        );
    }
}

fn random_point(curve_type: EccCurveType) -> EccPoint {
    let mut rng = rand::thread_rng();
    EccPoint::mul_by_g(&EccScalar::random(curve_type, &mut rng)).unwrap()
}

fn random_scalar(curve_type: EccCurveType) -> EccScalar {
    let mut rng = rand::thread_rng();
    EccScalar::random(curve_type, &mut rng)
}

fn random_lagrange_coeffs(curve_type: EccCurveType, num_terms: usize) -> LagrangeCoefficients {
    LagrangeCoefficients::new((0..num_terms).map(|_| random_scalar(curve_type)).collect()).unwrap()
}

fn poly_interpolate_point(c: &mut Criterion) {
    for curve_type in EccCurveType::all() {
        let mut group = c.benchmark_group(format!("crypto_poly_interpolate_point_{}", curve_type));

        // range of arguments for generic functions
        for degree in (5..=100).step_by(5) {
            group.bench_with_input(
                BenchmarkId::new("using precompute", degree),
                &degree,
                |b, &size| {
                    b.iter_batched_ref(
                        || {
                            let points: Vec<_> =
                                (0..size).map(|_| random_point(curve_type)).collect();
                            let coeffs = random_lagrange_coeffs(curve_type, degree);
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
    for curve_type in EccCurveType::all() {
        let mut group = c.benchmark_group(format!("crypto_poly_interpolate_scalar_{}", curve_type));
        // range of arguments for generic functions
        for degree in (5..=100).step_by(5) {
            group.bench_with_input(BenchmarkId::new("-", degree), &degree, |b, &size| {
                b.iter_batched_ref(
                    || {
                        let scalars: Vec<_> =
                            (0..size).map(|_| random_scalar(curve_type)).collect();
                        let coeffs = random_lagrange_coeffs(curve_type, degree);
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

//criterion_group!(benches, poly_bench);
criterion_group! {
name = benches;
config = Criterion::default().measurement_time(Duration::from_secs(30));
targets = poly_bench, poly_interpolate_point, poly_interpolate_scalar
}
criterion_main!(benches);
