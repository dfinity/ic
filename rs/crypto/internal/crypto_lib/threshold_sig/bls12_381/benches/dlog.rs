use criterion::*;
use ic_crypto_internal_bls12_381_type::{Gt, Scalar};
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg::dlog_recovery::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::{CryptoRng, Rng};

fn honest_dlog_instance<R: Rng + CryptoRng>(n: usize, rng: &mut R) -> (Vec<Scalar>, Vec<Gt>) {
    let mut scalars = Vec::with_capacity(n);
    let mut powers = Vec::with_capacity(n);

    for _ in 0..n {
        let s = rng.r#gen::<u16>();
        scalars.push(Scalar::from_u64(s as u64));
        powers.push(Gt::g_mul_u16(s));
    }

    (scalars, powers)
}

fn check_dlog_solution(solutions: &[Scalar], solved: &[Option<Scalar>]) {
    assert_eq!(solved.len(), solutions.len());

    for (x, y) in solutions.iter().zip(solved) {
        assert_eq!(x, y.as_ref().expect("Unable to solve dlog"));
    }
}

fn honest_dlog(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_nidkg_dlog_honest_dealer");

    let rng = &mut reproducible_rng();

    let dlog_solver = HonestDealerDlogLookupTable::new();

    group.bench_function("solve_1", |b| {
        b.iter_batched_ref(
            || honest_dlog_instance(1, rng),
            |(dlogs, powers)| check_dlog_solution(dlogs, &dlog_solver.solve_several(powers)),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("solve_16", |b| {
        b.iter_batched_ref(
            || honest_dlog_instance(16, rng),
            |(dlogs, powers)| check_dlog_solution(dlogs, &dlog_solver.solve_several(powers)),
            BatchSize::SmallInput,
        )
    });
}

fn baby_step_giant_step(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_nidkg_dlog_bsgs");

    let rng = &mut reproducible_rng();

    let bsgs = BabyStepGiantStep::new(Gt::generator(), 0, 1 << 16, 512, 10);
    group.bench_function("solve", |b| {
        b.iter_batched_ref(
            || honest_dlog_instance(1, rng),
            |(dlogs, powers)| check_dlog_solution(dlogs, &[bsgs.solve(&powers[0])]),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, honest_dlog, baby_step_giant_step);
criterion_main!(benches);
