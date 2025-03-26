use ic_crypto_internal_bls12_381_type::{Gt, Scalar};
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg::dlog_recovery::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::Rng;

fn cheating_dlog_instance<R: rand::RngCore + rand::CryptoRng>(
    m: usize,
    rng: &mut R,
    use_max_delta: bool,
) -> (Scalar, Gt) {
    let z = 1069531200 * 16 * m as u64;

    let s = Scalar::from_u64(rng.gen::<u64>() % z);

    let delta = if use_max_delta {
        // Instead of maximum delta (255) we use the largest
        // delta that is prime. This leads to consistent results
        // from run to run, and is only slightly faster than
        // the most pessimal delta.
        251
    } else {
        std::cmp::max(1, rng.gen::<u16>() % 10)
    } as u64;
    let delta = Scalar::from_u64(delta);

    let delta_inv = delta.inverse().expect("Delta not invertible");

    let s_div_delta = s * delta_inv;

    let p = Gt::generator() * &s_div_delta;
    (s_div_delta, p)
}

#[test]
fn test_that_cheating_dealer_solver_can_solve_instance() {
    let rng = &mut reproducible_rng();

    let m = 13;
    let solver = CheatingDealerDlogSolver::new(m, 16);

    let (solution, target) = cheating_dlog_instance(m, rng, false);

    assert_eq!(
        solution,
        solver.solve(&target).expect("Unable to solve dlog")
    );
}

#[test]
#[ignore]
fn print_time_for_cheating_dlog_solver_to_run() {
    let rng = &mut reproducible_rng();

    let subnet_size = 13;
    let total_tests = 16; // one fully bad dealing

    let table_start = std::time::SystemTime::now();
    let solver = CheatingDealerDlogSolver::new(subnet_size, 16);
    println!(
        "Created table for {} nodes in {:?}",
        subnet_size,
        table_start.elapsed().unwrap()
    );

    let tests = (0..total_tests)
        .map(|_| cheating_dlog_instance(subnet_size, rng, true))
        .collect::<Vec<_>>();

    for (solution, target) in tests {
        let solve_start = std::time::SystemTime::now();

        assert_eq!(
            solution,
            solver.solve(&target).expect("Unable to solve dlog")
        );

        println!("Solved an instance in {:?}", solve_start.elapsed().unwrap());
    }
}
