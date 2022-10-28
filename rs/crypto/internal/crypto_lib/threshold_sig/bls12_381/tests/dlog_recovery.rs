use ic_crypto_internal_bls12_381_type::{G1Affine, G2Affine, Gt, Scalar};
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg::dlog_recovery::*;
use rand::Rng;

// Returns a random element of Gt
fn gt_rand() -> Gt {
    let mut rng = rand::thread_rng();
    let g1 = G1Affine::hash(b"ic-crypto-test-gt-random", &rng.gen::<[u8; 32]>());
    let g2 = G2Affine::generator();
    Gt::pairing(&g1, g2)
}

#[test]
fn baby_giant_empty_range() {
    let base = Gt::generator().clone();
    let baby_giant = BabyStepGiantStep::new(&base, 0, 0);

    assert_eq!(baby_giant.solve(&base), None);
}

#[test]
fn baby_giant_1000() {
    let base = gt_rand();
    let baby_giant = BabyStepGiantStep::new(&base, -24, 1024);

    let mut accum = Gt::identity();
    for x in 0..1000 {
        assert_eq!(baby_giant.solve(&accum), Some(Scalar::from_usize(x)));
        accum += &base;
    }

    // now out of range:
    for _ in 1000..2000 {
        assert_eq!(baby_giant.solve(&accum), None);
        accum += &base;
    }
}

#[test]
fn baby_giant_negative() {
    let base = gt_rand();
    let baby_giant = BabyStepGiantStep::new(&base, -999, 1024);

    for x in 0..1000 {
        let x = Scalar::from_isize(-x);
        let tgt = &base * &x;
        assert_eq!(baby_giant.solve(&tgt), Some(x))
    }
}

// The bounds of the NIZK chunking proof are loose, so a malicious DKG
// participant can force us to search around 2^40 candidates for a discrete log.
// (This is not the entire cost. We must also search for a cofactor Delta.)
#[test]
fn baby_giant_big_range() {
    let x = (1 << 39) + 123;
    let base = gt_rand();
    let baby_giant = BabyStepGiantStep::new(&base, -(1 << 10), 1 << 40);

    let x = Scalar::from_isize(x);
    let tgt = &base * &x;

    assert_eq!(baby_giant.solve(&tgt), Some(x));
}

// Exhaustive test for honest dealer
//
// This takes ~20 seconds in release mode or ~hours in debug
#[test]
#[ignore]
fn honest_dealer_search_works_exhaustive_test() {
    println!("gen table");
    let search = HonestDealerDlogLookupTable::new();

    let mut accum = Gt::identity();

    let mut dlogs = vec![];
    let mut targets = vec![];
    for i in 0..=0xFFFF {
        dlogs.push(i);
        targets.push(accum.clone());
        accum += Gt::generator();
    }

    let recovered_dlogs = search.solve_several(&targets);

    assert_eq!(recovered_dlogs.len(), dlogs.len());

    for i in 0..dlogs.len() {
        assert_eq!(recovered_dlogs[i], Some(Scalar::from_usize(dlogs[i])));
    }
}

// Test for honest dealer
#[test]
fn honest_dealer_search_works_randomized_test() {
    let search = HonestDealerDlogLookupTable::new();

    let mut rng = rand::thread_rng();

    let mut dlogs = (0..500).map(|_| rng.gen::<u16>()).collect::<Vec<_>>();

    // also explicitly test the very begin and end elements
    dlogs.push(0);
    dlogs.push(1);
    dlogs.push(0xFFFE);
    dlogs.push(0xFFFF);

    let mut targets = vec![];
    for dlog in &dlogs {
        targets.push(Gt::g_mul_u16(*dlog));
    }

    let recovered_dlogs = search.solve_several(&targets);

    assert_eq!(recovered_dlogs.len(), dlogs.len());

    for i in 0..dlogs.len() {
        assert_eq!(
            recovered_dlogs[i],
            Some(Scalar::from_usize(dlogs[i] as usize))
        );
    }
}

// Test that honest dealer can handle hash collisions
#[test]
fn honest_dealer_search_handles_hash_collisions() {
    let search = HonestDealerDlogLookupTable::new();

    // values found where gt*x have a hash that collides
    // with a value in the honest dealer set
    let colliding_values = [
        197153, 232966, 334942, 589526, 714195, 787095, 804131, 910977, 940797, 1034014, 1059743,
        1149539, 1217135, 1223801, 1269911, 1345862, 1370947, 1487205, 1503151, 1596360, 1604027,
        1806351, 1815694, 1835218, 1919712, 1937604, 1952453, 1998806, 2059445, 2098027, 2136067,
        2268749, 2275919, 2380451, 2578002, 2598250, 2661500, 2672730, 2685331, 2694219, 2740783,
        2851762, 2950317,
    ];

    let targets = colliding_values
        .iter()
        .map(|v| Gt::generator() * Scalar::from_usize(*v))
        .collect::<Vec<_>>();

    let recovered_dlogs = search.solve_several(&targets);

    assert_eq!(recovered_dlogs.len(), colliding_values.len());

    for v in recovered_dlogs {
        assert_eq!(v, None);
    }
}

// Test for honest dealer finding no match
#[test]
fn honest_dealer_search_handles_no_match() {
    let search = HonestDealerDlogLookupTable::new();

    let cheating_dealer = [197152, 232965, 334941];

    let targets = cheating_dealer
        .iter()
        .map(|v| Gt::generator() * Scalar::from_usize(*v))
        .collect::<Vec<_>>();

    let recovered_dlogs = search.solve_several(&targets);

    assert_eq!(recovered_dlogs.len(), cheating_dealer.len());

    for v in recovered_dlogs {
        assert_eq!(v, None);
    }
}

// Find the log for a cheater who exceeds the bounds by a little.
#[test]
fn slightly_dishonest_dlog() {
    let base = Gt::generator();

    // With current parameters
    //   Z = 1069531200 * m * n
    // So searching for Delta with m = n = 1 should be tolerable.

    let cheat_solver = CheatingDealerDlogSolver::new(1, 1);

    let mut answer = Scalar::from_usize(8).inverse().expect("Inverse exists");
    answer *= Scalar::from_usize(12345678);
    assert_eq!(cheat_solver.solve(&(base * &answer)), Some(answer));

    // Check negative numbers also work.
    let mut answer = Scalar::from_usize(5).inverse().expect("Inverse exists");
    answer *= Scalar::from_isize(-12345678);
    assert_eq!(cheat_solver.solve(&(base * &answer)), Some(answer));
}

fn cheating_dlog_instance(m: usize) -> (Scalar, Gt) {
    let mut rng = rand::thread_rng();

    let z = 1069531200 * 16 * m as u64;

    let s = Scalar::from_u64(rng.gen::<u64>() % z);

    let delta = std::cmp::max(1, rng.gen::<u16>() % 10) as u64;
    let delta = Scalar::from_u64(delta);

    let delta_inv = delta.inverse().expect("Delta not invertible");

    let s_div_delta = s * delta_inv;

    let p = Gt::generator() * &s_div_delta;
    (s_div_delta, p)
}

#[test]
fn test_that_cheating_dealer_solver_can_solve_instance() {
    let m = 29;
    let solver = CheatingDealerDlogSolver::new(m, 16);

    let (solution, target) = cheating_dlog_instance(m);

    assert_eq!(
        solution,
        solver.solve(&target).expect("Unable to solve dlog")
    );
}
