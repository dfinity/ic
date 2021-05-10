#![allow(clippy::unwrap_used)]
use super::*;
use rand_chacha::rand_core::{RngCore, SeedableRng};
// The following test was disabled because the current params are too large for
// this to run
#[test]
#[ignore]
fn should_allow_for_2_pow_lambda_t_updates() {
    let sys = &mk_sys_params();
    // Check that we're not running with a too big lambda_t.
    assert_eq!(32, 2_i32.checked_pow(sys.lambda_t as u32).unwrap());

    let rng = &mut RAND_ChaCha20::new([83; 32]);
    const KEY_GEN_ASSOCIATED_DATA: &[u8] = &[0u8, 1u8, 0u8, 1u8];

    let (_pk, mut sk) = kgen(KEY_GEN_ASSOCIATED_DATA, sys, rng);
    let mut count = 0;
    while sk.current().is_some() {
        sk.update(sys, rng);
        count += 1;
    }
    assert_eq!(32, count);
}

#[test]
fn should_allow_for_32_updates() {
    let sys = &mk_sys_params();

    let rng = &mut RAND_ChaCha20::new([69; 32]);
    const KEY_GEN_ASSOCIATED_DATA: &[u8] = &[2u8, 0u8, 0u8, 7u8];

    let (_pk, mut sk) = kgen(KEY_GEN_ASSOCIATED_DATA, sys, rng);
    assert!(sk.current().is_some());

    for _i in 0..32 {
        sk.update(sys, rng);
        assert!(sk.current().is_some());
    }
}

#[test]
fn should_convert_tau_to_epoch() {
    let sys = &mk_sys_params();

    let mut rng = rand_chacha::ChaChaRng::from_seed([42; 32]);
    for _i in 0..200 {
        let epoch = Epoch::from(rng.next_u32());
        let tau = tau_from_epoch(sys, epoch);

        assert_eq!(epoch, epoch_from_tau_vec(&tau));
    }
}
