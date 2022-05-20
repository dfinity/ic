#![allow(clippy::unwrap_used)]

use super::*;
use proptest::prelude::*;

proptest! {
    //These tests are slow so we limit the number of iterations
    #![proptest_config(ProptestConfig {
        cases: 1,
        .. ProptestConfig::default()
    })]

    #[test]
    fn should_update_initial_epochs(seed: [u8;32], associated_data: [u8;4]) {
        let sys = &mk_sys_params();

        let rng = &mut RAND_ChaCha20::new(seed);

        let (_pk, mut sk) = kgen(&associated_data, sys, rng);
        assert!(sk.current().is_some());

        for i in 0..100 {
            let next_epoch = tau_from_epoch(sys, Epoch::from(i));
            sk.update_to(&next_epoch, sys, rng);
            assert!(sk.current().is_some());
        }
    }
    #[test]
    fn should_update_to_random_epochs(epochs: Vec<u32>, seed: [u8;32], associated_data: [u8;4]) {
        prop_assume!(epochs.len()<15);
        prop_assume!(epochs.len()>5);

        let sys = &mk_sys_params();

        let rng = &mut RAND_ChaCha20::new(seed);

        let (_pk, mut sk) = kgen(&associated_data, sys, rng);
        assert!(sk.current().is_some());

        let mut sorted_epochs : Vec<u32>= epochs;
        sorted_epochs.sort_unstable();
        for epoch in sorted_epochs{
            let tau= tau_from_epoch(sys,Epoch::from(epoch));
            sk.update_to(&tau, sys, rng);
            assert!(sk.current().is_some());
        }
    }
    #[test]
    fn should_update_to_the_highest_epoch(seed: [u8;32], associated_data: [u8;4]) {
        let sys = &mk_sys_params();

        let rng = &mut RAND_ChaCha20::new(seed);

        let (_pk, mut sk) = kgen(&associated_data, sys, rng);

        let max_epoch = if sys.lambda_t < 32 {
            (2u64.pow(sys.lambda_t as u32) - 1) as u32
        } else {
            u32::MAX
        };
        assert!(sk.current().is_some());
        for i in (0..100).rev() {
            let next_epoch = tau_from_epoch(sys, Epoch::from(max_epoch - i));
            sk.update_to(&next_epoch, sys, rng);
            assert!(sk.current().is_some());
        }
        // The key should be at the last epoch, the next update should erase the secret key.
        sk.update(sys, rng);
        assert!(sk.current().is_none());
    }

}

proptest! {
    #[test]
    fn should_convert_tau_to_epoch(epoch: u32) {
        let sys = &mk_sys_params();

        let epoch = Epoch::from(epoch);
        let tau = tau_from_epoch(sys, epoch);

        assert_eq!(epoch, epoch_from_tau_vec(&tau));
    }
}
