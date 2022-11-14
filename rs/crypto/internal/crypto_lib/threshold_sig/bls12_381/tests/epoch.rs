#![allow(clippy::unwrap_used)]

use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg::{forward_secure::*, Epoch};
use proptest::prelude::*;
use rand::SeedableRng;

proptest! {
    //These tests are slow so we limit the number of iterations
    #![proptest_config(ProptestConfig {
        cases: 1,
        .. ProptestConfig::default()
    })]

    #[test]
    fn should_update_initial_epochs(seed: [u8;32], associated_data: [u8;4]) {
        let sys = SysParam::global();

        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);

        let (_pk, mut sk) = kgen(&associated_data, sys, &mut rng);
        assert!(!sk.is_exhausted());

        for i in 0..100 {
            let next_epoch = tau_from_epoch(Epoch::from(i));
            sk.update_to(&next_epoch, sys, &mut rng);
            assert!(!sk.is_exhausted());
        }
    }
    #[test]
    fn should_update_to_random_epochs(epochs: Vec<u32>, seed: [u8;32], associated_data: [u8;4]) {
        prop_assume!(epochs.len()<15);
        prop_assume!(epochs.len()>5);

        let sys = SysParam::global();

        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);

        let (_pk, mut sk) = kgen(&associated_data, sys, &mut rng);
        assert!(!sk.is_exhausted());

        let mut sorted_epochs : Vec<u32>= epochs;
        sorted_epochs.sort_unstable();
        for epoch in sorted_epochs{
            let tau = tau_from_epoch(Epoch::from(epoch));
            sk.update_to(&tau, sys, &mut rng);
            assert!(!sk.is_exhausted());
        }
    }
    #[test]
    fn should_update_to_the_highest_epoch(seed: [u8;32], associated_data: [u8;4]) {
        let sys = SysParam::global();

        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);

        let (_pk, mut sk) = kgen(&associated_data, sys, &mut rng);

        assert!(!sk.is_exhausted());
        for i in (0..100).rev() {
            let next_epoch = tau_from_epoch(Epoch::from(MAXIMUM_EPOCH - i));
            sk.update_to(&next_epoch, sys, &mut rng);
            assert!(!sk.is_exhausted());
        }
        // The key should be at the last epoch, the next update should erase the secret key.
        sk.update(sys, &mut rng);
        assert!(sk.is_exhausted());
    }

}

proptest! {
    #[test]
    fn should_convert_tau_to_epoch(epoch: u32) {
        let epoch = Epoch::from(epoch);
        let tau = tau_from_epoch(epoch);

        assert_eq!(epoch, epoch_from_tau_vec(&tau));
    }
}
