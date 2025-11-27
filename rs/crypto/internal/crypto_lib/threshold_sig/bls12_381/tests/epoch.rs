use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg::{Epoch, forward_secure::*};
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

        let rng = &mut rand_chacha::ChaCha20Rng::from_seed(seed);

        let (_pk, mut sk) = kgen(&associated_data, sys, rng);
        assert_eq!(sk.current_epoch(), Some(Epoch::from(0)));

        for i in 0..100 {
            sk.update_to(Epoch::from(i), sys, rng);
            assert_eq!(sk.current_epoch(), Some(Epoch::from(i)));

            // no-op:
            sk.update_to(Epoch::from(i), sys, rng);
            assert_eq!(sk.current_epoch(), Some(Epoch::from(i)));
        }
    }
    #[test]
    fn should_update_to_random_epochs(epochs: Vec<u32>, seed: [u8;32], associated_data: [u8;4]) {
        prop_assume!(epochs.len()<15);
        prop_assume!(epochs.len()>5);

        let sys = SysParam::global();

        let rng = &mut rand_chacha::ChaCha20Rng::from_seed(seed);

        let (_pk, mut sk) = kgen(&associated_data, sys, rng);
        assert_eq!(sk.current_epoch(), Some(Epoch::from(0)));

        let mut sorted_epochs : Vec<u32>= epochs;
        sorted_epochs.sort_unstable();
        for epoch in sorted_epochs{
            sk.update_to(Epoch::from(epoch), sys, rng);
            assert_eq!(sk.current_epoch(), Some(Epoch::from(epoch)));

            // no-op:
            sk.update_to(Epoch::from(epoch), sys, rng);
            assert_eq!(sk.current_epoch(), Some(Epoch::from(epoch)));
        }
    }
    #[test]
    fn should_update_to_the_highest_epoch(seed: [u8;32], associated_data: [u8;4]) {
        let sys = SysParam::global();

        let rng = &mut rand_chacha::ChaCha20Rng::from_seed(seed);

        let (_pk, mut sk) = kgen(&associated_data, sys, rng);
        assert_eq!(sk.current_epoch(), Some(Epoch::from(0)));
        for i in (0..100).rev() {
            let next_epoch = Epoch::from(MAXIMUM_EPOCH - i);
            sk.update_to(next_epoch, sys, rng);
            assert_eq!(sk.current_epoch(), Some(next_epoch));

            // no-op:
            sk.update_to(next_epoch, sys, rng);
            assert_eq!(sk.current_epoch(), Some(next_epoch));
        }
        // The key should be at the last epoch, the next update should erase the secret key.
        sk.update(sys, rng);
        assert_eq!(sk.current_epoch(), None);

    }

}
