use crate::dkg::secp256k1::test_fixtures::{
    StateWithEphemeralKeys, StateWithResharedDealings, StateWithThresholdKey,
};
use crate::types::PublicKey;
use group::CurveProjective;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_types::Randomness;
use pairing::bls12_381::G2;
use proptest::prelude::*;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

fn test_resharing_dealing(seed: Randomness) {
    let mut rng = ChaChaRng::from_seed(seed.get());

    let state = StateWithThresholdKey::random(&mut rng);
    let state = StateWithEphemeralKeys::random(&mut rng, state);
    let state = StateWithResharedDealings::random(&mut rng, state);
    state
        .verify_dealings()
        .expect("Resharing dealings do not verify");
    // Verify that if the public coefficients are altered, verification fails:
    {
        let mut state = state;
        let current_first_term = state.initial_state.public_coefficients.coefficients[0];
        state.initial_state.public_coefficients.coefficients[0] = PublicKeyBytes::from(
            if current_first_term == PublicKeyBytes::from(PublicKey(G2::zero())) {
                PublicKey(G2::one())
            } else {
                PublicKey(G2::zero())
            },
        );
        assert!(
            state.verify_dealings().is_err(),
            "Verification does not reject reshared dealings with altered public coefficients"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 2,
        max_shrink_iters: 0,
        .. ProptestConfig::default()
    })]

    #[test]
    fn resharing_dealing(seed: Randomness) {
        test_resharing_dealing(seed);
    }
}
