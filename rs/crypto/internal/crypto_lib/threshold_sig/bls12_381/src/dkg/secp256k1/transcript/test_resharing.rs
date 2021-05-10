use crate::dkg::secp256k1::test_fixtures::{
    StateWithEphemeralKeys, StateWithResharedDealings, StateWithResponses, StateWithThresholdKey,
    StateWithTranscript,
};
use crate::types::public_coefficients::conversions::pub_key_bytes_from_pub_coeff_bytes;
use ic_types::Randomness;
use proptest::prelude::*;
use rand::Rng;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

fn test_reshared_transcript_is_compatible_with_previous_combined_signatures(seed: Randomness) {
    let mut rng = ChaChaRng::from_seed(seed.get());
    // Initial threshold key:
    let state = StateWithThresholdKey::random(&mut rng);
    let message = &rng.gen::<[u8; 11]>()[..];
    let original_signature = state.sign(message);
    let original_public_key = pub_key_bytes_from_pub_coeff_bytes(&state.public_coefficients);
    // Check that the signature verifies with the initial key:
    state.verify(message, original_signature);
    // Reshare:
    let state = StateWithEphemeralKeys::random(&mut rng, state);
    let state = StateWithResharedDealings::random(&mut rng, state);
    state
        .verify_dealings()
        .expect("Resharing dealings do not verify");
    let state = StateWithResponses::from_resharing_dealings(&mut rng, state);
    state
        .verify_responses()
        .expect("Reshared responses do not verify");
    let state = StateWithTranscript::from_resharing_responses(state);
    let state = StateWithThresholdKey::from_transcript(state);
    // Check compatibility
    assert_eq!(
        original_public_key,
        pub_key_bytes_from_pub_coeff_bytes(&state.public_coefficients),
        "Group public key has changed"
    );
    state.verify(message, original_signature);
    assert_eq!(
        original_signature,
        state.sign(message),
        "Group signature has changed"
    );
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 2,
        max_shrink_iters: 0,
        .. ProptestConfig::default()
    })]

    #[test]
    fn reshared_transcript_is_compatible_with_previous_combined_signatures(seed: Randomness) {
        test_reshared_transcript_is_compatible_with_previous_combined_signatures(seed);
    }
}
