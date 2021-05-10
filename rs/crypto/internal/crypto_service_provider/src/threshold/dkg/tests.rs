//! Tests for the CSP DKG implementation

use super::test_fixtures::*;
use super::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
fn verifies_that_dkg_works_with_all_players_acting_correctly() {
    let mut rng = ChaCha20Rng::from_seed([49; 32]);
    let num_receivers = 7;
    let num_dealers = 4;
    let threshold = 3;
    let participants = InitialState::random(&mut rng, num_receivers, num_dealers);

    let state = StateWithEphemeralKeys::new(participants);
    state
        .verify_ephemeral()
        .expect("Ephemeral keys failed to verify");
    let state = StateWithDealings::new(state, NumberOfNodes::from(threshold));
    state.verify_dealing().expect("Dealings failed to verify");
    let state = StateWithResponses::new(state);
    state
        .verify_responses()
        .expect("Responses failed to verify");
    let state = StateWithTranscript::new(state);
    let _state = StateWithThresholdKeys::new(state);
    // TODO(CRP-433): Use the threshold keys once the new API is supported.
}

#[test]
fn verifies_that_resharing_works_with_all_players_acting_correctly() {
    let mut rng = ChaCha20Rng::from_seed([49; 32]);
    let num_receivers = 7;
    let num_dealers = 4;
    let threshold = 3;
    let state =
        StateWithThresholdKeys::by_dkg_or_panic(&mut rng, num_receivers, num_dealers, threshold);
    // TODO(CRP-433): Use the threshold keys once the new API is supported.

    // Reshared:
    let first_public_coefficients = CspPublicCoefficients::from(&state.transcript);
    let second_num_receivers = 5;
    let second_threshold = 3;
    let state = StateWithThresholdKeys::by_resharing_or_panic(
        &mut rng,
        state,
        second_num_receivers,
        second_threshold,
    );
    let second_public_coefficients = CspPublicCoefficients::from(&state.transcript);
    match (&first_public_coefficients, &second_public_coefficients) {
        (
            CspPublicCoefficients::Bls12_381(first_public_coefficients),
            CspPublicCoefficients::Bls12_381(second_public_coefficients),
        ) => assert_eq!(
            first_public_coefficients.coefficients[0], second_public_coefficients.coefficients[0],
            "First reshare failed to preserve public coefficients"
        ),
    }
    // TODO(CRP-433): Use the threshold keys once the new API is supported.

    // Re-reshared:
    let third_num_receivers = 7;
    let third_threshold = 4;
    let state = StateWithThresholdKeys::by_resharing_or_panic(
        &mut rng,
        state,
        third_num_receivers,
        third_threshold,
    );
    let third_public_coefficients = CspPublicCoefficients::from(&state.transcript);
    match (&first_public_coefficients, &third_public_coefficients) {
        (
            CspPublicCoefficients::Bls12_381(first_public_coefficients),
            CspPublicCoefficients::Bls12_381(third_public_coefficients),
        ) => assert_eq!(
            first_public_coefficients.coefficients[0], third_public_coefficients.coefficients[0],
            "Second reshare failed to preserve public coefficients"
        ),
    }
    // TODO(CRP-433): Use the threshold keys once the new API is supported.

    // Re-reshared:
    let fourth_num_receivers = 5;
    let fourth_threshold = 3;
    let state = StateWithThresholdKeys::by_resharing_or_panic(
        &mut rng,
        state,
        fourth_num_receivers,
        fourth_threshold,
    );
    let fourth_public_coefficients = CspPublicCoefficients::from(&state.transcript);
    match (&first_public_coefficients, &fourth_public_coefficients) {
        (
            CspPublicCoefficients::Bls12_381(first_public_coefficients),
            CspPublicCoefficients::Bls12_381(fourth_public_coefficients),
        ) => assert_eq!(
            first_public_coefficients.coefficients[0], fourth_public_coefficients.coefficients[0],
            "Third reshare failed to preserve public coefficients"
        ),
    }
    // TODO(CRP-433): Use the threshold keys once the new API is supported.
}
