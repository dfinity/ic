//! Tests of the whole NiDKG protocol
mod fixtures;
mod test_create_dealing;
mod test_retention;

use super::*;
use crate::threshold::tests::util::test_threshold_signatures;
use crate::types as csp_types;
use crate::Csp;
use fixtures::*;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg as internal_types;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::PublicCoefficientsBytes;
use ic_types::crypto::KeyId;
use ic_types::Randomness;
use proptest::prelude::*;
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 4,
        max_shrink_iters: 0,
        .. ProptestConfig::default()
    })]

    #[test]
    fn ni_dkg_should_work_with_all_players_acting_correctly(seed: [u8;32], network_size in MockNetwork::MIN_SIZE..MockNetwork::DEFAULT_MAX_SIZE, num_reshares in 0..4) {
      test_ni_dkg_should_work_with_all_players_acting_correctly(seed, network_size, num_reshares);
    }
}

/// Verifies that non-interactive DKG works if all players act correctly.
fn test_ni_dkg_should_work_with_all_players_acting_correctly(
    seed: [u8; 32],
    network_size: usize,
    num_reshares: i32,
) {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let network = MockNetwork::random(&mut rng, network_size);
    let config = MockDkgConfig::from_network(&mut rng, &network, None);
    let mut state = state_with_transcript(&config, network);
    threshold_signatures_should_work(&state.network, &config, &state.transcript, &mut rng);
    let public_key = state.public_key();
    // Resharing
    for _ in 0..num_reshares {
        let StateWithTranscript {
            network,
            transcript,
            config,
        } = state;
        let config = MockDkgConfig::from_network(&mut rng, &network, Some((config, transcript)));
        state = state_with_transcript(&config, network);
        threshold_signatures_should_work(&state.network, &config, &state.transcript, &mut rng);
        assert_eq!(public_key, state.public_key());
    }
}

/// Creates a state with a transcript
/// Verifies that the config produces functional threshold signatures
fn state_with_transcript(config: &MockDkgConfig, network: MockNetwork) -> StateWithTranscript {
    let state = StateWithConfig {
        network,
        config: config.clone(),
    };
    let state = StateWithDealings::from_state_with_config(state).expect("Dealing failed");
    let state = StateWithVerifiedDealings::from_state_with_dealings(state);
    let mut state = StateWithTranscript::from_state_with_verified_dealings(state);
    state.load_keys();
    state
}

/// Verifies that threshold signatures can be used correctly and that common
/// misuses fail.
///
/// Note: This calls the standard threshold signature test on a test fixture.
/// The standard test verifies that the happy path succeeds and that deviations
/// from the happy path, such as providing an incorrect signature, result in an
/// error.
fn threshold_signatures_should_work(
    network: &MockNetwork,
    config: &MockDkgConfig,
    transcript: &internal_types::CspNiDkgTranscript,
    rng: &mut ChaCha20Rng,
) {
    let internal_types::CspNiDkgTranscript::Groth20_Bls12_381(transcript) = transcript;
    let public_coefficients = PublicCoefficientsBytes {
        coefficients: transcript.public_coefficients.coefficients.clone(),
    };
    let public_coefficients = csp_types::CspPublicCoefficients::Bls12_381(public_coefficients);
    let signatories: Vec<(&Csp<_, _, _>, KeyId)> = {
        let key_id = key_id_from_csp_pub_coeffs(&public_coefficients);
        config
            .receivers
            .get()
            .iter()
            .map(|node_id| {
                let node = network
                    .nodes_by_node_id
                    .get(node_id)
                    .expect("Test error - could not find node listed in configuration");
                let csp = &node.csp;
                (csp, key_id)
            })
            .collect()
    };
    let seed = Randomness::from(rng.gen::<[u8; 32]>());
    let message = b"Tinker tailor soldier spy";
    test_threshold_signatures(&public_coefficients, &signatories[..], seed, &message[..]);
}
