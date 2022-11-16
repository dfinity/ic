//! Tests of the whole NiDKG protocol
mod fixtures;
mod test_create_dealing;
mod test_retention;

use super::*;
use crate::key_id::KeyId;
use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
use crate::threshold::tests::util::test_threshold_signatures;
use crate::types as csp_types;
use crate::vault::test_utils::sks::secret_key_store_with_duplicated_key_id_error_on_insert;
use crate::Csp;
use fixtures::*;
use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg as internal_types;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::PublicCoefficientsBytes;
use ic_types_test_utils::ids::NODE_1;
use proptest::prelude::*;
use rand::SeedableRng;
use rand::{CryptoRng, Rng};
use rand_chacha::ChaCha20Rng;

mod gen_dealing_encryption_key_pair_tests {
    use super::*;
    use crate::keygen::utils::dkg_dealing_encryption_pk_to_proto;
    use crate::CspSecretKeyStoreChecker;
    use ic_crypto_internal_test_vectors::unhex::hex_to_32_bytes;
    use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::{
        CspDkgCreateFsKeyError, InternalError,
    };

    #[test]
    fn should_correctly_generate_dealing_encryption_key_pair() {
        let csp = Csp::with_rng(rng());
        let (public_key, pop) = csp
            .gen_dealing_encryption_key_pair(NODE_1)
            .expect("error generating NI-DKG encryption dealing key pair");
        let key_id = KeyId::from(&public_key);

        assert_eq!(
            key_id,
            KeyId::from(hex_to_32_bytes(
                "527ee4634b9361c9bde5e16cbf10f7586095ea877463dc4a14ee4c4a186d33e4"
            )),
        );

        assert_eq!(
            csp.current_node_public_keys()
                .dkg_dealing_encryption_public_key
                .expect("missing key"),
            dkg_dealing_encryption_pk_to_proto(public_key, pop)
        );
        assert!(csp.sks_contains(&key_id).is_ok());
    }

    #[test]
    fn should_fail_with_internal_error_if_dealing_encryption_pubkey_already_set() {
        let csp = Csp::with_rng(rng());
        let node_id = NODE_1;

        assert!(csp.gen_dealing_encryption_key_pair(node_id).is_ok());
        let result = csp.gen_dealing_encryption_key_pair(node_id);

        assert!(matches!(result,
            Err(CspDkgCreateFsKeyError::InternalError(InternalError { internal_error }))
            if internal_error.contains("ni-dkg dealing encryption public key already set")
        ));

        assert!(matches!(csp.gen_dealing_encryption_key_pair(node_id),
            Err(CspDkgCreateFsKeyError::InternalError(InternalError { internal_error }))
            if internal_error.contains("ni-dkg dealing encryption public key already set")
        ));
    }

    #[test]
    fn should_fail_with_internal_error_on_duplicate_secret_key() {
        let duplicated_key_id = KeyId::from([42; 32]);
        let csp = Csp::of(
            rng(),
            secret_key_store_with_duplicated_key_id_error_on_insert(duplicated_key_id),
            MockPublicKeyStore::new(),
        );

        let result = csp.gen_dealing_encryption_key_pair(NODE_1);

        assert!(matches!(result,
            Err(CspDkgCreateFsKeyError::DuplicateKeyId(error))
            if error.contains("duplicate ni-dkg dealing encryption secret key id: KeyId(0x2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a)")
        ));
    }

    fn rng() -> impl CryptoRng + Rng {
        ChaCha20Rng::seed_from_u64(42)
    }
}

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
    let state = StateWithTranscript::from_state_with_verified_dealings(state);
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
    let signatories: Vec<(&Csp, KeyId)> = {
        let key_id = KeyId::from(&public_coefficients);
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
    let seed = Seed::from_rng(rng);
    let message = b"Tinker tailor soldier spy";
    test_threshold_signatures(&public_coefficients, &signatories[..], seed, &message[..]);
}
