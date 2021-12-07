pub mod fixtures;

use crate::types::conversions::key_id_from_csp_pub_coeffs;
use crate::types::CspPublicCoefficients;
use crate::vault::api::CspVault;
use crate::vault::test_utils;
use crate::vault::test_utils::ni_dkg::fixtures::{
    random_algorithm_id, MockDkgConfig, MockNetwork, MockNode, StateWithConfig, StateWithDealings,
    StateWithTranscript, StateWithVerifiedDealings,
};
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::CspDkgCreateReshareDealingError;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg as internal_types;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::PublicCoefficientsBytes;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::CspFsEncryptionPublicKey;
use ic_types::crypto::{AlgorithmId, KeyId};
use ic_types::{NodeIndex, NumberOfNodes, Randomness};
use rand::prelude::IteratorRandom;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Verifies that non-interactive DKG works if all players act correctly.
pub fn test_ni_dkg_should_work_with_all_players_acting_correctly(
    seed: [u8; 32],
    network_size: usize,
    num_reshares: i32,
    csp_vault_factory: fn() -> Arc<dyn CspVault>,
) {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let network = MockNetwork::random(&mut rng, network_size, csp_vault_factory);
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
    let public_coefficients = CspPublicCoefficients::Bls12_381(public_coefficients);
    let signatories: Vec<(Arc<dyn CspVault>, KeyId)> = {
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
                (Arc::clone(&node.csp_vault), key_id)
            })
            .collect()
    };
    let seed = Randomness::from(rng.gen::<[u8; 32]>());
    let message = b"Tinker tailor soldier spy";
    test_utils::threshold_sig::test_threshold_signatures(
        &public_coefficients,
        &signatories[..],
        seed,
        &message[..],
    );
}

/// Verifies that precisely the expected keys are retained.
///
/// Note: NiDKG key generation is expensive, so this test uses a minimal number
/// of NiDKG keys.
///
/// The test should generate these keys:
/// * One NiDKG key
/// * One non-NiDKG key with no scope.
///
/// The test should then issue a retain command, retaining the NiDKG key.  This
/// should succeed.
///
/// The NiDKG key should still be available for use.
///
/// The test should then issue a retain command, not retaining the NiDKG key.
/// This should succeed.
///
/// The NiDKG key should no longer be available for use.
///
/// The forward-secure encryption key should not have been erased, as it SHOULD
/// have a different scope.  The presence of this key can be demonstrated by
/// successfully reloading the transcript.
pub fn test_retention(csp_vault_factory: fn() -> Arc<dyn CspVault>) {
    let seed = [69u8; 32];
    let network_size = 4;
    let mut rng = ChaCha20Rng::from_seed(seed);
    let network = MockNetwork::random(&mut rng, network_size, csp_vault_factory);
    let config = MockDkgConfig::from_network(&mut rng, &network, None);
    let mut state = state_with_transcript(&config, network);

    state.load_keys();

    let internal_public_coefficients = state.transcript.public_coefficients();

    // We will apply our tests to just one node:
    fn get_one_node(state: &mut StateWithTranscript) -> &mut MockNode {
        state
            .network
            .nodes_by_node_id
            .iter_mut()
            .next()
            .expect("Network has no nodes")
            .1
    }

    // Scoped access to a single CSP, so that we can recover ownership of the whole
    // state later:
    {
        let node: &mut MockNode = get_one_node(&mut state);

        // Verify that the key is there:
        let key_id = key_id_from_csp_pub_coeffs(&internal_public_coefficients);
        node.csp_vault
            .threshold_sign(
                AlgorithmId::ThresBls12_381,
                &b"Here's a howdyedo!"[..],
                key_id,
            )
            .expect("The key should be there initially");

        // Call retain, keeping the threshold key:
        let active_key_ids: BTreeSet<KeyId> = vec![internal_public_coefficients.clone()]
            .iter()
            .map(key_id_from_csp_pub_coeffs)
            .collect();
        node.csp_vault
            .retain_threshold_keys_if_present(active_key_ids);

        // The key should still be there:
        node.csp_vault
            .threshold_sign(
                AlgorithmId::ThresBls12_381,
                &b"Here's a state of things!"[..],
                key_id,
            )
            .expect("The key should have been retained");

        // Call retain, excluding the key:
        let different_public_coefficients =
            CspPublicCoefficients::Bls12_381(PublicCoefficientsBytes {
                coefficients: Vec::new(),
            });
        assert!(
            different_public_coefficients != internal_public_coefficients,
            "Public coefficients should be different - the different one has no entries after all!"
        );
        let active_key_ids = vec![different_public_coefficients]
            .iter()
            .map(key_id_from_csp_pub_coeffs)
            .collect();
        node.csp_vault
            .retain_threshold_keys_if_present(active_key_ids);

        // The key should be unavailable
        node.csp_vault
            .threshold_sign(
                AlgorithmId::ThresBls12_381,
                &b"To her life she clings!"[..],
                key_id,
            )
            .expect_err("The key should have been removed");
    }

    // The FS-encryption key MUST be retained, so that it is still available for
    // loading transcripts.

    // The state has a convenient function for loading the transcript:
    state.load_keys();

    // Verify that the threshold key has been loaded:
    {
        // Get the same node again:
        let node = get_one_node(&mut state);

        // Verify that the threshold key has been reloaded:
        let key_id = key_id_from_csp_pub_coeffs(&internal_public_coefficients);
        node.csp_vault
            .threshold_sign(
                AlgorithmId::ThresBls12_381,
                &b"Here's a howdyedo!"[..],
                key_id,
            )
            .expect("The key should be there initially");
    }
}

/// `create_dealing()` should return errors when appropriate
pub fn test_create_dealing_should_detect_errors(
    seed: [u8; 32],
    network_size: usize,
    _num_reshares: i32,
    csp_vault_factory: fn() -> Arc<dyn CspVault>,
) {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let network = MockNetwork::random(&mut rng, network_size, csp_vault_factory);
    let config = MockDkgConfig::from_network(&mut rng, &network, None);
    let mut state = StateWithConfig { network, config };
    // Dealing errors:
    state.deal_with_incorrect_algorithm_id_should_fail(&mut rng);
    state.deal_with_incorrect_threshold_should_fail(&mut rng);
    state.deal_with_incorrect_receiver_ids_should_fail(&mut rng);
    // MalformedFsPublicKeyError is untested as we have no Fs keys yet.
    // SizeError is untested because of the impracticality of making over 4
    // billion receivers.
}

impl StateWithConfig {
    //! Naughty operations

    /// Verifies that an incorrect algorithm id causes dealing to fail.
    ///
    /// Note: This error SHOULD be caught immediately, so there is no point in
    /// returning the result for further use.
    ///
    /// # Side effects
    /// Some randomness is consumed from rng.  The state is completely
    /// unchanged.
    pub fn deal_with_incorrect_algorithm_id_should_fail(&mut self, rng: &mut ChaCha20Rng) {
        // Note: We assume that any change in algorithm id makes this invalid.  At
        // present this is true, however if we introduce a new algorithm that uses the
        // same type of forward secure encryption key, this would have to change.
        let incorrect_algorithm_id: AlgorithmId = loop {
            let algorithm_id = random_algorithm_id(rng);
            if algorithm_id != self.config.algorithm_id {
                break algorithm_id;
            }
        };

        let (_dealer_index, dealer_id) = self
            .config
            .dealers
            .iter()
            .choose(rng)
            .expect("Config has no dealers");

        let dealer_node = self
            .network
            .nodes_by_node_id
            .get_mut(&dealer_id)
            .expect("Could not find dealer in nodes");

        let dealing = dealer_node.create_dealing(
            incorrect_algorithm_id,
            self.config
                .dealers
                .position(dealer_node.node_id)
                .expect("The node is not in the set of Dealers"),
            self.config.threshold.get(),
            self.config.epoch,
            self.config.receiver_keys.clone(),
            self.config
                .resharing_transcript
                .as_ref()
                .map(CspPublicCoefficients::from),
        );
        match dealing {
            Ok(_) => panic!(
                "Dealing should fail with AlgorithmId: {:?}",
                incorrect_algorithm_id
            ),
            Err(CspDkgCreateReshareDealingError::UnsupportedAlgorithmId(algorithm_id)) => {
                assert_eq!(
                    algorithm_id, incorrect_algorithm_id,
                    "Wrong algorithm_id reported"
                )
            }
            Err(error) => panic!("Incorrect error: {:?}", error),
        }
    }

    /// Verifies that dealing with an invalid threshold returns an error
    ///
    /// # Side effects
    /// None, other than consuming randomness.
    pub fn deal_with_incorrect_threshold_should_fail(&mut self, rng: &mut ChaCha20Rng) {
        let (_dealer_index, dealer_id) = self
            .config
            .dealers
            .iter()
            .choose(rng)
            .expect("Config has no dealers");

        let dealer_node = self
            .network
            .nodes_by_node_id
            .get_mut(&dealer_id)
            .expect("Could not find dealer in nodes");

        let num_receivers = self.config.receivers.count().get();
        for incorrect_threshold in &[0, num_receivers + 1, num_receivers + 2] {
            let dealing = dealer_node.create_dealing(
                self.config.algorithm_id,
                self.config
                    .dealers
                    .position(dealer_node.node_id)
                    .expect("The node is not in the set of Dealers"),
                NumberOfNodes::from(*incorrect_threshold),
                self.config.epoch,
                self.config.receiver_keys.clone(),
                self.config
                    .resharing_transcript
                    .as_ref()
                    .map(CspPublicCoefficients::from),
            );
            match dealing {
                Ok(_) => panic!("Dealing should fail with incorrect threshold.\n  Threshold: {}\n  Num receivers: {}", incorrect_threshold, num_receivers),
                Err(CspDkgCreateReshareDealingError::InvalidThresholdError(_)) => (),
                Err(error) => panic!("Incorrect error: {:?}", error),
            }
        }
    }

    /// Verifies that dealing with non-contiguous receiver IDs returns an error
    ///
    /// # Side effects
    /// None, other than consuming randomness.
    pub fn deal_with_incorrect_receiver_ids_should_fail(&mut self, rng: &mut ChaCha20Rng) {
        let (_dealer_index, dealer_id) = self
            .config
            .dealers
            .iter()
            .choose(rng)
            .expect("Config has no dealers");

        let dealer_node = self
            .network
            .nodes_by_node_id
            .get_mut(&dealer_id)
            .expect("Could not find dealer in nodes");

        // Choose another set of indices, leaving at least one gap in `[0..=n-1]`.
        let incorrect_receivers: BTreeMap<NodeIndex, CspFsEncryptionPublicKey> =
            Self::noncontiguous_indices(&self.config.receiver_keys, rng);
        let incorrect_indices: Vec<NodeIndex> = incorrect_receivers.keys().cloned().collect();

        let dealing = dealer_node.create_dealing(
            self.config.algorithm_id,
            self.config
                .dealers
                .position(dealer_node.node_id)
                .expect("The node is not in the set of Dealers"),
            self.config.threshold.get(),
            self.config.epoch,
            incorrect_receivers,
            self.config
                .resharing_transcript
                .as_ref()
                .map(CspPublicCoefficients::from),
        );
        match dealing {
            Ok(_) => panic!("Dealing should fail with indices: {:?}", incorrect_indices),
            Err(CspDkgCreateReshareDealingError::MisnumberedReceiverError { .. }) => (),
            Err(error) => panic!("Incorrect error: {:?}", error),
        }
    }

    /// Chooses another set of indices for a `BTreeMap`, leaving at least one
    /// gap in `[0..=n-1]`.
    ///
    /// This is used to test APIs that use `BTreeMaps` with indices `[0..=n-1]`.
    pub fn noncontiguous_indices<T: Clone>(
        map: &BTreeMap<NodeIndex, T>,
        rng: &mut ChaCha20Rng,
    ) -> BTreeMap<NodeIndex, T> {
        let missing_index = (0..map.len() as NodeIndex)
            .choose(rng)
            .expect("There were no receivers to choose from");
        let incorrect_indices: Vec<NodeIndex> = (0..map.len() as NodeIndex * 2)
            .filter(|index| *index != missing_index)
            .choose_multiple(rng, map.len());
        let values = map.iter().map(|(_, value)| (*value).clone());
        incorrect_indices.into_iter().zip(values).collect()
    }
}
