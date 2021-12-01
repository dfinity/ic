//! Tests for create_dealing()
use super::*;
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::CspDkgCreateReshareDealingError;
use rand::seq::IteratorRandom;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 4,
        max_shrink_iters: 0,
        .. ProptestConfig::default()
    })]

    #[test]
    fn create_dealing_should_detect_errors(seed: [u8;32], network_size in MockNetwork::MIN_SIZE..=MockNetwork::DEFAULT_MAX_SIZE, num_reshares in 0..4) {
      test_create_dealing_should_detect_errors(seed, network_size, num_reshares);
    }
}

/// `create_dealing()` should return errors when appropriate
fn test_create_dealing_should_detect_errors(
    seed: [u8; 32],
    network_size: usize,
    _num_reshares: i32,
) {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let network = MockNetwork::random(&mut rng, network_size, new_csp_vault);
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
