//! The state after each stage of the DKG.  This provides the framework for
//! tests; a correct DKG can be run up to a particular stage, then errors may be
//! injected.

use super::*;
use crate::api::DistributedKeyGenerationCspClient;
use crate::secret_key_store::volatile_store::VolatileSecretKeyStore;
use crate::types::CspPop;
use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors::{
    DkgVerifyDealingError, DkgVerifyEphemeralError, DkgVerifyReshareDealingError,
    DkgVerifyResponseError,
};
use ic_crypto_test_utils::dkg::random_dkg_id;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeMap;

pub struct Node {
    node_id: Vec<u8>,
    csp: Csp<ChaCha20Rng, VolatileSecretKeyStore>,
}
impl Node {
    pub fn random(rng: &mut ChaCha20Rng) -> Self {
        let csprng = ChaCha20Rng::from_seed(rng.gen::<[u8; 32]>());
        let csp = Csp::of(csprng, VolatileSecretKeyStore::new());
        let node_id = rng.gen::<[u8; 8]>().to_vec();
        Node { node_id, csp }
    }
}

#[allow(unused)]
pub struct InitialState {
    dkg_id: IDkgId,
    receivers: Vec<Node>,
    dealers: Vec<Node>,
    verifier: Node,
}
impl InitialState {
    pub fn random(mut rng: &mut ChaCha20Rng, num_receivers: usize, num_dealers: usize) -> Self {
        InitialState {
            dkg_id: random_dkg_id(&mut rng),
            receivers: (0..num_receivers).map(|_| Node::random(&mut rng)).collect(),
            dealers: (0..num_dealers).map(|_| Node::random(&mut rng)).collect(),
            verifier: Node::random(&mut rng),
        }
    }

    pub fn resharing(
        mut rng: &mut ChaCha20Rng,
        num_receivers: usize,
        state: StateWithThresholdKeys,
    ) -> Self {
        InitialState {
            dkg_id: random_dkg_id(&mut rng),
            receivers: (0..num_receivers).map(|_| Node::random(&mut rng)).collect(),
            dealers: state.receivers,
            verifier: state.verifier,
        }
    }
}

#[allow(unused)]
pub struct StateWithEphemeralKeys {
    dkg_id: IDkgId,
    receivers: Vec<Node>,
    dealers: Vec<Node>,
    verifier: Node,
    receiver_keys: Vec<Option<(CspEncryptionPublicKey, CspPop)>>,
    dealer_keys: Vec<(CspEncryptionPublicKey, CspPop)>,
}
impl StateWithEphemeralKeys {
    pub fn new(participants: InitialState) -> Self {
        let InitialState {
            dkg_id,
            mut receivers,
            mut dealers,
            verifier,
        } = participants;
        let receiver_keys = receivers
            .iter_mut()
            .map(Some)
            .map(|node_maybe| {
                node_maybe.map(|node| {
                    node.csp
                        .dkg_create_ephemeral(dkg_id, &node.node_id)
                        .expect("Failed to generate receiver ephemeral key")
                })
            })
            .collect();
        let dealer_keys = dealers
            .iter_mut()
            .map(|node| {
                node.csp
                    .dkg_create_ephemeral(dkg_id, &node.node_id)
                    .expect("Failed to generate dealer ephemeral key")
            })
            .collect();
        StateWithEphemeralKeys {
            dkg_id,
            receivers,
            dealers,
            verifier,
            receiver_keys,
            dealer_keys,
        }
    }

    pub fn verify_ephemeral(&self) -> Result<(), DkgVerifyEphemeralError> {
        for (node, public_key_with_pop) in self.dealers.iter().zip(&self.dealer_keys) {
            self.verifier.csp.dkg_verify_ephemeral(
                self.dkg_id,
                &node.node_id,
                *public_key_with_pop,
            )?;
        }
        for (node, key_maybe) in self.receivers.iter().zip(&self.receiver_keys) {
            if let Some(public_key_with_pop) = key_maybe {
                self.verifier.csp.dkg_verify_ephemeral(
                    self.dkg_id,
                    &node.node_id,
                    *public_key_with_pop,
                )?;
            }
        }
        Ok(())
    }
}

#[allow(unused)]
pub struct StateWithDealings {
    dkg_id: IDkgId,
    receivers: Vec<Node>,
    dealers: Vec<Node>,
    verifier: Node,
    receiver_keys: Vec<Option<(CspEncryptionPublicKey, CspPop)>>,
    dealer_keys: Vec<(CspEncryptionPublicKey, CspPop)>,
    threshold: NumberOfNodes,
    dealings: BTreeMap<CspEncryptionPublicKey, CspDealing>,
}
impl StateWithDealings {
    pub fn new(state: StateWithEphemeralKeys, threshold: NumberOfNodes) -> Self {
        let StateWithEphemeralKeys {
            dkg_id,
            receivers,
            mut dealers,
            verifier,
            receiver_keys,
            dealer_keys,
        } = state;

        let dealings = dealers
            .iter_mut()
            .zip(&dealer_keys)
            .map(|(dealer, keys)| {
                let dealer_public_key = keys.0;
                let dealing = dealer
                    .csp
                    .dkg_create_dealing(dkg_id, threshold, &receiver_keys)
                    .expect("Could not deal");
                (dealer_public_key, dealing)
            })
            .collect();

        StateWithDealings {
            dkg_id,
            receivers,
            dealers,
            verifier,
            receiver_keys,
            dealer_keys,
            threshold,
            dealings,
        }
    }

    pub fn resharing(
        state: StateWithEphemeralKeys,
        threshold: NumberOfNodes,
        resharing_public_coefficients: CspPublicCoefficients,
    ) -> Self {
        let StateWithEphemeralKeys {
            dkg_id,
            receivers,
            mut dealers,
            verifier,
            receiver_keys,
            dealer_keys,
        } = state;

        let dealings = dealers
            .iter_mut()
            .zip(&dealer_keys)
            .map(|(dealer, keys)| {
                let dealer_public_key = keys.0;
                let dealing = dealer
                    .csp
                    .dkg_create_resharing_dealing(
                        dkg_id,
                        threshold,
                        resharing_public_coefficients.clone(),
                        &receiver_keys,
                    )
                    .expect("Could not deal");
                (dealer_public_key, dealing)
            })
            .collect();

        StateWithDealings {
            dkg_id,
            receivers,
            dealers,
            verifier,
            receiver_keys,
            dealer_keys,
            threshold,
            dealings,
        }
    }

    /// Adds the PoP to each entry in a map of dealings, as used by
    /// dkg_create_response.
    pub fn dealings_with_pops(
        dealer_keys: &[(CspEncryptionPublicKey, CspPop)],
        dealings: &BTreeMap<CspEncryptionPublicKey, CspDealing>,
    ) -> Vec<((CspEncryptionPublicKey, CspPop), CspDealing)> {
        dealer_keys
            .iter()
            .filter_map(|public_key_with_pop| {
                dealings
                    .get(&public_key_with_pop.0)
                    .map(|dealing| (*public_key_with_pop, dealing.clone()))
            })
            .collect()
    }

    pub fn verify_dealing(&self) -> Result<(), DkgVerifyDealingError> {
        for dealing in self.dealings.values() {
            self.verifier.csp.dkg_verify_dealing(
                self.threshold,
                &self.receiver_keys,
                dealing.clone(),
            )?;
        }
        Ok(())
    }

    pub fn verify_resharing_dealing(
        &self,
        resharing_public_coefficients: CspPublicCoefficients,
    ) -> Result<(), DkgVerifyReshareDealingError> {
        for (index, key) in (0..).zip(&self.dealer_keys) {
            if let Some(dealing) = self.dealings.get(&key.0) {
                self.verifier.csp.dkg_verify_resharing_dealing(
                    self.threshold,
                    &self.receiver_keys,
                    dealing.clone(),
                    index,
                    resharing_public_coefficients.clone(),
                )?;
            }
        }
        Ok(())
    }
}

#[allow(unused)]
pub struct StateWithResponses {
    dkg_id: IDkgId,
    receivers: Vec<Node>,
    dealers: Vec<Node>,
    verifier: Node,
    receiver_keys: Vec<Option<(CspEncryptionPublicKey, CspPop)>>,
    dealer_keys: Vec<(CspEncryptionPublicKey, CspPop)>,
    threshold: NumberOfNodes,
    dealings: BTreeMap<CspEncryptionPublicKey, CspDealing>,
    responses: Vec<Option<CspResponse>>,
}
impl StateWithResponses {
    pub fn new(state: StateWithDealings) -> Self {
        let StateWithDealings {
            dkg_id,
            mut receivers,
            dealers,
            verifier,
            receiver_keys,
            dealer_keys,
            threshold,
            dealings,
        } = state;

        let dealings_with_pops = StateWithDealings::dealings_with_pops(&dealer_keys, &dealings);

        let responses = receivers
            .iter_mut()
            .zip(&receiver_keys)
            .enumerate()
            .map(|(receiver_index, (node, keys))| {
                keys.map(|_| {
                    node.csp
                        .dkg_create_response(
                            dkg_id,
                            &dealings_with_pops,
                            NodeIndex::try_from(receiver_index).expect("Node index out of range"),
                        )
                        .expect("Failed to create response")
                })
            })
            .collect();

        StateWithResponses {
            dkg_id,
            receivers,
            dealers,
            verifier,
            receiver_keys,
            dealer_keys,
            threshold,
            dealings,
            responses,
        }
    }
    pub fn verify_responses(&self) -> Result<(), DkgVerifyResponseError> {
        let dealings_with_pops =
            StateWithDealings::dealings_with_pops(&self.dealer_keys, &self.dealings);
        for ((receiver_index, response_maybe), receiver_public_key_maybe) in
            (0..).zip(&self.responses).zip(&self.receiver_keys)
        {
            if let Some(response) = response_maybe {
                self.verifier.csp.dkg_verify_response(
                    self.dkg_id,
                    &dealings_with_pops,
                    receiver_index,
                    receiver_public_key_maybe.expect("Responder has no public key"),
                    response.clone(),
                )?;
            }
        }
        Ok(())
    }
}

pub struct StateWithTranscript {
    dkg_id: IDkgId,
    receivers: Vec<Node>,
    dealers: Vec<Node>,
    verifier: Node,
    receiver_keys: Vec<Option<(CspEncryptionPublicKey, CspPop)>>,
    threshold: NumberOfNodes,
    pub transcript: CspDkgTranscript,
}
impl StateWithTranscript {
    pub fn new(state: StateWithResponses) -> Self {
        let StateWithResponses {
            dkg_id,
            receivers,
            dealers,
            verifier,
            receiver_keys,
            dealer_keys,
            threshold,
            dealings,
            responses,
            ..
        } = state;

        let dealings_with_pops = StateWithDealings::dealings_with_pops(&dealer_keys, &dealings);

        let transcript = verifier
            .csp
            .dkg_create_transcript(threshold, &receiver_keys, &dealings_with_pops, &responses)
            .expect("Failed to create transcript");

        StateWithTranscript {
            dkg_id,
            receivers,
            dealers,
            verifier,
            receiver_keys,
            threshold,
            transcript,
        }
    }
    pub fn resharing(
        state: StateWithResponses,
        resharing_public_coefficients: CspPublicCoefficients,
    ) -> Self {
        let StateWithResponses {
            dkg_id,
            receivers,
            dealers,
            verifier,
            receiver_keys,
            dealer_keys,
            threshold,
            dealings,
            responses,
            ..
        } = state;

        let dealer_keys_maybe: Vec<Option<(CspEncryptionPublicKey, CspPop)>> =
            dealer_keys.iter().copied().map(Some).collect();
        let dealings_with_pops = StateWithDealings::dealings_with_pops(&dealer_keys, &dealings);

        let transcript = verifier
            .csp
            .dkg_create_resharing_transcript(
                threshold,
                &receiver_keys,
                &dealings_with_pops,
                &responses,
                &dealer_keys_maybe,
                resharing_public_coefficients,
            )
            .expect("Failed to create transcript");

        StateWithTranscript {
            dkg_id,
            receivers,
            dealers,
            verifier,
            receiver_keys,
            threshold,
            transcript,
        }
    }
}

#[allow(unused)]
pub struct StateWithThresholdKeys {
    dkg_id: IDkgId,
    receivers: Vec<Node>,
    dealers: Vec<Node>,
    verifier: Node,
    receiver_keys: Vec<Option<(CspEncryptionPublicKey, CspPop)>>,
    threshold: NumberOfNodes,
    pub transcript: CspDkgTranscript,
}
impl StateWithThresholdKeys {
    pub fn new(state: StateWithTranscript) -> Self {
        let StateWithTranscript {
            dkg_id,
            mut receivers,
            dealers,
            verifier,
            receiver_keys,
            threshold,
            transcript,
            ..
        } = state;

        // Note: The presence of a receiver key acts as a proxy for whether the receiver
        // should receive a threshold secret key.
        for (receiver, receiver_keys) in receivers.iter_mut().zip(&receiver_keys) {
            if receiver_keys.is_some() {
                receiver
                    .csp
                    .dkg_load_private_key(dkg_id, transcript.clone())
                    .expect("Could not compute threshold key");
            }
        }
        StateWithThresholdKeys {
            dkg_id,
            receivers,
            dealers,
            verifier,
            receiver_keys,
            threshold,
            transcript,
        }
    }

    /// Executes a complete standard DKG.
    pub fn by_dkg_or_panic(
        mut rng: &mut ChaCha20Rng,
        num_receivers: usize,
        num_dealers: usize,
        threshold: usize,
    ) -> Self {
        let participants = InitialState::random(&mut rng, num_receivers, num_dealers);

        // First key generation:
        let state = StateWithEphemeralKeys::new(participants);
        state
            .verify_ephemeral()
            .expect("Ephemeral keys failed to verify");
        let state = StateWithDealings::new(state, NumberOfNodes::from(threshold as NodeIndex));
        state.verify_dealing().expect("Dealings failed to verify");
        let state = StateWithResponses::new(state);
        state
            .verify_responses()
            .expect("Responses failed to verify");
        let state = StateWithTranscript::new(state);
        StateWithThresholdKeys::new(state)
    }

    /// Executes a complete resharing DKG.
    ///
    /// Panics if the DKG fails at any stage.
    pub fn by_resharing_or_panic(
        mut rng: &mut ChaCha20Rng,
        state: StateWithThresholdKeys,
        num_new_receivers: usize,
        new_threshold: usize,
    ) -> Self {
        let original_public_coefficients = CspPublicCoefficients::from(&state.transcript);
        let state = InitialState::resharing(&mut rng, num_new_receivers, state);
        let state = StateWithEphemeralKeys::new(state);
        state
            .verify_ephemeral()
            .expect("Ephemeral keys failed to verify");
        let state = StateWithDealings::resharing(
            state,
            NumberOfNodes::from(new_threshold as NodeIndex),
            original_public_coefficients.clone(),
        );
        state
            .verify_resharing_dealing(original_public_coefficients.clone())
            .expect("Resharing dealing failed to verify");
        let state = StateWithResponses::new(state);
        state
            .verify_responses()
            .expect("Responses failed to verify");
        let state = StateWithTranscript::resharing(state, original_public_coefficients);
        StateWithThresholdKeys::new(state)
    }
}
