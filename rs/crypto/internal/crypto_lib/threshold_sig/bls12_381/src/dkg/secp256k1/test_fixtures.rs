//! (deprecated) Test fixtures for interactive distributed key generation.
use crate::api::dkg_errors::{DkgVerifyReshareDealingError, DkgVerifyResponseError};
use crate::api::{combine_signatures, keygen, sign_message, verify_combined_signature};
use crate::dkg::secp256k1 as dkg_lib;
use crate::types::public_coefficients::conversions::pub_key_bytes_from_pub_coeff_bytes;
use crate::types::{CombinedSignatureBytes, SecretKeyBytes as ThresholdSecretKeyBytes};
use dkg_lib::types::{
    CLibDealingBytes, CLibResponseBytes, CLibTranscriptBytes, CLibVerifiedResponseBytes,
    EphemeralKeySetBytes, EphemeralPopBytes, EphemeralPublicKeyBytes, EphemeralSecretKeyBytes,
};
use dkg_lib::{
    compute_private_key, create_ephemeral, create_resharing_dealing, create_resharing_transcript,
    create_response, verify_resharing_dealing, verify_response,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::PublicCoefficientsBytes;
use ic_crypto_test_utils::dkg::random_dkg_id;
use ic_types::NumberOfNodes;
use ic_types::{IDkgId, NodeIndex, Randomness};
use rand::seq::IteratorRandom;
use rand::Rng;
use rand_chacha::ChaChaRng;
use std::collections::BTreeMap;

pub fn ephemeral_key_set_from_tuple(
    tuple: (
        EphemeralSecretKeyBytes,
        EphemeralPublicKeyBytes,
        EphemeralPopBytes,
    ),
) -> EphemeralKeySetBytes {
    EphemeralKeySetBytes {
        secret_key_bytes: tuple.0,
        public_key_bytes: tuple.1,
        pop_bytes: tuple.2,
    }
}

pub fn ephemeral_key_set_public_key_with_pop(
    key_set: &EphemeralKeySetBytes,
) -> (EphemeralPublicKeyBytes, EphemeralPopBytes) {
    (key_set.public_key_bytes, key_set.pop_bytes)
}

#[derive(Clone)]
pub struct StateWithThresholdKey {
    pub threshold: NumberOfNodes,
    pub num_signatories: NumberOfNodes,
    pub public_coefficients: PublicCoefficientsBytes,
    pub secret_keys: Vec<Option<ThresholdSecretKeyBytes>>,
}
impl StateWithThresholdKey {
    pub fn random(rng: &mut ChaChaRng) -> Self {
        let threshold = NumberOfNodes::from(rng.gen_range(1 as NodeIndex, 10 as NodeIndex));
        let num_signatories = NumberOfNodes::from(rng.gen_range(threshold.get(), 10 as NodeIndex));
        let eligibility = vec![true; num_signatories.get() as usize];
        let (public_coefficients, secret_keys): (
            PublicCoefficientsBytes,
            Vec<Option<ThresholdSecretKeyBytes>>,
        ) = {
            let seed = Randomness::from(rng.gen::<[u8; 32]>());
            keygen(seed, threshold, &eligibility).expect("Initial keygen failed")
        };
        StateWithThresholdKey {
            threshold,
            num_signatories,
            public_coefficients,
            secret_keys,
        }
    }
    pub fn from_transcript(state: StateWithTranscript) -> Self {
        let secret_keys: Vec<Option<ThresholdSecretKeyBytes>> = state
            .receiver_ephemeral_keys
            .iter()
            .map(|key_maybe| {
                key_maybe
                    .map(|receiver_ephemeral_secret_key_bytes| {
                        compute_private_key(
                            receiver_ephemeral_secret_key_bytes.secret_key_bytes,
                            &state.transcript,
                            state.dkg_id,
                        )
                        .expect("Failed to compute threshold key from transcript")
                    })
                    .flatten()
            })
            .collect();

        StateWithThresholdKey {
            threshold: state.new_threshold,
            num_signatories: state.num_receivers,
            public_coefficients: state.transcript.public_coefficients,
            secret_keys,
        }
    }
    pub fn sign(&self, message: &[u8]) -> CombinedSignatureBytes {
        let individual_signatures: Vec<_> = self
            .secret_keys
            .iter()
            .map(|key_maybe| {
                key_maybe
                    .as_ref()
                    .map(|key| sign_message(message, key).expect("Could not sign"))
            })
            .collect();
        combine_signatures(&individual_signatures, self.threshold)
            .expect("Could not combine signatures")
    }
    pub fn verify(&self, message: &[u8], signature: CombinedSignatureBytes) {
        verify_combined_signature(
            message,
            signature,
            pub_key_bytes_from_pub_coeff_bytes(&self.public_coefficients),
        )
        .expect("Verification failed");
    }
}

#[derive(Clone)]
pub struct StateWithEphemeralKeys {
    pub initial_state: StateWithThresholdKey,
    pub dkg_id: IDkgId,
    pub num_dealers: NumberOfNodes,
    pub num_receivers: NumberOfNodes,
    pub dealer_ephemeral_keys: Vec<Option<EphemeralKeySetBytes>>,
    pub receiver_ephemeral_keys: Vec<Option<EphemeralKeySetBytes>>,
}
impl StateWithEphemeralKeys {
    pub fn random(mut rng: &mut ChaChaRng, initial_state: StateWithThresholdKey) -> Self {
        let dkg_id = random_dkg_id(&mut rng);
        let num_dealers = initial_state.num_signatories;
        let num_receivers = NumberOfNodes::from(rng.gen_range(1, 10 as NodeIndex));
        let dealer_ephemeral_keys = (0..num_dealers.get())
            .map(|dealer_index| {
                Some(ephemeral_key_set_from_tuple(create_ephemeral(
                    &mut rng,
                    dkg_id,
                    &dealer_index.to_be_bytes()[..],
                )))
            })
            .collect();
        let receiver_ephemeral_keys = (0..num_receivers.get())
            .map(|dealer_index| {
                Some(ephemeral_key_set_from_tuple(create_ephemeral(
                    &mut rng,
                    dkg_id,
                    &dealer_index.to_be_bytes()[..],
                )))
            })
            .collect();
        StateWithEphemeralKeys {
            initial_state,
            dkg_id,
            num_dealers,
            num_receivers,
            dealer_ephemeral_keys,
            receiver_ephemeral_keys,
        }
    }
}

#[derive(Clone)]
pub struct StateWithResharedDealings {
    pub initial_state: StateWithThresholdKey,
    pub dkg_id: IDkgId,
    pub num_dealers: NumberOfNodes,
    pub num_receivers: NumberOfNodes,
    pub dealer_ephemeral_keys: Vec<Option<EphemeralKeySetBytes>>,
    pub receiver_ephemeral_keys: Vec<Option<EphemeralKeySetBytes>>,
    pub dealer_indices: Vec<NodeIndex>,
    pub new_threshold: NumberOfNodes,
    pub dealings: BTreeMap<EphemeralPublicKeyBytes, CLibDealingBytes>,
}
impl StateWithResharedDealings {
    pub fn random(mut rng: &mut ChaChaRng, state: StateWithEphemeralKeys) -> Self {
        let StateWithEphemeralKeys {
            initial_state,
            dkg_id,
            num_dealers,
            num_receivers,
            dealer_ephemeral_keys,
            receiver_ephemeral_keys,
        } = state;
        // Some dealers may drop out; we need at least threshold dealers.
        assert!(
            initial_state.threshold.get() <= num_dealers.get(),
            "Insufficient dealers to reshare threshold key."
        );
        let num_dealers = NumberOfNodes::from(
            rng.gen_range(initial_state.threshold.get(), num_dealers.get() + 1),
        );
        let new_threshold = {
            let new_threshold = 5;
            let new_threshold = std::cmp::min(new_threshold, (num_receivers.get() + 1) / 2);
            let new_threshold = std::cmp::min(new_threshold, num_dealers.get());
            NumberOfNodes::from(rng.gen_range(1, new_threshold + 1))
        };
        let dealer_indices: Vec<NodeIndex> = (0..initial_state.num_signatories.get())
            .choose_multiple(&mut rng, num_dealers.get() as usize);
        // Assume that all receivers have ephemeral keys; we can replace Some with None
        // later if needed for testing.
        let receiver_public_keys_with_pop: Vec<
            Option<(EphemeralPublicKeyBytes, EphemeralPopBytes)>,
        > = receiver_ephemeral_keys
            .iter()
            .map(|keys_maybe| {
                keys_maybe
                    .as_ref()
                    .map(ephemeral_key_set_public_key_with_pop)
            })
            .collect();
        let dealings: BTreeMap<EphemeralPublicKeyBytes, CLibDealingBytes> = dealer_indices
            .iter()
            .filter_map(|dealer_index| {
                dealer_ephemeral_keys[*dealer_index as usize].map(|dealer_ephemeral_key_set| {
                    let seed = Randomness::from(rng.gen::<[u8; 32]>());
                    let dkg_id = dkg_id;
                    let reshared_secret_key = initial_state.secret_keys[*dealer_index as usize]
                        .expect(
                        "Could not get dealer secret key, even though we created all secret keys.",
                    );
                    let dealing = create_resharing_dealing(
                        seed,
                        dealer_ephemeral_key_set.secret_key_bytes,
                        dkg_id,
                        new_threshold,
                        &receiver_public_keys_with_pop,
                        reshared_secret_key,
                    )
                    .expect("Could not create resharing dealing");
                    (dealer_ephemeral_key_set.public_key_bytes, dealing)
                })
            })
            .collect();
        StateWithResharedDealings {
            initial_state,
            dkg_id,
            dealer_ephemeral_keys,
            receiver_ephemeral_keys,
            dealer_indices,
            new_threshold,
            dealings,
            num_dealers,
            num_receivers,
        }
    }
    pub fn verify_dealings(&self) -> Result<(), DkgVerifyReshareDealingError> {
        let receiver_public_keys: Vec<Option<(EphemeralPublicKeyBytes, EphemeralPopBytes)>> = self
            .receiver_ephemeral_keys
            .iter()
            .map(|keys_maybe| {
                keys_maybe
                    .as_ref()
                    .map(ephemeral_key_set_public_key_with_pop)
            })
            .collect();
        for dealer_index in self.dealer_indices.iter() {
            if let Some(dealer_key_set) = self.dealer_ephemeral_keys[*dealer_index as usize] {
                if let Some(dealing) = self.dealings.get(&dealer_key_set.public_key_bytes) {
                    verify_resharing_dealing(
                        self.new_threshold,
                        &receiver_public_keys,
                        dealing.clone(),
                        *dealer_index,
                        self.initial_state.public_coefficients.clone(),
                    )?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct StateWithResponses {
    pub initial_state: StateWithThresholdKey,
    pub dkg_id: IDkgId,
    pub num_dealers: NumberOfNodes,
    pub num_receivers: NumberOfNodes,
    pub dealer_ephemeral_keys: Vec<Option<EphemeralKeySetBytes>>,
    pub receiver_ephemeral_keys: Vec<Option<EphemeralKeySetBytes>>,
    pub dealer_indices: Vec<NodeIndex>,
    pub new_threshold: NumberOfNodes,
    pub dealings: BTreeMap<EphemeralPublicKeyBytes, CLibDealingBytes>,
    pub responses: Vec<Option<CLibResponseBytes>>,
}
impl StateWithResponses {
    pub fn from_resharing_dealings(rng: &mut ChaChaRng, state: StateWithResharedDealings) -> Self {
        let StateWithResharedDealings {
            initial_state,
            dkg_id,
            dealer_ephemeral_keys,
            receiver_ephemeral_keys,
            dealer_indices,
            new_threshold,
            dealings,
            num_dealers,
            num_receivers,
        } = state;

        let responses: Vec<_> = (0..)
            .zip(&receiver_ephemeral_keys)
            .map(|(receiver_index, key_maybe)| {
                key_maybe.map(|key_set| {
                    let seed = Randomness::from(rng.gen::<[u8; 32]>());
                    create_response(
                        seed,
                        &key_set.secret_key_bytes,
                        dkg_id,
                        &dealings,
                        receiver_index,
                    )
                    .expect("failed to create a response")
                })
            })
            .collect();

        StateWithResponses {
            initial_state,
            dkg_id,
            dealer_ephemeral_keys,
            receiver_ephemeral_keys,
            dealer_indices,
            new_threshold,
            dealings,
            num_dealers,
            num_receivers,
            responses,
        }
    }
    pub fn verify_responses(&self) -> Result<(), DkgVerifyResponseError> {
        for tuple in (0..)
            .zip(&self.receiver_ephemeral_keys)
            .zip(&self.responses)
        {
            if let ((receiver_index, Some(key)), Some(response)) = tuple {
                verify_response(
                    self.dkg_id,
                    &self.dealings,
                    receiver_index,
                    key.public_key_bytes,
                    &response,
                )?;
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct StateWithTranscript {
    pub initial_state: StateWithThresholdKey,
    pub dkg_id: IDkgId,
    pub num_dealers: NumberOfNodes,
    pub num_receivers: NumberOfNodes,
    pub dealer_ephemeral_keys: Vec<Option<EphemeralKeySetBytes>>,
    pub receiver_ephemeral_keys: Vec<Option<EphemeralKeySetBytes>>,
    pub dealer_indices: Vec<NodeIndex>,
    pub new_threshold: NumberOfNodes,
    pub dealings: BTreeMap<EphemeralPublicKeyBytes, CLibDealingBytes>,
    pub transcript: CLibTranscriptBytes,
}

impl StateWithTranscript {
    pub fn from_resharing_responses(state: StateWithResponses) -> Self {
        let StateWithResponses {
            initial_state,
            dkg_id,
            dealer_ephemeral_keys,
            receiver_ephemeral_keys,
            dealer_indices,
            new_threshold,
            dealings,
            num_dealers,
            num_receivers,
            responses,
        } = state;

        let dealer_public_keys: Vec<_> = dealer_ephemeral_keys
            .iter()
            .map(|key_maybe| {
                key_maybe
                    .as_ref()
                    .map(ephemeral_key_set_public_key_with_pop)
            })
            .collect();

        let verified_responses: Vec<_> = receiver_ephemeral_keys
            .iter()
            .zip(&responses)
            .map(|tuple| match tuple {
                (Some(key_set), Some(CLibResponseBytes { complaints })) => {
                    Some(CLibVerifiedResponseBytes {
                        receiver_public_key: key_set.public_key_bytes,
                        complaints: complaints.clone(),
                    })
                }
                _ => None,
            })
            .collect();

        let transcript = create_resharing_transcript(
            new_threshold,
            &dealings,
            &verified_responses,
            &dealer_public_keys,
            &initial_state.public_coefficients,
        )
        .expect("Could not compute transcript");

        StateWithTranscript {
            initial_state,
            dkg_id,
            dealer_ephemeral_keys,
            receiver_ephemeral_keys,
            dealer_indices,
            new_threshold,
            dealings,
            num_dealers,
            num_receivers,
            transcript,
        }
    }
}
