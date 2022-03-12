//! Tests for distributed key generation responses and response verification

use super::*;
use crate::dkg::secp256k1::dealing::create_dealing;
use crate::dkg::secp256k1::ephemeral_key::tests::create_ephemeral_public_key;
use crate::dkg::secp256k1::types::{
    EphemeralPopBytes, EphemeralPublicKeyBytes, EphemeralSecretKeyBytes,
};
use crate::test_utils::select_n;
use ic_types::{NodeIndex, NumberOfNodes, Randomness};
use ic_types_test_utils::arbitrary as arbitrary_types;
use proptest::prelude::*;

use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

use proptest::collection::vec as prop_vec;
use rand::Rng;
use std::collections::btree_map::BTreeMap;

/// Represents the node name of type Vec<u8> used in the spec
#[derive(Debug)]
pub struct NodeName {
    pub bytes: Vec<u8>,
}
impl proptest::prelude::Arbitrary for NodeName {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_vec(any::<u8>(), 0..33)
            .prop_map(|bytes| NodeName { bytes })
            .boxed()
    }
}

/// The ephemeral keys for a node
#[derive(Debug)]
pub struct EphemeralKeySet {
    pub owner: NodeName,
    pub secret_key_bytes: EphemeralSecretKeyBytes,
    pub public_key_bytes: EphemeralPublicKeyBytes,
    pub pop_bytes: EphemeralPopBytes,
}

/// This is the data needed to test responses
#[derive(Debug)]
pub struct ResponseFixture {
    pub dkg_id: IDkgId,
    pub seed: Randomness,
    pub dealer_key_sets: Vec<EphemeralKeySet>,
    pub receiver_key_sets: Vec<EphemeralKeySet>,
    pub eligible_receivers: Vec<bool>,
    pub honest_dealings: Vec<CLibDealingBytes>,
    pub threshold: NumberOfNodes,
}

/// Parameters for generating arbitrary fixtures
///
/// # Arguments
/// The arguments specify possible values of:
/// * `threshold` - the minimum number of receivers needed to make a valid
///   threshold signature.
/// * `redundancy` - the number of active receivers is threshold + redundancy.
/// * `inactive_receivers` - the number of receivers disqualified at the outset.
/// * `num_dealers` - the number of dealers.
#[derive(Copy, Clone, Debug)]
pub struct ResponseFixtureConfig {
    pub threshold_range: (NodeIndex, NodeIndex),
    pub redundancy_range: (NodeIndex, NodeIndex),
    pub inactive_receivers_range: (NodeIndex, NodeIndex),
    pub dealers_range: (NodeIndex, NodeIndex),
}

/// Generates an arbitrary fixture.
pub fn arbitrary_response_fixture(config: ResponseFixtureConfig) -> BoxedStrategy<ResponseFixture> {
    let parameter_strategy = (
        any::<[u8; 32]>(),
        arbitrary_types::dkg_id(),
        config.threshold_range.0..config.threshold_range.1,
        config.redundancy_range.0..config.redundancy_range.1,
        config.inactive_receivers_range.0..config.inactive_receivers_range.1,
        config.dealers_range.0..config.dealers_range.1,
    );

    let full_strategy = parameter_strategy.prop_flat_map(
        |(seed, dkg_id, threshold, redundancy, num_inactive_receivers, num_dealers)| {
            let num_receivers = (threshold + redundancy + num_inactive_receivers) as usize;
            let num_dealers = num_dealers as usize;

            (
                Just(Randomness::new(seed)),
                Just(dkg_id),
                Just(threshold),
                Just(redundancy),
                prop_vec(
                    any::<(NodeName, EphemeralSecretKeyBytes)>(),
                    num_dealers..=num_dealers,
                ),
                prop_vec(
                    any::<(NodeName, EphemeralSecretKeyBytes)>(),
                    num_receivers..=num_receivers,
                ),
            )
        },
    );

    full_strategy
        .prop_map(
            |(seed, dkg_id, threshold, redundancy, dealers, receivers)| {
                ResponseFixture::new(
                    seed,
                    dkg_id,
                    NumberOfNodes::from(threshold),
                    NumberOfNodes::from(redundancy),
                    dealers,
                    receivers,
                )
            },
        )
        .boxed()
}

impl ResponseFixture {
    pub fn new(
        seed: Randomness,
        dkg_id: IDkgId,
        threshold: NumberOfNodes,
        redundancy: NumberOfNodes,
        dealers: Vec<(NodeName, EphemeralSecretKeyBytes)>,
        receivers: Vec<(NodeName, EphemeralSecretKeyBytes)>,
    ) -> ResponseFixture {
        let mut rng = ChaChaRng::from_seed(seed.get());
        let dealer_key_sets: Vec<EphemeralKeySet> = dealers
            .into_iter()
            .map(|(owner, secret_key_bytes)| {
                let (public_key_bytes, pop_bytes) =
                    create_ephemeral_public_key(&mut rng, dkg_id, &secret_key_bytes, &owner.bytes)
                        .expect("Failed to generate test receiver public keys");
                EphemeralKeySet {
                    owner,
                    secret_key_bytes,
                    public_key_bytes,
                    pop_bytes,
                }
            })
            .collect();
        let receiver_key_sets: Vec<EphemeralKeySet> = receivers
            .into_iter()
            .map(|(owner, secret_key_bytes)| {
                let (public_key_bytes, pop_bytes) =
                    create_ephemeral_public_key(&mut rng, dkg_id, &secret_key_bytes, &owner.bytes)
                        .expect("Failed to generate test receiver public keys");
                EphemeralKeySet {
                    owner,
                    secret_key_bytes,
                    public_key_bytes,
                    pop_bytes,
                }
            })
            .collect();
        let some_receiver_public_keys: Vec<Option<(EphemeralPublicKeyBytes, EphemeralPopBytes)>> = {
            let seed = Randomness::from(rng.gen::<[u8; 32]>());
            let number_of_keys = threshold + redundancy;
            let all_public_keys: Vec<(EphemeralPublicKeyBytes, EphemeralPopBytes)> =
                receiver_key_sets
                    .iter()
                    .map(|key_set| (key_set.public_key_bytes, key_set.pop_bytes))
                    .collect();
            select_n(seed, number_of_keys, &all_public_keys)
        };
        let eligible_receivers: Vec<bool> = some_receiver_public_keys
            .iter()
            .map(|option| option.is_some())
            .collect();
        let honest_dealings: Vec<CLibDealingBytes> = dealer_key_sets
            .iter()
            .map(|dealer_key_set| {
                create_dealing(
                    Randomness::from(rng.gen::<[u8; 32]>()),
                    dealer_key_set.secret_key_bytes,
                    dkg_id,
                    threshold,
                    &some_receiver_public_keys,
                )
                .expect("Error in test setup: dealing failed")
            })
            .collect();
        ResponseFixture {
            dkg_id,
            seed: Randomness::from(rng.gen::<[u8; 32]>()),
            dealer_key_sets,
            receiver_key_sets,
            eligible_receivers,
            honest_dealings,
            threshold,
        }
    }
    pub fn dealings_with_keys(&self) -> BTreeMap<EphemeralPublicKeyBytes, CLibDealingBytes> {
        self.dealer_key_sets
            .iter()
            .zip(&self.honest_dealings)
            .map(|(key_set, dealing)| (key_set.public_key_bytes, dealing.clone()))
            .collect()
    }
}

fn test_honest_responses_to_honest_dealings_should_verify(fixture: ResponseFixture) {
    let mut rng = ChaChaRng::from_seed(fixture.seed.get());
    for receiver_index in 0..fixture.receiver_key_sets.len() {
        if fixture.eligible_receivers[receiver_index] {
            let response: CLibResponseBytes = {
                let seed = Randomness::from(rng.gen::<[u8; 32]>());
                let receiver_secret_key_bytes =
                    &fixture.receiver_key_sets[receiver_index].secret_key_bytes;
                create_response(
                    seed,
                    receiver_secret_key_bytes,
                    fixture.dkg_id,
                    &fixture.dealings_with_keys(),
                    NodeIndex::try_from(receiver_index).expect("Receiver index out of range"),
                )
                .expect("Failed to create a response")
            };
            verify_response(
                fixture.dkg_id,
                &fixture.dealings_with_keys(),
                NodeIndex::try_from(receiver_index).expect("Receiver index out of range"),
                fixture.receiver_key_sets[receiver_index].public_key_bytes,
                &response,
            )
            .expect("Failed to verify response");
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 2,
        max_shrink_iters: 0,
        .. ProptestConfig::default()
    })]

    #[test]
    fn honest_responses_to_honest_dealings_should_verify(fixture in arbitrary_response_fixture(ResponseFixtureConfig{threshold_range: (1,3), redundancy_range: (0,2), inactive_receivers_range:(0,2), dealers_range: (1,3)})) {
        test_honest_responses_to_honest_dealings_should_verify(fixture);
    }

    // TODO(CRP-333): Add more tests to cover all possible error conditions.
}
