//! Tests for transcript.rs
use super::*;
use crate::api::dkg_errors::DkgCreateTranscriptError;
use crate::crypto::tests::util::test_valid_public_coefficients;
use crate::dkg::secp256k1 as dkg;
use dkg::response::tests::{
    arbitrary_response_fixture, EphemeralKeySet, ResponseFixture, ResponseFixtureConfig,
};
use dkg::types::{CLibDealingBytes, CLibResponseBytes};
use ic_types::Randomness;
use proptest::collection::vec as prop_vec;
use proptest::prelude::*;
use rand::Rng;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use std::convert::TryInto;

#[derive(Debug)]
pub struct TranscriptFixture {
    pub seed: Randomness,
    pub dkg_id: IDkgId,
    pub threshold: NumberOfNodes,
    pub verified_dealings: BTreeMap<EphemeralPublicKeyBytes, CLibDealingBytes>,
    pub verified_responses: Vec<Option<CLibVerifiedResponseBytes>>,
    pub receiver_key_sets: Vec<EphemeralKeySet>,
    pub message: Vec<u8>,
}

impl TranscriptFixture {
    /// Protocol step: Receivers compute responses.
    fn responses(
        response_fixture: &ResponseFixture,
        rng: &mut ChaChaRng,
    ) -> Vec<Option<CLibResponseBytes>> {
        (0..)
            .zip(&response_fixture.receiver_key_sets)
            .zip(&response_fixture.eligible_receivers)
            .map(|((receiver_index, key_set), eligible_receiver)| {
                if *eligible_receiver {
                    let response: CLibResponseBytes = {
                        let seed = Randomness::from(rng.gen::<[u8; 32]>());
                        let receiver_secret_key_bytes = &key_set.secret_key_bytes;
                        dkg::response::create_response(
                            seed,
                            receiver_secret_key_bytes,
                            response_fixture.dkg_id,
                            &response_fixture.dealings_with_keys(),
                            NodeIndex::try_from(receiver_index)
                                .expect("Receiver index out of range"),
                        )
                        .expect("Failed to create a response")
                    };
                    Some(response)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Protocol step: Verifies responses.
    ///
    /// We skip the verification, as this is not necessary to test transcripts.
    /// If we want to simulate an invalid response, we can simply remove the
    /// (valid) response in the fixture.
    fn skip_verifying_responses(
        response_fixture: &ResponseFixture,
        responses: &[Option<CLibResponseBytes>],
    ) -> Vec<Option<CLibVerifiedResponseBytes>> {
        assert_eq!(response_fixture.receiver_key_sets.len(), responses.len());
        responses
            .iter()
            .cloned()
            .zip(&response_fixture.receiver_key_sets)
            .map(|(response_maybe, key_set)| {
                response_maybe.map(|CLibResponseBytes { complaints, .. }| {
                    CLibVerifiedResponseBytes {
                        complaints,
                        receiver_public_key: key_set.public_key_bytes,
                    }
                })
            })
            .collect()
    }

    /// Protocol step: Computes transcript.
    pub fn transcript(&self) -> Result<CLibTranscriptBytes, DkgCreateTranscriptError> {
        create_transcript(
            self.threshold,
            &self.verified_dealings,
            &self.verified_responses[..],
        )
    }

    /// Protocol step: Each receiver computes their own threshold secret key.
    pub fn threshold_secret_keys(
        &self,
        transcript: &CLibTranscriptBytes,
    ) -> Vec<Option<ThresholdSecretKey>> {
        self.receiver_key_sets
            .iter()
            .map(|key_set| {
                compute_private_key(key_set.secret_key_bytes, transcript, self.dkg_id)
                    .expect("Could not load private key")
                    .map(|key_bytes| {
                        (&key_bytes)
                            .try_into()
                            .expect("Computed malformed threshold secret key")
                    })
            })
            .collect()
    }

    /// Utility: Counts the number of verified responses.
    pub fn num_verified_responses(&self) -> NumberOfNodes {
        NumberOfNodes::from(
            self.verified_responses
                .iter()
                .filter(|response_maybe| response_maybe.is_some())
                .count() as NodeIndex,
        )
    }

    /// Utility: Counts the number of dealings.
    pub fn num_dealings(&self) -> NumberOfNodes {
        NumberOfNodes::from(self.verified_dealings.len() as NodeIndex)
    }
}

prop_compose! {
    /// Generates data with which to test transcripts.
    pub fn arbitrary_transcript_fixture(config: ResponseFixtureConfig) (
        response_fixture in arbitrary_response_fixture(config),
        message in prop_vec(any::<u8>(), 0..99),
    ) -> TranscriptFixture {
        let mut rng = ChaChaRng::from_seed(response_fixture.seed.get());
        let verified_dealings: BTreeMap<EphemeralPublicKeyBytes, CLibDealingBytes> = (&response_fixture.dealer_key_sets).iter().map(|key_set| key_set.public_key_bytes).zip(response_fixture.honest_dealings.iter().cloned()).collect();
        let responses = TranscriptFixture::responses(&response_fixture, &mut rng);
        let verified_responses = TranscriptFixture::skip_verifying_responses(&response_fixture, &responses[..]);

        TranscriptFixture{
          verified_responses,
          seed: response_fixture.seed,
          dkg_id: response_fixture.dkg_id,
          threshold: response_fixture.threshold,
          verified_dealings,
          message,
          receiver_key_sets: response_fixture.receiver_key_sets
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1,
        max_shrink_iters: 0,
        .. ProptestConfig::default()
    })]

    /// Tests that the threshold public coefficients and secret keys generated by DKG are valid.
    ///
    /// The threshold tests include a function that verifies that the threshold parameters are valid; we use that.
    #[test]
    fn dkg_should_produce_valid_threshold_keys(fixture in arbitrary_transcript_fixture(
        ResponseFixtureConfig{
            threshold_range: (1,3),
            redundancy_range: (3,7),
            inactive_receivers_range:(0,1),
            dealers_range: (3,5)})
    ) {
        prop_assume!(fixture.num_dealings() > fixture.threshold);
        prop_assume!(fixture.num_verified_responses() > fixture.threshold * 2);
        assert_eq!(NumberOfNodes::from(fixture.receiver_key_sets.len() as NodeIndex), fixture.num_verified_responses(), "Inactive receivers should be 0");

        // Setup:
        let transcript = fixture.transcript()
            .expect("Could not generate transcript");
        // TODO(CRP-812): The threshold test still uses the old assumption that all receivers
        // have keys.  It needs to be updated.  Once that is the case, we can update
        // this code:
        let threshold_secret_keys: Vec<ThresholdSecretKey> = fixture.threshold_secret_keys(&transcript).iter().map(|maybe| maybe
                    .expect("The threshold test does not support missing receivers")).collect();
        let public_coefficients =
            crate::types::PublicCoefficients::try_from(&transcript.public_coefficients)
                .expect("Invalid public coefficients");

        // Test:
        test_valid_public_coefficients(
            &public_coefficients,
            &threshold_secret_keys,
            fixture.threshold,
            fixture.seed,
            &fixture.message,
        )
    }

    /// Tests that if there are no dealers, creating a transcript fails.
    #[test]
    fn should_error_without_at_least_one_valid_dealer(fixture in arbitrary_transcript_fixture(
        ResponseFixtureConfig{
            threshold_range: (1,2),
            redundancy_range: (4,5),
            inactive_receivers_range:(0,1),
            dealers_range: (0,1)})
    ) {
        prop_assume!(fixture.num_verified_responses() > fixture.threshold * 2);
        assert!(fixture.transcript().is_err());
    }

    /// Tests that if there are insufficient verified responses, creating a transcript fails.
    #[test]
    fn should_error_without_sufficient_valid_responses(mut fixture in arbitrary_transcript_fixture(
        ResponseFixtureConfig{
            threshold_range: (1,2),
            redundancy_range: (4,5),
            inactive_receivers_range:(0,1),
            dealers_range: (1,3)})
    ) {
        prop_assume!(fixture.num_dealings() > fixture.threshold);

        // Remove responses until there are too few responses left
        let mut rng = ChaChaRng::from_seed(fixture.seed.get());
        let num_verified_responses =  fixture.verified_responses.len();
        while fixture.num_verified_responses() + NumberOfNodes::from(2) > fixture.threshold * 2 {
            fixture.verified_responses[rng.gen_range(0, num_verified_responses)] = None;
        }

        assert!(fixture.transcript().is_err(), "Expected to fail with threshold {} and {} responses", fixture.threshold, fixture.num_verified_responses());
    }
}
