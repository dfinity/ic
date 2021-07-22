#![allow(clippy::unwrap_used)]
use super::fixtures::cache::STATE_WITH_TRANSCRIPT;
use crate::api::NiDkgCspClient;
use crate::secret_key_store::volatile_store::VolatileSecretKeyStore;
use crate::threshold::ni_dkg::tests::fixtures::StateWithTranscript;
use crate::threshold::ThresholdSignatureCspClient;
use crate::types as csp_types;
use crate::Csp;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::PublicCoefficientsBytes;
use ic_types::crypto::AlgorithmId;
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeSet;

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
#[test]
fn test_retention() {
    let mut state = STATE_WITH_TRANSCRIPT
        .lock()
        .expect("Test setup failed:  Could not get CSP with transcript");
    state.load_keys();

    let internal_public_coefficients = state.transcript.public_coefficients();

    // We will apply our tests to just one CSP:
    fn get_one_csp(
        state: &mut StateWithTranscript,
    ) -> &mut Csp<ChaCha20Rng, VolatileSecretKeyStore> {
        &mut state
            .network
            .nodes_by_node_id
            .iter_mut()
            .next()
            .unwrap()
            .1
            .csp
    }

    // Scoped access to a single CSP, so that we can recover ownership of the whole
    // state later:
    {
        let csp = get_one_csp(&mut state);

        // Verify that the key is there:
        csp.threshold_sign(
            AlgorithmId::ThresBls12_381,
            &b"Here's a howdyedo!"[..],
            internal_public_coefficients.clone(),
        )
        .expect("The key should be there initially");

        // Call retain, keeping the threshold key:
        let active_keys: BTreeSet<csp_types::CspPublicCoefficients> =
            vec![internal_public_coefficients.clone()]
                .into_iter()
                .collect();
        csp.retain_threshold_keys_if_present(active_keys);

        // The key should still be there:
        csp.threshold_sign(
            AlgorithmId::ThresBls12_381,
            &b"Here's a state of things!"[..],
            internal_public_coefficients.clone(),
        )
        .expect("The key should have been retained");

        // Call retain, excluding the key:
        let different_public_coefficients =
            csp_types::CspPublicCoefficients::Bls12_381(PublicCoefficientsBytes {
                coefficients: Vec::new(),
            });
        assert!(
            different_public_coefficients != internal_public_coefficients,
            "Public coefficients should be different - the different one has no entries after all!"
        );
        let active_keys = vec![different_public_coefficients].into_iter().collect();
        csp.retain_threshold_keys_if_present(active_keys);

        // The key should be unavailable
        csp.threshold_sign(
            AlgorithmId::ThresBls12_381,
            &b"To her life she clings!"[..],
            internal_public_coefficients.clone(),
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
        let csp = get_one_csp(&mut state);

        // Verify that the threshold key has been reloaded:
        csp.threshold_sign(
            AlgorithmId::ThresBls12_381,
            &b"Here's a howdyedo!"[..],
            internal_public_coefficients,
        )
        .expect("The key should be there initially");
    }
}
