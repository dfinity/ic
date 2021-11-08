#![allow(clippy::unwrap_used)]
use super::fixtures::cache::STATE_WITH_TRANSCRIPT;
use crate::server::api::{NiDkgCspServer, ThresholdSignatureCspServer};
use crate::server::local_csp_server::ni_dkg::tests::fixtures::{MockNode, StateWithTranscript};
use crate::types as csp_types;
use crate::types::conversions::key_id_from_csp_pub_coeffs;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::PublicCoefficientsBytes;
use ic_types::crypto::{AlgorithmId, KeyId};
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

    // We will apply our tests to just one node:
    fn get_one_node(state: &mut StateWithTranscript) -> &mut MockNode {
        state.network.nodes_by_node_id.iter_mut().next().unwrap().1
    }

    // Scoped access to a single CSP, so that we can recover ownership of the whole
    // state later:
    {
        let node: &mut MockNode = get_one_node(&mut state);

        // Verify that the key is there:
        let key_id = key_id_from_csp_pub_coeffs(&internal_public_coefficients);
        node.csp_server
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
        node.csp_server
            .retain_threshold_keys_if_present(active_key_ids);

        // The key should still be there:
        node.csp_server
            .threshold_sign(
                AlgorithmId::ThresBls12_381,
                &b"Here's a state of things!"[..],
                key_id,
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
        let active_key_ids = vec![different_public_coefficients]
            .iter()
            .map(key_id_from_csp_pub_coeffs)
            .collect();
        node.csp_server
            .retain_threshold_keys_if_present(active_key_ids);

        // The key should be unavailable
        node.csp_server
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
        node.csp_server
            .threshold_sign(
                AlgorithmId::ThresBls12_381,
                &b"Here's a howdyedo!"[..],
                key_id,
            )
            .expect("The key should be there initially");
    }
}
