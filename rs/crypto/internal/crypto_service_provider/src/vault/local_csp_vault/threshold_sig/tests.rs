//! Tests for threshold signature implementations

use crate::key_id::KeyId;
use crate::public_key_store::PublicKeyStore;
use crate::secret_key_store::SecretKeyStore;
use crate::types::{CspPublicCoefficients, CspSecretKey};
use crate::vault::api::CspThresholdSignatureKeygenError;
use crate::vault::local_csp_vault::LocalCspVault;
use crate::vault::test_utils;
use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_threshold_sig_bls12381 as bls12381_clib;
use ic_types::crypto::AlgorithmId;
use proptest::prelude::*;
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaChaRng;

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    LocalCspVault<R, S, C, P>
{
    /// Generates threshold keys.
    ///
    /// This interface is primarily of interest for testing and demos.
    ///
    /// # Arguments
    /// * `algorithm_id` indicates the algorithms to be used in the key
    ///   generation.
    /// * `threshold` is the minimum number of signatures that can be combined
    ///   to make a valid threshold signature.
    /// * `receivers` is the total number of receivers
    /// # Returns
    /// * `CspPublicCoefficients` can be used by the caller to verify
    ///   signatures.
    /// * `Vec<KeyId>` contains key identifiers.  The vector has the
    ///   same length as the number of `receivers`.
    /// # Panics
    /// * An implementation MAY panic if it is unable to access the secret key
    ///   store to save keys or if it cannot access a suitable random number
    ///   generator.
    /// # Errors
    /// * If `threshold > receivers` then it is impossible for
    ///   the signatories to create a valid combined signature, so
    ///   implementations MUST return an error.
    /// * An implementation MAY return an error if it is temporarily unable to
    ///   generate and store keys.
    ///
    /// Warning: The secret key store has no transactions, so in the event of
    /// a failure it is possible that some but not all keys are written.
    pub fn threshold_keygen_for_test(
        &self,
        algorithm_id: AlgorithmId,
        threshold: ic_types::NumberOfNodes,
        receivers: ic_types::NumberOfNodes,
    ) -> Result<(CspPublicCoefficients, Vec<KeyId>), CspThresholdSignatureKeygenError> {
        match algorithm_id {
            AlgorithmId::ThresBls12_381 => {
                let seed = Seed::from_rng(&mut *self.rng_write_lock());
                let (public_coefficients, secret_keys) =
                    bls12381_clib::api::generate_threshold_key(seed, threshold, receivers)?;
                let key_ids: Vec<KeyId> = secret_keys
                    .iter()
                    .map(|secret_key| {
                        loop {
                            let key_id = KeyId::from(self.rng_write_lock().r#gen::<[u8; 32]>());
                            let csp_secret_key = CspSecretKey::ThresBls12_381(secret_key.clone());
                            let result = self.sks_write_lock().insert(key_id, csp_secret_key, None);
                            if result.is_ok() {
                                break key_id;
                            }
                        }
                    })
                    .collect();
                let csp_public_coefficients = CspPublicCoefficients::Bls12_381(public_coefficients);
                Ok((csp_public_coefficients, key_ids))
            }
            _ => Err(CspThresholdSignatureKeygenError::UnsupportedAlgorithm {
                algorithm: algorithm_id,
            }),
        }
    }
}

// Slow tests
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 4,
        .. ProptestConfig::default()
    })]

    #[test]
    fn test_threshold_scheme_with_basic_keygen(seed: [u8;32], message in proptest::collection::vec(any::<u8>(), 0..100)) {
        let rng = &mut ChaChaRng::from_seed(seed);
        let csp_vault  = {
            let csprng = ChaChaRng::from_seed(rng.r#gen::<[u8; 32]>());
            LocalCspVault::builder_for_test().with_rng(csprng).build_into_arc()
        };
        test_utils::threshold_sig::test_threshold_scheme_with_basic_keygen(Seed::from_rng(rng), csp_vault, &message);
    }
}
