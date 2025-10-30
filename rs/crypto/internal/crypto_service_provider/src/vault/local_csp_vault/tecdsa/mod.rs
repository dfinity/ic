use crate::public_key_store::PublicKeyStore;
use crate::secret_key_store::SecretKeyStore;
use crate::vault::api::{IDkgTranscriptInternalBytes, ThresholdEcdsaSignerCspVault};
use crate::vault::local_csp_vault::LocalCspVault;
use ic_crypto_internal_logmon::metrics::{MetricsDomain, MetricsResult, MetricsScope};
use ic_crypto_internal_threshold_sig_canister_threshold_sig::{
    IDkgTranscriptInternal, ThresholdEcdsaSigShareInternal,
    create_ecdsa_signature_share as tecdsa_sign_share,
};
use ic_types::Randomness;
use ic_types::crypto::AlgorithmId;
use ic_types::crypto::ExtendedDerivationPath;
use ic_types::crypto::canister_threshold_sig::error::ThresholdEcdsaCreateSigShareError;
use rand::{CryptoRng, Rng};

#[cfg(test)]
mod tests;

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    ThresholdEcdsaSignerCspVault for LocalCspVault<R, S, C, P>
{
    fn create_ecdsa_sig_share(
        &self,
        derivation_path: ExtendedDerivationPath,
        hashed_message: Vec<u8>,
        nonce: Randomness,
        key_raw: IDkgTranscriptInternalBytes,
        kappa_unmasked_raw: IDkgTranscriptInternalBytes,
        lambda_masked_raw: IDkgTranscriptInternalBytes,
        kappa_times_lambda_raw: IDkgTranscriptInternalBytes,
        key_times_lambda_raw: IDkgTranscriptInternalBytes,
        algorithm_id: AlgorithmId,
    ) -> Result<ThresholdEcdsaSigShareInternal, ThresholdEcdsaCreateSigShareError> {
        fn deserialize_transcript(
            bytes: &[u8],
        ) -> Result<IDkgTranscriptInternal, ThresholdEcdsaCreateSigShareError> {
            IDkgTranscriptInternal::deserialize(bytes).map_err(|e| {
                ThresholdEcdsaCreateSigShareError::SerializationError {
                    internal_error: e.0,
                }
            })
        }

        let start_time = self.metrics.now();

        let key = deserialize_transcript(key_raw.as_ref())?;

        let kappa_unmasked = deserialize_transcript(kappa_unmasked_raw.as_ref())?;
        let lambda_masked = deserialize_transcript(lambda_masked_raw.as_ref())?;
        let kappa_times_lambda = deserialize_transcript(kappa_times_lambda_raw.as_ref())?;
        let key_times_lambda = deserialize_transcript(key_times_lambda_raw.as_ref())?;
        let result = self.ecdsa_sign_share_internal(
            &derivation_path,
            &hashed_message[..],
            &nonce,
            &key,
            &kappa_unmasked,
            &lambda_masked,
            &kappa_times_lambda,
            &key_times_lambda,
            algorithm_id,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::ThresholdEcdsa,
            MetricsScope::Local,
            "ecdsa_sign_share",
            MetricsResult::from(&result),
            start_time,
        );
        result
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    LocalCspVault<R, S, C, P>
{
    fn ecdsa_sign_share_internal(
        &self,
        derivation_path: &ExtendedDerivationPath,
        hashed_message: &[u8],
        nonce: &Randomness,
        key: &IDkgTranscriptInternal,
        kappa_unmasked: &IDkgTranscriptInternal,
        lambda_masked: &IDkgTranscriptInternal,
        kappa_times_lambda: &IDkgTranscriptInternal,
        key_times_lambda: &IDkgTranscriptInternal,
        algorithm_id: AlgorithmId,
    ) -> Result<ThresholdEcdsaSigShareInternal, ThresholdEcdsaCreateSigShareError> {
        let lambda_share =
            self.combined_commitment_opening_from_sks(&lambda_masked.combined_commitment)?;
        let kappa_times_lambda_share =
            self.combined_commitment_opening_from_sks(&kappa_times_lambda.combined_commitment)?;
        let key_times_lambda_share =
            self.combined_commitment_opening_from_sks(&key_times_lambda.combined_commitment)?;

        tecdsa_sign_share(
            &derivation_path.into(),
            hashed_message,
            *nonce,
            key,
            kappa_unmasked,
            &lambda_share,
            &kappa_times_lambda_share,
            &key_times_lambda_share,
            algorithm_id,
        )
        .map_err(|e| ThresholdEcdsaCreateSigShareError::InternalError {
            internal_error: format!("{e:?}"),
        })
    }
}
