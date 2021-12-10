use crate::secret_key_store::SecretKeyStore;
use crate::types::CspSecretKey;
use crate::vault::api::ThresholdEcdsaSignerCspVault;
use crate::vault::local_csp_vault::idkg::commitment_key_id;
use crate::vault::local_csp_vault::LocalCspVault;
use ic_types::crypto::canister_threshold_sig::error::ThresholdEcdsaSignShareError;
use ic_types::crypto::canister_threshold_sig::ExtendedDerivationPath;
use ic_types::crypto::AlgorithmId;
use ic_types::Randomness;
use rand::{CryptoRng, Rng};
use std::convert::TryFrom;
use tecdsa::{
    sign_share as tecdsa_sign_share, CombinedCommitment, CommitmentOpening, IDkgTranscriptInternal,
    ThresholdEcdsaSigShareInternal,
};

impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore, C: SecretKeyStore>
    ThresholdEcdsaSignerCspVault for LocalCspVault<R, S, C>
{
    fn ecdsa_sign_share(
        &self,
        derivation_path: &ExtendedDerivationPath,
        hashed_message: &[u8],
        nonce: &Randomness,
        kappa_unmasked: &IDkgTranscriptInternal,
        lambda_masked: &IDkgTranscriptInternal,
        kappa_times_lambda: &IDkgTranscriptInternal,
        key_times_lambda: &IDkgTranscriptInternal,
        algorithm_id: AlgorithmId,
    ) -> Result<ThresholdEcdsaSigShareInternal, ThresholdEcdsaSignShareError> {
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
            kappa_unmasked,
            &lambda_share,
            &kappa_times_lambda_share,
            &key_times_lambda_share,
            algorithm_id,
        )
        .map_err(|e| ThresholdEcdsaSignShareError::InternalError {
            internal_error: format!("{:?}", e),
        })
    }
}

impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore, C: SecretKeyStore>
    LocalCspVault<R, S, C>
{
    fn combined_commitment_opening_from_sks(
        &self,
        combined_commitment: &CombinedCommitment,
    ) -> Result<CommitmentOpening, ThresholdEcdsaSignShareError> {
        let commitment = match combined_commitment {
            CombinedCommitment::BySummation(commitment)
            | CombinedCommitment::ByInterpolation(commitment) => commitment,
        };

        let key_id = commitment_key_id(commitment);
        let opening = self.canister_sks_read_lock().get(&key_id);
        match &opening {
            Some(CspSecretKey::IDkgCommitmentOpening(bytes)) => CommitmentOpening::try_from(bytes)
                .map_err(|e| ThresholdEcdsaSignShareError::InternalError {
                    internal_error: format!("{:?}", e),
                }),
            _ => Err(ThresholdEcdsaSignShareError::SecretSharesNotFound {
                commitment_string: format!("{:?}", commitment),
            }),
        }
    }
}
