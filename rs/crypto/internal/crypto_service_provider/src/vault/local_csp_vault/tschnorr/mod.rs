use crate::public_key_store::PublicKeyStore;
use crate::secret_key_store::SecretKeyStore;
use crate::vault::api::{
    IDkgTranscriptInternalBytes, ThresholdSchnorrCreateSigShareVaultError,
    ThresholdSchnorrSigShareBytes, ThresholdSchnorrSignerCspVault,
};
use crate::vault::local_csp_vault::LocalCspVault;
use ic_crypto_internal_logmon::metrics::{MetricsDomain, MetricsResult, MetricsScope};
use ic_crypto_internal_threshold_sig_ecdsa::{
    create_bip340_signature_share, DerivationPath, IDkgTranscriptInternal,
    ThresholdBip340GenerateSigShareInternalError,
};
use ic_types::crypto::canister_threshold_sig::ExtendedDerivationPath;
use ic_types::crypto::AlgorithmId;
use ic_types::Randomness;
use rand::{CryptoRng, Rng};

#[cfg(test)]
mod tests;

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    ThresholdSchnorrSignerCspVault for LocalCspVault<R, S, C, P>
{
    fn create_schnorr_sig_share(
        &self,
        extended_derivation_path: ExtendedDerivationPath,
        message: Vec<u8>,
        nonce: Randomness,
        key_raw: IDkgTranscriptInternalBytes,
        presig_raw: IDkgTranscriptInternalBytes,
        algorithm_id: AlgorithmId,
    ) -> Result<ThresholdSchnorrSigShareBytes, ThresholdSchnorrCreateSigShareVaultError> {
        fn deserialize_transcript(
            bytes: &[u8],
        ) -> Result<IDkgTranscriptInternal, ThresholdSchnorrCreateSigShareVaultError> {
            IDkgTranscriptInternal::deserialize(bytes)
                .map_err(|e| ThresholdSchnorrCreateSigShareVaultError::SerializationError(e.0))
        }

        let key_transcript = deserialize_transcript(key_raw.as_ref())?;
        let presig_transcript = deserialize_transcript(presig_raw.as_ref())?;
        let key_opening =
            self.combined_commitment_opening_from_sks(&key_transcript.combined_commitment)?;
        let presig_opening =
            self.combined_commitment_opening_from_sks(&presig_transcript.combined_commitment)?;

        let start_time = self.metrics.now();

        let derivation_path = DerivationPath::from(&extended_derivation_path);

        let result = match algorithm_id {
            AlgorithmId::ThresholdSchnorrBip340 => {
                let sig_share = create_bip340_signature_share(
                    &derivation_path,
                    &message[..],
                    nonce,
                    &key_transcript,
                    &presig_transcript,
                    &key_opening,
                    &presig_opening,
                )?;
                sig_share
                    .serialize()
                    .map_err(|e| ThresholdSchnorrCreateSigShareVaultError::SerializationError(e.0))
                    .map(ThresholdSchnorrSigShareBytes::from)
            }
            _ => Err(ThresholdSchnorrCreateSigShareVaultError::InvalidArguments(
                format!("invalid algorithm id for threshold Schnorr signature: {algorithm_id}"),
            )),
        };

        self.metrics.observe_duration_seconds(
            MetricsDomain::ThresholdSchnorr,
            MetricsScope::Local,
            "create_schnorr_sig_share",
            MetricsResult::from(&result),
            start_time,
        );
        result
    }
}

impl From<ThresholdBip340GenerateSigShareInternalError>
    for ThresholdSchnorrCreateSigShareVaultError
{
    fn from(e: ThresholdBip340GenerateSigShareInternalError) -> Self {
        type F = ThresholdBip340GenerateSigShareInternalError;

        match e {
            F::InvalidArguments(s) => Self::InvalidArguments(s),
            F::InconsistentCommitments => Self::InconsistentCommitments,
            F::InternalError(s) => Self::InternalError(s),
        }
    }
}
