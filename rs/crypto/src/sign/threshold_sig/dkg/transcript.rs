//! Implements the transcript methods of `DkgAlgorithm`.

use super::*;
use ic_crypto_internal_csp::api::DistributedKeyGenerationCspClient;
use ic_crypto_internal_csp::types::CspDkgTranscript;
use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors::DkgLoadPrivateKeyError;

pub use create::create_transcript;
pub use load::load_transcript;

#[cfg(test)]
mod tests;

mod create {
    use super::*;
    use crate::sign::threshold_sig::dkg::dealings_to_csp_dealings::DealingsToCspDealings;
    use crate::sign::threshold_sig::dkg::shared_utils::{csp_keys, csp_keys_for_optional_node_ids};
    use ic_crypto_internal_csp::types::CspResponse;
    use ic_types::crypto::dkg::Receivers;

    pub fn create_transcript<C: DistributedKeyGenerationCspClient, D: DealingsToCspDealings>(
        dkg_csp_client: &C,
        dealings_to_csp_dealings: D,
        config: &DkgConfig,
        verified_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        verified_dealings: &BTreeMap<NodeId, Dealing>,
        verified_responses: &BTreeMap<NodeId, Response>,
    ) -> CryptoResult<Transcript> {
        ensure_responses_are_not_empty(&verified_responses)?;
        let csp_transcript = create_csp_transcript(
            dkg_csp_client,
            dealings_to_csp_dealings,
            config,
            verified_keys,
            verified_dealings,
            verified_responses,
        )?;
        Ok(Transcript {
            dkg_id: config.dkg_id(),
            committee: committee(&config.receivers(), verified_keys),
            transcript_bytes: TranscriptBytes::from(&csp_transcript),
        })
    }

    fn create_csp_transcript<C: DistributedKeyGenerationCspClient, D: DealingsToCspDealings>(
        dkg_csp_client: &C,
        dealings_to_csp_dealings: D,
        config: &DkgConfig,
        verified_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        verified_dealings: &BTreeMap<NodeId, Dealing>,
        verified_responses: &BTreeMap<NodeId, Response>,
    ) -> CryptoResult<CspDkgTranscript> {
        let verified_csp_keys = csp_keys(config.receivers().get(), verified_keys);
        let verified_csp_dealings =
            &dealings_to_csp_dealings.convert(verified_keys, verified_dealings)?;
        let verified_csp_responses = &csp_responses(config.receivers(), verified_responses);
        if let Some(resharing_transcript) = &config.resharing_transcript() {
            let csp_resharing_transcript =
                CspDkgTranscript::from(&resharing_transcript.transcript_bytes);
            return Ok(dkg_csp_client.dkg_create_resharing_transcript(
                config.threshold().get(),
                &verified_csp_keys,
                &verified_csp_dealings,
                &verified_csp_responses,
                &csp_keys_for_optional_node_ids(&resharing_transcript.committee, verified_keys),
                CspPublicCoefficients::from(&csp_resharing_transcript),
            )?);
        }
        Ok(dkg_csp_client.dkg_create_transcript(
            config.threshold().get(),
            &verified_csp_keys,
            &verified_csp_dealings,
            &verified_csp_responses,
        )?)
    }

    fn ensure_responses_are_not_empty(
        verified_responses: &BTreeMap<NodeId, Response>,
    ) -> CryptoResult<()> {
        if verified_responses.is_empty() {
            return Err(CryptoError::InvalidArgument {
                message: "The responses must not be empty.".to_string(),
            });
        }
        Ok(())
    }

    fn csp_responses(
        receivers: &Receivers,
        responses: &BTreeMap<NodeId, Response>,
    ) -> Vec<Option<CspResponse>> {
        receivers
            .get()
            .iter()
            .map(|receiver| responses.get(receiver).map(CspResponse::from))
            .collect()
    }

    fn committee(
        receivers: &Receivers,
        keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
    ) -> Vec<Option<NodeId>> {
        receivers
            .get()
            .iter()
            .map(|receiver| keys.get(receiver).map(|_key| *receiver))
            .collect()
    }
}

mod load {
    use super::*;

    pub fn load_transcript<C: DistributedKeyGenerationCspClient>(
        lockable_threshold_sig_data_store: &LockableThresholdSigDataStore,
        dkg_csp_client: &C,
        transcript: &Transcript,
        _receiver: NodeId,
    ) -> CryptoResult<()> {
        let csp_transcript = CspDkgTranscript::from(&transcript.transcript_bytes);
        dkg_csp_client
            .dkg_load_private_key(transcript.dkg_id, csp_transcript.clone())
            .or_else(map_ephemeral_key_not_found_error_to_ok)?;
        lockable_threshold_sig_data_store
            .write()
            .insert_transcript_data(
                DkgId::IDkgId(transcript.dkg_id),
                CspPublicCoefficients::from(&csp_transcript),
                indices(&transcript.committee),
            );
        Ok(())
    }

    // Note that the index origin of `committee.iter().enumerate()` is 0.
    fn indices(committee: &[Option<NodeId>]) -> BTreeMap<NodeId, NodeIndex> {
        let mut indices = BTreeMap::new();
        for (i, receiver) in committee.iter().enumerate() {
            if let Some(node_id) = receiver {
                indices.insert(
                    *node_id,
                    NodeIndex::try_from(i).expect("node index overflow"),
                );
            }
        }
        indices
    }

    fn map_ephemeral_key_not_found_error_to_ok(
        load_private_key_error: DkgLoadPrivateKeyError,
    ) -> Result<(), DkgLoadPrivateKeyError> {
        if let DkgLoadPrivateKeyError::KeyNotFoundError(_) = load_private_key_error {
            return Ok(());
        }
        Err(load_private_key_error)
    }
}
