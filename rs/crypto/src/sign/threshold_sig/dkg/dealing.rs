//! Implements the dealing methods of `DkgAlgorithm`.

use super::*;
use crate::sign::threshold_sig::dkg::shared_utils::csp_keys;
use crate::sign::threshold_sig::dkg::shared_utils::ensure_node_id_has_key;
use ic_crypto_internal_csp::api::DistributedKeyGenerationCspClient;
use ic_crypto_internal_csp::types::{CspDealing, CspDkgTranscript, CspPop};
use ic_crypto_internal_types::sign::threshold_sig::dkg::encryption_public_key::CspEncryptionPublicKey;
use ic_types::NumberOfNodes;

pub use create::create_dealing;
use ic_types::crypto::dkg::Dealers;
pub use verify::verify_dealing;

#[cfg(test)]
mod tests;

mod create {
    use super::*;
    use ic_crypto_internal_csp::api::DistributedKeyGenerationCspClient;

    pub fn create_dealing<C: DistributedKeyGenerationCspClient>(
        dkg_csp_client: &C,
        config: &DkgConfig,
        verified_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        dealer: NodeId,
    ) -> CryptoResult<Dealing> {
        ensure_node_id_has_key(dealer, verified_keys)?;
        ensure_dealers_contain_node_id(dealer, config.dealers())?;
        let receiver_keys = &csp_keys(&config.receivers().get(), verified_keys);
        let csp_dealing = csp_dealing(
            dkg_csp_client,
            config,
            config.threshold().get(),
            &receiver_keys,
        )?;
        Ok(Dealing::from(&csp_dealing))
    }

    fn csp_dealing<C: DistributedKeyGenerationCspClient>(
        dkg_csp_client: &C,
        config: &DkgConfig,
        threshold: NumberOfNodes,
        receiver_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
    ) -> CryptoResult<CspDealing> {
        if let Some(transcript) = &config.resharing_transcript() {
            return csp_create_resharing_dealing(
                dkg_csp_client,
                config.dkg_id(),
                threshold,
                receiver_keys,
                transcript,
            );
        }
        csp_create_dealing(dkg_csp_client, config, threshold, &receiver_keys)
    }

    fn csp_create_resharing_dealing<C: DistributedKeyGenerationCspClient>(
        dkg_csp_client: &C,
        dkg_id: IDkgId,
        threshold: NumberOfNodes,
        receiver_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
        transcript: &Transcript,
    ) -> Result<CspDealing, CryptoError> {
        // load_private_key ensures that the resharing threshold secret key is available
        // in the SKS
        let csp_transcript = CspDkgTranscript::from(&transcript.transcript_bytes);
        dkg_csp_client.dkg_load_private_key(transcript.dkg_id, csp_transcript.clone())?;
        Ok(dkg_csp_client.dkg_create_resharing_dealing(
            dkg_id,
            threshold,
            CspPublicCoefficients::from(&csp_transcript),
            &receiver_keys,
        )?)
    }

    fn csp_create_dealing<C: DistributedKeyGenerationCspClient>(
        dkg_csp_client: &C,
        config: &DkgConfig,
        threshold: NumberOfNodes,
        receiver_keys: &&[Option<(CspEncryptionPublicKey, CspPop)>],
    ) -> Result<CspDealing, CryptoError> {
        Ok(dkg_csp_client.dkg_create_dealing(config.dkg_id(), threshold, &receiver_keys)?)
    }

    // TODO (CRP-314): Map the CSP errors to IDKM errors.
    // TODO (CRP-415): Map the CSP errors to IDKM errors.
}

mod verify {
    use super::*;

    pub fn verify_dealing<C: DistributedKeyGenerationCspClient>(
        dkg_csp_client: &C,
        config: &DkgConfig,
        verified_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        dealer: NodeId,
        dealing: &Dealing,
    ) -> CryptoResult<()> {
        ensure_node_id_has_key(dealer, verified_keys)?;
        ensure_dealers_contain_node_id(dealer, config.dealers())?;
        verify_csp_dealing(
            dkg_csp_client,
            config.threshold().get(),
            &csp_keys(&config.receivers().get(), verified_keys),
            CspDealing::from(dealing),
            dealer,
            &config.resharing_transcript(),
        )
    }

    fn verify_csp_dealing<C: DistributedKeyGenerationCspClient>(
        dkg_csp_client: &C,
        threshold: NumberOfNodes,
        receiver_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
        csp_dealing: CspDealing,
        dealer: NodeId,
        resharing_transcript: &Option<Transcript>,
    ) -> CryptoResult<()> {
        if let Some(transcript) = resharing_transcript {
            return Ok(dkg_csp_client.dkg_verify_resharing_dealing(
                threshold,
                &receiver_keys,
                csp_dealing,
                dealer_index(dealer, &transcript.committee),
                CspPublicCoefficients::from(&CspDkgTranscript::from(&transcript.transcript_bytes)),
            )?);
        }
        Ok(dkg_csp_client.dkg_verify_dealing(threshold, &receiver_keys, csp_dealing)?)
    }

    fn dealer_index(dealer: NodeId, committee: &[Option<NodeId>]) -> NodeIndex {
        committee
            .iter()
            .position(|current_value| *current_value == Some(dealer))
            .map(|index| NodeIndex::try_from(index).expect("node index overflow"))
            .unwrap_or_else(|| panic!("internal error: expected dealer to be present in committee"))
    }
}

fn ensure_dealers_contain_node_id(node_id: NodeId, dealers: &Dealers) -> CryptoResult<()> {
    if dealers.get().contains(&node_id) {
        return Ok(());
    }
    Err(CryptoError::InvalidArgument {
        message: format!("The node with ID \"{:?}\" is not a dealer.", node_id),
    })
}
