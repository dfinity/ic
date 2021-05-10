//! Implements the dealing methods of `NiDkgAlgorithm`.
use super::*;
pub use creation::create_dealing;
use ic_crypto_internal_csp::api::NiDkgCspClient;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    CspFsEncryptionPublicKey, CspNiDkgDealing, CspNiDkgTranscript,
};
use ic_types::crypto::threshold_sig::ni_dkg::config::receivers::NiDkgReceivers;
use ic_types::crypto::AlgorithmId;
use utils::{
    csp_encryption_pubkey, dealer_index_in_dealers_or_panic, epoch,
    index_in_resharing_committee_or_panic, DkgEncPubkeyRegistryQueryError,
};
pub use verification::verify_dealing;

mod error_conversions;

#[cfg(test)]
mod tests;

mod creation {
    use super::*;
    use ic_types::crypto::threshold_sig::ni_dkg::errors::NotADealerError;

    pub fn create_dealing<C: NiDkgCspClient>(
        self_node_id: &NodeId,
        ni_dkg_csp_client: &C,
        registry: &Arc<dyn RegistryClient>,
        config: &NiDkgConfig,
    ) -> Result<NiDkgDealing, DkgCreateDealingError> {
        ensure_dealer_eligibility(self_node_id, config)?;
        let receiver_encryption_pubkeys = csp_dealing_encryption_pubkeys(
            config.receivers(),
            registry,
            config.registry_version(),
        )?;
        let csp_dealing = csp_dealing(
            self_node_id,
            ni_dkg_csp_client,
            config,
            receiver_encryption_pubkeys,
        )?;
        Ok(NiDkgDealing::from(csp_dealing))
    }

    fn ensure_dealer_eligibility(
        self_node_id: &NodeId,
        config: &NiDkgConfig,
    ) -> Result<(), DkgCreateDealingError> {
        if !is_eligible_dealer(self_node_id, config) {
            return Err(DkgCreateDealingError::NotADealer(NotADealerError {
                node_id: *self_node_id,
            }));
        }
        Ok(())
    }

    fn csp_dealing<C: NiDkgCspClient>(
        self_node_id: &NodeId,
        ni_dkg_csp_client: &C,
        config: &NiDkgConfig,
        receiver_encryption_pubkeys: BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
    ) -> Result<CspNiDkgDealing, DkgCreateDealingError> {
        if let Some(transcript) = config.resharing_transcript() {
            csp_load_key_and_create_resharing_dealing(
                self_node_id,
                ni_dkg_csp_client,
                config,
                receiver_encryption_pubkeys,
                transcript,
            )
        } else {
            csp_create_dealing(
                self_node_id,
                ni_dkg_csp_client,
                config,
                receiver_encryption_pubkeys,
            )
        }
    }

    fn csp_load_key_and_create_resharing_dealing<C: NiDkgCspClient>(
        self_node_id: &NodeId,
        ni_dkg_csp_client: &C,
        config: &NiDkgConfig,
        receiver_encryption_pubkeys: BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
        transcript: &NiDkgTranscript,
    ) -> Result<CspNiDkgDealing, DkgCreateDealingError> {
        ni_dkg_csp_client.load_threshold_signing_key(
            AlgorithmId::NiDkg_Groth20_Bls12_381,
            transcript.dkg_id,
            epoch(transcript.registry_version),
            CspNiDkgTranscript::from(transcript),
            index_in_resharing_committee_or_panic(self_node_id, &transcript.committee),
        )?;

        Ok(ni_dkg_csp_client.create_resharing_dealing(
            AlgorithmId::NiDkg_Groth20_Bls12_381,
            config.dkg_id(),
            index_in_resharing_committee_or_panic(self_node_id, &transcript.committee),
            config.threshold().get(),
            epoch(config.registry_version()),
            receiver_encryption_pubkeys,
            CspPublicCoefficients::from(transcript),
        )?)
    }

    fn csp_create_dealing<C: NiDkgCspClient>(
        self_node_id: &NodeId,
        ni_dkg_csp_client: &C,
        config: &NiDkgConfig,
        receiver_encryption_pubkeys: BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
    ) -> Result<CspNiDkgDealing, DkgCreateDealingError> {
        Ok(ni_dkg_csp_client.create_dealing(
            AlgorithmId::NiDkg_Groth20_Bls12_381,
            config.dkg_id(),
            dealer_index_in_dealers_or_panic(config.dealers(), *self_node_id),
            config.threshold().get(),
            epoch(config.registry_version()),
            receiver_encryption_pubkeys,
        )?)
    }
}

mod verification {
    use super::*;
    use ic_types::crypto::threshold_sig::ni_dkg::errors::NotADealerError;

    pub fn verify_dealing<C: NiDkgCspClient>(
        ni_dkg_csp_client: &C,
        registry: &Arc<dyn RegistryClient>,
        config: &NiDkgConfig,
        dealer: &NodeId,
        dealing: &NiDkgDealing,
    ) -> Result<(), DkgVerifyDealingError> {
        ensure_dealer_eligibility(dealer, config)?;
        let receiver_encryption_pubkeys = csp_dealing_encryption_pubkeys(
            config.receivers(),
            registry,
            config.registry_version(),
        )?;
        verify_csp_dealing(
            ni_dkg_csp_client,
            config,
            dealer,
            receiver_encryption_pubkeys,
            CspNiDkgDealing::from(dealing.clone()),
        )
    }

    fn ensure_dealer_eligibility(
        dealer: &NodeId,
        config: &NiDkgConfig,
    ) -> Result<(), DkgVerifyDealingError> {
        if !is_eligible_dealer(dealer, config) {
            return Err(DkgVerifyDealingError::NotADealer(NotADealerError {
                node_id: *dealer,
            }));
        }
        Ok(())
    }

    fn verify_csp_dealing<C: NiDkgCspClient>(
        ni_dkg_csp_client: &C,
        config: &NiDkgConfig,
        dealer: &NodeId,
        receiver_encryption_pubkeys: BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
        csp_dealing: CspNiDkgDealing,
    ) -> Result<(), DkgVerifyDealingError> {
        let epoch = epoch(config.registry_version());
        if let Some(transcript) = config.resharing_transcript() {
            Ok(ni_dkg_csp_client.verify_resharing_dealing(
                AlgorithmId::NiDkg_Groth20_Bls12_381,
                config.dkg_id(),
                index_in_resharing_committee_or_panic(dealer, &transcript.committee),
                config.threshold().get(),
                epoch,
                receiver_encryption_pubkeys,
                csp_dealing,
                CspPublicCoefficients::from(transcript),
            )?)
        } else {
            Ok(ni_dkg_csp_client.verify_dealing(
                AlgorithmId::NiDkg_Groth20_Bls12_381,
                config.dkg_id(),
                dealer_index_in_dealers_or_panic(config.dealers(), *dealer),
                config.threshold().get(),
                epoch,
                receiver_encryption_pubkeys,
                csp_dealing,
            )?)
        }
    }
}

fn is_eligible_dealer(node_id: &NodeId, config: &NiDkgConfig) -> bool {
    config.dealers().get().contains(node_id)
    // There is no need to check that the resharing committee contains the
    // node_id because (a) the NiDkgConfig guarantees that all dealers are
    // contained in resharing committee, and (b) the above check ensures that
    // node_id is a dealer
}

fn csp_dealing_encryption_pubkeys(
    receivers: &NiDkgReceivers,
    registry: &Arc<dyn RegistryClient>,
    registry_version: RegistryVersion,
) -> Result<BTreeMap<NodeIndex, CspFsEncryptionPublicKey>, DkgEncPubkeyRegistryQueryError> {
    let mut enc_pubkeys = BTreeMap::new();
    for (index, receiver) in receivers.iter() {
        let enc_pubkey = csp_encryption_pubkey(&receiver, registry, registry_version)?;
        enc_pubkeys.insert(index, enc_pubkey);
    }
    Ok(enc_pubkeys)
}
