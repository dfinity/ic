use super::*;

pub use creation::create_transcript;
use ic_crypto_internal_csp::api::NiDkgCspClient;
use ic_types::NumberOfNodes;
pub use loading::load_transcript;
use std::collections::btree_map::Iter;

mod error_conversions;

#[cfg(test)]
mod tests;

mod creation {
    use super::*;
    use crate::sign::threshold_sig::ni_dkg::utils::dealer_index_in_dealers_or_panic;
    use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors::InvalidArgumentError;
    use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
        CspNiDkgDealing, CspNiDkgTranscript,
    };
    use ic_types::crypto::threshold_sig::ni_dkg::config::dealers::NiDkgDealers;

    pub fn create_transcript<C: NiDkgCspClient>(
        ni_dkg_csp_client: &C,
        config: &NiDkgConfig,
        verified_dealings: &BTreeMap<NodeId, NiDkgDealing>,
    ) -> Result<NiDkgTranscript, DkgCreateTranscriptError> {
        let verified_dealings = NiDkgDealings::new(verified_dealings.clone())?;
        ensure_sufficiently_many_dealings(config, &verified_dealings)?;
        ensure_dealing_node_ids_in_dealers(&config.dealers(), &verified_dealings);
        let csp_transcript = create_csp_transcript(ni_dkg_csp_client, config, &verified_dealings)?;
        Ok(NiDkgTranscript {
            dkg_id: config.dkg_id(),
            threshold: config.threshold(),
            committee: config.receivers().clone(),
            registry_version: config.registry_version(),
            internal_csp_transcript: csp_transcript,
        })
    }

    fn ensure_sufficiently_many_dealings(
        config: &NiDkgConfig,
        verified_dealings: &NiDkgDealings,
    ) -> Result<(), DkgCreateTranscriptError> {
        if verified_dealings.count() <= config.max_corrupt_dealers() {
            return Err(DkgCreateTranscriptError::InsufficientDealings(
                InvalidArgumentError { message:
                    format!("Too few dealings: got {}, need more than {} (the maximum number of corrupt dealers).", verified_dealings.count(), config.max_corrupt_dealers()),
                }
            ));
        }
        Ok(())
    }

    fn ensure_sufficiently_many_dealings_for_resharing(
        verified_dealings: &NiDkgDealings,
        resharing_transcript: &NiDkgTranscript,
    ) -> Result<(), DkgCreateTranscriptError> {
        if verified_dealings.count() < resharing_transcript.threshold.get() {
            return Err(DkgCreateTranscriptError::InsufficientDealings(
                InvalidArgumentError {
                    message: format!("Too few dealings for resharing: got {}, need at least {} (threshold in re-sharing transcript).", verified_dealings.count(), resharing_transcript.threshold.get()),
                }
            ));
        }
        Ok(())
    }

    fn ensure_dealing_node_ids_in_dealers(
        dealers: &NiDkgDealers,
        verified_dealings: &NiDkgDealings,
    ) {
        // TODO (CRP-572): We could improve the complexity from O(|dealings| *
        // log(|dealers|)) to O(|dealings| + |dealers|) e.g. by using a HashSet.
        let dealing_node_ids_not_in_dealers: BTreeSet<NodeId> = verified_dealings
            .iter()
            .filter(|(node_id, _)| !dealers.get().contains(node_id))
            .map(|(node_id, _)| node_id)
            .copied()
            .collect();
        if !dealing_node_ids_not_in_dealers.is_empty() {
            // panic because this is a precondition violation:
            panic!(
                "Missing node ids in dealers: {:?}",
                dealing_node_ids_not_in_dealers
            );
        }
    }

    fn create_csp_transcript<C: NiDkgCspClient>(
        ni_dkg_csp_client: &C,
        config: &NiDkgConfig,
        verified_dealings: &NiDkgDealings,
    ) -> Result<CspNiDkgTranscript, DkgCreateTranscriptError> {
        if let Some(resharing_transcript) = &config.resharing_transcript() {
            ensure_sufficiently_many_dealings_for_resharing(
                verified_dealings,
                &resharing_transcript,
            )?;
            return Ok(convert_dealings_and_call_create_resharing_transcript(
                ni_dkg_csp_client,
                config,
                verified_dealings,
                &resharing_transcript,
            )?);
        }
        Ok(convert_dealings_and_call_create_transcript(
            ni_dkg_csp_client,
            config,
            verified_dealings,
        )?)
    }

    fn convert_dealings_and_call_create_resharing_transcript<C: NiDkgCspClient>(
        ni_dkg_csp_client: &C,
        config: &NiDkgConfig,
        verified_dealings: &NiDkgDealings,
        resharing_transcript: &NiDkgTranscript,
    ) -> Result<CspNiDkgTranscript, DkgCreateTranscriptError> {
        let csp_dealings = csp_dealings(verified_dealings, |dealer| {
            dealer_index_in_resharing_committee_or_panic(resharing_transcript, dealer)
        });
        Ok(ni_dkg_csp_client.create_resharing_transcript(
            AlgorithmId::NiDkg_Groth20_Bls12_381,
            config.threshold().get(),
            config.receivers().count(),
            csp_dealings,
            CspPublicCoefficients::from(resharing_transcript),
        )?)
    }

    fn dealer_index_in_resharing_committee_or_panic(
        resharing_transcript: &NiDkgTranscript,
        dealer: NodeId,
    ) -> NodeIndex {
        // the following never panics due to `ensure_dealing_node_ids_in_dealers` and
        // since the config guarantees that all dealers are contained in the resharing
        // committee.
        resharing_transcript
            .committee
            .position(dealer)
            .unwrap_or_else(|| {
                panic!(
                    "This operation requires node ({}) to be a dealer, but it is not.",
                    dealer
                )
            })
    }

    fn convert_dealings_and_call_create_transcript<C: NiDkgCspClient>(
        ni_dkg_csp_client: &C,
        config: &NiDkgConfig,
        verified_dealings: &NiDkgDealings,
    ) -> Result<CspNiDkgTranscript, DkgCreateTranscriptError> {
        let csp_dealings = csp_dealings(verified_dealings, |dealer| {
            dealer_index_in_dealers_or_panic(config.dealers(), dealer)
        });
        Ok(ni_dkg_csp_client.create_transcript(
            AlgorithmId::NiDkg_Groth20_Bls12_381,
            config.threshold().get(),
            config.receivers().count(),
            csp_dealings,
        )?)
    }

    fn csp_dealings(
        verified_dealings: &NiDkgDealings,
        index_provider: impl Fn(NodeId) -> NodeIndex,
    ) -> BTreeMap<NodeIndex, CspNiDkgDealing> {
        let mut csp_dealings = BTreeMap::new();
        for (dealer, dealing) in verified_dealings.iter() {
            let csp_dealing = CspNiDkgDealing::from(dealing.clone());
            let dealer_index = index_provider(*dealer);
            csp_dealings.insert(dealer_index, csp_dealing);
        }
        csp_dealings
    }

    struct NiDkgDealings {
        dealings: BTreeMap<NodeId, NiDkgDealing>,
        // The count equals `dealings.len()`.
        // This information is redundant since in several places we need the number
        // of dealings as NumberOfNodes. For that, the set length (`usize`) must
        // be converted to `NodeIndex`, which may fail. To avoid doing this in
        // several places this is done here on initialization.
        count: NumberOfNodes,
    }

    impl NiDkgDealings {
        pub fn new(
            dealings: BTreeMap<NodeId, NiDkgDealing>,
        ) -> Result<Self, DkgCreateTranscriptError> {
            Self::ensure_dealings_not_empty(&dealings)?;
            let count = Self::number_of_dealings(dealings.len())?;
            Ok(NiDkgDealings { dealings, count })
        }

        fn number_of_dealings(
            dealings_count: usize,
        ) -> Result<NumberOfNodes, DkgCreateTranscriptError> {
            let count = NodeIndex::try_from(dealings_count)
                .expect("The verified dealings size is too large, it must fit into NodeIndex.");
            Ok(NumberOfNodes::from(count))
        }

        fn ensure_dealings_not_empty(
            dealers: &BTreeMap<NodeId, NiDkgDealing>,
        ) -> Result<(), DkgCreateTranscriptError> {
            if dealers.is_empty() {
                return Err(DkgCreateTranscriptError::InsufficientDealings(
                    InvalidArgumentError {
                        message: "The verified dealings must not be empty".to_string(),
                    },
                ));
            }
            Ok(())
        }

        pub fn iter(&self) -> Iter<'_, NodeId, NiDkgDealing> {
            self.dealings.iter()
        }

        pub fn count(&self) -> NumberOfNodes {
            self.count
        }
    }
}

mod loading {
    use super::*;
    use crate::sign::threshold_sig::ni_dkg::utils::epoch;
    use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::CspDkgLoadPrivateKeyError;
    use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::CspNiDkgTranscript;
    use ic_logger::info;
    use ic_types::crypto::threshold_sig::ni_dkg::config::receivers::NiDkgReceivers;
    use ic_types::crypto::threshold_sig::ni_dkg::NiDkgId;

    pub fn load_transcript<C: NiDkgCspClient>(
        self_node_id: &NodeId,
        lockable_threshold_sig_data_store: &LockableThresholdSigDataStore,
        ni_dkg_csp_client: &C,
        transcript: &NiDkgTranscript,
        logger: &ReplicaLogger,
    ) -> Result<(), DkgLoadTranscriptError> {
        let csp_transcript = CspNiDkgTranscript::from(transcript);
        if let Some(self_index_in_committee) = transcript.committee.position(*self_node_id) {
            csp_load_threshold_signing_key(
                ni_dkg_csp_client,
                transcript,
                &csp_transcript,
                self_index_in_committee,
            )
            .or_else(|error|
                // If the decryption key was not found, or if the decryption key's epoch is newer than
                // the ciphertext in the transcript, then the threshold signing key was not loaded.
                // This is legal, but this node will not be able to threshold sign.
                map_decryption_key_not_usable_error_to_ok_and_log(error, logger))?;
        }
        insert_transcript_data_into_store(
            lockable_threshold_sig_data_store,
            &csp_transcript,
            transcript.dkg_id,
            &transcript.committee,
        );
        Ok(())
    }

    fn csp_load_threshold_signing_key<C: NiDkgCspClient>(
        ni_dkg_csp_client: &C,
        transcript: &NiDkgTranscript,
        csp_transcript: &CspNiDkgTranscript,
        self_index_in_committee: NodeIndex,
    ) -> Result<(), CspDkgLoadPrivateKeyError> {
        ni_dkg_csp_client.load_threshold_signing_key(
            AlgorithmId::NiDkg_Groth20_Bls12_381,
            transcript.dkg_id,
            epoch(transcript.registry_version),
            csp_transcript.clone(),
            self_index_in_committee,
        )
    }

    fn insert_transcript_data_into_store(
        lockable_threshold_sig_data_store: &LockableThresholdSigDataStore,
        csp_transcript: &CspNiDkgTranscript,
        dkg_id: NiDkgId,
        committee: &NiDkgReceivers,
    ) {
        lockable_threshold_sig_data_store
            .write()
            .insert_transcript_data(
                DkgId::NiDkgId(dkg_id),
                CspPublicCoefficients::from(csp_transcript),
                indices(committee),
            );
    }

    fn indices(committee: &NiDkgReceivers) -> BTreeMap<NodeId, NodeIndex> {
        let mut indices = BTreeMap::new();
        committee.iter().for_each(|(index, node_id)| {
            indices.insert(node_id, index);
        });
        indices
    }

    fn map_decryption_key_not_usable_error_to_ok_and_log(
        load_private_key_error: CspDkgLoadPrivateKeyError,
        logger: &ReplicaLogger,
    ) -> Result<(), CspDkgLoadPrivateKeyError> {
        match load_private_key_error {
            CspDkgLoadPrivateKeyError::KeyNotFoundError(_) => {
                info!(logger;
                      crypto.error =>
                      "Warning: unable to load the threshold signing key because the
                       decryption key was not found in the secret key store. Still proceeding to insert
                       the transcript data into the threshold signature data store. Verifying signature
                       shares, combining shares and verifying combined signatures is still possible, but
                       signing is not.",
                );
                Ok(())
            }
            CspDkgLoadPrivateKeyError::EpochTooOldError {
                ciphertext_epoch,
                secret_key_epoch,
            } => {
                info!(logger;
                      crypto.error =>
                      format!(
                          "Warning: threshold signing key was found but is for a newer epoch <{}> than this transcript <{}>.
                       Still proceeding to insert the transcript data into the threshold signature data store.
                       Verifying signature shares, combining shares and verifying combined signatures is still
                       possible, but signing is not.", secret_key_epoch, ciphertext_epoch),
                );
                Ok(())
            }
            e => Err(e),
        }
    }
}
