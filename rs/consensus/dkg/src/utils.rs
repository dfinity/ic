use ic_consensus_utils::pool_reader::PoolReader;
use ic_interfaces_registry::RegistryClient;
use ic_logger::{ReplicaLogger, warn};
use ic_management_canister_types_private::MasterPublicKeyId;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_types::{
    NodeId, RegistryVersion, SubnetId,
    consensus::{
        Block,
        dkg::{DkgPayloadCreationError, DkgSummary},
    },
    crypto::{
        AlgorithmId,
        canister_threshold_sig::MasterPublicKey,
        threshold_sig::{
            ThresholdSigPublicKey,
            ni_dkg::{NiDkgDealing, NiDkgId, NiDkgMasterPublicKeyId, NiDkgTag},
        },
    },
};
use std::collections::{BTreeMap, HashSet};

/// Returns the [`MasterPublicKey`]s and also the [`NiDkgId`]s of the `next_transcript`
/// (or, if unavialable, of the `current_transcript`) corresponding to the [`MasterPublicKeyId`]s
/// active on the subnet.
#[allow(clippy::type_complexity)]
pub fn get_vetkey_public_keys(
    summary: &DkgSummary,
    logger: &ReplicaLogger,
) -> (
    BTreeMap<MasterPublicKeyId, MasterPublicKey>,
    BTreeMap<NiDkgMasterPublicKeyId, NiDkgId>,
) {
    // Get all next transcripts
    // If there is a current transcript, but no next transcript, use that one instead.
    let mut transcripts = summary
        .next_transcripts()
        .iter()
        .collect::<BTreeMap<_, _>>();
    for (tag, transcript) in summary.current_transcripts().iter() {
        if !transcripts.contains_key(tag) {
            warn!(logger, "Reusing current transcript for tag {:?}", tag);
            transcripts.insert(tag, transcript);
        }
    }

    let (master_keys, dkg_ids) = transcripts
        .iter()
        // Filter out transcripts that are not for VetKD
        .filter_map(|(tag, &transcript)| match tag {
            NiDkgTag::HighThresholdForKey(key_id) => Some((key_id, transcript)),
            _ => None,
        })
        // Try to build the public key from the transcript
        .filter_map(
            |(key_id, transcript)| match ThresholdSigPublicKey::try_from(transcript) {
                Err(err) => {
                    warn!(
                        logger,
                        "Failed to get public key for key id {}: {:?}", key_id, err
                    );
                    None
                }
                Ok(pubkey) => Some((key_id, pubkey, transcript.dkg_id.clone())),
            },
        )
        // Unzip the data into the two maps that delivery needs
        .map(|(key_id, pubkey, ni_dkg_id)| {
            (
                (
                    key_id.clone().into(),
                    MasterPublicKey {
                        algorithm_id: AlgorithmId::VetKD,
                        public_key: pubkey.into_bytes().to_vec(),
                    },
                ),
                (key_id.clone(), ni_dkg_id),
            )
        })
        .unzip();

    (master_keys, dkg_ids)
}

pub(super) fn get_dealers_from_chain(
    pool_reader: &PoolReader<'_>,
    block: &Block,
) -> HashSet<(NiDkgId, NodeId)> {
    get_dkg_dealings(pool_reader, block)
        .into_iter()
        .flat_map(|(dkg_id, dealings)| {
            dealings
                .into_keys()
                .map(move |node_id| (dkg_id.clone(), node_id))
        })
        .collect()
}

// Starts with the given block and creates a nested mapping from the DKG Id to
// the node Id to the dealing. This function panics if multiple dealings
// from one dealer are discovered, hence, we assume a valid block chain.
pub(super) fn get_dkg_dealings(
    pool_reader: &PoolReader<'_>,
    block: &Block,
) -> BTreeMap<NiDkgId, BTreeMap<NodeId, NiDkgDealing>> {
    pool_reader
        .chain_iterator(block.clone())
        .take_while(|block| !block.payload.is_summary())
        .fold(Default::default(), |mut acc, block| {
            block
                .payload
                .as_ref()
                .as_data()
                .dkg
                .messages
                .iter()
                .for_each(|msg| {
                    let collected_dealings = acc.entry(msg.content.dkg_id.clone()).or_default();
                    assert!(
                        collected_dealings
                            .insert(msg.signature.signer, msg.content.dealing.clone())
                            .is_none(),
                        "Dealings from the same dealers discovered."
                    );
                });
            acc
        })
}

/// Fetch all key ids for which the subnet should hold a key
pub(crate) fn vetkd_key_ids_for_subnet(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    registry_version: RegistryVersion,
) -> Result<Vec<NiDkgMasterPublicKeyId>, DkgPayloadCreationError> {
    let Some(chain_key_config) = registry_client
        .get_chain_key_config(subnet_id, registry_version)
        .map_err(DkgPayloadCreationError::FailedToGetVetKdKeyList)?
    else {
        return Ok(vec![]);
    };

    let keys = chain_key_config
        .key_configs
        .into_iter()
        .filter_map(|config| match config.key_id {
            MasterPublicKeyId::VetKd(key_id) => Some(NiDkgMasterPublicKeyId::VetKd(key_id)),
            _ => None,
        })
        .collect::<Vec<_>>();

    Ok(keys)
}

/// Iterate over all [`NiDkgTag`]s, i.e. high and low threshold as well as all key ids
pub(crate) fn tags_iter(
    vet_keys: &[NiDkgMasterPublicKeyId],
) -> impl Iterator<Item = NiDkgTag> + use<'_> {
    // Currently we assume that we run DKGs for all of these tags.
    const TAGS: [NiDkgTag; 2] = [NiDkgTag::LowThreshold, NiDkgTag::HighThreshold];
    TAGS.iter()
        .cloned()
        .chain(vet_keys.iter().cloned().map(NiDkgTag::HighThresholdForKey))
}

#[cfg(test)]
mod tests {
    use crate::utils::vetkd_key_ids_for_subnet;
    use ic_interfaces_registry::RegistryValue;
    use ic_interfaces_registry_mocks::MockRegistryClient;
    use ic_management_canister_types_private::{
        MasterPublicKeyId, SchnorrAlgorithm, SchnorrKeyId, VetKdCurve, VetKdKeyId,
    };
    use ic_registry_subnet_features::{ChainKeyConfig, KeyConfig};
    use ic_test_utilities_registry::SubnetRecordBuilder;
    use ic_test_utilities_types::ids::subnet_test_id;
    use ic_types::{RegistryVersion, crypto::threshold_sig::ni_dkg::NiDkgMasterPublicKeyId};

    /// Test that `get_enabled_vet_keys` correctly extracts the vet keys that are in the [`SubnetRecord`] of the
    /// subnet.
    #[test]
    fn test_get_vet_keys_for_subnet() {
        let mut registry = MockRegistryClient::new();

        // Create a [`SubnetRecord`] with two VetKD keys and a Schnorr key (which should be ignored)
        let subnet_record = SubnetRecordBuilder::new()
            .with_chain_key_config(ChainKeyConfig {
                key_configs: vec![
                    KeyConfig {
                        key_id: MasterPublicKeyId::Schnorr(SchnorrKeyId {
                            algorithm: SchnorrAlgorithm::Ed25519,
                            name: String::from("schnorr_key_to_ignore"),
                        }),
                        pre_signatures_to_create_in_advance: Some(50),
                        max_queue_size: 50,
                    },
                    KeyConfig {
                        key_id: MasterPublicKeyId::VetKd(VetKdKeyId {
                            curve: VetKdCurve::Bls12_381_G2,
                            name: String::from("first_vet_kd_key"),
                        }),
                        pre_signatures_to_create_in_advance: None,
                        max_queue_size: 50,
                    },
                    KeyConfig {
                        key_id: MasterPublicKeyId::VetKd(VetKdKeyId {
                            curve: VetKdCurve::Bls12_381_G2,
                            name: String::from("second_vet_kd_key"),
                        }),
                        pre_signatures_to_create_in_advance: None,
                        max_queue_size: 50,
                    },
                ],
                signature_request_timeout_ns: None,
                idkg_key_rotation_period_ms: None,
                max_parallel_pre_signature_transcripts_in_creation: None,
            })
            .build();

        registry.expect_get_value().return_const({
            let mut v = Vec::new();
            subnet_record.encode(&mut v).unwrap();
            Ok(Some(v))
        });

        // Check that the two expected keys are contained in the output and no unexpected other keys
        let vetkeys =
            vetkd_key_ids_for_subnet(subnet_test_id(1), &registry, RegistryVersion::default())
                .unwrap();
        assert_eq!(vetkeys.len(), 2);
        assert!(
            matches!(&vetkeys[0], NiDkgMasterPublicKeyId::VetKd(key) if key.name == "first_vet_kd_key")
        );
        assert!(
            matches!(&vetkeys[1], NiDkgMasterPublicKeyId::VetKd(key) if key.name == "second_vet_kd_key")
        );
    }

    // TODO: Unit test for `get_vetkey_public_keys`. (Currently its covered through a system test)
}
