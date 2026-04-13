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
use std::collections::{BTreeMap, BTreeSet, HashSet};

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
    let mut dealers = HashSet::new();
    for block in pool_reader
        .chain_iterator(block.clone())
        .take_while(|block| !block.payload.is_summary())
    {
        let payload = &block.payload.as_ref().as_data().dkg;
        for message in payload.messages.iter() {
            let unique = dealers.insert((message.content.dkg_id.clone(), message.signature.signer));
            assert!(unique, "Dealings from the same dealers discovered.");
        }
    }
    dealers
}

/// Starts with the given block and creates a nested mapping from the DKG Id to
/// the node Id to the dealing. This function panics if multiple dealings
/// from one dealer are discovered, hence, we assume a valid block chain.
/// It also excludes dealings for ni_dkg ids which already have a transcript in the
/// blockchain, and returns these exlcuded ni_dkg ids.
pub(super) fn get_dkg_dealings(
    pool_reader: &PoolReader<'_>,
    block: &Block,
) -> (
    BTreeMap<NiDkgId, BTreeMap<NodeId, NiDkgDealing>>,
    BTreeSet<NiDkgId>,
) {
    let mut dealings: BTreeMap<NiDkgId, BTreeMap<NodeId, NiDkgDealing>> = BTreeMap::new();
    let mut excluded: BTreeSet<NiDkgId> = BTreeSet::new();

    for block in pool_reader
        .chain_iterator(block.clone())
        .take_while(|block| !block.payload.is_summary())
    {
        let payload = &block.payload.as_ref().as_data().dkg;

        for (dkg_id, _, _) in payload.transcripts_for_remote_subnets.iter() {
            // Add the finished DKG to excluded list
            excluded.insert(dkg_id.clone());
            // Remove already selected dealings
            dealings.remove(dkg_id);
        }

        for message in payload.messages.iter() {
            if excluded.contains(&message.content.dkg_id) {
                continue;
            }

            let old_dealing = dealings
                .entry(message.content.dkg_id.clone())
                .or_default()
                .insert(message.signature.signer, message.content.dealing.clone());

            assert!(
                old_dealing.is_none(),
                "Dealings from the same dealers discovered."
            );
        }
    }

    (dealings, excluded)
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
    use super::{get_dealers_from_chain, get_dkg_dealings};
    use crate::test_utils::create_dealing;
    use crate::utils::vetkd_key_ids_for_subnet;
    use ic_consensus_mocks::{Dependencies, dependencies_with_subnet_params};
    use ic_consensus_utils::pool_reader::PoolReader;
    use ic_crypto_test_utils_ni_dkg::dummy_transcript_for_tests;
    use ic_interfaces_registry::RegistryValue;
    use ic_interfaces_registry_mocks::MockRegistryClient;
    use ic_management_canister_types_private::{
        MasterPublicKeyId, SchnorrAlgorithm, SchnorrKeyId, VetKdCurve, VetKdKeyId,
    };
    use ic_registry_subnet_features::{ChainKeyConfig, KeyConfig};
    use ic_test_artifact_pool::consensus_pool::TestConsensusPool;
    use ic_test_utilities_consensus::fake::FakeContentSigner;
    use ic_test_utilities_registry::SubnetRecordBuilder;
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{
        Height, RegistryVersion,
        batch::BatchPayload,
        consensus::{
            Block, BlockPayload, BlockProposal, DataPayload, Payload, Rank, dkg::DkgDataPayload,
            idkg,
        },
        crypto::{
            crypto_hash,
            threshold_sig::ni_dkg::{NiDkgId, NiDkgMasterPublicKeyId, NiDkgTag, NiDkgTargetSubnet},
        },
        messages::CallbackId,
    };

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

    fn dkg_id(subnet_id: ic_types::SubnetId, tag: NiDkgTag) -> NiDkgId {
        NiDkgId {
            start_block_height: Height::from(0),
            dealer_subnet: subnet_id,
            target_subnet: NiDkgTargetSubnet::Local,
            dkg_tag: tag,
        }
    }

    fn make_data_block(
        pool: &TestConsensusPool,
        parent: &Block,
        dkg_payload: DkgDataPayload,
    ) -> BlockProposal {
        let block = Block::new(
            crypto_hash(parent),
            Payload::new(
                crypto_hash,
                BlockPayload::Data(DataPayload {
                    batch: BatchPayload::default(),
                    dkg: dkg_payload,
                    idkg: idkg::Payload::default(),
                }),
            ),
            parent.height.increment(),
            Rank(0),
            parent.context.clone(),
        );
        BlockProposal::fake(
            block,
            pool.get_block_maker_by_rank(parent.height.increment(), Some(Rank(0))),
        )
    }

    #[test]
    fn test_get_dkg_dealings_included_and_excluded_by_transcript() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let subnet_id = subnet_test_id(1);
            let nodes: Vec<_> = (0..4).map(node_test_id).collect();
            let dkg_interval_len = 10;
            let Dependencies { mut pool, .. } = dependencies_with_subnet_params(
                pool_config,
                subnet_id,
                vec![(
                    1,
                    SubnetRecordBuilder::from(&nodes)
                        .with_dkg_interval_length(dkg_interval_len)
                        .build(),
                )],
            );

            pool.advance_round_normal_operation_n(dkg_interval_len);
            let pool_reader = PoolReader::new(&pool);
            let tip = pool_reader.get_finalized_tip();

            // DKG id that has a transcript in this block -> its dealings should be excluded.
            let dkg_id_with_transcript = dkg_id(subnet_id, NiDkgTag::HighThreshold);
            // DKG id with no transcript -> its dealings should be included.
            let dkg_id_without_transcript = dkg_id(subnet_id, NiDkgTag::LowThreshold);

            // Dealings per dealer (0..4) for each DKG id.
            let dealings_excluded: Vec<_> = (0..4)
                .map(|i| create_dealing(i, dkg_id_with_transcript.clone()))
                .collect();
            let dealings_included: Vec<_> = (0..4)
                .map(|i| create_dealing(i, dkg_id_without_transcript.clone()))
                .collect();

            let start_height = tip.payload.as_ref().as_data().dkg.start_height;

            // Parent block: dealer 2 for both DKG ids.
            let parent_proposal = make_data_block(
                &pool,
                &tip,
                DkgDataPayload {
                    start_height,
                    messages: vec![dealings_excluded[2].clone(), dealings_included[2].clone()],
                    transcripts_for_remote_subnets: vec![],
                },
            );
            pool.advance_round_with_block(&parent_proposal);
            let parent_block = parent_proposal.content.as_ref().clone();

            // Middle block: transcript for dkg_id_with_transcript, dealers 0, 1 for both DKG ids.
            let middle_proposal = make_data_block(
                &pool,
                &parent_block,
                DkgDataPayload {
                    start_height,
                    messages: vec![
                        dealings_excluded[0].clone(),
                        dealings_excluded[1].clone(),
                        dealings_included[0].clone(),
                        dealings_included[1].clone(),
                    ],
                    transcripts_for_remote_subnets: vec![(
                        dkg_id_with_transcript.clone(),
                        CallbackId::from(0),
                        Ok(dummy_transcript_for_tests()),
                    )],
                },
            );
            pool.advance_round_with_block(&middle_proposal);
            let middle_block = middle_proposal.content.as_ref().clone();

            let pool_reader = PoolReader::new(&pool);

            // Child block (used for get_dkg_dealings): dealer 3 for both DKG ids.
            let child_proposal = make_data_block(
                &pool,
                &middle_block,
                DkgDataPayload {
                    start_height,
                    messages: vec![dealings_excluded[3].clone(), dealings_included[3].clone()],
                    transcripts_for_remote_subnets: vec![],
                },
            );
            let child_block = child_proposal.content.as_ref().clone();

            let (dealings, excluded) = get_dkg_dealings(&pool_reader, &child_block);

            // Excluded: only the DKG id that has a transcript (in the middle block).
            assert_eq!(excluded.len(), 1);
            assert!(excluded.contains(&dkg_id_with_transcript));

            // Dealings for the transcript DKG id must not appear in the result (neither from
            // child, middle nor parent).
            assert_eq!(dealings.len(), 1);
            assert!(!dealings.contains_key(&dkg_id_with_transcript));

            // Dealings for the other DKG id must be included from all three blocks
            // (dealers 0, 1 from middle; dealer 2 from parent; dealer 3 from child).
            let included = dealings.get(&dkg_id_without_transcript).unwrap();
            assert_eq!(included.len(), 4);

            // get_dealers_from_chain returns all dealers from the chain (no transcript exclusion).
            let dealers = get_dealers_from_chain(&pool_reader, &child_block);
            assert_eq!(dealers.len(), 8);

            for i in 0..4 {
                assert!(included.contains_key(&node_test_id(i)));
                assert!(dealers.contains(&(dkg_id_with_transcript.clone(), node_test_id(i))));
                assert!(dealers.contains(&(dkg_id_without_transcript.clone(), node_test_id(i))));
            }
        });
    }

    // TODO: Unit test for `get_vetkey_public_keys`. (Currently its covered through a system test)
}
