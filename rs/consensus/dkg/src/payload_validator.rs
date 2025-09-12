use crate::{crypto_validate_dealing, payload_builder, utils};
use ic_consensus_utils::{crypto::ConsensusCrypto, pool_reader::PoolReader};
use ic_interfaces::{
    dkg::{DkgPayloadValidationError, DkgPool},
    validation::ValidationResult,
};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateManager;
use ic_logger::{ReplicaLogger, warn};
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    SubnetId,
    batch::ValidationContext,
    consensus::{
        Block, BlockPayload,
        dkg::{DkgDataPayload, DkgPayloadValidationFailure, DkgSummary, InvalidDkgPayloadReason},
    },
};
use prometheus::IntCounterVec;
use std::collections::HashSet;

/// Validates the DKG payload. The parent block is expected to be a valid block.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::result_large_err)]
pub fn validate_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    crypto: &dyn ConsensusCrypto,
    pool_reader: &PoolReader<'_>,
    dkg_pool: &dyn DkgPool,
    parent: Block,
    payload: &BlockPayload,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    validation_context: &ValidationContext,
    metrics: &IntCounterVec,
    log: &ReplicaLogger,
) -> ValidationResult<DkgPayloadValidationError> {
    let current_height = parent.height.increment();
    let registry_version = pool_reader
        .registry_version(current_height)
        .ok_or(DkgPayloadValidationFailure::FailedToGetRegistryVersion)?;

    let last_summary_block = pool_reader
        .dkg_summary_block(&parent)
        // We expect the parent to be valid, so there will be _always_ a DKG start block on the
        // chain.
        .expect("No DKG start block found for the parent block.");
    let last_dkg_summary = &last_summary_block.payload.as_ref().as_summary().dkg;

    let is_dkg_start_height = last_dkg_summary.get_next_start_height() == current_height;

    match payload {
        BlockPayload::Summary(summary_payload) => {
            if !is_dkg_start_height {
                return Err(
                    InvalidDkgPayloadReason::DkgSummaryAtNonStartHeight(current_height).into(),
                );
            }
            let expected_summary = payload_builder::create_summary_payload(
                subnet_id,
                registry_client,
                crypto,
                pool_reader,
                last_dkg_summary,
                &parent,
                registry_version,
                state_manager,
                validation_context,
                ic_logger::replica_logger::no_op_logger(),
            )?;
            if summary_payload.dkg != expected_summary {
                return Err(InvalidDkgPayloadReason::MismatchedDkgSummary(
                    expected_summary,
                    summary_payload.dkg.clone(),
                )
                .into());
            }
            for (tag, transcript) in summary_payload.dkg.current_transcripts() {
                if *tag != transcript.dkg_id.dkg_tag {
                    metrics.with_label_values(&["tag_mismatch"]).inc();
                    warn!(
                        log,
                        "Current transcript key {:?} doesn't match transcript tag {:?}!",
                        tag,
                        transcript.dkg_id.dkg_tag
                    );
                }
            }
            for (tag, transcript) in summary_payload.dkg.next_transcripts() {
                if *tag != transcript.dkg_id.dkg_tag {
                    metrics.with_label_values(&["tag_mismatch"]).inc();
                    warn!(
                        log,
                        "Next transcript key {:?} doesn't match transcript tag {:?}!",
                        tag,
                        transcript.dkg_id.dkg_tag
                    );
                }
            }
            Ok(())
        }
        BlockPayload::Data(data_payload) => {
            if is_dkg_start_height {
                return Err(
                    InvalidDkgPayloadReason::DkgDealingAtStartHeight(current_height).into(),
                );
            }
            let max_dealings_per_block = registry_client
                .get_dkg_dealings_per_block(subnet_id, registry_version)
                .map_err(DkgPayloadValidationFailure::FailedToGetMaxDealingsPerBlock)?
                .unwrap_or_else(|| {
                    panic!(
                        "No subnet record found for registry version={registry_version} and subnet_id={subnet_id}"
                    )
                });

            validate_dealings_payload(
                crypto,
                pool_reader,
                dkg_pool,
                last_dkg_summary,
                &data_payload.dkg,
                max_dealings_per_block,
                &parent,
                metrics,
            )
        }
    }
}

// Validates the payload containing dealings.
#[allow(clippy::result_large_err)]
fn validate_dealings_payload(
    crypto: &dyn ConsensusCrypto,
    pool_reader: &PoolReader<'_>,
    dkg_pool: &dyn DkgPool,
    last_summary: &DkgSummary,
    dealings: &DkgDataPayload,
    max_dealings_per_payload: usize,
    parent: &Block,
    metrics: &IntCounterVec,
) -> ValidationResult<DkgPayloadValidationError> {
    if dealings.start_height != parent.payload.as_ref().dkg_interval_start_height() {
        return Err(InvalidDkgPayloadReason::DkgStartHeightDoesNotMatchParentBlock.into());
    }

    if dealings.messages.len() > max_dealings_per_payload {
        return Err(InvalidDkgPayloadReason::TooManyDealings {
            limit: max_dealings_per_payload,
            actual: dealings.messages.len(),
        }
        .into());
    }

    // Get a list of all dealers, who created a dealing already, indexed by DKG id.
    let dealers_from_chain = utils::get_dealers_from_chain(pool_reader, parent);

    // Get a list of all dealers in the payload.
    let dealers_from_payload: HashSet<_> = dealings
        .messages
        .iter()
        .map(|message| (message.content.dkg_id.clone(), message.signature.signer))
        .collect();

    if dealers_from_payload.len() != dealings.messages.len() {
        return Err(InvalidDkgPayloadReason::DuplicateDealers.into());
    }

    if let Some(&(_, dealer_id)) = dealers_from_payload
        .intersection(&dealers_from_chain)
        .next()
    {
        return Err(InvalidDkgPayloadReason::DealerAlreadyDealt(dealer_id).into());
    }

    // Check that all messages have a valid DKG config from the summary and the
    // dealer is valid, then verify each dealing.
    for message in &dealings.messages {
        metrics.with_label_values(&["total"]).inc();

        // Skip the rest if already present in DKG pool
        if dkg_pool.validated_contains(message) {
            metrics.with_label_values(&["dkg_pool_hit"]).inc();
            continue;
        }

        let Some(config) = last_summary.configs.get(&message.content.dkg_id) else {
            return Err(InvalidDkgPayloadReason::MissingDkgConfigForDealing.into());
        };

        // Verify the signature and dealing.
        crypto_validate_dealing(crypto, config, message)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DkgImpl, DkgKeyManager};
    use ic_artifact_pool::dkg_pool::DkgPoolImpl;
    use ic_consensus_mocks::{Dependencies, dependencies_with_subnet_params};
    use ic_crypto_temp_crypto::{NodeKeysToGenerate, TempCryptoComponent};
    use ic_interfaces::{
        consensus_pool::ConsensusPool,
        dkg::ChangeAction,
        p2p::consensus::{MutablePool, PoolMutationsProducer},
    };
    use ic_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_registry_keys::make_subnet_record_key;
    use ic_test_utilities_consensus::fake::FakeContentSigner;
    use ic_test_utilities_registry::SubnetRecordBuilder;
    use ic_test_utilities_types::ids::{
        NODE_1, NODE_2, NODE_3, SUBNET_1, SUBNET_2, node_test_id, subnet_test_id,
    };
    use ic_types::{
        Height, NodeId, RegistryVersion,
        batch::BatchPayload,
        consensus::{
            DataPayload, Payload,
            dkg::{DealingContent, Message},
            idkg,
        },
        crypto::threshold_sig::ni_dkg::{NiDkgDealing, NiDkgId, NiDkgTag, NiDkgTargetSubnet},
        time::UNIX_EPOCH,
    };
    use std::{
        ops::Deref,
        sync::{Arc, Mutex},
    };

    /// This tests the `validate_payload` function.
    /// It sets up a subnet with 4 nodes and a dkg interval of 4.
    /// Then, it calls `validate_payload` on the 4th (batch) and 5th (summary)
    /// block, expecting both to succeed.
    #[test]
    fn test_validate_payload() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let dkg_interval_length = 4;
            let committee = (0..4).map(node_test_id).collect::<Vec<_>>();
            let Dependencies {
                crypto,
                mut pool,
                registry,
                state_manager,
                dkg_pool,
                ..
            } = dependencies_with_subnet_params(
                pool_config,
                subnet_test_id(0),
                vec![(
                    5,
                    SubnetRecordBuilder::from(&committee)
                        .with_dkg_interval_length(dkg_interval_length)
                        .build(),
                )],
            );

            let context = ValidationContext {
                registry_version: RegistryVersion::from(5),
                certified_height: Height::from(0),
                time: ic_types::time::UNIX_EPOCH,
            };

            // Advance the blockchain to height `dkg_interval_length - 1`
            pool.advance_round_normal_operation_n(dkg_interval_length - 1);
            let parent_block = PoolReader::new(&pool).get_finalized_tip();
            // This will be a regular block, since we are not at dkg_interval_length height
            let block = Block::from(pool.make_next_block());
            let block_payload = block.payload.as_ref();

            assert!(
                validate_payload(
                    subnet_test_id(0),
                    registry.as_ref(),
                    crypto.as_ref(),
                    &PoolReader::new(&pool),
                    dkg_pool.read().unwrap().deref(),
                    parent_block,
                    block_payload,
                    state_manager.as_ref(),
                    &context,
                    &mock_metrics(),
                    &no_op_logger(),
                )
                .is_ok()
            );

            // Advance the blockchain by one block to height `dkg_interval_length`
            pool.advance_round_normal_operation();
            let parent_block = PoolReader::new(&pool).get_finalized_tip();
            // This will be a summary block, since we are at dkg_interval_length height
            let block = Block::from(pool.make_next_block());
            let summary = block.payload.as_ref();

            assert!(
                validate_payload(
                    subnet_test_id(0),
                    registry.as_ref(),
                    crypto.as_ref(),
                    &PoolReader::new(&pool),
                    dkg_pool.read().unwrap().deref(),
                    parent_block,
                    summary,
                    state_manager.as_ref(),
                    &context,
                    &mock_metrics(),
                    &no_op_logger(),
                )
                .is_ok()
            );
        })
    }

    #[test]
    fn validate_dealings_payload_when_valid_passes_test() {
        assert_eq!(
            validate_payload_test_case(
                /*dealings_to_validate=*/
                vec![
                    fake_dkg_message_with_dkg_tag(SUBNET_1, NODE_1, NiDkgTag::LowThreshold),
                    fake_dkg_message_with_dkg_tag(SUBNET_1, NODE_1, NiDkgTag::HighThreshold),
                    fake_dkg_message_with_dkg_tag(SUBNET_1, NODE_2, NiDkgTag::HighThreshold),
                ],
                /*parents_dealings=*/
                vec![
                    fake_dkg_message_with_dkg_tag(SUBNET_1, NODE_2, NiDkgTag::LowThreshold),
                    fake_dkg_message_with_dkg_tag(SUBNET_1, NODE_3, NiDkgTag::LowThreshold),
                    fake_dkg_message_with_dkg_tag(SUBNET_1, NODE_3, NiDkgTag::HighThreshold),
                ],
                /*max_dealings_per_block=*/ 3,
                SUBNET_1,
                /*committee=*/ &[NODE_1, NODE_2, NODE_3],
            ),
            Ok(())
        );
    }

    #[test]
    fn validate_dealings_payload_when_wrong_dkg_id_fails_test() {
        // The dkg dealing will have a wrong id, because we are using a wrong subnet id.
        assert_eq!(
            validate_payload_test_case(
                /*dealings_to_validate=*/ vec![fake_dkg_message(SUBNET_2, NODE_1)],
                /*parents_dealings=*/ vec![],
                /*max_dealings_per_block=*/ 1,
                SUBNET_1,
                /*committee=*/ &[NODE_1],
            ),
            Err(DkgPayloadValidationError::InvalidArtifact(
                InvalidDkgPayloadReason::MissingDkgConfigForDealing
            ))
        );
    }

    #[test]
    fn validate_dealings_payload_when_invalid_dealer_fails_test() {
        assert_eq!(
            validate_payload_test_case(
                /*dealings_to_validate=*/ vec![fake_dkg_message(SUBNET_1, NODE_2)],
                /*parents_dealings=*/ vec![],
                /*max_dealings_per_block=*/ 1,
                SUBNET_1,
                /*committee=*/ &[NODE_1],
            ),
            Err(DkgPayloadValidationError::InvalidArtifact(
                InvalidDkgPayloadReason::InvalidDealer(NODE_2)
            ))
        );
    }

    #[test]
    fn validate_dealings_payload_when_existing_dealer_fails_test() {
        assert_eq!(
            validate_payload_test_case(
                /*dealings_to_validate=*/
                vec![
                    fake_dkg_message(SUBNET_1, NODE_1),
                    fake_dkg_message(SUBNET_1, NODE_2)
                ],
                /*parents_dealings=*/
                vec![
                    fake_dkg_message(SUBNET_1, NODE_2),
                    fake_dkg_message(SUBNET_1, NODE_3)
                ],
                /*max_dealings_per_block=*/ 2,
                SUBNET_1,
                /*committee=*/ &[NODE_1, NODE_2, NODE_3],
            ),
            Err(DkgPayloadValidationError::InvalidArtifact(
                InvalidDkgPayloadReason::DealerAlreadyDealt(NODE_2)
            ))
        );
    }

    #[test]
    fn validate_dealings_payload_when_duplicate_dealer_fails_test() {
        assert_eq!(
            validate_payload_test_case(
                /*dealings_to_validate=*/
                vec![
                    fake_dkg_message(SUBNET_1, NODE_1),
                    fake_dkg_message(SUBNET_1, NODE_1)
                ],
                /*parents_dealings=*/
                vec![],
                /*max_dealings_per_block=*/ 2,
                SUBNET_1,
                /*committee=*/ &[NODE_1, NODE_2, NODE_3],
            ),
            Err(DkgPayloadValidationError::InvalidArtifact(
                InvalidDkgPayloadReason::DuplicateDealers
            ))
        );
    }

    #[test]
    fn validate_dealings_payload_when_too_many_dealings_fails_test() {
        let messages = vec![
            fake_dkg_message(SUBNET_1, NODE_1),
            fake_dkg_message(SUBNET_1, NODE_2),
            fake_dkg_message(SUBNET_1, NODE_3),
        ];

        assert_eq!(
            validate_payload_test_case(
                messages,
                /*parents_dealings=*/ vec![],
                /*max_dealings_per_block=*/ 2,
                SUBNET_1,
                /*committee=*/ &[NODE_1, NODE_2, NODE_3],
            ),
            Err(DkgPayloadValidationError::InvalidArtifact(
                InvalidDkgPayloadReason::TooManyDealings {
                    limit: 2,
                    actual: 3
                }
            ))
        );
    }

    /// Configures all the dependencies and calls [`validate_payload`] with
    /// `dealings_to_validate` as an argument.
    #[allow(clippy::result_large_err)]
    fn validate_payload_test_case(
        dealings_to_validate: Vec<Message>,
        parent_dealings: Vec<Message>,
        max_dealings_per_payload: u64,
        subnet_id: SubnetId,
        committee: &[NodeId],
    ) -> ValidationResult<DkgPayloadValidationError> {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let registry_version = 1;

            let Dependencies {
                crypto,
                pool,
                dkg_pool,
                registry,
                state_manager,
                ..
            } = dependencies_with_subnet_params(
                pool_config.clone(),
                subnet_id,
                vec![(
                    registry_version,
                    SubnetRecordBuilder::from(committee)
                        .with_dkg_dealings_per_block(max_dealings_per_payload)
                        .build(),
                )],
            );

            let mut parent = Block::from(pool.make_next_block());
            parent.payload = Payload::new(
                ic_types::crypto::crypto_hash,
                BlockPayload::Data(DataPayload {
                    batch: BatchPayload::default(),
                    dkg: DkgDataPayload::new(Height::from(0), parent_dealings),
                    idkg: idkg::Payload::default(),
                }),
            );

            let context = ValidationContext {
                registry_version: RegistryVersion::from(registry_version),
                certified_height: Height::from(0),
                time: ic_types::time::UNIX_EPOCH,
            };

            let block_payload = BlockPayload::Data(DataPayload {
                batch: BatchPayload::default(),
                dkg: DkgDataPayload::new(Height::from(0), dealings_to_validate),
                idkg: idkg::Payload::default(),
            });

            validate_payload(
                subnet_id,
                registry.as_ref(),
                crypto.as_ref(),
                &PoolReader::new(&pool),
                dkg_pool.read().unwrap().deref(),
                parent.clone(),
                &block_payload,
                state_manager.as_ref(),
                &context,
                &mock_metrics(),
                &no_op_logger(),
            )
        })
    }

    fn fake_dkg_message(subnet_id: SubnetId, dealer_id: NodeId) -> Message {
        fake_dkg_message_with_dkg_tag(subnet_id, dealer_id, NiDkgTag::HighThreshold)
    }

    fn fake_dkg_message_with_dkg_tag(
        subnet_id: SubnetId,
        dealer_id: NodeId,
        dkg_tag: NiDkgTag,
    ) -> Message {
        let content = DealingContent::new(
            NiDkgDealing::dummy_dealing_for_tests(0),
            NiDkgId {
                start_block_height: Height::from(0),
                dealer_subnet: subnet_id,
                target_subnet: NiDkgTargetSubnet::Local,
                dkg_tag,
            },
        );

        Message::fake(content, dealer_id)
    }

    fn mock_metrics() -> IntCounterVec {
        MetricsRegistry::new().int_counter_vec(
            "consensus_dkg_validator",
            "DKG validator counter",
            &["type"],
        )
    }

    /// Test that dealings are created and validated using the same registry version
    #[test]
    fn test_validate_payload_dealings_registry_version() {
        let registry_version_start = RegistryVersion::new(1);
        let registry_version_active = RegistryVersion::new(5);
        // The node is registered at registry verions 5, at which point its node keys exist.
        let node_id = node_test_id(1);
        let subnet_id = subnet_test_id(0);
        let crypto = TempCryptoComponent::builder()
            .with_node_id(node_id)
            .with_keys_in_registry_version(NodeKeysToGenerate::all(), registry_version_active)
            .build_arc();
        let committee = vec![node_id];
        let dkg_interval_length = 9;

        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies {
                mut pool,
                registry,
                state_manager,
                registry_data_provider,
                ..
            } = dependencies_with_subnet_params(
                pool_config,
                subnet_id,
                vec![(
                    registry_version_start.get(),
                    SubnetRecordBuilder::from(&committee)
                        .with_dkg_interval_length(dkg_interval_length)
                        .build(),
                )],
            );

            // Both summary registry versions should be 1 initially
            let summary_block = pool.as_cache().summary_block();
            assert_eq!(summary_block.height.get(), 0);
            assert_eq!(
                summary_block.context.registry_version,
                registry_version_start
            );
            assert_eq!(
                summary_block
                    .payload
                    .as_ref()
                    .as_summary()
                    .dkg
                    .registry_version,
                registry_version_start
            );

            // Bump the registry version (by creating a random subnet)
            registry_data_provider
                .add(
                    &make_subnet_record_key(subnet_test_id(5)),
                    registry_version_active,
                    Some(ic_types::subnet_id_into_protobuf(subnet_test_id(5))),
                )
                .unwrap();
            registry.update_to_latest_version();

            // Advance pool by one DKG interval
            pool.advance_round_normal_operation_n(dkg_interval_length + 1);

            // The context summary registry version should now be the active version
            let summary_block = pool.as_cache().summary_block();
            assert_eq!(summary_block.height.get(), 10);
            assert_eq!(
                summary_block.context.registry_version,
                registry_version_active
            );
            let dkg_summary = &summary_block.payload.as_ref().as_summary().dkg;
            assert_eq!(dkg_summary.registry_version, registry_version_start);

            // Create the DKG components
            let key_manager = DkgKeyManager::new(
                MetricsRegistry::new(),
                crypto.clone(),
                no_op_logger(),
                &PoolReader::new(&pool),
            );
            let key_manager = Arc::new(Mutex::new(key_manager));
            let dkg_impl = DkgImpl::new(
                node_id,
                crypto.clone(),
                pool.get_cache(),
                key_manager,
                MetricsRegistry::new(),
                no_op_logger(),
            );
            let mut dkg_pool = DkgPoolImpl::new(MetricsRegistry::new(), no_op_logger());
            // Update start height
            let start_height = Height::new(10);
            dkg_pool.apply(vec![ChangeAction::Purge(start_height)]);

            // It should be possible to create a dealing
            let result = dkg_impl.on_state_change(&dkg_pool);
            let first = result.first().unwrap();
            let ChangeAction::AddToValidated(dealing) = first else {
                panic!("Unexpected change action: {first:?}")
            };

            // It should be possible to validate the dealing
            let result = dkg_impl.validate_dealings_for_dealer(
                &dkg_pool,
                &dkg_summary.configs,
                start_height,
                vec![dealing],
            );
            let first = result.first().unwrap();
            let ChangeAction::MoveToValidated(dealing_validated) = first else {
                panic!("Unexpected change action: {first:?}")
            };
            assert_eq!(dealing, dealing_validated);

            // It should be possible to validate the dealing as part of a block payload
            let parent = Block::from(pool.make_next_block());
            let context = ValidationContext {
                registry_version: registry_version_active,
                certified_height: Height::from(0),
                time: UNIX_EPOCH,
            };
            let block_payload = BlockPayload::Data(DataPayload {
                batch: BatchPayload::default(),
                dkg: DkgDataPayload::new(start_height, vec![dealing.clone()]),
                idkg: idkg::Payload::default(),
            });

            let result = validate_payload(
                subnet_id,
                registry.as_ref(),
                crypto.as_ref(),
                &PoolReader::new(&pool),
                &dkg_pool,
                parent.clone(),
                &block_payload,
                state_manager.as_ref(),
                &context,
                &mock_metrics(),
                &no_op_logger(),
            );
            assert!(result.is_ok());

            // Add the dealing to the validated pool
            dkg_pool.apply(vec![ChangeAction::AddToValidated(dealing.clone())]);

            // It should be possible to validate the dealing as part of a block payload,
            // even if the dealing is already part of the validated pool
            let result = validate_payload(
                subnet_id,
                registry.as_ref(),
                crypto.as_ref(),
                &PoolReader::new(&pool),
                &dkg_pool,
                parent,
                &block_payload,
                state_manager.as_ref(),
                &context,
                &mock_metrics(),
                &no_op_logger(),
            );
            assert!(result.is_ok());
        })
    }
}
