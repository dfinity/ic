use super::{payload_builder, utils, PayloadCreationError};
use ic_consensus_utils::{crypto::ConsensusCrypto, pool_reader::PoolReader};
use ic_interfaces::{
    dkg::DkgPool,
    validation::{ValidationError, ValidationResult},
};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateManager;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    batch::ValidationContext,
    consensus::{
        dkg::{self, Message, Summary},
        Block, BlockPayload,
    },
    crypto::{
        threshold_sig::ni_dkg::errors::verify_dealing_error::DkgVerifyDealingError, CryptoError,
    },
    Height, NodeId, SubnetId,
};
use prometheus::IntCounterVec;

/// Permanent Dkg message validation errors.
// The `Debug` implementation is ignored during the dead code analysis and we are getting a `field
// is never used` warning on this enum even though we are implicitly reading them when we log the
// enum. See https://github.com/rust-lang/rust/issues/88900
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum PermanentPayloadValidationError {
    CryptoError(CryptoError),
    DkgVerifyDealingError(DkgVerifyDealingError),
    MismatchedDkgSummary(dkg::Summary, dkg::Summary),
    MissingDkgConfigForDealing,
    DkgStartHeightDoesNotMatchParentBlock,
    DkgSummaryAtNonStartHeight(Height),
    DkgDealingAtStartHeight(Height),
    InvalidDealer(NodeId),
    DealerAlreadyDealt(NodeId),
}

/// Transient Dkg message validation errors.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum TransientPayloadValidationError {
    PayloadCreationFailed(PayloadCreationError),
    /// Crypto related errors.
    CryptoError(CryptoError),
    DkgVerifyDealingError(DkgVerifyDealingError),
}

/// Dkg errors.
pub(crate) type PayloadValidationError =
    ValidationError<PermanentPayloadValidationError, TransientPayloadValidationError>;

impl From<DkgVerifyDealingError> for PermanentPayloadValidationError {
    fn from(err: DkgVerifyDealingError) -> Self {
        PermanentPayloadValidationError::DkgVerifyDealingError(err)
    }
}

impl From<DkgVerifyDealingError> for TransientPayloadValidationError {
    fn from(err: DkgVerifyDealingError) -> Self {
        TransientPayloadValidationError::DkgVerifyDealingError(err)
    }
}

impl From<CryptoError> for PermanentPayloadValidationError {
    fn from(err: CryptoError) -> Self {
        PermanentPayloadValidationError::CryptoError(err)
    }
}

impl From<CryptoError> for TransientPayloadValidationError {
    fn from(err: CryptoError) -> Self {
        TransientPayloadValidationError::CryptoError(err)
    }
}

impl From<PermanentPayloadValidationError> for PayloadValidationError {
    fn from(err: PermanentPayloadValidationError) -> Self {
        PayloadValidationError::Permanent(err)
    }
}

impl From<TransientPayloadValidationError> for PayloadValidationError {
    fn from(err: TransientPayloadValidationError) -> Self {
        PayloadValidationError::Transient(err)
    }
}

impl From<PayloadCreationError> for PayloadValidationError {
    fn from(err: PayloadCreationError) -> Self {
        PayloadValidationError::Transient(TransientPayloadValidationError::PayloadCreationFailed(
            err,
        ))
    }
}

/// Validates the DKG payload. The parent block is expected to be a valid block.
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_payload(
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
) -> ValidationResult<PayloadValidationError> {
    let last_summary_block = pool_reader
        .dkg_summary_block(&parent)
        // We expect the parent to be valid, so there will be _always_ a DKG start block on the
        // chain.
        .expect("No DKG start block found for the parent block.");
    let last_dkg_summary = &last_summary_block.payload.as_ref().as_summary().dkg;

    let current_height = parent.height.increment();
    let is_dkg_start_height = last_dkg_summary.get_next_start_height() == current_height;

    if payload.is_summary() {
        if !is_dkg_start_height {
            return Err(PermanentPayloadValidationError::DkgSummaryAtNonStartHeight(
                current_height,
            )
            .into());
        }
        let registry_version = pool_reader
            .registry_version(current_height)
            .expect("Couldn't get the registry version.");
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
        if payload.as_summary().dkg != expected_summary {
            return Err(PermanentPayloadValidationError::MismatchedDkgSummary(
                expected_summary,
                payload.as_summary().dkg.clone(),
            )
            .into());
        }
        Ok(())
    } else {
        if is_dkg_start_height {
            return Err(
                PermanentPayloadValidationError::DkgDealingAtStartHeight(current_height).into(),
            );
        }
        validate_dealings_payload(
            crypto,
            pool_reader,
            dkg_pool,
            last_dkg_summary,
            payload.dkg_interval_start_height(),
            &payload.as_data().dealings.messages,
            &parent,
            metrics,
        )
    }
}

// Validates the payload containing dealings.
#[allow(clippy::too_many_arguments)]
fn validate_dealings_payload(
    crypto: &dyn ConsensusCrypto,
    pool_reader: &PoolReader<'_>,
    dkg_pool: &dyn DkgPool,
    last_summary: &Summary,
    start_height: Height,
    messages: &[Message],
    parent: &Block,
    metrics: &IntCounterVec,
) -> ValidationResult<PayloadValidationError> {
    let valid_start_height = parent.payload.as_ref().dkg_interval_start_height();
    if start_height != valid_start_height {
        return Err(PermanentPayloadValidationError::DkgStartHeightDoesNotMatchParentBlock.into());
    }

    // Get a list of all dealers, who created a dealing already, indexed by DKG id.
    let dealers_from_chain = utils::get_dealers_from_chain(pool_reader, parent);

    // Check that all messages have a valid DKG config from the summary and the
    // dealer is valid, then verify each dealing.
    for (message, config) in messages
        .iter()
        .map(|m| (m, last_summary.configs.get(&m.content.dkg_id)))
    {
        metrics.with_label_values(&["total"]).inc();
        // Skip the rest if already present in DKG pool
        if dkg_pool.validated_contains(message) {
            metrics.with_label_values(&["dkg_pool_hit"]).inc();
            continue;
        }

        match config {
            None => {
                return Err(PermanentPayloadValidationError::MissingDkgConfigForDealing.into());
            }
            Some(config) => {
                let dealer_id = message.signature.signer;
                // If the dealer is not in the set of dealers, reject.
                if !config.dealers().get().contains(&dealer_id) {
                    return Err(PermanentPayloadValidationError::InvalidDealer(dealer_id).into());
                }

                // If the dealer created a dealing already, reject.
                if dealers_from_chain
                    .get(&config.dkg_id())
                    .map(|dealers| dealers.contains(&dealer_id))
                    .unwrap_or(false)
                {
                    return Err(
                        PermanentPayloadValidationError::DealerAlreadyDealt(dealer_id).into(),
                    );
                }

                // Verify the signature.
                crypto.verify(message, last_summary.registry_version)?;

                // Verify the dealing.
                ic_interfaces::crypto::NiDkgAlgorithm::verify_dealing(
                    crypto,
                    config,
                    message.signature.signer,
                    &message.content.dealing,
                )?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use ic_consensus_mocks::{dependencies, dependencies_with_subnet_params, Dependencies};
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities_consensus::fake::FakeContentSigner;
    use ic_test_utilities_registry::SubnetRecordBuilder;
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{batch::BatchPayload, consensus::dkg::DealingContent};
    use ic_types::{
        consensus::{dkg, idkg, DataPayload, Payload},
        crypto::threshold_sig::ni_dkg::{NiDkgDealing, NiDkgId, NiDkgTag, NiDkgTargetSubnet},
        RegistryVersion,
    };
    use std::ops::Deref;

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

            assert!(validate_payload(
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
            )
            .is_ok());

            // Advance the blockchain by one block to height `dkg_interval_length`
            pool.advance_round_normal_operation();
            let parent_block = PoolReader::new(&pool).get_finalized_tip();
            // This will be a summary block, since we are at dkg_interval_length height
            let block = Block::from(pool.make_next_block());
            let summary = block.payload.as_ref();

            assert!(validate_payload(
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
            )
            .is_ok());
        })
    }

    #[test]
    fn test_validate_dealings_payload() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies {
                crypto,
                pool,
                dkg_pool,
                ..
            } = dependencies(pool_config, 1);

            let parent = Block::from(pool.make_next_block());
            let last_summary_block = PoolReader::new(&pool).dkg_summary_block(&parent).unwrap();
            let last_summary = last_summary_block.payload.as_ref().as_summary();

            let validate_dealings_payload = |messages, parent| {
                validate_dealings_payload(
                    crypto.as_ref(),
                    &PoolReader::new(&pool),
                    dkg_pool.read().unwrap().deref(),
                    &last_summary.dkg,
                    Height::from(0),
                    messages,
                    parent,
                    &mock_metrics(),
                )
            };

            // Construct a dealing content that passes
            let valid_dealing_content = DealingContent::new(
                NiDkgDealing::dummy_dealing_for_tests(0),
                NiDkgId {
                    start_block_height: Height::from(0),
                    dealer_subnet: subnet_test_id(0),
                    dkg_tag: NiDkgTag::HighThreshold,
                    target_subnet: NiDkgTargetSubnet::Local,
                },
            );
            let messages = vec![Message::fake(
                valid_dealing_content.clone(),
                node_test_id(0),
            )];
            assert!(validate_dealings_payload(&messages, &parent).is_ok());

            // Construct a dealing with invalid `start_block_height` such that no config can
            // be found and `MissingDkgConfigForDealing` is returned
            let wrong_height_dealing_content = DealingContent::new(
                NiDkgDealing::dummy_dealing_for_tests(0),
                NiDkgId {
                    start_block_height: Height::from(1),
                    dealer_subnet: subnet_test_id(0),
                    dkg_tag: NiDkgTag::HighThreshold,
                    target_subnet: NiDkgTargetSubnet::Local,
                },
            );
            let messages = vec![Message::fake(wrong_height_dealing_content, node_test_id(0))];
            let result = validate_dealings_payload(&messages, &parent);
            assert_matches!(
                result,
                Err(PayloadValidationError::Permanent(
                    PermanentPayloadValidationError::MissingDkgConfigForDealing
                ))
            );

            // Use a valid dealing but invalid signer, such that `InvalidDealer` is returned
            let messages = vec![Message::fake(
                valid_dealing_content.clone(),
                node_test_id(1),
            )];
            let result = validate_dealings_payload(&messages, &parent);
            assert_matches!(
                result,
                Err(PayloadValidationError::Permanent(
                    PermanentPayloadValidationError::InvalidDealer(_)
                ))
            );

            // Use valid message and valid signer but add messages to parent block as well.
            // Now the message is already in the blockchain, and `DealerAlreadyDealt` error
            // is returned.
            let messages = vec![Message::fake(valid_dealing_content, node_test_id(0))];
            let payload = Payload::new(
                ic_types::crypto::crypto_hash,
                BlockPayload::Data(DataPayload {
                    batch: BatchPayload::default(),
                    dealings: dkg::Dealings::new(Height::from(0), messages.clone()),
                    ecdsa: idkg::Payload::default(),
                }),
            );
            let mut parent = Block::from(pool.make_next_block());
            parent.payload = payload;
            let result = validate_dealings_payload(&messages, &parent);
            assert_matches!(
                result,
                Err(PayloadValidationError::Permanent(
                    PermanentPayloadValidationError::DealerAlreadyDealt(_)
                ))
            );
        })
    }

    fn mock_metrics() -> IntCounterVec {
        MetricsRegistry::new().int_counter_vec(
            "consensus_dkg_validator",
            "DKG validator counter",
            &["type"],
        )
    }
}
