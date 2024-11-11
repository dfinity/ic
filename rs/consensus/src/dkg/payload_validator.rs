use std::collections::HashSet;

use super::{payload_builder, utils, PayloadCreationError};
use ic_consensus_utils::{crypto::ConsensusCrypto, pool_reader::PoolReader};
use ic_interfaces::{
    dkg::DkgPool,
    validation::{ValidationError, ValidationResult},
};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateManager;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    batch::ValidationContext,
    consensus::{
        dkg::{self, Dealings, Summary},
        Block, BlockPayload,
    },
    crypto::{
        threshold_sig::ni_dkg::errors::verify_dealing_error::DkgVerifyDealingError, CryptoError,
    },
    registry::RegistryClientError,
    Height, NodeId, SubnetId,
};
use prometheus::IntCounterVec;

/// Reasons for why a dkg payload might be invalid.
// The `Debug` implementation is ignored during the dead code analysis and we are getting a `field
// is never used` warning on this enum even though we are implicitly reading them when we log the
// enum. See https://github.com/rust-lang/rust/issues/88900
#[allow(dead_code)]
#[derive(PartialEq, Debug)]
pub(crate) enum InvalidDkgPayloadReason {
    CryptoError(CryptoError),
    DkgVerifyDealingError(DkgVerifyDealingError),
    MismatchedDkgSummary(dkg::Summary, dkg::Summary),
    MissingDkgConfigForDealing,
    DkgStartHeightDoesNotMatchParentBlock,
    DkgSummaryAtNonStartHeight(Height),
    DkgDealingAtStartHeight(Height),
    InvalidDealer(NodeId),
    DealerAlreadyDealt(NodeId),
    /// There are multiple dealings from the same dealer in the payload.
    DuplicateDealers,
    /// The number of dealings in the payload exceeds the maximum allowed number of dealings.
    TooManyDealings {
        limit: usize,
        actual: usize,
    },
}

/// Possible failures which could occur while validating a dkg payload. They don't imply that the
/// payload is invalid.
#[allow(dead_code)]
#[derive(PartialEq, Debug)]
pub(crate) enum DkgPayloadValidationFailure {
    PayloadCreationFailed(PayloadCreationError),
    /// Crypto related errors.
    CryptoError(CryptoError),
    DkgVerifyDealingError(DkgVerifyDealingError),
    FailedToGetMaxDealingsPerBlock(RegistryClientError),
    FailedToGetRegistryVersion,
}

/// Dkg errors.
pub(crate) type PayloadValidationError =
    ValidationError<InvalidDkgPayloadReason, DkgPayloadValidationFailure>;

impl From<DkgVerifyDealingError> for InvalidDkgPayloadReason {
    fn from(err: DkgVerifyDealingError) -> Self {
        InvalidDkgPayloadReason::DkgVerifyDealingError(err)
    }
}

impl From<DkgVerifyDealingError> for DkgPayloadValidationFailure {
    fn from(err: DkgVerifyDealingError) -> Self {
        DkgPayloadValidationFailure::DkgVerifyDealingError(err)
    }
}

impl From<CryptoError> for InvalidDkgPayloadReason {
    fn from(err: CryptoError) -> Self {
        InvalidDkgPayloadReason::CryptoError(err)
    }
}

impl From<CryptoError> for DkgPayloadValidationFailure {
    fn from(err: CryptoError) -> Self {
        DkgPayloadValidationFailure::CryptoError(err)
    }
}

impl From<InvalidDkgPayloadReason> for PayloadValidationError {
    fn from(err: InvalidDkgPayloadReason) -> Self {
        PayloadValidationError::InvalidArtifact(err)
    }
}

impl From<DkgPayloadValidationFailure> for PayloadValidationError {
    fn from(err: DkgPayloadValidationFailure) -> Self {
        PayloadValidationError::ValidationFailed(err)
    }
}

impl From<PayloadCreationError> for PayloadValidationError {
    fn from(err: PayloadCreationError) -> Self {
        PayloadValidationError::ValidationFailed(
            DkgPayloadValidationFailure::PayloadCreationFailed(err),
        )
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
                        "No subnet record found for registry version={} and subnet_id={}",
                        registry_version, subnet_id
                    )
                });

            validate_dealings_payload(
                crypto,
                pool_reader,
                dkg_pool,
                last_dkg_summary,
                &data_payload.dealings,
                max_dealings_per_block,
                &parent,
                metrics,
            )
        }
    }
}

// Validates the payload containing dealings.
fn validate_dealings_payload(
    crypto: &dyn ConsensusCrypto,
    pool_reader: &PoolReader<'_>,
    dkg_pool: &dyn DkgPool,
    last_summary: &Summary,
    dealings: &Dealings,
    max_dealings_per_payload: usize,
    parent: &Block,
    metrics: &IntCounterVec,
) -> ValidationResult<PayloadValidationError> {
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
        .map(|message| (message.content.dkg_id, message.signature.signer))
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

        let dealer_id = message.signature.signer;
        // If the dealer is not in the set of dealers, reject.
        if !config.dealers().get().contains(&dealer_id) {
            return Err(InvalidDkgPayloadReason::InvalidDealer(dealer_id).into());
        }

        // Verify the signature.
        crypto.verify(message, last_summary.registry_version)?;

        // Verify the dealing.
        crypto.verify_dealing(config, message.signature.signer, &message.content.dealing)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_consensus_mocks::{dependencies_with_subnet_params, Dependencies};
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities_consensus::fake::FakeContentSigner;
    use ic_test_utilities_registry::SubnetRecordBuilder;
    use ic_test_utilities_types::ids::{
        node_test_id, subnet_test_id, NODE_1, NODE_2, NODE_3, SUBNET_1, SUBNET_2,
    };
    use ic_types::{
        batch::BatchPayload,
        consensus::{
            dkg::{self, DealingContent, Message},
            idkg, DataPayload, Payload,
        },
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
            Err(PayloadValidationError::InvalidArtifact(
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
            Err(PayloadValidationError::InvalidArtifact(
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
            Err(PayloadValidationError::InvalidArtifact(
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
            Err(PayloadValidationError::InvalidArtifact(
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
            Err(PayloadValidationError::InvalidArtifact(
                InvalidDkgPayloadReason::TooManyDealings {
                    limit: 2,
                    actual: 3
                }
            ))
        );
    }

    /// Configures all the dependencies and calls [`validate_payload`] with
    /// `dealings_to_validate` as an argument.
    fn validate_payload_test_case(
        dealings_to_validate: Vec<Message>,
        parent_dealings: Vec<Message>,
        max_dealings_per_payload: u64,
        subnet_id: SubnetId,
        committee: &[NodeId],
    ) -> ValidationResult<PayloadValidationError> {
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
                    dealings: dkg::Dealings::new(Height::from(0), parent_dealings),
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
                dealings: dkg::Dealings::new(Height::from(0), dealings_to_validate),
                idkg: idkg::Payload::default(),
            });

            let result = validate_payload(
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
            );

            result
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
}
