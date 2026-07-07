use ic_interfaces_registry::RegistryClient;
use ic_protobuf::{
    proxy::ProxyDecodeError, registry::subnet::v1::catch_up_package_contents::CupType,
};
use ic_registry_client_helpers::{node::NodeRegistry, subnet::SubnetRegistry};
use ic_types::{
    NodeId, RegistryVersion, SubnetId,
    consensus::{
        Block, SubnetSplittingArgs,
        dkg::{SplittingArgs, SubnetSplittingStatus},
    },
    registry::RegistryClientError,
};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    NotScheduled,
    Scheduled {
        destination_subnet_id: SubnetId,
        /// The registry version at which the subnet was scheduled to be split
        scheduled_at: RegistryVersion,
    },
}

#[derive(Debug, Error)]
pub enum StatusError {
    #[error("Error while getting CatchUpContents at registry version {0}: {1:?}")]
    FailedToGetCatchUpContents(RegistryVersion, RegistryClientError),
    #[error("CatchUpContents not found at registry version: {0}")]
    CatchUpContentsMissingInRegistry(RegistryVersion),
    #[error("Failed to deserialize CatchUpContents: {0}")]
    CatchUpContentsDeserializationError(ProxyDecodeError),
}

pub fn get_status(
    registry_client: &dyn RegistryClient,
    subnet_id: SubnetId,
    last_summary_block_registry_version: RegistryVersion,
    looked_up_registry_version: RegistryVersion,
) -> Result<Status, StatusError> {
    let versioned_record = registry_client
        .get_cup_contents(subnet_id, looked_up_registry_version)
        .map_err(|err| StatusError::FailedToGetCatchUpContents(looked_up_registry_version, err))?;

    let Some(contents) = versioned_record.value else {
        return Err(StatusError::CatchUpContentsMissingInRegistry(
            looked_up_registry_version,
        ));
    };

    let Some(CupType::SubnetSplitting(subnet_splitting_args_proto)) = contents.cup_type else {
        return Ok(Status::NotScheduled);
    };

    if versioned_record.version <= last_summary_block_registry_version {
        // This record corresponds to a past subnet split
        return Ok(Status::NotScheduled);
    }

    let subnet_splitting_args = SubnetSplittingArgs::try_from(subnet_splitting_args_proto)
        .map_err(StatusError::CatchUpContentsDeserializationError)?;

    Ok(Status::Scheduled {
        destination_subnet_id: subnet_splitting_args.destination_subnet_id,
        scheduled_at: versioned_record.version,
    })
}

pub fn is_split_scheduled(summary_block: &Block) -> Option<SplittingArgs> {
    match summary_block
        .payload
        .as_ref()
        .as_summary()
        .dkg
        .subnet_splitting_status()
    {
        SubnetSplittingStatus::Scheduled(splitting_args) => Some(splitting_args),
        SubnetSplittingStatus::NotScheduled | SubnetSplittingStatus::PostSplit { .. } => None,
    }
}

#[derive(Debug)]
pub struct PostSplitAssignment {
    pub new_subnet_id: SubnetId,
    pub other_subnet_id: SubnetId,
}

#[derive(Debug, Error)]
pub enum PostSplitAssignmentError {
    #[error("Error while getting the subnet id from the registry at version {0}: {1}")]
    FailedToGetSubnetIdFromTheRegistry(RegistryVersion, RegistryClientError),
    #[error("The node is unassigned at registry version {0}")]
    Unassigned(RegistryVersion),
    #[error("The node changed subnets during subnet splitting")]
    DisallowedMembershipChange(SubnetId),
}

pub fn get_post_split_subnet_assignment(
    node_id: NodeId,
    summary_block: &Block,
    registry_client: &dyn RegistryClient,
    SplittingArgs {
        destination_subnet_id,
        source_subnet_id,
    }: SplittingArgs,
) -> Result<PostSplitAssignment, PostSplitAssignmentError> {
    let new_subnet_id = registry_client
        .get_subnet_id_from_node_id(node_id, summary_block.context.registry_version)
        .map_err(|err| {
            PostSplitAssignmentError::FailedToGetSubnetIdFromTheRegistry(
                summary_block.context.registry_version,
                err,
            )
        })?
        .ok_or(PostSplitAssignmentError::Unassigned(
            summary_block.context.registry_version,
        ))?;

    let other_subnet_id = if new_subnet_id == destination_subnet_id {
        source_subnet_id
    } else if new_subnet_id == source_subnet_id {
        destination_subnet_id
    } else {
        return Err(PostSplitAssignmentError::DisallowedMembershipChange(
            new_subnet_id,
        ));
    };

    Ok(PostSplitAssignment {
        new_subnet_id,
        other_subnet_id,
    })
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use std::sync::Arc;

    use ic_interfaces_registry::RegistryClientVersionedResult;
    use ic_protobuf::registry::subnet::v1::CatchUpPackageContents;
    use ic_protobuf::registry::subnet::v1::{GenesisArgs, RecoveryArgs};
    use ic_registry_keys::make_catch_up_package_contents_key;
    use ic_test_utilities_consensus::fake::Fake;
    use ic_test_utilities_registry::{
        SubnetRecordBuilder, add_single_subnet_record, add_subnet_list_record,
        setup_registry_non_final,
    };
    use ic_test_utilities_types::ids::{
        NODE_1, NODE_2, NODE_3, NODE_4, SUBNET_1, SUBNET_2, SUBNET_3,
    };
    use ic_types::subnet_id_into_protobuf;
    use ic_types::{
        Height, ReplicaVersion, Time,
        batch::ValidationContext,
        consensus::{
            BlockPayload, Payload, Rank, SummaryPayload,
            backwards_compatibility::BackwardsCompatibleOption,
        },
        crypto::{CryptoHash, CryptoHashOf},
        time::UNIX_EPOCH,
    };
    use rstest::rstest;

    const SOURCE_SUBNET_ID: SubnetId = SUBNET_1;
    const DESTINATION_SUBNET_ID: SubnetId = SUBNET_2;
    const OTHER_SUBNET_ID: SubnetId = SUBNET_3;
    const REGISTRY_CUP_REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(2);

    use super::*;

    #[rstest]
    fn should_return_not_scheduled_when_latest_cup_is_not_subnet_splitting_test(
        #[values(
            None,
            Some(CupType::Genesis(GenesisArgs { height: 0 })),
            Some(CupType::Recovery(RecoveryArgs {
                height: 1_000,
                time: 1,
                state_hash: vec![],
            })),
        )]
        cup_type: Option<CupType>,
    ) {
        let registry = set_up_registry(cup_type);

        let status = get_status(
            registry.as_ref(),
            SUBNET_1,
            REGISTRY_CUP_REGISTRY_VERSION.decrement(),
            REGISTRY_CUP_REGISTRY_VERSION,
        )
        .expect("Should succeed given correct inputs");

        assert_eq!(status, Status::NotScheduled);
    }

    #[test]
    fn should_return_scheduled_test() {
        let registry = set_up_registry(Some(CupType::SubnetSplitting(
            ic_protobuf::registry::subnet::v1::SubnetSplittingArgs {
                destination_subnet_id: Some(subnet_id_into_protobuf(DESTINATION_SUBNET_ID)),
            },
        )));

        let status = get_status(
            registry.as_ref(),
            SOURCE_SUBNET_ID,
            REGISTRY_CUP_REGISTRY_VERSION.decrement(),
            REGISTRY_CUP_REGISTRY_VERSION,
        )
        .expect("Should succeed given correct inputs");

        assert_eq!(
            status,
            Status::Scheduled {
                destination_subnet_id: DESTINATION_SUBNET_ID,
                scheduled_at: REGISTRY_CUP_REGISTRY_VERSION,
            }
        );
    }

    #[test]
    fn should_return_not_scheduled_when_subnet_splitting_was_already_done_test() {
        let registry = set_up_registry(Some(CupType::SubnetSplitting(
            ic_protobuf::registry::subnet::v1::SubnetSplittingArgs {
                destination_subnet_id: Some(subnet_id_into_protobuf(DESTINATION_SUBNET_ID)),
            },
        )));

        let status = get_status(
            registry.as_ref(),
            SOURCE_SUBNET_ID,
            REGISTRY_CUP_REGISTRY_VERSION,
            REGISTRY_CUP_REGISTRY_VERSION,
        )
        .expect("Should succeed given correct inputs");

        assert_eq!(status, Status::NotScheduled);
    }

    fn set_up_registry(cup_type: Option<CupType>) -> Arc<dyn RegistryClient> {
        let (registry_data_provider, registry) = setup_registry_non_final(
            SOURCE_SUBNET_ID,
            vec![(
                1,
                SubnetRecordBuilder::new().with_committee(&[NODE_1]).build(),
            )],
        );
        registry_data_provider
            .add(
                &make_catch_up_package_contents_key(SOURCE_SUBNET_ID),
                REGISTRY_CUP_REGISTRY_VERSION,
                Some(CatchUpPackageContents {
                    cup_type,
                    ..Default::default()
                }),
            )
            .unwrap();
        registry.update_to_latest_version();

        registry
    }

    fn make_summary_block_with_status(subnet_splitting_status: SubnetSplittingStatus) -> Block {
        let mut summary = SummaryPayload::fake();
        summary.dkg.subnet_splitting_status =
            BackwardsCompatibleOption::new_for_test_only(Some(subnet_splitting_status));
        Block {
            version: ReplicaVersion::default(),
            parent: CryptoHashOf::from(CryptoHash(vec![])),
            payload: Payload::new(
                ic_types::crypto::crypto_hash,
                BlockPayload::Summary(summary),
            ),
            height: Height::new(0),
            rank: Rank(0),
            context: ValidationContext {
                certified_height: Height::new(0),
                registry_version: REGISTRY_CUP_REGISTRY_VERSION,
                time: UNIX_EPOCH,
            },
        }
    }

    fn make_scheduled_summary_block() -> Block {
        make_summary_block_with_status(SubnetSplittingStatus::Scheduled(SplittingArgs {
            source_subnet_id: SOURCE_SUBNET_ID,
            destination_subnet_id: DESTINATION_SUBNET_ID,
        }))
    }

    fn set_up_post_split_registry(
        source_committee: &[NodeId],
        destination_committee: &[NodeId],
        other_committee: &[NodeId],
    ) -> Arc<dyn RegistryClient> {
        let (registry_data_provider, registry) = setup_registry_non_final(
            SOURCE_SUBNET_ID,
            vec![(
                1,
                SubnetRecordBuilder::new()
                    .with_committee(source_committee)
                    .build(),
            )],
        );
        add_single_subnet_record(
            &registry_data_provider,
            REGISTRY_CUP_REGISTRY_VERSION.get(),
            DESTINATION_SUBNET_ID,
            SubnetRecordBuilder::new()
                .with_committee(destination_committee)
                .build(),
        );
        add_single_subnet_record(
            &registry_data_provider,
            REGISTRY_CUP_REGISTRY_VERSION.get(),
            OTHER_SUBNET_ID,
            SubnetRecordBuilder::new()
                .with_committee(other_committee)
                .build(),
        );
        add_subnet_list_record(
            &registry_data_provider,
            REGISTRY_CUP_REGISTRY_VERSION.get(),
            vec![SOURCE_SUBNET_ID, DESTINATION_SUBNET_ID, OTHER_SUBNET_ID],
        );
        registry.update_to_latest_version();
        registry
    }

    struct ErrorRegistryClient;

    impl RegistryClient for ErrorRegistryClient {
        fn get_versioned_value(
            &self,
            _key: &str,
            version: RegistryVersion,
        ) -> RegistryClientVersionedResult<Vec<u8>> {
            Err(RegistryClientError::VersionNotAvailable { version })
        }

        fn get_key_family(
            &self,
            _key_prefix: &str,
            version: RegistryVersion,
        ) -> Result<Vec<String>, RegistryClientError> {
            Err(RegistryClientError::VersionNotAvailable { version })
        }

        fn get_latest_version(&self) -> RegistryVersion {
            RegistryVersion::from(0)
        }

        fn get_version_timestamp(&self, _registry_version: RegistryVersion) -> Option<Time> {
            None
        }
    }

    #[test]
    fn should_return_source_subnet_assignment_when_node_stays_on_source_subnet_test() {
        let block = make_scheduled_summary_block();
        let registry = set_up_post_split_registry(&[NODE_1], &[NODE_2], &[NODE_3]);

        let splitting_args = is_split_scheduled(&block).expect("Should be scheduled");
        let result =
            get_post_split_subnet_assignment(NODE_1, &block, registry.as_ref(), splitting_args)
                .expect("Should succeed");

        assert_eq!(result.new_subnet_id, SOURCE_SUBNET_ID);
        assert_eq!(result.other_subnet_id, DESTINATION_SUBNET_ID);
    }

    #[test]
    fn should_return_destination_subnet_assignment_when_node_moves_to_destination_subnet_test() {
        let block = make_scheduled_summary_block();
        let registry = set_up_post_split_registry(&[NODE_1], &[NODE_2], &[NODE_3]);

        let splitting_args = is_split_scheduled(&block).expect("Should be scheduled");
        let result =
            get_post_split_subnet_assignment(NODE_2, &block, registry.as_ref(), splitting_args)
                .expect("Should succeed");

        assert_eq!(result.new_subnet_id, DESTINATION_SUBNET_ID);
        assert_eq!(result.other_subnet_id, SOURCE_SUBNET_ID);
    }

    #[rstest]
    fn should_not_be_scheduled_when_subnet_splitting_not_scheduled_test(
        #[values(
            SubnetSplittingStatus::NotScheduled,
            SubnetSplittingStatus::PostSplit { new_subnet_id: SOURCE_SUBNET_ID },
        )]
        status: SubnetSplittingStatus,
    ) {
        let block = make_summary_block_with_status(status);
        let registry = set_up_post_split_registry(&[NODE_1], &[NODE_2], &[NODE_3]);

        assert!(is_split_scheduled(&block).is_none());
    }

    #[test]
    fn should_fail_when_node_moved_to_unrelated_subnet_test() {
        let block = make_scheduled_summary_block();
        let registry = set_up_post_split_registry(&[NODE_1], &[NODE_2], &[NODE_3]);

        let splitting_args = is_split_scheduled(&block).expect("Should be scheduled");
        let result =
            get_post_split_subnet_assignment(NODE_3, &block, registry.as_ref(), splitting_args);

        assert_matches!(result, Err(PostSplitAssignmentError::DisallowedMembershipChange(s)) if s == OTHER_SUBNET_ID);
    }

    #[test]
    fn should_fail_when_node_is_unassigned_test() {
        let block = make_scheduled_summary_block();
        let registry = set_up_post_split_registry(&[NODE_1], &[NODE_2], &[NODE_3]);

        let splitting_args = is_split_scheduled(&block).expect("Should be scheduled");
        let result =
            get_post_split_subnet_assignment(NODE_4, &block, registry.as_ref(), splitting_args);

        assert_matches!(result, Err(PostSplitAssignmentError::Unassigned(v)) if v == REGISTRY_CUP_REGISTRY_VERSION);
    }

    #[test]
    fn should_fail_when_registry_returns_error_test() {
        let block = make_scheduled_summary_block();

        let splitting_args = is_split_scheduled(&block).expect("Should be scheduled");
        let result =
            get_post_split_subnet_assignment(NODE_1, &block, &ErrorRegistryClient, splitting_args);

        assert_matches!(result, Err(PostSplitAssignmentError::FailedToGetSubnetIdFromTheRegistry(v, _)) if v == REGISTRY_CUP_REGISTRY_VERSION);
    }
}
