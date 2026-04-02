use ic_interfaces_registry::RegistryClient;
use ic_protobuf::{
    proxy::ProxyDecodeError, registry::subnet::v1::catch_up_package_contents::CupType,
};
use ic_registry_client_helpers::{node::NodeRegistry, subnet::SubnetRegistry};
use ic_types::{
    NodeId, RegistryVersion, SubnetId,
    consensus::{Block, SubnetSplittingArgs, dkg::SubnetSplittingStatus},
    registry::RegistryClientError,
};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Scheduled {
        destination_subnet_id: SubnetId,
        /// The registry version at which the subnet was scheduled to be split
        scheduled_at: RegistryVersion,
    },
    AlreadyDone,
    NotScheduled,
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

#[derive(Debug)]
pub struct Context {
    pub last_summary_block_registry_version: RegistryVersion,
    pub current_registry_version: RegistryVersion,
}

pub fn get_status(
    registry_client: &dyn RegistryClient,
    subnet_id: SubnetId,
    Context {
        last_summary_block_registry_version,
        current_registry_version,
    }: Context,
) -> Result<Status, StatusError> {
    let versioned_record = registry_client
        .get_cup_contents(subnet_id, current_registry_version)
        .map_err(|err| StatusError::FailedToGetCatchUpContents(current_registry_version, err))?;

    let Some(contents) = versioned_record.value else {
        return Err(StatusError::CatchUpContentsMissingInRegistry(
            current_registry_version,
        ));
    };

    let Some(CupType::SubnetSplitting(subnet_splitting_args_proto)) = contents.cup_type else {
        return Ok(Status::NotScheduled);
    };

    if versioned_record.version <= last_summary_block_registry_version {
        return Ok(Status::AlreadyDone);
    }

    let subnet_splitting_args: SubnetSplittingArgs = subnet_splitting_args_proto
        .try_into()
        .map_err(StatusError::CatchUpContentsDeserializationError)?;

    Ok(Status::Scheduled {
        destination_subnet_id: subnet_splitting_args.destination_subnet_id,
        scheduled_at: versioned_record.version,
    })
}

pub struct PostSplitAssignment {
    pub new_subnet_id: SubnetId,
    // for debugging purposes
    pub other_subnet_id: SubnetId,
}

#[derive(Debug, Error)]
pub enum PostSplitAssignmentError {
    #[error("Error while getting the subnet id from the registry at version {0}: {1}")]
    FailedToGetSubnetIdFromTheRegistry(RegistryVersion, RegistryClientError),
    #[error("The node is unassigned to any subnet at registry version {0}")]
    Unassigned(RegistryVersion),
    #[error("The subnet is not being split according to the summary block")]
    NotSplitting,
    #[error("The node changed subnets during subnet splitting")]
    DisallowedMembershipChange(SubnetId),
}

pub fn get_post_split_subnet_assignment(
    node_id: NodeId,
    summary_block: &Block,
    registry_client: &dyn RegistryClient,
) -> Result<PostSplitAssignment, PostSplitAssignmentError> {
    let SubnetSplittingStatus::Scheduled {
        destination_subnet_id,
        source_subnet_id,
    } = summary_block
        .payload
        .as_ref()
        .as_summary()
        .dkg
        .subnet_splitting_status()
    else {
        return Err(PostSplitAssignmentError::NotSplitting);
    };

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
    use std::sync::Arc;

    use ic_protobuf::registry::subnet::v1::CatchUpPackageContents;
    use ic_protobuf::registry::subnet::v1::{GenesisArgs, RecoveryArgs};
    use ic_registry_keys::make_catch_up_package_contents_key;
    use ic_test_utilities_registry::{SubnetRecordBuilder, setup_registry_non_final};
    use ic_test_utilities_types::ids::{NODE_1, SUBNET_1, SUBNET_2};
    use ic_types::subnet_id_into_protobuf;
    use rstest::rstest;

    const SOURCE_SUBNET_ID: SubnetId = SUBNET_1;
    const DESTINATION_SUBNET_ID: SubnetId = SUBNET_2;
    const REGISTRY_CUP_REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(2);

    use super::*;

    #[rstest]
    fn should_return_not_scheduled_test(
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
            Context {
                last_summary_block_registry_version: REGISTRY_CUP_REGISTRY_VERSION.decrement(),
                current_registry_version: REGISTRY_CUP_REGISTRY_VERSION,
            },
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
            Context {
                last_summary_block_registry_version: REGISTRY_CUP_REGISTRY_VERSION.decrement(),
                current_registry_version: REGISTRY_CUP_REGISTRY_VERSION,
            },
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
    fn should_return_already_done_test() {
        let registry = set_up_registry(Some(CupType::SubnetSplitting(
            ic_protobuf::registry::subnet::v1::SubnetSplittingArgs {
                destination_subnet_id: Some(subnet_id_into_protobuf(DESTINATION_SUBNET_ID)),
            },
        )));

        let status = get_status(
            registry.as_ref(),
            SOURCE_SUBNET_ID,
            Context {
                last_summary_block_registry_version: REGISTRY_CUP_REGISTRY_VERSION,
                current_registry_version: REGISTRY_CUP_REGISTRY_VERSION,
            },
        )
        .expect("Should succeed given correct inputs");

        assert_eq!(status, Status::AlreadyDone);
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
}
