use ic_interfaces_registry::RegistryClient;
use ic_protobuf::{
    proxy::ProxyDecodeError, registry::subnet::v1::catch_up_package_contents::CupType,
};
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_types::{
    RegistryVersion, SubnetId, consensus::SubnetSplittingArgs, registry::RegistryClientError,
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

#[cfg(test)]
mod tests {
    use ic_protobuf::registry::subnet::v1::CatchUpPackageContents;
    use ic_protobuf::registry::subnet::v1::{GenesisArgs, RecoveryArgs};
    use ic_registry_keys::make_catch_up_package_contents_key;
    use ic_test_utilities_registry::{SubnetRecordBuilder, setup_registry_non_final};
    use ic_test_utilities_types::ids::{NODE_1, SUBNET_1, SUBNET_2};
    use ic_types::subnet_id_into_protobuf;
    use rstest::rstest;
    use std::sync::Arc;

    const SOURCE_SUBNET_ID: SubnetId = SUBNET_1;
    const DESTINATION_SUBNET_ID: SubnetId = SUBNET_2;
    const REGISTRY_CUP_REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(2);

    use super::*;

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

    #[rstest]
    fn get_status_should_return_not_scheduled_when_latest_cup_is_not_subnet_splitting_test(
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
    fn get_status_should_return_scheduled_test() {
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
    fn get_status_should_return_not_scheduled_when_subnet_splitting_was_already_done_test() {
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
}
