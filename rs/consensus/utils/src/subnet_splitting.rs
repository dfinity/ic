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
    Scheduled { destination_subnet_id: SubnetId },
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

pub struct Context {
    last_summary_block_registry_version: RegistryVersion,
    current_registry_version: RegistryVersion,
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
        let registry = set_up_registry(RegistryVersion::new(1), cup_type);

        let status = get_status(
            registry.as_ref(),
            SUBNET_1,
            Context {
                last_summary_block_registry_version: RegistryVersion::new(1),
                current_registry_version: RegistryVersion::new(2),
            },
        )
        .expect("Should succeed given correct inputs");

        assert_eq!(status, Status::NotScheduled);
    }

    #[test]
    fn should_return_scheduled_test() {
        let registry = set_up_registry(
            RegistryVersion::new(1),
            Some(CupType::SubnetSplitting(
                ic_protobuf::registry::subnet::v1::SubnetSplittingArgs {
                    destination_subnet_id: Some(subnet_id_into_protobuf(DESTINATION_SUBNET_ID)),
                },
            )),
        );

        let status = get_status(
            registry.as_ref(),
            SOURCE_SUBNET_ID,
            Context {
                last_summary_block_registry_version: RegistryVersion::new(1),
                current_registry_version: RegistryVersion::new(2),
            },
        )
        .expect("Should succeed given correct inputs");

        assert_eq!(
            status,
            Status::Scheduled {
                destination_subnet_id: DESTINATION_SUBNET_ID
            }
        );
    }

    #[test]
    fn should_return_already_done_test() {
        let registry = set_up_registry(
            RegistryVersion::new(1),
            Some(CupType::SubnetSplitting(
                ic_protobuf::registry::subnet::v1::SubnetSplittingArgs {
                    destination_subnet_id: Some(subnet_id_into_protobuf(DESTINATION_SUBNET_ID)),
                },
            )),
        );

        let status = get_status(
            registry.as_ref(),
            SOURCE_SUBNET_ID,
            Context {
                last_summary_block_registry_version: RegistryVersion::new(2),
                current_registry_version: RegistryVersion::new(2),
            },
        )
        .expect("Should succeed given correct inputs");

        assert_eq!(status, Status::AlreadyDone);
    }

    fn set_up_registry(
        cup_registry_version: RegistryVersion,
        cup_type: Option<CupType>,
    ) -> Arc<dyn RegistryClient> {
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
                cup_registry_version,
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
