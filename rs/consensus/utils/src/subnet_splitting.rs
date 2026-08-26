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
    #[error(
        "The looked up registry version {looked_up_registry_version} is smaller than the last \
        summary block's registry version {last_summary_block_registry_version}"
    )]
    LookedUpRegistryVersionSmallerThanLastSummaryBlock {
        looked_up_registry_version: RegistryVersion,
        last_summary_block_registry_version: RegistryVersion,
    },
}

/// Returns whether a split of `subnet_id` is still pending, as seen from
/// `looked_up_registry_version`.
///
/// `looked_up_registry_version` must be at least `last_summary_block`'s registry version:
/// validation context registry versions never decrease along the chain, so a smaller version can
/// never legitimately be asked about. As defense-in-depth, such a call fails with
/// [`StatusError::LookedUpRegistryVersionSmallerThanLastSummaryBlock`].
///
/// If `last_summary_block` is itself the summary block starting a split (its DKG summary has
/// [`SubnetSplittingStatus::Scheduled`]), the split is pending by definition and the registry is
/// not consulted at all: the subnet is halting, and the registry version must stay frozen at the
/// version adopted by that summary block — the version at which the split was scheduled — until
/// the post-split CUP replaces the chain. This holds regardless of what the registry contains at
/// `looked_up_registry_version`; in particular, a recovery record may have already overwritten
/// the subnet splitting record.
///
/// Otherwise, the registry decides. A [`CupType::SubnetSplitting`] record is never deleted — a
/// later split, a recovery or the genesis record just overwrite it — so its presence alone
/// doesn't mean the split is still ahead of us. Three versions decide that:
///
/// * `looked_up_registry_version` is only an upper bound: the lookup returns the latest CUP
///   contents record written at or below it.
/// * That record's own version is the version the subnet must adopt for the split to happen, and
///   is reported as `scheduled_at`.
/// * `last_summary_block`'s registry version is the watermark: the block maker bumps the registry
///   version to `scheduled_at` exactly at the summary block starting the split (see
///   `BlockMaker::get_stable_registry_version`), so a record at or below the last summary's version
///   describes a split already picked up — [`Status::NotScheduled`].
///
/// Consequently, the following invariant holds for a returned [`Status::Scheduled`] value:
/// `last_summary_block.context.registry_version < scheduled_at <= looked_up_registry_version` when
/// the last summary block is not `Scheduled`, and
/// `scheduled_at == last_summary_block.context.registry_version` when it is.
pub fn get_status(
    registry_client: &dyn RegistryClient,
    subnet_id: SubnetId,
    last_summary_block: &Block,
    looked_up_registry_version: RegistryVersion,
) -> Result<Status, StatusError> {
    // Validation context registry versions never decrease along the chain, so every version we
    // are asked about must be at least the last summary block's version. This should never happen
    // in practice and is only checked as defense-in-depth.
    if looked_up_registry_version < last_summary_block.context.registry_version {
        return Err(
            StatusError::LookedUpRegistryVersionSmallerThanLastSummaryBlock {
                looked_up_registry_version,
                last_summary_block_registry_version: last_summary_block.context.registry_version,
            },
        );
    }

    // While the last summary block is itself the summary starting a split, the split stays
    // pending regardless of what the registry contains at `looked_up_registry_version` (e.g. a
    // recovery record could have already overwritten the subnet splitting record): the subnet is
    // halting, and the registry version stays frozen at the version adopted by that summary block
    // — the version at which the split was scheduled — until the post-split CUP replaces the
    // chain.
    if let SubnetSplittingStatus::Scheduled(SplittingArgs {
        destination_subnet_id,
        source_subnet_id: _,
    }) = last_summary_block
        .payload
        .as_ref()
        .as_summary()
        .dkg
        .subnet_splitting_status()
    {
        return Ok(Status::Scheduled {
            destination_subnet_id,
            scheduled_at: last_summary_block.context.registry_version,
        });
    }

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

    if versioned_record.version <= last_summary_block.context.registry_version {
        // The last summary block already references this version, so this record corresponds to a
        // past subnet split rather than a pending one.
        return Ok(Status::NotScheduled);
    }

    let subnet_splitting_args = SubnetSplittingArgs::try_from(subnet_splitting_args_proto)
        .map_err(StatusError::CatchUpContentsDeserializationError)?;

    Ok(Status::Scheduled {
        destination_subnet_id: subnet_splitting_args.destination_subnet_id,
        scheduled_at: versioned_record.version,
    })
}

/// Returns the `SplittingArgs` if the given summary block has a scheduled subnet split, or `None`
/// otherwise.
/// To be used in conjunction with `get_post_split_subnet_assignment` to determine the post-split
/// subnet assignment of a node.
pub fn is_split_scheduled(summary_block: &Block) -> Option<SplittingArgs> {
    match summary_block
        .payload
        .as_ref()
        .as_summary()
        .dkg
        .subnet_splitting_status()
    {
        SubnetSplittingStatus::Scheduled(splitting_args) => Some(splitting_args),
        SubnetSplittingStatus::NotScheduled | SubnetSplittingStatus::PostSplit(..) => None,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct PostSplitAssignment {
    pub new_subnet_id: SubnetId,
    pub other_subnet_id: SubnetId,
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum PostSplitAssignmentError {
    #[error("The summary block does not have a scheduled subnet split: {0:?}")]
    SummaryBlockNotScheduled(SubnetSplittingStatus),
    #[error("Error while getting the subnet id from the registry at version {0}: {1}")]
    FailedToGetSubnetIdFromTheRegistry(RegistryVersion, RegistryClientError),
    #[error("The node is unassigned at registry version {0}")]
    Unassigned(RegistryVersion),
    #[error(
        "The node changed to subnet {0} during the split, which is neither the source nor destination subnet"
    )]
    DisallowedMembershipChange(SubnetId),
}

/// Returns the subnet assignment of a node after a subnet split, given the `Scheduled` summary
/// block
pub fn get_post_split_subnet_assignment(
    node_id: NodeId,
    summary_block: &Block,
    registry_client: &dyn RegistryClient,
    SplittingArgs {
        destination_subnet_id,
        source_subnet_id,
    }: SplittingArgs,
) -> Result<PostSplitAssignment, PostSplitAssignmentError> {
    match summary_block
        .payload
        .as_ref()
        .as_summary()
        .dkg
        .subnet_splitting_status()
    {
        SubnetSplittingStatus::Scheduled(..) => {}
        status @ (SubnetSplittingStatus::NotScheduled | SubnetSplittingStatus::PostSplit(..)) => {
            return Err(PostSplitAssignmentError::SummaryBlockNotScheduled(status));
        }
    }

    // We determine the new subnet assignment of the node by looking up its subnet id in the
    // registry at the registry version of the summary block's validation context because this will
    // contain precisely the registry version at which the subnet split was scheduled to happen.
    let looked_up_registry_version = summary_block.context.registry_version;
    let new_subnet_id = registry_client
        .get_subnet_id_from_node_id(node_id, looked_up_registry_version)
        .map_err(|err| {
            PostSplitAssignmentError::FailedToGetSubnetIdFromTheRegistry(
                looked_up_registry_version,
                err,
            )
        })?
        .ok_or(PostSplitAssignmentError::Unassigned(
            looked_up_registry_version,
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
        NODE_1, NODE_2, NODE_3, NODE_4, SUBNET_1, SUBNET_2, SUBNET_3, test_replica_version,
    };
    use ic_types::{
        Height, Time,
        batch::ValidationContext,
        consensus::{BlockPayload, Payload, Rank, SummaryPayload, dkg::PostSplitArgs},
        crypto::{CryptoHash, CryptoHashOf},
        subnet_id_into_protobuf,
        time::UNIX_EPOCH,
    };
    use rstest::rstest;
    use std::sync::Arc;

    const SOURCE_SUBNET_ID: SubnetId = SUBNET_1;
    const DESTINATION_SUBNET_ID: SubnetId = SUBNET_2;
    const OTHER_SUBNET_ID: SubnetId = SUBNET_3;
    const REGISTRY_CUP_REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(2);

    use super::*;

    fn set_up_registry(cup_type: Option<CupType>) -> Arc<dyn RegistryClient> {
        let (registry_data_provider, registry) = setup_registry_non_final(
            SOURCE_SUBNET_ID,
            (1..=REGISTRY_CUP_REGISTRY_VERSION.increment().get())
                .map(|version| (version, SubnetRecordBuilder::from(&[NODE_1]).build()))
                .collect(),
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
    #[case(
        REGISTRY_CUP_REGISTRY_VERSION.decrement(),
        REGISTRY_CUP_REGISTRY_VERSION.decrement(),
    )]
    #[case(
        REGISTRY_CUP_REGISTRY_VERSION.decrement(),
        REGISTRY_CUP_REGISTRY_VERSION,
    )]
    #[case(
        REGISTRY_CUP_REGISTRY_VERSION.decrement(),
        REGISTRY_CUP_REGISTRY_VERSION.increment(),
    )]
    #[case(REGISTRY_CUP_REGISTRY_VERSION, REGISTRY_CUP_REGISTRY_VERSION)]
    #[case(
        REGISTRY_CUP_REGISTRY_VERSION,
        REGISTRY_CUP_REGISTRY_VERSION.increment(),
    )]
    #[case(
        REGISTRY_CUP_REGISTRY_VERSION.increment(),
        REGISTRY_CUP_REGISTRY_VERSION.increment(),
    )]
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
        #[values(
            SubnetSplittingStatus::NotScheduled,
            SubnetSplittingStatus::PostSplit(PostSplitArgs {
                new_subnet_id: SOURCE_SUBNET_ID,
            }),
        )]
        last_summary_block_status: SubnetSplittingStatus,
        #[case] last_summary_block_registry_version: RegistryVersion,
        #[case] looked_up_registry_version: RegistryVersion,
    ) {
        let registry = set_up_registry(cup_type);

        let status = get_status(
            registry.as_ref(),
            SUBNET_1,
            &make_summary_block(
                last_summary_block_status,
                last_summary_block_registry_version,
            ),
            looked_up_registry_version,
        )
        .expect("Should succeed given correct inputs");

        assert_eq!(status, Status::NotScheduled);
    }

    #[rstest]
    #[case(
        REGISTRY_CUP_REGISTRY_VERSION.decrement(),
        REGISTRY_CUP_REGISTRY_VERSION,
    )]
    #[case(
        REGISTRY_CUP_REGISTRY_VERSION.decrement(),
        REGISTRY_CUP_REGISTRY_VERSION.increment(),
    )]
    fn get_status_should_return_scheduled_test(
        #[values(
            SubnetSplittingStatus::NotScheduled,
            SubnetSplittingStatus::PostSplit(PostSplitArgs {
                new_subnet_id: SOURCE_SUBNET_ID,
            }),
        )]
        last_summary_block_status: SubnetSplittingStatus,
        #[case] last_summary_block_registry_version: RegistryVersion,
        #[case] looked_up_registry_version: RegistryVersion,
    ) {
        let registry = set_up_registry(Some(CupType::SubnetSplitting(
            ic_protobuf::registry::subnet::v1::SubnetSplittingArgs {
                destination_subnet_id: Some(subnet_id_into_protobuf(DESTINATION_SUBNET_ID)),
            },
        )));

        let status = get_status(
            registry.as_ref(),
            SOURCE_SUBNET_ID,
            &make_summary_block(
                last_summary_block_status,
                last_summary_block_registry_version,
            ),
            looked_up_registry_version,
        )
        .expect("Should succeed given correct inputs");

        assert_eq!(
            status,
            Status::Scheduled {
                destination_subnet_id: DESTINATION_SUBNET_ID,
                scheduled_at: REGISTRY_CUP_REGISTRY_VERSION,
            }
        );
        // Asserting the invariant described in the function documentation, which holds because
        // the last summary block is not `Scheduled`:
        // `last_summary_block.context.registry_version < scheduled_at <= looked_up_registry_version`.
        assert!(
            last_summary_block_registry_version < REGISTRY_CUP_REGISTRY_VERSION
                && REGISTRY_CUP_REGISTRY_VERSION <= looked_up_registry_version
        );
    }

    #[rstest]
    #[case(
        REGISTRY_CUP_REGISTRY_VERSION.decrement(),
        REGISTRY_CUP_REGISTRY_VERSION.decrement(),
    )]
    #[case(REGISTRY_CUP_REGISTRY_VERSION, REGISTRY_CUP_REGISTRY_VERSION)]
    #[case(
        REGISTRY_CUP_REGISTRY_VERSION,
        REGISTRY_CUP_REGISTRY_VERSION.increment(),
    )]
    #[case(
        REGISTRY_CUP_REGISTRY_VERSION.increment(),
        REGISTRY_CUP_REGISTRY_VERSION.increment(),
    )]
    fn get_status_should_return_not_scheduled_when_subnet_splitting_not_reached_or_already_done(
        #[values(
            SubnetSplittingStatus::NotScheduled,
            SubnetSplittingStatus::PostSplit(PostSplitArgs {
                new_subnet_id: SOURCE_SUBNET_ID,
            }),
        )]
        last_summary_block_status: SubnetSplittingStatus,
        #[case] last_summary_block_registry_version: RegistryVersion,
        #[case] looked_up_registry_version: RegistryVersion,
    ) {
        let registry = set_up_registry(Some(CupType::SubnetSplitting(
            ic_protobuf::registry::subnet::v1::SubnetSplittingArgs {
                destination_subnet_id: Some(subnet_id_into_protobuf(DESTINATION_SUBNET_ID)),
            },
        )));

        let status = get_status(
            registry.as_ref(),
            SOURCE_SUBNET_ID,
            &make_summary_block(
                last_summary_block_status,
                last_summary_block_registry_version,
            ),
            looked_up_registry_version,
        )
        .expect("Should succeed given correct inputs");

        assert_eq!(status, Status::NotScheduled);
    }

    /// Validation context registry versions never decrease along the chain, so `get_status` can
    /// never legitimately be asked about a version smaller than the last summary block's version.
    /// As defense-in-depth, such a call must fail — regardless of the other inputs.
    #[rstest]
    #[case(
        REGISTRY_CUP_REGISTRY_VERSION,
        REGISTRY_CUP_REGISTRY_VERSION.decrement(),
    )]
    #[case(
        REGISTRY_CUP_REGISTRY_VERSION.increment(),
        REGISTRY_CUP_REGISTRY_VERSION.decrement(),
    )]
    #[case(
        REGISTRY_CUP_REGISTRY_VERSION.increment(),
        REGISTRY_CUP_REGISTRY_VERSION,
    )]
    fn get_status_should_fail_when_looked_up_version_is_smaller_than_last_summary_version_test(
        #[values(
            None,
            Some(CupType::Genesis(GenesisArgs { height: 0 })),
            Some(CupType::Recovery(RecoveryArgs {
                height: 1_000,
                time: 1,
                state_hash: vec![],
            })),
            Some(CupType::SubnetSplitting(
                ic_protobuf::registry::subnet::v1::SubnetSplittingArgs {
                    destination_subnet_id: Some(subnet_id_into_protobuf(DESTINATION_SUBNET_ID)),
                },
            )),
        )]
        cup_type: Option<CupType>,
        #[values(
            SubnetSplittingStatus::NotScheduled,
            SubnetSplittingStatus::Scheduled(SplittingArgs {
                source_subnet_id: SOURCE_SUBNET_ID,
                destination_subnet_id: DESTINATION_SUBNET_ID,
            }),
            SubnetSplittingStatus::PostSplit(PostSplitArgs {
                new_subnet_id: SOURCE_SUBNET_ID,
            }),
        )]
        last_summary_block_status: SubnetSplittingStatus,
        #[case] last_summary_block_registry_version: RegistryVersion,
        #[case] looked_up_registry_version: RegistryVersion,
    ) {
        let registry = set_up_registry(cup_type);

        let result = get_status(
            registry.as_ref(),
            SOURCE_SUBNET_ID,
            &make_summary_block(
                last_summary_block_status,
                last_summary_block_registry_version,
            ),
            looked_up_registry_version,
        );

        assert_matches!(
            result,
            Err(StatusError::LookedUpRegistryVersionSmallerThanLastSummaryBlock {
                looked_up_registry_version: looked_up,
                last_summary_block_registry_version: last_summary,
            }) if looked_up == looked_up_registry_version
                && last_summary == last_summary_block_registry_version
        );
    }

    /// While the last summary block is itself the one starting the split (`Scheduled` status), the
    /// split stays pending even though the last summary already references the split's registry
    /// version: the subnet is halting and the registry version stays frozen at `scheduled_at` for
    /// all blocks built on top, until the post-split CUP replaces the chain. This holds regardless
    /// of the record found at `looked_up_registry_version`.
    #[rstest]
    fn get_status_should_return_scheduled_when_last_summary_block_starts_the_split_test(
        #[values(
            None,
            Some(CupType::Genesis(GenesisArgs { height: 0 })),
            Some(CupType::Recovery(RecoveryArgs {
                height: 1_000,
                time: 1,
                state_hash: vec![],
            })),
            Some(CupType::SubnetSplitting(
                ic_protobuf::registry::subnet::v1::SubnetSplittingArgs {
                    destination_subnet_id: Some(subnet_id_into_protobuf(DESTINATION_SUBNET_ID)),
                },
            )),
        )]
        cup_type: Option<CupType>,
        #[values(REGISTRY_CUP_REGISTRY_VERSION, REGISTRY_CUP_REGISTRY_VERSION.increment())]
        looked_up_registry_version: RegistryVersion,
    ) {
        let registry = set_up_registry(cup_type);

        let status = get_status(
            registry.as_ref(),
            SOURCE_SUBNET_ID,
            // The summary block starting the split adopts `REGISTRY_CUP_REGISTRY_VERSION`, the
            // version at which the split is scheduled.
            &make_scheduled_summary_block(),
            looked_up_registry_version,
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

    /// While the last summary block is the one starting the split, the registry is not consulted
    /// at all, so the status is available even when the registry is not.
    #[rstest]
    fn get_status_should_return_scheduled_when_last_summary_block_starts_the_split_and_registry_is_unreadable_test(
        #[values(REGISTRY_CUP_REGISTRY_VERSION, REGISTRY_CUP_REGISTRY_VERSION.increment())]
        looked_up_registry_version: RegistryVersion,
    ) {
        let status = get_status(
            &ErrorRegistryClient,
            SOURCE_SUBNET_ID,
            &make_scheduled_summary_block(),
            looked_up_registry_version,
        )
        .expect("Should succeed without consulting the registry");

        assert_eq!(
            status,
            Status::Scheduled {
                destination_subnet_id: DESTINATION_SUBNET_ID,
                scheduled_at: REGISTRY_CUP_REGISTRY_VERSION,
            }
        );
    }

    fn make_summary_block(
        subnet_splitting_status: SubnetSplittingStatus,
        registry_version: RegistryVersion,
    ) -> Block {
        let mut summary = SummaryPayload::fake();
        summary.dkg.subnet_splitting_status = subnet_splitting_status;
        Block {
            version: test_replica_version(),
            parent: CryptoHashOf::from(CryptoHash(vec![])),
            payload: Payload::new(
                ic_types::crypto::crypto_hash,
                BlockPayload::Summary(summary),
            ),
            height: Height::new(0),
            rank: Rank(0),
            context: ValidationContext {
                certified_height: Height::new(0),
                registry_version,
                time: UNIX_EPOCH,
            },
        }
    }

    fn make_summary_block_with_status(subnet_splitting_status: SubnetSplittingStatus) -> Block {
        make_summary_block(subnet_splitting_status, REGISTRY_CUP_REGISTRY_VERSION)
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
    #[case::not_scheduled(SubnetSplittingStatus::NotScheduled)]
    #[case::post_split_source(SubnetSplittingStatus::PostSplit(PostSplitArgs { new_subnet_id: SOURCE_SUBNET_ID }))]
    #[case::post_split_destination(SubnetSplittingStatus::PostSplit(PostSplitArgs { new_subnet_id: DESTINATION_SUBNET_ID }))]
    fn should_not_be_scheduled_and_assignment_should_fail_when_subnet_splitting_not_scheduled_test(
        #[case] status: SubnetSplittingStatus,
    ) {
        let block = make_summary_block_with_status(status);

        assert!(is_split_scheduled(&block).is_none());

        let registry = set_up_post_split_registry(&[NODE_1], &[NODE_2], &[NODE_3]);

        let result = get_post_split_subnet_assignment(
            NODE_1,
            &block,
            registry.as_ref(),
            SplittingArgs {
                source_subnet_id: SOURCE_SUBNET_ID,
                destination_subnet_id: DESTINATION_SUBNET_ID,
            },
        );

        assert_eq!(
            result,
            Err(PostSplitAssignmentError::SummaryBlockNotScheduled(status))
        );
    }

    #[test]
    fn should_fail_when_node_moved_to_unrelated_subnet_test() {
        let block = make_scheduled_summary_block();
        let registry = set_up_post_split_registry(&[NODE_1], &[NODE_2], &[NODE_3]);

        let splitting_args = is_split_scheduled(&block).expect("Should be scheduled");
        let result =
            get_post_split_subnet_assignment(NODE_3, &block, registry.as_ref(), splitting_args);

        assert_eq!(
            result,
            Err(PostSplitAssignmentError::DisallowedMembershipChange(
                OTHER_SUBNET_ID
            ))
        );
    }

    #[test]
    fn should_fail_when_node_is_unassigned_test() {
        let block = make_scheduled_summary_block();
        let registry = set_up_post_split_registry(&[NODE_1], &[NODE_2], &[NODE_3]);

        let splitting_args = is_split_scheduled(&block).expect("Should be scheduled");
        let result =
            get_post_split_subnet_assignment(NODE_4, &block, registry.as_ref(), splitting_args);

        assert_eq!(
            result,
            Err(PostSplitAssignmentError::Unassigned(
                REGISTRY_CUP_REGISTRY_VERSION
            ))
        );
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
