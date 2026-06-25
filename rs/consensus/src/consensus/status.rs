use std::fmt::Display;

use ic_consensus_utils::{lookup_replica_version, pool_reader::PoolReader};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{ReplicaLogger, warn};
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_types::{
    Height, ReplicaVersion, SubnetId,
    consensus::{Block, dkg::SubnetSplittingStatus},
};

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub(crate) enum Status {
    /// The Consensus is running normally.
    Running,
    /// The Consensus is halting, meaning we will produce *empty* blocks but no batches will be
    /// delivered.
    Halting,
    /// The Consensus is halted, meaning that no blocks are created and no batches are delivered.
    Halted,
}

/// Get the status of the consensus.
///
/// Note: If 'height' is smaller than the height of the last CUP, this will return [None].
///
/// Returns
/// * [Status::Halting] when there is a pending upgrade or the registry instructs the subnet to halt
/// * [Status::Halted] when a CUP height has been finalized and either an upgrade is in progress or
///   the registry instructs the subnet to halt;
/// * [Status::Running] when there is no upgrade and the registry doesn't instruct the subnet to
///   halt.
pub(crate) fn get_status(
    height: Height,
    last_summary_block: &Block,
    registry_client: &(impl RegistryClient + ?Sized),
    subnet_id: SubnetId,
    pool: &PoolReader<'_>,
    logger: &ReplicaLogger,
) -> Option<Status> {
    if should_halt(
        height,
        Some(last_summary_block),
        registry_client,
        subnet_id,
        pool,
        logger,
    )
    .warn_if_none(logger, "Failed to check if the subnet is halting!")?
    {
        let certified_height = pool.get_finalized_tip().context.certified_height;

        if should_halt(
            certified_height,
            Some(last_summary_block),
            registry_client,
            subnet_id,
            pool,
            logger,
        )
        .warn_if_none(logger, "Failed to check if the subnet is halted!")
            == Some(true)
        {
            return Some(Status::Halted);
        }

        return Some(Status::Halting);
    }

    Some(Status::Running)
}

pub(crate) fn should_halt(
    height: Height,
    last_summary_block: Option<&Block>,
    registry_client: &(impl RegistryClient + ?Sized),
    subnet_id: SubnetId,
    pool: &PoolReader<'_>,
    logger: &ReplicaLogger,
) -> Option<bool> {
    let registry_version = pool.registry_version(height).warn_if_none(
        logger,
        format!("Failed to get the registry version at height {height}"),
    )?;

    let should_halt_due_to_upgrading =
        lookup_replica_version(registry_client, subnet_id, logger, registry_version)
            .map(|replica_version| replica_version != ReplicaVersion::default())
            .warn_if_none(logger, "Failed to check if the upgrade is pending!");

    let should_halt_due_to_subnet_splitting = last_summary_block.map(|summary_block| {
        match summary_block
            .payload
            .as_ref()
            .as_summary()
            .dkg
            .subnet_splitting_status()
        {
            SubnetSplittingStatus::NotScheduled => false,
            // After the split, don't produce any blocks until we are on the right subnet.
            SubnetSplittingStatus::PostSplit { new_subnet_id } => subnet_id != new_subnet_id,
            SubnetSplittingStatus::Scheduled(..) => height >= summary_block.height,
        }
    });

    let should_halt_by_subnet_record = registry_client
        .get_halt_at_cup_height(subnet_id, registry_version)
        .inspect_err(|err| {
            warn!(
                logger,
                "Failed querying the registry at version {registry_version}: {err}"
            )
        })
        .ok()
        .flatten()
        .warn_if_none(
            logger,
            format!(
                "Failed to check if the registry version at height {height} \
                instructs the subnet to halt!",
            ),
        );

    any(&[
        should_halt_due_to_upgrading,
        should_halt_due_to_subnet_splitting,
        should_halt_by_subnet_record,
    ])
}

/// Returns `true` if any of the provided values is known to be `true`.
fn any(values: &[Option<bool>]) -> Option<bool> {
    if values.contains(&Some(true)) {
        Some(true)
    } else if values.iter().all(|value| *value == Some(false)) {
        Some(false)
    } else {
        None
    }
}

/// Utility trait which adds a [warn_if_none] function to the [Option] struct.
trait LogIfNone {
    /// Logs a warning if the option is [None].
    fn warn_if_none(self, logger: &ReplicaLogger, message: impl Display) -> Self;
}

impl<T> LogIfNone for Option<T> {
    fn warn_if_none(self, logger: &ReplicaLogger, message: impl Display) -> Self {
        if self.is_none() {
            warn!(logger, "{}", message);
        }

        self
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ic_config::artifact_pool::ArtifactPoolConfig;
    use ic_consensus_mocks::{Dependencies, dependencies_with_subnet_params};
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_test_artifact_pool::consensus_pool::{Round, TestConsensusPool};
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_registry::SubnetRecordBuilder;
    use ic_test_utilities_types::ids::node_test_id;
    use ic_types::{
        ReplicaVersion,
        consensus::{BlockPayload, Payload, dkg::SplittingArgs},
        crypto::crypto_hash,
    };
    use ic_types_test_utils::ids::{SUBNET_0, SUBNET_1};
    use rstest::rstest;

    use super::*;

    const DKG_LENGTH: u64 = 3;
    const CUP_HEIGHT: Height = Height::new(2 * (1 + DKG_LENGTH));

    fn set_up(
        pool_config: ArtifactPoolConfig,
        subnet_id: SubnetId,
        certified_height: Height,
        replica_version: ReplicaVersion,
        halt_at_cup_height: bool,
    ) -> (TestConsensusPool, Arc<FakeRegistryClient>) {
        let node_ids = [node_test_id(0)];
        let Dependencies {
            mut pool, registry, ..
        } = dependencies_with_subnet_params(
            pool_config,
            subnet_id,
            vec![
                (
                    1,
                    SubnetRecordBuilder::from(&node_ids)
                        .with_dkg_interval_length(DKG_LENGTH)
                        .build(),
                ),
                (
                    10,
                    SubnetRecordBuilder::from(&node_ids)
                        .with_dkg_interval_length(DKG_LENGTH)
                        .with_replica_version(replica_version.as_ref())
                        .with_halt_at_cup_height(halt_at_cup_height)
                        .build(),
                ),
            ],
        );

        pool.advance_round_normal_operation_no_cup_n(CUP_HEIGHT.get());
        Round::new(&mut pool)
            .with_certified_height(certified_height)
            .advance();

        (pool, registry)
    }

    #[derive(Debug)]
    struct TestCase {
        certified_height: Height,
        current_height: Height,
        replica_version: ReplicaVersion,
        halt_at_cup_height: bool,
        subnet_splitting_status: Option<SubnetSplittingStatus>,
        subnet_id: SubnetId,
        expected_status: Option<Status>,
    }

    #[rstest]
    #[case::upgrade_finalized(TestCase{
        certified_height: CUP_HEIGHT,
        current_height: CUP_HEIGHT,
        replica_version: ReplicaVersion::try_from("new_replica_version").unwrap(),
        halt_at_cup_height: false,
        subnet_splitting_status: None,
        subnet_id: SUBNET_0,
        expected_status: Some(Status::Halted),
    })]
    #[case::upgrade_pending(TestCase{
        certified_height: CUP_HEIGHT.decrement(),
        current_height: CUP_HEIGHT,
        replica_version: ReplicaVersion::try_from("new_replica_version").unwrap(),
        halt_at_cup_height: false,
        subnet_splitting_status: None,
        subnet_id: SUBNET_0,
        expected_status: Some(Status::Halting),
    })]
    #[case::subnet_splitting_finalized(TestCase{
        certified_height: CUP_HEIGHT,
        current_height: CUP_HEIGHT,
        replica_version: ReplicaVersion::default(),
        halt_at_cup_height: false,
        subnet_splitting_status: Some(SubnetSplittingStatus::Scheduled(SplittingArgs { destination_subnet_id: SUBNET_0, source_subnet_id: SUBNET_1 })),
        subnet_id: SUBNET_0,
        expected_status: Some(Status::Halted),
    })]
    #[case::subnet_splitting_pending(TestCase{
        certified_height: CUP_HEIGHT.decrement(),
        current_height: CUP_HEIGHT,
        replica_version: ReplicaVersion::default(),
        halt_at_cup_height: false,
        subnet_splitting_status: Some(SubnetSplittingStatus::Scheduled(SplittingArgs { destination_subnet_id: SUBNET_0, source_subnet_id: SUBNET_1 })),
        subnet_id: SUBNET_0,
        expected_status: Some(Status::Halting),
    })]
    #[case::post_subnet_splitting_old_subnet_id(TestCase{
        certified_height: CUP_HEIGHT.decrement(),
        current_height: CUP_HEIGHT,
        replica_version: ReplicaVersion::default(),
        halt_at_cup_height: false,
        subnet_splitting_status: Some(SubnetSplittingStatus::PostSplit { new_subnet_id: SUBNET_0 }),
        subnet_id: SUBNET_1,
        expected_status: Some(Status::Halted),
    })]
    #[case::post_subnet_splitting_new_subnet_id(TestCase{
        certified_height: CUP_HEIGHT.decrement(),
        current_height: CUP_HEIGHT,
        replica_version: ReplicaVersion::default(),
        halt_at_cup_height: false,
        subnet_splitting_status: Some(SubnetSplittingStatus::PostSplit { new_subnet_id: SUBNET_0 }),
        subnet_id: SUBNET_0,
        expected_status: Some(Status::Running),
    })]
    #[case::halt_at_cup_height(TestCase{
        certified_height: CUP_HEIGHT,
        current_height: CUP_HEIGHT,
        replica_version: ReplicaVersion::default(),
        halt_at_cup_height: true,
        subnet_splitting_status: None,
        subnet_id: SUBNET_0,
        expected_status: Some(Status::Halted),
    })]
    #[case::halting_at_cup_height(TestCase{
        certified_height: CUP_HEIGHT.decrement(),
        current_height: CUP_HEIGHT,
        replica_version: ReplicaVersion::default(),
        halt_at_cup_height: true,
        subnet_splitting_status: None,
        subnet_id: SUBNET_0,
        expected_status: Some(Status::Halting),
    })]
    #[case::running(TestCase{
        certified_height: CUP_HEIGHT,
        current_height: CUP_HEIGHT,
        replica_version: ReplicaVersion::default(),
        halt_at_cup_height: false,
        subnet_splitting_status: None,
        subnet_id: SUBNET_0,
        expected_status: Some(Status::Running),
    })]
    fn status_test(#[case] test_case: TestCase) {
        with_test_replica_logger(|logger| {
            ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
                use ic_types::consensus::backwards_compatibility::BackwardsCompatibleOption;

                let (pool, registry_client) = set_up(
                    pool_config,
                    test_case.subnet_id,
                    test_case.certified_height,
                    test_case.replica_version,
                    test_case.halt_at_cup_height,
                );
                let mut last_summary_block =
                    PoolReader::new(&pool).get_highest_finalized_summary_block();
                let mut payload = last_summary_block.payload.as_ref().as_summary().clone();
                payload.dkg.subnet_splitting_status =
                    BackwardsCompatibleOption::new_for_test_only(test_case.subnet_splitting_status);
                last_summary_block.payload =
                    Payload::new(crypto_hash, BlockPayload::Summary(payload));

                let status = get_status(
                    test_case.current_height,
                    &last_summary_block,
                    registry_client.as_ref(),
                    test_case.subnet_id,
                    &PoolReader::new(&pool),
                    &logger,
                );

                assert_eq!(status, test_case.expected_status);
            })
        })
    }
}
