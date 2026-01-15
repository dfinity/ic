use std::fmt::Display;

use ic_consensus_utils::{lookup_replica_version, pool_reader::PoolReader};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{ReplicaLogger, warn};
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_types::{Height, ReplicaVersion, SubnetId};

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
    registry_client: &(impl RegistryClient + ?Sized),
    subnet_id: SubnetId,
    pool: &PoolReader<'_>,
    logger: &ReplicaLogger,
) -> Option<Status> {
    if should_halt(height, registry_client, subnet_id, pool, logger)
        .warn_if_none(logger, "Failed to check if the subnet is halting!")?
    {
        let certified_height = pool.get_finalized_tip().context.certified_height;

        if should_halt(certified_height, registry_client, subnet_id, pool, logger)
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
    registry_client: &(impl RegistryClient + ?Sized),
    subnet_id: SubnetId,
    pool: &PoolReader<'_>,
    logger: &ReplicaLogger,
) -> Option<bool> {
    let registry_version = pool.registry_version(height).warn_if_none(
        logger,
        format!("Failed to get the registry version at height {height}"),
    )?;

    let upgrading = lookup_replica_version(registry_client, subnet_id, logger, registry_version)
        .map(|replica_version| replica_version != ReplicaVersion::default())
        .warn_if_none(logger, "Failed to check if the upgrade is pending!");

    let should_halt_by_subnet_record = registry_client
        .get_halt_at_cup_height(subnet_id, registry_version)
        .ok()
        .flatten()
        .warn_if_none(
            logger,
            format!(
                "Failed to check if the registry version at height {height} instructs the subnet to halt!",
            ),
        );

    match (upgrading, should_halt_by_subnet_record) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), Some(false)) => Some(false),
        (_, _) => None,
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
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::ReplicaVersion;

    use super::*;

    fn set_up(
        pool_config: ArtifactPoolConfig,
        certified_height: Height,
        replica_version: ReplicaVersion,
        halt_at_cup_height: bool,
    ) -> (TestConsensusPool, Arc<FakeRegistryClient>, SubnetId) {
        let dkg_interval_length = 3;
        let node_ids = [node_test_id(0)];
        let subnet_id = subnet_test_id(0);
        let Dependencies {
            mut pool, registry, ..
        } = dependencies_with_subnet_params(
            pool_config,
            subnet_id,
            vec![
                (
                    1,
                    SubnetRecordBuilder::from(&node_ids)
                        .with_dkg_interval_length(dkg_interval_length)
                        .build(),
                ),
                (
                    10,
                    SubnetRecordBuilder::from(&node_ids)
                        .with_dkg_interval_length(dkg_interval_length)
                        .with_replica_version(replica_version.as_ref())
                        .with_halt_at_cup_height(halt_at_cup_height)
                        .build(),
                ),
            ],
        );

        pool.advance_round_normal_operation_n(10);
        Round::new(&mut pool)
            .with_certified_height(certified_height)
            .advance();

        (pool, registry, subnet_id)
    }

    fn run_test_case(
        certified_height: Height,
        current_height: Height,
        replica_version: ReplicaVersion,
        halt_at_cup_height: bool,
        expected_status: Option<Status>,
    ) {
        with_test_replica_logger(|logger| {
            ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
                let (pool, registry_client, subnet_id) = set_up(
                    pool_config,
                    certified_height,
                    replica_version,
                    halt_at_cup_height,
                );

                let status = get_status(
                    current_height,
                    registry_client.as_ref(),
                    subnet_id,
                    &PoolReader::new(&pool),
                    &logger,
                );

                assert_eq!(status, expected_status);
            })
        })
    }

    /// The replica version changes at height = 8
    /// CUP height = 8
    /// Certified height = 8
    /// Current height = 10
    ///
    /// Therefore the status should be [Status::Halted]
    #[test]
    fn upgrade_finalized_test() {
        run_test_case(
            Height::from(8),
            Height::from(10),
            ReplicaVersion::try_from("new_replica_version").unwrap(),
            /*halt_at_cup_height=*/ false,
            Some(Status::Halted),
        );
    }

    /// The replica version changes at height = 8
    /// CUP height = 8
    /// Certified height = 7
    /// Current height = 10
    ///
    /// Therefore the status should be [Status::Halting]
    #[test]
    fn upgrade_pending_test() {
        run_test_case(
            Height::from(7),
            Height::from(10),
            ReplicaVersion::try_from("new_replica_version").unwrap(),
            /*halt_at_cup_height=*/ false,
            Some(Status::Halting),
        );
    }

    /// The registry version at height >= 8 has halt_at_cup_height = true.
    /// CUP height = 8
    /// Certified height = 8
    /// Current height = 10
    ///
    /// Therefore the status should be [Status::Halted]
    #[test]
    fn halt_finalized_test() {
        run_test_case(
            Height::from(8),
            Height::from(10),
            ReplicaVersion::default(),
            /*halt_at_cup_height=*/ true,
            Some(Status::Halted),
        );
    }

    /// The registry version at height >= 8 has halt_at_cup_height = true.
    /// CUP height = 8
    /// Certified height = 7
    /// Current height = 10
    ///
    /// Therefore the status should be [Status::Halting]
    #[test]
    fn halting_test() {
        run_test_case(
            Height::from(7),
            Height::from(10),
            ReplicaVersion::default(),
            /*halt_at_cup_height=*/ true,
            Some(Status::Halting),
        );
    }

    /// The replica version never changes and the registry doesn't instruct the subnet to halt.
    /// CUP height = 8
    /// Certified height = 7
    /// Current height = 10
    ///
    /// Therefore the status should be [Status::Running]
    #[test]
    fn running_test() {
        run_test_case(
            Height::from(7),
            Height::from(10),
            ReplicaVersion::default(),
            /*halt_at_cup_height=*/ false,
            Some(Status::Running),
        );
    }
}
