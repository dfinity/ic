use std::fmt::Display;

use ic_consensus_utils::{is_upgrade_pending, pool_reader::PoolReader};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{warn, ReplicaLogger};
use ic_types::{Height, SubnetId};

#[derive(Debug, Eq, PartialEq)]
pub enum Status {
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
/// * [Status::Halting] when there is a pending upgrade;
/// * [Status::Halted] when an upgrade is finalized;
/// * [Status::Running] when no upgrade is in progress.
pub fn get_status(
    height: Height,
    registry_client: &(impl RegistryClient + ?Sized),
    subnet_id: SubnetId,
    pool: &PoolReader<'_>,
    logger: &ReplicaLogger,
) -> Option<Status> {
    let certified_height = pool.get_finalized_tip().context.certified_height;

    // Check if an upgrade is pending
    let upgrading = is_upgrade_pending(height, registry_client, subnet_id, logger, pool)
        .warn_if_none(logger, "Failed to check if the upgrade is pending!");
    if upgrading == Some(true) {
        // Check if an upgrade has been finalized
        if is_upgrade_pending(certified_height, registry_client, subnet_id, logger, pool)
            .warn_if_none(logger, "Failed to check if the upgrade has been finalized!")
            == Some(true)
        {
            return Some(Status::Halted);
        }

        return Some(Status::Halting);
    }

    if upgrading == Some(false) {
        return Some(Status::Running);
    }

    // If we are here then we were unable to determine if the subnet is upgrading.
    warn!(logger, "Failed to check the status of the subnet!");
    None
}

/// Utility trait which adds a [warn_if_none] function to the [Option] struct.
trait LogIfNone {
    /// Logs a warning if the option is None.
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
    use ic_consensus_mocks::{dependencies_with_subnet_params, Dependencies};
    use ic_logger::replica_logger::no_op_logger;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_test_artifact_pool::consensus_pool::{Round, TestConsensusPool};
    use ic_test_utilities::types::ids::{node_test_id, subnet_test_id};
    use ic_test_utilities_registry::SubnetRecordBuilder;
    use ic_types::ReplicaVersion;

    use super::*;

    fn set_up(
        pool_config: ArtifactPoolConfig,
        certified_height: Height,
        replica_version: ReplicaVersion,
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

    /// The replica version changes at height = 8
    /// CUP height = 8
    /// Certified height = 8
    /// Current height = 10
    ///
    /// Therefore the status should be [Status::Halted]
    #[test]
    fn halt_finalized_test() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let (pool, registry_client, subnet_id) = set_up(
                pool_config,
                Height::from(8),
                ReplicaVersion::try_from("new_replica_version").unwrap(),
            );

            let status = get_status(
                Height::from(10),
                registry_client.as_ref(),
                subnet_id,
                &PoolReader::new(&pool),
                &no_op_logger(),
            );

            assert_eq!(status, Some(Status::Halted));
        });
    }

    /// The replica version changes at height = 8
    /// CUP height = 8
    /// Certified height = 7
    /// Current height = 10
    ///
    /// Therefore the status should be [Status::Halting]
    #[test]
    fn halting_test() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let (pool, registry_client, subnet_id) = set_up(
                pool_config,
                Height::from(7),
                ReplicaVersion::try_from("new_replica_version").unwrap(),
            );

            let status = get_status(
                Height::from(10),
                registry_client.as_ref(),
                subnet_id,
                &PoolReader::new(&pool),
                &no_op_logger(),
            );

            assert_eq!(status, Some(Status::Halting));
        });
    }

    /// The replica version never changes
    /// CUP height = 8
    /// Certified height = 8
    /// Current height = 10
    ///
    /// Therefore the status should be [Status::Running]
    #[test]
    fn running_test() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let (pool, registry_client, subnet_id) =
                set_up(pool_config, Height::from(8), ReplicaVersion::default());

            let status = get_status(
                Height::from(10),
                registry_client.as_ref(),
                subnet_id,
                &PoolReader::new(&pool),
                &no_op_logger(),
            );

            assert_eq!(status, Some(Status::Running));
        });
    }
}
