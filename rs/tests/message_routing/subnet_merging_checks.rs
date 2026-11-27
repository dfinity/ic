use anyhow::ensure;
use ic_recovery::{IC_CHECKPOINTS_PATH, IC_DATA_PATH};
use ic_subnet_merging::metrics_helper::{fetch_available_metrics, replica_values};
use ic_system_test_driver::driver::test_env_api::{
    HasRegistryVersion, IcNodeSnapshot, RETRY_BACKOFF, SshSession, TopologySnapshot,
};
use ic_system_test_driver::retry_with_msg_async;
use ic_types::SubnetId;
use slog::{Logger, info};
use std::time::Duration;

const REPLICA_RESTART_TIMEOUT: Duration = Duration::from_secs(300);
const METRIC_MAX_RESIDENT_HEIGHT: &str = "state_manager_max_resident_height";

/// Checks that the destination node holds no checkpoint below the merged
/// checkpoint, i.e. the checkpoint its subnet halted at was replaced, and that
/// its replica runs at or above the height of the merged checkpoint.
///
/// Both still hold once the destination subnet is unhalted, when the replica
/// creates newer checkpoints and may delete the merged one.
pub(crate) async fn check_merged_state_running(
    logger: &Logger,
    node: &IcNodeSnapshot,
    merged_checkpoint: &str,
) {
    let node_ip = node.get_ip_addr();
    let checkpoints_dir = format!("{IC_DATA_PATH}/{IC_CHECKPOINTS_PATH}");
    let height = |checkpoint: &str| {
        u64::from_str_radix(checkpoint, 16)
            .unwrap_or_else(|e| panic!("checkpoint {checkpoint} is not named by its height: {e}"))
    };
    let merged_height = height(merged_checkpoint);
    let checkpoints = node
        .block_on_bash_script_async(&format!("sudo ls {checkpoints_dir}"))
        .await
        .unwrap_or_else(|e| panic!("failed to list {checkpoints_dir} on node {node_ip}: {e}"));
    let checkpoints: Vec<_> = checkpoints.split_whitespace().collect();
    assert!(
        !checkpoints.is_empty()
            && checkpoints
                .iter()
                .all(|checkpoint| height(checkpoint) >= merged_height),
        "{checkpoints_dir} on node {node_ip} holds checkpoints {checkpoints:?}, expected none \
         below the merged checkpoint {merged_checkpoint}",
    );

    // The state manager sets this metric to the height of the checkpoint it
    // starts from, and raises it as the subnet makes progress.
    retry_with_msg_async!(
        format!("node {node_ip} reporting {METRIC_MAX_RESIDENT_HEIGHT} {merged_height}"),
        logger,
        REPLICA_RESTART_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            let (metrics, error) =
                fetch_available_metrics(&[node_ip], &[METRIC_MAX_RESIDENT_HEIGHT]).await;
            if let Some(error) = error {
                return Err(error.into());
            }
            let heights: Vec<_> = metrics
                .get(&node_ip)
                .into_iter()
                .flat_map(|metrics| replica_values(metrics, METRIC_MAX_RESIDENT_HEIGHT, |_| true))
                .collect();
            ensure!(
                matches!(heights[..], [height] if height >= merged_height as f64),
                "node {node_ip} reports {METRIC_MAX_RESIDENT_HEIGHT} {heights:?}"
            );
            Ok(())
        }
    )
    .await
    .unwrap_or_else(|e| {
        panic!("the replica on node {node_ip} did not start from the merged state: {e}")
    });
}

/// Checks that the registry no longer holds the source subnet, after syncing
/// `topology` to the newest registry version.
///
/// Precondition: the registry canister has already deleted the source subnet,
/// so a single sync suffices and the check does not wait for the deletion.
pub(crate) async fn check_source_subnet_deleted(
    logger: &Logger,
    topology: &TopologySnapshot,
    source_subnet_id: SubnetId,
) {
    let topology = topology
        .block_for_newest_mainnet_registry_version()
        .await
        .expect("failed to sync the registry with the NNS");
    let remaining: Vec<_> = topology.subnets().map(|subnet| subnet.subnet_id).collect();
    assert!(
        !remaining.contains(&source_subnet_id),
        "subnet {source_subnet_id} is still in the registry at version {}: {remaining:?}",
        topology.get_registry_version(),
    );
    info!(
        logger,
        "Subnet {source_subnet_id} is gone as of registry version {}; the remaining subnets are \
         {remaining:?}",
        topology.get_registry_version(),
    );
}
