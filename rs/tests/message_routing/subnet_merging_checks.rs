use anyhow::ensure;
use ic_recovery::{IC_CHECKPOINTS_PATH, IC_DATA_PATH};
use ic_subnet_merging::metrics_helper::{fetch_available_metrics, replica_values};
use ic_system_test_driver::driver::test_env_api::{IcNodeSnapshot, RETRY_BACKOFF, SshSession};
use ic_system_test_driver::retry_with_msg_async;
use slog::Logger;
use std::time::Duration;

const REPLICA_RESTART_TIMEOUT: Duration = Duration::from_secs(300);
const METRIC_MAX_RESIDENT_HEIGHT: &str = "state_manager_max_resident_height";

/// Checks that the destination node holds exactly the merged checkpoint and
/// that its replica reports the height of that checkpoint after restarting.
pub(crate) async fn check_merged_state_running(
    logger: &Logger,
    node: &IcNodeSnapshot,
    merged_checkpoint: &str,
) {
    let node_ip = node.get_ip_addr();
    let checkpoints_dir = format!("{IC_DATA_PATH}/{IC_CHECKPOINTS_PATH}");
    let checkpoints = node
        .block_on_bash_script_async(&format!("sudo ls {checkpoints_dir}"))
        .await
        .unwrap_or_else(|e| panic!("failed to list {checkpoints_dir} on node {node_ip}: {e}"));
    assert_eq!(
        checkpoints.split_whitespace().collect::<Vec<_>>(),
        [merged_checkpoint],
        "{checkpoints_dir} on node {node_ip} does not hold exactly the merged checkpoint",
    );

    let merged_height = u64::from_str_radix(merged_checkpoint, 16).unwrap_or_else(|e| {
        panic!("checkpoint {merged_checkpoint} is not named by its height: {e}")
    });
    // The state manager sets this metric to the height of the checkpoint it starts from.
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
                heights == [merged_height as f64],
                "node {node_ip} reports {METRIC_MAX_RESIDENT_HEIGHT} {heights:?}"
            );
            Ok(())
        }
    )
    .await
    .unwrap_or_else(|e| {
        panic!("the replica on node {node_ip} did not start from the merged checkpoint: {e}")
    });
}
