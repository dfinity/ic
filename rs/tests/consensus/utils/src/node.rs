use ic_system_test_driver::{
    driver::test_env_api::{
        HasPublicApiUrl, IcNodeContainer, IcNodeSnapshot, ORCHESTRATOR_METRICS_PORT,
        READY_WAIT_TIMEOUT, REPLICA_METRICS_PORT, RETRY_BACKOFF, SshSession, SubnetSnapshot, secs,
    },
    util::{MetricsFetcher, block_on},
};
use ic_types::{Height, RegistryVersion};

use anyhow::{Result, anyhow, bail, ensure};
use slog::{Logger, info};
use ssh2::Session;
use std::fmt::Debug;
use std::time::Duration;

use crate::ssh_access::execute_bash_command;

pub fn await_node_certified_height(node: &IcNodeSnapshot, target_height: Height, log: Logger) {
    ic_system_test_driver::retry_with_msg!(
        format!(
            "check if node {} is at height {}",
            node.node_id, target_height
        ),
        log,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || {
            node.status()
                .and_then(|response| match response.certified_height {
                    Some(height) if height > target_height => Ok(()),
                    Some(height) => bail!(
                        "Target height not yet reached, height: {}, target: {}",
                        height,
                        target_height
                    ),
                    None => bail!("Certified height not available"),
                })
        }
    )
    .expect("The node did not reach the specified height in time")
}

pub fn get_node_certified_height(node: &IcNodeSnapshot, log: Logger) -> Height {
    ic_system_test_driver::retry_with_msg!(
        format!("get certified height of node {}", node.node_id),
        log,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || {
            node.status().and_then(|response| {
                response
                    .certified_height
                    .ok_or_else(|| anyhow!("Certified height not available"))
            })
        }
    )
    .expect("Should be able to retrieve the certified height")
}

/// Assert that the given node has a state and local CUP within the next 5 minutes.
pub fn assert_node_is_assigned(node: &IcNodeSnapshot, logger: &Logger) {
    assert_node_is_assigned_with_ssh_session(node, None, logger)
}

/// Assert that the given node has a state and local CUP within the next 5 minutes.
/// Reuses the provided SSH session if given, otherwise creates a new one.
pub fn assert_node_is_assigned_with_ssh_session(
    node: &IcNodeSnapshot,
    existing_session: Option<&Session>,
    logger: &Logger,
) {
    info!(
        logger,
        "Asserting that node {} has a state and local CUP.",
        node.get_ip_addr()
    );
    // We consider the node to be assigned if it has both a subnet state
    // and a local CUP
    // We need to exclude the page_deltas/ directory, which is not deleted on state deletion.
    // That is because deleting it would break SELinux assumptions.
    let check = r#"
        [ "$(ls -A /var/lib/ic/data/ic_state -I page_deltas)" ] && \
        [ -f /var/lib/ic/data/cups/cup.types.v1.CatchUpPackage.pb ] && \
        echo "assigned" || echo "unassigned"
    "#;
    let s = existing_session.cloned().unwrap_or_else(|| {
        node.block_on_ssh_session()
            .expect("Failed to establish SSH session")
    });

    ic_system_test_driver::retry_with_msg!(
        format!("check if node {} is assigned", node.node_id),
        logger.clone(),
        secs(300),
        secs(10),
        || match execute_bash_command(&s, check.to_string()) {
            Ok(s) if s.trim() == "assigned" => Ok(()),
            Ok(s) if s.trim() == "unassigned" => {
                bail!("Node {} is unassigned.", node.get_ip_addr())
            }
            Ok(s) => bail!("Received unexpected output: {}", s),
            Err(e) => bail!("Failed to read directory: {}", e),
        }
    )
    .expect("Failed to detect that node has a state and local CUP.");
}

/// Assert that the node deletes its state and local CUP within 5 minutes, then trims within 2 more.
///
/// `fstrim_count_before` is [`get_node_fstrim_count`] read before the unassignment was triggered.
pub fn assert_node_is_unassigned(node: &IcNodeSnapshot, fstrim_count_before: u64, logger: &Logger) {
    assert_node_is_unassigned_with_ssh_session(node, None, fstrim_count_before, logger)
}

/// Return how often the given node has synced and trimmed its filesystem after removing its state.
///
/// Read this before triggering an unassignment and pass it to [`assert_node_is_unassigned`], which
/// waits for the count to grow. A fixed threshold wouldn't do: the count survives re-assignment, so
/// a node unassigned twice starts out non-zero. It does reset if the orchestrator restarts.
pub fn get_node_fstrim_count(node: &IcNodeSnapshot, logger: &Logger) -> u64 {
    ic_system_test_driver::retry_with_msg!(
        format!("fetching the fstrim count of node {}", node.node_id),
        logger.clone(),
        secs(120),
        secs(10),
        || block_on(fetch_metric_from_nodes::<u64>(
            vec![node.clone()],
            FSTRIM_TOTAL
        ))
        .map(|counts| counts[0])
    )
    .expect("Failed to fetch the fstrim count of the node.")
}

/// Assert that the node deletes its state and local CUP within 5 minutes, then trims within 2 more.
/// Reuses the provided SSH session if given, otherwise creates a new one.
pub fn assert_node_is_unassigned_with_ssh_session(
    node: &IcNodeSnapshot,
    existing_session: Option<&Session>,
    fstrim_count_before: u64,
    logger: &Logger,
) {
    info!(
        logger,
        "Asserting that node {} has deleted its state and local CUP.",
        node.get_ip_addr()
    );
    // We consider the node to be unassigned once it deleted both the state directory and the
    // local CUP.
    // We need to exclude the page_deltas/ directory, which is not deleted on state deletion.
    // That is because deleting it would break SELinux assumptions.
    let check = r#"
        ([ "$(ls -A /var/lib/ic/data/ic_state -I page_deltas)" ] || \
        [ -f /var/lib/ic/data/cups/cup.types.v1.CatchUpPackage.pb ]) && \
        echo "assigned" || echo "unassigned"
    "#;
    let s = existing_session.cloned().unwrap_or_else(|| {
        node.block_on_ssh_session()
            .expect("Failed to establish SSH session")
    });

    ic_system_test_driver::retry_with_msg!(
        format!("check if node {} is unassigned", node.node_id),
        logger.clone(),
        secs(300),
        secs(10),
        || match execute_bash_command(&s, check.to_string()) {
            Ok(s) if s.trim() == "unassigned" => Ok(()),
            Ok(s) if s.trim() == "assigned" => {
                bail!("Node {} is still assigned.", node.get_ip_addr())
            }
            Ok(s) => bail!("Received unexpected output: {}", s),
            Err(e) => bail!("Failed to read directory: {}", e),
        }
    )
    .expect("Failed to detect that node has deleted its state and local CUP.");

    const STATE_REMOVAL_FAILED: &str = "orchestrator_state_removal_failed_total";
    let fetcher = MetricsFetcher::new_with_port(
        std::iter::once(node.clone()),
        vec![STATE_REMOVAL_FAILED.to_string(), FSTRIM_TOTAL.0.to_string()],
        ORCHESTRATOR_METRICS_PORT,
    );

    ic_system_test_driver::retry_with_msg!(
        format!("fetching metrics of node {}", node.node_id),
        logger.clone(),
        secs(120),
        secs(10),
        || match block_on(fetcher.fetch::<u64>()) {
            Ok(metrics) => {
                // This counter never goes back to zero, so retrying wouldn't help.
                assert_eq!(
                    metrics[STATE_REMOVAL_FAILED][0],
                    0,
                    "Node {} failed to remove its state",
                    node.get_ip_addr()
                );
                // Bumped only after the removal and the trim, so the check above can pass first.
                ensure!(
                    metrics[FSTRIM_TOTAL.0][0] > fstrim_count_before,
                    "Node {} has not finished trimming its filesystem yet.",
                    node.get_ip_addr()
                );
                Ok(())
            }
            Err(e) => bail!("Failed to fetch metrics: {}", e),
        }
    )
    .expect("Failed to detect that node has deleted its state and trimmed its filesystem.");
}

async fn fetch_metric_from_nodes<T>(
    nodes: Vec<IcNodeSnapshot>,
    (metric_name, metric_port): (&str, u16),
) -> Result<Vec<T>>
where
    T: Copy + Debug + std::str::FromStr,
{
    let metrics_fetcher = MetricsFetcher::new_with_port(
        nodes.iter().cloned(),
        vec![metric_name.to_string()],
        metric_port,
    );
    let metrics = metrics_fetcher
        .fetch::<T>()
        .await
        .map_err(|err| anyhow!("Could not connect to metrics yet {:?}", err))?;

    // Empty if no node exports it yet, so the check below reports it instead of panicking.
    let vals = metrics.get(metric_name).cloned().unwrap_or_default();
    if vals.len() != nodes.len() {
        bail!(
            "Metrics not available for all nodes yet. {} metrics, {} nodes",
            vals.len(),
            nodes.len()
        );
    }

    Ok(vals)
}

async fn await_metric_registry_version(
    (metric_name, metric_port): (&str, u16),
    log_text: &str,
    nodes: Vec<IcNodeSnapshot>,
    target_version: RegistryVersion,
    logger: &Logger,
    retry_timeout: Duration,
    retry_backoff: Duration,
) {
    info!(logger, "{}", log_text);
    ic_system_test_driver::retry_with_msg_async!(
        log_text,
        logger,
        retry_timeout,
        retry_backoff,
        || async {
            fetch_metric_from_nodes::<u64>(nodes.clone(), (metric_name, metric_port))
                .await
                .and_then(|registry_versions| {
                    let min_registry_version = registry_versions.iter().min().unwrap();
                    assert!(
                        *min_registry_version <= target_version.get(),
                        "Target version already surpassed"
                    );
                    ensure!(
                        *min_registry_version == target_version.get(),
                        "Target registry version not yet reached, current: {:?}, target: {}",
                        registry_versions,
                        target_version
                    );
                    Ok(())
                })
        }
    )
    .await
    .expect("The nodes did not reach the specified registry version in time")
}

const FSTRIM_TOTAL: (&str, u16) = ("orchestrator_fstrim_total", ORCHESTRATOR_METRICS_PORT);

const EARLIEST_TOPOLOGY_VERSION: (&str, u16) = (
    "peer_manager_topology_earliest_registry_version",
    REPLICA_METRICS_PORT,
);

pub fn get_node_earliest_topology_version(node: &IcNodeSnapshot) -> Result<RegistryVersion> {
    block_on(fetch_metric_from_nodes::<u64>(
        vec![node.clone()],
        EARLIEST_TOPOLOGY_VERSION,
    ))
    .map(|versions| RegistryVersion::from(versions[0]))
}

pub fn await_subnet_earliest_topology_version(
    subnet: &SubnetSnapshot,
    target_version: RegistryVersion,
    logger: &Logger,
) {
    block_on(await_subnet_earliest_topology_version_with_retries_async(
        subnet,
        target_version,
        logger,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
    ))
}

pub async fn await_subnet_earliest_topology_version_with_retries_async(
    subnet: &SubnetSnapshot,
    target_version: RegistryVersion,
    logger: &Logger,
    retry_timeout: Duration,
    retry_backoff: Duration,
) {
    await_metric_registry_version(
        EARLIEST_TOPOLOGY_VERSION,
        &format!(
            "Waiting until earliest topology version {} on subnet {}",
            target_version, subnet.subnet_id,
        ),
        subnet.nodes().collect(),
        target_version,
        logger,
        retry_timeout,
        retry_backoff,
    )
    .await
}

const FIREWALL_REGISTRY_VERSION: (&str, u16) =
    ("firewall_registry_version", ORCHESTRATOR_METRICS_PORT);

pub async fn await_subnet_firewall_registry_version_with_retries_async(
    subnet: &SubnetSnapshot,
    target_version: RegistryVersion,
    logger: &Logger,
    retry_timeout: Duration,
    retry_backoff: Duration,
) {
    await_metric_registry_version(
        FIREWALL_REGISTRY_VERSION,
        &format!(
            "Waiting until firewall registry version {} on subnet {}",
            target_version, subnet.subnet_id,
        ),
        subnet.nodes().collect(),
        target_version,
        logger,
        retry_timeout,
        retry_backoff,
    )
    .await
}
