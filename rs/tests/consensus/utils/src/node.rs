use ic_system_test_driver::driver::test_env_api::{IcNodeContainer, SubnetSnapshot, secs};
use ic_system_test_driver::{
    driver::test_env_api::{
        HasPublicApiUrl, IcNodeSnapshot, READY_WAIT_TIMEOUT, RETRY_BACKOFF, SshSession,
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

/// Assert that the given node has deleted its state within the next 5 minutes.
pub fn assert_node_is_unassigned(node: &IcNodeSnapshot, logger: &Logger) {
    assert_node_is_unassigned_with_ssh_session(node, None, logger)
}

/// Assert that the given node has deleted its state within the next 5 minutes.
/// Reuses the provided SSH session if given, otherwise creates a new one.
pub fn assert_node_is_unassigned_with_ssh_session(
    node: &IcNodeSnapshot,
    existing_session: Option<&Session>,
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

    let state_removal_failed = "orchestrator_state_removal_failed_total".to_string();
    let fs_trim_duration = "orchestrator_fstrim_duration_milliseconds".to_string();
    let fetcher = MetricsFetcher::new_with_port(
        std::iter::once(node.clone()),
        vec![state_removal_failed.clone(), fs_trim_duration.clone()],
        9091,
    );

    ic_system_test_driver::retry_with_msg!(
        format!("fetching metrics of node {}", node.node_id),
        logger.clone(),
        secs(120),
        secs(10),
        || match block_on(fetcher.fetch::<u64>()) {
            Ok(metrics) => {
                assert_eq!(metrics[&state_removal_failed][0], 0);
                assert!(metrics[&fs_trim_duration][0] > 0);
                Ok(())
            }
            Err(e) => bail!("Failed to fetch metrics: {}", e),
        }
    )
    .expect("Failed to detect that node has deleted its state.");
}

fn fetch_metric_from_nodes<T>(nodes: Vec<IcNodeSnapshot>, metric_name: &str) -> Result<Vec<T>>
where
    T: Copy + Debug + std::str::FromStr,
{
    let metrics_fetcher = MetricsFetcher::new(nodes.iter().cloned(), vec![metric_name.to_string()]);
    let metrics = block_on(metrics_fetcher.fetch::<T>())
        .map_err(|err| anyhow!("Could not connect to metrics yet {:?}", err))?;

    let vals = metrics[metric_name].clone();
    if vals.len() != nodes.len() {
        bail!(
            "Metrics not available for all nodes yet. {} metrics, {} nodes",
            vals.len(),
            nodes.len()
        );
    }

    Ok(vals)
}

const EARLIEST_TOPOLOGY_VERSION: &str = "peer_manager_topology_earliest_registry_version";

pub fn get_node_earliest_topology_version(node: &IcNodeSnapshot) -> Result<RegistryVersion> {
    fetch_metric_from_nodes::<u64>(vec![node.clone()], EARLIEST_TOPOLOGY_VERSION)
        .map(|versions| RegistryVersion::from(versions[0]))
}

pub fn await_subnet_earliest_topology_version(
    subnet: &SubnetSnapshot,
    target_version: RegistryVersion,
    logger: &Logger,
) {
    await_subnet_earliest_topology_version_with_retries(
        subnet,
        target_version,
        logger,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
    )
}

pub fn await_subnet_earliest_topology_version_with_retries(
    subnet: &SubnetSnapshot,
    target_version: RegistryVersion,
    logger: &Logger,
    retry_timeout: Duration,
    retry_backoff: Duration,
) {
    info!(
        logger,
        "Waiting until earliest topology version {} on subnet {}", target_version, subnet.subnet_id,
    );
    ic_system_test_driver::retry_with_msg!(
        format!(
            "Waiting until earliest topology version {} on subnet {}",
            target_version, subnet.subnet_id,
        ),
        logger.clone(),
        retry_timeout,
        retry_backoff,
        || fetch_metric_from_nodes::<u64>(subnet.nodes().collect(), EARLIEST_TOPOLOGY_VERSION)
            .and_then(|earliest_registry_versions| {
                let min_earliest_registry_version =
                    earliest_registry_versions.iter().min().unwrap();
                assert!(
                    *min_earliest_registry_version <= target_version.get(),
                    "Target version already surpassed"
                );
                ensure!(
                    *min_earliest_registry_version == target_version.get(),
                    "Target registry version not yet reached, current: {:?}, target: {}",
                    earliest_registry_versions,
                    target_version
                );
                Ok(())
            })
    )
    .expect("The subnet did not reach the specified registry version in time")
}
