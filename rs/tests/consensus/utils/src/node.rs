use ic_system_test_driver::driver::test_env_api::secs;
use ic_system_test_driver::{
    driver::test_env_api::{
        HasPublicApiUrl, IcNodeSnapshot, SshSession, READY_WAIT_TIMEOUT, RETRY_BACKOFF,
    },
    util::{block_on, MetricsFetcher},
};
use ic_types::Height;

use anyhow::{anyhow, bail};
use slog::{info, Logger};

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
    let s = node
        .block_on_ssh_session()
        .expect("Failed to establish SSH session");

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
    let s = node
        .block_on_ssh_session()
        .expect("Failed to establish SSH session");

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
