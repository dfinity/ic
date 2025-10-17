use candid::Principal;
use ic_consensus_system_test_utils::rw_message::{can_read_msg, cannot_store_msg};
use ic_recovery::{get_node_metrics, steps::Step};
use ic_system_test_driver::{
    driver::test_env_api::{IcNodeContainer, IcNodeSnapshot, SshSession, SubnetSnapshot},
    util::block_on,
};
use slog::{Logger, info};
use std::fmt::Debug;
use url::Url;

/// Break the replica binary on the given nodes
pub fn break_nodes<T>(nodes: &[T], logger: &Logger)
where
    T: SshSession,
{
    info!(
        logger,
        "Breaking the subnet by breaking the replica binary on {} nodes...",
        nodes.len()
    );

    // Simulate subnet failure by breaking the replica process, but not the orchestrator
    let ssh_command =
        "sudo mount --bind /bin/false /opt/ic/bin/replica && sudo systemctl restart ic-replica";
    for node in nodes {
        let ip = node.get_host_ip().unwrap();
        info!(logger, "Breaking the replica on node with IP {ip}");

        node.block_on_bash_script(ssh_command)
            .unwrap_or_else(|_| panic!("SSH command failed on node with IP {ip}"));
    }
}

/// A subnet is considered to be broken if it (potentially) still works in read mode, but doesn't
/// in write mode.
pub fn assert_subnet_is_broken(
    node_url: &Url,
    can_id: Principal,
    msg: &str,
    can_read: bool,
    logger: &Logger,
) {
    if can_read {
        info!(logger, "Ensure the subnet works in read mode");
        assert!(
            can_read_msg(logger, node_url, can_id, msg),
            "Failed to read message on node: {node_url}"
        );
    }
    info!(
        logger,
        "Ensure the subnet doesn't work in write mode anymore"
    );
    assert!(
        cannot_store_msg(logger.clone(), node_url, can_id, msg),
        "Writing messages still successful on: {node_url}"
    );
}

/// Select a node with highest certification share height in the given subnet snapshot
pub fn node_with_highest_certification_share_height(
    subnet: &SubnetSnapshot,
    logger: &Logger,
) -> (IcNodeSnapshot, u64) {
    subnet
        .nodes()
        .filter_map(|n| {
            block_on(get_node_metrics(logger, &n.get_ip_addr()))
                .map(|m| (n, m.certification_share_height.get()))
        })
        .max_by_key(|&(_, cert_height)| cert_height)
        .expect("No healthy node found")
}

/// Execute all recovery steps remotely, i.e. from the test driver
pub fn remote_recovery<Recovery, StepType>(recovery: Recovery, logger: &Logger)
where
    Recovery: IntoIterator<Item = (StepType, Box<dyn Step>)>,
    StepType: Debug,
{
    for (step_type, step) in recovery {
        info!(logger, "Next step: {:?}", step_type);

        info!(logger, "{}", step.descr());
        step.exec()
            .unwrap_or_else(|e| panic!("Execution of step {step_type:?} failed: {e}"));
    }
}

