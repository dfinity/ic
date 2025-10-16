use ic_system_test_driver::driver::test_env_api::SshSession;
use slog::{Logger, info};

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

