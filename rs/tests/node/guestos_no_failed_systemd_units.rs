use anyhow::Result;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        constants::SSH_USERNAME,
        driver_setup::SSH_AUTHORIZED_PRIV_KEYS_DIR,
        group::SystemTestGroup,
        ic::InternetComputer,
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, SshSession},
    },
    systest,
};
use slog::info;
use std::process::Command;

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

/// Wait for GuestOS nodes to be SSH-accessible and then assert that no systemd
/// units have failed on any of them.
fn check_no_failed_systemd_units(env: TestEnv) {
    let logger = env.logger();
    let topology = env.topology_snapshot();

    for node in topology.subnets().flat_map(|s| s.nodes()) {
        node.await_status_is_healthy()
            .expect("Node's status endpoint didn't report healthy");
        node.await_can_login_as_admin_via_ssh()
            .expect("Failed to establish SSH session to GuestOS node");

        let failed_units = node
            .block_on_bash_script("systemctl list-units --failed --no-legend --no-pager --plain")
            .expect("Failed to run systemctl list-units --failed on GuestOS node");
        info!(
            logger,
            "Node {}: systemctl list-units --failed:\n{}", node.node_id, failed_units
        );
        if !failed_units.trim().is_empty() {
            for line in failed_units.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                // With `--plain`, lines have no leading status glyph or tree
                // structure, so the first whitespace-separated token is the
                // unit name.
                let Some(unit) = line.split_whitespace().next() else {
                    continue;
                };
                let cmd = format!("journalctl -u '{}' --no-pager -n 500", unit);
                match node.block_on_bash_script(&cmd) {
                    Ok(journal) => info!(
                        logger,
                        "Node {}: journalctl -u {} (last 500 lines):\n{}",
                        node.node_id,
                        unit,
                        journal
                    ),
                    Err(err) => info!(
                        logger,
                        "Node {}: failed to fetch journalctl logs for unit {}: {}",
                        node.node_id,
                        unit,
                        err
                    ),
                }
            }
        }
        assert!(
            failed_units.trim().is_empty(),
            "Node {} has failed systemd units:\n{}",
            node.node_id,
            failed_units
        );
    }
    info!(logger, "No failed systemd units found on any GuestOS node.");
}

/// Assert that the kernel took `oops=panic panic=10 softlockup_panic=1
/// watchdog_thresh=60` from the command line
/// (ic-os/bootloader/guestos_boot_args.template): a GuestOS that hits a kernel
/// Oops, panic or soft lockup must reboot instead of hanging. Shares this
/// group's single node to avoid a dedicated target.
fn check_kernel_panic_params(env: TestEnv) {
    let logger = env.logger();
    for node in env.topology_snapshot().subnets().flat_map(|s| s.nodes()) {
        node.await_can_login_as_admin_via_ssh()
            .expect("Failed to establish SSH session to GuestOS node");
        let out = node
            .block_on_bash_script(
                "cat /proc/cmdline; cd /proc/sys/kernel && \
                 cat panic_on_oops panic softlockup_panic watchdog_thresh soft_watchdog",
            )
            .expect("Failed to read the kernel cmdline and panic/lockup sysctls on GuestOS node");
        info!(
            logger,
            "Node {}: kernel cmdline and panic/lockup sysctls:\n{}", node.node_id, out
        );
        let mut lines = out.lines();
        let cmdline: Vec<&str> = lines
            .next()
            .unwrap_or_default()
            .split_whitespace()
            .collect();
        for param in [
            "oops=panic",
            "panic=10",
            "softlockup_panic=1",
            "watchdog_thresh=60",
        ] {
            assert!(
                cmdline.contains(&param),
                "Node {} did not boot with {param}:\n{}",
                node.node_id,
                out
            );
        }
        // kernel.panic_on_oops, kernel.panic, kernel.softlockup_panic, kernel.watchdog_thresh and
        // kernel.soft_watchdog (the soft-lockup detector is enabled), in the order read above.
        assert_eq!(
            lines.collect::<Vec<_>>(),
            ["1", "10", "1", "60", "1"],
            "Node {}: unexpected panic/lockup sysctls:\n{}",
            node.node_id,
            out
        );
    }
}

/// Assert that SSH agent forwarding works: log in to each node with `ssh -A`
/// and, from there, log in to the node again using only the forwarded agent.
fn check_ssh_agent_forwarding(env: TestEnv) {
    let logger = env.logger();
    let admin_key = env
        .get_path(SSH_AUTHORIZED_PRIV_KEYS_DIR)
        .join(SSH_USERNAME);
    for node in env.topology_snapshot().subnets().flat_map(|s| s.nodes()) {
        node.await_can_login_as_admin_via_ssh()
            .expect("Failed to establish SSH session to GuestOS node");
        // The test's temporary directory is too long for the path of a Unix socket.
        let agent_dir = tempfile::Builder::new()
            .prefix("ssh-agent")
            .tempdir_in("/tmp")
            .expect("Failed to create a directory for the SSH agent socket");
        let ssh = format!(
            "ssh -A -F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=no \
             -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR admin@{}",
            node.get_ip_addr()
        );
        // Lists the key of a fresh agent locally and, after two hops of agent
        // forwarding, on the node.
        let script = format!(
            r#"ssh-add -q "$1" && ssh-add -l && {ssh} 'echo "SSH_AUTH_SOCK=$SSH_AUTH_SOCK" >&2; {ssh} ssh-add -l'"#
        );
        let out = Command::new("ssh-agent")
            .arg("-a")
            .arg(agent_dir.path().join("agent.sock"))
            .args(["sh", "-c", &script, "sh"])
            .arg(&admin_key)
            .output()
            .expect("Failed to run ssh-agent");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        info!(
            logger,
            "Node {}: SSH agent forwarding ({}):\nstdout:\n{}stderr:\n{}",
            node.node_id,
            out.status,
            stdout,
            stderr
        );
        let lines: Vec<&str> = stdout.lines().collect();
        assert!(
            out.status.success() && lines.len() == 2 && lines[0] == lines[1],
            "Node {}: the forwarded agent did not list the local key ({}):\nstdout:\n{}stderr:\n{}",
            node.node_id,
            out.status,
            stdout,
            stderr
        );
    }
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(check_no_failed_systemd_units))
        .add_test(systest!(check_kernel_panic_params))
        .add_test(systest!(check_ssh_agent_forwarding))
        .execute_from_args()?;

    Ok(())
}
