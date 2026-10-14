use anyhow::Result;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::InternetComputer,
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, SshSession},
    },
    systest,
};
use slog::info;

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

/// Assert that the kernel took `oops=panic panic=10` from the command line
/// (ic-os/bootloader/guestos_boot_args.template): a GuestOS that Oopses or
/// panics must reboot instead of hanging. Shares this group's single node to
/// avoid a dedicated target.
fn check_kernel_panic_params(env: TestEnv) {
    let logger = env.logger();
    for node in env.topology_snapshot().subnets().flat_map(|s| s.nodes()) {
        node.await_can_login_as_admin_via_ssh()
            .expect("Failed to establish SSH session to GuestOS node");
        let out = node
            .block_on_bash_script(
                "cat /proc/cmdline; cat /proc/sys/kernel/panic_on_oops /proc/sys/kernel/panic",
            )
            .expect("Failed to read the kernel cmdline and panic sysctls on GuestOS node");
        info!(
            logger,
            "Node {}: kernel cmdline and panic sysctls:\n{}", node.node_id, out
        );
        let mut lines = out.lines();
        let cmdline: Vec<&str> = lines
            .next()
            .unwrap_or_default()
            .split_whitespace()
            .collect();
        assert!(
            cmdline.contains(&"oops=panic") && cmdline.contains(&"panic=10"),
            "Node {} did not boot with oops=panic panic=10:\n{}",
            node.node_id,
            out
        );
        assert_eq!(
            lines.collect::<Vec<_>>(),
            ["1", "10"],
            "Node {}: expected kernel.panic_on_oops=1 and kernel.panic=10:\n{}",
            node.node_id,
            out
        );
    }
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(check_no_failed_systemd_units))
        .add_test(systest!(check_kernel_panic_params))
        .execute_from_args()?;

    Ok(())
}
