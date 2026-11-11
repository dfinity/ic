use anyhow::{Result, bail};
use slog::info;
use std::time::Duration;

use ic_system_test_driver::{
    driver::{group::SystemTestGroup, nested::HasNestedVms, test_env::TestEnv, test_env_api::*},
    retry_with_msg, systest,
    util::block_on,
};

use nested::{HOST_VM_NAME, registration};

use nested::util::{
    NODE_UPGRADE_BACKOFF, NODE_UPGRADE_TIMEOUT, check_hostos_version, elect_hostos_version,
    try_get_host_boot_id, try_logging_guestos_diagnostics, update_nodes_hostos_version,
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(nested::setup)
        .add_test(systest!(upgrade_hostos))
        .add_test(systest!(check_metrics_proxy))
        .with_timeout_per_test(Duration::from_secs(30 * 60))
        .with_overall_timeout(Duration::from_secs(40 * 60))
        .execute_from_args()?;

    Ok(())
}

/// Upgrade each HostOS VM to the target version, and verify that each is
/// healthy before and after the upgrade.
pub fn upgrade_hostos(env: TestEnv) {
    let logger = env.logger();

    let original_version = get_hostos_version();
    let target_version = get_hostos_update_img_version();
    let update_image_url = get_hostos_update_img_url(&env);
    let update_image_sha256 = get_hostos_update_img_sha256();

    info!(logger, "Image configuration:");
    info!(logger, "  Original HostOS version: {original_version}");
    info!(logger, "  Target HostOS version: {target_version}");
    info!(logger, "  Update image URL: {update_image_url}");
    info!(logger, "  Update image SHA256: {update_image_sha256}");

    registration(env.clone());

    let host = env
        .get_nested_vm(HOST_VM_NAME)
        .expect("Unable to find HostOS node.");

    info!(
        logger,
        "Checking version via SSH on HostOS: '{}'",
        host.get_vm().expect("Unable to get HostOS VM.").ipv6
    );
    assert_eq!(original_version.to_string(), check_hostos_version(&host));

    info!(logger, "Electing target HostOS version '{target_version}'");
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();
    block_on(elect_hostos_version(
        &nns_node,
        &target_version,
        &update_image_sha256,
        vec![update_image_url.to_string()],
    ));
    info!(logger, "Elected target HostOS version");

    info!(
        logger,
        "Retrieving the current boot ID from the host before upgrade to detect reboot after upgrade..."
    );
    let host_boot_id_pre_upgrade = try_get_host_boot_id(&host).expect("Failed to retrieve boot ID");
    info!(
        logger,
        "Host boot ID pre upgrade: '{host_boot_id_pre_upgrade}'"
    );

    let node_id = env
        .topology_snapshot()
        .unassigned_nodes()
        .next()
        .unwrap()
        .node_id;
    info!(logger, "Upgrading node '{node_id}' to '{target_version}'");
    block_on(update_nodes_hostos_version(
        &nns_node,
        &target_version,
        vec![node_id],
    ));

    info!(logger, "Waiting for the HostOS upgrade to apply...");

    if let Err(e) = retry_with_msg!(
        format!(
            "Waiting until the host's boot ID changes from its pre upgrade value of '{host_boot_id_pre_upgrade}'"
        ),
        logger.clone(),
        NODE_UPGRADE_TIMEOUT,
        NODE_UPGRADE_BACKOFF,
        || {
            // Use try_get_host_boot_id instead of get_host_boot_id to avoid
            // panicking when SSH is unavailable during the reboot cycle.
            let host_boot_id = try_get_host_boot_id(&host)?;
            if host_boot_id != host_boot_id_pre_upgrade {
                info!(
                    logger,
                    "Host boot ID changed from '{host_boot_id_pre_upgrade}' to '{host_boot_id}'",
                );
                Ok(())
            } else {
                bail!("Host boot ID is still '{host_boot_id_pre_upgrade}'")
            }
        }
    ) {
        try_logging_guestos_diagnostics(&host, &logger);
        panic!("Failed to see the host boot ID change from '{host_boot_id_pre_upgrade}': {e}");
    }

    info!(logger, "Waiting for Orchestrator dashboard...");
    if let Err(e) = host.await_orchestrator_dashboard_accessible() {
        try_logging_guestos_diagnostics(&host, &logger);
        panic!("Orchestrator dashboard is not accessible: {e}");
    }

    info!(logger, "Checking HostOS version after reboot");
    let new_version = check_hostos_version(&host);
    info!(logger, "Version found is: '{new_version}'");

    assert_eq!(new_version, target_version.to_string());
}

/// Where `config_tool generate-metrics-proxy-config` writes, mirroring
/// `DEFAULT_HOSTOS_METRICS_PROXY_OUTPUT_PATH`.
const GENERATED_METRICS_PROXY_CONFIG: &str = "/run/ic-node/etc/metrics-proxy.yaml";

/// HostOS no longer ships a static `/etc/metrics-proxy.yaml`: it generates one,
/// because a multi-VM node has no single `guestos` to chainload. Runs after the
/// upgrade so it covers the HostOS build under test.
pub fn check_metrics_proxy(env: TestEnv) {
    let logger = env.logger();
    let host = env
        .get_nested_vm(HOST_VM_NAME)
        .expect("Unable to find HostOS node.");

    let run = |cmd: &str| {
        host.block_on_bash_script(cmd)
            .unwrap_or_else(|e| panic!("Failed to run '{cmd}' on HostOS: {e:?}"))
    };

    let state = run(
        "systemctl show -p ActiveState -p SubState --value generate-metrics-proxy-config.service",
    );
    info!(logger, "generate-metrics-proxy-config.service: {state}");
    assert!(
        state.contains("active") && state.contains("exited"),
        "config generation did not complete: {state}"
    );

    let config = run(&format!("sudo cat {GENERATED_METRICS_PROXY_CONFIG}"));
    info!(logger, "Generated metrics-proxy config:\n{config}");
    assert!(
        !config.contains("https://guestos:"),
        "config still chainloads the unresolvable `guestos` name"
    );
    assert!(
        config.contains("/metrics/guestos_replica"),
        "config proxies no GuestOS replica metrics"
    );

    let exec_start = run("systemctl show -p ExecStart --value metrics-proxy.service");
    assert!(
        exec_start.contains(GENERATED_METRICS_PROXY_CONFIG),
        "metrics-proxy does not use the generated config: {exec_start}"
    );

    // The guest is registered by this point, so both ends of the chainload work.
    for path in ["hostos_node_exporter", "guestos_replica"] {
        let url = format!("https://[::1]:42372/metrics/{path}");
        if let Err(e) = retry_with_msg!(
            format!("Waiting for metrics on {url}"),
            logger.clone(),
            Duration::from_secs(300),
            Duration::from_secs(10),
            || {
                let out = run(&format!("curl -sk --max-time 10 {url} | head -n 20"));
                if out.trim().is_empty() {
                    bail!("no metrics returned from {url}")
                } else {
                    info!(logger, "{url} served:\n{out}");
                    Ok(())
                }
            }
        ) {
            try_logging_guestos_diagnostics(&host, &logger);
            panic!("{url} never served metrics: {e}");
        }
    }
}
