use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use bare_metal_deployment::{BareMetalIpmiSession, LoginInfo};
use ic_system_test_driver::driver::nested::NestedNode;
use ic_system_test_driver::driver::test_env::SshKeyGen;
use ic_system_test_driver::{
    driver::{
        nested::{HasNestedVms, NestedNodes, NestedVm},
        test_env::TestEnv,
        test_env_api::*,
    },
    retry_with_msg,
    util::block_on,
};
use slog::info;
use util::{
    NODE_REGISTRATION_BACKOFF, NODE_REGISTRATION_TIMEOUT, setup_ic_infrastructure,
    try_logging_guestos_diagnostics,
};

pub mod util;

pub const HOST_VM_NAME: &str = "host-1";
const BARE_METAL_HOST_SECRETS: &str = "BARE_METAL_HOST_SECRETS";

/// Prepare the environment for nested tests.
/// SetupOS -> HostOS -> GuestOS
pub fn setup(env: TestEnv) {
    setup_ic_infrastructure(&env, /*dkg_interval=*/ None, /*is_fast=*/ true);

    if std::env::var("TRUSTED_EXECUTION_ENVIRONMENT").is_ok() {
        let bare_metal = create_bare_metal_session(&env);
        let mut nodes = NestedNodes {
            nodes: vec![create_bare_metal_tee_node(&bare_metal)],
        };
        nodes.setup_and_start(&env).unwrap();
    } else {
        simple_setup(env);
    }
}

/// Minimal setup that only creates a nested VM without any IC infrastructure.
/// This is much faster than the full setup().
pub fn simple_setup(env: TestEnv) {
    NestedNodes::new([HOST_VM_NAME])
        .setup_and_start(&env)
        .unwrap();
}

/// Starts a bare metal IPMI session and injects the SSH key from `env`.
pub fn create_bare_metal_session(env: &TestEnv) -> BareMetalIpmiSession {
    let bare_metal_login_info = get_bare_metal_login_info();
    let mut bare_metal = BareMetalIpmiSession::start(&bare_metal_login_info)
        .expect("Failed to start baremetal session");
    bare_metal
        .inject_ssh_key(
            &env.get_ssh_public_key()
                .expect("Could not get SSH public key"),
        )
        .expect("Failed to inject SSH key");
    bare_metal
}

/// Creates a bare-metal nested node. Set `enable_trusted_execution_environment` when the host
/// runs AMD SEV-SNP (same meaning as the `TRUSTED_EXECUTION_ENVIRONMENT` env var in `setup()`).
pub fn create_bare_metal_node(
    bare_metal: &BareMetalIpmiSession,
    enable_trusted_execution_environment: bool,
) -> NestedNode {
    NestedNode::new_bare_metal(
        HOST_VM_NAME.to_string(),
        bare_metal.hostos_address(),
        bare_metal.mgmt_mac(),
        enable_trusted_execution_environment,
    )
}

/// Creates a `NestedNodes` with a single bare metal TEE (SEV-SNP) node.
pub fn create_bare_metal_tee_node(bare_metal: &BareMetalIpmiSession) -> NestedNode {
    create_bare_metal_node(bare_metal, true)
}

pub fn get_bare_metal_login_info() -> LoginInfo {
    let bare_metal_secrets_file = std::env::var(BARE_METAL_HOST_SECRETS)
        .expect("Could not read env var BARE_METAL_HOST_SECRETS");
    let bare_metal_secrets = std::fs::read_to_string(bare_metal_secrets_file)
        .expect("Could not read baremetal secrets file");
    bare_metal_deployment::parse_login_info_from_ini(&bare_metal_secrets)
        .expect("Failed to parse baremetal login info")
}

pub fn registration(env: TestEnv) {
    registration_with_timeout(env, NODE_REGISTRATION_TIMEOUT);
}

/// Allow the nested GuestOS to install and launch, and check that it can
/// successfully join the testnet.
pub fn registration_with_timeout(env: TestEnv, timeout: Duration) {
    let logger = env.logger();

    let initial_topology = env.topology_snapshot();

    // Keep track of the initial number of unassigned nodes.
    let initial_num_unassigned_nodes = initial_topology.unassigned_nodes().count();

    let nested_vms = env.get_all_nested_vms().unwrap();
    let n = nested_vms.len();

    // If the nodes are able to join successfully, the registry will be updated,
    // and the new node IDs will enter the unassigned pool.
    let mut new_topology = initial_topology;
    let expected_num_unassigned_nodes = initial_num_unassigned_nodes + n;
    retry_with_msg!(
        format!("Waiting for all {n} nodes to join ..."),
        logger.clone(),
        timeout,
        NODE_REGISTRATION_BACKOFF,
        || {
            new_topology = block_on(
                new_topology.block_for_newer_registry_version_within_duration(
                    timeout,
                    NODE_REGISTRATION_BACKOFF,
                ),
            )
            .unwrap();
            let num_unassigned_nodes = new_topology.unassigned_nodes().count();
            if num_unassigned_nodes == expected_num_unassigned_nodes {
                Ok(())
            } else {
                bail!("Expected {expected_num_unassigned_nodes} unassigned nodes, but found {num_unassigned_nodes}. Waiting for the rest to register ...");
            }
        }
    ).unwrap();
    info!(logger, "All {n} nodes successfully came up and registered.");
}

/// `guest_vm_runner` logs this line when it relaunches a GuestOS whose domain went away
/// (rs/ic_os/os_tools/guest_vm_runner/src/main.rs, `run()`); the gates below count it.
const GUEST_VM_RELAUNCH_LINE: &str = "Guest VM stopped, restarting";

/// Crash the GuestOS kernel (sysrq 'c' panics it) and check that `panic=10` on its kernel
/// command line reboots it and that HostOS (libvirt `on_reboot=destroy` plus `guest_vm_runner`)
/// relaunches the VM exactly once. Runs after `registration`, so `boot_cycle` is already stable
/// and the relaunch boots the same slot.
pub fn guestos_panic_relaunch(env: TestEnv) {
    let logger = env.logger();
    let host = env
        .get_nested_vm(HOST_VM_NAME)
        .expect("Unable to find HostOS node.");
    if let Err(e) = guestos_panic_relaunch_inner(&env, &host) {
        try_logging_guestos_diagnostics(&host, &logger);
        panic!("GuestOS panic-relaunch check failed: {e:?}");
    }
    info!(
        logger,
        "GuestOS panicked, rebooted after panic=10 and was relaunched by guest_vm_runner."
    );
}

/// Number of GuestOS relaunches logged by `guest_vm_runner` since the HostOS booted.
/// `_TRANSPORT=journal` selects the runner's native journald entries only; its stderr is captured
/// into the journal as well (`_TRANSPORT=stdout`), which would count every relaunch twice.
fn count_guest_vm_relaunches(host: &NestedVm) -> Result<usize> {
    let out = host.block_on_bash_script(&format!(
        "journalctl -q -b -o cat --no-pager _TRANSPORT=journal \
         | grep -c '{GUEST_VM_RELAUNCH_LINE}' || true"
    ))?;
    out.trim()
        .parse()
        .with_context(|| format!("Unexpected relaunch count output: {out:?}"))
}

fn guestos_panic_relaunch_inner(env: &TestEnv, host: &NestedVm) -> Result<()> {
    let logger = env.logger();
    let guest = host.get_guest_ssh()?;

    // 1. The kernel took the parameters on the direct-boot path; remember the boot id.
    let out = guest.block_on_bash_script(
        "cat /proc/cmdline; cd /proc/sys/kernel && \
         cat panic_on_oops panic softlockup_panic watchdog_thresh soft_watchdog random/boot_id",
    )?;
    info!(
        logger,
        "GuestOS kernel cmdline, panic/lockup sysctls and boot id:\n{out}"
    );
    let mut lines = out.lines();
    let cmdline: Vec<&str> = lines
        .next()
        .context("Missing /proc/cmdline")?
        .split_whitespace()
        .collect();
    for param in [
        "oops=panic",
        "panic=10",
        "softlockup_panic=1",
        "watchdog_thresh=60",
    ] {
        ensure!(
            cmdline.contains(&param),
            "GuestOS did not boot with {param}: {out}"
        );
    }
    // kernel.panic_on_oops, kernel.panic, kernel.softlockup_panic, kernel.watchdog_thresh and
    // kernel.soft_watchdog (the soft-lockup detector is enabled), in the order read above.
    let sysctls: Vec<&str> = lines.by_ref().take(5).collect();
    ensure!(
        sysctls == ["1", "10", "1", "60", "1"],
        "Unexpected panic/lockup sysctls {sysctls:?}: {out}"
    );
    let boot_id_before = lines.next().context("Missing boot id")?.to_string();
    let relaunches_before = count_guest_vm_relaunches(host)?;

    // 2. Trigger the panic detached, with all fds redirected, so the SSH channel closes before
    // the kernel dies; a channel still open at the panic would block until the TCP timeout.
    info!(logger, "Crashing the GuestOS kernel via sysrq");
    let session = guest.block_on_ssh_session()?;
    session.set_timeout(30_000);
    guest.block_on_bash_script_from_session(
        &session,
        "nohup sudo sh -c 'sleep 5; echo c > /proc/sysrq-trigger' >/dev/null 2>&1 </dev/null &",
    )?;

    // 3. guest_vm_runner saw the domain go away and relaunched it (expected within ~30 s),
    // exactly once.
    let relaunches_after = retry_with_msg!(
        "Waiting for guest_vm_runner to relaunch the GuestOS",
        logger.clone(),
        Duration::from_secs(3 * 60),
        Duration::from_secs(5),
        || {
            let n = count_guest_vm_relaunches(host)?;
            if n > relaunches_before {
                Ok(n)
            } else {
                bail!("No relaunch logged yet ({n} before the panic)")
            }
        }
    )?;
    ensure!(
        relaunches_after == relaunches_before + 1,
        "Expected exactly one relaunch, found {} ({relaunches_before} before the panic)",
        relaunches_after - relaunches_before
    );

    // 4. The guest is up again on a new boot. Bound each SSH attempt, including the command I/O
    // (a fresh session has no I/O timeout after authentication), so a failure here still
    // leaves time for the diagnostics within the per-test timeout.
    retry_with_msg!(
        "Waiting for the GuestOS to boot again",
        logger.clone(),
        Duration::from_secs(5 * 60),
        Duration::from_secs(10),
        || {
            let session = guest.block_on_ssh_session_with_timeout(Duration::from_secs(60))?;
            session.set_timeout(60_000);
            let boot_id = guest.block_on_bash_script_from_session(
                &session,
                "cat /proc/sys/kernel/random/boot_id",
            )?;
            if boot_id.trim() != boot_id_before {
                Ok(())
            } else {
                bail!("GuestOS still reports the pre-panic boot id")
            }
        }
    )?;

    // 5. The orchestrator serves its dashboard again (NestedVm's public address is the guest IP).
    host.await_orchestrator_dashboard_accessible()?;

    // 6. Still exactly one relaunch: the guest did not end up in a panic/reboot loop.
    let relaunches_final = count_guest_vm_relaunches(host)?;
    ensure!(
        relaunches_final == relaunches_after,
        "GuestOS was relaunched again ({relaunches_after} -> {relaunches_final})"
    );

    // 7. Evidence only: the serial console is forwarded to the HostOS journal through a
    // block-buffered pipe, so these lines may lag behind the relaunch.
    let evidence = host.block_on_bash_script(
        "journalctl -q -b -o cat --no-pager \
         | grep -E 'Kernel panic - not syncing|Rebooting in 10 seconds|GuestOS boot succeeded' || true",
    )?;
    info!(
        logger,
        "HostOS journal evidence of the panic and relaunch:\n{evidence}"
    );
    Ok(())
}
