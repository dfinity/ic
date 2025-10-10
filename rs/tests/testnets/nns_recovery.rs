// The `nested` testnet is meant to interactively test the HostOS. In particular to test NNS subnet recovery by interacting with the host grub menu during boot.
//
// The testnet will consist of a single system subnet with a single node running the NNS.
//
// Then SUBNET_SIZE VMs are deployed and started booting SetupOS which will install HostOS to their virtual disks
// and eventually boot the GuestOS in a VM nested inside the host VM.
// These GuestOSes will then register with the NNS as unassigned nodes.
// Finally, a proposal will be made to assign them to the NNS subnet while removing the original node.
//
// The driver will print how to reboot the host-1 VM and how to get to its console such that you can interact with its grub:
//
// ```
// $ ict testnet create nns_recovery --lifetime-mins 10 --verbose -- --test_env=SUBNET_SIZE=40 --test_env=DKG_INTERVAL=199 --test_env=NUM_NODES_TO_BREAK=14 --test_env=BREAK_AT_HEIGHT=2123 --test_tmpdir=./nns_recovery_testnet
// ...
// 2025-09-02 18:35:22.985 INFO[log_instructions:rs/tests/testnets/nested.rs:16:0] To reboot the host VM run the following command:
// 2025-09-02 18:35:22.985 INFO[log_instructions:rs/tests/testnets/nested.rs:17:0] curl -X PUT 'https://farm.dfinity.systems/group/nested--1756837630333/vm/host-1/reboot'
// ...
//     {
//       "url": "https://farm.dfinity.systems/group/nested--1756837630333/vm/host-1/console/",
//       "vm_name": "host-1"
//     }
// ```
//
// To get access to P8s and Grafana look for the following lines in the ict console output:
//
//     prometheus: Prometheus Web UI at http://prometheus.nns-recovery--1758812276301.testnet.farm.dfinity.systems,
//     grafana: Grafana at http://grafana.nns-recovery--1758812276301.testnet.farm.dfinity.systems,
//     progress_clock: IC Progress Clock at http://grafana.nns-recovery--1758812276301.testnet.farm.dfinity.systems/d/ic-progress-clock/ic-progress-clock?refresh=10s&from=now-5m&to=now,
//
// Happy testing!

use anyhow::Result;
use ic_nested_nns_recovery_common::{
    BACKUP_USERNAME, SetupConfig, grant_backup_access_to_all_nns_nodes,
    replace_nns_with_unassigned_nodes,
};
use ic_recovery::get_node_metrics;
use ic_system_test_driver::driver::driver_setup::{
    SSH_AUTHORIZED_PRIV_KEYS_DIR, SSH_AUTHORIZED_PUB_KEYS_DIR,
};
use ic_system_test_driver::driver::nested::HasNestedVms;
use ic_system_test_driver::driver::prometheus_vm::{HasPrometheus, PrometheusVm};
use ic_system_test_driver::driver::test_env::{SshKeyGen, TestEnv, TestEnvAttribute};
use ic_system_test_driver::driver::test_env_api::*;
use ic_system_test_driver::driver::test_setup::GroupSetup;
use ic_system_test_driver::util::block_on;
use ic_system_test_driver::{driver::group::SystemTestGroup, systest};
use slog::{info, warn};
use std::time::Duration;

fn setup(env: TestEnv) {
    let subnet_size = std::env::var("SUBNET_SIZE")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1);

    let dkg_interval = std::env::var("DKG_INTERVAL")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(199);

    PrometheusVm::default()
        .start(&env)
        .expect("failed to start prometheus VM");

    ic_nested_nns_recovery_common::setup(
        env.clone(),
        SetupConfig {
            impersonate_upstreams: false,
            subnet_size,
            dkg_interval,
        },
    );
}

fn log_instructions(env: TestEnv) {
    let num_to_break = std::env::var("NUM_NODES_TO_BREAK")
        .ok()
        .and_then(|s| s.parse::<usize>().ok());

    let break_at_height = std::env::var("BREAK_AT_HEIGHT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok());

    let subnet_size = env.get_all_nested_vms().unwrap().len();
    let minimum_to_break_subnet = (subnet_size - 1) / 3 + 1;
    if let Some(nb) = num_to_break
        && nb < minimum_to_break_subnet
    {
        warn!(
            env.logger(),
            "NUM_NODES_TO_BREAK is {nb} but needs to be at least {minimum_to_break_subnet} to break a subnet of size {subnet_size}."
        );
    }

    // Generate a new backup keypair
    env.ssh_keygen_for_user(BACKUP_USERNAME)
        .expect("ssh-keygen failed for backup key");
    let ssh_backup_priv_key_path = env
        .get_path(SSH_AUTHORIZED_PRIV_KEYS_DIR)
        .join(BACKUP_USERNAME);
    let ssh_backup_pub_key_path = env
        .get_path(SSH_AUTHORIZED_PUB_KEYS_DIR)
        .join(BACKUP_USERNAME);

    nested::registration(env.clone());
    replace_nns_with_unassigned_nodes(&env);
    grant_backup_access_to_all_nns_nodes(&env, &ssh_backup_priv_key_path, &ssh_backup_pub_key_path);

    env.sync_with_prometheus();

    let logger = env.logger();

    let farm_url = env.get_farm_url().expect("Unable to get Farm url.");
    let group_setup = GroupSetup::read_attribute(&env);
    let group_name: String = group_setup.infra_group_name;

    let upgrade_version = get_guestos_update_img_version();
    let upgrade_image_url = get_guestos_update_img_url();
    let upgrade_image_hash = get_guestos_update_img_sha256();
    info!(
        logger,
        r#"Working GuestOS version:
    --upgrade-version {upgrade_version}
    --upgrade-image-url {upgrade_image_url}
    --upgrade-image-hash {upgrade_image_hash}"#
    );

    info!(
        logger,
        "To reboot host VMs run any, or some of the following commands:"
    );
    for vm in env.get_all_nested_vms().unwrap() {
        let vm_name = vm.vm_name();
        info!(
            logger,
            "curl -X PUT '{farm_url}group/{group_name}/vm/{vm_name}/reboot'"
        );
    }

    let (Some(num_to_break), Some(break_at_height)) = (num_to_break, break_at_height) else {
        info!(
            logger,
            "Provide both NUM_NODES_TO_BREAK and BREAK_AT_HEIGHT environment variables to automatically break the given number of nodes at the given height."
        );
        return;
    };

    loop {
        let highest_certified_height = env
            .topology_snapshot()
            .root_subnet()
            .nodes()
            .filter_map(|n| {
                block_on(get_node_metrics(&logger, &n.get_ip_addr()))
                    .map(|m| m.certification_height.get())
            })
            .max()
            .expect("No heights found");

        if highest_certified_height >= break_at_height {
            info!(
                logger,
                "Reached break height {break_at_height} (current height is {highest_certified_height})."
            );
            break;
        }
        info!(
            logger,
            "Waiting to reach break height {break_at_height}, current height is {highest_certified_height}..."
        );
        std::thread::sleep(Duration::from_secs(5));
    }

    // Break faulty nodes by SSHing into them and breaking the replica binary.
    info!(
        logger,
        "Breaking the subnet by breaking the replica binary on {} nodes", num_to_break
    );
    let ssh_command =
        "sudo mount --bind /bin/false /opt/ic/bin/replica && sudo systemctl restart ic-replica";
    for vm in env.get_all_nested_vms().unwrap().iter().take(num_to_break) {
        let ip = vm.get_nested_network().unwrap().guest_ip;
        info!(logger, "Breaking the replica on IP {ip}...",);

        vm.get_guest_ssh()
            .unwrap()
            .block_on_bash_script(ssh_command)
            .unwrap_or_else(|_| panic!("SSH command failed on IP {ip}",));
    }

    info!(logger, "The subnet should now be broken.");
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_timeout_per_test(Duration::from_secs(90 * 60))
        .with_setup(setup)
        .add_test(systest!(log_instructions))
        .execute_from_args()?;
    Ok(())
}
