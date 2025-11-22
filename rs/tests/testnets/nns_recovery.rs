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
// $ ict testnet create nns_recovery --lifetime-mins 10 --verbose -- --test_env=SUBNET_SIZE=40 --test_env=DKG_INTERVAL=499 --test_env=NUM_NODES_TO_BREAK=14 --test_env=BREAK_AT_HEIGHT=2123 --test_tmpdir=./nns_recovery_testnet
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
// To recover the latest mainnet NNS subnet backup make sure your testnet is deployed to zh1 (where the backup pod is located)
// by passing the following to ict `--set-required-host-features=dc=zh1` and pass `--test_env=RECOVER_LATEST_MAINNET_NNS_SUBNET_BACKUP=1`.
// Note that the NNS backup is over 15GB so it will require around 3 minutes to download, X minutes to unpack and Y GB of disk space.
//
// To get access to P8s and Grafana look for the following lines in the ict console output:
//
//     prometheus: Prometheus Web UI at http://prometheus.nns-recovery--1758812276301.testnet.farm.dfinity.systems,
//     grafana: Grafana at http://grafana.nns-recovery--1758812276301.testnet.farm.dfinity.systems,
//     progress_clock: IC Progress Clock at http://grafana.nns-recovery--1758812276301.testnet.farm.dfinity.systems/d/ic-progress-clock/ic-progress-clock?refresh=10s&from=now-5m&to=now,
//
// Happy testing!

use anyhow::Result;
use ic_consensus_system_test_subnet_recovery::utils::{
    AdminAndUserKeys, break_nodes, get_admin_keys_and_generate_backup_keys,
    node_with_highest_certification_share_height,
};
use ic_limits::DKG_INTERVAL_HEIGHT;
use ic_nested_nns_recovery_common::{
    SetupConfig, grant_backup_access_to_all_nns_nodes, replace_nns_with_unassigned_nodes,
};
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::nested::HasNestedVms;
use ic_system_test_driver::driver::prometheus_vm::{HasPrometheus, PrometheusVm};
use ic_system_test_driver::driver::test_env::{TestEnv, TestEnvAttribute};
use ic_system_test_driver::driver::test_env_api::*;
use ic_system_test_driver::driver::test_setup::GroupSetup;
use slog::{info, warn};
use std::{io::Write, process::Command, time::Duration};

const NNS_BACKUP_POD: &str = "zh1-pyr07.zh1.dfinity.network";
const NNS_BACKUP_POD_USER: &str = "dev";
const NNS_STATE_DIR_PATH: &str = "recovery/working_dir/data";
const NNS_STATE_BACKUP_TARBALL_PATH: &str = "nns_state.tar.zst";

fn fetch_nns_state_from_backup_pod(env: TestEnv) {
    let target = format!(
        "{NNS_BACKUP_POD_USER}@{NNS_BACKUP_POD}:/home/{NNS_BACKUP_POD_USER}/{NNS_STATE_BACKUP_TARBALL_PATH}"
    );
    let logger: slog::Logger = env.logger();
    let nns_state_backup_path = env.get_path(NNS_STATE_BACKUP_TARBALL_PATH);
    info!(
        logger,
        "Downloading {} to {:?} ...",
        target,
        nns_state_backup_path.clone()
    );
    // TODO: consider using the ssh2 crate (like we do in prometheus_vm.rs)
    // instead of shelling out to scp.
    let mut cmd = Command::new("scp");
    cmd.arg("-oUserKnownHostsFile=/dev/null")
        .arg("-oStrictHostKeyChecking=no")
        .arg(target.clone())
        .arg(nns_state_backup_path.clone());
    info!(env.logger(), "{cmd:?} ...");
    let scp_out = cmd.output().unwrap_or_else(|e| {
        panic!(
            "Could not scp the {NNS_STATE_BACKUP_TARBALL_PATH} from the backup pod because: {e:?}!",
        )
    });
    if !scp_out.status.success() {
        std::io::stdout().write_all(&scp_out.stdout).unwrap();
        std::io::stderr().write_all(&scp_out.stderr).unwrap();
        panic!("Could not scp the {NNS_STATE_BACKUP_TARBALL_PATH} from the backup pod!");
    }
    info!(
        logger,
        "Downloaded {target:} to {:?}, unpacking ...", nns_state_backup_path
    );
    let mut cmd = Command::new("tar");
    cmd.arg("xf")
        .arg(nns_state_backup_path.clone())
        .arg("-C")
        .arg(env.base_path())
        .arg(format!("--transform=s|nns_state/|{NNS_STATE_DIR_PATH}/|"));
    info!(env.logger(), "{cmd:?} ...");
    let tar_out = cmd
        .output()
        .expect("Could not unpack {NNS_STATE_BACKUP_TARBALL_PATH}!");
    if !tar_out.status.success() {
        std::io::stdout().write_all(&tar_out.stdout).unwrap();
        std::io::stderr().write_all(&tar_out.stderr).unwrap();
        panic!("Could not unpack {NNS_STATE_BACKUP_TARBALL_PATH}!");
    }
    info!(logger, "Unpacked {:?}", nns_state_backup_path);
}

fn setup(env: TestEnv) {
    let recover_latest_mainnet_nns_subnet_backup =
        std::env::var("RECOVER_LATEST_MAINNET_NNS_SUBNET_BACKUP").is_ok();

    let subnet_size = std::env::var("SUBNET_SIZE")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1);

    let dkg_interval = std::env::var("DKG_INTERVAL")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DKG_INTERVAL_HEIGHT);

    let opt_fetch_nns_backup_thread = if recover_latest_mainnet_nns_subnet_backup {
        let env_clone = env.clone();
        Some(std::thread::spawn(move || {
            fetch_nns_state_from_backup_pod(env_clone);
        }))
    } else {
        None
    };

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

    log_instructions(env.clone());

    if let Some(fetch_thread) = opt_fetch_nns_backup_thread {
        fetch_thread
            .join()
            .expect("Failed to fetch latest mainnet NNS subnet backup.");
    }
}

fn log_instructions(env: TestEnv) {
    let num_to_break = std::env::var("NUM_NODES_TO_BREAK")
        .ok()
        .and_then(|s| s.parse::<usize>().ok());

    let break_at_height = std::env::var("BREAK_AT_HEIGHT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok());

    let logger = env.logger();

    let subnet_size = env.get_all_nested_vms().unwrap().len();
    let minimum_to_break_subnet = (subnet_size - 1) / 3 + 1;
    if let Some(nb) = num_to_break
        && nb < minimum_to_break_subnet
    {
        warn!(
            logger,
            "NUM_NODES_TO_BREAK is {nb} but needs to be at least {minimum_to_break_subnet} to break a subnet of size {subnet_size}."
        );
    }

    let AdminAndUserKeys {
        user_auth: backup_auth,
        ssh_user_pub_key: ssh_backup_pub_key,
        ..
    } = get_admin_keys_and_generate_backup_keys(&env);

    nested::registration(env.clone());
    replace_nns_with_unassigned_nodes(&env);
    grant_backup_access_to_all_nns_nodes(&env, &backup_auth, &ssh_backup_pub_key);

    env.sync_with_prometheus();

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

    info!(logger, "Host <-> IPs mapping:");
    for vm in env.get_all_nested_vms().unwrap() {
        let vm_name = vm.vm_name();
        let host_ip = vm.get_nested_network().unwrap().host_ip;
        let guest_ip = vm.get_nested_network().unwrap().guest_ip;
        info!(logger, "{vm_name}: HostOS {host_ip}, GuestOS {guest_ip}");
    }

    let farm_url = env.get_farm_url().expect("Unable to get Farm url.");
    let group_setup = GroupSetup::read_attribute(&env);
    let group_name: String = group_setup.infra_group_name;
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
        let (_, highest_cert_share) = node_with_highest_certification_share_height(
            &env.topology_snapshot().root_subnet(),
            &logger,
        );

        if highest_cert_share >= break_at_height {
            info!(
                logger,
                "Reached break height {break_at_height} (current height is {highest_cert_share})."
            );
            break;
        }
        info!(
            logger,
            "Waiting to reach break height {break_at_height}, current height is {highest_cert_share}..."
        );
        std::thread::sleep(Duration::from_secs(5));
    }

    break_nodes(
        &env.get_all_nested_vms()
            .unwrap()
            .iter()
            .map(|vm| vm.get_guest_ssh().unwrap())
            .take(num_to_break)
            .collect::<Vec<_>>(),
        &logger,
    );

    info!(logger, "The subnet should now be broken.");
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_timeout_per_test(Duration::from_secs(90 * 60))
        .with_setup(setup)
        .execute_from_args()?;
    Ok(())
}
