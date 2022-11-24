/* tag::catalog[]

Title:: Backup Manager

Goal:: Ensure that the backup tool is able to restore a subnet state across a replica upgrade.

Description::
In this test we create 4 nodes NNS network and run the backup tool on its backup artifacts. It includes an upgrade to a new replica version.
It makes sure we can restore the subnet state and archive all backup snapshots.

Runbook::
. Deploy an IC with 4 node NNS. The replica version is of the current branch.
. Generate SSH credentials for the backup user.
. Download the ic-backup tool and create a configuration file for it.
. Start the backup process in a separate thread.
. Upgrade the subnet to the replica version of the master branch.
. Wait for backup and archive of a new version checkpoint.

Success::
. Backup tool is able to restore the state from pulled artifacts, including those after the upgrade. The state is also archived.

end::catalog[] */

use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::test_env::HasIcPrepDir;
use crate::driver::{test_env::TestEnv, test_env_api::*};
use crate::{
    orchestrator::utils::{
        rw_message::install_nns_and_message_canisters,
        ssh_access::{
            generate_key_strings, get_updatesubnetpayload_with_keys, update_subnet_record,
            wait_until_authentication_is_granted, AuthMean,
        },
        upgrade::{
            assert_assigned_replica_version, bless_public_replica_version,
            get_assigned_replica_version, update_subnet_replica_version, UpdateImageType,
        },
    },
    util::{block_on, get_nns_node},
};
use ic_backup::config::{Config, SubnetConfig};
use ic_backup::util::sleep_secs;
use ic_recovery::file_sync_helper::{download_binary, write_file};
use ic_registry_subnet_type::SubnetType;
use ic_types::{Height, ReplicaVersion};
use slog::info;
use std::ffi::OsStr;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::{env, fs};

const DKG_INTERVAL: u64 = 9;
const SUBNET_SIZE: usize = 4;

pub fn config(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .add_nodes(SUBNET_SIZE)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL)),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_message_canisters(env.topology_snapshot());
}

pub fn test(env: TestEnv) {
    let log = env.logger();

    // Create all directories
    let root_dir = tempfile::TempDir::new()
        .expect("failed to create a temporary directory")
        .path()
        .to_path_buf();
    let backup_dir = root_dir.join("backup");
    fs::create_dir_all(backup_dir.clone()).expect("failure creating backup directory");
    let bin_dir = root_dir.join("bin");
    fs::create_dir_all(bin_dir.clone()).expect("failure creating bin directory");
    let config_dir = root_dir.join("config");
    fs::create_dir_all(config_dir.clone()).expect("failure creating config directory");

    let nns_node = get_nns_node(&env.topology_snapshot());
    let node_ip: IpAddr = nns_node.get_ip_addr();
    let subnet_id = env.topology_snapshot().root_subnet_id();
    let replica_version = get_assigned_replica_version(&nns_node).unwrap();
    let initial_replica_version = ReplicaVersion::try_from(replica_version.clone()).unwrap();

    // Generate keypair and store the private key
    info!(log, "Create backup user credentials");
    let (backup_private_key, backup_public_key) = generate_key_strings();
    let private_key_path = config_dir.join("id_rsa");
    std::fs::write(private_key_path.clone(), &backup_private_key)
        .expect("writing private key file failed");
    let chmod = Command::new("chmod")
        .arg("600")
        .arg(private_key_path.clone())
        .spawn()
        .expect("chmod command failed");
    chmod.wait_with_output().expect("chmod execution failed");

    // Update the registry with the backup key
    let payload = get_updatesubnetpayload_with_keys(subnet_id, None, Some(vec![backup_public_key]));
    block_on(update_subnet_record(nns_node.get_public_url(), payload));
    let backup_mean = AuthMean::PrivateKey(backup_private_key);
    wait_until_authentication_is_granted(&node_ip, "backup", &backup_mean);

    // Fetch NNS public key
    let nns_public_key = env
        .prep_dir("")
        .expect("missing NNS public key")
        .root_public_key_path();

    info!(log, "Fetch ic-backup binary");
    let backup_exe = "ic-backup".to_string();
    assert!(block_on(download_binary(
        &log,
        initial_replica_version.clone(),
        backup_exe.clone(),
        bin_dir.clone(),
    ))
    .is_ok());

    info!(log, "Generate config file for ic-backup");
    let subnet = SubnetConfig {
        subnet_id,
        initial_replica_version,
        nodes_syncing: 2,
        sync_period_secs: 30,
        replay_period_secs: 30,
    };

    let config = Config {
        backup_instance: "backup_test_node".to_string(),
        nns_url: Some(nns_node.get_public_url()),
        nns_pem: nns_public_key,
        root_dir: backup_dir.clone(),
        excluded_dirs: vec![],
        ssh_private_key: private_key_path,
        slack_token: "NO_TOKEN_IN_TESTING".to_string(),
        subnets: vec![subnet],
    };
    let config_str =
        serde_json::to_string(&config).expect("Config structure can't be converted to json");
    info!(log, "Config: {}", config_str);
    let config_file = config_dir.join("config.json5");
    write_file(&config_file, config_str).expect("writing config file failed");

    info!(log, "Start the backup process in a separate thread");
    let mut command = Command::new(bin_dir.join(backup_exe));
    command.arg("--config-file").arg(config_file);
    info!(log, "Will execute: {:?}", command);

    let mut child = command
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start backup process");

    info!(log, "Started process: {}", child.id());

    info!(log, "Elect the mainnet replica version");
    let target_version =
        env::var("TARGET_VERSION").expect("Environment variable $TARGET_VERSION is not set!");
    info!(log, "TARGET_VERSION: {}", target_version);
    block_on(bless_public_replica_version(
        &nns_node,
        &target_version,
        UpdateImageType::Image,
        UpdateImageType::Image,
        &log,
    ));

    info!(log, "Proposal to upgrade the subnet replica version");
    block_on(update_subnet_replica_version(
        &nns_node,
        &ReplicaVersion::try_from(target_version.clone()).expect("bad TARGET_VERSION string"),
        subnet_id,
    ));

    info!(log, "Wait until the upgrade happens");
    assert_assigned_replica_version(&nns_node, &target_version, env.logger());

    let checkpoint_dir = backup_dir
        .join("data")
        .join(subnet_id.to_string())
        .join("ic_state/checkpoints");
    let orig_spool_dir = backup_dir
        .join("spool")
        .join(subnet_id.to_string())
        .join(replica_version)
        .join("0");
    let new_spool_dir = backup_dir
        .join("spool")
        .join(subnet_id.to_string())
        .join(target_version)
        .join("0");
    let archive_dir = backup_dir.join("archive").join(subnet_id.to_string());

    info!(
        log,
        "Wait for backup and archive of a new version checkpoint"
    );
    loop {
        let old_height = highest_dir_entry(&orig_spool_dir, 10);
        let new_height = highest_dir_entry(&new_spool_dir, 10);
        let good_progress = old_height + 3 * (DKG_INTERVAL + 1);
        let checkpoint = highest_dir_entry(&checkpoint_dir, 16);
        let archive_height = highest_dir_entry(&archive_dir, 10);
        info!(
            log,
            "New version: {}  Checkpoint: {}  Archive: {} Progress: {} ",
            new_height,
            checkpoint,
            archive_height,
            good_progress,
        );
        if new_height > 0 && checkpoint > good_progress && archive_height > good_progress {
            info!(log, "New version was sucessfully backed up and archived");
            break;
        }
        sleep_secs(5);
    }

    info!(log, "Kill child process");
    child.kill().expect("Error killing backup process");
}

fn highest_dir_entry(dir: &PathBuf, radix: u32) -> u64 {
    if !dir.exists() {
        return 0u64;
    }
    match std::fs::read_dir(dir) {
        Ok(file_list) => file_list
            .flatten()
            .map(|filename| {
                filename
                    .path()
                    .file_name()
                    .unwrap_or_else(|| OsStr::new("0"))
                    .to_os_string()
                    .into_string()
                    .unwrap_or_else(|_| "0".to_string())
            })
            .map(|s| u64::from_str_radix(&s, radix).unwrap_or(0))
            .fold(0u64, |a: u64, b: u64| -> u64 { a.max(b) }),
        Err(_) => 0,
    }
}
