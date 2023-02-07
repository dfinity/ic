/* tag::catalog[]

Title:: Backup Manager

Goal:: Ensure that the backup tool is able to restore a subnet state across a replica upgrade.

Description::
In this test we create 4 nodes NNS network and run the backup tool on its backup artifacts. It includes an upgrade to a new replica version.
It makes sure we can restore the subnet state and archive all backup snapshots.

Runbook::
. Deploy an IC with 4 node NNS. The replica version is of the current branch.
. Copy prebuilt ic-backup and add ic-replay tools for this version.
. Download the binaries of the ic-replay for the mainnet version.
. Generate SSH credentials for the backup user.
. Create a configuration file for ic-backup.
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
        rw_message::install_nns_and_check_progress,
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
use ic_backup::config::{ColdStorage, Config, SubnetConfig};
use ic_backup::util::sleep_secs;
use ic_recovery::file_sync_helper::{download_binary, write_file};
use ic_registry_subnet_type::SubnetType;
use ic_types::{Height, ReplicaVersion};
use slog::{info, Logger};
use std::ffi::OsStr;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const DKG_INTERVAL: u64 = 9;
const SUBNET_SIZE: usize = 4;

pub fn config(env: TestEnv) {
    env.ensure_group_setup_created();
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .add_nodes(SUBNET_SIZE)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL)),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
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
    let config_dir = root_dir.join("config");
    fs::create_dir_all(config_dir.clone()).expect("failure creating config directory");
    let cold_storage_dir = tempfile::TempDir::new()
        .expect("failed to create a temporary directory")
        .path()
        .to_path_buf();

    let nns_node = get_nns_node(&env.topology_snapshot());
    let node_ip: IpAddr = nns_node.get_ip_addr();
    let subnet_id = env.topology_snapshot().root_subnet_id();
    let replica_version = get_assigned_replica_version(&nns_node).unwrap();
    let initial_replica_version = ReplicaVersion::try_from(replica_version.clone()).unwrap();

    let backup_binaries_dir = backup_dir.join("binaries").join(&replica_version);
    fs::create_dir_all(&backup_binaries_dir).expect("failure creating backup binaries directory");

    // Copy all the binaries needed for the replay of the current version in order to avoid downloading them
    let testing_dir = env.get_dependency_path("rs/tests");
    let binaries_path = testing_dir.join("backup/binaries");
    copy_file(&binaries_path, &backup_binaries_dir, "ic-replay");
    copy_file(&binaries_path, &backup_binaries_dir, "sandbox_launcher");
    copy_file(&binaries_path, &backup_binaries_dir, "canister_sandbox");

    let mainnet_version = env
        .read_dependency_to_string("testnet/mainnet_nns_revision.txt")
        .expect("could not read mainnet version!");

    // Download all the binaries needed for the replay of the mainnet version
    // This can be moved to the bazel script and completely avoid downloading them
    download_mainnet_binaries(&log, &backup_dir, &mainnet_version);

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

    info!(log, "Generate config file for ic-backup");
    let subnet = SubnetConfig {
        subnet_id,
        initial_replica_version,
        nodes_syncing: 2,
        sync_period_secs: 30,
        replay_period_secs: 30,
        thread_id: 0,
        disable_cold_storage: false,
    };

    let cold_storage = Some(ColdStorage {
        cold_storage_dir: cold_storage_dir.clone(),
        versions_hot: 1,
    });

    let config = Config {
        version: 1,
        push_metrics: false,
        backup_instance: "backup_test_node".to_string(),
        nns_url: Some(nns_node.get_public_url()),
        nns_pem: nns_public_key,
        root_dir: backup_dir.clone(),
        excluded_dirs: vec![],
        ssh_private_key: private_key_path,
        disk_threshold_warn: 75,
        slack_token: "NO_TOKEN_IN_TESTING".to_string(),
        cold_storage,
        subnets: vec![subnet],
    };
    let config_str =
        serde_json::to_string(&config).expect("Config structure can't be converted to json");
    info!(log, "Config: {}", config_str);
    let config_file = config_dir.join("config.json5");
    write_file(&config_file, config_str).expect("writing config file failed");

    info!(log, "Start the backup process in a separate thread");

    let ic_backup_path = binaries_path.join("ic-backup");

    let mut command = Command::new(&ic_backup_path);
    command.arg("--config-file").arg(&config_file);
    info!(log, "Will execute: {:?}", command);

    let mut child = command
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start backup process");

    info!(log, "Started process: {}", child.id());

    info!(log, "Elect the mainnet replica version");
    info!(log, "TARGET_VERSION: {}", mainnet_version);
    block_on(bless_public_replica_version(
        &nns_node,
        &mainnet_version,
        UpdateImageType::Image,
        UpdateImageType::Image,
        &log,
    ));

    info!(log, "Proposal to upgrade the subnet replica version");
    block_on(update_subnet_replica_version(
        &nns_node,
        &ReplicaVersion::try_from(mainnet_version.clone()).expect("bad TARGET_VERSION string"),
        subnet_id,
    ));

    info!(log, "Wait until the upgrade happens");
    assert_assigned_replica_version(&nns_node, &mainnet_version, env.logger());

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
        .join(mainnet_version)
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

    info!(log, "Restart and wait for the cold storage to happen");
    child.kill().expect("Error killing backup process");

    let mut command = Command::new(ic_backup_path);
    command.arg("--config-file").arg(config_file);
    info!(log, "Will execute: {:?}", command);
    let mut child = command
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start backup process");
    info!(log, "Started process: {}", child.id());

    assert!(cold_storage_exists(
        cold_storage_dir.join(subnet_id.to_string())
    ));
    info!(log, "Artifacts and states are moved to cold storage");

    info!(log, "Kill child process");
    child.kill().expect("Error killing backup process");
}

fn cold_storage_exists(cold_storage_dir: PathBuf) -> bool {
    for _ in 0..12 {
        if dir_exists_and_have_file(&cold_storage_dir.join("states"))
            && dir_exists_and_have_file(&cold_storage_dir.join("artifacts"))
        {
            return true;
        }
        sleep_secs(10);
    }
    false
}

fn dir_exists_and_have_file(dir: &PathBuf) -> bool {
    if !dir.exists() {
        return false;
    }
    fs::read_dir(dir).unwrap().next().is_some()
}

fn copy_file(binaries_path: &Path, backup_binaries_dir: &Path, file_name: &str) {
    fs::copy(
        binaries_path.join(file_name),
        backup_binaries_dir.join(file_name),
    )
    .expect("failed to copy file");
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

fn download_mainnet_binaries(log: &Logger, backup_dir: &Path, mainnet_version: &str) {
    let binaries_dir = backup_dir.join("binaries").join(mainnet_version);
    let replica_version = ReplicaVersion::try_from(mainnet_version).unwrap();
    fs::create_dir_all(&binaries_dir).expect("failure creating backup binaries directory");
    download_binary_file(log, &replica_version, &binaries_dir, "ic-replay");
    download_binary_file(log, &replica_version, &binaries_dir, "sandbox_launcher");
    download_binary_file(log, &replica_version, &binaries_dir, "canister_sandbox");
}

fn download_binary_file(
    log: &Logger,
    replica_version: &ReplicaVersion,
    binaries_dir: &Path,
    binary: &str,
) {
    info!(log, "Downloading binary: {binary}");
    block_on(download_binary(
        log,
        replica_version.clone(),
        binary.to_string(),
        binaries_dir.to_path_buf(),
    ))
    .expect("error downloading binaty");
}
