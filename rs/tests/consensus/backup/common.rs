/* tag::catalog[]

Title:: Backup Manager

Goal:: Ensure that the backup tool is able to restore a subnet state across a replica up- and downgrade.

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
use ic_backup::{
    backup_helper::last_checkpoint,
    config::{ColdStorage, Config, SubnetConfig},
};
use ic_base_types::SubnetId;
use ic_consensus_system_test_utils::upgrade::bless_replica_version;
use ic_consensus_system_test_utils::{
    rw_message::install_nns_and_check_progress,
    ssh_access::{
        AuthMean, generate_key_strings, get_updatesubnetpayload_with_keys, update_subnet_record,
        wait_until_authentication_is_granted,
    },
    upgrade::{
        assert_assigned_replica_version, deploy_guestos_to_all_subnet_nodes,
        get_assigned_replica_version,
    },
};
use ic_consensus_threshold_sig_system_test_utils::{
    get_master_public_key, make_key_ids_for_all_schemes, run_chain_key_signature_test,
};
use ic_registry_subnet_features::{ChainKeyConfig, KeyConfig};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        ic::{InternetComputer, Subnet},
        test_env::{HasIcPrepDir, TestEnv},
        test_env_api::*,
    },
    util::{MessageCanister, block_on, get_nns_node},
};
use ic_types::Height;
use slog::{Logger, debug, error, info};
use std::{
    ffi::OsStr,
    fs,
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use std::{fs::File, time::Duration};

const DKG_INTERVAL: u64 = 9;
const SUBNET_SIZE: usize = 4;
const DIVERGENCE_LOG_STR: &str = "The state hash of the CUP at height ";

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .add_nodes(SUBNET_SIZE)
                .with_chain_key_config(ChainKeyConfig {
                    key_configs: make_key_ids_for_all_schemes()
                        .into_iter()
                        .map(|key_id| KeyConfig {
                            max_queue_size: 20,
                            pre_signatures_to_create_in_advance: key_id
                                .requires_pre_signatures()
                                .then_some(7),
                            key_id,
                        })
                        .collect(),
                    signature_request_timeout_ns: None,
                    idkg_key_rotation_period_ms: None,
                    max_parallel_pre_signature_transcripts_in_creation: None,
                })
                .with_dkg_interval_length(Height::from(DKG_INTERVAL)),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
}

pub fn test(env: TestEnv) {
    let log = env.logger();
    let nns_node = get_nns_node(&env.topology_snapshot());
    info!(log, "Elect the target replica version");
    let binary_version = get_current_branch_version();
    let target_version = get_guestos_update_img_version();

    // Bless target version
    let sha256 = get_guestos_update_img_sha256();
    let upgrade_url = get_guestos_update_img_url();
    let guest_launch_measurements = get_guestos_launch_measurements();
    block_on(bless_replica_version(
        &nns_node,
        &target_version,
        &log,
        sha256,
        Some(guest_launch_measurements),
        vec![upgrade_url.to_string()],
    ));
    info!(log, "TARGET_VERSION: {}", target_version);

    info!(log, "Create all directories");
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

    info!(log, "Fetch the replica version");
    let nns_node = get_nns_node(&env.topology_snapshot());
    let node_ip: IpAddr = nns_node.get_ip_addr();
    let subnet_id = env.topology_snapshot().root_subnet_id();
    let initial_replica_version =
        get_assigned_replica_version(&nns_node).expect("There should be assigned replica version");

    info!(
        log,
        "Copy the binaries needed for replay of the current version"
    );
    let backup_binaries_dir = backup_dir.join("binaries").join(binary_version.to_string());
    fs::create_dir_all(&backup_binaries_dir).expect("failure creating backup binaries directory");

    // Copy all the binaries needed for the replay of the current version in order to avoid downloading them
    copy_file(
        &get_dependency_path(std::env::var("IC_REPLAY_PATH").expect("IC_REPLAY_PATH not set")),
        &backup_binaries_dir,
        "ic-replay",
    );
    copy_file(
        &get_dependency_path(
            std::env::var("SANDBOX_LAUNCHER_PATH").expect("SANDBOX_LAUNCHER_PATH not set"),
        ),
        &backup_binaries_dir,
        "sandbox_launcher",
    );
    copy_file(
        &get_dependency_path(
            std::env::var("CANISTER_SANDBOX_PATH").expect("CANISTER_SANDBOX_PATH not set"),
        ),
        &backup_binaries_dir,
        "canister_sandbox",
    );
    copy_file(
        &get_dependency_path(
            std::env::var("COMPILER_SANDBOX_PATH").expect("COMPILER_SANDBOX_PATH not set"),
        ),
        &backup_binaries_dir,
        "compiler_sandbox",
    );

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

    info!(log, "Run threshold signature test");
    let nns_node = env.get_first_healthy_nns_node_snapshot();
    let agent = nns_node.build_default_agent();
    let nns_canister = block_on(MessageCanister::new(
        &agent,
        nns_node.effective_canister_id(),
    ));

    for key_id in make_key_ids_for_all_schemes() {
        let public_key = get_master_public_key(&nns_canister, &key_id, &log);
        run_chain_key_signature_test(&nns_canister, &log, &key_id, public_key);
    }

    info!(log, "Install universal canister");
    let log2 = log.clone();
    let id = nns_node.effective_canister_id();
    let canister_id_hex: String = block_on({
        async move {
            let canister = MessageCanister::new_with_retries(
                &agent,
                id,
                &log2,
                Duration::from_secs(120),
                Duration::from_secs(1),
            )
            .await;
            hex::encode(canister.canister_id().as_slice())
        }
    });

    info!(log, "Update the registry with the backup key");
    let payload = get_updatesubnetpayload_with_keys(subnet_id, None, Some(vec![backup_public_key]));
    block_on(update_subnet_record(nns_node.get_public_url(), payload));
    let backup_mean = AuthMean::PrivateKey(backup_private_key);
    wait_until_authentication_is_granted(&log, &node_ip, "backup", &backup_mean);

    info!(log, "Fetch NNS public key");
    let nns_public_key = env
        .prep_dir("")
        .expect("missing NNS public key")
        .root_public_key_path();

    info!(log, "Generate config file for ic-backup");
    let subnet = SubnetConfig {
        subnet_id,
        initial_replica_version: initial_replica_version.clone(),
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
        push_metrics: true,
        metrics_urls: vec!["https://127.0.0.1:8080".try_into().unwrap()],
        network_name: "testnet".to_string(),
        backup_instance: "backup_test_node".to_string(),
        nns_url: Some(nns_node.get_public_url()),
        nns_pem: nns_public_key,
        root_dir: backup_dir.clone(),
        excluded_dirs: vec![],
        ssh_private_key: private_key_path,
        hot_disk_resource_threshold_percentage: 75,
        cold_disk_resource_threshold_percentage: 95,
        slack_token: "NO_TOKEN_IN_TESTING".to_string(),
        cold_storage,
        blacklisted_nodes: None,
        subnets: vec![subnet],
    };
    let config_str =
        serde_json::to_string(&config).expect("Config structure can't be converted to json");
    info!(log, "Config: {}", config_str);
    let config_file = config_dir.join("config.json5");
    let mut f = File::create(&config_file).expect("Should be able to create the config file");
    write!(f, "{config_str}").expect("Should be able to write the config file");

    info!(log, "Start the backup process in a separate thread");
    let ic_backup_path =
        &get_dependency_path(std::env::var("IC_BACKUP_PATH").expect("IC_BACKUP_PATH not set"));
    let mut command = Command::new(ic_backup_path);
    command
        .arg("--config-file")
        .arg(&config_file)
        .arg("--debug");
    info!(log, "Will execute: {:?}", command);

    let mut child = command
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start backup process");
    info!(log, "Started process: {}", child.id());

    info!(log, "Wait for archived checkpoint");
    let archive_dir = backup_dir.join("archive").join(subnet_id.to_string());
    // make sure we have some archive of the old version before upgrading to the new one
    loop {
        if highest_dir_entry(&archive_dir, 10) > 0 {
            info!(log, "A checkpoint has been archived");
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }

    info!(log, "Proposal to upgrade the subnet replica version");
    block_on(deploy_guestos_to_all_subnet_nodes(
        &nns_node,
        &target_version,
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
        .join(initial_replica_version.to_string())
        .join("0");
    let new_spool_dir = backup_dir
        .join("spool")
        .join(subnet_id.to_string())
        .join(target_version.to_string())
        .join("0");

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
            "New version: {}  Checkpoint: {}  Archive: {} Target: {} ",
            new_height,
            checkpoint,
            archive_height,
            good_progress,
        );
        if new_height > 0 && checkpoint > good_progress && archive_height > good_progress {
            info!(log, "New version was successfully backed up and archived");
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }

    info!(
        log,
        "Restart and wait for cold storage and divergence to happen"
    );
    child.kill().expect("Error killing backup process");
    child.wait().expect("Error waiting for backup process");

    let checkpoint =
        some_checkpoint_dir(&backup_dir, &subnet_id).expect("Checkpoint doesn't exist");

    let canister_dir = checkpoint.join("canister_states").join(canister_id_hex);
    let memory_artifact_path = fs::read_dir(canister_dir)
        .expect("Should read canister dir")
        .flatten()
        .map(|entry| entry.path())
        .find(|path| path.display().to_string().contains("vmemory_0"))
        .expect("Should find file");

    assert!(memory_artifact_path.exists());
    info!(log, "Removing memory file: {:?}", memory_artifact_path);
    fs::remove_file(&memory_artifact_path).unwrap();
    assert!(!memory_artifact_path.exists());

    info!(log, "Start again the backup process in a separate thread");
    let mut command = Command::new(ic_backup_path);
    command
        .arg("--config-file")
        .arg(&config_file)
        .arg("--debug");
    info!(log, "Will execute: {:?}", command);
    let mut child = command
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start backup process");
    info!(log, "Started process: {}", child.id());

    if !cold_storage_exists(&log, cold_storage_dir.join(subnet_id.to_string())) {
        info!(log, "Kill child process");
        child.kill().expect("Error killing backup process");
        panic!("No cold storage");
    }

    info!(log, "Artifacts and states are moved to cold storage");

    let mut hash_mismatch = false;
    for i in 0..60 {
        info!(log, "Checking logs for hash mismatch...");
        if let Ok(dirs) = fs::read_dir(backup_dir.join("logs")) {
            for en in dirs {
                info!(log, "DirEntry in logs: {:?}", en);
                match en {
                    Ok(d) => {
                        let contents = fs::read_to_string(d.path())
                            .expect("Should have been able to read the log file");
                        if i == 15 {
                            println!("{}", contents);
                        }

                        if contents.contains(DIVERGENCE_LOG_STR) {
                            hash_mismatch = true;
                            break;
                        }
                    }
                    Err(e) => error!(log, "Error opening log file: {:?}", e),
                }
            }
        } else {
            error!(log, "Error reading log file directory")
        }
        if hash_mismatch {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(10));
    }

    info!(log, "Kill child process");
    child.kill().expect("Error killing backup process");
    child.wait().expect("Error waiting for backup process");

    assert!(hash_mismatch);
    info!(log, "There was a divergence of the state");
}

fn some_checkpoint_dir(backup_dir: &Path, subnet_id: &SubnetId) -> Option<PathBuf> {
    let dir = backup_dir
        .join("data")
        .join(subnet_id.to_string())
        .join("ic_state");
    if !dir.exists() {
        return None;
    }
    let lcp = last_checkpoint(&dir);
    if lcp == 0 {
        return None;
    }
    Some(dir.join(format!("checkpoints/{lcp:016x}")))
}

fn cold_storage_exists(log: &Logger, cold_storage_dir: PathBuf) -> bool {
    for _ in 0..12 {
        if dir_exists_and_have_file(log, &cold_storage_dir.join("states"))
            && dir_exists_and_have_file(log, &cold_storage_dir.join("artifacts"))
        {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
    false
}

fn dir_exists_and_have_file(log: &Logger, dir: &PathBuf) -> bool {
    debug!(log, "Check directory: {:?}", dir);
    if !dir.exists() {
        debug!(log, "Doesn't exists!");
        return false;
    }
    debug!(log, "Directory exists!");
    let have_file = fs::read_dir(dir)
        .expect("Should be able to read existing directory")
        .next()
        .is_some();
    debug!(log, "Check does it contain file(s): {}", have_file);
    have_file
}

fn copy_file(binary_path: &Path, backup_binaries_dir: &Path, file_name: &str) {
    fs::copy(binary_path, backup_binaries_dir.join(file_name)).expect("failed to copy file");
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
