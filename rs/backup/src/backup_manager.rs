use std::{
    collections::HashSet,
    fs,
    io::BufRead,
    path::PathBuf,
    process::Command,
    str::FromStr,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key;
use ic_logger::ReplicaLogger;
use ic_recovery::command_helper::exec_cmd;
use ic_registry_replicator::RegistryReplicator;
use ic_types::{PrincipalId, ReplicaVersion, SubnetId};
use slog::{Logger, error, info, o};
use tokio_util::sync::CancellationToken;

use crate::{
    backup_helper::{BackupHelper, retrieve_replica_version_last_replayed},
    cmd::BackupArgs,
    config::{ColdStorage, Config, SubnetConfig},
    notification_client::NotificationClient,
    util::sleep_secs,
};

const DEFAULT_SYNC_NODES: usize = 5;
const DEFAULT_SYNC_PERIOD: u64 = 30;
const DEFAULT_REPLAY_PERIOD: u64 = 240;
const DEFAULT_VERSIONS_HOT: usize = 2;
const SECONDS_IN_DAY: u64 = 24u64 * 60 * 60;
const COLD_STORAGE_PERIOD: u64 = 60 * 60; // each hour
const PERIODIC_METRICS_PUSH_PERIOD: u64 = 5 * 60; // each 5 min

struct SubnetBackup {
    nodes_syncing: usize,
    sync_period: Duration,
    replay_period: Duration,
    backup_helper: BackupHelper,
}

pub struct BackupManager {
    _registry_replicator: RegistryReplicator,
    subnet_backups: Vec<SubnetBackup>,
    log: Logger,
}

impl BackupManager {
    pub async fn new(log: Logger, args: BackupArgs, cancellation_token: CancellationToken) -> Self {
        let config = Config::load_config(args.config_file).expect("Config file can't be loaded");
        // verification that all is initialized with the init command
        if config.subnets.is_empty() {
            panic!("No subnets are configured for backup")
        }
        let ColdStorage {
            cold_storage_dir,
            versions_hot,
        } = match config.cold_storage {
            Some(cs) => cs,
            None => panic!("Cold storage and cleanup are not configured"),
        };
        let ssh_credentials_file = match config.ssh_private_key.into_os_string().into_string() {
            Ok(f) => f,
            Err(e) => panic!("Bad file name for ssh credentials: {e:?}"),
        };

        let replica_logger = ReplicaLogger::from(log.clone());
        let local_store_dir = config.root_dir.join("ic_registry_local_store");
        let nns_urls = vec![config.nns_url.expect("Missing NNS Url")];
        let nns_public_key =
            parse_threshold_sig_key(&config.nns_pem).expect("Missing NNS public key");

        let registry_replicator = RegistryReplicator::new(
            replica_logger,
            &local_store_dir,
            Duration::from_secs(30),
            nns_urls,
            Some(nns_public_key),
        )
        .await;

        info!(log, "Starting the registry replicator");
        let registry_replicator_future = registry_replicator
            .start_polling(cancellation_token)
            .expect("Failed to start registry replicator");

        info!(log, "Spawning the registry replicator background thread.");
        tokio::spawn(registry_replicator_future);

        let mut backups = Vec::new();

        let downloads = Arc::new(Mutex::new(true));
        let blacklisted = Arc::new(config.blacklisted_nodes.unwrap_or_default());

        for subnet_config in config.subnets {
            let subnet_log =
                log.new(o!("subnet" => subnet_config.subnet_id.to_string()[..5].to_string()));
            let notification_client = NotificationClient {
                push_metrics: config.push_metrics,
                metrics_urls: config.metrics_urls.clone(),
                network_name: config.network_name.clone(),
                backup_instance: config.backup_instance.clone(),
                slack_token: config.slack_token.clone(),
                subnet: subnet_config.subnet_id.to_string(),
                log: subnet_log.clone(),
            };
            let daily_replays: usize = SECONDS_IN_DAY
                .checked_div(subnet_config.replay_period_secs)
                .unwrap_or(0) as usize;
            let backup_helper = BackupHelper {
                subnet_id: subnet_config.subnet_id,
                initial_replica_version: subnet_config.initial_replica_version,
                root_dir: config.root_dir.clone(),
                excluded_dirs: config.excluded_dirs.clone(),
                ssh_private_key: ssh_credentials_file.clone(),
                registry_client: registry_replicator.get_registry_client(),
                notification_client,
                downloads_guard: downloads.clone(),
                hot_disk_resource_threshold_percentage: config
                    .hot_disk_resource_threshold_percentage,
                cold_disk_resource_threshold_percentage: config
                    .cold_disk_resource_threshold_percentage,
                cold_storage_dir: cold_storage_dir.clone(),
                versions_hot,
                artifacts_guard: Mutex::new(true),
                daily_replays,
                do_cold_storage: !subnet_config.disable_cold_storage,
                thread_id: subnet_config.thread_id,
                blacklisted_nodes: blacklisted.clone(),
                log: subnet_log.clone(),
            };

            backups.push(SubnetBackup {
                nodes_syncing: subnet_config.nodes_syncing,
                sync_period: Duration::from_secs(subnet_config.sync_period_secs),
                replay_period: Duration::from_secs(subnet_config.replay_period_secs),
                backup_helper,
            });
        }

        BackupManager {
            _registry_replicator: registry_replicator, // it will be used as a background task, so keep it
            subnet_backups: backups,
            log,
        }
    }

    pub fn get_version(log: Logger, config_file: PathBuf, subnet_id: SubnetId) {
        let config = Config::load_config(config_file).expect("Config file can't be loaded");
        let spool_dir = config.root_dir.join("spool").join(subnet_id.to_string());
        let state_dir = config.root_dir.join(format!("data/{subnet_id}/ic_state"));
        let replica_version = retrieve_replica_version_last_replayed(&log, spool_dir, state_dir)
            .expect("Proper replica version is expected");
        println!("{replica_version}")
    }

    pub fn upgrade(log: Logger, config_file: PathBuf) {
        let config = Config::load_config(config_file.clone()).expect("Config file can't be loaded");
        config
            .save_config(config_file)
            .expect("Config file couldn't be saved");
        info!(log, "Configuration updated...");
    }

    pub fn init(reader: &mut impl BufRead, log: Logger, config_file: PathBuf) {
        let config = BackupManager::init_config(reader, config_file);
        BackupManager::init_copy_states(reader, log, config);
    }

    fn init_config(reader: &mut impl BufRead, config_file: PathBuf) -> Config {
        let mut config =
            Config::load_config(config_file.clone()).expect("Config file can't be loaded");
        if !config.subnets.is_empty() {
            println!("Subnets are already configured!");
            return config;
        }

        let mut thread_id = 0;
        loop {
            println!("Enter subnet ID of the subnet to backup (<ENTER> if done):");
            let mut subnet_id_str = String::new();
            let _ = reader.read_line(&mut subnet_id_str);
            subnet_id_str = subnet_id_str.trim().to_string();
            if subnet_id_str.is_empty() {
                break;
            }
            let subnet_id = match PrincipalId::from_str(&subnet_id_str) {
                Ok(principal) => SubnetId::from(principal),
                Err(err) => {
                    println!("Couldn't parse the subnet id: {err}");
                    println!("Try again!");
                    continue;
                }
            };

            println!("Enter the current replica version of the subnet:");
            let mut replica_version_str = String::new();
            let _ = reader.read_line(&mut replica_version_str);
            let initial_replica_version = match ReplicaVersion::try_from(replica_version_str.trim())
            {
                Ok(version) => version,
                Err(err) => {
                    println!("Couldn't parse the replica version: {err}");
                    println!("Try again!");
                    continue;
                }
            };

            println!(
                "Enter from how many nodes you'd like to sync this subnet (default {DEFAULT_SYNC_NODES}):"
            );
            let mut nodes_syncing_str = String::new();
            let _ = reader.read_line(&mut nodes_syncing_str);
            let nodes_syncing = nodes_syncing_str
                .trim()
                .parse::<usize>()
                .unwrap_or(DEFAULT_SYNC_NODES);

            println!("Enter period of syncing in minutes (default {DEFAULT_SYNC_PERIOD}):");
            let mut sync_period_min = String::new();
            let _ = reader.read_line(&mut sync_period_min);
            let sync_period_secs = 60
                * sync_period_min
                    .trim()
                    .parse::<u64>()
                    .unwrap_or(DEFAULT_SYNC_PERIOD);
            println!("Enter period of replaying in minutes (default {DEFAULT_REPLAY_PERIOD}):");
            let mut replay_period_min = String::new();
            let _ = reader.read_line(&mut replay_period_min);
            let replay_period_secs = 60
                * replay_period_min
                    .trim()
                    .parse::<u64>()
                    .unwrap_or(DEFAULT_REPLAY_PERIOD);
            thread_id += 1; // run all of them in parallel
            config.subnets.push(SubnetConfig {
                subnet_id,
                initial_replica_version,
                nodes_syncing,
                sync_period_secs,
                replay_period_secs,
                thread_id,
                disable_cold_storage: false,
            })
        }

        println!("Enter the Slack token:");
        let mut slack_token = String::new();
        let _ = reader.read_line(&mut slack_token);
        config.slack_token = slack_token.trim().to_string();

        let cold_storage_dir = loop {
            println!("Enter the directory for the cold storage:");
            let mut cold_storage_str = String::new();
            let _ = reader.read_line(&mut cold_storage_str);
            let cold_storage_path = PathBuf::from(&cold_storage_str.trim());
            if !cold_storage_path.exists() {
                println!("Directory doesn't exist!");
                continue;
            }
            break cold_storage_path;
        };
        let versions_hot = loop {
            println!(
                "How many replica versions to keep in the spool hot storage (default {DEFAULT_VERSIONS_HOT}):"
            );
            let mut versions_hot_str = String::new();
            let _ = reader.read_line(&mut versions_hot_str);
            versions_hot_str = versions_hot_str.trim().to_string();
            if versions_hot_str.is_empty() {
                break DEFAULT_VERSIONS_HOT;
            }
            if let Ok(versions_num) = versions_hot_str.parse::<usize>()
                && versions_num > 0
            {
                break versions_num;
            }
            println!("Error: invalid number was entered!")
        };

        config.cold_storage = Some(ColdStorage {
            cold_storage_dir,
            versions_hot,
        });

        config
            .save_config(config_file)
            .expect("Config file couldn't be saved");

        config
    }

    fn init_copy_states(reader: &mut impl BufRead, log: Logger, config: Config) {
        for b in &config.subnets {
            let data_dir = &config.root_dir.join("data").join(b.subnet_id.to_string());
            if !data_dir.exists() {
                fs::create_dir_all(data_dir).expect("Failure creating a directory");
            }
            if !data_dir.join("ic_state/checkpoints").exists() {
                loop {
                    let mut state_dir_str = String::new();
                    println!("Enter ic_state directory for subnet {}:", b.subnet_id);
                    let _ = reader.read_line(&mut state_dir_str);
                    let mut old_state_dir = PathBuf::from(&state_dir_str.trim());
                    if !old_state_dir.exists() {
                        println!("Error: directory {old_state_dir:?} doesn't exist!");
                        continue;
                    }
                    old_state_dir = old_state_dir.join("ic_state");
                    if !old_state_dir.exists() {
                        println!("Error: directory {old_state_dir:?} doesn't exist!");
                        continue;
                    }
                    if !old_state_dir.join("checkpoints").exists() {
                        println!("Error: directory {old_state_dir:?} doesn't have checkpoints!");
                        continue;
                    }
                    let mut cmd = Command::new("rsync");
                    cmd.arg("-a").arg(old_state_dir).arg(data_dir);
                    info!(log, "Will execute: {:?}", cmd);
                    if let Err(e) = exec_cmd(&mut cmd) {
                        println!("Error: {}", e);
                    } else {
                        break;
                    }
                }
            }
        }
    }

    /// Note: this method does some blocking operations so be careful when running it
    /// in an async context.
    pub fn do_backups(self: Arc<BackupManager>) {
        let size = self.subnet_backups.len();

        if let Some(backup) = self.subnet_backups.first() {
            backup
                .backup_helper
                .notification_client
                .push_metrics_version();
        }

        for i in 0..size {
            // should we sync the subnet
            if self.subnet_backups[i].sync_period >= Duration::from_secs(1) {
                self.subnet_backups[i].backup_helper.create_spool_dir();
                let m = self.clone();
                thread::spawn(move || sync_subnet(m, i));
            }
        }

        let mut thread_ids: HashSet<u32> = HashSet::new();
        for i in 0..size {
            // should we replay the subnet
            if self.subnet_backups[i].replay_period >= Duration::from_secs(1) {
                let id = self.subnet_backups[i].backup_helper.thread_id;
                if !thread_ids.contains(&id) {
                    thread_ids.insert(id);
                    let m = self.clone();
                    thread::spawn(move || replay_subnets(m, id));
                }
            }
        }

        let m = self.clone();
        thread::spawn(move || cold_store(m));

        loop {
            let mut progress = Vec::new();
            for backup in &self.subnet_backups {
                let backup_helper = &backup.backup_helper;
                let last_block = backup_helper.retrieve_spool_top_height();
                let last_cp = backup_helper.last_state_checkpoint();
                let subnet = &backup_helper.subnet_id.to_string()[..5];
                progress.push(format!("{subnet}: {last_cp}/{last_block}"));

                backup_helper
                    .notification_client
                    .push_metrics_synced_height(last_block);
                backup_helper
                    .notification_client
                    .push_metrics_restored_height(last_cp);
                let _ = backup_helper.log_disk_stats(false);
            }
            info!(self.log, "Replay/Sync - {}", progress.join(", "));

            sleep_secs(PERIODIC_METRICS_PUSH_PERIOD);
        }
    }
}

fn sync_subnet(m: Arc<BackupManager>, i: usize) {
    let b = &m.subnet_backups[i];
    let subnet_id = &b.backup_helper.subnet_id;
    info!(m.log, "Spawned sync for subnet {:?} thread...", subnet_id);
    let mut sync_last_time = Instant::now() - b.sync_period;
    loop {
        if sync_last_time.elapsed() > b.sync_period {
            match b.backup_helper.collect_nodes(b.nodes_syncing) {
                Ok(nodes) => {
                    sync_last_time = Instant::now();
                    b.backup_helper.sync_files(&nodes);
                }
                Err(e) => error!(m.log, "Error fetching subnet node list: {:?}", e),
            }
        }

        sleep_secs(30);
    }
}

fn replay_subnets(m: Arc<BackupManager>, thread_id: u32) {
    info!(m.log, "Spawned replay for ID {thread_id} thread...");
    let size = m.subnet_backups.len();
    let mut replay_last_time = Vec::new();
    m.subnet_backups
        .iter()
        .for_each(|b| replay_last_time.push(Instant::now() - b.replay_period));
    loop {
        for (i, it) in replay_last_time.iter_mut().enumerate().take(size) {
            let b = &m.subnet_backups[i];
            if b.backup_helper.thread_id != thread_id {
                continue;
            }
            if it.elapsed() > b.replay_period {
                *it = Instant::now();
                b.backup_helper.replay();
            }
        }

        sleep_secs(30);
    }
}

fn cold_store(m: Arc<BackupManager>) {
    info!(m.log, "Spawned cold storage thread...");
    let size = m.subnet_backups.len();
    loop {
        for i in 0..size {
            let b = &m.subnet_backups[i];

            let subnet_id = &b.backup_helper.subnet_id;
            match b.backup_helper.need_cold_storage_move() {
                Ok(need) => {
                    if !need {
                        continue;
                    }
                }
                Err(e) => {
                    error!(
                        m.log,
                        "Error checking for cold store on subnet {}: {:?}", subnet_id, e
                    );
                    continue;
                }
            };
            if let Err(err) = b.backup_helper.do_move_cold_storage() {
                let msg = format!("Error moving to cold storage for subnet {subnet_id}: {err:?}");
                error!(m.log, "{}", msg);
                b.backup_helper
                    .notification_client
                    .report_failure_slack(msg);
            }
        }

        sleep_secs(COLD_STORAGE_PERIOD);
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Write};

    use ic_logger::replica_logger::no_op_logger;
    use ic_test_utilities_tmpdir::tmpdir;

    use super::*;

    const FAKE_SUBNET_ID: &str = "drqnc-7tqyt-atxvj-gc6rp-lly5u-i6kqv-37nvv-uncaw-7vpwn-rx33x-aqe";
    const FAKE_INITIAL_REPLICA_VERSION: &str = "26";
    const FAKE_NODES_SYNCING: usize = 6;
    const FAKE_SYNC_PERIOD_MINS: u64 = 27;
    const FAKE_REPLAY_PERIOD_MINS: u64 = 154;
    const FAKE_VERSIONS_HOT: usize = 7;
    const FAKE_SLACK_TOKEN: &str = "FAKE_SLACK_TOKEN";

    /// Read the config from `test_data/fake_input_config.json`, pass several fake values as inputs
    /// to `BackupManager::init`.
    #[test]
    fn init_test() {
        let dir = tmpdir("test_dir");
        let fake_config_path = dir.as_ref().join("fake_config.json");
        let fake_ssh_private_key_path = dir.as_ref().join("fake_ssh_private_key");
        let fake_cold_storage_path = dir.as_ref().join("fake_cold_storage");
        let fake_state_path = dir.as_ref().join("fake_state");
        std::fs::create_dir_all(&fake_cold_storage_path).unwrap();
        std::fs::create_dir_all(fake_state_path.join("ic_state/checkpoints")).unwrap();
        File::create(&fake_ssh_private_key_path).unwrap();

        let fake_input_config = include_str!("../test_data/fake_input_config.json.template")
            .replace(
                "SSH_PRIVATE_KEY_TEMPLATE",
                &fake_ssh_private_key_path.to_string_lossy(),
            );

        let mut f = File::create(&fake_config_path).unwrap();
        write!(f, "{fake_input_config}").unwrap();

        let fake_cold_storage_path_str = fake_cold_storage_path.to_string_lossy();
        let fake_state_path_str = fake_state_path.to_string_lossy();

        let mut cursor = std::io::Cursor::new(
            ([
                FAKE_SUBNET_ID,
                FAKE_INITIAL_REPLICA_VERSION,
                &FAKE_NODES_SYNCING.to_string(),
                &FAKE_SYNC_PERIOD_MINS.to_string(),
                &FAKE_REPLAY_PERIOD_MINS.to_string(),
                /*skip*/ "",
                FAKE_SLACK_TOKEN,
                &fake_cold_storage_path_str,
                &FAKE_VERSIONS_HOT.to_string(),
                &fake_state_path_str,
            ])
            .join("\n"),
        );

        BackupManager::init(
            &mut cursor,
            no_op_logger().inner_logger.root,
            fake_config_path.clone(),
        );

        let expected_config = Config {
            subnets: vec![SubnetConfig {
                subnet_id: SubnetId::from(PrincipalId::from_str(FAKE_SUBNET_ID).unwrap()),
                initial_replica_version: ReplicaVersion::try_from(FAKE_INITIAL_REPLICA_VERSION)
                    .unwrap(),
                nodes_syncing: FAKE_NODES_SYNCING,
                sync_period_secs: FAKE_SYNC_PERIOD_MINS * 60,
                replay_period_secs: FAKE_REPLAY_PERIOD_MINS * 60,
                thread_id: 1,
                disable_cold_storage: false,
            }],
            cold_storage: Some(ColdStorage {
                cold_storage_dir: fake_cold_storage_path,
                versions_hot: FAKE_VERSIONS_HOT,
            }),
            slack_token: FAKE_SLACK_TOKEN.to_string(),
            ..serde_json::from_str(&fake_input_config).unwrap()
        };

        let config = Config::load_config(fake_config_path).unwrap();

        assert_eq!(config, expected_config);
    }
}
