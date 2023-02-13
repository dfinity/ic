use std::{
    collections::HashSet,
    fs, io,
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
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_local_store::LocalStoreImpl;
use ic_registry_replicator::RegistryReplicator;
use ic_types::{PrincipalId, ReplicaVersion, SubnetId};
use slog::{error, info, Logger};
use tokio::runtime::Handle;

use crate::util::{block_on, sleep_secs};
use crate::{
    backup_helper::BackupHelper,
    cmd::BackupArgs,
    config::{ColdStorage, Config, SubnetConfig},
    notification_client::NotificationClient,
};

const DEFAULT_SYNC_NODES: usize = 5;
const DEFAULT_SYNC_PERIOD: u64 = 30;
const DEFAULT_REPLAY_PERIOD: u64 = 240;
const DEFAULT_VERSIONS_HOT: usize = 2;
const SECONDS_IN_DAY: u64 = 24u64 * 60 * 60;
const COLD_STORAGE_PERIOD: u64 = 60 * 60; // each hour
const PERIODIC_METRICS_PUSH_PERIOD: u64 = 5 * 60; // each 5 min

struct SubnetBackup {
    pub nodes_syncing: usize,
    pub sync_period: Duration,
    pub replay_period: Duration,
    pub backup_helper: BackupHelper,
}

pub struct BackupManager {
    pub version: u32,
    pub root_dir: PathBuf,
    pub local_store: Arc<LocalStoreImpl>,
    pub registry_client: Arc<RegistryClientImpl>,
    pub registry_replicator: Arc<RegistryReplicator>,
    subnet_backups: Vec<SubnetBackup>,
    pub log: Logger,
}

impl BackupManager {
    pub fn new(log: Logger, args: BackupArgs, rt: &Handle) -> Self {
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
            Err(e) => panic!("Bad file name for ssh credentials: {:?}", e),
        };
        let local_store_dir = config.root_dir.join("ic_registry_local_store");
        let data_provider = Arc::new(LocalStoreImpl::new(local_store_dir.clone()));
        let registry_client = Arc::new(RegistryClientImpl::new(data_provider, None));

        let local_store = Arc::new(LocalStoreImpl::new(local_store_dir));

        let replica_logger = ReplicaLogger::from(log.clone());
        let registry_replicator = Arc::new(RegistryReplicator::new_with_clients(
            replica_logger,
            local_store.clone(),
            registry_client.clone(),
            Duration::from_secs(30),
        ));
        let nns_public_key =
            parse_threshold_sig_key(&config.nns_pem).expect("Missing NNS public key");
        let nns_urls = vec![config.nns_url.expect("Missing NNS Url")];
        let reg_replicator2 = registry_replicator.clone();

        info!(log.clone(), "Starting the registry replicator");
        block_on(async {
            rt.spawn(async move {
                reg_replicator2
                    .start_polling(nns_urls, Some(nns_public_key))
                    .await
                    .expect("Failed to start registry replicator");
            })
            .await
            .expect("Task spawned in Tokio executor panicked")
        });
        info!(log.clone(), "Fetch and start polling");
        if let Err(err) = registry_client.fetch_and_start_polling() {
            error!(
                log.clone(),
                "Error fetching registry by the client: {}", err
            );
        }

        let mut backups = Vec::new();

        let downloads = Arc::new(Mutex::new(true));
        let disk_threshold_warn = config.disk_threshold_warn;

        for s in config.subnets {
            let notification_client = NotificationClient {
                push_metrics: config.push_metrics,
                backup_instance: config.backup_instance.clone(),
                slack_token: config.slack_token.clone(),
                subnet: s.subnet_id.to_string(),
                log: log.clone(),
            };
            let daily_replays: usize = SECONDS_IN_DAY
                .checked_div(s.replay_period_secs)
                .unwrap_or(0) as usize;
            let do_cold_storage = !s.disable_cold_storage;
            let backup_helper = BackupHelper {
                subnet_id: s.subnet_id,
                initial_replica_version: s.initial_replica_version,
                root_dir: config.root_dir.clone(),
                excluded_dirs: config.excluded_dirs.clone(),
                ssh_private_key: ssh_credentials_file.clone(),
                registry_client: registry_client.clone(),
                notification_client,
                downloads_guard: downloads.clone(),
                disk_threshold_warn,
                cold_storage_dir: cold_storage_dir.clone(),
                versions_hot,
                artifacts_guard: Mutex::new(true),
                daily_replays,
                do_cold_storage,
                thread_id: s.thread_id,
                log: log.clone(),
            };
            let sync_period = std::time::Duration::from_secs(s.sync_period_secs);
            let replay_period = std::time::Duration::from_secs(s.replay_period_secs);
            backups.push(SubnetBackup {
                nodes_syncing: s.nodes_syncing,
                sync_period,
                replay_period,
                backup_helper,
            });
        }
        BackupManager {
            version: config.version,
            root_dir: config.root_dir,
            local_store,
            registry_client,
            registry_replicator, // it will be used as a background task, so keep it
            subnet_backups: backups,
            log,
        }
    }

    pub fn upgrade(log: Logger, config_file: PathBuf) {
        let config = Config::load_config(config_file.clone()).expect("Config file can't be loaded");
        config
            .save_config(config_file)
            .expect("Config file couldn't be saved");
        info!(log, "Configuration updated...");
    }

    pub fn init(log: Logger, config_file: PathBuf) {
        let config = BackupManager::init_config(config_file);
        BackupManager::init_copy_states(log, config);
    }

    fn init_config(config_file: PathBuf) -> Config {
        let mut config =
            Config::load_config(config_file.clone()).expect("Config file can't be loaded");
        if !config.subnets.is_empty() {
            println!("Subnets are already configured!");
            return config;
        }

        let stdin = io::stdin();
        let mut thread_id = 0;
        loop {
            println!("Enter subnet ID of the subnet to backup (<ENTER> if done):");
            let mut subnet_id_str = String::new();
            let _ = stdin.read_line(&mut subnet_id_str);
            subnet_id_str = subnet_id_str.trim().to_string();
            if subnet_id_str.is_empty() {
                break;
            }
            let subnet_id = match PrincipalId::from_str(&subnet_id_str) {
                Ok(principal) => SubnetId::from(principal),
                Err(err) => {
                    println!("Couldn't parse the subnet id: {}", err);
                    println!("Try again!");
                    continue;
                }
            };

            println!("Enter the current replica version of the subnet:");
            let mut replica_version_str = String::new();
            let _ = stdin.read_line(&mut replica_version_str);
            let initial_replica_version = match ReplicaVersion::try_from(replica_version_str.trim())
            {
                Ok(version) => version,
                Err(err) => {
                    println!("Couldn't parse the replica version: {}", err);
                    println!("Try again!");
                    continue;
                }
            };

            println!(
                "Enter from how many nodes you'd like to sync this subnet (default {}):",
                DEFAULT_SYNC_NODES
            );
            let mut nodes_syncing_str = String::new();
            let _ = stdin.read_line(&mut nodes_syncing_str);
            let nodes_syncing = nodes_syncing_str
                .trim()
                .parse::<usize>()
                .unwrap_or(DEFAULT_SYNC_NODES);

            println!(
                "Enter period of syncing in minutes (default {}):",
                DEFAULT_SYNC_PERIOD
            );
            let mut sync_period_min = String::new();
            let _ = stdin.read_line(&mut sync_period_min);
            let sync_period_secs = 60
                * sync_period_min
                    .trim()
                    .parse::<u64>()
                    .unwrap_or(DEFAULT_SYNC_PERIOD);
            println!(
                "Enter period of replaying in minutes (default {}):",
                DEFAULT_REPLAY_PERIOD
            );
            let mut replay_period_min = String::new();
            let _ = stdin.read_line(&mut replay_period_min);
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
        let _ = stdin.read_line(&mut slack_token);
        config.slack_token = slack_token.trim().to_string();

        let cold_storage_dir = loop {
            println!("Enter the directory for the cold storage:");
            let mut cold_storage_str = String::new();
            let _ = stdin.read_line(&mut cold_storage_str);
            let cold_storage_path = PathBuf::from(&cold_storage_str.trim());
            if !cold_storage_path.exists() {
                println!("Directory doesn't exist!");
                continue;
            }
            break cold_storage_path;
        };
        let versions_hot = loop {
            println!(
                "How many replica versions to keep in the spool hot storage (default {}):",
                DEFAULT_VERSIONS_HOT
            );
            let mut versions_hot_str = String::new();
            let _ = stdin.read_line(&mut versions_hot_str);
            versions_hot_str = versions_hot_str.trim().to_string();
            if versions_hot_str.is_empty() {
                break DEFAULT_VERSIONS_HOT;
            }
            if let Ok(versions_num) = versions_hot_str.parse::<usize>() {
                if versions_num > 0 {
                    break versions_num;
                }
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

    fn init_copy_states(log: Logger, config: Config) {
        for b in &config.subnets {
            let data_dir = &config.root_dir.join("data").join(b.subnet_id.to_string());
            if !data_dir.exists() {
                fs::create_dir_all(data_dir).expect("Failure creating a directory");
            }
            if !data_dir.join("ic_state/checkpoints").exists() {
                let stdin = io::stdin();
                loop {
                    let mut state_dir_str = String::new();
                    println!("Enter ic_state directory for subnet {}:", b.subnet_id);
                    let _ = stdin.read_line(&mut state_dir_str);
                    let mut old_state_dir = PathBuf::from(&state_dir_str.trim());
                    if !old_state_dir.exists() {
                        println!("Error: directory {:?} doesn't exist!", old_state_dir);
                        continue;
                    }
                    old_state_dir = old_state_dir.join("ic_state");
                    if !old_state_dir.exists() {
                        println!("Error: directory {:?} doesn't exist!", old_state_dir);
                        continue;
                    }
                    if !old_state_dir.join("checkpoints").exists() {
                        println!(
                            "Error: directory {:?} doesn't have checkpints!",
                            old_state_dir
                        );
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

    pub fn do_backups(self: Arc<BackupManager>) {
        let size = self.subnet_backups.len();

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
            // should we sync the subnet
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
            for i in 0..size {
                let b = &self.subnet_backups[i].backup_helper;
                let last_block = b.retrieve_spool_top_height();
                let last_cp = b.last_state_checkpoint();
                let subnet = &b.subnet_id.to_string()[..5];
                progress.push(format!("{}: {}/{}", subnet, last_cp, last_block));

                b.notification_client.push_metrics_synced_height(last_block);
                b.notification_client.push_metrics_restored_height(last_cp);
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

            // announce the current version of the ic-backup on each cold storage check
            b.backup_helper
                .notification_client
                .push_metrics_version(m.version);

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
                let msg = format!(
                    "Error moving to cold storage for subnet {}: {:?}",
                    subnet_id, err
                );
                error!(m.log, "{}", msg);
                b.backup_helper
                    .notification_client
                    .report_failure_slack(msg);
            }
        }

        sleep_secs(COLD_STORAGE_PERIOD);
    }
}
