use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, Write},
    path::PathBuf,
    process::Command,
    sync::{Arc, Mutex, RwLock},
    thread,
    time::{Duration, Instant},
};

use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key;
use ic_logger::ReplicaLogger;
use ic_recovery::command_helper::exec_cmd;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_local_store::LocalStoreImpl;
use ic_registry_replicator::RegistryReplicator;
use ic_types::{ReplicaVersion, SubnetId};
use serde::{Deserialize, Serialize};
use slog::{error, info, Logger};
use tokio::runtime::Handle;

use crate::config::Config;
use crate::util::{block_on, sleep_secs};
use crate::{backup_helper::BackupHelper, notification_client::NotificationClient};

const STATE_FILE_NAME: &str = "backup_manager_state.json5";

struct SubnetBackup {
    pub nodes_syncing: usize,
    pub sync_period: Duration,
    pub replay_period: Duration,
    pub backup_helper: BackupHelper,
}

pub struct BackupManager {
    pub root_dir: PathBuf,
    pub local_store: Arc<LocalStoreImpl>,
    pub registry_client: Arc<RegistryClientImpl>,
    pub registry_replicator: Option<Arc<RegistryReplicator>>,
    subnet_backups: Vec<SubnetBackup>,
    save_state: RwLock<BackupManagerState>,
    pub log: Logger,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct SubnetState {
    #[serde(
        deserialize_with = "crate::util::replica_from_string",
        serialize_with = "crate::util::replica_to_string"
    )]
    pub replica_version: ReplicaVersion,
    #[serde(with = "serde_millis")]
    pub sync_last_time: Instant,
    #[serde(with = "serde_millis")]
    pub replay_last_time: Instant,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct BackupManagerState {
    pub subnet_states: HashMap<SubnetId, SubnetState>,
    #[serde(skip)]
    pub dirty: bool,
}

fn fetch_value_or_default<T>(
    state: &Result<BackupManagerState, String>,
    subnet_id: &SubnetId,
    fetch_value_fn: fn(&SubnetState) -> T,
    default_value: T,
) -> T {
    match state {
        Ok(ms) => match ms.subnet_states.get(subnet_id) {
            Some(subnet_state) => fetch_value_fn(subnet_state),
            None => default_value,
        },
        _ => default_value,
    }
}

impl BackupManager {
    pub fn new(config_file: PathBuf, rt: &Handle, init: bool, log: Logger) -> Self {
        let config = Config::load_config(config_file).expect("Updated config file can't be loaded");
        // Load the manager state
        let state_file = config.root_dir.join(STATE_FILE_NAME);
        let manager_state = load_state_file(&state_file);
        if !init {
            info!(log, "Loaded manager state: {:?}", manager_state);
        }
        let ssh_credentials_file = match config.ssh_private_key.into_os_string().into_string() {
            Ok(f) => f,
            Err(e) => panic!("Bad file name for ssh credentials: {:?}", e),
        };
        let nns_url = config.nns_url.expect("Missing NNS Url");
        let local_store_dir = config.root_dir.join("ic_registry_local_store");
        let data_provider = Arc::new(LocalStoreImpl::new(local_store_dir.clone()));
        let registry_client = Arc::new(RegistryClientImpl::new(data_provider, None));

        let local_store = Arc::new(LocalStoreImpl::new(local_store_dir));
        let registry_replicator = if init {
            None
        } else {
            let replica_logger = ReplicaLogger::from(log.clone());
            let reg_replicator = Arc::new(RegistryReplicator::new_with_clients(
                replica_logger,
                local_store.clone(),
                registry_client.clone(),
                Duration::from_secs(30),
            ));
            let nns_public_key =
                parse_threshold_sig_key(&config.nns_pem).expect("Missing NNS public key");
            let nns_urls = vec![nns_url.clone()];
            let reg_replicator2 = reg_replicator.clone();

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
            Some(reg_replicator)
        };

        let mut backups = Vec::new();
        let mut save_state = BackupManagerState::default();

        let downloads = Arc::new(Mutex::new(true));
        let disk_threshold_warn = config.disk_threshold_warn;

        for s in config.subnets {
            let replica_version = fetch_value_or_default(
                &manager_state,
                &s.subnet_id,
                |sub| sub.replica_version.clone(),
                s.initial_replica_version,
            );
            let notification_client = NotificationClient {
                ic_name_metrics: config.ic_name_metrics.clone(),
                backup_instance: config.backup_instance.clone(),
                slack_token: config.slack_token.clone(),
                subnet: s.subnet_id.to_string(),
                log: log.clone(),
            };
            let backup_helper = BackupHelper {
                subnet_id: s.subnet_id,
                nns_url: nns_url.to_string(),
                root_dir: config.root_dir.clone(),
                excluded_dirs: config.excluded_dirs.clone(),
                ssh_private_key: ssh_credentials_file.clone(),
                registry_client: registry_client.clone(),
                notification_client,
                downloads: downloads.clone(),
                disk_threshold_warn,
                log: log.clone(),
            };
            let sync_period = std::time::Duration::from_secs(s.sync_period_secs);
            let replay_period = std::time::Duration::from_secs(s.replay_period_secs);
            let sync_last_time = fetch_value_or_default(
                &manager_state,
                &s.subnet_id,
                |sub| sub.sync_last_time,
                Instant::now() - sync_period,
            );
            let replay_last_time = fetch_value_or_default(
                &manager_state,
                &s.subnet_id,
                |sub| sub.replay_last_time,
                Instant::now() - replay_period,
            );
            backups.push(SubnetBackup {
                nodes_syncing: s.nodes_syncing,
                sync_period,
                replay_period,
                backup_helper,
            });
            save_state.subnet_states.insert(
                s.subnet_id,
                SubnetState {
                    replica_version,
                    sync_last_time,
                    replay_last_time,
                },
            );
        }
        BackupManager {
            root_dir: config.root_dir,
            local_store,
            registry_client,
            registry_replicator, // it will be used as a background task, so keep it
            subnet_backups: backups,
            save_state: RwLock::new(save_state),
            log,
        }
    }

    pub fn init(&self) {
        for b in &self.subnet_backups {
            if !b.backup_helper.data_dir().exists() {
                fs::create_dir_all(b.backup_helper.data_dir())
                    .expect("Failure creating a directory");
            }
            if !b
                .backup_helper
                .data_dir()
                .join("ic_state/checkpoints")
                .exists()
            {
                let stdin = io::stdin();
                loop {
                    let mut state_dir = String::new();
                    println!(
                        "Enter ic_state directory for subnet {}:",
                        b.backup_helper.subnet_id
                    );
                    let _ = stdin.read_line(&mut state_dir);
                    let old_state_dir = PathBuf::from(&state_dir.trim());
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
                    cmd.arg("-a")
                        .arg(old_state_dir)
                        .arg(b.backup_helper.data_dir());
                    info!(self.log, "Will execute: {:?}", cmd);
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
            if self.subnet_backups[i].sync_period >= Duration::from_secs(1) {
                let m = self.clone();
                thread::spawn(move || sync_subnet(m, i));
            }
        }

        for i in 0..size {
            if self.subnet_backups[i].replay_period >= Duration::from_secs(1) {
                let m = self.clone();
                thread::spawn(move || replay_subnet(m, i));
            }
        }

        let config_file = self.root_dir.join(STATE_FILE_NAME);
        loop {
            // Continuosly save the state
            let mut save_state = self.save_state.write().expect("write lock failed");
            if save_state.dirty {
                if let Err(err) = save_state_file(&save_state, &config_file) {
                    error!(self.log, "Error saving state: {:?}", err);
                }
                save_state.dirty = false;
            }
            drop(save_state);

            // Have a small break before the next check for save
            sleep_secs(30);
        }
    }

    fn get_value<T>(&self, subnet_id: &SubnetId, getter: fn(&SubnetState) -> T) -> T {
        let locked_state = self.save_state.read().expect("read lock failed");
        let subnet_state = locked_state
            .subnet_states
            .get(subnet_id)
            .expect("missing record for subnet_id");
        getter(subnet_state)
    }

    fn set_value<T>(&self, subnet_id: &SubnetId, setter: fn(&mut SubnetState, T), value: T) {
        let mut locked_state = self.save_state.write().expect("write lock failed");
        let subnet_state = locked_state
            .subnet_states
            .get_mut(subnet_id)
            .expect("missing record for subnet_id");
        setter(subnet_state, value);
        locked_state.dirty = true;
    }
}

fn sync_subnet(m: Arc<BackupManager>, i: usize) {
    let b = &m.subnet_backups[i];
    let subnet_id = &b.backup_helper.subnet_id;
    loop {
        let sync_last_time = m.get_value(subnet_id, |s| s.sync_last_time);
        if sync_last_time.elapsed() > b.sync_period {
            match b.backup_helper.collect_nodes(b.nodes_syncing) {
                Ok(nodes) => {
                    b.backup_helper.sync_files(&nodes);
                    m.set_value(subnet_id, |s, v| s.sync_last_time = v, Instant::now())
                }
                Err(e) => error!(m.log, "Error fetching subnet node list: {:?}", e),
            }
        }
        // Have a small break before the next check for sync
        sleep_secs(30);
    }
}

fn replay_subnet(m: Arc<BackupManager>, i: usize) {
    let b = &m.subnet_backups[i];
    let subnet_id = &b.backup_helper.subnet_id;
    loop {
        let replay_last_time = m.get_value(subnet_id, |s| s.replay_last_time);
        if replay_last_time.elapsed() > b.replay_period {
            let current_replica_version = m.get_value(subnet_id, |s| s.replica_version.clone());
            let new_replica_version = b.backup_helper.replay(current_replica_version);
            m.set_value(subnet_id, |s, v| s.replica_version = v, new_replica_version);
            m.set_value(subnet_id, |s, v| s.replay_last_time = v, Instant::now());
        }
        // Have a small break before the next check for replay
        sleep_secs(30);
    }
}

fn save_state_file(state: &BackupManagerState, state_file: &PathBuf) -> Result<(), String> {
    let json =
        json5::to_string(state).map_err(|err| format!("Error serializing state: {:?}", err))?;
    let mut file =
        File::create(state_file).map_err(|err| format!("Error creating state file: {:?}", err))?;
    file.write_all(json.as_bytes())
        .map_err(|err| format!("Error writing state: {:?}", err))
}

fn load_state_file(state_file: &PathBuf) -> Result<BackupManagerState, String> {
    let cfg_str = fs::read_to_string(state_file)
        .map_err(|err| format!("Error loading state file: {:?}", err))?;
    json5::from_str::<BackupManagerState>(&cfg_str)
        .map_err(|err| format!("Error deserializing state: {:?}", err))
}
