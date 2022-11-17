use std::{
    collections::HashMap,
    fs::{self, File},
    io::Write,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key;
use ic_logger::ReplicaLogger;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_local_store::LocalStoreImpl;
use ic_registry_replicator::RegistryReplicator;
use ic_types::{ReplicaVersion, SubnetId};
use rand::{seq::SliceRandom, thread_rng};
use serde::{Deserialize, Serialize};
use slog::{error, info, Logger};
use tokio::runtime::Handle;
use url::Url;

use crate::config::Config;
use crate::util::{block_on, sleep_secs};
use crate::{backup_helper::BackupHelper, notification_client::NotificationClient};

const STATE_FILE_NAME: &str = "backup_manager_state.json5";

pub struct SubnetBackup {
    pub nodes_syncing: u32,
    pub sync_last_time: Instant,
    pub sync_period: Duration,
    pub replay_last_time: Instant,
    pub replay_period: Duration,
    pub backup_helper: BackupHelper,
}
pub struct BackupManager {
    pub root_dir: PathBuf,
    pub nns_url: Url,
    pub local_store: Arc<LocalStoreImpl>,
    pub registry_client: Arc<RegistryClientImpl>,
    pub registry_replicator: Arc<RegistryReplicator>,
    pub subnet_backups: Vec<SubnetBackup>,
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
    pub fn new(config_file: PathBuf, rt: &Handle, log: Logger) -> Self {
        let config = Config::load_config(config_file).expect("Updated config file can't be loaded");
        // Load the manager state
        let state_file = config.root_dir.join(STATE_FILE_NAME);
        let manager_state = BackupManager::load_state(&state_file);
        info!(log, "Loaded manager state: {:?}", manager_state);
        let ssh_credentials_file = match config.ssh_private_key.into_os_string().into_string() {
            Ok(f) => f,
            Err(e) => panic!("Bad file name for ssh credentials: {:?}", e),
        };
        let nns_url = config.nns_url.expect("Missing NNS Url");
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
        let nns_urls = vec![nns_url.clone()];
        let registry_replicator2 = registry_replicator.clone();

        info!(log.clone(), "Starting the registry replicator");
        block_on(async {
            rt.spawn(async move {
                registry_replicator2
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
        for s in config.subnets {
            let replica_version = fetch_value_or_default(
                &manager_state,
                &s.subnet_id,
                |sub| sub.replica_version.clone(),
                s.initial_replica_version,
            );
            let notification_client = NotificationClient {
                backup_instance: config.backup_instance.clone(),
                slack_token: config.slack_token.clone(),
                subnet: s.subnet_id.to_string(),
                log: log.clone(),
            };
            let backup_helper = BackupHelper {
                replica_version,
                subnet_id: s.subnet_id,
                nns_url: nns_url.to_string(),
                root_dir: config.root_dir.clone(),
                excluded_dirs: config.excluded_dirs.clone(),
                ssh_private_key: ssh_credentials_file.clone(),
                registry_client: registry_client.clone(),
                notification_client,
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
                sync_last_time,
                sync_period,
                replay_last_time,
                replay_period,
                backup_helper,
            });
        }
        BackupManager {
            root_dir: config.root_dir,
            nns_url,
            local_store,
            registry_client,
            registry_replicator, // it will be used as a background task, so keep it
            subnet_backups: backups,
            log,
        }
    }

    pub fn do_backups(&mut self) {
        let config_file = self.root_dir.join(STATE_FILE_NAME);

        loop {
            let mut state = BackupManagerState::default();
            for b in &self.subnet_backups {
                let s = SubnetState {
                    replica_version: b.backup_helper.replica_version.clone(),
                    sync_last_time: b.sync_last_time,
                    replay_last_time: b.replay_last_time,
                };
                state.subnet_states.insert(b.backup_helper.subnet_id, s);
            }
            for b in &mut self.subnet_backups {
                if b.sync_last_time.elapsed() > b.sync_period {
                    match b.backup_helper.collect_subnet_nodes() {
                        Ok(nodes) => {
                            let mut shuf_nodes = nodes;
                            shuf_nodes.shuffle(&mut thread_rng());
                            b.backup_helper.sync_files(
                                &shuf_nodes
                                    .iter()
                                    .take(b.nodes_syncing as usize)
                                    .collect::<Vec<_>>(),
                            );
                            b.sync_last_time = Instant::now();
                            // save the updated state
                            let s = state
                                .subnet_states
                                .get_mut(&b.backup_helper.subnet_id)
                                .expect("HashMap should still contain the value");
                            s.sync_last_time = b.sync_last_time;
                            if let Err(err) = BackupManager::save_state(&state, &config_file) {
                                error!(self.log, "Error saving state: {:?}", err);
                            }
                        }
                        Err(e) => error!(self.log, "Error fetching subnet node list: {:?}", e),
                    }
                }
                if b.replay_last_time.elapsed() > b.replay_period {
                    b.backup_helper.replay();
                    b.replay_last_time = Instant::now();
                    // save the updated state
                    let s = state
                        .subnet_states
                        .get_mut(&b.backup_helper.subnet_id)
                        .expect("HashMap should still contain the value");
                    s.replay_last_time = b.replay_last_time;
                    s.replica_version = b.backup_helper.replica_version.clone();
                    if let Err(err) = BackupManager::save_state(&state, &config_file) {
                        error!(self.log, "Error saving state: {:?}", err);
                    }
                }
            }

            // Have a small break before the next round of checks
            sleep_secs(30);
        }
    }

    fn save_state(state: &BackupManagerState, state_file: &PathBuf) -> Result<(), String> {
        let json =
            json5::to_string(state).map_err(|err| format!("Error serializing state: {:?}", err))?;
        let mut file = File::create(state_file)
            .map_err(|err| format!("Error creating state file: {:?}", err))?;
        file.write_all(json.as_bytes())
            .map_err(|err| format!("Error writing state: {:?}", err))
    }

    fn load_state(state_file: &PathBuf) -> Result<BackupManagerState, String> {
        let cfg_str = fs::read_to_string(&state_file)
            .map_err(|err| format!("Error loading state file: {:?}", err))?;
        json5::from_str::<BackupManagerState>(&cfg_str)
            .map_err(|err| format!("Error deserializing state: {:?}", err))
    }
}
