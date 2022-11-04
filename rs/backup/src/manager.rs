use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use ic_registry_client::client::RegistryClientImpl;
use ic_registry_local_store::LocalStoreImpl;
use ic_types::{ReplicaVersion, SubnetId};
use slog::{error, Logger};

use crate::backup_helper::BackupHelper;
use crate::config::Config;
use crate::util::sleep_secs;

pub struct SubnetBackup {
    pub subnet_id: SubnetId,
    pub replica_version: ReplicaVersion,
    pub sync_last_time: Instant,
    pub sync_period: Duration,
    pub replay_last_time: Instant,
    pub replay_period: Duration,
    pub backup_helper: BackupHelper,
}
pub struct Manager {
    pub root_dir: PathBuf,
    pub nns_url: String,
    pub subnet_backups: Vec<SubnetBackup>,
    pub log: Logger,
}

impl Manager {
    pub fn new(config_file: PathBuf, log: Logger) -> Manager {
        let config = Config::load_config(config_file).expect("Updated config file can't be loaded");
        let file_name = match config.ssh_credentials.into_os_string().into_string() {
            Ok(f) => f,
            Err(e) => panic!("Bad file name for ssh credentials: {:?}", e),
        };
        let local_store_dir = config.root_dir.join("ic_registry_local_store");
        let data_provider = Arc::new(LocalStoreImpl::new(local_store_dir));
        let registry_client = Arc::new(RegistryClientImpl::new(data_provider, None));
        // TODO: load the state in order to deduce the starting replica version
        let mut backups = Vec::new();
        for s in config.subnets {
            let backup_helper = BackupHelper {
                replica_version: s.replica_version.clone(),
                subnet_id: s.subnet_id,
                nns_url: config.nns_url.clone(),
                root_dir: config.root_dir.clone(),
                ssh_credentials: file_name.clone(),
                registry_client: registry_client.clone(),
                log: log.clone(),
            };
            let sync_period = std::time::Duration::from_secs(s.sync_period_secs);
            let replay_period = std::time::Duration::from_secs(s.replay_period_secs);
            backups.push(SubnetBackup {
                subnet_id: s.subnet_id,
                replica_version: s.replica_version,
                sync_last_time: Instant::now() - sync_period,
                sync_period,
                replay_last_time: Instant::now() - replay_period,
                replay_period,
                backup_helper,
            });
        }
        Manager {
            root_dir: config.root_dir.clone(),
            nns_url: config.nns_url,
            subnet_backups: backups,
            log,
        }
    }

    pub fn do_backups(&mut self) {
        loop {
            for b in &mut self.subnet_backups {
                // TODO: split sync and replay into separate threads
                if b.sync_last_time + b.sync_period < Instant::now() {
                    match b.backup_helper.collect_subnet_nodes() {
                        Ok(nodes) => {
                            // TODO: randomize and take first N
                            b.backup_helper.sync(nodes);
                            b.sync_last_time = Instant::now();
                        }
                        Err(e) => error!(self.log, "Error fetching subnet node list: {:?}", e),
                    }
                }
                if b.replay_last_time + b.replay_period < Instant::now() {
                    b.backup_helper.replay();
                    b.replay_last_time = Instant::now();
                }
            }

            // Have a small break before the next round of checks
            // TODO: maybe configure it
            sleep_secs(30);
        }
    }
}
