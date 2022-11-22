use crate::notification_client::NotificationClient;
use crate::util::{block_on, sleep_secs};
use ic_recovery::command_helper::exec_cmd;
use ic_recovery::file_sync_helper::download_binary;
use ic_registry_client::client::{RegistryClient, RegistryClientImpl};
use ic_registry_client_helpers::node::NodeRegistry;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_types::{ReplicaVersion, SubnetId};

use rand::seq::SliceRandom;
use rand::thread_rng;
use slog::{error, info, warn, Logger};
use std::ffi::OsStr;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Instant;

const RETRIES_RSYNC_HOST: u64 = 5;
const RETRIES_BINARY_DOWNLOAD: u64 = 3;

pub struct BackupHelper {
    pub replica_version: ReplicaVersion,
    pub subnet_id: SubnetId,
    pub nns_url: String,
    pub root_dir: PathBuf,
    pub excluded_dirs: Vec<String>,
    pub ssh_private_key: String,
    pub registry_client: Arc<RegistryClientImpl>,
    pub notification_client: NotificationClient,
    pub log: Logger,
}

enum ReplayResult {
    Done,
    UpgradeRequired(ReplicaVersion),
}

impl BackupHelper {
    fn binary_dir(&self) -> PathBuf {
        self.root_dir
            .join(format!("binaries/{}", self.replica_version))
    }

    fn binary_file(&self, executable: &str) -> PathBuf {
        self.binary_dir().join(executable)
    }

    fn spool_root_dir(&self) -> PathBuf {
        self.root_dir.join("spool")
    }

    fn spool_dir(&self) -> PathBuf {
        self.spool_root_dir().join(self.subnet_id.to_string())
    }

    fn local_store_dir(&self) -> PathBuf {
        self.root_dir.join("ic_registry_local_store")
    }

    fn data_dir(&self) -> PathBuf {
        self.root_dir.join(format!("data/{}", self.subnet_id))
    }

    fn ic_config_dir(&self) -> PathBuf {
        self.data_dir().join("config")
    }

    fn ic_config_file_local(&self) -> PathBuf {
        self.ic_config_dir().join("ic.json5")
    }

    fn state_dir(&self) -> PathBuf {
        self.data_dir().join("ic_state")
    }

    fn archive_dir(&self, last_height: u64) -> PathBuf {
        self.root_dir
            .join(format!("archive/{}/{}", self.subnet_id, last_height))
    }

    fn username(&self) -> String {
        "backup".to_string()
    }

    fn download_binaries(&self) {
        if !self.binary_dir().exists() {
            std::fs::create_dir_all(self.binary_dir()).expect("Failure creating a directory");
        }
        self.download_binary("ic-replay".to_string());
        self.download_binary("sandbox_launcher".to_string());
        self.download_binary("canister_sandbox".to_string());
    }

    fn download_binary(&self, binary_name: String) {
        if self.binary_file(&binary_name).exists() {
            return;
        }
        for _ in 0..RETRIES_BINARY_DOWNLOAD {
            let res = block_on(download_binary(
                &self.log,
                self.replica_version.clone(),
                binary_name.clone(),
                self.binary_dir(),
            ));
            if res.is_ok() {
                return;
            }
            warn!(
                self.log,
                "Error while downloading {}: {:?}", binary_name, res
            );
            sleep_secs(10);
        }
        // Without the binaries we can't replay...
        self.notification_client
            .report_failure_slack(format!("Couldn't download: {}", binary_name));
        panic!(
            "Binary {} is required for the replica {}",
            binary_name, self.replica_version
        );
    }

    fn rsync_node_backup(&self, node_ip: &IpAddr) {
        info!(self.log, "Sync backup data from the node: {}", node_ip);
        let remote_dir = format!(
            "{}@[{}]:/var/lib/ic/backup/{}/",
            self.username(),
            node_ip,
            self.subnet_id
        );
        for _ in 0..RETRIES_RSYNC_HOST {
            match self.rsync_cmd(
                remote_dir.clone(),
                &self.spool_dir().into_os_string(),
                &["-qa", "--append-verify"],
            ) {
                Ok(_) => return,
                Err(e) => warn!(
                    self.log,
                    "Problem syncing backup directory with host: {} : {}", node_ip, e
                ),
            }
            sleep_secs(60);
        }
        warn!(self.log, "Didn't sync at all with host: {}", node_ip);
        self.notification_client
            .report_failure_slack("Couldn't pull artefacts from the nodes!".to_string());
    }

    fn rsync_config(&self, node_ip: &IpAddr) {
        info!(self.log, "Sync ic.json5 from the node: {}", node_ip);
        let remote_dir = format!(
            "{}@[{}]:/run/ic-node/config/ic.json5",
            self.username(),
            node_ip
        );
        for _ in 0..RETRIES_RSYNC_HOST {
            match self.rsync_cmd(
                remote_dir.clone(),
                &self.ic_config_file_local().into_os_string(),
                &["-q"],
            ) {
                Ok(_) => return,
                Err(e) => warn!(
                    self.log,
                    "Problem syncing config from host: {} : {}", node_ip, e
                ),
            }
            sleep_secs(60);
        }
        warn!(self.log, "Didn't sync any config from host: {}", node_ip);
        self.notification_client
            .report_failure_slack("Couldn't pull ic.json5 from the nodes!".to_string());
    }

    fn rsync_cmd(
        &self,
        remote_dir: String,
        local_dir: &OsStr,
        arguments: &[&str],
    ) -> Result<(), String> {
        let mut cmd = Command::new("rsync");
        cmd.arg("-e");
        cmd.arg(format!(
            "ssh -o StrictHostKeyChecking=no -i {}",
            self.ssh_private_key
        ));
        cmd.arg("--timeout=60");
        cmd.args(arguments);
        cmd.arg("--min-size=1").arg(remote_dir).arg(local_dir);
        info!(self.log, "Will execute: {:?}", cmd);
        if let Err(e) = exec_cmd(&mut cmd) {
            Err(format!("Error: {}", e))
        } else {
            Ok(())
        }
    }

    pub fn sync_files(&self, nodes: &Vec<&IpAddr>) {
        let start_time = Instant::now();

        if !self.spool_dir().exists() {
            std::fs::create_dir_all(self.spool_dir()).expect("Failure creating a directory");
        }
        if !self.ic_config_dir().exists() {
            std::fs::create_dir_all(self.ic_config_dir()).expect("Failure creating a directory");
        }

        for n in nodes {
            self.rsync_config(n);
        }
        for n in nodes {
            self.rsync_node_backup(n);
        }
        let duration = start_time.elapsed();
        let minutes = duration.as_secs() / 60;
        self.notification_client.push_metrics_sync_time(minutes);
    }

    pub fn collect_subnet_nodes(&self) -> Result<Vec<IpAddr>, String> {
        let subnet_id = self.subnet_id;
        let version = self.registry_client.get_latest_version();
        let result = match self
            .registry_client
            .get_node_ids_on_subnet(subnet_id, version)
        {
            Ok(Some(node_ids)) => Ok(node_ids
                .into_iter()
                .filter_map(|node_id| {
                    self.registry_client
                        .get_transport_info(node_id, version)
                        .unwrap_or_default()
                })
                .collect::<Vec<_>>()),
            other => Err(format!(
                "no node ids found in the registry for subnet_id={}: {:?}",
                subnet_id, other
            )),
        }?;
        result
            .into_iter()
            .filter_map(|node_record| {
                node_record.http.map(|http| {
                    http.ip_addr.parse().map_err(|err| {
                        format!("couldn't parse ip address from the registry: {:?}", err)
                    })
                })
            })
            .collect()
    }

    fn last_checkpoint(&self) -> u64 {
        if !self.state_dir().exists() {
            return 0u64;
        }
        match std::fs::read_dir(self.state_dir().join("checkpoints")) {
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
                .map(|s| u64::from_str_radix(&s, 16).unwrap_or(0))
                .fold(0u64, |a, b| -> u64 { a.max(b) }),
            Err(_) => 0,
        }
    }

    pub fn replay(&mut self) {
        let start_height = self.last_checkpoint();
        let start_time = Instant::now();

        if !self.state_dir().exists() {
            std::fs::create_dir_all(self.state_dir()).expect("Failure creating a directory");
        }

        // replay the current version once, but if there is upgrade do it again
        while let Ok(ReplayResult::UpgradeRequired(upgrade_version)) = self.replay_current_version()
        {
            self.notification_client.message_slack(format!(
                "Replica version upgrade detected (current: {} new: {}): upgrading the ic-replay tool to retry... 🤞",
                self.replica_version, upgrade_version
            ));
            // collect nodes from which we will fetch the config
            match self.collect_subnet_nodes() {
                Ok(nodes) => {
                    let mut shuf_nodes = nodes;
                    shuf_nodes.shuffle(&mut thread_rng());
                    // fetch the ic.json5 file from the first node
                    // TODO: fetch from another f nodes and compare them
                    if let Some(node_ip) = shuf_nodes.get(0) {
                        self.rsync_config(node_ip)
                    } else {
                        error!(self.log, "Error getting first node.");
                        break;
                    }
                }
                Err(e) => {
                    error!(self.log, "Error fetching subnet node list: {:?}", e);
                    break;
                }
            }
            self.replica_version = upgrade_version;
        }

        let finish_height = self.last_checkpoint();
        if finish_height > start_height {
            info!(self.log, "Replay was successful!");
            if self.archive_state(finish_height).is_ok() {
                self.notification_client.message_slack(format!(
                    "✅ Successfully restored the state at height *{}*",
                    finish_height
                ));
                let duration = start_time.elapsed();
                let minutes = duration.as_secs() / 60;
                self.notification_client.push_metrics_replay_time(minutes);
                self.notification_client
                    .push_metrics_restored_height(finish_height);
            }
        } else {
            warn!(self.log, "No progress in the replay!");
            self.notification_client.report_failure_slack(
                "No height progress after the last replay detected!".to_string(),
            );
        }
    }

    fn replay_current_version(&self) -> Result<ReplayResult, String> {
        let start_height = self.last_checkpoint();
        info!(
            self.log,
            "Replaying from height #{} of subnet {:?} with version {}",
            start_height,
            self.subnet_id,
            self.replica_version
        );
        self.download_binaries();

        let ic_admin = self.binary_file("ic-replay");
        let mut cmd = Command::new(ic_admin);
        cmd.arg("--data-root")
            .arg(&self.data_dir())
            .arg("--subnet-id")
            .arg(&self.subnet_id.to_string())
            .arg(&self.ic_config_file_local())
            .arg("restore-from-backup2")
            .arg(&self.local_store_dir())
            .arg(&self.spool_root_dir())
            .arg(&self.replica_version.to_string())
            .arg(start_height.to_string())
            .stdout(Stdio::piped());
        info!(self.log, "Will execute: {:?}", cmd);
        match exec_cmd(&mut cmd) {
            Err(e) => {
                error!(self.log, "Error: {}", e.to_string());
                Err(e.to_string())
            }
            Ok(Some(stdout)) => {
                info!(self.log, "Replay result:");
                info!(self.log, "{}", stdout);
                if let Some(upgrade_version) = self.check_upgrade_request(stdout) {
                    info!(self.log, "Upgrade detected to: {}", upgrade_version);
                    Ok(ReplayResult::UpgradeRequired(
                        ReplicaVersion::try_from(upgrade_version).map_err(|e| e.to_string())?,
                    ))
                } else {
                    info!(self.log, "Last height: #{}!", self.last_checkpoint());
                    Ok(ReplayResult::Done)
                }
            }
            Ok(None) => {
                error!(self.log, "No output from the replay process!");
                Err("No ic-replay output".to_string())
            }
        }
    }

    fn check_upgrade_request(&self, stdout: String) -> Option<String> {
        let prefix = "Please use the replay tool of version";
        let suffix = "to continue backup recovery from height";
        let min_version_len = 8;
        if let Some(pos) = stdout.find(prefix) {
            if pos + prefix.len() + min_version_len + suffix.len() < stdout.len() {
                let pos2 = pos + prefix.len();
                if let Some(pos3) = stdout[pos2..].find(suffix) {
                    return Some(stdout[pos2..(pos2 + pos3)].trim().to_string());
                }
            }
        }
        None
    }
    fn archive_state(&self, last_height: u64) -> Result<(), String> {
        let state_dir = self.data_dir().join(".");
        let archive_dir = self.archive_dir(last_height);
        info!(
            self.log,
            "Archiving: {} to: {}",
            state_dir.to_string_lossy(),
            archive_dir.to_string_lossy()
        );
        if !archive_dir.exists() {
            std::fs::create_dir_all(archive_dir.clone())
                .unwrap_or_else(|e| panic!("Failure creating archive directory: {}", e));
        }

        let mut cmd = Command::new("rsync");
        cmd.arg("-a");
        cmd.arg("--info=progress2");
        for dir in &self.excluded_dirs {
            cmd.arg("--exclude").arg(dir);
        }
        cmd.arg(state_dir).arg(archive_dir);
        info!(self.log, "Will execute: {:?}", cmd);
        if let Err(e) = exec_cmd(&mut cmd) {
            error!(self.log, "Error: {}", e);
            self.notification_client
                .report_failure_slack("Couldn't backup the recovered state!".to_string());
            Err(e.to_string())
        } else {
            info!(self.log, "State archived!");
            Ok(())
        }
    }
}
