use crate::{
    notification_client::NotificationClient,
    util::{block_on, sleep_secs},
};
use anyhow::{Context, anyhow, bail};
use chrono::{DateTime, Utc};
use ic_interfaces_registry::RegistryClient;
use ic_recovery::{
    command_helper::exec_cmd, error::RecoveryError, file_sync_helper::download_binary,
};
use ic_registry_client_helpers::{node::NodeRegistry, subnet::SubnetRegistry};
use ic_types::{ReplicaVersion, SubnetId};
use rand::{seq::SliceRandom, thread_rng};
use slog::{Logger, debug, error, info, warn};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs::{DirEntry, File, create_dir_all, read_dir, remove_dir_all},
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

const RETRIES_RSYNC_HOST: u64 = 5;
const RETRIES_BINARY_DOWNLOAD: u64 = 3;
const BUCKET_SIZE: u64 = 10000;
/// For how many days should we keep the states in the hot storage. States older than this number
/// will be moved to the cold storage.
const DAYS_TO_KEEP_STATES_IN_HOT_STORAGE: usize = 1;

const TIMESTAMP_FILE_NAME: &str = "archiving_timestamp.txt";

pub(crate) struct BackupHelper {
    pub(crate) subnet_id: SubnetId,
    pub(crate) initial_replica_version: ReplicaVersion,
    pub(crate) root_dir: PathBuf,
    pub(crate) excluded_dirs: Vec<String>,
    pub(crate) ssh_private_key: String,
    pub(crate) registry_client: Arc<dyn RegistryClient>,
    pub(crate) notification_client: NotificationClient,
    pub(crate) downloads_guard: Arc<Mutex<bool>>,
    pub(crate) hot_disk_resource_threshold_percentage: u32,
    pub(crate) cold_disk_resource_threshold_percentage: u32,
    pub(crate) cold_storage_dir: PathBuf,
    pub(crate) versions_hot: usize,
    pub(crate) max_logs_age_to_keep: Option<Duration>,
    pub(crate) artifacts_guard: Mutex<bool>,
    pub(crate) logs_guard: Arc<Mutex<()>>,
    pub(crate) daily_replays: usize,
    pub(crate) do_cold_storage: bool,
    pub(crate) thread_id: u32,
    pub(crate) blacklisted_nodes: Arc<Vec<IpAddr>>,
    pub(crate) log: Logger,
}

enum ReplayResult {
    Done,
    UpgradeRequired(ReplicaVersion),
}

enum DiskStats {
    Inodes,
    Space,
}

impl BackupHelper {
    fn binary_dir(&self, replica_version: &ReplicaVersion) -> PathBuf {
        create_if_not_exists(self.root_dir.join(format!("binaries/{replica_version}")))
    }

    fn binary_file(&self, executable: &str, replica_version: &ReplicaVersion) -> PathBuf {
        self.binary_dir(replica_version).join(executable)
    }

    fn logs_dir(&self) -> PathBuf {
        create_if_not_exists(self.root_dir.join("logs"))
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

    pub(crate) fn data_dir(&self) -> PathBuf {
        self.root_dir.join(format!("data/{}", self.subnet_id))
    }

    fn ic_config_file_local(&self, replica_version: &ReplicaVersion) -> PathBuf {
        self.binary_dir(replica_version).join("ic.json5")
    }

    fn state_dir(&self) -> PathBuf {
        create_if_not_exists(self.data_dir().join("ic_state"))
    }

    fn archive_dir(&self) -> PathBuf {
        self.root_dir.join(format!("archive/{}", self.subnet_id))
    }

    fn archive_height_dir(&self, last_height: u64) -> PathBuf {
        create_if_not_exists(self.archive_dir().join(format!("{last_height}")))
    }

    fn work_dir(&self) -> PathBuf {
        create_if_not_exists(self.root_dir.join(format!("work_dir/{}", self.subnet_id)))
    }

    fn cold_storage_artifacts_dir(&self) -> PathBuf {
        create_if_not_exists(
            self.cold_storage_dir
                .join(format!("{}/artifacts", self.subnet_id)),
        )
    }

    fn cold_storage_states_dir(&self) -> PathBuf {
        create_if_not_exists(
            self.cold_storage_dir
                .join(format!("{}/states", self.subnet_id)),
        )
    }

    fn trash_dir(&self) -> PathBuf {
        create_if_not_exists(self.root_dir.join("trash"))
    }

    fn username(&self) -> String {
        "backup".to_string()
    }

    fn download_binaries(
        &self,
        replica_version: &ReplicaVersion,
        start_height: u64,
    ) -> Result<(), String> {
        debug!(
            self.log,
            "[#{}] Check if there are new artifacts.", self.thread_id
        );

        let cup_file = self.spool_dir().join(format!(
            "{}/{}/{}/catch_up_package.bin",
            replica_version,
            start_height - start_height % 10000,
            start_height
        ));
        // Make sure that the CUP from this replica version and at this height is
        // already synced from the node.
        // That way it is guaranteed that the node is running the new replica version and
        // has the latest version of the ic.json5 file.
        while !cup_file.exists() {
            debug!(self.log, "CUP file {} not yet present", cup_file.display());
            sleep_secs(30);
        }
        debug!(
            self.log,
            "[#{}] Start downloading binaries.", self.thread_id
        );

        let _guard = self
            .downloads_guard
            .lock()
            .expect("downloads mutex lock failed");
        self.download_binary("ic-replay", replica_version)?;
        self.download_binary("sandbox_launcher", replica_version)?;
        self.download_binary("canister_sandbox", replica_version)?;
        self.download_binary("compiler_sandbox", replica_version)?;

        if !self.ic_config_file_local(replica_version).exists() {
            // collect nodes from which we will fetch the config
            match self.collect_nodes(1) {
                Ok(nodes) => {
                    // fetch the ic.json5 file from the first node
                    // TODO: fetch from another f nodes and compare them
                    if let Some(node_ip) = nodes.first() {
                        self.rsync_config(node_ip, replica_version);
                        Ok(())
                    } else {
                        Err("Error getting first node.".to_string())
                    }
                }
                Err(e) => Err(format!("Error fetching subnet node list: {e:?}")),
            }
        } else {
            Ok(())
        }
    }

    fn download_binary(
        &self,
        binary_name: &str,
        replica_version: &ReplicaVersion,
    ) -> Result<(), String> {
        if self.binary_file(binary_name, replica_version).exists() {
            return Ok(());
        }
        for _ in 0..RETRIES_BINARY_DOWNLOAD {
            let res = block_on(download_binary(
                &self.log,
                replica_version,
                binary_name.to_string(),
                &self.binary_dir(replica_version),
            ));
            if res.is_ok() {
                return Ok(());
            }
            warn!(
                self.log,
                "Error while downloading {}: {:?}", binary_name, res
            );
            sleep_secs(10);
        }
        // Without the binaries we can't replay...
        self.notification_client
            .report_failure_slack(format!("Couldn't download: {binary_name}"));
        Err(format!(
            "Binary {binary_name} is required for the replica {replica_version}"
        ))
    }

    fn rsync_spool(&self, node_ip: &IpAddr) -> bool {
        let _guard = self
            .artifacts_guard
            .lock()
            .expect("artifacts mutex lock failed");
        info!(self.log, "Sync backup data from the node: {}", node_ip,);
        let remote_dir = format!(
            "{}@[{}]:/var/lib/ic/backup/{}/",
            self.username(),
            node_ip,
            self.subnet_id
        );
        for _ in 0..RETRIES_RSYNC_HOST {
            match self.rsync_remote_cmd(
                remote_dir.clone(),
                &self.spool_dir().into_os_string(),
                &["-qam", "--ignore-existing"],
            ) {
                Ok(_) => return true,
                Err(e) => warn!(
                    self.log,
                    "Problem syncing backup directory with host: {} : {}", node_ip, e
                ),
            }
            sleep_secs(60);
        }
        warn!(self.log, "Didn't sync at all with host: {}", node_ip);
        false
    }

    fn rsync_config(&self, node_ip: &IpAddr, replica_version: &ReplicaVersion) {
        info!(
            self.log,
            "[#{}] Sync ic.json5 from the node: {} for replica: {}",
            self.thread_id,
            node_ip,
            replica_version,
        );
        let remote_dir = format!(
            "{}@[{}]:/run/ic-node/config/ic.json5",
            self.username(),
            node_ip
        );
        for _ in 0..RETRIES_RSYNC_HOST {
            match self.rsync_remote_cmd(
                remote_dir.clone(),
                &self.ic_config_file_local(replica_version).into_os_string(),
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

    fn rsync_remote_cmd(
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
        cmd.arg("--bwlimit=25M").arg("--time-limit=5"); // 25M * 5 * 60 = 7.5G max per sync
        cmd.arg("--min-size=1").arg(remote_dir).arg(local_dir);
        debug!(self.log, "Will execute: {:?}", cmd);

        exec_cmd(&mut cmd).map_err(|e| format!("Error: {}", e))?;
        Ok(())
    }

    pub(crate) fn sync_files(&self, nodes: &[IpAddr]) {
        let start_time = Instant::now();
        let total_succeeded: usize = nodes
            .iter()
            .map(|node| self.rsync_spool(node) as usize)
            .sum();
        if 2 * total_succeeded >= nodes.len() {
            let duration = start_time.elapsed();
            info!(
                self.log,
                "Sync succeeded after {} seconds",
                duration.as_secs()
            );
            self.notification_client
                .push_metrics_sync_time(duration.as_secs() / 60);
        } else {
            self.notification_client
                .report_failure_slack("Couldn't pull artifacts from the nodes!".to_string());
        }
    }

    pub(crate) fn create_spool_dir(&self) {
        if !self.spool_dir().exists() {
            create_dir_all(self.spool_dir()).expect("Failure creating a directory");
        }
    }

    pub(crate) fn collect_nodes(&self, num_nodes: usize) -> Result<Vec<IpAddr>, String> {
        let mut shuf_nodes = self.collect_all_subnet_nodes()?;
        shuf_nodes.shuffle(&mut thread_rng());
        Ok(shuf_nodes
            .iter()
            .filter(|ip| !self.blacklisted_nodes.contains(ip))
            .take(num_nodes)
            .cloned()
            .collect::<Vec<_>>())
    }

    fn collect_all_subnet_nodes(&self) -> Result<Vec<IpAddr>, String> {
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
                        .get_node_record(node_id, version)
                        .unwrap_or_default()
                })
                .collect::<Vec<_>>()),
            other => Err(format!(
                "no node ids found in the registry for subnet_id={subnet_id}: {other:?}"
            )),
        }?;
        result
            .into_iter()
            .filter_map(|node_record| {
                node_record.http.map(|http| {
                    http.ip_addr.parse().map_err(|err| {
                        format!("couldn't parse ip address from the registry: {err:?}")
                    })
                })
            })
            .collect()
    }

    pub(crate) fn last_state_checkpoint(&self) -> u64 {
        last_checkpoint(&self.state_dir())
    }

    pub(crate) fn replay(&self) {
        let start_height = self.last_state_checkpoint();
        let start_time = Instant::now();
        let mut current_replica_version =
            retrieve_replica_version_last_replayed(&self.log, self.spool_dir(), self.state_dir())
                .unwrap_or_else(|| self.initial_replica_version.clone());

        // replay the current version once, but if there is upgrade do it again
        loop {
            match self.replay_current_version(&current_replica_version) {
                Ok(ReplayResult::UpgradeRequired(upgrade_version)) => {
                    // replayed the current version, but if there is upgrade try to do it again
                    self.notification_client.message_slack(format!(
                        "Replica version upgrade detected (current: {current_replica_version} \
                        new: {upgrade_version}): upgrading the ic-replay tool to retry... 🤞"
                    ));
                    current_replica_version = upgrade_version;
                }
                Ok(_) => break,
                Err(err) => {
                    error!(self.log, "Error replaying: {err:?}");
                    break;
                }
            }
        }

        let finish_height = self.last_state_checkpoint();
        if finish_height > start_height {
            info!(self.log, "[#{}] Replay was successful!", self.thread_id);

            if self.archive_state(finish_height).is_ok() {
                self.notification_client.message_slack(format!(
                    "✅ Successfully restored the state at height *{finish_height}*"
                ));
                let duration = start_time.elapsed();
                let minutes = duration.as_secs() / 60;
                self.notification_client.push_metrics_replay_time(minutes);
                self.notification_client
                    .push_metrics_restored_height(finish_height);
            }
        } else {
            warn!(self.log, "[#{}] No progress in the replay!", self.thread_id);
            self.notification_client.report_failure_slack(
                "No height progress after the last replay detected!".to_string(),
            );
        }

        match self.maybe_cold_store_states() {
            Ok(false) => info!(self.log, "No need to move any states to the cold storage"),
            Ok(true) => info!(self.log, "Moved some states to the cold storage"),
            Err(err) => warn!(
                self.log,
                "Failed moving some states to the cold storage: {}", err
            ),
        }
    }

    fn replay_current_version(
        &self,
        replica_version: &ReplicaVersion,
    ) -> anyhow::Result<ReplayResult> {
        let start_height = self.last_state_checkpoint();
        info!(
            self.log,
            "[#{}] Replaying from height #{} with version {}",
            self.thread_id,
            start_height,
            replica_version
        );
        self.download_binaries(replica_version, start_height)
            .map_err(|err| anyhow!("Failed to download binaries: {err}"))?;
        debug!(self.log, "[#{}] Binaries are downloaded.", self.thread_id);

        let ic_admin = self.binary_file("ic-replay", replica_version);
        let mut cmd = Command::new(ic_admin);
        cmd.arg("--data-root")
            .arg(self.data_dir())
            .arg("--subnet-id")
            .arg(self.subnet_id.to_string())
            .arg(self.ic_config_file_local(replica_version))
            .arg("restore-from-backup")
            .arg(self.local_store_dir())
            .arg(self.spool_root_dir())
            .arg(replica_version.to_string())
            .arg(start_height.to_string())
            .stdout(Stdio::piped());
        debug!(self.log, "[#{}] Will execute: {:?}", self.thread_id, cmd);
        match exec_cmd(&mut cmd) {
            Err(err) => {
                error!(self.log, "[#{}] Error: {}", self.thread_id, err.to_string());
                if let RecoveryError::CommandError(_, ref out_str) = err {
                    self.dump_log_file(start_height, out_str)?;
                }
                bail!("Failed to run `ic-replay`: {err}");
            }
            Ok(Some(stdout)) => {
                self.dump_log_file(start_height, &stdout)?;

                if let Some(upgrade_version) = self.check_upgrade_request(stdout) {
                    debug!(
                        self.log,
                        "[#{}] Upgrade detected to: {}", self.thread_id, upgrade_version
                    );

                    Ok(ReplayResult::UpgradeRequired(
                        ReplicaVersion::try_from(upgrade_version)
                            .context("Failed to convert replica version")?,
                    ))
                } else {
                    debug!(
                        self.log,
                        "[#{}] Last height: #{}!",
                        self.thread_id,
                        self.last_state_checkpoint()
                    );

                    Ok(ReplayResult::Done)
                }
            }
            Ok(None) => {
                error!(
                    self.log,
                    "[#{}] No output from the replay process!", self.thread_id
                );
                bail!("No `ic-replay` output");
            }
        }
    }

    fn dump_log_file(&self, start_height: u64, stdout: &String) -> anyhow::Result<()> {
        let timestamp = Utc::now().timestamp();
        let log_file_name = format!(
            "{}_{:010}_{:012}.log",
            self.subnet_id, timestamp, start_height
        );
        let _guard = self.logs_guard.lock().unwrap();
        let logs_dir = self.logs_dir();
        let file_name = logs_dir.join(log_file_name);
        debug!(self.log, "Write replay log to: {file_name:?}");
        let mut file = File::create(file_name).context("Failed to create log file")?;
        file.write_all(stdout.as_bytes())
            .context("Failed to write to log file")?;

        if let Some(max_logs_age_to_keep) = self.max_logs_age_to_keep {
            let min_time_to_keep = SystemTime::now()
                .checked_sub(max_logs_age_to_keep)
                .expect("`max_logs_age_to_keep` should be small enough");

            self.purge_old_logs(&logs_dir, min_time_to_keep)
                .context("Failed to purge old logs")?;
        }

        Ok(())
    }

    fn purge_old_logs(&self, logs_dir: &Path, min_time: SystemTime) -> anyhow::Result<()> {
        for dir_entry in read_dir(logs_dir)
            .with_context(|| format!("Failed to read directory {}", logs_dir.display()))?
        {
            let entry = match dir_entry {
                Ok(entry) => entry,
                Err(err) => {
                    warn!(self.log, "Failed to read directory entry: {err}");
                    continue;
                }
            };

            let creation_time = match entry.metadata().and_then(|metadata| metadata.created()) {
                Ok(time) => time,
                Err(err) => {
                    warn!(self.log, "Failed to get file's creation time: {err}");
                    continue;
                }
            };

            if creation_time < min_time
                && let Err(err) = std::fs::remove_file(entry.path())
            {
                warn!(self.log, "Failed to delete logs file: {err}");
            }
        }

        Ok(())
    }

    pub(crate) fn retrieve_spool_top_height(&self) -> u64 {
        let mut spool_top_height = 0;
        let spool_dirs = collect_spool_dirs(&self.log, self.spool_dir());
        for spool_dir in spool_dirs {
            if into_replica_version(&self.log, &spool_dir).is_some() {
                let (top_height, _) = fetch_top_height(&spool_dir);
                if spool_top_height < top_height {
                    spool_top_height = top_height;
                }
            }
        }
        spool_top_height
    }

    fn check_upgrade_request(&self, stdout: String) -> Option<String> {
        let prefix = "Please use the replay tool of version";
        let suffix = "to continue backup recovery from height";
        let min_version_len = 8;
        if let Some(pos) = stdout.find(prefix)
            && pos + prefix.len() + min_version_len + suffix.len() < stdout.len()
        {
            let pos2 = pos + prefix.len();
            if let Some(pos3) = stdout[pos2..].find(suffix) {
                return Some(stdout[pos2..(pos2 + pos3)].trim().to_string());
            }
        }
        None
    }

    fn get_disk_stats(
        &self,
        dir: &Path,
        threshold: u32,
        typ: DiskStats,
        notify_if_exceeds_threshold: bool,
    ) -> Result<u32, String> {
        let mut cmd = Command::new("df");
        cmd.arg(match typ {
            DiskStats::Inodes => "-i",
            DiskStats::Space => "-k",
        });
        cmd.arg(dir);
        match exec_cmd(&mut cmd) {
            Ok(str) => {
                if let Some(val) = str
                    .as_ref()
                    .unwrap_or(&"".to_string())
                    .lines()
                    .next_back()
                    .unwrap_or_default()
                    .split_whitespace()
                    .nth(4)
                {
                    let mut num_str = val.to_string();
                    num_str.pop();
                    if let Ok(n) = num_str.parse::<u32>() {
                        if notify_if_exceeds_threshold && n >= threshold {
                            let resource = match typ {
                                DiskStats::Inodes => "inodes",
                                DiskStats::Space => "space",
                            };
                            self.notification_client.report_warning_slack(format!(
                                "[{}] {} usage is at {}%",
                                dir.to_str().unwrap_or_default(),
                                resource,
                                n
                            ))
                        }
                        Ok(n)
                    } else {
                        Err(format!("Error converting number from: {str:?}"))
                    }
                } else {
                    Err(format!("Error converting disk stats: {str:?}"))
                }
            }
            Err(err) => Err(format!("Error fetching disk stats: {err}")),
        }
    }

    fn archive_state(&self, last_height: u64) -> Result<(), String> {
        let state_dir = self.data_dir().join(".");
        let archive_last_dir = self.archive_height_dir(last_height);
        info!(
            self.log,
            "[#{}] Archiving state to: {}",
            self.thread_id,
            archive_last_dir.to_string_lossy()
        );

        let mut cmd = Command::new("rsync");
        cmd.arg("-a");
        for dir in &self.excluded_dirs {
            cmd.arg("--exclude").arg(dir);
        }
        cmd.arg(state_dir).arg(&archive_last_dir);
        debug!(self.log, "[#{}] Will execute: {:?}", self.thread_id, cmd);
        if let Err(e) = exec_cmd(&mut cmd) {
            error!(self.log, "Error: {}", e);
            self.notification_client
                .report_failure_slack("Couldn't archive the replayed state!".to_string());
            return Err(e.to_string());
        }
        // leave only one archived checkpoint
        let checkpoints_dir = archive_last_dir.join("ic_state/checkpoints");
        if !checkpoints_dir.exists() {
            return Err("Archiving didn't succeed - missing checkpoints directory".to_string());
        }
        let archived_checkpoint = last_checkpoint(&archive_last_dir.join("ic_state"));
        if archived_checkpoint == 0 {
            return Err("No proper archived checkpoint".to_string());
        }
        // delete the older checkpoint(s)
        match read_dir(checkpoints_dir) {
            Ok(dirs) => dirs
                .flatten()
                .map(|filename| (height_from_dir_entry(&filename), filename))
                .filter(|(height, _)| *height != 0 && *height != archived_checkpoint)
                .for_each(|(_, filename)| {
                    let _ = remove_dir_all(filename.path());
                }),
            Err(err) => return Err(format!("Error reading archive checkpoints: {err}")),
        };
        debug!(self.log, "[#{}] State archived!", self.thread_id);

        let now: DateTime<Utc> = Utc::now();
        write_timestamp(&archive_last_dir, now).map_err(|err| err.to_string())?;
        self.log_disk_stats(true)
    }

    pub(crate) fn log_disk_stats(&self, notify_if_exceeds_threshold: bool) -> Result<(), String> {
        let mut stats = Vec::new();
        for (dir, threshold, storage_type) in [
            (
                &self.root_dir,
                self.hot_disk_resource_threshold_percentage,
                "hot",
            ),
            (
                &self.cold_storage_dir,
                self.cold_disk_resource_threshold_percentage,
                "cold",
            ),
        ] {
            let space = self.get_disk_stats(
                dir,
                threshold,
                DiskStats::Space,
                notify_if_exceeds_threshold,
            )?;
            let inodes = self.get_disk_stats(
                dir,
                threshold,
                DiskStats::Inodes,
                notify_if_exceeds_threshold,
            )?;
            stats.push((dir.as_path(), space, inodes, storage_type));
        }
        self.notification_client
            .push_metrics_disk_stats(stats.as_slice());
        Ok(())
    }

    pub(crate) fn need_cold_storage_move(&self) -> Result<bool, String> {
        let _guard = self
            .artifacts_guard
            .lock()
            .expect("artifacts mutex lock failed");
        let spool_dirs = collect_only_dirs(&self.spool_dir())?;
        Ok(spool_dirs.len() > self.versions_hot)
    }

    pub(crate) fn do_move_cold_storage(&self) -> Result<(), String> {
        let max_height = self.cold_store_artifacts()?;
        self.cold_store_states(max_height)?;
        info!(
            self.log,
            "Finished moving old artifacts and states to the cold storage",
        );
        Ok(())
    }

    fn cold_store_artifacts(&self) -> Result<u64, String> {
        let guard = self
            .artifacts_guard
            .lock()
            .expect("artifacts mutex lock failed");
        info!(
            self.log,
            "Start moving old artifacts and states to the cold storage",
        );
        let spool_dirs = collect_only_dirs(&self.spool_dir())?;
        let mut dir_heights = BTreeMap::new();
        spool_dirs.iter().for_each(|replica_version_dir| {
            let (top_height, replica_version_path) = fetch_top_height(replica_version_dir);
            dir_heights.insert(top_height, replica_version_path);
        });
        if spool_dirs.len() != dir_heights.len() {
            error!(
                self.log,
                "Non equal size of collections - spool: {} heights: {}",
                spool_dirs.len(),
                dir_heights.len()
            )
        }
        let mut max_height: u64 = 0;
        let to_clean = dir_heights.len() - self.versions_hot;
        let work_dir = self.work_dir();
        for (height, dir) in dir_heights.iter().take(to_clean) {
            info!(
                self.log,
                "Artifact directory: {:?} needs to be moved to the cold storage", dir
            );
            max_height = max_height.max(*height);
            // move artifact dir(s)
            let mut cmd = Command::new("mv");
            cmd.arg(dir).arg(&work_dir);
            debug!(self.log, "Will execute: {:?}", cmd);
            exec_cmd(&mut cmd).map_err(|err| format!("Error moving artifacts: {err:?}"))?;
        }
        // we have moved all the artifacts from the spool directory,
        // so don't need the mutex guard anymore
        drop(guard);

        if self.do_cold_storage {
            // process moved artifact directories
            let cold_storage_artifacts_dir = self.cold_storage_artifacts_dir();
            let work_dir_str = work_dir
                .clone()
                .into_os_string()
                .into_string()
                .expect("work directory is missing or invalid");
            let pack_dirs = collect_only_dirs(&work_dir)?;
            for pack_dir in pack_dirs {
                let replica_version = pack_dir
                    .file_name()
                    .into_string()
                    .expect("replica version entry in work directory is missing or invalid");
                debug!(self.log, "Packing artifacts of {}", replica_version);
                let timestamp = Utc::now().timestamp();
                let (top_height, _) = fetch_top_height(&pack_dir);
                let packed_file = format!(
                    "{work_dir_str}/{timestamp:010}_{top_height:012}_{replica_version}.txz"
                );
                let mut cmd = Command::new("tar");
                cmd.arg("cJvf");
                cmd.arg(&packed_file);
                cmd.arg("-C").arg(&work_dir);
                cmd.arg(&replica_version);
                cmd.env("XZ_OPT", "-9");
                debug!(self.log, "Will execute: {:?}", cmd);
                exec_cmd(&mut cmd).map_err(|err| format!("Error packing artifacts: {err:?}"))?;

                info!(self.log, "Copy packed file of {}", replica_version);
                let mut cmd2 = Command::new("cp");
                cmd2.arg(packed_file).arg(&cold_storage_artifacts_dir);
                debug!(self.log, "Will execute: {:?}", cmd2);
                exec_cmd(&mut cmd2).map_err(|err| format!("Error copying artifacts: {err:?}"))?;
            }
            ls_path(
                &self.log,
                self.cold_storage_dir
                    .join(format!("{}", self.subnet_id))
                    .as_path(),
            )?;
        }

        info!(self.log, "Remove leftovers");
        remove_dir_all(work_dir).map_err(|err| format!("Error deleting leftovers: {err:?}"))?;

        Ok(max_height)
    }

    /// Moves some of the states to the cold storage, such that the states from the last
    /// [DAYS_TO_KEEP_STATES_IN_HOT_STORAGE] days remain in the hot storage.
    fn maybe_cold_store_states(&self) -> Result<bool, String> {
        let max_number_of_states_to_remain_in_hot_storage =
            self.daily_replays * DAYS_TO_KEEP_STATES_IN_HOT_STORAGE;

        let states = collect_only_dirs(&self.archive_dir())?;

        info!(
            self.log,
            "Number of states in the hot storage: {}. \
            Will move some of them to the cold storage if the number is > {}.",
            states.len(),
            max_number_of_states_to_remain_in_hot_storage,
        );

        // Nothing to do in this case.
        if states.len() <= max_number_of_states_to_remain_in_hot_storage {
            return Ok(false);
        }

        let mut heights: Vec<_> = states
            .iter()
            .map(|dir_entry| height_from_dir_entry_radix(dir_entry, 10))
            .collect();

        heights.sort();

        let number_of_states_to_remove_from_hot_storage =
            heights.len() - max_number_of_states_to_remain_in_hot_storage;

        let max_height = heights[number_of_states_to_remove_from_hot_storage - 1];

        self.cold_store_states(max_height).map(|_| true)
    }

    fn cold_store_states(&self, max_height: u64) -> Result<(), String> {
        info!(
            self.log,
            "Moving states with height up to: {:?} from the archive to the cold storage",
            max_height
        );

        // clean up the archive directory now
        let archive_dirs = collect_only_dirs(&self.archive_dir())?;
        let mut old_state_dirs = BTreeMap::new();
        archive_dirs.iter().for_each(|state_dir| {
            let height = height_from_dir_entry_radix(state_dir, 10);
            if height <= max_height {
                old_state_dirs.insert(height, state_dir.path());
            }
        });

        for dir in old_state_dirs.values() {
            if self.should_cold_store(dir) {
                info!(self.log, "Will copy to cold storage: {:?}", dir);
                let mut cmd = Command::new("rsync");
                cmd.arg("-a");
                cmd.arg(dir).arg(self.cold_storage_states_dir());
                debug!(self.log, "Will execute: {:?}", cmd);
                exec_cmd(&mut cmd).map_err(|err| format!("Error copying states: {err:?}"))?;
            }
        }

        let trash_dir = self.trash_dir();
        for dir in old_state_dirs {
            info!(self.log, "Will move to trash directory {:?}", dir.1);
            let mut cmd = Command::new("mv");
            cmd.arg(dir.1).arg(&trash_dir);
            debug!(self.log, "Will execute: {:?}", cmd);
            exec_cmd(&mut cmd).map_err(|err| format!("Error moving artifacts: {err:?}"))?;
        }

        remove_dir_all(trash_dir).map_err(|err| format!("Error deleting trash dir: {err:?}"))?;

        Ok(())
    }

    fn should_cold_store(&self, state_dir: &Path) -> bool {
        if !self.do_cold_storage {
            return false;
        }

        let cold_storage_timestamp = match self.cold_storage_newest_state_timestamp() {
            Ok(timestamp) => timestamp,
            Err(err) => {
                error!(
                    self.log,
                    "Failed to read the timestamp of the newest state in the cold storage. \
                    Force cold storing the state: {:?}",
                    err
                );
                return true;
            }
        };

        let hot_storage_timestamp = match state_dir_timestamp(state_dir) {
            Ok(timestamp) => timestamp,
            Err(err) => {
                error!(
                    self.log,
                    "Failed to read the timestamp of the state in the hot storage. \
                    Force cold storing the state: {:?}",
                    err
                );
                return true;
            }
        };

        // Cold store if the timestamp of the state is at least one day newer than the newest state
        // in the cold storage.
        hot_storage_timestamp
            .signed_duration_since(cold_storage_timestamp)
            .num_days()
            >= 1
    }

    fn cold_storage_newest_state_timestamp(&self) -> anyhow::Result<DateTime<Utc>> {
        let last_height = last_dir_height(&self.cold_storage_states_dir(), 10);

        state_dir_timestamp(&self.cold_storage_states_dir().join(last_height.to_string()))
    }
}

pub(crate) fn ls_path(log: &Logger, dir: &Path) -> Result<(), String> {
    let mut cmd = Command::new("ls");
    cmd.arg(dir);
    debug!(log, "Will execute: {:?}", cmd);
    let res =
        exec_cmd(&mut cmd).map_err(|err| format!("Error listing cold store directory: {err:?}"))?;
    debug!(log, "{:?}", res);
    Ok(())
}

fn into_replica_version(log: &Logger, spool_dir: &DirEntry) -> Option<ReplicaVersion> {
    let replica_version_str = spool_dir
        .file_name()
        .into_string()
        .expect("replica version directory entry in spool is missing or invalid");
    let replica_version = match ReplicaVersion::try_from(replica_version_str) {
        Ok(ver) => ver,
        Err(err) => {
            error!(log, "{:?}", err);
            return None;
        }
    };
    Some(replica_version)
}

fn collect_only_dirs(path: &PathBuf) -> Result<Vec<DirEntry>, String> {
    Ok(read_dir(path)
        .map_err(|e| format!("Error reading directory {path:?}: {e}"))?
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .collect())
}

fn fetch_top_height(replica_version_dir: &DirEntry) -> (u64, PathBuf) {
    let replica_version_path = replica_version_dir.path();
    let height_bucket = last_dir_height(&replica_version_path, 10);
    let top_height = last_dir_height(&replica_version_path.join(format!("{height_bucket}")), 10);
    (top_height, replica_version_path)
}

fn is_height_in_spool(replica_version_dir: &DirEntry, height: u64) -> bool {
    let replica_version_path = replica_version_dir.path();
    let height_bucket = height / BUCKET_SIZE * BUCKET_SIZE;
    let path = replica_version_path.join(format!("{height_bucket}/{height}"));
    path.exists()
}

fn height_from_dir_entry_radix(filename: &DirEntry, radix: u32) -> u64 {
    let height = filename
        .path()
        .file_name()
        .unwrap_or_else(|| OsStr::new("0"))
        .to_os_string()
        .into_string()
        .unwrap_or_else(|_| "0".to_string());
    u64::from_str_radix(&height, radix).unwrap_or(0)
}

fn height_from_dir_entry(filename: &DirEntry) -> u64 {
    height_from_dir_entry_radix(filename, 16)
}

fn last_dir_height(dir: &PathBuf, radix: u32) -> u64 {
    if !dir.exists() {
        return 0u64;
    }
    match read_dir(dir) {
        Ok(file_list) => file_list
            .flatten()
            .map(|filename| height_from_dir_entry_radix(&filename, radix))
            .fold(0u64, |a, b| -> u64 { a.max(b) }),
        Err(_) => 0,
    }
}

pub fn last_checkpoint(dir: &Path) -> u64 {
    last_dir_height(&dir.join("checkpoints"), 16)
}

fn create_if_not_exists(dir: PathBuf) -> PathBuf {
    if !dir.exists() {
        create_dir_all(&dir).unwrap_or_else(|e| panic!("Failure creating directory {dir:?}: {e}"));
    }
    dir
}

fn collect_spool_dirs(log: &Logger, spool_dir: PathBuf) -> Vec<DirEntry> {
    if !spool_dir.exists() {
        return Vec::new();
    }
    match collect_only_dirs(&spool_dir) {
        Ok(dirs) => dirs,
        Err(err) => {
            error!(log, "{:?}", err);
            Vec::new()
        }
    }
}

/// Searches in spool a directory that contains a block finishing the last call to ic-replay.
pub(crate) fn retrieve_replica_version_last_replayed(
    log: &Logger,
    spool_dir: PathBuf,
    state_dir: PathBuf,
) -> Option<ReplicaVersion> {
    let last_checkpoint = last_checkpoint(&state_dir);
    if last_checkpoint == 0 {
        return None;
    }

    let mut max_height = 0;
    let mut current_replica_version = None;
    let spool_dirs = collect_spool_dirs(log, spool_dir);
    for spool_dir in spool_dirs {
        let replica_version = into_replica_version(log, &spool_dir);
        if is_height_in_spool(&spool_dir, last_checkpoint) && replica_version.is_some() {
            let (top_height, _) = fetch_top_height(&spool_dir);
            if max_height < top_height {
                max_height = top_height;
                current_replica_version = replica_version;
            }
        }
    }

    current_replica_version
}

fn state_dir_timestamp(dir: &Path) -> anyhow::Result<DateTime<Utc>> {
    let path = dir.join(TIMESTAMP_FILE_NAME);
    let timestamp_str =
        std::fs::read_to_string(&path).context("Failed to read the timestamp file")?;
    let timestamp = DateTime::parse_from_rfc2822(timestamp_str.trim())
        .context("Failed to parse the timestamp")?;

    Ok(timestamp.into())
}

fn write_timestamp(dir: &Path, timestamp: DateTime<Utc>) -> anyhow::Result<()> {
    let timestamp_str = format!("{}\n", timestamp.to_rfc2822());
    let mut file =
        File::create(dir.join(TIMESTAMP_FILE_NAME)).context("Error creating timestamp file")?;
    file.write_all(timestamp_str.as_bytes())
        .context("Error writing timestamp")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, thread::sleep};

    use ic_registry_client::client::RegistryClientImpl;
    use ic_registry_local_store::LocalStoreImpl;
    use ic_test_utilities_tmpdir::tmpdir;
    use ic_types::PrincipalId;
    use rstest::rstest;

    use super::*;

    const FAKE_SUBNET_ID: &str = "gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe";

    #[test]
    fn need_cold_storage_move_test() {
        let dir = tmpdir("test_dir");

        let backup_helper = fake_backup_helper(
            dir.as_ref(),
            /*versions_hot=*/ 2,
            /*daily_replays=*/ 2,
        );

        create_dir_all(backup_helper.spool_dir().join("replica_version_1")).unwrap();
        create_dir_all(backup_helper.spool_dir().join("replica_version_2")).unwrap();
        create_dir_all(backup_helper.spool_dir().join("replica_version_3")).unwrap();

        let need_cold_storage_move = backup_helper
            .need_cold_storage_move()
            .expect("should execute successfully");

        assert!(need_cold_storage_move);
    }

    #[test]
    fn does_not_need_cold_storage_move_test() {
        let dir = tmpdir("test_dir");

        let backup_helper = fake_backup_helper(
            dir.as_ref(),
            /*versions_hot=*/ 2,
            /*daily_replays=*/ 2,
        );

        create_dir_all(backup_helper.spool_dir().join("replica_version_1")).unwrap();
        create_dir_all(backup_helper.spool_dir().join("replica_version_2")).unwrap();

        let need_cold_storage_move = backup_helper
            .need_cold_storage_move()
            .expect("should execute successfully");

        assert!(!need_cold_storage_move);
    }

    #[test]
    fn cold_store_artifacts_test() {
        let dir = tmpdir("test_dir");

        let backup_helper = fake_backup_helper(
            dir.as_ref(),
            /*versions_hot=*/ 2,
            /*daily_replays=*/ 2,
        );

        create_artifacts_dir_with_heights(
            &backup_helper.spool_dir().join("replica_version_1"),
            vec![0, 50, 100, 150],
        );
        create_artifacts_dir_with_heights(
            &backup_helper.spool_dir().join("replica_version_2"),
            vec![200, 250],
        );
        create_artifacts_dir_with_heights(
            &backup_helper.spool_dir().join("replica_version_3"),
            vec![300, 350, 400, 450, 500, 550],
        );

        let max_height = backup_helper
            .cold_store_artifacts()
            .expect("should execute successfully");

        assert_eq!(max_height, 150);

        let cold_storage_dirs = collect_and_sort_dir_entries(
            &backup_helper
                .cold_storage_dir
                .join(FAKE_SUBNET_ID)
                .join("artifacts"),
        );

        // Only the artifacts from the earliest replica version are moved to the cold storage.
        assert_eq!(cold_storage_dirs.len(), 1);
        assert!(cold_storage_dirs[0].ends_with("_000000000150_replica_version_1.txz"));

        let artifacts_dirs = collect_and_sort_dir_entries(&backup_helper.spool_dir());

        // The artifacts from the earliest replica version are removed from the hot storage.
        assert_eq!(artifacts_dirs.len(), 2);
        assert!(!artifacts_dirs.contains(&"replica_version_1".to_string()));
        assert!(artifacts_dirs.contains(&"replica_version_2".to_string()));
        assert!(artifacts_dirs.contains(&"replica_version_3".to_string()));
    }

    #[test]
    fn cold_store_states_test() {
        let dir = tmpdir("test_dir");

        let backup_helper = fake_backup_helper(
            dir.as_ref(),
            /*versions_hot=*/ 2,
            /*daily_replays=*/ 2,
        );

        let mut fake_timestamp = DateTime::UNIX_EPOCH;

        for height in [0, 10, 20, 30, 40, 50] {
            let dir = backup_helper.archive_dir().join(height.to_string());
            create_dir_all(&dir).unwrap();

            fake_timestamp += std::time::Duration::from_secs(12 * 60 * 60);
            write_timestamp(&dir, fake_timestamp).unwrap();
        }

        backup_helper
            .cold_store_states(30)
            .expect("should execute successfully");

        let cold_storage_dirs = collect_and_sort_dir_entries(
            &backup_helper
                .cold_storage_dir
                .join(FAKE_SUBNET_ID)
                .join("states"),
        );

        assert_eq!(cold_storage_dirs.len(), 2);
        assert!(cold_storage_dirs.contains(&"0".to_string()));
        assert!(cold_storage_dirs.contains(&"20".to_string()));

        let archives_dirs = collect_and_sort_dir_entries(&backup_helper.archive_dir());

        // The artifacts from the earliest replica version are removed from the hot storage.
        assert_eq!(archives_dirs.len(), 2);
        assert!(archives_dirs.contains(&"40".to_string()));
        assert!(archives_dirs.contains(&"50".to_string()));
    }

    #[test]
    fn maybe_cold_store_states_moves_test() {
        let dir = tmpdir("test_dir");

        let backup_helper = fake_backup_helper(
            dir.as_ref(),
            /*versions_hot=*/ 2,
            /*daily_replays=*/ 2,
        );

        let mut fake_timestamp = DateTime::UNIX_EPOCH;
        for height in [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100] {
            let dir = backup_helper.archive_dir().join(height.to_string());
            create_dir_all(&dir).unwrap();

            fake_timestamp += std::time::Duration::from_secs(12 * 60 * 60);
            write_timestamp(&dir, fake_timestamp).unwrap();
        }

        let cold_stored_states = backup_helper
            .maybe_cold_store_states()
            .expect("should execute successfully");

        assert!(cold_stored_states);

        let cold_storage_dirs = collect_and_sort_dir_entries(
            &backup_helper
                .cold_storage_dir
                .join(FAKE_SUBNET_ID)
                .join("states"),
        );

        assert_eq!(
            cold_storage_dirs,
            vec![
                "0".to_string(),
                "20".to_string(),
                "40".to_string(),
                "60".to_string(),
                "80".to_string()
            ]
        );

        assert_eq!(
            collect_and_sort_dir_entries(&backup_helper.archive_dir()),
            vec!["100".to_string(), "90".to_string(),]
        );
    }

    #[test]
    fn maybe_cold_store_states_does_not_move_test() {
        let dir = tmpdir("test_dir");

        let backup_helper = fake_backup_helper(
            dir.as_ref(),
            /*versions_hot=*/ 2,
            /*daily_replays=*/ 2,
        );

        let mut fake_timestamp = DateTime::UNIX_EPOCH;
        for height in [0, 10] {
            let dir = backup_helper.archive_dir().join(height.to_string());
            create_dir_all(&dir).unwrap();

            fake_timestamp += std::time::Duration::from_secs(12 * 60 * 60);
            write_timestamp(&dir, fake_timestamp).unwrap();
        }

        let cold_stored_states = backup_helper
            .maybe_cold_store_states()
            .expect("should execute successfully");

        assert!(!cold_stored_states);

        // Assert that all the states remain in the hot storage
        assert_eq!(
            collect_and_sort_dir_entries(&backup_helper.archive_dir()),
            vec!["0".to_string(), "10".to_string()]
        );
    }

    #[test]
    fn test_purge_old_logs_works() {
        let dir = tmpdir("test_dir");
        let backup_helper = fake_backup_helper(
            dir.as_ref(),
            /*versions_hot=*/ 2,
            /*daily_replays=*/ 2,
        );
        let logs_dir = backup_helper.logs_dir();
        let very_old_file = logs_dir.join("very_old");
        let old_file = logs_dir.join("old");
        let new_file = logs_dir.join("new");
        std::fs::File::create_new(&very_old_file).unwrap();
        sleep(Duration::from_secs(1));
        std::fs::File::create_new(&old_file).unwrap();
        sleep(Duration::from_secs(1));
        std::fs::File::create_new(&new_file).unwrap();

        backup_helper
            .purge_old_logs(
                &logs_dir,
                std::fs::metadata(&old_file).unwrap().created().unwrap(),
            )
            .expect("Should succeed");

        assert!(!std::fs::exists(&very_old_file).unwrap());
        assert!(std::fs::exists(&old_file).unwrap());
        assert!(std::fs::exists(&new_file).unwrap());
    }

    #[rstest]
    #[case::all_logs_are_kept_when_max_age_not_specified(None, 3)]
    #[case::only_old_enough_logs_are_purged(Some(Duration::from_secs(3)), 3)]
    #[case::only_old_enough_logs_are_purged(Some(Duration::from_secs(2)), 2)]
    #[case::only_old_enough_logs_are_purged(Some(Duration::from_secs(1)), 1)]
    #[case::only_old_enough_logs_are_purged(Some(Duration::from_secs(0)), 0)]
    fn test_dump_logs_file_sometimes_purges_logs(
        #[case] max_logs_age_to_keep: Option<Duration>,
        #[case] expected_logs_count: usize,
    ) {
        let dir = tmpdir("test_dir");
        let mut backup_helper = fake_backup_helper(
            dir.as_ref(),
            /*versions_hot=*/ 2,
            /*daily_replays=*/ 2,
        );
        backup_helper.max_logs_age_to_keep = max_logs_age_to_keep;

        backup_helper
            .dump_log_file(/*height=*/ 100, &String::from("fake stdout 1"))
            .unwrap();
        sleep(Duration::from_secs(1));
        backup_helper
            .dump_log_file(/*height=*/ 200, &String::from("fake stdout 2"))
            .unwrap();
        sleep(Duration::from_secs(1));
        backup_helper
            .dump_log_file(/*height=*/ 300, &String::from("fake stdout 3"))
            .unwrap();

        assert_eq!(
            std::fs::read_dir(backup_helper.logs_dir()).unwrap().count(),
            expected_logs_count,
        );
    }

    // Utility functions below

    fn create_artifacts_dir_with_heights(replica_version_dir: &Path, heights: Vec<u64>) {
        for height in heights {
            let shard = 100 * (height / 100);
            create_dir_all(
                replica_version_dir
                    .join(shard.to_string())
                    .join(height.to_string()),
            )
            .unwrap();
        }
    }

    fn fake_backup_helper(
        temp_dir: &Path,
        versions_hot: usize,
        daily_replays: usize,
    ) -> BackupHelper {
        let data_provider = Arc::new(LocalStoreImpl::new(
            temp_dir.join("ic_registry_local_store"),
        ));
        let registry_client = Arc::new(RegistryClientImpl::new(
            data_provider,
            /*metrics_registry=*/ None,
        ));

        let notification_client = NotificationClient {
            push_metrics: false,
            metrics_urls: vec![],
            network_name: "fake_network_name".into(),
            backup_instance: "fake_backup_instance".into(),
            slack_token: "fake_slack_token".into(),
            subnet: "fake_subnet".into(),
            log: ic_recovery::util::make_logger(),
        };

        BackupHelper {
            subnet_id: PrincipalId::from_str(FAKE_SUBNET_ID)
                .map(SubnetId::from)
                .unwrap(),
            initial_replica_version: ReplicaVersion::try_from("fake_replica_version").unwrap(),
            root_dir: temp_dir.join("backup"),
            excluded_dirs: vec![],
            ssh_private_key: "fake_ssh_private_key".into(),
            registry_client,
            notification_client,
            downloads_guard: Mutex::new(true).into(),
            logs_guard: Arc::new(Mutex::new(())),
            max_logs_age_to_keep: None,
            hot_disk_resource_threshold_percentage: 75,
            cold_disk_resource_threshold_percentage: 95,
            cold_storage_dir: temp_dir.join("cold_storage"),
            versions_hot,
            artifacts_guard: Mutex::new(true),
            daily_replays,
            do_cold_storage: true,
            thread_id: 1,
            blacklisted_nodes: Arc::new(vec![]),
            log: ic_recovery::util::make_logger(),
        }
    }

    fn collect_and_sort_dir_entries(dir: &Path) -> Vec<String> {
        let mut dirs = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .path()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into()
            })
            .collect::<Vec<_>>();

        dirs.sort();

        dirs
    }
}
