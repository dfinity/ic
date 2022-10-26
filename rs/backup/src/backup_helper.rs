use crate::cmd::BackupArgs;
use crate::util::{block_on, sleep_secs};
use ic_recovery::command_helper::exec_cmd; // TODO: refactor this and next, out of ic_recovery
use ic_recovery::file_sync_helper::download_binary;
use ic_types::{ReplicaVersion, SubnetId};
use rand::{seq::SliceRandom, thread_rng};
use serde_json::Value;
use slog::{info, warn, Logger};
use std::convert::TryFrom;
use std::ffi::OsStr;
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;
use std::process::{Command, Stdio};

const RETRIES_RSYNC_HOST: u64 = 5;
const RETRIES_BINARY_DOWNLOAD: u64 = 3;

pub struct BackupHelper {
    pub replica_version: ReplicaVersion,
    pub subnet_id: SubnetId,
    pub nns_url: String,
    pub root_dir: PathBuf,
    pub testnet: bool,
    pub log: Logger,
}

impl BackupHelper {
    pub fn new(log: Logger, args: BackupArgs) -> Result<Self, String> {
        info!(log, "NNS Url: {:?}", args.nns_url);
        info!(log, "Subnet ID: {:?}", args.subnet_id);
        info!(log, "Data root: {:?}", args.data_root);
        info!(log, "Replica version: {:?}", args.replica_version);
        info!(log, "testnet: {}", args.testnet);

        Ok(Self {
            replica_version: ReplicaVersion::try_from(args.replica_version)
                .expect("Wrong format of the replica version"),
            nns_url: args.nns_url,
            subnet_id: args.subnet_id,
            root_dir: args.data_root,
            testnet: args.testnet,
            log,
        })
    }

    fn binary_dir(&self) -> PathBuf {
        self.root_dir
            .join(format!("binaries/{}/", self.replica_version))
    }

    fn binary_file(&self, executable: &str) -> PathBuf {
        self.binary_dir().join(executable)
    }

    fn spool_root_dir(&self) -> PathBuf {
        self.root_dir.join("spool/")
    }

    fn spool_dir(&self) -> PathBuf {
        self.spool_root_dir().join(self.subnet_id.to_string())
    }

    fn data_dir(&self) -> PathBuf {
        self.root_dir.join(format!("data/{}/", self.subnet_id))
    }

    fn ic_config_dir(&self) -> PathBuf {
        self.data_dir().join("config/")
    }

    fn ic_config_file_local(&self) -> PathBuf {
        self.ic_config_dir().join("ic.json5")
    }

    fn username(&self) -> String {
        if self.testnet { "admin" } else { "backup" }.to_string()
    }

    pub fn download_binaries(&self) {
        if !self.binary_dir().exists() {
            std::fs::create_dir_all(self.binary_dir()).expect("Failure creating a directory");
        }
        self.download_binary("ic-admin".to_string());
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
        panic!(
            "Binary {} is required for the replica {}",
            binary_name, self.replica_version
        );
    }

    fn rsync_node_backup(&self, node_ip: IpAddr) {
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
    }

    fn rsync_config(&self, node_ip: IpAddr) {
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
    }

    fn rsync_cmd(
        &self,
        remote_dir: String,
        local_dir: &OsStr,
        arguments: &[&str],
    ) -> Result<(), String> {
        let mut cmd = Command::new("rsync");
        cmd.arg("-e")
            .arg("ssh -o StrictHostKeyChecking=no")
            // TODO: add login credentials for the user "backup", also 600 access right to the private key file
            //.arg(format!("ssh -o StrictHostKeyChecking=no -i {}", private_key_file))
            .arg("--timeout=600");
        cmd.args(arguments);
        cmd.arg("--min-size=1").arg(remote_dir).arg(local_dir);
        info!(self.log, "Will execute: {:?}", cmd);
        if let Err(e) = exec_cmd(&mut cmd) {
            // TODO: probably tolerate: rsync warning: some files vanished before they could be transferred (code 24)
            Err(format!("Error: {}", e))
        } else {
            Ok(())
        }
    }

    pub fn sync(&self, nodes: Vec<IpAddr>) {
        if !self.spool_dir().exists() {
            std::fs::create_dir_all(self.spool_dir()).expect("Failure creating a directory");
        }
        if !self.ic_config_dir().exists() {
            std::fs::create_dir_all(self.ic_config_dir()).expect("Failure creating a directory");
        }

        let mut shuf_nodes = nodes;
        shuf_nodes.shuffle(&mut thread_rng());
        for n in shuf_nodes.clone() {
            self.rsync_config(n);
        }
        for n in shuf_nodes {
            self.rsync_node_backup(n);
        }
    }

    // TODO: better implementation once we get registry with the replicator
    pub fn collect_subnet_nodes(&self) -> Vec<IpAddr> {
        let ic_admin = self.binary_file("ic-admin");
        let mut cmd = Command::new(ic_admin);
        cmd.arg("--nns-url")
            .arg(&self.nns_url)
            .arg("get-subnet")
            .arg(&self.subnet_id.to_string())
            .stdout(Stdio::piped());
        if let Ok(Some(stdout)) = exec_cmd(&mut cmd) {
            if let Ok(v) = serde_json::from_str::<Value>(&stdout) {
                let arr = &v["records"][0]["value"]["membership"];
                if let Some(nodes) = arr.as_array() {
                    let mut node_ips = Vec::new();
                    for n in nodes {
                        if let Some(node_id) = n.as_str() {
                            let ic_admin = self.binary_file("ic-admin");
                            let mut cmd2 = Command::new(ic_admin);
                            cmd2.arg("--nns-url")
                                .arg(&self.nns_url)
                                .arg("get-node")
                                .arg(node_id)
                                .stdout(Stdio::piped());
                            if let Ok(Some(stdout)) = exec_cmd(&mut cmd2) {
                                if let Some(pos) = stdout.find("ip_addr: \"") {
                                    let str2 = stdout[(pos + 10)..].to_string();
                                    if let Some(pos2) = str2.find('"') {
                                        let ip_addr = str2[..pos2].to_string();
                                        if let Ok(ip_v6) = ip_addr.parse::<Ipv6Addr>() {
                                            node_ips.push(IpAddr::V6(ip_v6));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    return node_ips;
                }
            }
        }
        Vec::new()
    }
}
