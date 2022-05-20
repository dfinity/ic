use crate::orchestrator::utils::ssh_access::{read_remote_file, AuthMean};
use ic_replay::{
    cmd::{ClapSubnetId, ReplayToolArgs, RestoreFromBackupCmd, SubCommand},
    player::{ReplayError, StateParams},
};
use ic_types::SubnetId;
use slog::{info, Logger};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

const BACKUP_DIR: &str = "./backup";
const SSH_FILE_PERMISSIONS: &str = "600";

pub struct Backup {
    nns_ip: IpAddr,
    backup_private_key: String,
    backup_dir: String,
    subnet_id: SubnetId,
    logger: Logger,
}

impl Backup {
    pub fn new(
        nns_ip: IpAddr,
        backup_private_key: String,
        subnet_id: SubnetId,
        logger: Logger,
    ) -> Self {
        // First clear the backup directory
        let backup_dir = BACKUP_DIR.to_string();
        if Path::new(&backup_dir).exists() {
            std::fs::remove_dir_all(backup_dir.clone()).unwrap();
        }
        std::fs::create_dir(backup_dir.clone()).unwrap();

        Self {
            nns_ip,
            backup_private_key,
            backup_dir,
            subnet_id,
            logger,
        }
    }

    pub fn replay(&self, replica_version: &str) -> Result<StateParams, ReplayError> {
        let start_height = self.get_start_height(replica_version);
        info!(
            self.logger,
            "Starting to replay from height {}", start_height
        );
        let args = ReplayToolArgs {
            subnet_id: ClapSubnetId(self.subnet_id),
            config: PathBuf::from(&self.config_path()),
            canister_caller_id: None,
            replay_until_height: None,
            subcmd: Some(SubCommand::RestoreFromBackup(RestoreFromBackupCmd {
                registry_local_store_path: PathBuf::from(&self.local_store_path()),
                backup_spool_path: PathBuf::from(&self.spool_path()),
                replica_version: replica_version.to_string(),
                start_height,
            })),
        };
        self.print_contents_of_dir(&self.local_store_path());
        self.print_contents_of_dir(&self.backup_dir);
        ic_replay::replay(args)
    }

    pub fn rsync_local_store(&self) {
        std::fs::create_dir_all(self.local_store_path()).unwrap();

        // Save the private key and adjust its permissions.
        let private_key_path = format!("{}/id_rsa", &self.backup_dir);
        std::fs::write(Path::new(&private_key_path), &self.backup_private_key).unwrap();
        let chmod = Command::new("chmod")
            .arg(SSH_FILE_PERMISSIONS)
            .arg(private_key_path.clone())
            .spawn()
            .unwrap();
        chmod.wait_with_output().unwrap();

        // Execute the following rsync command:
        //    rsync -e "ssh -o StrictHostKeyChecking=no -i path/to/id_rsa" \
        //        --timeout=600 \
        //        -qac --append-verify \
        //        "backup@[$NODE_IP]:/var/lib/ic/data/ic_registry_local_store/" \
        //        "$LOCAL_STORE_DIR"
        let cmd = Command::new("rsync")
            .arg("-e")
            .arg(format!(
                "ssh -o StrictHostKeyChecking=no -i {}",
                private_key_path
            ))
            .arg("--timeout=600")
            .arg("-qac")
            .arg("--append-verify")
            .arg(format!(
                "backup@[{}]:/var/lib/ic/data/ic_registry_local_store/",
                self.nns_ip
            ))
            .arg(&self.local_store_path())
            .spawn()
            .unwrap();

        cmd.wait_with_output().unwrap();
        self.print_contents_of_dir(&self.local_store_path());
    }

    pub fn sync_ic_json5_file(&self) {
        let mut config = read_remote_file(
            &self.nns_ip,
            "backup",
            &AuthMean::PrivateKey(self.backup_private_key.to_string()),
            Path::new("/run/ic-node/config/ic.json5"),
        )
        .unwrap();

        // Overwrite both the state and the registry local store paths in the config.
        let ic_state_path = format!("{}/restored/ic_state", &self.backup_dir);
        config = config.replace(
            "/var/lib/ic/data/ic_registry_local_store",
            &self.local_store_path(),
        );
        config = config.replace("/var/lib/ic/data/ic_state", &ic_state_path);
        std::fs::create_dir_all(ic_state_path).unwrap();
        std::fs::write(Path::new(&self.config_path()), config).unwrap();
    }

    pub fn rsync_spool(&self) {
        info!(self.logger, "Synching artefacts ...");
        // Save the private key and adjust its permissions.
        let private_key_path = format!("{}/id_rsa", &self.backup_dir);
        std::fs::write(Path::new(&private_key_path), &self.backup_private_key).unwrap();
        let chmod = Command::new("chmod")
            .arg("600")
            .arg(private_key_path.clone())
            .spawn()
            .unwrap();
        chmod.wait_with_output().unwrap();

        // Execute the following rsync command:
        //    rsync -e "ssh -o StrictHostKeyChecking=no -i path/to/id_rsa" \
        //        --timeout=600 \
        //        -qa --min-size=1 --append-verify \
        //        "backup@[$NODE_IP]:/var/lib/ic/backup/" "$SPOOL_DIR/"
        let cmd = Command::new("rsync")
            .arg("-e")
            .arg(format!(
                "ssh -o StrictHostKeyChecking=no -i {}",
                private_key_path
            ))
            .arg("--timeout=600")
            .arg("-qa")
            .arg("--min-size=1")
            .arg("--append-verify")
            .arg(format!("backup@[{}]:/var/lib/ic/backup/", &self.nns_ip))
            .arg(&self.spool_path())
            .spawn()
            .unwrap();

        cmd.wait_with_output().unwrap();
    }

    fn config_path(&self) -> String {
        format!("{}/ic.json5", &self.backup_dir)
    }

    fn local_store_path(&self) -> String {
        format!("{}/restored/ic_registry_local_store/", &self.backup_dir)
    }

    fn spool_path(&self) -> String {
        format!("{}/spool/", &self.backup_dir)
    }

    fn print_contents_of_dir(&self, path: &str) {
        let paths = std::fs::read_dir(path).unwrap();
        info!(self.logger, "Contents of {}:", path);
        for path in paths {
            info!(self.logger, "{}", path.unwrap().path().display());
        }
    }

    fn get_start_height(&self, replica_version: &str) -> u64 {
        let dir_path = format!(
            "{}/{}/{}/0/",
            self.spool_path(),
            self.subnet_id,
            replica_version
        );

        info!(self.logger, "Heights:");
        let heights = std::fs::read_dir(dir_path).unwrap();
        heights
            .map(|height| {
                height
                    .unwrap()
                    .path()
                    .into_os_string()
                    .into_string()
                    .unwrap()
                    .rsplit('/')
                    .next()
                    .unwrap()
                    .parse::<u64>()
                    .unwrap()
            })
            .min()
            .unwrap()
    }
}
