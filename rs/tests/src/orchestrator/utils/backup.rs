use crate::orchestrator::utils::ssh_access::{read_remote_file, AuthMean};
use ic_artifact_pool::backup::BackupArtifact;
use ic_replay::{
    cmd::{ClapSubnetId, ReplayToolArgs, RestoreFromBackupCmd, SubCommand},
    player::{ReplayError, StateParams},
};
use ic_types::{Height, SubnetId};
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
            data_root: None,
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

    /// Write a batch of fake artifacts (without finalization) to the local backup spool.
    /// Return the height at which the artifacts were written (= first height after last
    /// finalization in spool).
    pub fn store_invalid_artifacts(&self, replica_version: &str) -> Height {
        use ic_test_utilities::{consensus::fake::*, mock_time, types::ids::node_test_id};
        use ic_types::{
            batch::*,
            consensus::*,
            crypto::{CryptoHash, CryptoHashOf},
            RegistryVersion,
        };

        let registry_version = RegistryVersion::from(4);
        let hash = CryptoHashOf::from(CryptoHash(vec![1, 2, 3]));
        let path = Path::new(&self.spool_path())
            .join(&self.subnet_id.to_string())
            .join(replica_version);
        let height = Height::from(self.get_end_height(replica_version) + 1);

        let artifact = BlockProposal::fake(
            Block::new(
                hash.clone(),
                Payload::new(
                    ic_crypto::crypto_hash,
                    (ic_types::consensus::dkg::Summary::fake(), None).into(),
                ),
                height,
                Rank(456),
                ValidationContext {
                    registry_version,
                    certified_height: height - Height::from(10),
                    time: mock_time(),
                },
            ),
            node_test_id(333),
        );
        BackupArtifact::BlockProposal(Box::new(artifact))
            .write_to_disk(&path)
            .unwrap();

        let artifact = RandomTape::fake(RandomTapeContent::new(height));
        BackupArtifact::RandomTape(Box::new(artifact))
            .write_to_disk(&path)
            .unwrap();

        let artifact = RandomBeacon::fake(RandomBeaconContent::new(
            height,
            CryptoHashOf::from(CryptoHash(vec![1, 2, 3])),
        ));
        BackupArtifact::RandomBeacon(Box::new(artifact))
            .write_to_disk(&path)
            .unwrap();

        let artifact = Notarization::fake(NotarizationContent::new(height, hash));
        BackupArtifact::Notarization(Box::new(artifact))
            .write_to_disk(&path)
            .unwrap();

        height
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
        self.get_height_iterator(replica_version, false)
            .min()
            .unwrap()
    }

    /// get height of highest finalized batch in spool
    fn get_end_height(&self, replica_version: &str) -> u64 {
        self.get_height_iterator(replica_version, true)
            .max()
            .unwrap()
    }

    fn get_height_iterator(
        &self,
        replica_version: &str,
        finalizations: bool,
    ) -> impl Iterator<Item = u64> {
        let dir_path = format!(
            "{}/{}/{}/0/",
            self.spool_path(),
            self.subnet_id,
            replica_version
        );

        let has_finalization = |path: PathBuf| {
            std::fs::read_dir(path).unwrap().flatten().any(|artifact| {
                artifact
                    .file_name()
                    .into_string()
                    .unwrap()
                    .contains("finalization")
            })
        };

        let heights = std::fs::read_dir(dir_path).unwrap();
        heights
            .flatten()
            .filter(move |height| !finalizations || has_finalization(height.path()))
            .map(|height| {
                height
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
    }
}
