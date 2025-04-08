//! This module implements a backup mechanism for essential consensus artifacts.
//! These back ups will allow us to obtain a relevant state, and recover a
//! subnet from that state.
//!
//! To re-compute a state at any height, we need to follow the finalized chain
//! starting from the genesis block, executing all block proposals one by one,
//! using their payloads (ingress + xnet) and the random tape as inputs. We can
//! use CUPs as checkpoints, to verify the hash of the re-computed state. We
//! can use finalizations to verify the authenticity of each stored proposal of
//! the finalized chain. We can use notarizations to verify the authenticity of
//! all proposals behind the latest finalized block (if the situation applies).
//! Since consensus purges only after a new CUP was stored in the validated pool
//! and since we backup all artifacts instantly after the pool update, there is
//! no possibility to inject purging (or any other deletion) of artifacts
//! between the pool update and the backup.

use ic_config::artifact_pool::BACKUP_GROUP_SIZE;
use ic_interfaces::{p2p::artifact_manager::JoinGuard, time_source::TimeSource};
use ic_logger::{error, info, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_protobuf::types::v1 as pb;
use ic_types::{
    consensus::{
        BlockProposal, ConsensusMessage, Finalization, HasHeight, Notarization, RandomBeacon,
        RandomTape,
    },
    time::{Time, UNIX_EPOCH},
    Height,
};
use prometheus::IntCounter;
use prost::Message;
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        mpsc::{sync_channel, Receiver, SyncSender},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

pub enum BackupArtifact {
    Finalization(Finalization),
    Notarization(Notarization),
    BlockProposal(BlockProposal),
    RandomBeacon(RandomBeacon),
    RandomTape(RandomTape),
    CatchUpPackage(Height, pb::CatchUpPackage),
}

impl TryFrom<ConsensusMessage> for BackupArtifact {
    type Error = ();
    fn try_from(artifact: ConsensusMessage) -> Result<Self, Self::Error> {
        use ConsensusMessage::*;
        match artifact {
            Finalization(artifact) => Ok(BackupArtifact::Finalization(artifact)),
            Notarization(artifact) => Ok(BackupArtifact::Notarization(artifact)),
            BlockProposal(artifact) => Ok(BackupArtifact::BlockProposal(artifact)),
            RandomTape(artifact) => Ok(BackupArtifact::RandomTape(artifact)),
            RandomBeacon(artifact) => Ok(BackupArtifact::RandomBeacon(artifact)),
            CatchUpPackage(artifact) => Ok(BackupArtifact::CatchUpPackage(
                artifact.height(),
                pb::CatchUpPackage::from(&artifact),
            )),
            // Do not replace by a `_` so that we evaluate at this place if we want to
            // backup a new artifact!
            RandomBeaconShare(_)
            | NotarizationShare(_)
            | FinalizationShare(_)
            | RandomTapeShare(_)
            | CatchUpPackageShare(_)
            | EquivocationProof(_) => Err(()),
        }
    }
}

#[derive(Clone, Debug)]
struct Metrics {
    // Amount of I/O errors. Any number above 0 is critical.
    io_errors: IntCounter,
}

impl Metrics {
    fn new(registry: &MetricsRegistry) -> Self {
        Self {
            io_errors: registry.int_counter(
                "consensus_backup_io_errors",
                "The number of I/O errors happened during the consensus backup storing or purging.",
            ),
        }
    }
}

// The number of backup / purging rounds, that can queue up before we start
// blocking consensus. Currently, we have a full rendevouz, i.e. consensus
// blocks when the artifacts of the last round have not persisted yet.
const QUEUE_LENGTH: usize = 0;

pub enum BackupRequest {
    Backup(Vec<ConsensusMessage>),
    BackupCUP(Height, pb::CatchUpPackage),
    Await(SyncSender<()>),
    Shutdown,
}

struct BackupThread {
    // The timestamp of the last backup purge.
    time_of_last_purge: Time,
    purge_interval: Duration,
    time_source: Arc<dyn TimeSource>,
    // The queue for the purging thread
    purging_queue: SyncSender<PurgingRequest>,
    // Thread handle of the thread executing the purging.
    purging_thread: Option<thread::JoinHandle<()>>,
    // Path pointing to <backup_dir>/<subnet_id>/<replica_version>. It contains all artifacts
    // backed up by the current replica version.
    version_path: PathBuf,
    metrics: Metrics,
    log: ReplicaLogger,
}

impl BackupThread {
    fn new(
        age_threshold: Duration,
        purge_interval: Duration,
        age: Box<dyn BackupAge>,
        time_source: Arc<dyn TimeSource>,
        backup_path: PathBuf,
        version_path: PathBuf,
        metrics: Metrics,
        log: ReplicaLogger,
    ) -> Self {
        let (purging_queue, purging_thread) = PurgingThread::new(
            backup_path,
            age_threshold,
            metrics.clone(),
            log.clone(),
            age,
        )
        .start();

        BackupThread {
            time_of_last_purge: UNIX_EPOCH,
            purge_interval,
            time_source,
            purging_queue,
            purging_thread: Some(purging_thread),
            version_path,
            metrics,
            log,
        }
    }

    fn start(mut self) -> (SyncSender<BackupRequest>, JoinHandle<()>) {
        let (tx, rx) = sync_channel(QUEUE_LENGTH);
        let handle = thread::Builder::new()
            .name("BackupThread".to_string())
            .spawn(move || self.run(rx))
            .expect("Failed to spawn BackupThread");
        (tx, handle)
    }

    fn run(&mut self, rx: Receiver<BackupRequest>) {
        loop {
            match rx.recv() {
                Ok(BackupRequest::Backup(artifacts)) => {
                    let artifacts: Vec<BackupArtifact> = artifacts
                        .into_iter()
                        .flat_map(BackupArtifact::try_from)
                        .collect();
                    if let Err(err) = store_artifacts(artifacts, &self.version_path) {
                        error!(self.log, "Backup storing failed: {:?}", err);
                        self.metrics.io_errors.inc();
                    }
                }
                Ok(BackupRequest::BackupCUP(height, cup_proto)) => {
                    if let Err(err) = store_artifacts(
                        vec![BackupArtifact::CatchUpPackage(height, cup_proto)],
                        &self.version_path,
                    ) {
                        error!(self.log, "Backup storing failed: {:?}", err);
                        self.metrics.io_errors.inc();
                    }
                }
                Ok(BackupRequest::Await(tx)) => {
                    self.purging_queue.send(PurgingRequest::Await(tx)).ok();
                }
                Ok(BackupRequest::Shutdown) => {
                    info!(self.log, "Shutting down the backup thread.");
                    break;
                }
                Err(_) => {
                    error!(self.log, "Orphaned backup thread. This is a bug");
                    break;
                }
            }

            // If we didn't purge within the last PURGE_INTERVAL, trigger a new purge.
            // This way we avoid a too frequent purging. We also block if the previous
            // purging has not finished yet, which is not expected with sufficiently
            // large PURGE_INTERVAL.
            let time_of_last_purge = self.time_of_last_purge;
            let time_now = self.time_source.get_relative_time();
            if time_now >= time_of_last_purge + self.purge_interval {
                if self.purging_queue.send(PurgingRequest::Purge).is_err() {
                    error!(
                        self.log,
                        "Purging thread exited unexpectedly. This is a bug."
                    );
                    self.metrics.io_errors.inc();
                }

                // Set the time to current
                self.time_of_last_purge = time_now;
            }
        }
    }
}

impl Drop for BackupThread {
    fn drop(&mut self) {
        let _ = self.purging_queue.send(PurgingRequest::Shutdown);
        if self.purging_thread.take().unwrap().join().is_err() {
            error!(
                self.log,
                "Purging thread exited prematurely during shutdown"
            );
        }
    }
}

enum PurgingRequest {
    Purge,
    Await(SyncSender<()>),
    Shutdown,
}

struct PurgingThread {
    // Path containing all backups of all versions running on the current node.
    backup_path: PathBuf,
    // The maximum age backup artifacts can reach before purging.
    age_threshold: Duration,
    metrics: Metrics,
    log: ReplicaLogger,
    age: Box<dyn BackupAge>,
}

pub enum PurgingError {
    Transient(String),
    Permanent(io::Error),
}

/// Trait defining an interface to determine the age of backup artifacts stored on disk
pub trait BackupAge: Send {
    fn get_elapsed_time(&self, path: &Path) -> Result<Duration, PurgingError>;
}

pub struct FileSystemAge {}

impl BackupAge for FileSystemAge {
    fn get_elapsed_time(&self, path: &Path) -> Result<Duration, PurgingError> {
        // return elapsed time since last modification as reported by file system
        path.metadata()
            .map_err(PurgingError::Permanent)?
            .modified()
            .map_err(PurgingError::Permanent)?
            .elapsed()
            .map_err(|err| PurgingError::Transient(err.to_string()))
    }
}

impl PurgingThread {
    fn new(
        backup_path: PathBuf,
        age_threshold: Duration,
        metrics: Metrics,
        log: ReplicaLogger,
        age: Box<dyn BackupAge>,
    ) -> Self {
        Self {
            backup_path,
            age_threshold,
            metrics,
            log,
            age,
        }
    }

    fn start(mut self) -> (SyncSender<PurgingRequest>, JoinHandle<()>) {
        let (tx, rx) = sync_channel(QUEUE_LENGTH);
        let handle = thread::Builder::new()
            .name("BackupPurgingThread".to_string())
            .spawn(move || self.run(rx))
            .expect("Failed to start BackupPurgingThread");
        (tx, handle)
    }

    fn run(&mut self, rx: Receiver<PurgingRequest>) {
        loop {
            match rx.recv() {
                Ok(PurgingRequest::Purge) => {
                    let start = std::time::Instant::now();
                    if let Err(err) = purge(
                        self.age_threshold,
                        &self.backup_path,
                        self.log.clone(),
                        self.age.as_ref(),
                    ) {
                        error!(self.log, "Backup purging failed: {:?}", err);
                        self.metrics.io_errors.inc();
                    }
                    info!(self.log, "Backup purging finished in {:?}", start.elapsed());
                }
                Ok(PurgingRequest::Await(tx)) => tx.send(()).unwrap(),
                Ok(PurgingRequest::Shutdown) => {
                    info!(self.log, "Shutting down the purging thread.");
                    break;
                }
                Err(_) => {
                    error!(self.log, "Orphaned purging thread. This is a bug");
                    break;
                }
            }
        }
    }
}

pub struct Backup {
    // The queue of the backup thread
    backup_queue: SyncSender<BackupRequest>,
    // Thread handle of the thread executing the backup.
    backup_thread: Option<thread::JoinHandle<()>>,
    log: ReplicaLogger,
}

impl JoinGuard for Backup {}

impl Backup {
    pub fn new_with_age_func(
        backup_path: PathBuf,
        version_path: PathBuf,
        age_threshold: Duration,
        purge_interval: Duration,
        metrics_registry: MetricsRegistry,
        log: ReplicaLogger,
        age: Box<dyn BackupAge>,
        time_source: Arc<dyn TimeSource>,
    ) -> (Self, SyncSender<BackupRequest>) {
        let metrics = Metrics::new(&metrics_registry);
        let (backup_queue, backup_thread) = BackupThread::new(
            age_threshold,
            purge_interval,
            age,
            time_source,
            backup_path,
            version_path.clone(),
            metrics.clone(),
            log.clone(),
        )
        .start();
        let backup = Self {
            backup_queue: backup_queue.clone(),
            backup_thread: Some(backup_thread),
            log,
        };

        (backup, backup_queue)
    }

    pub fn new(
        backup_path: PathBuf,
        version_path: PathBuf,
        age_threshold: Duration,
        purge_interval: Duration,
        metrics_registry: MetricsRegistry,
        log: ReplicaLogger,
        time_source: Arc<dyn TimeSource>,
    ) -> (Self, SyncSender<BackupRequest>) {
        Self::new_with_age_func(
            backup_path,
            version_path,
            age_threshold,
            purge_interval,
            metrics_registry,
            log,
            Box::new(FileSystemAge {}),
            time_source,
        )
    }
}

// Write all backup files to the disk. For the sake of simplicity, we write all
// artifacts sequentially.
fn store_artifacts(artifacts: Vec<BackupArtifact>, path: &Path) -> Result<(), io::Error> {
    artifacts
        .into_iter()
        .try_for_each(|artifact| artifact.write_to_disk(path))
}

/// Traverses the whole backup directory and finds all leaf directories
/// (containing no other directories). Then it purges all leaves older than the
/// specified retention time. Age of a leave is determined by calling the given
/// implementation of [`BackupAge`]
fn purge(
    age_threshold: Duration,
    path: &Path,
    log: ReplicaLogger,
    age: &dyn BackupAge,
) -> Result<(), io::Error> {
    let mut leaves = Vec::new();
    get_leaves(path, &mut leaves)?;
    for path in leaves {
        let age = match age.get_elapsed_time(&path) {
            Ok(time) => time,
            // According to the documentation of `elapsed` this function may fail as
            // "the underlying system clock is susceptible to drift and updates". Those
            // errors are transient and safe to ignore. As they are very rare it's ok to
            // log a warning.
            Err(PurgingError::Transient(err)) => {
                warn!(
                    log,
                    "Skipping {:?}, because the modified timestamp couldn't be computed: {:?}",
                    &path,
                    err
                );
                continue;
            }

            Err(PurgingError::Permanent(err)) => return Err(err),
        };
        if age > age_threshold {
            fs::remove_dir_all(path)?;
        }
    }
    Ok(())
}

// Traverses the given path and returns a list of all leaf directories.
fn get_leaves(dir: &Path, leaves: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    let mut sub_directory_found = false;
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            sub_directory_found = true;
            get_leaves(&path, leaves)?;
        }
    }
    if !sub_directory_found {
        if let Some(path_name) = dir.to_str() {
            // We skip the folder lost+found, which is currently present on the backup
            // volume.
            if !path_name.contains("lost+found") {
                leaves.push(dir.to_path_buf());
            }
        }
    }
    Ok(())
}

impl Drop for Backup {
    fn drop(&mut self) {
        let _ = self.backup_queue.send(BackupRequest::Shutdown);
        if self.backup_thread.take().unwrap().join().is_err() {
            error!(self.log, "Backup thread exited prematurely during shutdown");
        }
    }
}

impl BackupArtifact {
    /// Writes the protobuf serialization of the artifact into a file in the given
    /// directory.
    pub fn write_to_disk(&self, path: &Path) -> Result<(), std::io::Error> {
        let (file_directory, file_name) = self.file_location(path);
        // Create the path if necessary.
        fs::create_dir_all(&file_directory)?;
        let full_path = file_directory.join(file_name);
        // If the file exists, it will be overwritten (this is required on
        // initializations).
        let serialized = self.serialize()?;
        ic_sys::fs::write_using_tmp_file(full_path, |writer| writer.write_all(&serialized))
    }

    /// Serializes the artifact to protobuf.
    pub fn serialize(&self) -> Result<Vec<u8>, io::Error> {
        let mut buf = Vec::new();
        use BackupArtifact::*;
        match self {
            Finalization(artifact) => pb::Finalization::from(artifact).encode(&mut buf),
            Notarization(artifact) => pb::Notarization::from(artifact).encode(&mut buf),
            BlockProposal(artifact) => pb::BlockProposal::from(artifact).encode(&mut buf),
            RandomTape(artifact) => pb::RandomTape::from(artifact).encode(&mut buf),
            RandomBeacon(artifact) => pb::RandomBeacon::from(artifact).encode(&mut buf),
            CatchUpPackage(_, artifact) => artifact.encode(&mut buf),
        }
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
        Ok(buf)
    }

    /// Each artifact will be stored separately used the following path:
    ///
    /// <subnet_id>/<replica_version>/<(height / N) * N>/height/<artifact_specific_name>.bin
    ///
    /// Note that the artifact specific name must contain all parameters to be
    /// differentiated not only across other artifacts of the same replica, but also
    /// across artifacts from all replicas. E.g., since we use multi-signatures for
    /// notarizations and finalizations, these artifacts can be created in different
    /// ways on different replicas, so we need to put their hashes into the artifact
    /// name.
    pub fn file_location(&self, path: &Path) -> (PathBuf, String) {
        // Create a subdirectory for the height
        let (height, file_name) = match self {
            BackupArtifact::Finalization(artifact) => (artifact.height(), "finalization.bin"),
            BackupArtifact::Notarization(artifact) => (artifact.height(), "notarization.bin"),
            BackupArtifact::BlockProposal(artifact) => (artifact.height(), "block_proposal.bin"),
            BackupArtifact::RandomTape(artifact) => (artifact.height(), "random_tape.bin"),
            BackupArtifact::RandomBeacon(artifact) => (artifact.height(), "random_beacon.bin"),
            BackupArtifact::CatchUpPackage(height, _) => (*height, "catch_up_package.bin"),
        };
        // We group heights by directories to avoid running into any kind of unexpected
        // FS inode limitations. Each group directory will contain at most
        // [BACKUP_GROUP_SIZE] heights.
        let group_key = (height.get() / BACKUP_GROUP_SIZE) * BACKUP_GROUP_SIZE;
        let path_with_height = path.join(group_key.to_string()).join(height.to_string());
        (path_with_height, file_name.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_test_utilities_consensus::fake::*;
    use ic_test_utilities_types::ids::node_test_id;
    use ic_types::{
        batch::*,
        consensus::*,
        crypto::{CryptoHash, CryptoHashOf},
        RegistryVersion,
    };
    use std::convert::TryFrom;

    #[test]
    fn test_random_tape_conversion() {
        let artifact = RandomTape::fake(RandomTapeContent::new(Height::from(22)));
        let mut buf = Vec::new();
        pb::RandomTape::from(&artifact).encode(&mut buf).unwrap();
        assert_eq!(
            artifact,
            RandomTape::try_from(pb::RandomTape::decode(buf.as_slice()).unwrap()).unwrap()
        );
    }

    #[test]
    fn test_finalization_conversion() {
        let artifact = Finalization::fake(FinalizationContent::new(
            Height::from(22),
            CryptoHashOf::from(CryptoHash(vec![1, 2, 3])),
        ));
        let mut buf = Vec::new();
        pb::Finalization::from(&artifact).encode(&mut buf).unwrap();
        assert_eq!(
            artifact,
            Finalization::try_from(pb::Finalization::decode(buf.as_slice()).unwrap()).unwrap()
        );
    }

    #[test]
    fn test_notarization_conversion() {
        let artifact = Notarization::fake(NotarizationContent::new(
            Height::from(22),
            CryptoHashOf::from(CryptoHash(vec![1, 2, 3])),
        ));
        let mut buf = Vec::new();
        pb::Notarization::from(&artifact).encode(&mut buf).unwrap();
        assert_eq!(
            artifact,
            Notarization::try_from(pb::Notarization::decode(buf.as_slice()).unwrap()).unwrap()
        );
    }

    #[test]
    fn test_block_proposal_conversion() {
        let artifact = BlockProposal::fake(
            Block::new(
                CryptoHashOf::from(CryptoHash(Vec::new())),
                Payload::new(
                    ic_types::crypto::crypto_hash,
                    BlockPayload::Summary(SummaryPayload::fake()),
                ),
                Height::from(123),
                Rank(456),
                ValidationContext {
                    registry_version: RegistryVersion::from(99),
                    certified_height: Height::from(42),
                    time: UNIX_EPOCH,
                },
            ),
            node_test_id(333),
        );
        let mut buf = Vec::new();
        pb::BlockProposal::from(&artifact).encode(&mut buf).unwrap();
        assert_eq!(
            artifact,
            BlockProposal::try_from(pb::BlockProposal::decode(buf.as_slice()).unwrap()).unwrap()
        );
    }
}
