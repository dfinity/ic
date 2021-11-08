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
use ic_interfaces::{
    consensus_pool::{ConsensusPool, HeightRange},
    time_source::TimeSource,
};
use ic_logger::{error, info, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_protobuf::types::v1 as pb;
use ic_types::{
    consensus::{
        BlockProposal, CatchUpPackage, ConsensusMessage, Finalization, HasHeight, Notarization,
        RandomBeacon, RandomTape,
    },
    crypto::CryptoHashOf,
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
        RwLock,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

enum BackupArtifact {
    Finalization(Box<Finalization>),
    Notarization(Box<Notarization>),
    BlockProposal(Box<BlockProposal>),
    RandomBeacon(Box<RandomBeacon>),
    RandomTape(Box<RandomTape>),
    CatchUpPackage(Box<CatchUpPackage>),
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

enum BackupRequest {
    Backup(Vec<ConsensusMessage>),
    Await(SyncSender<()>),
    Shutdown,
}

struct BackupThread {
    // Path pointing to <backup_dir>/<subnet_id>/<replica_version>. It contains all artifacts
    // backed up by the current replica version.
    version_path: PathBuf,
    metrics: Metrics,
    log: ReplicaLogger,
}

impl BackupThread {
    fn new(version_path: PathBuf, metrics: Metrics, log: ReplicaLogger) -> Self {
        BackupThread {
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
                    if let Err(err) = store_artifacts(artifacts, &self.version_path) {
                        error!(self.log, "Backup storing failed: {:?}", err);
                        self.metrics.io_errors.inc();
                    }
                }
                Ok(BackupRequest::Await(tx)) => tx.send(()).unwrap(),
                Ok(BackupRequest::Shutdown) => {
                    info!(self.log, "Shutting down the backup thread.");
                    break;
                }
                Err(_) => {
                    error!(self.log, "Orphaned backup thread. This is a bug");
                    break;
                }
            }
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
    age_threshold_secs: Duration,
    metrics: Metrics,
    log: ReplicaLogger,
}

impl PurgingThread {
    fn new(
        backup_path: PathBuf,
        age_threshold_secs: Duration,
        metrics: Metrics,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            backup_path,
            age_threshold_secs,
            metrics,
            log,
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
                    if let Err(err) =
                        purge(self.age_threshold_secs, &self.backup_path, self.log.clone())
                    {
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

pub(super) struct Backup {
    // The timestamp of the last backup purge.
    time_of_last_purge: RwLock<Time>,
    // The queue of the backup thread
    backup_queue: SyncSender<BackupRequest>,
    // Thread handle of the thread executing the backup.
    backup_thread: Option<thread::JoinHandle<()>>,
    // The queue for the purging thread
    purging_queue: SyncSender<PurgingRequest>,
    // Thread handle of the thread executing the purging.
    purging_thread: Option<thread::JoinHandle<()>>,
    // Time interval between purges.
    purge_interval_secs: Duration,
    metrics: Metrics,
    log: ReplicaLogger,
}

impl Backup {
    pub fn new(
        pool: &dyn ConsensusPool,
        backup_path: PathBuf,
        version_path: PathBuf,
        age_threshold_secs: Duration,
        purge_interval_secs: Duration,
        metrics_registry: MetricsRegistry,
        log: ReplicaLogger,
    ) -> Self {
        let metrics = Metrics::new(&metrics_registry);
        let (backup_queue, backup_thread) =
            BackupThread::new(version_path.clone(), metrics.clone(), log.clone()).start();
        let (purging_queue, purging_thread) = PurgingThread::new(
            backup_path,
            age_threshold_secs,
            metrics.clone(),
            log.clone(),
        )
        .start();
        let backup = Self {
            time_of_last_purge: RwLock::new(UNIX_EPOCH),
            backup_queue,
            backup_thread: Some(backup_thread),
            purging_queue,
            purging_thread: Some(purging_thread),
            purge_interval_secs,
            metrics,
            log,
        };

        // Due to the fact that the backup is synced to the disk completely
        // independently of the consensus pool and always after the consensus pool was
        // mutated, we might run into an inconsistent state between the pool and the
        // backup data if the replica gets killed by the node manager. To avoid this
        // situation, on the instantiation of the consensus pool and the backup
        // component, we need to synchronize the backup with the pool in a blocking
        // manner.
        let artifacts = get_all_persisted_artifacts(pool);
        if let Err(err) = store_artifacts(artifacts, &version_path) {
            error!(backup.log, "Backup storing failed: {:?}", err);
            backup.metrics.io_errors.inc();
        }
        backup
    }

    // Filters the new artifacts and asynchronously writes the relevant artifacts
    // to the disk.
    pub fn store(&self, time_source: &dyn TimeSource, artifacts: Vec<ConsensusMessage>) {
        // If the queue is full, we will block here.
        if self
            .backup_queue
            .send(BackupRequest::Backup(artifacts))
            .is_err()
        {
            error!(
                self.log,
                "Backup thread exited unexpectedly. This is a bug."
            );
            self.metrics.io_errors.inc();
        }

        // If we didn't purge within the last PURGE_INTERVAL, trigger a new purge.
        // This way we avoid a too frequent purging. We also block if the previous
        // purging has not finished yet, which is not expected with sufficiently
        // large PURGE_INTERVAL.
        let time_of_last_purge = *self.time_of_last_purge.read().unwrap();
        if time_source.get_relative_time() - time_of_last_purge >= self.purge_interval_secs {
            if self.purging_queue.send(PurgingRequest::Purge).is_err() {
                error!(
                    self.log,
                    "Purging thread exited unexpectedly. This is a bug."
                );
                self.metrics.io_errors.inc();
            }

            // Set the time to current
            *self.time_of_last_purge.write().unwrap() = time_source.get_relative_time();
        }
    }

    /// Blocks the current thread until all artifacts have been written to disk.
    ///
    /// Mainly useful for testing.
    #[allow(dead_code)]
    pub(crate) fn sync_backup(&self) {
        let (tx, rx) = sync_channel(0);
        // NOTE: If we have an error here we will also have one in the next line
        let _ = self.backup_queue.send(BackupRequest::Await(tx));
        if rx.recv().is_err() {
            error!(self.log, "Error while syncing the backup thread");
            self.metrics.io_errors.inc();
        }
    }

    /// Joins on the purging thread handle and blocks until the thread has
    /// finished.
    ///
    /// Mainly useful for testing.
    #[allow(dead_code)]
    pub(crate) fn sync_purging(&self) {
        let (tx, rx) = sync_channel(0);
        // NOTE: If we have an error here we will also have one in the next line
        let _ = self.purging_queue.send(PurgingRequest::Await(tx));
        if rx.recv().is_err() {
            error!(self.log, "Error while syncing the purging thread");
            self.metrics.io_errors.inc();
        }
    }
}

// Write all backup files to the disk. For the sake of simplicity, we write all
// artifacts sequentially.
fn store_artifacts(artifacts: Vec<ConsensusMessage>, path: &Path) -> Result<(), io::Error> {
    use ConsensusMessage::*;
    artifacts
        .into_iter()
        .filter_map(|artifact| match artifact {
            Finalization(artifact) => Some(BackupArtifact::Finalization(Box::new(artifact))),
            Notarization(artifact) => Some(BackupArtifact::Notarization(Box::new(artifact))),
            BlockProposal(artifact) => Some(BackupArtifact::BlockProposal(Box::new(artifact))),
            RandomTape(artifact) => Some(BackupArtifact::RandomTape(Box::new(artifact))),
            RandomBeacon(artifact) => Some(BackupArtifact::RandomBeacon(Box::new(artifact))),
            CatchUpPackage(artifact) => Some(BackupArtifact::CatchUpPackage(Box::new(artifact))),
            // Do not replace by a `_` so that we evaluate at this place if we want to
            // backup a new artifact!
            RandomBeaconShare(_)
            | NotarizationShare(_)
            | FinalizationShare(_)
            | RandomTapeShare(_)
            | CatchUpPackageShare(_) => None,
        })
        .try_for_each(|artifact| artifact.write_to_disk(path))
}

// Traverses the whole backup directory and finds all leaf directories
// (containing no other directories). Then it purges all leaves older than the
// specified retention time.
fn purge(threshold_secs: Duration, path: &Path, log: ReplicaLogger) -> Result<(), io::Error> {
    let mut leaves = Vec::new();
    get_leaves(path, &mut leaves)?;
    for path in leaves {
        let age = match path.metadata()?.modified()?.elapsed() {
            Ok(time) => time,
            // According to the documentation of `elapsed` this function may fail as
            // "the underlying system clock is susceptible to drift and updates". Those
            // errors are transient and safe to ignore. As they are very rare it's ok to
            // log a warning.
            Err(err) => {
                warn!(
                    log,
                    "Skipping {:?}, because the modified timestamp couldn't be computed: {:?}",
                    &path,
                    err
                );
                continue;
            }
        };
        if age > threshold_secs {
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

// Returns all artifacts starting from the latest catch-up package height.
fn get_all_persisted_artifacts(pool: &dyn ConsensusPool) -> Vec<ConsensusMessage> {
    let cup_height = pool.as_cache().catch_up_package().height();
    let notarization_pool = pool.validated().notarization();
    let notarization_range = HeightRange::new(
        cup_height,
        notarization_pool
            .max_height()
            .unwrap_or_else(|| Height::from(0)),
    );
    let finalization_pool = pool.validated().finalization();
    let finalization_range = HeightRange::new(
        cup_height,
        finalization_pool
            .max_height()
            .unwrap_or_else(|| Height::from(0)),
    );
    let block_proposal_pool = pool.validated().block_proposal();
    let block_proposal_range = HeightRange::new(
        cup_height,
        block_proposal_pool
            .max_height()
            .unwrap_or_else(|| Height::from(0)),
    );
    let catch_up_package_pool = pool.validated().catch_up_package();
    let catch_up_package_range = HeightRange::new(
        cup_height,
        catch_up_package_pool
            .max_height()
            .unwrap_or_else(|| Height::from(0)),
    );
    let random_tape_pool = pool.validated().random_tape();
    let random_tape_range = HeightRange::new(
        cup_height,
        random_tape_pool
            .max_height()
            .unwrap_or_else(|| Height::from(0)),
    );
    let random_beacon_pool = pool.validated().random_beacon();
    let random_beacon_range = HeightRange::new(
        cup_height,
        random_beacon_pool
            .max_height()
            .unwrap_or_else(|| Height::from(0)),
    );

    finalization_pool
        .get_by_height_range(finalization_range)
        .map(ConsensusMessage::Finalization)
        .chain(
            notarization_pool
                .get_by_height_range(notarization_range)
                .map(ConsensusMessage::Notarization),
        )
        .chain(
            catch_up_package_pool
                .get_by_height_range(catch_up_package_range)
                .map(ConsensusMessage::CatchUpPackage),
        )
        .chain(
            random_tape_pool
                .get_by_height_range(random_tape_range)
                .map(ConsensusMessage::RandomTape),
        )
        .chain(
            random_beacon_pool
                .get_by_height_range(random_beacon_range)
                .map(ConsensusMessage::RandomBeacon),
        )
        .chain(
            block_proposal_pool
                .get_by_height_range(block_proposal_range)
                .map(ConsensusMessage::BlockProposal),
        )
        .collect()
}

impl Drop for Backup {
    fn drop(&mut self) {
        let _ = self.backup_queue.send(BackupRequest::Shutdown);
        if self.backup_thread.take().unwrap().join().is_err() {
            error!(self.log, "Backup thread exited prematurely during shutdown");
        }
        let _ = self.purging_queue.send(PurgingRequest::Shutdown);
        if self.purging_thread.take().unwrap().join().is_err() {
            error!(
                self.log,
                "Purging thread exited prematurely during shutdown"
            );
        }
    }
}

impl BackupArtifact {
    // Writes the protobuf serialization of the artifact into a file in the given
    // directory.
    fn write_to_disk(&self, path: &Path) -> Result<(), std::io::Error> {
        let (file_directory, file_name) = self.file_location(path);
        // Create the path if necessary.
        fs::create_dir_all(&file_directory)?;
        let full_path = file_directory.join(file_name);
        // If the file exists, it will be overwritten (this is required on
        // intializations).
        let serialized = self.serialize()?;
        ic_utils::fs::write_using_tmp_file(full_path, |writer| writer.write_all(&serialized))
    }

    // Serializes the artifact to protobuf.
    fn serialize(&self) -> Result<Vec<u8>, io::Error> {
        let mut buf = Vec::new();
        use BackupArtifact::*;
        match self {
            Finalization(artifact) => pb::Finalization::from(artifact.as_ref()).encode(&mut buf),
            Notarization(artifact) => pb::Notarization::from(artifact.as_ref()).encode(&mut buf),
            BlockProposal(artifact) => pb::BlockProposal::from(artifact.as_ref()).encode(&mut buf),
            RandomTape(artifact) => pb::RandomTape::from(artifact.as_ref()).encode(&mut buf),
            RandomBeacon(artifact) => pb::RandomBeacon::from(artifact.as_ref()).encode(&mut buf),
            CatchUpPackage(artifact) => {
                pb::CatchUpPackage::from(artifact.as_ref()).encode(&mut buf)
            }
        }
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
        Ok(buf)
    }

    // Each artifact will be stored separately used the following path:
    //
    // <subnet_id>/<(height / N) * N>/height/<artifact_specific_name>.bin
    //
    // Note that the artifact specific name must contain all parameters to be
    // differentiated not only across other artifacts of the same replica, but also
    // across artifacts from all replicas. E.g., since we use multi-signatures for
    // notarizations and finalizations, these artifacts can be created in different
    // ways on different replicas, so we need to put their hashes into the artifact
    // name.
    fn file_location(&self, path: &Path) -> (PathBuf, String) {
        // Create a subdir for the height
        use BackupArtifact::*;
        let (height, file_name) = match self {
            Finalization(artifact) => (
                artifact.height(),
                format!(
                    "finalization_{}_{}.bin",
                    bytes_to_hex_str(&artifact.content.block),
                    bytes_to_hex_str(&ic_crypto::crypto_hash(artifact.as_ref())),
                ),
            ),
            Notarization(artifact) => (
                artifact.height(),
                format!(
                    "notarization_{}_{}.bin",
                    bytes_to_hex_str(&artifact.content.block),
                    bytes_to_hex_str(&ic_crypto::crypto_hash(artifact.as_ref())),
                ),
            ),
            BlockProposal(artifact) => (
                artifact.height(),
                format!(
                    "block_proposal_{}_{}.bin",
                    bytes_to_hex_str(artifact.content.get_hash()),
                    bytes_to_hex_str(&ic_crypto::crypto_hash(artifact.as_ref())),
                ),
            ),
            RandomTape(artifact) => (artifact.height(), "random_tape.bin".to_string()),
            RandomBeacon(artifact) => (artifact.height(), "random_beacon.bin".to_string()),
            CatchUpPackage(artifact) => (artifact.height(), "catch_up_package.bin".to_string()),
        };
        // We group heights by directories to avoid running into any kind of unexpected
        // FS inode limitations. Each group directory will contain at most
        // `BACKUP_GROUP_SIZE` heights.
        let group_key = (height.get() / BACKUP_GROUP_SIZE) * BACKUP_GROUP_SIZE;
        let path_with_height = path.join(group_key.to_string()).join(height.to_string());
        (path_with_height, file_name)
    }
}

// Dumps a CryptoHash to a hex-encoded string.
pub(super) fn bytes_to_hex_str<T>(hash: &CryptoHashOf<T>) -> String {
    hash.clone()
        .get()
        .0
        .iter()
        .fold(String::new(), |mut hash, byte| {
            hash.push_str(&format!("{:X}", byte));
            hash
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_test_utilities::{consensus::fake::*, mock_time, types::ids::node_test_id};
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
                    ic_crypto::crypto_hash,
                    ic_types::consensus::dkg::Summary::fake().into(),
                ),
                Height::from(123),
                Rank(456),
                ValidationContext {
                    registry_version: RegistryVersion::from(99),
                    certified_height: Height::from(42),
                    time: mock_time(),
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
