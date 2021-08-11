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

use ic_interfaces::{
    consensus_pool::{ConsensusPool, HeightRange},
    time_source::TimeSource,
};
use ic_logger::{error, info, warn, ReplicaLogger};
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
use std::{fs, io::Write, path::PathBuf, sync::RwLock, thread, time::Duration};
use std::{io, path::Path};

#[allow(clippy::large_enum_variant)]
enum BackupArtifact {
    Finalization(Finalization),
    Notarization(Notarization),
    BlockProposal(BlockProposal),
    RandomBeacon(RandomBeacon),
    RandomTape(RandomTape),
    CatchUpPackage(CatchUpPackage),
}

struct Metrics {
    // Amount of I/O errors. Any number above 0 is critical.
    io_errors: IntCounter,
}

pub(super) struct Backup {
    // Path pointing to <backup_dir>/<subnet_id>/<replica_version>. It contains all artifacts
    // backed up by the current replica version.
    version_path: PathBuf,
    // Path containing all backups of all versions running on the current node.
    backup_path: PathBuf,
    // The timestamp of the last backup purge.
    time_of_last_purge: RwLock<Time>,
    // Thread handle of the thread executing the backup.
    pending_backup: RwLock<Option<thread::JoinHandle<()>>>,
    // Thread handle of the thread executing the purging.
    pending_purging: RwLock<Option<thread::JoinHandle<()>>>,
    // The maximum age backup artifacts can reach before purging.
    age_threshold_secs: Duration,
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
        metrics_registry: ic_metrics::MetricsRegistry,
        log: ReplicaLogger,
    ) -> Self {
        let backup = Self {
            backup_path,
            version_path: version_path.clone(),
            time_of_last_purge: RwLock::new(UNIX_EPOCH),
            pending_purging: Default::default(),
            pending_backup: Default::default(),
            age_threshold_secs,
            purge_interval_secs,
            metrics: Metrics {
                io_errors: metrics_registry
                    .int_counter("consensus_backup_io_errors", "The number of I/O errors happened during the consensus backup storing or purging."),
            },
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
        if let Err(err) = store_artifacts(artifacts, version_path) {
            error!(backup.log, "Backup storing failed: {:?}", err);
            backup.metrics.io_errors.inc();
        }
        backup
    }

    // Filters the new artifacts and asynchronously writes the relevant artifacts
    // to the disk.
    pub fn store(&self, time_source: &dyn TimeSource, artifacts: Vec<ConsensusMessage>) {
        // We block until the previous write has finished. This should never happen, as
        // writing of the artifacts should take less than one consensus round, otherwise
        // a full backup is infeasible.
        self.sync_backup();
        let path = self.version_path.clone();
        let log = self.log.clone();
        let io_errors = self.metrics.io_errors.clone();
        let handle = std::thread::spawn(move || {
            if let Err(err) = store_artifacts(artifacts, path) {
                error!(log, "Backup storing failed: {:?}", err);
                io_errors.inc();
            }
        });
        *self.pending_backup.write().unwrap() = Some(handle);

        // If we didn't purge within the last PURGE_INTERVAL, trigger a new purge.
        // This way we avoid a too frequent purging. We also block if the previous
        // purging has not finished yet, which is not expected with sufficiently
        // large PURGE_INTERVAL.
        let time_of_last_purge = *self.time_of_last_purge.read().unwrap();
        if time_source.get_relative_time() - time_of_last_purge > self.purge_interval_secs {
            self.sync_purging();
            // We purge all outdated sub-directories in the backup directory.
            let path = self.backup_path.clone();
            let threshold = self.age_threshold_secs;
            let log = self.log.clone();
            let io_errors = self.metrics.io_errors.clone();
            let handle = std::thread::spawn(move || {
                let start = std::time::Instant::now();
                if let Err(err) = purge(threshold, path, log.clone()) {
                    error!(log, "Backup purging failed: {:?}", err);
                    io_errors.inc();
                }
                info!(log, "Backup purging finished in {:?}", start.elapsed());
            });
            *self.pending_backup.write().unwrap() = Some(handle);
            *self.time_of_last_purge.write().unwrap() = time_source.get_relative_time();
        }
    }

    // Joins on the backup thread handle and blocks until the thread has finished.
    fn sync_backup(&self) {
        if let Some(handle) = self.pending_backup.write().unwrap().take() {
            if let Err(err) = handle.join() {
                error!(self.log, "Couldn't finish writing backup files: {:?}", err);
                self.metrics.io_errors.inc();
            }
        }
    }

    // Joins on the purging thread handle and blocks until the thread has finished.
    fn sync_purging(&self) {
        if let Some(handle) = self.pending_purging.write().unwrap().take() {
            if let Err(err) = handle.join() {
                error!(self.log, "Couldn't finish purging backup files: {:?}", err);
                self.metrics.io_errors.inc();
            }
        }
    }
}

// Write all backup files to the disk. For the sake of simplicity, we write all
// artifacts sequentially.
fn store_artifacts(artifacts: Vec<ConsensusMessage>, path: PathBuf) -> Result<(), io::Error> {
    use ConsensusMessage::*;
    artifacts
        .into_iter()
        .filter_map(|artifact| match artifact {
            Finalization(artifact) => Some(BackupArtifact::Finalization(artifact)),
            Notarization(artifact) => Some(BackupArtifact::Notarization(artifact)),
            BlockProposal(artifact) => Some(BackupArtifact::BlockProposal(artifact)),
            RandomTape(artifact) => Some(BackupArtifact::RandomTape(artifact)),
            RandomBeacon(artifact) => Some(BackupArtifact::RandomBeacon(artifact)),
            CatchUpPackage(artifact) => Some(BackupArtifact::CatchUpPackage(artifact)),
            // Do not replace by a `_` so that we evaluate at this place if we want to
            // backup a new artifact!
            RandomBeaconShare(_)
            | NotarizationShare(_)
            | FinalizationShare(_)
            | RandomTapeShare(_)
            | CatchUpPackageShare(_) => None,
        })
        .try_for_each(|artifact| artifact.write_to_disk(&path))
}

// Traverses the whole backup directory and finds all leaf directories
// (containing no other directories). Then it purges all leaves older than the
// specified retention time.
fn purge(threshold_secs: Duration, path: PathBuf, log: ReplicaLogger) -> Result<(), io::Error> {
    let mut leaves = Vec::new();
    get_leaves(&path, &mut leaves)?;
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
        self.sync_backup();
        self.sync_purging();
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
        let mut file = fs::File::create(&full_path)?;
        file.write_all(&self.serialize()?)
    }

    // Serializes the artifact to protobuf.
    fn serialize(&self) -> Result<Vec<u8>, io::Error> {
        let mut buf = Vec::new();
        use BackupArtifact::*;
        match self {
            Finalization(artifact) => pb::Finalization::from(artifact).encode(&mut buf),
            Notarization(artifact) => pb::Notarization::from(artifact).encode(&mut buf),
            BlockProposal(artifact) => pb::BlockProposal::from(artifact).encode(&mut buf),
            RandomTape(artifact) => pb::RandomTape::from(artifact).encode(&mut buf),
            RandomBeacon(artifact) => pb::RandomBeacon::from(artifact).encode(&mut buf),
            CatchUpPackage(artifact) => pb::CatchUpPackage::from(artifact).encode(&mut buf),
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
                    bytes_to_hex_str(&ic_crypto::crypto_hash(artifact)),
                ),
            ),
            Notarization(artifact) => (
                artifact.height(),
                format!(
                    "notarization_{}_{}.bin",
                    bytes_to_hex_str(&artifact.content.block),
                    bytes_to_hex_str(&ic_crypto::crypto_hash(artifact)),
                ),
            ),
            BlockProposal(artifact) => (
                artifact.height(),
                format!(
                    "block_proposal_{}_{}.bin",
                    bytes_to_hex_str(&artifact.content.get_hash()),
                    bytes_to_hex_str(&ic_crypto::crypto_hash(artifact)),
                ),
            ),
            RandomTape(artifact) => (artifact.height(), "random_tape.bin".to_string()),
            RandomBeacon(artifact) => (artifact.height(), "random_beacon.bin".to_string()),
            CatchUpPackage(artifact) => (artifact.height(), "catch_up_package.bin".to_string()),
        };
        // We group heights by directories to avoid running into any kind of unexpected
        // FS inode limitations. Each group directory will contain at most
        // `group_size` heights.
        let group_size = 10000;
        let group_key = (height.get() / group_size) * group_size;
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
