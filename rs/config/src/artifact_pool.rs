use ic_types::Height;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Default capacity, in number of messages, for validated and unvalidated pools
const MAX_INGRESS_POOL_VALIDATED_CAPACITY: usize = 1024;
const MAX_INGRESS_POOL_UNVALIDATED_CAPACITY_PER_PEER: usize = 100_000_000;
const MAX_CONSENSUS_POOL_VALIDATED_CAPACITY: usize = 2048;
const MAX_CONSENSUS_POOL_UNVALIDATED_CAPACITY_PER_PEER: usize = 2048;
const PERSISTENT_POOL_VALIDATED_PURGE_INTERVAL: u64 = 5000;

/// External configuration for artifact pools meant to be used by replica's
/// config file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactPoolTomlConfig {
    /// The path in which to store the validated section of the consensus pool.
    pub consensus_pool_path: PathBuf,

    /// If the total entries in validated + unvalidated ingress pool exceeds
    /// this threshold, reject the user HTTP request. If this field is not
    /// specified, throttling would be disabled.
    pub ingress_pool_size_threshold: Option<usize>,

    /// Choice of persistent pool backend database. None means default choice,
    /// which at the moment is "lmdb".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consensus_pool_backend: Option<String>,

    /// Path to a folder with write permissions, for consensus artifact backup.
    /// If no path was provided, no backup will be saved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup: Option<BackupConfig>,
}

impl ArtifactPoolTomlConfig {
    /// Create a ArtifactPoolTomlConfig from a given path to the consensus pool.
    pub fn new(consensus_pool_path: PathBuf, backup: Option<BackupConfig>) -> Self {
        Self {
            consensus_pool_path,
            ingress_pool_size_threshold: None,
            consensus_pool_backend: Some("lmdb".to_string()),
            backup,
        }
    }
}

/// Configuration of the consensus artifact backup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupConfig {
    /// Path to a folder with write permissions, for consensus artifact backup.
    /// If no path was provided, no backup will be saved.
    pub spool_path: PathBuf,
    /// The maximum age backup artifacts can reach before purging.
    pub retention_time_secs: u64,
    /// Time interval between purges.
    pub purging_interval_secs: u64,
}

/// The configuration for the ingress and consensus artifact pools, both the
/// validated and unvalidated portions.
#[derive(Clone, Debug)]
pub struct ArtifactPoolConfig {
    /// The maximum size, in number of messages, of the validated section
    /// of the ingress pool.
    pub ingress_pool_validated_capacity: usize,
    /// The maximum size, in number of messages, of the unvalidated section
    /// of the ingress pool, per peer.
    pub ingress_pool_unvalidated_capacity_per_peer: usize,
    /// Threshold for ingress rate limiting. If this field is not
    /// specified, throttling would be disabled.
    pub ingress_pool_size_threshold: Option<usize>,
    /// The maximum size, in number of messages, of the unvalidated section
    /// of the artifact pool, per peer.
    pub consensus_pool_unvalidated_capacity_per_peer: usize,
    /// The maximum size, in number of messages, of the validated section
    /// of the artifact pool.
    pub consensus_pool_validated_capacity: usize,
    /// Choice of persistent pool backend
    pub persistent_pool_backend: PersistentPoolBackend,
    /// Whether the persistent pool should be opened as read-only
    pub persistent_pool_read_only: bool,
    /// Contains all parameters for the consensus artifact backup.
    pub backup_config: Option<BackupConfig>,
}

/// Choice of persistent pool database is either LMDB or RocksDB.
#[derive(Clone, Debug)]
pub enum PersistentPoolBackend {
    Lmdb(LMDBConfig),
    RocksDB(RocksDBConfig),
}

/// LMDB specific configuration
#[derive(Clone, Debug)]
pub struct LMDBConfig {
    /// The path at which the validated section of the persistent pool is
    /// stored.
    pub persistent_pool_validated_persistent_db_path: PathBuf,
}

/// RocksDB specific configuration
#[derive(Clone, Debug)]
pub struct RocksDBConfig {
    /// Whether the validated section on the artifact pool, which is persistent
    /// should skips fsync calls, for tests.
    ///
    /// NOTE: This nullifies all durability guarantees and thus should
    /// only be used in tests.
    pub persistent_pool_validated_skip_fsync_for_tests: bool,
    /// The path at which the validated section of the persistent pool is
    /// stored.
    pub persistent_pool_validated_persistent_db_path: PathBuf,
    /// Consensus pool is purged at a fixed interval.
    pub persistent_pool_validated_purge_interval: Height,
}

impl From<ArtifactPoolTomlConfig> for ArtifactPoolConfig {
    fn from(toml_config: ArtifactPoolTomlConfig) -> ArtifactPoolConfig {
        let backend = toml_config
            .consensus_pool_backend
            .unwrap_or_else(|| "lmdb".to_string());
        let persistent_pool_backend = match backend.as_str() {
            "lmdb" => PersistentPoolBackend::Lmdb(LMDBConfig {
                persistent_pool_validated_persistent_db_path: toml_config.consensus_pool_path,
            }),
            "rocksdb" => PersistentPoolBackend::RocksDB(RocksDBConfig {
                persistent_pool_validated_skip_fsync_for_tests: false,
                persistent_pool_validated_persistent_db_path: toml_config.consensus_pool_path,
                persistent_pool_validated_purge_interval: Height::from(
                    PERSISTENT_POOL_VALIDATED_PURGE_INTERVAL,
                ),
            }),
            _ => {
                panic!("Unsupported persistent_pool_backend: {}, must be either \"lmdb\" or \"rocksdb\".", backend);
            }
        };
        ArtifactPoolConfig {
            ingress_pool_validated_capacity: MAX_INGRESS_POOL_VALIDATED_CAPACITY,
            ingress_pool_unvalidated_capacity_per_peer:
                MAX_INGRESS_POOL_UNVALIDATED_CAPACITY_PER_PEER,
            ingress_pool_size_threshold: toml_config.ingress_pool_size_threshold,
            consensus_pool_unvalidated_capacity_per_peer: MAX_CONSENSUS_POOL_VALIDATED_CAPACITY,
            consensus_pool_validated_capacity: MAX_CONSENSUS_POOL_UNVALIDATED_CAPACITY_PER_PEER,
            persistent_pool_backend,
            persistent_pool_read_only: false,
            backup_config: toml_config.backup,
        }
    }
}

impl ArtifactPoolConfig {
    pub fn new(consensus_pool_path: PathBuf) -> ArtifactPoolConfig {
        Self::from(ArtifactPoolTomlConfig::new(consensus_pool_path, None))
    }

    /// Return the directory path to the persistent pool database.
    pub fn persistent_pool_db_path(&self) -> PathBuf {
        match &self.persistent_pool_backend {
            PersistentPoolBackend::Lmdb(config) => {
                config.persistent_pool_validated_persistent_db_path.clone()
            }
            PersistentPoolBackend::RocksDB(config) => {
                config.persistent_pool_validated_persistent_db_path.clone()
            }
        }
    }
}
