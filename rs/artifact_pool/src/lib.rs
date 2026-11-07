pub mod canister_http_pool;
pub mod certification_pool;
pub mod consensus_pool;
mod consensus_pool_cache;
pub mod dkg_pool;
mod height_index;
pub mod idkg_pool;
pub mod ingress_pool;
mod inmemory_pool;
mod metrics;
mod pool_common;
#[cfg(test)]
mod test_utils;

pub mod backup;
mod lmdb_iterator;
mod lmdb_pool;

// On macOS we have support for rocksdb in addition to lmdb as lmdb
// historically caused issues.

#[cfg(target_os = "macos")]
mod rocksdb_iterator;
#[cfg(target_os = "macos")]
mod rocksdb_pool;

use ic_config::artifact_pool::{ArtifactPoolConfig, PersistentPoolBackend};
use ic_interfaces::{consensus_pool::ValidatedArtifact, p2p::consensus::UnvalidatedArtifact};
use ic_logger::{ReplicaLogger, info};
use ic_types::{Height, ReplicaVersion, Time, consensus::certification::CertificationMessage};
use std::convert::TryFrom;
use std::fs;
use std::io::Write;
use std::path::Path;

/// Name of the directory of the (LMDB) certification pool within the persistent
/// pool directory.
///
/// Unlike the rest of the persistent pool, the certification pool is kept when the
/// replica version changes, so that certifications and shares created before an
/// upgrade remain available after it. Its artifacts are therefore protobuf-encoded.
/// Older replica versions stored bincode-encoded artifacts in `certification`
/// instead, which is deleted on the first replica version change like the rest of
/// the pool.
pub const CERTIFICATION_POOL_DIR: &str = "certification_v2";

pub fn get_replica_version<P: AsRef<Path>>(filepath: P) -> Option<ReplicaVersion> {
    std::fs::read_to_string(filepath)
        .ok()
        .and_then(|version_string| ReplicaVersion::try_from(version_string).ok())
}

pub fn set_replica_version<P: AsRef<Path>>(filepath: P, replica_version: &ReplicaVersion) {
    // Write the version file durably (fsync the file and its directory): if this file is
    // lost in a crash or power failure, the next boot treats the pool as incompatible and
    // deletes its contents.
    let filepath = filepath.as_ref();
    let mut file = fs::File::create(filepath).expect("Couldn't create the version file");
    file.write_all(String::from(replica_version).as_bytes())
        .expect("Couldn't write the version file");
    file.sync_all().expect("Couldn't sync the version file");
    if let Some(parent) = filepath.parent() {
        fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .expect("Couldn't sync the version file's directory");
    }
}

/// Check that the replica version of the pool matches that of this process. If it does
/// not, delete the contents of the old pool directory, except for the certification pool
/// (see [`CERTIFICATION_POOL_DIR`]), and create a new one.
///
/// Deleting the consensus pool loses the chain above the latest CUP: the subnet re-builds
/// it, not necessarily with the same blocks, so certifications above `cup_height` (the
/// height of the CUP this replica starts from) may not match the new chain's state hashes
/// and would make the state manager panic when delivered. They are therefore purged from
/// the kept certification pool whenever the rest of the pool is deleted.
pub fn ensure_persistent_pool_replica_version_compatibility(
    config: &ArtifactPoolConfig,
    replica_version: &ReplicaVersion,
    cup_height: Height,
    log: &ReplicaLogger,
) {
    let pool_path = config.persistent_pool_db_path();
    let mut replica_version_file_path = pool_path.clone();
    replica_version_file_path.push("replica_version");
    let pool_replica_version = get_replica_version(&replica_version_file_path);
    if pool_replica_version.as_ref() != Some(replica_version) {
        info!(
            log,
            "Persistent pool was written by replica version {:?} while this is replica \
             version {}: deleting the pool contents, except for the certification pool",
            pool_replica_version.as_ref().map(String::from),
            String::from(replica_version),
        );
        if pool_path.exists() {
            for entry in fs::read_dir(&pool_path).expect("Couldn't read the directory") {
                let entry = entry.expect("Couldn't read the metadata");
                if entry.file_name() == CERTIFICATION_POOL_DIR {
                    continue;
                }
                let path = entry.path();
                if path.is_dir() {
                    fs::remove_dir_all(path).expect("Couldn't remove the directory");
                } else {
                    fs::remove_file(path).expect("Couldn't remove the file");
                }
            }
        }
        if let PersistentPoolBackend::Lmdb(lmdb_config) = &config.persistent_pool_backend {
            let purged =
                lmdb_pool::PersistentHeightIndexedPool::<CertificationMessage>::new_certification_pool(
                    lmdb_config.clone(),
                    /*read_only=*/ false,
                    log.clone(),
                )
                .purge_above(cup_height);
            info!(
                log,
                "Purged {} certification artifacts above the CUP height {} from the \
                 certification pool",
                purged.len(),
                cup_height,
            );
        }
        // The RocksDB (macOS) certification pool lives in `certification`, which the loop
        // above deleted, so there is nothing to purge for that backend.
        std::fs::create_dir_all(&pool_path).expect("Couldn't create a directory");
        set_replica_version(replica_version_file_path, replica_version);
    }
}

/// A trait to get timestamp.
pub trait HasTimestamp {
    fn timestamp(&self) -> Time;
}

impl<T> HasTimestamp for ValidatedArtifact<T> {
    fn timestamp(&self) -> Time {
        self.timestamp
    }
}

impl<T> HasTimestamp for UnvalidatedArtifact<T> {
    fn timestamp(&self) -> Time {
        self.timestamp
    }
}

/// A trait similar to Into, but without its restrictions.
pub trait IntoInner<T>: AsRef<T> {
    fn into_inner(self) -> T;
}

impl<T> IntoInner<T> for ValidatedArtifact<T> {
    fn into_inner(self) -> T {
        self.msg
    }
}

impl<T> IntoInner<T> for UnvalidatedArtifact<T> {
    fn into_inner(self) -> T {
        self.message
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_logger::replica_logger::no_op_logger;
    use std::str::FromStr;

    #[test]
    fn test_ensure_persistent_pool_replica_version_compatibility() {
        let replica_version = ReplicaVersion::from_str("12344556").unwrap();
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|config| {
            ensure_persistent_pool_replica_version_compatibility(
                &config,
                &replica_version,
                Height::from(0),
                &no_op_logger(),
            );
            let mut replica_version_file_path = config.persistent_pool_db_path();
            replica_version_file_path.push("replica_version");

            // Ensure that a file was added indicating which replica version the
            // directory was made with.
            assert_eq!(
                replica_version,
                get_replica_version(&replica_version_file_path).unwrap()
            );
            let mut random_file_path = config.persistent_pool_db_path();
            random_file_path.push("random_file");
            std::fs::write(&random_file_path, "stuff").unwrap();

            ensure_persistent_pool_replica_version_compatibility(
                &config,
                &replica_version,
                Height::from(0),
                &no_op_logger(),
            );

            // Ensure that the directory was not deleted by checking for the file.
            assert_eq!(std::fs::read_to_string(&random_file_path).unwrap(), "stuff");

            set_replica_version(
                &replica_version_file_path,
                &ReplicaVersion::from_str("somerandomversion").unwrap(),
            );

            ensure_persistent_pool_replica_version_compatibility(
                &config,
                &replica_version,
                Height::from(0),
                &no_op_logger(),
            );

            // Now that the folder has a different replica version it should
            // have been deleted and created with the new replica version.
            assert!(std::fs::metadata(&random_file_path).is_err());
            random_file_path.pop();
            random_file_path.pop();

            for path in std::fs::read_dir(&random_file_path).unwrap() {
                println!("Name: {}", path.unwrap().path().display());
            }

            assert_eq!(
                replica_version,
                get_replica_version(replica_version_file_path).unwrap()
            );
        })
    }

    #[test]
    fn test_only_certification_pool_is_kept_across_replica_versions() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|config| {
            let pool_path = config.persistent_pool_db_path();
            ensure_persistent_pool_replica_version_compatibility(
                &config,
                &ReplicaVersion::from_str("old_version").unwrap(),
                Height::from(0),
                &no_op_logger(),
            );
            // `certification` is the (bincode-encoded) certification pool of older replica
            // versions.
            for dir in ["consensus", "certification"] {
                std::fs::create_dir_all(pool_path.join(dir)).unwrap();
                std::fs::write(pool_path.join(dir).join("data.mdb"), "stuff").unwrap();
            }
            // Create a real (empty) certification pool, since a replica version change
            // opens it to purge the certifications above the CUP height.
            let PersistentPoolBackend::Lmdb(lmdb_config) = &config.persistent_pool_backend else {
                panic!("This test requires the LMDB backend");
            };
            drop(
                lmdb_pool::PersistentHeightIndexedPool::<CertificationMessage>::new_certification_pool(
                    lmdb_config.clone(),
                    /*read_only=*/ false,
                    no_op_logger(),
                ),
            );

            ensure_persistent_pool_replica_version_compatibility(
                &config,
                &ReplicaVersion::from_str("new_version").unwrap(),
                Height::from(0),
                &no_op_logger(),
            );

            assert!(!pool_path.join("consensus").exists());
            assert!(!pool_path.join("certification").exists());
            assert!(
                pool_path
                    .join(CERTIFICATION_POOL_DIR)
                    .join("data.mdb")
                    .exists()
            );
        })
    }
}
