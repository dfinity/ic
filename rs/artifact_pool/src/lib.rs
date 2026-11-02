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

use ic_interfaces::{consensus_pool::ValidatedArtifact, p2p::consensus::UnvalidatedArtifact};
use ic_types::{ReplicaVersion, Time};
use std::convert::TryFrom;
use std::fs;
use std::path::{Path, PathBuf};

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
    std::fs::write(filepath, String::from(replica_version).as_str()).unwrap();
}

/// Check that the replica version of the pool matches that of this process. If
/// it does not, delete the contents of the old pool directory, except for the
/// certification pool (see [`CERTIFICATION_POOL_DIR`]), and create a new one.
pub fn ensure_persistent_pool_replica_version_compatibility(
    pool_path: PathBuf,
    replica_version: &ReplicaVersion,
) {
    let mut replica_version_file_path = pool_path.clone();
    replica_version_file_path.push("replica_version");
    if get_replica_version(&replica_version_file_path).as_ref() != Some(replica_version) {
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
    use std::str::FromStr;

    #[test]
    fn test_ensure_persistent_pool_replica_version_compatibility() {
        let replica_version = ReplicaVersion::from_str("12344556").unwrap();
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|config| {
            ensure_persistent_pool_replica_version_compatibility(
                config.persistent_pool_db_path(),
                &replica_version,
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
                config.persistent_pool_db_path(),
                &replica_version,
            );

            // Ensure that the directory was not deleted by checking for the file.
            assert_eq!(std::fs::read_to_string(&random_file_path).unwrap(), "stuff");

            set_replica_version(
                &replica_version_file_path,
                &ReplicaVersion::from_str("somerandomversion").unwrap(),
            );

            ensure_persistent_pool_replica_version_compatibility(
                config.persistent_pool_db_path(),
                &replica_version,
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
                pool_path.clone(),
                &ReplicaVersion::from_str("old_version").unwrap(),
            );
            // `certification` is the (bincode-encoded) certification pool of older replica
            // versions.
            for dir in ["consensus", "certification", CERTIFICATION_POOL_DIR] {
                std::fs::create_dir_all(pool_path.join(dir)).unwrap();
                std::fs::write(pool_path.join(dir).join("data.mdb"), "stuff").unwrap();
            }

            ensure_persistent_pool_replica_version_compatibility(
                pool_path.clone(),
                &ReplicaVersion::from_str("new_version").unwrap(),
            );

            assert!(!pool_path.join("consensus").exists());
            assert!(!pool_path.join("certification").exists());
            assert_eq!(
                std::fs::read_to_string(pool_path.join(CERTIFICATION_POOL_DIR).join("data.mdb"))
                    .unwrap(),
                "stuff"
            );
        })
    }
}
