pub mod certification_pool;
pub mod consensus_pool;
mod consensus_pool_cache;
pub mod dkg_pool;
pub mod ecdsa_pool;
mod height_index;
pub mod ingress_pool;
mod inmemory_pool;
mod metrics;
mod peer_index;

mod backup;
mod lmdb_iterator;
mod lmdb_pool;
mod rocksdb_iterator;
mod rocksdb_pool;

use ic_types::ReplicaVersion;
use std::convert::TryFrom;
use std::fs;
use std::path::{Path, PathBuf};

pub fn get_replica_version<P: AsRef<Path>>(filepath: P) -> Option<ReplicaVersion> {
    std::fs::read_to_string(filepath)
        .ok()
        .and_then(|version_string| ReplicaVersion::try_from(version_string).ok())
}

pub fn set_replica_version<P: AsRef<Path>>(filepath: P, replica_version: &ReplicaVersion) {
    std::fs::write(filepath, String::from(replica_version).as_str()).unwrap();
}

/// Check that the replica version of the pool matches that of this process. If
/// it does not, delete the contents of the old pool directory and create a new
/// one.
pub fn ensure_persistent_pool_replica_version_compatibility(pool_path: PathBuf) {
    let mut replica_version_file_path = pool_path.clone();
    replica_version_file_path.push("replica_version");
    if get_replica_version(&replica_version_file_path) != Some(ReplicaVersion::default()) {
        if pool_path.exists() {
            for entry in fs::read_dir(&pool_path).expect("Couldn't read the directory") {
                let path = entry.expect("Couldn't read the metadata").path();
                if path.is_dir() {
                    fs::remove_dir_all(path).expect("Couldn't remove the directory");
                } else {
                    fs::remove_file(path).expect("Couldn't remove the file");
                }
            }
        }
        std::fs::create_dir_all(&pool_path).expect("Couldn't create a directory");
        set_replica_version(replica_version_file_path, &ReplicaVersion::default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryFrom;

    #[test]
    fn test_ensure_persistent_pool_replica_version_compatibility() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|config| {
            ensure_persistent_pool_replica_version_compatibility(config.persistent_pool_db_path());
            let mut replica_version_file_path = config.persistent_pool_db_path();
            replica_version_file_path.push("replica_version");

            // Ensure that a file was added indicating which replica version the
            // directory was made with.
            assert_eq!(
                ReplicaVersion::default(),
                get_replica_version(&replica_version_file_path).unwrap()
            );
            let mut random_file_path = config.persistent_pool_db_path();
            random_file_path.push("random_file");
            std::fs::write(&random_file_path, "stuff").unwrap();

            ensure_persistent_pool_replica_version_compatibility(config.persistent_pool_db_path());

            // Ensure that the directory was not deleted by checking for the file.
            assert_eq!(std::fs::read_to_string(&random_file_path).unwrap(), "stuff");

            set_replica_version(
                &replica_version_file_path,
                &ReplicaVersion::try_from("somerandomversion").unwrap(),
            );

            ensure_persistent_pool_replica_version_compatibility(config.persistent_pool_db_path());

            // Now that the folder has a different replica version it should
            // have been deleted and created with the new replica version.
            assert!(std::fs::metadata(&random_file_path).is_err());
            random_file_path.pop();
            random_file_path.pop();

            for path in std::fs::read_dir(&random_file_path).unwrap() {
                println!("Name: {}", path.unwrap().path().display());
            }

            assert_eq!(
                ReplicaVersion::default(),
                get_replica_version(replica_version_file_path).unwrap()
            );
        })
    }
}
