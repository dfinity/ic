//! Each subnet of a running IC specifies a replica version that the nodes on
//! that subnet are supposed to be running. This module contains utility
//! functions and structures used to specify replica versions in tests.
use ic_crypto_sha::Sha256;
use ic_types::ReplicaVersion;
use ic_utils::command::find_file_on_path;
use std::hash::Hash;
use url::Url;

#[derive(Debug, Clone, Hash)]
pub struct NodeSoftwareVersion {
    pub replica_version: ReplicaVersion,
    pub replica_url: Url,
    pub replica_hash: String,
    pub orchestrator_url: Url,
    pub orchestrator_hash: String,
}

impl NodeSoftwareVersion {
    /// In a system test environment, this constructor gathers the `current`
    /// binaries from the path and creates an `NodeSoftwareVersion`-object with
    /// the given replica version.
    ///
    /// The `current` version of replica is assumed to be the binaries named
    /// `replica` and `orchestrator` found on `$PATH`.
    ///
    /// # Panics
    ///
    /// This method panics if the current binaries cannot be found or the hash
    /// could not be dervied.
    pub fn system_test_current(replica_version: ReplicaVersion) -> Self {
        let (replica_url, replica_hash) =
            get_replica_url_and_hash().expect("Could not find replica on $PATH");
        let (orchestrator_url, orchestrator_hash) =
            get_orchestrator_url_and_hash().expect("Could not find orchestrator on $PATH");
        Self {
            replica_version,
            replica_url,
            replica_hash,
            orchestrator_url,
            orchestrator_hash,
        }
    }
}

/// Finds the replica on the path and returns a `file:///`-URL pointing to the found replica.
pub fn get_replica_url() -> Option<Url> {
    find_file_on_path("replica").map(|path| {
        Url::parse(&format!(
            "file://{}",
            path.as_path()
                .as_os_str()
                .to_str()
                .expect("Failed to obtain path string from PathBuf")
        ))
        .expect("Failed to parse URL")
    })
}

/// Returns a URL to orchestrator binary on path, and the sha256 value of the
/// data contained in the file.
pub fn get_orchestrator_url_and_hash() -> Option<(Url, String)> {
    get_binary_url_and_hash("orchestrator")
}

/// Returns a URL to replica binary on path, and the sha256 value of the data
/// contained in the file.
pub fn get_replica_url_and_hash() -> Option<(Url, String)> {
    get_binary_url_and_hash("replica")
}

/// Returns a URL to `bin` on path, and the sha256 value of the data contained
/// in the file.
pub fn get_binary_url_and_hash(bin: &str) -> Option<(Url, String)> {
    let replica = match find_file_on_path(bin) {
        Some(p) => p,
        None => return None,
    };

    let mut bin_file = std::fs::File::open(&replica)
        .unwrap_or_else(|err| panic!("Failed to open {:?}: {}", &replica, err));

    let mut hasher = Sha256::new();
    std::io::copy(&mut bin_file, &mut hasher)
        .unwrap_or_else(|err| panic!("Failed to compute hash of {:?}: {}", &bin_file, err));

    let hash = hex::encode(hasher.finish());

    let url = Url::parse(&format!(
        "file://{}",
        replica
            .as_path()
            .as_os_str()
            .to_str()
            .unwrap_or_else(|| panic!("Failed to obtain path string from PathBuf: {:?}", replica))
    ))
    .expect("Failed to construct URL from a file");

    Some((url, hash))
}
