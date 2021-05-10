use crate::error::{ReleaseError, ReleaseResult};
use flate2::Compression;
use flate2::{read::GzDecoder, write::GzEncoder};
use ic_crypto_sha256::Sha256;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tar::{Archive, Builder};

pub const REPLICA_KEY: &str = "replica";
pub const NODEMANAGER_KEY: &str = "nodemanager";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReleaseIdentifier(pub [u8; 32]);

impl std::fmt::Display for ReleaseIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

/// The content of a release is defined by a set of named octet-streams:
///
/// { (name1, bytes), (name2, bytes), ... }
///
/// where the names are unique. The names are the field names on this struct.
/// Hence, they do not necessarily correspond to the filename in the given
/// paths. This is important when deciding how to hash/identify a release.
#[derive(Debug)]
pub struct ReleaseContent {
    entries: BTreeMap<String, Value>,
}

impl Default for ReleaseContent {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }
}

#[derive(Debug)]
enum Value {
    File(PathBuf),
    #[allow(dead_code)]
    Bytes(Vec<u8>),
}

impl Value {
    fn hash(&self) -> ReleaseResult<[u8; 32]> {
        match self {
            Value::File(path) => {
                let content = fs::read(path.as_path())
                    .map_err(|e| ReleaseError::file_open_error(path.as_path(), e))?;
                Ok(Sha256::hash(&content))
            }
            Value::Bytes(data) => Ok(Sha256::hash(data.as_slice())),
        }
    }
}

/// Try to convert a path to a directory containing only (!) `ReleaseContent`
/// files into a `ReleaseContent`
impl TryFrom<&Path> for ReleaseContent {
    type Error = ReleaseError;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        let map_to_err = |e| ReleaseError::release_directory_error(path, e);
        if path.is_dir() {
            let mut entries: BTreeMap<String, Value> = BTreeMap::new();
            for dir_entry in fs::read_dir(path).map_err(map_to_err)? {
                let dir_entry = dir_entry.map_err(map_to_err)?.path();
                if !dir_entry.is_dir() {
                    let key = match dir_entry.as_path().file_name().and_then(|v| v.to_str()) {
                        Some(v) => v.to_string(),
                        None => return Err(ReleaseError::invalid_file_name(dir_entry)),
                    };
                    entries.insert(key, Value::File(dir_entry));
                }
            }
            let rel_content = ReleaseContent::from_entries(entries);
            rel_content.validate()?;
            Ok(rel_content)
        } else {
            Err(ReleaseError::invalid_release_directory(path))
        }
    }
}

impl ReleaseContent {
    pub fn from_paths<P: AsRef<Path>>(replica_binary: P, nodemanager_binary: P) -> Self {
        let mut entries = BTreeMap::default();
        entries.insert(
            REPLICA_KEY.to_string(),
            Value::File(PathBuf::from(replica_binary.as_ref())),
        );
        entries.insert(
            NODEMANAGER_KEY.to_string(),
            Value::File(PathBuf::from(nodemanager_binary.as_ref())),
        );
        Self { entries }
    }

    fn from_entries(entries: BTreeMap<String, Value>) -> Self {
        Self { entries }
    }

    pub fn add_entry(&mut self, key: &str, path: PathBuf) {
        self.entries.remove(key);
        self.entries.insert(key.into(), Value::File(path));
    }

    pub fn pack<P: AsRef<Path>>(&self, target_file: P) -> ReleaseResult<ReleasePackage> {
        let mut ar = Builder::new(GzEncoder::new(vec![], Compression::fast()));

        for (key, value) in self.entries.iter() {
            match value {
                Value::File(path) => ar
                    .append_path_with_name(path.as_path(), key)
                    .map_err(|e| ReleaseError::tar_error(target_file.as_ref(), e))?,
                Value::Bytes(data) => {
                    let mut header = tar::Header::new_gnu();
                    header.set_size(data.len() as u64);
                    header.set_cksum();
                    ar.append_data(&mut header, key, data.as_slice())
                        .map_err(|e| ReleaseError::tar_error(target_file.as_ref(), e))?;
                }
            }
        }

        let gz_stream = ar
            .into_inner()
            .map_err(|e| ReleaseError::tar_finish_error(target_file.as_ref(), e))?;
        let compressed_bytes = gz_stream.finish().map_err(ReleaseError::gz_error)?;
        let mut out_file = File::create(target_file.as_ref())
            .map_err(|e| ReleaseError::file_open_error(target_file.as_ref(), e))?;
        out_file
            .write_all(&compressed_bytes)
            .map_err(|e| ReleaseError::write_error(target_file.as_ref(), e))?;
        Ok(ReleasePackage::from_file(target_file.as_ref()))
    }

    /// Provide rudimentary validation of the provided files. E.g.,
    ///
    /// * All files exist
    /// * All paths are different
    pub fn validate(&self) -> ReleaseResult<()> {
        let paths = self
            .entries
            .values()
            .filter_map(|v| match v {
                Value::File(p) => Some(p.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();

        // all files exist
        if let Some(path) = paths.iter().find(|p| !p.exists()) {
            return Err(ReleaseError::file_not_found(path));
        }

        // all paths are unique
        let unique_paths: BTreeSet<_> = paths.iter().collect();
        if unique_paths.len() != paths.len() {
            return Err(ReleaseError::NonUniquePaths);
        }

        Ok(())
    }

    /// H(
    ///   concat( "\x0Aic-release",
    ///   sort
    ///      [ H(key_1) · H(value_1)
    ///      , H(key_2) · H(value_2)
    ///      , ...
    ///      ]
    ///   )
    /// )
    pub fn get_release_identifier(&self) -> ReleaseResult<ReleaseIdentifier> {
        self.validate()?;

        let mut hash = Sha256::new();
        // [length-of-domain-sep-as-byte] || domain separator
        hash.write(b"\x0Aic-release");

        let mut field_hashes: Vec<Vec<u8>> = vec![];
        for (key, value) in self.entries.iter() {
            // H(field_name) · H(field_data)
            let mut v: Vec<u8> = vec![];
            v.extend(&Sha256::hash(key.as_bytes()));
            v.extend(&value.hash()?);
            field_hashes.push(v);
        }
        field_hashes.sort();

        for field_hash in field_hashes {
            hash.write(field_hash.as_slice());
        }

        Ok(ReleaseIdentifier(hash.finish()))
    }

    /// Return a path to the file associated with the given key, if this path
    /// exists
    pub fn get_file_by_key(&self, key: &str) -> ReleaseResult<PathBuf> {
        self.entries
            .get(key)
            .and_then(|value| match value {
                Value::File(path) => Some(path.clone()),
                _ => None,
            })
            .ok_or_else(|| ReleaseError::KeyMissing(key.into()))
    }

    /// Return a path to the node manager binary, if this path exists
    pub fn get_node_manager_binary(&self) -> ReleaseResult<PathBuf> {
        self.get_file_by_key(NODEMANAGER_KEY)
    }

    /// Return the hash of the node manager, if it exists in the release package
    pub fn get_node_manager_hash(&self) -> ReleaseResult<[u8; 32]> {
        self.entries
            .get(NODEMANAGER_KEY)
            .map(|x| x.hash())
            .ok_or_else(|| ReleaseError::KeyMissing(NODEMANAGER_KEY.to_string()))?
    }

    /// Return a path to the replica binary, if this path exists
    pub fn get_replica_binary(&self) -> ReleaseResult<PathBuf> {
        self.get_file_by_key(REPLICA_KEY)
    }
}

/// A release package is a file containing the release content.
pub struct ReleasePackage {
    #[allow(dead_code)]
    release_file: PathBuf,
}

impl ReleasePackage {
    pub fn from_file<P: AsRef<Path>>(release_file: P) -> Self {
        Self {
            release_file: PathBuf::from(release_file.as_ref()),
        }
    }

    pub fn unpack_in<P: AsRef<Path>>(&self, target_dir: P) -> ReleaseResult<ReleaseContent> {
        let map_to_untar_error = |e| ReleaseError::untar_error(self.release_file.as_path(), e);

        let tar_gz_file = File::open(self.release_file.as_path())
            .map_err(|e| ReleaseError::file_open_error(self.release_file.as_path(), e))?;

        let tar = GzDecoder::new(tar_gz_file);
        let mut archive = Archive::new(tar);

        let mut entries: BTreeMap<String, Value> = Default::default();
        let archive_entries = archive.entries().map_err(map_to_untar_error)?;
        for entry in archive_entries {
            let mut entry = entry.map_err(map_to_untar_error)?;
            entry
                .unpack_in(target_dir.as_ref())
                .map_err(map_to_untar_error)?;
            let key = entry.path().map_err(map_to_untar_error)?.into_owned();
            let entry_target_path = PathBuf::from(target_dir.as_ref()).join(key.as_path());

            // Set read and execute (but not write) permissions on the entry file
            fs::set_permissions(&entry_target_path, fs::Permissions::from_mode(0o555))
                .map_err(|e| ReleaseError::file_set_permissions_error(&entry_target_path, e))?;

            let key = key
                .to_str()
                .expect("could not convert to string")
                .to_string();
            entries.insert(key, Value::File(entry_target_path));
        }

        Ok(ReleaseContent::from_entries(entries))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use assert_matches::assert_matches;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    #[test]
    fn roundtrip_succeeds() {
        let replica_file = random_file();
        let nodemanager_file = random_file();

        let release = ReleaseContent::from_paths(replica_file.path(), nodemanager_file.path());

        let release_ident = release.get_release_identifier().unwrap();

        let target_file = NamedTempFile::new().unwrap();
        let release_pack = release.pack(target_file.path()).unwrap();

        let temp_dir = TempDir::new().unwrap();
        let release = release_pack.unpack_in(temp_dir.path()).unwrap();
        assert!(release.validate().is_ok());
        assert_eq!(release_ident, release.get_release_identifier().unwrap());
    }

    // generate a file with random content, size 100kb..150kb
    fn random_file() -> NamedTempFile {
        let size: usize = 100 * 1024 + rand::random::<usize>() % (50 * 1024);
        let mut buf: Vec<u8> = vec![0; size];

        OsRng.fill_bytes(&mut buf);

        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&buf).unwrap();

        f
    }

    #[test]
    fn providing_same_file_twice_failes() {
        let replica_file = random_file();

        let release = ReleaseContent::from_paths(replica_file.path(), replica_file.path());

        assert_matches!(release.validate(), Err(ReleaseError::NonUniquePaths));
    }

    #[test]
    fn nonexistent_file_failes() {
        let replica_file = random_file();
        let nodemanager_file = {
            // file is dropped and deleted in this context
            let f = random_file();
            PathBuf::from(f.path())
        };

        let release = ReleaseContent::from_paths(replica_file.path(), &nodemanager_file);

        assert_matches!(release.validate(), Err(ReleaseError::FileNotFound(_)));
    }

    #[test]
    fn round_trip_from_release_directory() {
        let replica_file = random_file();
        let nodemanager_file = random_file();

        let release = ReleaseContent::from_paths(replica_file.path(), nodemanager_file.path());

        let release_ident = release.get_release_identifier().unwrap();

        let target_file = NamedTempFile::new().unwrap();
        let release_pack = release.pack(target_file.path()).unwrap();

        let temp_dir = TempDir::new().unwrap();
        let _ = release_pack.unpack_in(temp_dir.path()).unwrap();
        let release = ReleaseContent::try_from(temp_dir.as_ref()).unwrap();
        assert_eq!(release.get_release_identifier().unwrap(), release_ident);
    }
}
