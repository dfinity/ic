//! Filesystem-backed secret key store
use crate::canister_threshold::IDKG_MEGA_SCOPE;
use crate::key_id::KeyId;
use crate::secret_key_store::{
    Scope, SecretKeyStore, SecretKeyStoreInsertionError, SecretKeyStoreWriteError,
};
use crate::types::CspSecretKey;
use hex::{FromHex, ToHex};
use ic_config::crypto::CryptoConfig;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_logger::{ReplicaLogger, debug, info, replica_logger::no_op_logger, warn};
use prost::Message;
use std::collections::HashMap;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;

#[cfg(test)]
mod tests;

const CURRENT_SKS_VERSION: u32 = 3;

fn key_id_from_hex(key_id_hex: &str) -> KeyId {
    KeyId::from_hex(key_id_hex).unwrap_or_else(|_| panic!("Error parsing hex KeyId {key_id_hex}"))
}

/// The secret key store protobuf definitions
// Include the prost-build generated registry protos.
#[allow(clippy::all)]
#[path = "../gen/ic.crypto.v1.rs"]
pub mod pb;

type SecretKeys = HashMap<KeyId, (CspSecretKey, Option<Scope>)>;

/// A secret key store that persists data to the filesystem, using protobufs for
/// serialization
pub struct ProtoSecretKeyStore {
    proto_file: PathBuf,
    old_proto_file_to_zeroize: PathBuf,
    keys: SecretKeys,
    logger: ReplicaLogger,
    metrics: Arc<CryptoMetrics>,
}

#[derive(Debug, Error)]
enum CleanupError {
    #[error(
        "error determining the existence of the old secret key store file '{old_sks_file}': {source:?}"
    )]
    OldFileExistenceDetermination {
        old_sks_file: String,
        #[source]
        source: std::io::Error,
    },
    #[error("error determining the existence of the current file '{current_sks_file}': {source:?}")]
    CurrentFileExistenceDetermination {
        current_sks_file: String,
        #[source]
        source: std::io::Error,
    },
    #[error("error removing old secret key store file {old_sks_file}: {source:?}")]
    OldFileRemoval {
        old_sks_file: String,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "error determining if secret key store file '{current_sks_file}' and old secret key store '{old_sks_file}' are the same file: {source:?}"
    )]
    InodesComparison {
        old_sks_file: String,
        current_sks_file: String,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "inconsistent state - the old file '{old_sks_file}' exists but the current file '{current_sks_file}' does not"
    )]
    OldFileExistsButCurrentFileDoesNot {
        old_sks_file: String,
        current_sks_file: String,
    },
    #[error("error overwriting the old file: {0:?}")]
    OldFileOverwriting(#[source] std::io::Error),
    #[error("error getting the metadata of the old file: {0:?}")]
    OldFileMetadataRetrieval(#[source] std::io::Error),
    #[error("error opening file for writing: {0:?}")]
    OpeningFileForWriting(#[source] std::io::Error),
    #[error(
        "error creating hard link to existing file (original: '{original}', link: '{link}'): {source:?}"
    )]
    HardLinkCreation {
        original: String,
        link: String,
        #[source]
        source: std::io::Error,
    },
}

impl ProtoSecretKeyStore {
    /// Creates a `ProtoSecretKeyStore` instance backed by a file. To access the secret keys
    /// generated as part of previous invocations, it is assumed that the values provided for `dir`
    /// and `file_name` are the same as in previous invocations. If different values for `dir`
    /// and/or `file_name` are provided, cleanup of previously failed zeroizations of old secret
    /// key store instances will not be performed correctly. `dir` shall point to a directory that
    /// the process has read and write access to, and `file_name` shall point to an existing
    /// regular file (e.g., not a symbolic link) that the process also has access to, or the name
    /// of the file to be created, if one does not yet exist.
    ///
    /// # Panics
    ///  - If the crypto root directory does not have the required permissions
    ///  - If the secret key store file is not a POSIX regular file
    pub fn open(
        dir: &Path,
        file_name: &str,
        logger: Option<ReplicaLogger>,
        metrics: Arc<CryptoMetrics>,
    ) -> Self {
        CryptoConfig::check_dir_has_required_permissions(dir)
            .expect("wrong crypto root permissions");
        let proto_file = dir.join(file_name);
        if let Ok(true) = proto_file.try_exists() {
            Self::check_proto_file_is_regular_file_or_panic(&proto_file);
        }
        let old_proto_file_to_zeroize = dir.join(format!("{file_name}.old"));
        let secret_keys = Self::sks_data_from_disk_or_new(&proto_file);
        let logger = logger.unwrap_or_else(no_op_logger);
        let sks = ProtoSecretKeyStore {
            proto_file,
            old_proto_file_to_zeroize,
            keys: secret_keys,
            logger,
            metrics,
        };
        sks.log_cleanup_errors_and_observe_metrics(sks.clean_up_old_sks());
        sks
    }

    /// Returns the path to the protobuf file storing the keys.
    pub fn proto_file_path(&self) -> &Path {
        self.proto_file.as_path()
    }

    fn clean_up_old_sks(&self) -> Result<(), Vec<CleanupError>> {
        match self.old_proto_file_to_zeroize.try_exists() {
            Ok(exists) => {
                if !exists {
                    return Ok(());
                }
            }
            Err(err) => {
                return Err(vec![CleanupError::OldFileExistenceDetermination {
                    old_sks_file: self.old_proto_file_to_zeroize.to_string_lossy().to_string(),
                    source: err,
                }]);
            }
        }
        let sks_exists = self.proto_file.try_exists().map_err(|err| {
            vec![CleanupError::CurrentFileExistenceDetermination {
                current_sks_file: self.proto_file.to_string_lossy().to_string(),
                source: err,
            }]
        })?;

        if !sks_exists {
            let mut cleanup_errors =
                overwrite_file_with_zeroes_and_delete_if_it_exists(&self.old_proto_file_to_zeroize)
                    .map_or_else(|err| err, |()| vec![]);
            cleanup_errors.push(CleanupError::OldFileExistsButCurrentFileDoesNot {
                old_sks_file: self.old_proto_file_to_zeroize.to_string_lossy().to_string(),
                current_sks_file: self.proto_file.to_string_lossy().to_string(),
            });
            return Err(cleanup_errors);
        }

        let are_same_file = ic_sys::fs::are_hard_links_to_the_same_inode(
            &self.proto_file,
            &self.old_proto_file_to_zeroize,
        )
        .map_err(|err| {
            vec![CleanupError::InodesComparison {
                old_sks_file: self.old_proto_file_to_zeroize.to_string_lossy().to_string(),
                current_sks_file: self.proto_file.to_string_lossy().to_string(),
                source: err,
            }]
        })?;
        if are_same_file {
            ic_sys::fs::remove_file(&self.old_proto_file_to_zeroize).map_err(|err| {
                vec![CleanupError::OldFileRemoval {
                    old_sks_file: self.old_proto_file_to_zeroize.to_string_lossy().to_string(),
                    source: err,
                }]
            })
        } else {
            overwrite_file_with_zeroes_and_delete_if_it_exists(&self.old_proto_file_to_zeroize)
        }
    }

    fn log_cleanup_errors_and_observe_metrics(
        &self,
        cleanup_result: Result<(), Vec<CleanupError>>,
    ) {
        if let Err(cleanup_error) = cleanup_result {
            warn!(
                self.logger,
                "error(s) cleaning up old secret key store file: [{}]",
                cleanup_error
                    .iter()
                    .map(|e| format!("{e}"))
                    .collect::<Vec<String>>()
                    .join(", ")
            );
            self.metrics
                .observe_secret_key_store_cleanup_error(cleanup_error.len() as u64);
        }
    }

    /// Writes the secret keys to disk, and performs cleanup (zeroization and removal) of the old
    /// secret key store file. Note that the cleanup is best-effort. Any errors encountered during
    /// cleanup are collected internally in the function, and a metric is observed. Cleanup errors
    /// are not returned, but if an error occurs while writing the updated secret key store to disk,
    /// that is returned.
    fn write_secret_keys_to_disk_and_cleanup_old_file(
        &self,
        secret_keys: &SecretKeys,
    ) -> Result<(), SecretKeyStoreWriteError> {
        let mut cleanup_result = self.try_create_hard_link_to_existing_file();
        // Write the new keystore to a new file and atomically replace the existing keystore.
        // The previously created hard link still points to the old keystore file.
        let write_result = self.write_secret_keys_to_disk(secret_keys);
        if write_result.is_ok() {
            // Use the previously created hard link to zeroize and delete the old keystore file.
            let overwrite_result =
                overwrite_file_with_zeroes_and_delete_if_it_exists(&self.old_proto_file_to_zeroize);
            cleanup_result = combine_cleanup_results(cleanup_result, overwrite_result);
        };
        self.log_cleanup_errors_and_observe_metrics(cleanup_result);
        write_result
    }

    fn try_create_hard_link_to_existing_file(&self) -> Result<(), Vec<CleanupError>> {
        match self.proto_file.try_exists() {
            Ok(exists) => {
                if exists {
                    // Create a hard link to the existing keystore, so that we maintain a handle to
                    // it, which can later be used to zeroize and delete the old keystore.
                    if let Err(err) = ic_sys::fs::create_hard_link_to_existing_file(
                        &self.proto_file,
                        &self.old_proto_file_to_zeroize,
                    ) {
                        Err(vec![CleanupError::HardLinkCreation {
                            original: self.proto_file.to_string_lossy().to_string(),
                            link: self.old_proto_file_to_zeroize.to_string_lossy().to_string(),
                            source: err,
                        }])
                    } else {
                        Ok(())
                    }
                } else {
                    Ok(())
                }
            }
            Err(err) => Err(vec![CleanupError::CurrentFileExistenceDetermination {
                current_sks_file: self.proto_file.to_string_lossy().to_string(),
                source: err,
            }]),
        }
    }

    fn write_secret_keys_to_disk(
        &self,
        secret_keys: &SecretKeys,
    ) -> Result<(), SecretKeyStoreWriteError> {
        let sks_proto = ProtoSecretKeyStore::secret_keys_to_sks_proto(secret_keys)?;
        match ic_sys::fs::write_protobuf_using_tmp_file(&self.proto_file, &sks_proto) {
            Ok(()) => {
                debug!(
                    self.logger,
                    "Secret key store written to {:?}", self.proto_file
                );
                Ok(())
            }
            Err(e) => Err(SecretKeyStoreWriteError::TransientError(format!(
                "Secret key store internal error writing protobuf using tmp file: {e}"
            ))),
        }
    }

    fn check_proto_file_is_regular_file_or_panic(proto_file: &PathBuf) {
        if !ic_sys::fs::is_regular_file(&proto_file)
            .expect("error checking if secret key store is a regular file")
        {
            panic!(
                "secret key store {} is not a regular file",
                proto_file.to_string_lossy()
            );
        }
    }

    fn sks_data_from_disk_or_new(sks_data_file: &Path) -> SecretKeys {
        let proto_file = match fs::read(sks_data_file) {
            Ok(data) => {
                let sks_pb = pb::SecretKeyStore::decode(&*data).unwrap_or_else(
                    |_ignored_so_that_no_data_is_leaked| panic!("error parsing SKS protobuf data"),
                );
                let keys = ProtoSecretKeyStore::migrate_to_current_version(sks_pb);
                Some(keys)
            }
            Err(err) => {
                if err.kind() == ErrorKind::NotFound {
                    None
                } else {
                    panic!("Error reading SKS data: {err}")
                }
            }
        };
        proto_file.unwrap_or_default()
    }

    fn migrate_to_current_version(sks_proto: pb::SecretKeyStore) -> SecretKeys {
        match sks_proto.version {
            CURRENT_SKS_VERSION => ProtoSecretKeyStore::sks_proto_to_secret_keys(&sks_proto),
            2 => {
                let secret_keys_from_disk =
                    ProtoSecretKeyStore::sks_proto_to_secret_keys(&sks_proto);
                Self::migrate_sks_from_v2_to_v3(secret_keys_from_disk)
            }
            _ => panic!(
                "Unsupported SecretKeyStore-proto version: {}",
                sks_proto.version
            ),
        }
    }

    fn migrate_sks_from_v2_to_v3(existing_secret_keys: SecretKeys) -> SecretKeys {
        let mut migrated_secret_keys = SecretKeys::new();
        for (key_id, (csp_key, scope)) in existing_secret_keys.into_iter() {
            let migrated_scope = match &csp_key {
                CspSecretKey::MEGaEncryptionK256(_) => Some(IDKG_MEGA_SCOPE),
                _ => scope,
            };
            migrated_secret_keys.insert(key_id, (csp_key, migrated_scope));
        }
        migrated_secret_keys
    }

    fn parse_csp_secret_key(key_bytes: &[u8], key_id: &KeyId) -> CspSecretKey {
        serde_cbor::from_slice(key_bytes).unwrap_or_else(|_ignored_so_that_no_data_is_leaked| {
            panic!("Error deserializing key with ID {key_id}")
        })
    }

    fn parse_scope(scope_proto: &str) -> Option<Scope> {
        if scope_proto.is_empty() {
            None
        } else {
            Some(
                Scope::from_str(scope_proto)
                    .unwrap_or_else(|_| panic!("Unknown scope: {scope_proto}")),
            )
        }
    }

    fn sks_proto_to_secret_keys(sks_proto: &pb::SecretKeyStore) -> SecretKeys {
        Self::ensure_version_is_supported(sks_proto.version);
        let mut secret_keys = SecretKeys::new();
        for (key_id_hex, sk_proto) in sks_proto.key_id_to_secret_key_v1.iter() {
            let key_id = key_id_from_hex(key_id_hex);
            let csp_key = Self::parse_csp_secret_key(&sk_proto.csp_secret_key, &key_id);
            let maybe_scope = Self::parse_scope(&sk_proto.scope);
            secret_keys.insert(key_id, (csp_key, maybe_scope));
        }
        secret_keys
    }

    fn ensure_version_is_supported(version: u32) {
        let supported_versions = [1, 2, CURRENT_SKS_VERSION];
        if !supported_versions.contains(&version) {
            panic!("Unexpected SecretKeyStore-proto version: {version}")
        }
    }

    fn secret_keys_to_sks_proto(
        secret_keys: &SecretKeys,
    ) -> Result<pb::SecretKeyStore, SecretKeyStoreWriteError> {
        let mut sks_proto = pb::SecretKeyStore {
            version: CURRENT_SKS_VERSION,
            ..Default::default()
        };
        for (key_id, (csp_key, maybe_scope)) in secret_keys {
            let key_id_hex = key_id.encode_hex();
            let key_as_cbor =
                serde_cbor::to_vec(&csp_key).map_err(|_ignored_so_that_no_data_is_leaked| {
                    SecretKeyStoreWriteError::SerializationError(format!(
                        "Error serializing key with ID {key_id}"
                    ))
                })?;
            let sk_pb = match maybe_scope {
                Some(scope) => pb::SecretKeyV1 {
                    csp_secret_key: key_as_cbor,
                    scope: String::from(scope),
                },
                None => pb::SecretKeyV1 {
                    csp_secret_key: key_as_cbor,
                    scope: String::from(""),
                },
            };
            sks_proto.key_id_to_secret_key_v1.insert(key_id_hex, sk_pb);
        }
        Ok(sks_proto)
    }
}

impl SecretKeyStore for ProtoSecretKeyStore {
    fn insert(
        &mut self,
        id: KeyId,
        key: CspSecretKey,
        scope: Option<Scope>,
    ) -> Result<(), SecretKeyStoreInsertionError> {
        match self.keys.get(&id) {
            Some(_) => Err(SecretKeyStoreInsertionError::DuplicateKeyId(id)),
            None => {
                self.keys.insert(id, (key, scope));
                self.write_secret_keys_to_disk_and_cleanup_old_file(&self.keys)?;
                debug!(self.logger, "Inserted new secret key {}", id);
                Ok(())
            }
        }
    }

    fn insert_or_replace(
        &mut self,
        id: KeyId,
        key: CspSecretKey,
        scope: Option<Scope>,
    ) -> Result<(), SecretKeyStoreWriteError> {
        let previous_key = self.keys.insert(id, (key, scope));
        self.write_secret_keys_to_disk_and_cleanup_old_file(&self.keys)?;
        match previous_key {
            None => debug!(self.logger, "Inserted new secret key {}", id),
            Some(_) => debug!(self.logger, "Replaced existing secret key {}", id),
        };
        Ok(())
    }

    fn get(&self, id: &KeyId) -> Option<CspSecretKey> {
        self.keys.get(id).map(|(csp_key, _)| csp_key.to_owned())
    }

    fn contains(&self, id: &KeyId) -> bool {
        self.get(id).is_some()
    }

    fn remove(&mut self, id: &KeyId) -> Result<bool, SecretKeyStoreWriteError> {
        match self.keys.get(id) {
            Some(_) => {
                self.keys.remove(id);
                self.write_secret_keys_to_disk_and_cleanup_old_file(&self.keys)?;
                debug!(self.logger, "Removed secret key {}", id);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn retain<F>(&mut self, filter: F, scope: Scope) -> Result<(), SecretKeyStoreWriteError>
    where
        F: Fn(&KeyId, &CspSecretKey) -> bool,
    {
        let mut all_keys = SecretKeys::new();
        core::mem::swap(&mut all_keys, &mut self.keys);
        let orig_keys_count = all_keys.len();
        for (key_id, (csp_key, maybe_scope)) in all_keys.drain() {
            if maybe_scope != Some(scope) || filter(&key_id, &csp_key) {
                self.keys.insert(key_id, (csp_key, maybe_scope));
            } else {
                info!(
                    self.logger,
                    "Deleting key with ID {} with scope {}", key_id, scope
                );
            }
        }
        if self.keys.len() < orig_keys_count {
            self.write_secret_keys_to_disk_and_cleanup_old_file(&self.keys)?;
        }
        Ok(())
    }

    fn retain_would_modify_keystore<F>(&self, filter: F, scope: Scope) -> bool
    where
        F: Fn(&KeyId, &CspSecretKey) -> bool + 'static,
    {
        for (key_id, (csp_key, maybe_scope)) in self.keys.iter() {
            if maybe_scope == &Some(scope) && !filter(key_id, csp_key) {
                // Key is to be deleted, i.e., the keystore will be modified.
                return true;
            }
        }
        false
    }
}

impl Drop for ProtoSecretKeyStore {
    fn drop(&mut self) {
        self.log_cleanup_errors_and_observe_metrics(self.clean_up_old_sks());
    }
}

fn overwrite_file_with_zeroes_and_delete_if_it_exists<P: AsRef<Path>>(
    file: P,
) -> Result<(), Vec<CleanupError>> {
    let mut old_file_exists = true;
    let mut result = match ic_sys::fs::open_existing_file_for_write(&file) {
        Ok(mut f) => match f.metadata() {
            Ok(metadata) => {
                let len = metadata.len() as usize;
                if len > 0 {
                    let zeros = vec![0; len];
                    f.write_all(&zeros)
                        .map_err(|e| vec![CleanupError::OldFileOverwriting(e)])
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(vec![CleanupError::OldFileMetadataRetrieval(e)]),
        },
        Err(e) if e.kind() == ErrorKind::NotFound => {
            old_file_exists = false;
            Ok(())
        }
        Err(e) => Err(vec![CleanupError::OpeningFileForWriting(e)]),
    };
    if old_file_exists {
        result = combine_cleanup_results(
            result,
            ic_sys::fs::remove_file(&file).map_err(|e| {
                vec![CleanupError::OldFileRemoval {
                    old_sks_file: file.as_ref().to_string_lossy().to_string(),
                    source: e,
                }]
            }),
        );
    }
    result
}

fn combine_cleanup_results(
    res1: Result<(), Vec<CleanupError>>,
    res2: Result<(), Vec<CleanupError>>,
) -> Result<(), Vec<CleanupError>> {
    match (res1, res2) {
        (Err(e1), Err(e2)) => Err(e1.into_iter().chain(e2).collect()),
        (res1, res2) => res1.and(res2),
    }
}
