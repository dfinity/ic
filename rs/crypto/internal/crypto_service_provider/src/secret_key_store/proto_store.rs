//! Filesystem-backed secret key store
#![allow(clippy::unwrap_used)]
use crate::canister_threshold::IDKG_MEGA_SCOPE;
use crate::key_id::KeyId;
use crate::secret_key_store::{
    Scope, SecretKeyStore, SecretKeyStoreError, SecretKeyStorePersistenceError,
};
use crate::types::CspSecretKey;
use hex::{FromHex, ToHex};
use ic_config::crypto::CryptoConfig;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::groth20_bls12_381::types::convert_keyset_to_keyset_with_pop;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::types::CspFsEncryptionKeySet;
use ic_logger::{info, replica_logger::no_op_logger, ReplicaLogger};
use parking_lot::RwLock;
use prost::Message;
use std::borrow::{Borrow, BorrowMut};
use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

#[cfg(test)]
mod tests;

const CURRENT_SKS_VERSION: u32 = 3;

fn key_id_from_hex(key_id_hex: &str) -> KeyId {
    KeyId::from_hex(key_id_hex).unwrap_or_else(|_| panic!("Error parsing hex KeyId {}", key_id_hex))
}

/// The secret key store protobuf definitions
// Include the prost-build generated registry protos.
#[allow(clippy::all)]
#[path = "../../gen/ic.crypto.v1.rs"]
pub mod pb;

type SecretKeys = HashMap<KeyId, (CspSecretKey, Option<Scope>)>;

/// A secret key store that persists data to the filesystem, using protobufs for
/// serialization
pub struct ProtoSecretKeyStore {
    proto_file: PathBuf,
    keys: Arc<RwLock<SecretKeys>>,
    logger: ReplicaLogger,
}

impl ProtoSecretKeyStore {
    /// Creates a database instance.
    pub fn open(dir: &Path, file_name: &str, logger: Option<ReplicaLogger>) -> Self {
        CryptoConfig::check_dir_has_required_permissions(dir)
            .expect("wrong crypto root permissions");
        let proto_file = dir.join(file_name);
        let secret_keys = match Self::read_sks_data_from_disk(&proto_file) {
            Some(sks_proto) => sks_proto,
            None => SecretKeys::new(),
        };
        ProtoSecretKeyStore {
            proto_file,
            keys: Arc::new(RwLock::new(secret_keys)),
            logger: logger.unwrap_or_else(no_op_logger),
        }
    }

    /// Returns the path to the protobuf file storing the keys.
    pub fn proto_file_path(&self) -> &Path {
        self.proto_file.as_path()
    }

    fn read_sks_data_from_disk(sks_data_file: &Path) -> Option<SecretKeys> {
        match fs::read(sks_data_file) {
            Ok(data) => {
                let sks_pb = pb::SecretKeyStore::decode(&*data).expect("error parsing SKS data");
                let keys = ProtoSecretKeyStore::migrate_to_current_version(sks_pb);
                Some(keys)
            }
            Err(err) => {
                if err.kind() == ErrorKind::NotFound {
                    None
                } else {
                    panic!("Error reading SKS data: {}", err)
                }
            }
        }
    }

    fn migrate_to_current_version(sks_proto: pb::SecretKeyStore) -> SecretKeys {
        match sks_proto.version {
            CURRENT_SKS_VERSION => ProtoSecretKeyStore::sks_proto_to_secret_keys(&sks_proto),
            2 => {
                let secret_keys_from_disk =
                    ProtoSecretKeyStore::sks_proto_to_secret_keys(&sks_proto);
                Self::migrate_sks_from_v2_to_v3(secret_keys_from_disk)
            }
            1 => {
                let secret_keys_from_disk =
                    ProtoSecretKeyStore::sks_proto_to_secret_keys(&sks_proto);
                let sks_v2 = Self::migrate_sks_from_v1_to_v2(secret_keys_from_disk);
                Self::migrate_sks_from_v2_to_v3(sks_v2)
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

    fn migrate_sks_from_v1_to_v2(existing_secret_keys: SecretKeys) -> SecretKeys {
        let mut migrated_secret_keys = SecretKeys::new();
        for (key_id, (csp_key, scope)) in existing_secret_keys.into_iter() {
            let migrated_secret_key = match &csp_key {
                CspSecretKey::FsEncryption(CspFsEncryptionKeySet::Groth20_Bls12_381(key_set)) => {
                    let key_set_with_pop = convert_keyset_to_keyset_with_pop(key_set.clone());
                    CspSecretKey::FsEncryption(CspFsEncryptionKeySet::Groth20WithPop_Bls12_381(
                        key_set_with_pop,
                    ))
                }
                _ => csp_key,
            };
            migrated_secret_keys.insert(key_id, (migrated_secret_key, scope));
        }
        migrated_secret_keys
    }

    fn parse_csp_secret_key(key_bytes: &[u8], key_id: &KeyId) -> CspSecretKey {
        serde_cbor::from_slice(key_bytes)
            .unwrap_or_else(|e| panic!("Error deserializing key with ID {}: {}", key_id, e))
    }

    fn parse_scope(scope_proto: &str) -> Option<Scope> {
        if scope_proto.is_empty() {
            None
        } else {
            Some(
                Scope::from_str(scope_proto)
                    .unwrap_or_else(|_| panic!("Unknown scope: {}", scope_proto)),
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
        let supported_versions = vec![1, 2, CURRENT_SKS_VERSION];
        if !supported_versions.contains(&version) {
            panic!("Unexpected SecretKeyStore-proto version: {}", version)
        }
    }

    fn secret_keys_to_sks_proto(
        secret_keys: &SecretKeys,
    ) -> Result<pb::SecretKeyStore, SecretKeyStorePersistenceError> {
        let mut sks_proto = pb::SecretKeyStore {
            version: CURRENT_SKS_VERSION,
            ..Default::default()
        };
        for (key_id, (csp_key, maybe_scope)) in secret_keys {
            let key_id_hex = key_id.encode_hex();
            let key_as_cbor = serde_cbor::to_vec(&csp_key).map_err(|_| {
                SecretKeyStorePersistenceError::SerializationError(format!(
                    "Error serializing key with ID {}",
                    key_id
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

    fn write_secret_keys_to_disk(
        sks_data_file: &Path,
        secret_keys: &SecretKeys,
    ) -> Result<(), SecretKeyStorePersistenceError> {
        let sks_proto = ProtoSecretKeyStore::secret_keys_to_sks_proto(secret_keys)?;
        ic_utils::fs::write_protobuf_using_tmp_file(sks_data_file, &sks_proto).map_err(|e| {
            SecretKeyStorePersistenceError::IoError(format!(
                "Secret key store internal error writing protobuf using tmp file: {}",
                e
            ))
        })
    }
}

impl SecretKeyStore for ProtoSecretKeyStore {
    fn insert(
        &mut self,
        id: KeyId,
        key: CspSecretKey,
        scope: Option<Scope>,
    ) -> Result<(), SecretKeyStoreError> {
        let inserted: Result<bool, SecretKeyStorePersistenceError> =
            with_write_lock(&self.keys, |keys| match keys.get(&id) {
                Some(_) => Ok(false),
                None => {
                    keys.insert(id, (key, scope));
                    ProtoSecretKeyStore::write_secret_keys_to_disk(&self.proto_file, keys)?;
                    Ok(true)
                }
            });
        match inserted {
            Ok(false) => Err(SecretKeyStoreError::DuplicateKeyId(id)),
            Ok(true) => Ok(()),
            Err(e) => Err(SecretKeyStoreError::PersistenceError(e)),
        }
    }

    fn get(&self, id: &KeyId) -> Option<CspSecretKey> {
        with_read_lock(&self.keys, |keys| {
            keys.get(id).map(|(csp_key, _)| csp_key.to_owned())
        })
    }

    fn contains(&self, id: &KeyId) -> bool {
        self.get(id).is_some()
    }

    fn remove(&mut self, id: &KeyId) -> Result<bool, SecretKeyStorePersistenceError> {
        with_write_lock(&self.keys, |keys| match keys.get(id) {
            Some(_) => {
                keys.remove(id);
                ProtoSecretKeyStore::write_secret_keys_to_disk(&self.proto_file, keys)?;
                Ok(true)
            }
            None => Ok(false),
        })
    }

    fn retain<F>(&mut self, filter: F, scope: Scope) -> Result<(), SecretKeyStorePersistenceError>
    where
        F: Fn(&KeyId, &CspSecretKey) -> bool,
    {
        with_write_lock(&self.keys, |keys| {
            let mut all_keys = SecretKeys::new();
            core::mem::swap(&mut all_keys, keys);
            let orig_keys_count = all_keys.len();
            for (key_id, (csp_key, maybe_scope)) in all_keys.drain() {
                if maybe_scope != Some(scope) || filter(&key_id, &csp_key) {
                    keys.insert(key_id, (csp_key, maybe_scope));
                } else {
                    info!(
                        self.logger,
                        "Deleting key with ID {} with scope {}", key_id, scope
                    );
                }
            }
            if keys.len() < orig_keys_count {
                ProtoSecretKeyStore::write_secret_keys_to_disk(&self.proto_file, keys)?;
            }
            Ok(())
        })
    }
}

fn with_write_lock<T, I, R, F>(v: T, f: F) -> Result<R, SecretKeyStorePersistenceError>
where
    T: AsRef<RwLock<I>>,
    F: FnOnce(&mut I) -> Result<R, SecretKeyStorePersistenceError>,
{
    let mut lock_result = v.as_ref().write();
    f(lock_result.borrow_mut())
}

fn with_read_lock<T, I, R, F>(v: T, f: F) -> Option<R>
where
    T: AsRef<RwLock<I>>,
    F: FnOnce(&I) -> Option<R>,
{
    let lock_result = v.as_ref().read();
    f(lock_result.borrow())
}
