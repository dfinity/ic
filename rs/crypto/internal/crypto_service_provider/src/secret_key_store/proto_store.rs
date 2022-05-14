//! Filesystem-backed secret key store
#![allow(clippy::unwrap_used)]
use crate::secret_key_store::{Scope, SecretKeyStore, SecretKeyStoreError};
use crate::threshold::ni_dkg::{NIDKG_FS_SCOPE, NIDKG_THRESHOLD_SCOPE};
use crate::types::CspSecretKey;
use ic_config::crypto::CryptoConfig;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::groth20_bls12_381::types::convert_keyset_to_keyset_with_pop;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::types::CspFsEncryptionKeySet;
use ic_logger::{info, replica_logger::no_op_logger, ReplicaLogger};
use ic_types::crypto::KeyId;
use parking_lot::RwLock;
use prost::Message;
use std::borrow::{Borrow, BorrowMut};
use std::collections::HashMap;
use std::convert::TryInto;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

const CURRENT_SKS_VERSION: u32 = 2;

// TODO(CRP-523): turn this to FromStr-trait once KeyId is not public.
const KEY_ID_PREFIX: &str = "KeyId(0x";
const KEY_ID_SUFFIX: &str = ")";
fn key_id_from_display_string(s: &str) -> KeyId {
    if s.starts_with(KEY_ID_PREFIX) && s.ends_with(KEY_ID_SUFFIX) {
        let key_id_hex = s
            .get(KEY_ID_PREFIX.len()..s.len() - KEY_ID_SUFFIX.len())
            .unwrap_or_else(|| panic!("Invalid display string for KeyId: {}", s));
        key_id_from_hex(key_id_hex)
    } else {
        panic!("Invalid display string for KeyId: {}", s)
    }
}

fn key_id_to_hex(key_id: &KeyId) -> String {
    hex::encode(key_id.0)
}

fn key_id_from_hex(key_id_hex: &str) -> KeyId {
    let parsed = hex::decode(key_id_hex)
        .unwrap_or_else(|e| panic!("Error parsing hex KeyId {}: {}", key_id_hex, e));
    let bytes: [u8; 32] = parsed[..]
        .try_into()
        .unwrap_or_else(|_| panic!("KeyId {} should have 32 bytes", key_id_hex));
    KeyId::from(bytes)
}

/// The secret key store protobuf definitions
// Include the prost-build generated registry protos.
#[rustfmt::skip]
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

    // TODO(CRP-532): remove support for the legacy format in a few weeks after
    // merging.
    fn migrate_to_current_version(sks_proto: pb::SecretKeyStore) -> SecretKeys {
        match sks_proto.version {
            CURRENT_SKS_VERSION => ProtoSecretKeyStore::sks_proto_to_secret_keys(&sks_proto),
            0 => {
                let mut secret_keys = SecretKeys::new();
                for (key_id_string, key_bytes) in sks_proto.key_id_to_csp_secret_key.iter() {
                    let key_id = key_id_from_display_string(key_id_string);
                    let mut csp_key: CspSecretKey = serde_cbor::from_slice(key_bytes)
                        .unwrap_or_else(|e| {
                            panic!("Error deserializing key with ID {}: {}", key_id, e)
                        });
                    if let CspSecretKey::FsEncryption(CspFsEncryptionKeySet::Groth20_Bls12_381(
                        key_set,
                    )) = &csp_key
                    {
                        let key_set_with_pop = convert_keyset_to_keyset_with_pop(key_set.clone());
                        csp_key = CspSecretKey::FsEncryption(
                            CspFsEncryptionKeySet::Groth20WithPop_Bls12_381(key_set_with_pop),
                        );
                    }
                    let maybe_scope: Option<Scope> = match csp_key {
                        CspSecretKey::FsEncryption(_) => Some(NIDKG_FS_SCOPE),
                        CspSecretKey::ThresBls12_381(_) => Some(NIDKG_THRESHOLD_SCOPE),
                        _ => None,
                    };
                    secret_keys.insert(key_id, (csp_key, maybe_scope));
                }
                secret_keys
            }

            1 => {
                let mut secret_keys = SecretKeys::new();
                for (key_id_hex, sk_proto) in sks_proto.key_id_to_secret_key_v1.iter() {
                    let key_id = key_id_from_hex(key_id_hex);
                    let mut csp_key = serde_cbor::from_slice(&sk_proto.csp_secret_key)
                        .unwrap_or_else(|e| {
                            panic!("Error deserializing key with ID {}: {}", key_id, e)
                        });

                    if let CspSecretKey::FsEncryption(CspFsEncryptionKeySet::Groth20_Bls12_381(
                        key_set,
                    )) = &csp_key
                    {
                        let key_set_with_pop = convert_keyset_to_keyset_with_pop(key_set.clone());
                        csp_key = CspSecretKey::FsEncryption(
                            CspFsEncryptionKeySet::Groth20WithPop_Bls12_381(key_set_with_pop),
                        );
                    }
                    let maybe_scope = if sk_proto.scope.is_empty() {
                        None
                    } else {
                        Some(
                            Scope::from_str(&sk_proto.scope)
                                .unwrap_or_else(|_| panic!("Unknown scope: {}", sk_proto.scope)),
                        )
                    };
                    secret_keys.insert(key_id, (csp_key, maybe_scope));
                }
                secret_keys
            }
            _ => panic!(
                "Unsupported SecretKeyStore-proto version: {}",
                sks_proto.version
            ),
        }
    }

    fn sks_proto_to_secret_keys(sks_proto: &pb::SecretKeyStore) -> SecretKeys {
        if sks_proto.version != CURRENT_SKS_VERSION {
            panic!(
                "Unexpected SecretKeyStore-proto version: {}",
                sks_proto.version
            )
        }
        let mut secret_keys = SecretKeys::new();
        for (key_id_hex, sk_proto) in sks_proto.key_id_to_secret_key_v1.iter() {
            let key_id = key_id_from_hex(key_id_hex);
            let csp_key = serde_cbor::from_slice(&sk_proto.csp_secret_key)
                .unwrap_or_else(|e| panic!("Error deserializing key with ID {}: {}", key_id, e));
            let maybe_scope = if sk_proto.scope.is_empty() {
                None
            } else {
                Some(
                    Scope::from_str(&sk_proto.scope)
                        .unwrap_or_else(|_| panic!("Unknown scope: {}", sk_proto.scope)),
                )
            };
            secret_keys.insert(key_id, (csp_key, maybe_scope));
        }
        secret_keys
    }

    fn secret_keys_to_sks_proto(secret_keys: &SecretKeys) -> pb::SecretKeyStore {
        let mut sks_proto = pb::SecretKeyStore {
            version: CURRENT_SKS_VERSION,
            ..Default::default()
        };
        for (key_id, (csp_key, maybe_scope)) in secret_keys {
            let key_id_hex = key_id_to_hex(key_id);
            let key_as_cbor = serde_cbor::to_vec(&csp_key)
                .unwrap_or_else(|_| panic!("Error serializing key with ID {}", key_id));
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
        sks_proto
    }

    fn write_secret_keys_to_disk(sks_data_file: &Path, secret_keys: &SecretKeys) {
        let sks_proto = ProtoSecretKeyStore::secret_keys_to_sks_proto(secret_keys);
        ic_utils::fs::write_protobuf_using_tmp_file(sks_data_file, &sks_proto).unwrap();
    }
}

impl SecretKeyStore for ProtoSecretKeyStore {
    fn insert(
        &mut self,
        id: KeyId,
        key: CspSecretKey,
        scope: Option<Scope>,
    ) -> Result<(), SecretKeyStoreError> {
        with_write_lock(&self.keys, |keys| match keys.get(&id) {
            Some(_) => Err(SecretKeyStoreError::DuplicateKeyId(id)),
            None => {
                keys.insert(id, (key, scope));
                ProtoSecretKeyStore::write_secret_keys_to_disk(&self.proto_file, keys);
                Ok(())
            }
        })
    }

    fn get(&self, id: &KeyId) -> Option<CspSecretKey> {
        with_read_lock(&self.keys, |keys| {
            keys.get(id).map(|(csp_key, _)| csp_key.to_owned())
        })
    }

    fn contains(&self, id: &KeyId) -> bool {
        self.get(id).is_some()
    }

    fn remove(&mut self, id: &KeyId) -> bool {
        let result = with_write_lock(&self.keys, |keys| match keys.get(id) {
            Some(_) => {
                keys.remove(id);
                ProtoSecretKeyStore::write_secret_keys_to_disk(&self.proto_file, keys);
                Ok(true)
            }
            None => Ok(false),
        });
        result.expect("lambda unexpectedly returned Err")
    }

    fn retain<F>(&mut self, filter: F, scope: Scope)
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
                ProtoSecretKeyStore::write_secret_keys_to_disk(&self.proto_file, keys);
            }
            Ok(())
        })
        .unwrap_or_else(|e| panic!("retain failed for scope {} with error {}", scope, e));
    }
}

fn with_write_lock<T, I, R, F>(v: T, f: F) -> Result<R, SecretKeyStoreError>
where
    T: AsRef<RwLock<I>>,
    F: FnOnce(&mut I) -> Result<R, SecretKeyStoreError>,
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

#[cfg(test)]
pub mod tests {
    use super::super::test_utils;
    use super::*;
    use crate::secret_key_store::test_utils::TempSecretKeyStore;
    use ic_crypto_internal_csp_test_utils::files::mk_temp_dir_with_permissions;
    use proptest::prelude::*;
    use tempfile::tempdir as tempdir_deleted_at_end_of_scope;

    // TODO(CRP-351): add tests that SKS updates hit the disk.
    #[test]
    #[should_panic]
    fn open_should_panic_for_paths_that_do_not_exist() {
        let dir_path = {
            let dir = tempdir_deleted_at_end_of_scope().unwrap();
            format!("{}", dir.path().display())
        };
        ProtoSecretKeyStore::open(Path::new(&dir_path), "dummy_file", None);
    }

    #[test]
    #[should_panic]
    fn open_should_panic_for_paths_that_are_widely_readable() {
        let dir = mk_temp_dir_with_permissions(0o744);
        ProtoSecretKeyStore::open(dir.as_ref(), "dummy_file", None);
    }

    proptest! {
        #[test]
        fn should_retrieve_inserted_key(seed1: u64, seed2: u64) {
            test_utils::should_retrieve_inserted_key(seed1, seed2, proto_key_store());
        }

        #[test]
        fn should_contain_existing_key(seed1: u64, seed2: u64) {
            test_utils::should_contain_existing_key(seed1, seed2, proto_key_store());
        }

        #[test]
        fn should_not_contain_nonexisting_key(seed1: u64) {
            test_utils::should_not_contain_nonexisting_key(seed1, proto_key_store());
        }

        #[test]
        fn should_remove_existing_key(seed1: u64, seed2: u64) {
            test_utils::should_remove_existing_key(seed1, seed2, proto_key_store());
        }

        #[test]
        fn should_not_remove_nonexisting_key(seed1: u64) {
            test_utils::should_not_remove_nonexisting_key(seed1, proto_key_store());
        }

        #[test]
        fn deleting_twice_should_return_false(seed1: u64, seed2: u64) {
            test_utils::deleting_twice_should_return_false(seed1, seed2, proto_key_store());
        }

        #[test]
        fn no_overwrites(seed1: u64, seed2: u64, seed3: u64) {
            test_utils::no_overwrites(seed1, seed2, seed3, proto_key_store());
        }

        ////////////////////////////////////////////////////////////////////////////////////////
        // If you add tests here, remember to also add them for the VolatileSecretKeyStore
        ////////////////////////////////////////////////////////////////////////////////////////
    }

    #[test]
    fn should_retain_expected_keys() {
        test_utils::should_retain_expected_keys(proto_key_store());
    }

    fn proto_key_store() -> TempSecretKeyStore {
        TempSecretKeyStore::new()
    }
}
