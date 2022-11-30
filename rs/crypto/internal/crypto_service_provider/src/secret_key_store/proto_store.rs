//! Filesystem-backed secret key store
#![allow(clippy::unwrap_used)]
use crate::canister_threshold::IDKG_MEGA_SCOPE;
use crate::key_id::KeyId;
use crate::secret_key_store::{
    Scope, SecretKeyStore, SecretKeyStoreError, SecretKeyStorePersistenceError,
};
use crate::threshold::ni_dkg::{NIDKG_FS_SCOPE, NIDKG_THRESHOLD_SCOPE};
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

const CURRENT_SKS_VERSION: u32 = 2;

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

    // TODO(CRP-532): remove support for the legacy format in a few weeks after
    // merging.
    fn migrate_to_current_version(sks_proto: pb::SecretKeyStore) -> SecretKeys {
        match sks_proto.version {
            3 => ProtoSecretKeyStore::sks_proto_to_secret_keys(&sks_proto),
            CURRENT_SKS_VERSION => {
                let mut secret_keys = SecretKeys::new();
                for (key_id_hex, sk_proto) in sks_proto.key_id_to_secret_key_v1.iter() {
                    let key_id = key_id_from_hex(key_id_hex);
                    let csp_key = Self::parse_csp_secret_key(&sk_proto.csp_secret_key, &key_id);
                    let scope = match &csp_key {
                        CspSecretKey::MEGaEncryptionK256(_) => {
                            let _ensure_scope_is_valid = Self::parse_scope(&sk_proto.scope);
                            Some(IDKG_MEGA_SCOPE)
                        }
                        _ => Self::parse_scope(&sk_proto.scope),
                    };
                    secret_keys.insert(key_id, (csp_key, scope));
                }
                secret_keys
            }
            0 => {
                let mut secret_keys = SecretKeys::new();
                for (key_id_string, key_bytes) in sks_proto.key_id_to_csp_secret_key.iter() {
                    let key_id = KeyId::try_from(key_id_string.as_str()).unwrap_or_else(|err| {
                        panic!("Failed to create KeyId: {}", err);
                    });
                    let mut csp_key = Self::parse_csp_secret_key(key_bytes, &key_id);
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
                    let mut csp_key = Self::parse_csp_secret_key(&sk_proto.csp_secret_key, &key_id);
                    if let CspSecretKey::FsEncryption(CspFsEncryptionKeySet::Groth20_Bls12_381(
                        key_set,
                    )) = &csp_key
                    {
                        let key_set_with_pop = convert_keyset_to_keyset_with_pop(key_set.clone());
                        csp_key = CspSecretKey::FsEncryption(
                            CspFsEncryptionKeySet::Groth20WithPop_Bls12_381(key_set_with_pop),
                        );
                    }
                    let maybe_scope = Self::parse_scope(&sk_proto.scope);
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
        let supported_versions = vec![CURRENT_SKS_VERSION, 3];
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

#[cfg(test)]
pub mod tests {
    use super::super::test_utils;
    use super::*;
    use crate::canister_threshold::IDKG_MEGA_SCOPE;
    use crate::secret_key_store::test_utils::{make_key_id, make_secret_key, TempSecretKeyStore};
    use crate::secret_key_store::{
        scope::ConstScope, Scope, SecretKeyStore, SecretKeyStoreError,
        SecretKeyStorePersistenceError,
    };
    use crate::types::CspSecretKey;
    use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
    use ic_crypto_internal_csp_test_utils::files::mk_temp_dir_with_permissions;
    use ic_crypto_internal_multi_sig_bls12381::types::SecretKeyBytes;
    use ic_crypto_internal_threshold_sig_ecdsa::{
        EccCurveType, MEGaKeySetK256Bytes, MEGaPrivateKey, MEGaPrivateKeyK256Bytes, MEGaPublicKey,
        MEGaPublicKeyK256Bytes,
    };
    use ic_crypto_internal_tls::keygen::TlsEd25519SecretKeyDerBytes;
    use ic_crypto_secrets_containers::SecretArray;
    use proptest::prelude::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::{tempdir as tempdir_deleted_at_end_of_scope, TempDir};

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

    #[test]
    fn should_deserialize_all_existing_secret_key_stores() {
        for version in SecretKeyStoreVersion::all_versions() {
            let (_temp_dir, secret_key_store) = existing_secret_key_store_in_temp_dir(&version);
            let guard = secret_key_store.keys.read();
            assert_eq!(guard.keys().len(), 5);

            let test_vecs = vec![
                TestVector::mega_encryption(),
                TestVector::tls(),
                TestVector::ed25519(),
                TestVector::multi_bls(),
            ];
            for test_vec in test_vecs {
                let secret_key = secret_key_store
                    .get(&test_vec.key_id)
                    .expect("secret key not found");
                assert_eq!(secret_key, test_vec.secret_key);
            }
            // We test for FSEncryption separately because the structure of the private key is way more complex
            // and so recreating it from scratch from some byte arrays would be very time-consuming
            // (e.g., d_t contains 32 96-byte arrays and d_h contains 256 96-byte arrays)
            let fs_key_id =
                KeyId::from_hex("bdf42c6970fdeb0dc16c8175430b8f8428a2a1cd387da5ca805eaeb461c2518b")
                    .expect("invalid key id");
            let fs_key = secret_key_store
                .get(&fs_key_id)
                .expect("Secret key for FS encryption not found");
            assert!(matches!(
                fs_key,
                CspSecretKey::FsEncryption(CspFsEncryptionKeySet::Groth20WithPop_Bls12_381(..))
            ));
        }
    }

    #[test]
    fn should_downgrade_secret_key_store_to_current_sks_version() {
        //TODO CRP-1806: remove this test when version bumped to 3
        //TODO CRP-1806: change `supported_versions` to only contain CURRENT_SKS_VERSION
        assert_eq!(CURRENT_SKS_VERSION, 2);
        let (_temp_dir, mut secret_key_store) =
            existing_secret_key_store_in_temp_dir(&SecretKeyStoreVersion::V3);

        let seed = 42;
        let (key_id, secret_key) = (make_key_id(seed), make_secret_key(seed));
        secret_key_store
            .insert(
                key_id,
                secret_key.clone(),
                Some(Scope::Const(ConstScope::Test0)),
            )
            .expect("could not write generated key");

        assert_eq!(
            secret_key_store.get(&key_id).expect("could not read SKS"),
            secret_key
        );
        assert_secret_key_store_proto_has_correct_version(
            secret_key_store.proto_file_path(),
            &SecretKeyStoreVersion::V2,
        );
    }

    #[test]
    fn should_have_scope_for_mega_private() {
        let (_temp_dir, secret_key_store) =
            existing_secret_key_store_in_temp_dir(&SecretKeyStoreVersion::V2);
        let (_csp_key, scope) = with_read_lock(&secret_key_store.keys, |keys| {
            keys.get(&TestVector::mega_encryption().key_id)
                .map(|(csp_key, scope)| (csp_key.to_owned(), scope.to_owned()))
        })
        .expect("missing MEGa private key");

        assert_eq!(scope, Some(IDKG_MEGA_SCOPE));
    }

    #[test]
    fn should_fail_to_write_to_read_only_secret_key_store_directory() {
        let (temp_dir, mut secret_key_store) =
            existing_secret_key_store_in_temp_dir(&SecretKeyStoreVersion::V2);
        let mut seed = ChaCha20Rng::seed_from_u64(42);
        let key_id = KeyId::from(seed.gen::<[u8; 32]>());
        let key = CspSecretKey::Ed25519(ed25519_types::SecretKeyBytes(
            SecretArray::new_and_dont_zeroize_argument(&seed.gen()),
        ));

        // make the crypto root directory non-writeable, causing the subsequent call to insert a
        // new key into the key store to fail
        fs::set_permissions(temp_dir.path(), Permissions::from_mode(0o400))
            .expect("Could not set the permissions of the temp dir.");

        assert!(matches!(
            secret_key_store.insert(key_id, key, None),
            Err(SecretKeyStoreError::PersistenceError(
                SecretKeyStorePersistenceError::IoError(msg)
            ))
            if msg.to_lowercase().contains("secret key store internal error writing protobuf using tmp file: permission denied")
        ));

        fs::set_permissions(temp_dir.path(), Permissions::from_mode(0o700)).expect(
            "failed to change permissions of temp_dir so that writing is possible \
                again, so that the directory can automatically be cleaned up",
        );
    }

    #[test]
    #[should_panic(expected = "Error reading SKS data: Permission denied")]
    fn should_fail_to_read_from_secret_key_store_with_no_read_permissions() {
        let temp_dir: TempDir = mk_temp_dir_with_permissions(0o700);
        copy_file_to_dir(
            path_to_existing_secret_key_store(&SecretKeyStoreVersion::V2).as_path(),
            temp_dir.path(),
        );

        // remove read permissions from the secret key store file, causing the subsequent call to
        // open the key store to panic (since it tries to read the key store)
        fs::set_permissions(
            temp_dir.path().join(existing_secret_key_store_file_name(
                &SecretKeyStoreVersion::V2,
            )),
            Permissions::from_mode(0o000),
        )
        .expect("Could not set the permissions of the secret key store file.");

        let _secret_key_store = ProtoSecretKeyStore::open(
            temp_dir.path(),
            &existing_secret_key_store_file_name(&SecretKeyStoreVersion::V2),
            None,
        );
    }

    fn copy_file_to_dir(source_file: &Path, target_dir: &Path) {
        let filename = source_file.file_name().expect("expected file name");
        let target_file = target_dir.join(filename);
        fs::copy(source_file, target_file).expect("could not copy source file");
    }

    fn proto_key_store() -> TempSecretKeyStore {
        TempSecretKeyStore::new()
    }

    // Secret key store file was generated using TempCryptoBuilder to generate all keys.
    // (See for example the test `should_collect_correctly_key_count_metrics_for_all_keys`).
    // A break point was set before the crypto component went out-of-scoped to be able to copy the
    // secret key store file somewhere else.
    fn path_to_existing_secret_key_store(version: &SecretKeyStoreVersion) -> PathBuf {
        let mut path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        path.push(format!(
            "test_resources/{}",
            existing_secret_key_store_file_name(version)
        ));
        path
    }

    fn existing_secret_key_store_file_name(version: &SecretKeyStoreVersion) -> String {
        let version_suffix = match version {
            SecretKeyStoreVersion::V2 => "v2",
            SecretKeyStoreVersion::V3 => "v3",
        };
        format!("sks_data_{}.pb", version_suffix)
    }

    fn existing_secret_key_store_in_temp_dir(
        version: &SecretKeyStoreVersion,
    ) -> (TempDir, ProtoSecretKeyStore) {
        let temp_dir: TempDir = mk_temp_dir_with_permissions(0o700);
        let sks_path = path_to_existing_secret_key_store(version);
        assert_secret_key_store_proto_has_correct_version(sks_path.as_path(), version);
        copy_file_to_dir(sks_path.as_path(), temp_dir.path());

        let secret_key_store = ProtoSecretKeyStore::open(
            temp_dir.path(),
            &existing_secret_key_store_file_name(version),
            None,
        );
        (temp_dir, secret_key_store)
    }

    enum SecretKeyStoreVersion {
        V2,
        V3,
    }

    impl SecretKeyStoreVersion {
        fn all_versions() -> Vec<SecretKeyStoreVersion> {
            vec![SecretKeyStoreVersion::V2, SecretKeyStoreVersion::V3]
        }
    }

    fn assert_secret_key_store_proto_has_correct_version(
        sks_data_file: &Path,
        version: &SecretKeyStoreVersion,
    ) {
        let data = fs::read(sks_data_file).expect("error reading SKS");
        let sks_proto = pb::SecretKeyStore::decode(&*data).expect("error parsing SKS data");
        let actual_version = sks_proto.version;
        let expected_version = match version {
            SecretKeyStoreVersion::V2 => 2,
            SecretKeyStoreVersion::V3 => 3,
        };
        assert_eq!(actual_version, expected_version);
    }

    struct TestVector {
        key_id: KeyId,
        secret_key: CspSecretKey,
    }

    impl TestVector {
        fn multi_bls() -> TestVector {
            TestVector {
                key_id: KeyId::from_hex(
                    "7d969948abc60881eef2794043a7550f691dad53d698f4fbbb747a590285bb5e",
                )
                .expect("invalid key id"),
                secret_key: CspSecretKey::MultiBls12_381(SecretKeyBytes([
                    54, 109, 33, 204, 23, 220, 113, 219, 1, 25, 39, 129, 69, 119, 21, 235, 75, 183,
                    245, 235, 173, 111, 112, 201, 140, 232, 154, 233, 186, 139, 22, 211,
                ])),
            }
        }

        fn tls() -> TestVector {
            TestVector {
                key_id: KeyId::from_hex(
                    "0a58fa33655098ce6e72abb3c79ec02ad1906fad8ae64a208fbee6814a4f0cc8",
                )
                .expect("invalid key id"),
                secret_key: CspSecretKey::TlsEd25519(TlsEd25519SecretKeyDerBytes {
                    bytes: [
                        48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32, 155, 183, 227,
                        248, 2, 202, 222, 165, 100, 242, 173, 163, 239, 23, 85, 16, 84, 8, 182, 46,
                        199, 93, 167, 71, 223, 94, 157, 198, 73, 52, 6, 130,
                    ]
                    .to_vec(),
                }),
            }
        }

        fn ed25519() -> TestVector {
            TestVector {
                key_id: KeyId::from_hex(
                    "0a150e8c7f9512dcb5469f7e16f630085124f49f9c96ee54e713f04efa385d02",
                )
                .expect("invalid key id"),
                secret_key: CspSecretKey::Ed25519(ed25519_types::SecretKeyBytes(
                    SecretArray::new_and_dont_zeroize_argument(&[
                        97, 251, 60, 99, 225, 10, 6, 206, 44, 165, 122, 119, 156, 82, 104, 37, 138,
                        128, 122, 142, 3, 81, 54, 35, 98, 106, 111, 134, 97, 63, 185, 195,
                    ]),
                )),
            }
        }

        fn mega_encryption() -> TestVector {
            let public_key = MEGaPublicKey::deserialize(
                EccCurveType::K256,
                &[
                    3, 213, 89, 237, 206, 111, 232, 127, 10, 11, 181, 243, 38, 72, 166, 209, 32,
                    134, 57, 134, 26, 137, 214, 20, 11, 226, 134, 194, 19, 87, 70, 26, 243,
                ],
            )
            .expect("invalid public key");
            let private_key = MEGaPrivateKey::deserialize(
                EccCurveType::K256,
                &[
                    30, 138, 154, 17, 223, 252, 133, 244, 207, 36, 180, 75, 159, 242, 208, 133,
                    142, 127, 2, 199, 54, 174, 218, 236, 183, 244, 233, 123, 244, 50, 179, 189,
                ],
            )
            .expect("invalid private key");
            TestVector {
                key_id: KeyId::from_hex(
                    "2a7aa030452b5615d75cec6c4bc8eb34b37abdc40c71612f2daae934f2f3d1d8",
                )
                .expect("invalid key id"),
                secret_key: CspSecretKey::MEGaEncryptionK256(MEGaKeySetK256Bytes {
                    public_key: MEGaPublicKeyK256Bytes::try_from(&public_key)
                        .expect("invalid public key bytes"),
                    private_key: MEGaPrivateKeyK256Bytes::try_from(&private_key)
                        .expect("invalid private key bytes"),
                }),
            }
        }
    }
}
