use super::*;
use crate::canister_threshold::IDKG_MEGA_SCOPE;
use crate::secret_key_store::temp_secret_key_store::TempSecretKeyStore;
use crate::secret_key_store::test_utils::{make_key_id, make_secret_key};
use crate::secret_key_store::{
    scope::ConstScope, Scope, SecretKeyStore, SecretKeyStoreError, SecretKeyStorePersistenceError,
};
use crate::types::CspSecretKey;
use assert_matches::assert_matches;
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
        let mut key_store = proto_key_store();
        let key_id: KeyId = make_key_id(seed1);
        let key = make_secret_key(seed2);

        assert!(key_store.insert(key_id, key.clone(), None).is_ok());

        let retrieved_key = key_store.get(&key_id).unwrap();
        assert_eq!(key, retrieved_key);
    }

    #[test]
    fn should_contain_existing_key(seed1: u64, seed2: u64) {
        let mut key_store = proto_key_store();
        let key_id: KeyId = make_key_id(seed1);

        assert!(key_store
            .insert(key_id, make_secret_key(seed2), None)
            .is_ok());
        assert!(key_store.contains(&key_id));
    }

    #[test]
    fn should_not_contain_nonexisting_key(seed1: u64) {
        let key_store = proto_key_store();
        let non_existing_key_id: KeyId = make_key_id(seed1);

        assert!(!key_store.contains(&non_existing_key_id));
    }

    #[test]
    fn should_remove_existing_key(seed1: u64, seed2: u64) {
        let mut key_store = proto_key_store();
        let key_id: KeyId = make_key_id(seed1);

        assert!(key_store
            .insert(key_id, make_secret_key(seed2), None)
            .is_ok());

        assert!(key_store.get(&key_id).is_some());
        assert!(key_store.remove(&key_id).unwrap());
        assert!(key_store.get(&key_id).is_none());
    }

    #[test]
    fn should_not_remove_nonexisting_key(seed1: u64) {
        let mut key_store = proto_key_store();
        let non_existing_key_id: KeyId = make_key_id(seed1);

        assert!(!key_store.remove(&non_existing_key_id).unwrap());
    }

    #[test]
    fn deleting_twice_should_return_false(seed1: u64, seed2: u64) {
        let mut key_store = proto_key_store();
        let key_id_1: KeyId = make_key_id(seed1);
        let key_1 = make_secret_key(seed2);

        assert!(key_store.insert(key_id_1, key_1, None).is_ok());

        assert!(key_store.remove(&key_id_1).unwrap());
        assert!(!key_store.contains(&key_id_1));
        assert!(!key_store.remove(&key_id_1).unwrap());
    }

    #[test]
    fn no_overwrites(seed1: u64, seed2: u64, seed3: u64) {
        let mut key_store = proto_key_store();
        let key_id_1: KeyId = make_key_id(seed1);
        let key_1 = make_secret_key(seed2);
        let key_2 = make_secret_key(seed3);
        assert_ne!(key_1, key_2);

        key_store.insert(key_id_1, key_1.clone(), None).unwrap();

        assert!(key_store.insert(key_id_1, key_2, None).is_err());
        assert_eq!(key_1, key_store.get(&key_id_1).unwrap());
    }
}

/// Verifies that `retain(..)` removes precisely the expected keys, no more, no
/// less.
#[test]
fn should_retain_expected_keys() {
    let mut key_store = proto_key_store();
    let mut seeds = 0..;
    let mut next_key = || {
        (
            make_key_id(seeds.next().unwrap()),
            make_secret_key(seeds.next().unwrap()),
        )
    };
    let key_with_id_to_retain = next_key();
    let key_with_value_to_retain = next_key();
    let key_to_remove = next_key();
    let key_with_different_scope = next_key();
    let key_with_no_scope = next_key();

    let selected_scope = Scope::Const(ConstScope::Test0);
    let different_scope = Scope::Const(ConstScope::Test1);

    let mut insert_key_with_scope = |pair: &(KeyId, CspSecretKey), scope: Option<Scope>| {
        key_store.insert(pair.0, pair.1.clone(), scope).unwrap();
        assert!(key_store.contains(&pair.0));
    };

    insert_key_with_scope(&key_with_id_to_retain, Some(selected_scope));
    insert_key_with_scope(&key_with_value_to_retain, Some(selected_scope));
    insert_key_with_scope(&key_to_remove, Some(selected_scope));
    insert_key_with_scope(&key_with_different_scope, Some(different_scope));
    insert_key_with_scope(&key_with_no_scope, None);

    let id_to_retain = key_with_id_to_retain.0;
    let value_to_retain = key_with_value_to_retain.1;
    assert!(key_store
        .retain(
            move |id, value| (id == &id_to_retain) || (value == &value_to_retain),
            selected_scope,
        )
        .is_ok());

    assert!(
        key_store.contains(&key_with_id_to_retain.0),
        "Expected to retain key by ID"
    );
    assert!(
        key_store.contains(&key_with_value_to_retain.0),
        "Expected to retain key by value"
    );
    assert!(
        !key_store.contains(&key_to_remove.0),
        "Expected to remove unselected key"
    );
    assert!(
        key_store.contains(&key_with_different_scope.0),
        "Expected to keep key in different scope"
    );
    assert!(
        key_store.contains(&key_with_no_scope.0),
        "Expected to keep key with no scope"
    );
}

#[test]
fn should_deserialize_all_existing_secret_key_stores() {
    for version in SecretKeyStoreVersion::all_versions() {
        let (_temp_dir, secret_key_store) = open_existing_secret_key_store_in_temp_dir(&version);
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
        assert_matches!(
            fs_key,
            CspSecretKey::FsEncryption(CspFsEncryptionKeySet::Groth20WithPop_Bls12_381(..))
        );
    }
}

#[test]
fn should_upgrade_secret_key_store_to_current_sks_version() {
    let (_temp_dir, mut secret_key_store) =
        open_existing_secret_key_store_in_temp_dir(&SecretKeyStoreVersion::V2);
    write_secret_key_store_to_disk(&mut secret_key_store);

    assert_secret_key_store_proto_has_correct_version(
        secret_key_store.proto_file_path(),
        &SecretKeyStoreVersion::V3,
    );
}

//Generate dummy key to ensure that SKS is written to disk
fn write_secret_key_store_to_disk(secret_key_store: &mut ProtoSecretKeyStore) {
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
}

#[test]
fn should_have_scope_for_mega_private_key_that_had_no_scope_before_migration() {
    let (_temp_dir, secret_key_store) =
        open_existing_secret_key_store_in_temp_dir(&SecretKeyStoreVersion::V2);
    let (_csp_key, scope) = with_read_lock(&secret_key_store.keys, |keys| {
        keys.get(&TestVector::mega_encryption().key_id)
            .map(|(csp_key, scope)| (csp_key.to_owned(), scope.to_owned()))
    })
    .expect("missing MEGa private key");

    assert_eq!(scope, Some(IDKG_MEGA_SCOPE));
}

#[test]
fn should_be_idempotent_when_opening_secret_key_store() {
    for version in SecretKeyStoreVersion::all_versions() {
        let (temp_dir, secret_key_store) = open_existing_secret_key_store_in_temp_dir(&version);
        let secret_keys_after_first_opening =
            with_read_lock(&secret_key_store.keys, |keys| Some(keys.clone()));

        let secret_key_store = ProtoSecretKeyStore::open(
            temp_dir.path(),
            secret_key_store
                .proto_file_path()
                .file_name()
                .expect("missing file name")
                .to_str()
                .expect("invalid UTF-8 characters"),
            None,
        );
        let secret_keys_after_second_opening =
            with_read_lock(&secret_key_store.keys, |keys| Some(keys.clone()));

        assert_eq!(
            secret_keys_after_first_opening,
            secret_keys_after_second_opening
        );
    }
}

#[test]
fn should_fail_to_write_to_read_only_secret_key_store_directory() {
    let (temp_dir, mut secret_key_store) =
        open_existing_secret_key_store_in_temp_dir(&SecretKeyStoreVersion::V2);
    let mut seed = ChaCha20Rng::seed_from_u64(42);
    let key_id = KeyId::from(seed.gen::<[u8; 32]>());
    let key = CspSecretKey::Ed25519(ed25519_types::SecretKeyBytes(
        SecretArray::new_and_dont_zeroize_argument(&seed.gen()),
    ));

    // make the crypto root directory non-writeable, causing the subsequent call to insert a
    // new key into the key store to fail
    fs::set_permissions(temp_dir.path(), Permissions::from_mode(0o400))
        .expect("Could not set the permissions of the temp dir.");

    assert_matches!(
        secret_key_store.insert(key_id, key, None),
        Err(SecretKeyStoreError::PersistenceError(
            SecretKeyStorePersistenceError::IoError(msg)
        ))
        if msg.to_lowercase().contains("secret key store internal error writing protobuf using tmp file: permission denied")
    );

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
    format!("sks_data_v{}.pb", version.as_u32())
}

fn open_existing_secret_key_store_in_temp_dir(
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

    fn as_u32(&self) -> u32 {
        match self {
            SecretKeyStoreVersion::V2 => 2,
            SecretKeyStoreVersion::V3 => 3,
        }
    }
}

fn assert_secret_key_store_proto_has_correct_version(
    sks_data_file: &Path,
    version: &SecretKeyStoreVersion,
) {
    let data = fs::read(sks_data_file).expect("error reading SKS");
    let sks_proto = pb::SecretKeyStore::decode(&*data).expect("error parsing SKS data");
    let actual_version = sks_proto.version;
    assert_eq!(actual_version, version.as_u32());
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
            secret_key: CspSecretKey::TlsEd25519(TlsEd25519SecretKeyDerBytes::new(vec![
                48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32, 155, 183, 227, 248, 2,
                202, 222, 165, 100, 242, 173, 163, 239, 23, 85, 16, 84, 8, 182, 46, 199, 93, 167,
                71, 223, 94, 157, 198, 73, 52, 6, 130,
            ])),
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
                3, 213, 89, 237, 206, 111, 232, 127, 10, 11, 181, 243, 38, 72, 166, 209, 32, 134,
                57, 134, 26, 137, 214, 20, 11, 226, 134, 194, 19, 87, 70, 26, 243,
            ],
        )
        .expect("invalid public key");
        let private_key = MEGaPrivateKey::deserialize(
            EccCurveType::K256,
            &[
                30, 138, 154, 17, 223, 252, 133, 244, 207, 36, 180, 75, 159, 242, 208, 133, 142,
                127, 2, 199, 54, 174, 218, 236, 183, 244, 233, 123, 244, 50, 179, 189,
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
