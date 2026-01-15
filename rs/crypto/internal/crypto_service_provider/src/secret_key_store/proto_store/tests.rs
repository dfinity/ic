use super::*;
use crate::canister_threshold::IDKG_MEGA_SCOPE;
use crate::secret_key_store::temp_secret_key_store::TempSecretKeyStore;
use crate::secret_key_store::test_utils::{make_key_id, make_secret_key};
use crate::secret_key_store::{
    Scope, SecretKeyStore, SecretKeyStoreInsertionError, scope::ConstScope,
};
use crate::types::CspSecretKey;
use assert_matches::assert_matches;
use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
use ic_crypto_internal_csp_test_utils::files::mk_temp_dir_with_permissions;
use ic_crypto_internal_multi_sig_bls12381::types::SecretKeyBytes;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::types::CspFsEncryptionKeySet;
use ic_crypto_internal_threshold_sig_canister_threshold_sig::{
    EccCurveType, MEGaKeySetK256Bytes, MEGaPrivateKey, MEGaPrivateKeyK256Bytes, MEGaPublicKey,
    MEGaPublicKeyK256Bytes,
};
use ic_crypto_internal_tls::TlsEd25519SecretKeyDerBytes;
use ic_crypto_secrets_containers::SecretArray;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use proptest::prelude::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use tempfile::{TempDir, tempdir as tempdir_deleted_at_end_of_scope};

#[test]
#[should_panic]
fn open_should_panic_for_paths_that_do_not_exist() {
    let dir_path = {
        let dir = tempdir_deleted_at_end_of_scope().unwrap();
        format!("{}", dir.path().display())
    };
    ProtoSecretKeyStore::open(
        Path::new(&dir_path),
        "dummy_file",
        None,
        Arc::new(CryptoMetrics::none()),
    );
}

#[test]
#[should_panic]
fn open_should_panic_for_paths_that_are_widely_readable() {
    let dir = mk_temp_dir_with_permissions(0o744);
    ProtoSecretKeyStore::open(
        dir.as_ref(),
        "dummy_file",
        None,
        Arc::new(CryptoMetrics::none()),
    );
}

#[test]
fn should_not_leak_any_data_on_protobuf_deserialization_error_when_opening_key_store() {
    let temp_dir = tempfile::Builder::new()
        .prefix("ic_crypto_")
        .tempdir()
        .expect("failed to create temporary crypto directory");
    fs::set_permissions(temp_dir.path(), Permissions::from_mode(0o700)).unwrap_or_else(|_| {
        panic!(
            "failed to set permissions of crypto directory {}",
            temp_dir.path().display()
        )
    });
    let sks_file_name = "temp_sks_data.pb";
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(temp_dir.path().join(sks_file_name))
        .unwrap();
    use std::os::unix::fs::FileExt;
    file.write_all_at(b"invalid-protobuf-data", 0)
        .expect("failed to write");

    let panic_msg = catch_unwind(AssertUnwindSafe(|| {
        ProtoSecretKeyStore::open(
            temp_dir.path(),
            sks_file_name,
            None,
            Arc::new(CryptoMetrics::none()),
        );
    }));
    assert_eq!(
        "error parsing SKS protobuf data",
        *panic_msg.unwrap_err().downcast_ref::<&str>().unwrap()
    );
}

#[test]
fn should_not_leak_any_data_on_cbor_deserialization_error_when_opening_key_store() {
    let rng = &mut reproducible_rng();
    let temp_dir = tempfile::Builder::new()
        .prefix("ic_crypto_")
        .tempdir()
        .expect("failed to create temporary crypto directory");
    fs::set_permissions(temp_dir.path(), Permissions::from_mode(0o700)).unwrap_or_else(|_| {
        panic!(
            "failed to set permissions of crypto directory {}",
            temp_dir.path().display()
        )
    });
    let temp_file = "temp_sks_data.pb";
    let mut key_store = ProtoSecretKeyStore::open(
        temp_dir.path(),
        temp_file,
        None,
        Arc::new(CryptoMetrics::none()),
    );
    let key_id: KeyId = KeyId::from([1; 32]);
    let key = make_secret_key(rng);
    assert!(key_store.insert(key_id, key, None).is_ok());

    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(temp_dir.path().join(temp_file))
        .unwrap();

    use std::os::unix::fs::FileExt;
    // Found index 74 by printing the cbor-encoded data in
    // `sks_proto_to_secret_keys` and then looking where this data starts in
    // the file with `std::fs::read`.
    file.write_all_at(b"not-a-cbor-header", 74)
        .expect("failed to write");

    let panic_msg = catch_unwind(AssertUnwindSafe(|| {
        ProtoSecretKeyStore::open(
            temp_dir.path(),
            temp_file,
            None,
            Arc::new(CryptoMetrics::none()),
        );
    }));
    assert_eq!(
        "Error deserializing key with ID KeyId(0x0101010101010101010101010101010101010101010101010101010101010101)",
        *panic_msg.unwrap_err().downcast_ref::<String>().unwrap()
    );
}

#[test]
#[should_panic(expected = "is not a regular file")]
fn open_should_panic_if_secret_keystore_is_a_symbolic_link() {
    let (temp_dir, _secret_key_store) = open_existing_secret_key_store_in_temp_dir(
        &SecretKeyStoreVersion::V3,
        CryptoMetrics::none(),
        None,
    );
    let original_sks_path_and_filename = temp_dir.as_ref().join(
        existing_secret_key_store_file_name(&SecretKeyStoreVersion::V3),
    );
    let symbolic_link_filename = format!(
        "{}.test",
        existing_secret_key_store_file_name(&SecretKeyStoreVersion::V3)
    );
    let symbolic_link_path_and_filename = temp_dir.as_ref().join(&symbolic_link_filename);
    std::os::unix::fs::symlink(
        original_sks_path_and_filename,
        symbolic_link_path_and_filename,
    )
    .expect("error creating symbolic link");

    let _opened_sks = ProtoSecretKeyStore::open(
        temp_dir.as_ref(),
        &symbolic_link_filename,
        None,
        Arc::new(CryptoMetrics::none()),
    );
}

#[test]
#[should_panic(expected = "is not a regular file")]
fn open_should_panic_if_secret_keystore_is_a_directory() {
    let (temp_dir, _secret_key_store) = open_existing_secret_key_store_in_temp_dir(
        &SecretKeyStoreVersion::V3,
        CryptoMetrics::none(),
        None,
    );
    let sks_file_name = format!(
        "{}.test",
        existing_secret_key_store_file_name(&SecretKeyStoreVersion::V3)
    );
    let name_of_dir_inside_temp_dir = temp_dir.as_ref().join(&sks_file_name);
    fs::create_dir(name_of_dir_inside_temp_dir).expect("error creating directory inside temp dir");

    let _opened_sks = ProtoSecretKeyStore::open(
        temp_dir.as_ref(),
        &sks_file_name,
        None,
        Arc::new(CryptoMetrics::none()),
    );
}
#[test]
fn should_retrieve_inserted_key() {
    let rng = &mut reproducible_rng();
    let mut key_store = proto_key_store();
    let key_id: KeyId = make_key_id(rng);
    let key = make_secret_key(rng);

    assert!(key_store.insert(key_id, key.clone(), None).is_ok());

    let retrieved_key = key_store.get(&key_id).unwrap();
    assert_eq!(key, retrieved_key);
}

#[test]
fn should_contain_existing_key() {
    let rng = &mut reproducible_rng();
    let mut key_store = proto_key_store();
    let key_id: KeyId = make_key_id(rng);

    assert!(key_store.insert(key_id, make_secret_key(rng), None).is_ok());
    assert!(key_store.contains(&key_id));
}

#[test]
fn should_not_contain_nonexisting_key() {
    let rng = &mut reproducible_rng();
    let key_store = proto_key_store();
    let non_existing_key_id: KeyId = make_key_id(rng);

    assert!(!key_store.contains(&non_existing_key_id));
}

#[test]
fn should_remove_existing_key() {
    let rng = &mut reproducible_rng();
    let mut key_store = proto_key_store();
    let key_id: KeyId = make_key_id(rng);

    assert!(key_store.insert(key_id, make_secret_key(rng), None).is_ok());

    assert!(key_store.get(&key_id).is_some());
    assert!(key_store.remove(&key_id).unwrap());
    assert!(key_store.get(&key_id).is_none());
}

#[test]
fn should_not_remove_nonexisting_key() {
    let rng = &mut reproducible_rng();
    let mut key_store = proto_key_store();
    let non_existing_key_id: KeyId = make_key_id(rng);

    assert!(!key_store.remove(&non_existing_key_id).unwrap());
}

#[test]
fn deleting_twice_should_return_false() {
    let rng = &mut reproducible_rng();
    let mut key_store = proto_key_store();
    let key_id_1: KeyId = make_key_id(rng);
    let key_1 = make_secret_key(rng);

    assert!(key_store.insert(key_id_1, key_1, None).is_ok());

    assert!(key_store.remove(&key_id_1).unwrap());
    assert!(!key_store.contains(&key_id_1));
    assert!(!key_store.remove(&key_id_1).unwrap());
}

#[test]
fn no_overwrites() {
    let rng = &mut reproducible_rng();
    let mut key_store = proto_key_store();
    let key_id_1: KeyId = make_key_id(rng);
    let key_1 = make_secret_key(rng);
    let key_2 = make_secret_key(rng);
    assert_ne!(key_1, key_2);

    key_store.insert(key_id_1, key_1.clone(), None).unwrap();

    assert!(key_store.insert(key_id_1, key_2, None).is_err());
    assert_eq!(key_1, key_store.get(&key_id_1).unwrap());
}

#[test]
fn should_deserialize_all_existing_secret_key_stores() {
    for version in SecretKeyStoreVersion::all_versions() {
        let (_temp_dir, secret_key_store) =
            open_existing_secret_key_store_in_temp_dir(&version, CryptoMetrics::none(), None);
        assert_eq!(secret_key_store.keys.len(), 5);

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
    let (_temp_dir, mut secret_key_store) = open_existing_secret_key_store_in_temp_dir(
        &SecretKeyStoreVersion::V2,
        CryptoMetrics::none(),
        None,
    );
    write_secret_key_store_to_disk(&mut secret_key_store);

    assert_secret_key_store_proto_has_correct_version(
        secret_key_store.proto_file_path(),
        &SecretKeyStoreVersion::V3,
    );
}

//Generate dummy key to ensure that SKS is written to disk
fn write_secret_key_store_to_disk(secret_key_store: &mut ProtoSecretKeyStore) {
    let rng = &mut reproducible_rng();
    let (key_id, secret_key) = (make_key_id(rng), make_secret_key(rng));
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
    let (_temp_dir, secret_key_store) = open_existing_secret_key_store_in_temp_dir(
        &SecretKeyStoreVersion::V2,
        CryptoMetrics::none(),
        None,
    );
    let (_csp_key, scope) = secret_key_store
        .keys
        .get(&TestVector::mega_encryption().key_id)
        .map(|(csp_key, scope)| (csp_key.to_owned(), scope.to_owned()))
        .expect("missing MEGa private key");

    assert_eq!(scope, Some(IDKG_MEGA_SCOPE));
}

#[test]
fn should_be_idempotent_when_opening_secret_key_store() {
    for version in SecretKeyStoreVersion::all_versions() {
        let (temp_dir, secret_key_store) =
            open_existing_secret_key_store_in_temp_dir(&version, CryptoMetrics::none(), None);
        let secret_keys_after_first_opening = secret_key_store.keys.clone();

        let secret_key_store = ProtoSecretKeyStore::open(
            temp_dir.path(),
            secret_key_store
                .proto_file_path()
                .file_name()
                .expect("missing file name")
                .to_str()
                .expect("invalid UTF-8 characters"),
            None,
            Arc::new(CryptoMetrics::none()),
        );
        let secret_keys_after_second_opening = secret_key_store.keys.clone();

        assert_eq!(
            secret_keys_after_first_opening,
            secret_keys_after_second_opening
        );
    }
}

#[test]
fn should_fail_to_write_to_read_only_secret_key_store_directory() {
    let (temp_dir, mut secret_key_store) = open_existing_secret_key_store_in_temp_dir(
        &SecretKeyStoreVersion::V2,
        CryptoMetrics::none(),
        None,
    );
    let mut seed = ChaCha20Rng::seed_from_u64(42);
    let key_id = KeyId::from(seed.r#gen::<[u8; 32]>());
    let key = CspSecretKey::Ed25519(ed25519_types::SecretKeyBytes(
        SecretArray::new_and_dont_zeroize_argument(&seed.r#gen()),
    ));

    // make the crypto root directory non-writeable, causing the subsequent call to insert a
    // new key into the key store to fail
    fs::set_permissions(temp_dir.path(), Permissions::from_mode(0o400))
        .expect("Could not set the permissions of the temp dir.");

    assert_matches!(
        secret_key_store.insert(key_id, key, None),
        Err(SecretKeyStoreInsertionError::TransientError(msg))
        if msg.to_lowercase().contains("secret key store internal error writing protobuf using tmp file: permission denied")
    );

    fs::set_permissions(temp_dir.path(), Permissions::from_mode(0o700)).expect(
        "failed to change permissions of temp_dir so that writing is possible \
                again, so that the directory can automatically be cleaned up",
    );
}

#[test]
fn should_fail_to_write_to_secret_key_store_directory_without_execute_permissions() {
    let (temp_dir, mut secret_key_store) = open_existing_secret_key_store_in_temp_dir(
        &SecretKeyStoreVersion::V3,
        CryptoMetrics::none(),
        None,
    );
    let mut seed = ChaCha20Rng::seed_from_u64(42);
    let key_id = KeyId::from(seed.r#gen::<[u8; 32]>());
    let key = CspSecretKey::Ed25519(ed25519_types::SecretKeyBytes(
        SecretArray::new_and_dont_zeroize_argument(&seed.r#gen()),
    ));

    // make the crypto root directory non-executable, causing the subsequent call to insert a
    // new key into the key store to fail
    fs::set_permissions(temp_dir.path(), Permissions::from_mode(0o600))
        .expect("Could not set the permissions of the temp dir.");

    assert_matches!(
        secret_key_store.insert(key_id, key, None),
        Err(SecretKeyStoreInsertionError::TransientError(msg))
        if msg.to_lowercase().contains("permission denied")
    );

    fs::set_permissions(temp_dir.path(), Permissions::from_mode(0o700)).expect(
        "failed to change permissions of temp_dir so that writing is possible \
                again, so that the directory can automatically be cleaned up",
    );
}

#[test]
fn should_fail_to_write_to_secret_key_store_directory_without_write_permissions() {
    let (temp_dir, mut secret_key_store) = open_existing_secret_key_store_in_temp_dir(
        &SecretKeyStoreVersion::V3,
        CryptoMetrics::none(),
        None,
    );
    let mut seed = ChaCha20Rng::seed_from_u64(42);
    let key_id = KeyId::from(seed.r#gen::<[u8; 32]>());
    let key = CspSecretKey::Ed25519(ed25519_types::SecretKeyBytes(
        SecretArray::new_and_dont_zeroize_argument(&seed.r#gen()),
    ));

    // make the crypto root directory non-writeable, causing the subsequent call to insert a
    // new key into the key store to fail
    fs::set_permissions(temp_dir.path(), Permissions::from_mode(0o500))
        .expect("Could not set the permissions of the temp dir.");

    assert_matches!(
        secret_key_store.insert(key_id, key, None),
        Err(SecretKeyStoreInsertionError::TransientError(msg))
        if msg.to_lowercase().contains("permission denied")
    );

    fs::set_permissions(temp_dir.path(), Permissions::from_mode(0o700)).expect(
        "failed to change permissions of temp_dir so that writing is possible \
                again, so that the directory can automatically be cleaned up",
    );
}

#[test]
fn should_successfully_write_to_secret_key_store_directory_with_write_and_execute_permissions() {
    let (temp_dir, mut secret_key_store) = open_existing_secret_key_store_in_temp_dir(
        &SecretKeyStoreVersion::V2,
        CryptoMetrics::none(),
        None,
    );
    fs::set_permissions(temp_dir.path(), Permissions::from_mode(0o700))
        .expect("Could not set the permissions of the temp dir.");
    let mut seed = ChaCha20Rng::seed_from_u64(42);
    let key_id = KeyId::from(seed.r#gen::<[u8; 32]>());
    let key = CspSecretKey::Ed25519(ed25519_types::SecretKeyBytes(
        SecretArray::new_and_dont_zeroize_argument(&seed.r#gen()),
    ));
    assert_matches!(secret_key_store.insert(key_id, key, None), Ok(()));
}

mod retain {
    use super::*;
    use std::fs;
    use std::time::UNIX_EPOCH;

    #[test]
    fn should_retain_expected_keys_with_specified_scope_and_not_remove_keys_with_non_matching_scope()
     {
        let mut key_store = proto_key_store();
        let rng = &mut reproducible_rng();
        let mut next_key = || (make_key_id(rng), make_secret_key(rng));
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
        assert!(
            key_store
                .retain(
                    move |id, value| (id == &id_to_retain) || (value == &value_to_retain),
                    selected_scope,
                )
                .is_ok()
        );

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
    fn should_succeed_on_empty_secret_key_store() {
        let rng = &mut reproducible_rng();
        let mut key_store = proto_key_store();
        let selected_scope = Scope::Const(ConstScope::Test0);
        let id_to_retain = make_key_id(rng);
        let value_to_retain = make_secret_key(rng);

        assert_eq!(key_store.retain(|_, _| true, selected_scope), Ok(()));
        assert_eq!(key_store.retain(|_, _| false, selected_scope), Ok(()));
        assert_eq!(
            key_store.retain(move |id, _| id == &id_to_retain, selected_scope),
            Ok(())
        );
        assert_eq!(
            key_store.retain(move |_, value| value == &value_to_retain, selected_scope),
            Ok(())
        );
    }

    #[test]
    fn should_not_modify_secret_key_store_on_disk_when_retain_is_a_nop() {
        let rng = &mut reproducible_rng();
        let (_temp_dir, mut key_store, file) = temp_proto_secret_key_store_and_file_path();
        let selected_scope = Scope::Const(ConstScope::Test0);
        let key_id = make_key_id(rng);
        let key_value = make_secret_key(rng);

        key_store
            .insert(key_id, key_value, Some(selected_scope))
            .expect("insert should succeed");
        let initial_modified_time = file_modified_time_in_nanoseconds(&file);

        assert_eq!(
            key_store.retain(move |id, _| id == &key_id, selected_scope),
            Ok(())
        );
        assert!(key_store.contains(&key_id));
        assert_eq!(
            file_modified_time_in_nanoseconds(&file),
            initial_modified_time
        );
    }

    #[test]
    fn should_succeed_when_retaining_non_existing_key_by_key_id() {
        let rng = &mut reproducible_rng();
        let mut key_store = proto_key_store();
        let selected_scope = Scope::Const(ConstScope::Test0);
        let key_id = make_key_id(rng);
        let key_value = make_secret_key(rng);
        let key_id_to_retain = make_key_id(rng);

        key_store
            .insert(key_id, key_value, Some(selected_scope))
            .expect("insert should succeed");

        assert_eq!(
            key_store.retain(move |id, _| id == &key_id_to_retain, selected_scope),
            Ok(())
        );
        assert!(!key_store.contains(&key_id));
    }

    #[test]
    fn should_succeed_when_retaining_non_existing_key_by_key_value() {
        let rng = &mut reproducible_rng();
        let mut key_store = proto_key_store();
        let selected_scope = Scope::Const(ConstScope::Test0);
        let key_id = make_key_id(rng);
        let key_value = make_secret_key(rng);
        let key_value_to_retain = make_secret_key(rng);

        key_store
            .insert(key_id, key_value, Some(selected_scope))
            .expect("insert should succeed");

        assert_eq!(
            key_store.retain(
                move |_, value| value == &key_value_to_retain,
                selected_scope
            ),
            Ok(())
        );
        assert!(!key_store.contains(&key_id));
    }

    #[test]
    fn should_not_remove_if_filter_matches_but_scope_does_not_match() {
        let rng = &mut reproducible_rng();
        let mut key_store = proto_key_store();
        let selected_scope = Scope::Const(ConstScope::Test0);
        let different_scope = Scope::Const(ConstScope::Test1);
        let key_id = make_key_id(rng);
        let key_value = make_secret_key(rng);

        key_store
            .insert(key_id, key_value, Some(selected_scope))
            .expect("insert should succeed");

        assert_eq!(
            key_store.retain(move |id, _| id == &key_id, different_scope),
            Ok(())
        );
        assert!(key_store.contains(&key_id));
    }

    #[test]
    #[should_panic(expected = "retain filter panicked!")]
    fn should_panic_if_retain_filter_panics() {
        let rng = &mut reproducible_rng();
        let mut key_store = proto_key_store();
        let selected_scope = Scope::Const(ConstScope::Test0);
        let key_id = make_key_id(rng);
        key_store
            .insert(key_id, make_secret_key(rng), Some(selected_scope))
            .expect("insert should succeed");

        assert_eq!(
            key_store.retain(
                move |_, _| panic!("retain filter panicked!"),
                selected_scope
            ),
            Ok(())
        );
    }

    fn file_modified_time_in_nanoseconds(path: &PathBuf) -> u128 {
        fs::metadata(path)
            .expect("getting file metadata should succeed")
            .modified()
            .expect("getting modification time should succeed")
            .duration_since(UNIX_EPOCH)
            .expect("getting duration since unix epoch should succeed")
            .as_nanos()
    }

    fn temp_proto_secret_key_store_and_file_path() -> (TempDir, ProtoSecretKeyStore, PathBuf) {
        let temp_dir: TempDir = mk_temp_dir_with_permissions(0o700);
        let sks_filename = "sks_data.pb";
        let key_store = ProtoSecretKeyStore::open(
            temp_dir.path(),
            sks_filename,
            None,
            Arc::new(CryptoMetrics::none()),
        );
        let file = temp_dir.path().join(sks_filename);
        (temp_dir, key_store, file)
    }
}

mod retain_would_modify_keystore {
    use super::*;

    #[test]
    fn should_return_true_if_some_keys_match_scope_but_not_filter() {
        let mut key_store = proto_key_store();
        let rng = &mut reproducible_rng();
        let mut next_key = || (make_key_id(rng), make_secret_key(rng));
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

        assert!(key_store.retain_would_modify_keystore(
            move |id, value| (id == &id_to_retain) || (value == &value_to_retain),
            selected_scope,
        ));
    }

    #[test]
    fn should_return_false_on_empty_secret_key_store() {
        let rng = &mut reproducible_rng();
        let key_store = proto_key_store();
        let selected_scope = Scope::Const(ConstScope::Test0);
        let id_to_retain = make_key_id(rng);
        let value_to_retain = make_secret_key(rng);

        assert!(!key_store.retain_would_modify_keystore(|_, _| true, selected_scope));
        assert!(!key_store.retain_would_modify_keystore(|_, _| false, selected_scope));
        assert!(
            !key_store
                .retain_would_modify_keystore(move |id, _| id == &id_to_retain, selected_scope)
        );
        assert!(!key_store.retain_would_modify_keystore(
            move |_, value| value == &value_to_retain,
            selected_scope
        ));
    }

    #[test]
    fn should_return_true_when_retaining_non_existing_key_by_key_id() {
        let rng = &mut reproducible_rng();
        let mut key_store = proto_key_store();
        let selected_scope = Scope::Const(ConstScope::Test0);
        let key_id = make_key_id(rng);
        let key_value = make_secret_key(rng);
        let key_id_to_retain = make_key_id(rng);

        key_store
            .insert(key_id, key_value, Some(selected_scope))
            .expect("insert should succeed");

        assert!(
            key_store
                .retain_would_modify_keystore(move |id, _| id == &key_id_to_retain, selected_scope)
        );
    }

    #[test]
    fn should_return_true_when_retaining_non_existing_key_by_key_value() {
        let rng = &mut reproducible_rng();
        let mut key_store = proto_key_store();
        let selected_scope = Scope::Const(ConstScope::Test0);
        let key_id = make_key_id(rng);
        let key_value = make_secret_key(rng);
        let key_value_to_retain = make_secret_key(rng);

        key_store
            .insert(key_id, key_value, Some(selected_scope))
            .expect("insert should succeed");

        assert!(key_store.retain_would_modify_keystore(
            move |_, value| value == &key_value_to_retain,
            selected_scope
        ));
    }

    #[test]
    fn should_return_false_if_filter_matches_but_scope_does_not_match() {
        let rng = &mut reproducible_rng();
        let mut key_store = proto_key_store();
        let selected_scope = Scope::Const(ConstScope::Test0);
        let different_scope = Scope::Const(ConstScope::Test1);
        let key_id = make_key_id(rng);
        let key_value = make_secret_key(rng);

        key_store
            .insert(key_id, key_value, Some(selected_scope))
            .expect("insert should succeed");

        assert!(
            !key_store.retain_would_modify_keystore(move |id, _| id == &key_id, different_scope)
        );
    }

    #[test]
    #[should_panic(expected = "retain filter panicked!")]
    fn should_panic_if_retain_filter_panics() {
        let rng = &mut reproducible_rng();
        let mut key_store = proto_key_store();
        let selected_scope = Scope::Const(ConstScope::Test0);
        let key_id = make_key_id(rng);
        key_store
            .insert(key_id, make_secret_key(rng), Some(selected_scope))
            .expect("insert should succeed");

        let _would_modify = key_store.retain_would_modify_keystore(
            move |_, _| panic!("retain filter panicked!"),
            selected_scope,
        );
    }
}

mod zeroize_old_secret_key_store {
    use super::*;
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities_in_memory_logger::InMemoryReplicaLogger;
    use std::fs;

    #[test]
    fn should_overwrite_old_secret_key_store_with_zeroes() {
        let rng = &mut reproducible_rng();
        let mut setup = Setup::new();
        ic_sys::fs::create_hard_link_to_existing_file(
            &setup.secret_key_store.proto_file,
            &setup.hard_link_to_test_zeroization,
        )
        .expect("error creating hard link to existing secret key store file");

        let key_id = make_key_id(rng);
        let key = make_secret_key(rng);
        setup
            .secret_key_store
            .insert(key_id, key, None)
            .expect("error inserting key in secret key store");

        assert_contains_only_zeroes(&setup.hard_link_to_test_zeroization);
    }

    #[test]
    fn should_not_overwrite_new_keystore_with_zeroes() {
        let rng = &mut reproducible_rng();
        let mut setup = Setup::new();
        ic_sys::fs::create_hard_link_to_existing_file(
            &setup.secret_key_store.proto_file,
            &setup.hard_link_to_test_zeroization,
        )
        .expect("error creating hard link to existing secret key store file");

        let key_id = make_key_id(rng);
        let key = make_secret_key(rng);
        setup
            .secret_key_store
            .insert(key_id, key, None)
            .expect("error inserting key in secret key store");

        assert_contains_only_zeroes(&setup.hard_link_to_test_zeroization);
        assert!(setup.secret_key_store.contains(&key_id));
    }

    #[test]
    fn should_overwrite_leftover_backup_copy_with_zeroes_when_opening_secret_key_store() {
        let setup = Setup::new();
        fs::copy(
            &setup.secret_key_store.proto_file,
            &setup.secret_key_store.old_proto_file_to_zeroize,
        )
        .expect("error copying sks");
        ic_sys::fs::create_hard_link_to_existing_file(
            &setup.secret_key_store.old_proto_file_to_zeroize,
            &setup.hard_link_to_test_zeroization,
        )
        .expect("error creating hard link to old secret key store file");

        let _opened_sks = ProtoSecretKeyStore::open(
            setup.temp_dir.as_ref(),
            &existing_secret_key_store_file_name(&SecretKeyStoreVersion::V3),
            None,
            Arc::new(CryptoMetrics::none()),
        );

        assert_contains_only_zeroes(&setup.hard_link_to_test_zeroization);
    }

    #[test]
    fn should_cleanup_leftover_backup_file_of_zero_length_when_opening_secret_key_store() {
        let setup = Setup::new();
        let _old_sks_file =
            std::fs::File::create(&setup.secret_key_store.old_proto_file_to_zeroize)
                .expect("error creating empty old secret key store file");
        assert!(
            Path::try_exists(&setup.secret_key_store.old_proto_file_to_zeroize)
                .expect("error checking if old secret key store file exists")
        );

        let _opened_sks = ProtoSecretKeyStore::open(
            setup.temp_dir.as_ref(),
            &existing_secret_key_store_file_name(&SecretKeyStoreVersion::V3),
            None,
            Arc::new(CryptoMetrics::none()),
        );
        assert!(
            !Path::try_exists(&setup.secret_key_store.old_proto_file_to_zeroize)
                .expect("error checking if old secret key store file exists")
        );
    }

    #[test]
    fn should_overwrite_leftover_backup_copy_with_zeroes_when_opening_non_existing_secret_key_store()
     {
        let setup = Setup::new();
        fs::copy(
            &setup.secret_key_store.proto_file,
            &setup.secret_key_store.old_proto_file_to_zeroize,
        )
        .expect("error copying sks");
        fs::remove_file(&setup.secret_key_store.proto_file)
            .expect("error removing original sks file");
        ic_sys::fs::create_hard_link_to_existing_file(
            &setup.secret_key_store.old_proto_file_to_zeroize,
            &setup.hard_link_to_test_zeroization,
        )
        .expect("error creating hard link to old secret key store file");

        let _opened_sks = ProtoSecretKeyStore::open(
            setup.temp_dir.as_ref(),
            &existing_secret_key_store_file_name(&SecretKeyStoreVersion::V3),
            None,
            Arc::new(CryptoMetrics::none()),
        );

        assert_contains_only_zeroes(&setup.hard_link_to_test_zeroization);
        assert!(
            !Path::try_exists(&setup.secret_key_store.proto_file)
                .expect("error checking if secret key store file exists")
        );
    }

    #[test]
    fn should_only_remove_leftover_hard_linked_duplicate_file_when_opening_secret_key_store() {
        let setup = Setup::new();
        ic_sys::fs::create_hard_link_to_existing_file(
            &setup.secret_key_store.proto_file,
            &setup.secret_key_store.old_proto_file_to_zeroize,
        )
        .expect("error creating hard link from current secret key store file to backup file");
        let initial_sks_bytes = fs::read(&setup.secret_key_store.proto_file)
            .expect("error reading initial secret key store");

        let _opened_sks = ProtoSecretKeyStore::open(
            setup.temp_dir.as_ref(),
            &existing_secret_key_store_file_name(&SecretKeyStoreVersion::V3),
            None,
            Arc::new(CryptoMetrics::none()),
        );

        let current_sks_bytes = fs::read(&setup.secret_key_store.proto_file)
            .expect("error reading current secret key store");
        assert_matches!(
            Path::try_exists(&setup.secret_key_store.old_proto_file_to_zeroize),
            Ok(false)
        );
        assert_eq!(current_sks_bytes, initial_sks_bytes);
    }

    #[test]
    fn should_clean_up_leftover_old_file_when_dropping_secret_key_store() {
        let setup = Setup::new();
        let opened_sks = ProtoSecretKeyStore::open(
            setup.temp_dir.as_ref(),
            &existing_secret_key_store_file_name(&SecretKeyStoreVersion::V3),
            None,
            Arc::new(CryptoMetrics::none()),
        );
        assert!(
            !Path::try_exists(&setup.secret_key_store.old_proto_file_to_zeroize)
                .expect("error checking if old secret key store file exists")
        );
        fs::copy(
            &setup.secret_key_store.proto_file,
            &setup.secret_key_store.old_proto_file_to_zeroize,
        )
        .expect("error copying sks");
        ic_sys::fs::create_hard_link_to_existing_file(
            &setup.secret_key_store.old_proto_file_to_zeroize,
            &setup.hard_link_to_test_zeroization,
        )
        .expect("error creating hard link to old secret key store file");
        drop(opened_sks);
        assert!(
            !Path::try_exists(&setup.secret_key_store.old_proto_file_to_zeroize)
                .expect("error checking if old secret key store file exists")
        );

        assert_contains_only_zeroes(&setup.hard_link_to_test_zeroization);
        assert!(
            Path::try_exists(&setup.secret_key_store.proto_file)
                .expect("error checking if secret key store file exists")
        );
    }

    mod metrics {
        use super::*;
        use ic_crypto_test_utils_metrics::assertions::MetricsObservationsAssert;

        #[test]
        fn should_not_observe_any_metrics_if_zeroization_and_cleanup_succeeds_for_existing_keystore()
         {
            // Perform setup that sets up an existing SKS
            let mut setup = Setup::new();

            // Generate and insert a key into the SKS, triggering zeroization and
            // cleanup of the old SKS file
            let rng = &mut reproducible_rng();
            let key_id = make_key_id(rng);
            let key = make_secret_key(rng);
            setup
                .secret_key_store
                .insert(key_id, key, None)
                .expect("error inserting key in secret key store");

            MetricsObservationsAssert::assert_that(setup.metrics)
                .contains_crypto_secret_key_store_cleanup_error(0);
        }

        #[test]
        fn should_not_observe_any_metrics_if_zeroization_and_cleanup_succeeds_for_new_keystore() {
            // Create a temp dir for storing the SKS
            let temp_dir: TempDir = mk_temp_dir_with_permissions(0o700);
            let metrics = MetricsRegistry::new();
            let crypto_metrics = CryptoMetrics::new(Some(&metrics));
            // Open a non-existing SKS in the temp dir, which will initialize a `ProtoSecretKeyStore`
            // struct, but will not write anything to disk.
            let mut secret_key_store = ProtoSecretKeyStore::open(
                temp_dir.path(),
                "sks_data.pb",
                None,
                Arc::new(crypto_metrics),
            );
            assert_matches!(Path::try_exists(&secret_key_store.proto_file), Ok(false));
            assert_matches!(
                Path::try_exists(&secret_key_store.old_proto_file_to_zeroize),
                Ok(false)
            );

            // Generate and insert a key to the SKS, which will trigger a write to disk. The
            // zeroization code will be triggered, but there will be no old SKS file to clean up.
            let rng = &mut reproducible_rng();
            let key_id = make_key_id(rng);
            let key = make_secret_key(rng);
            secret_key_store
                .insert(key_id, key, Some(Scope::Const(ConstScope::Test0)))
                .expect("error inserting key in secret key store");
            assert_matches!(
                Path::try_exists(&secret_key_store.old_proto_file_to_zeroize),
                Ok(false)
            );

            // No cleanup error metrics should be observed when trying to clean up a non-existing SKS
            MetricsObservationsAssert::assert_that(metrics)
                .contains_crypto_secret_key_store_cleanup_error(0);
        }

        #[test]
        fn should_observe_cleanup_error_metrics_on_write_if_inode_of_current_and_old_sks_are_the_same()
         {
            let mut setup = Setup::new();
            // Make the current and old SKS files point to the same inode. This is a reasonable
            // situation if e.g., the vault process crashed during
            // `[ProtoSecretKeyStore::write_secret_keys_to_disk]`, `[ProtoSecretKeyStore::drop]` was
            // not executed, and the old SKS file was not cleaned up. However, on the next startup
            // of the vault process, this situation should be cleaned up.
            // This situation is NOT expected to occur once the vault process is running. In
            // particular, it is not expected to be the current state when
            // `[ProtoSecretKeyStore::write_secret_keys_to_disk]` is called. It is therefore treated
            // internally as an error, and the cleanup error metric counter is expected to be
            // incremented.
            ic_sys::fs::create_hard_link_to_existing_file(
                &setup.secret_key_store.proto_file,
                &setup.secret_key_store.old_proto_file_to_zeroize,
            )
            .expect("error creating hard link from current secret key store file to backup file");
            let rng = &mut reproducible_rng();
            let key_id = make_key_id(rng);
            let key = make_secret_key(rng);
            setup
                .secret_key_store
                .insert(key_id, key, None)
                .expect("error inserting key in secret key store");

            MetricsObservationsAssert::assert_that(setup.metrics)
                .contains_crypto_secret_key_store_cleanup_error(1);
        }
    }

    mod logging {
        use super::*;
        use ic_test_utilities_in_memory_logger::assertions::LogEntriesAssert;
        use slog::Level;

        #[test]
        fn should_log_warning_on_write_if_inode_of_current_and_old_sks_are_the_same() {
            let mut setup = Setup::new();
            // Make the current and old SKS files point to the same inode. This is a reasonable
            // situation if e.g., the vault process crashed during
            // `[ProtoSecretKeyStore::write_secret_keys_to_disk]`, `[ProtoSecretKeyStore::drop]` was
            // not executed, and the old SKS file was not cleaned up. However, on the next startup
            // of the vault process, this situation should be cleaned up.
            // This situation is NOT expected to occur once the vault process is running. In
            // particular, it is not expected to be the current state when
            // `[ProtoSecretKeyStore::write_secret_keys_to_disk]` is called. It is therefore treated
            // internally as an error, and a cleanup error log warning is expected to be written.
            ic_sys::fs::create_hard_link_to_existing_file(
                &setup.secret_key_store.proto_file,
                &setup.secret_key_store.old_proto_file_to_zeroize,
            )
            .expect("error creating hard link from current secret key store file to backup file");
            let rng = &mut reproducible_rng();
            let key_id = make_key_id(rng);
            let key = make_secret_key(rng);
            setup
                .secret_key_store
                .insert(key_id, key, None)
                .expect("error inserting key in secret key store");

            let logs = setup.logger.drain_logs();
            LogEntriesAssert::assert_that(logs)
                .has_only_one_message_containing(
                    &Level::Warning,
                    "error(s) cleaning up old secret key store file: [error creating hard link to existing file"
                );
        }
    }

    struct Setup {
        temp_dir: TempDir,
        secret_key_store: ProtoSecretKeyStore,
        hard_link_to_test_zeroization: PathBuf,
        metrics: MetricsRegistry,
        logger: InMemoryReplicaLogger,
    }

    impl Setup {
        fn new() -> Self {
            let metrics = MetricsRegistry::new();
            let logger = InMemoryReplicaLogger::new();
            let (temp_dir, secret_key_store) = open_existing_secret_key_store_in_temp_dir(
                &SecretKeyStoreVersion::V3,
                CryptoMetrics::new(Some(&metrics)),
                Some(ReplicaLogger::from(&logger)),
            );
            let hard_link_to_test_zeroization = temp_dir.as_ref().join(format!(
                "{}.test",
                existing_secret_key_store_file_name(&SecretKeyStoreVersion::V3)
            ));
            Setup {
                temp_dir,
                secret_key_store,
                hard_link_to_test_zeroization,
                metrics,
                logger,
            }
        }
    }

    fn assert_contains_only_zeroes(file: &Path) {
        let read_bytes = fs::read(file).expect("error reading file");
        assert!(!read_bytes.is_empty());
        for byte in read_bytes {
            assert_eq!(byte, 0u8);
        }
    }
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
        Arc::new(CryptoMetrics::none()),
    );
}

mod insert_or_replace {
    use super::*;
    use ic_test_utilities_in_memory_logger::InMemoryReplicaLogger;
    use ic_test_utilities_in_memory_logger::assertions::LogEntriesAssert;
    use proptest::option;
    use slog::Level;

    proptest! {
        #[test]
        fn should_insert_secret_key(seed: [u8; 32], scope in option::of(arb_scope())) {
            let rng = &mut ChaCha20Rng::from_seed(seed);
            let mut key_store = proto_key_store();
            let key_id: KeyId = KeyId::from(rng.r#gen::<[u8; 32]>());
            let secret_key = secret_key(rng);

            assert!(key_store.insert_or_replace(key_id, secret_key.clone(), scope).is_ok());

            let retrieved_key = key_store.get(&key_id).unwrap();
            assert_eq!(secret_key, retrieved_key);
        }

        #[test]
        fn should_replace_previously_inserted_secret_key_with_same_or_different_scope(
            seed: [u8; 32],
            scope_first_key in option::of(arb_scope()),
            scope_second_key in option::of(arb_scope())
        ) {
            let rng = &mut ChaCha20Rng::from_seed(seed);
            let mut key_store = proto_key_store();
            let key_id: KeyId = KeyId::from(rng.r#gen::<[u8; 32]>());
            let first_secret_key = secret_key(rng);
            assert!(key_store.insert(key_id, first_secret_key.clone(), scope_first_key).is_ok());

            let second_secret_key = secret_key(rng);
            assert_ne!(first_secret_key, second_secret_key);
            assert!(key_store.insert_or_replace(key_id, second_secret_key.clone(), scope_second_key).is_ok());

            let retrieved_key = key_store.get(&key_id).unwrap();
            assert_eq!(second_secret_key, retrieved_key);
        }

         #[test]
        fn should_replace_scope_in_previously_inserted_secret_key(
            seed: [u8; 32],
            scope1 in option::of(arb_scope()),
            scope2 in option::of(arb_scope())
        ) {
            let rng = &mut ChaCha20Rng::from_seed(seed);
            let mut key_store = proto_key_store();
            let key_id: KeyId = KeyId::from(rng.r#gen::<[u8; 32]>());
            let secret_key = secret_key(rng);
            assert!(key_store.insert(key_id, secret_key.clone(), scope1).is_ok());

            assert!(key_store.insert_or_replace(key_id, secret_key.clone(), scope2).is_ok());

            let retrieved_key = key_store.get(&key_id).unwrap();
            assert_eq!(secret_key, retrieved_key);
        }

        #[test]
        fn should_overwrite_key_store_only_once(seed: [u8; 32], scope in option::of(arb_scope())) {
            let temp_dir: TempDir = mk_temp_dir_with_permissions(0o700);
            let in_memory_logger = InMemoryReplicaLogger::new();
            let replica_logger = ReplicaLogger::from(&in_memory_logger);
            let mut key_store = ProtoSecretKeyStore::open(temp_dir.path(), "sks_data.pb", Some(replica_logger), Arc::new(CryptoMetrics::none()));
            let rng = &mut ChaCha20Rng::from_seed(seed);
            let key_id: KeyId = KeyId::from(rng.r#gen::<[u8; 32]>());
            let secret_key = secret_key(rng);

            assert!(key_store.insert(key_id, secret_key.clone(), scope).is_ok()); // 1 overwrite
            assert!(key_store.insert_or_replace(key_id, secret_key, scope).is_ok()); // expect 1 overwrite

            let logs = in_memory_logger.drain_logs();
            LogEntriesAssert::assert_that(logs)
                .has_exactly_n_messages_containing(2, &Level::Debug, "Secret key store written to");
        }
    }

    fn secret_key<R: Rng>(rng: &mut R) -> CspSecretKey {
        CspSecretKey::Ed25519(ed25519_types::SecretKeyBytes(
            SecretArray::new_and_dont_zeroize_argument(&rng.r#gen()),
        ))
    }

    fn arb_scope() -> impl Strategy<Value = Scope> {
        prop_oneof![
            Just(Scope::Const(ConstScope::Test0)),
            Just(Scope::Const(ConstScope::Test1)),
            Just(Scope::Const(ConstScope::NiDkgThresholdKeys)),
            Just(Scope::Const(ConstScope::NiDkgFsEncryptionKeys)),
            Just(Scope::Const(ConstScope::IDkgMEGaEncryptionKeys)),
            Just(Scope::Const(ConstScope::IDkgThresholdKeys)),
        ]
    }
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
    crypto_metrics: CryptoMetrics,
    logger: Option<ReplicaLogger>,
) -> (TempDir, ProtoSecretKeyStore) {
    let temp_dir: TempDir = mk_temp_dir_with_permissions(0o700);
    let sks_path = path_to_existing_secret_key_store(version);
    assert_secret_key_store_proto_has_correct_version(sks_path.as_path(), version);
    copy_file_to_dir(sks_path.as_path(), temp_dir.path());

    let secret_key_store = ProtoSecretKeyStore::open(
        temp_dir.path(),
        &existing_secret_key_store_file_name(version),
        logger,
        Arc::new(crypto_metrics),
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
            secret_key: CspSecretKey::MultiBls12_381(SecretKeyBytes::new(
                SecretArray::new_and_dont_zeroize_argument(&[
                    54, 109, 33, 204, 23, 220, 113, 219, 1, 25, 39, 129, 69, 119, 21, 235, 75, 183,
                    245, 235, 173, 111, 112, 201, 140, 232, 154, 233, 186, 139, 22, 211,
                ]),
            )),
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
