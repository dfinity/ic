use super::*;
use crate::secret_key_store::test_utils::{make_key_id, make_secret_key};
use crate::secret_key_store::{Scope, SecretKeyStore, scope::ConstScope};
use crate::types::CspSecretKey;
use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
use ic_crypto_secrets_containers::SecretArray;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use proptest::prelude::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
fn should_retrieve_inserted_key() {
    let rng = &mut reproducible_rng();
    let mut key_store = inmem_sks();
    let key_id: KeyId = make_key_id(rng);
    let key = make_secret_key(rng);

    assert!(key_store.insert(key_id, key.clone(), None).is_ok());

    let retrieved_key = key_store.get(&key_id).unwrap();
    assert_eq!(key, retrieved_key);
}

#[test]
fn should_contain_existing_key() {
    let rng = &mut reproducible_rng();
    let mut key_store = inmem_sks();
    let key_id: KeyId = make_key_id(rng);

    assert!(key_store.insert(key_id, make_secret_key(rng), None).is_ok());
    assert!(key_store.contains(&key_id));
}

#[test]
fn should_not_contain_nonexisting_key() {
    let rng = &mut reproducible_rng();
    let key_store = inmem_sks();
    let non_existing_key_id: KeyId = make_key_id(rng);

    assert!(!key_store.contains(&non_existing_key_id));
}

#[test]
fn should_remove_existing_key() {
    let rng = &mut reproducible_rng();
    let mut key_store = inmem_sks();
    let key_id: KeyId = make_key_id(rng);

    assert!(key_store.insert(key_id, make_secret_key(rng), None).is_ok());

    assert!(key_store.get(&key_id).is_some());
    assert!(key_store.remove(&key_id).unwrap());
    assert!(key_store.get(&key_id).is_none());
}

#[test]
fn should_not_remove_nonexisting_key() {
    let rng = &mut reproducible_rng();
    let mut key_store = inmem_sks();
    let non_existing_key_id: KeyId = make_key_id(rng);

    assert!(!key_store.remove(&non_existing_key_id).unwrap());
}

#[test]
fn deleting_twice_should_return_false() {
    let rng = &mut reproducible_rng();
    let mut key_store = inmem_sks();
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
    let mut key_store = inmem_sks();
    let key_id_1: KeyId = make_key_id(rng);
    let key_1 = make_secret_key(rng);
    let key_2 = make_secret_key(rng);
    assert_ne!(key_1, key_2);

    key_store.insert(key_id_1, key_1.clone(), None).unwrap();

    assert!(key_store.insert(key_id_1, key_2, None).is_err());
    assert_eq!(key_1, key_store.get(&key_id_1).unwrap());
}

mod retain {
    use super::*;

    #[test]
    fn should_retain_expected_keys_with_specified_scope_and_not_remove_keys_with_non_matching_scope()
     {
        let mut key_store = inmem_sks();
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
        let mut key_store = inmem_sks();
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
    fn should_succeed_when_retaining_non_existing_key_by_key_id() {
        let rng = &mut reproducible_rng();
        let mut key_store = inmem_sks();
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
        let mut key_store = inmem_sks();
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
        let mut key_store = inmem_sks();
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
        let mut key_store = inmem_sks();
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
}

mod retain_would_modify_keystore {
    use super::*;

    #[test]
    fn should_return_true_if_some_keys_match_scope_but_not_filter() {
        let mut key_store = inmem_sks();
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
        let key_store = inmem_sks();
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
        let mut key_store = inmem_sks();
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
        let mut key_store = inmem_sks();
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
        let mut key_store = inmem_sks();
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
        let mut key_store = inmem_sks();
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

mod insert_or_replace {
    use super::*;
    use proptest::option;

    proptest! {
        #[test]
        fn should_insert_secret_key(seed: [u8; 32], scope in option::of(arb_scope())) {
            let rng = &mut ChaCha20Rng::from_seed(seed);
            let mut key_store = inmem_sks();
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
            let mut key_store = inmem_sks();
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
            let mut key_store = inmem_sks();
            let key_id: KeyId = KeyId::from(rng.r#gen::<[u8; 32]>());
            let secret_key = secret_key(rng);
            assert!(key_store.insert(key_id, secret_key.clone(), scope1).is_ok());

            assert!(key_store.insert_or_replace(key_id, secret_key.clone(), scope2).is_ok());

            let retrieved_key = key_store.get(&key_id).unwrap();
            assert_eq!(secret_key, retrieved_key);
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

fn inmem_sks() -> InMemorySecretKeyStore {
    InMemorySecretKeyStore::new(None)
}
