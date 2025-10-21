//! Tests for Local CSP vault

use crate::LocalCspVault;
use crate::public_key_store::proto_pubkey_store::ProtoPublicKeyStore;
use crate::secret_key_store::SecretKeyStore;
use crate::secret_key_store::test_utils::{make_key_id, make_secret_key};
use crate::vault::local_csp_vault::ProtoSecretKeyStore;
use ic_crypto_internal_csp_test_utils::files::mk_temp_dir_with_permissions;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_logger::replica_logger::no_op_logger;
use std::sync::Arc;

mod csp_new {
    use crate::secret_key_store::memory_secret_key_store::InMemorySecretKeyStore;

    use super::*;
    use std::path::Path;

    #[test]
    fn should_not_panic_when_key_stores_use_distinct_files() {
        let temp_dir = mk_temp_dir_with_permissions(0o700);
        let node_secret_key_store_file = "temp_sks_data.pb";
        let public_key_store_file = "temp_pks_data.pb";
        let (node_sks, canister_sks, node_pks) = key_stores(
            temp_dir.path(),
            node_secret_key_store_file,
            public_key_store_file,
        );

        let _csp_vault = LocalCspVault::new(
            node_sks,
            canister_sks,
            node_pks,
            Arc::new(CryptoMetrics::none()),
            no_op_logger(),
        );
    }

    #[test]
    #[should_panic(expected = "/temp_sks_data.pb\" is used more than once")]
    fn should_panic_when_node_secret_key_store_file_same_as_public_key_store() {
        let temp_dir = mk_temp_dir_with_permissions(0o700);
        let node_secret_key_store_file = "temp_sks_data.pb";
        let (node_sks, canister_sks, node_pks) = key_stores(
            temp_dir.path(),
            node_secret_key_store_file,
            node_secret_key_store_file,
        );

        let _csp_vault = LocalCspVault::new(
            node_sks,
            canister_sks,
            node_pks,
            Arc::new(CryptoMetrics::none()),
            no_op_logger(),
        );
    }

    fn key_stores(
        key_store_dir: &Path,
        node_secret_key_store_name: &str,
        public_key_store_name: &str,
    ) -> (
        ProtoSecretKeyStore,
        InMemorySecretKeyStore,
        ProtoPublicKeyStore,
    ) {
        let node_secret_key_store = ProtoSecretKeyStore::open(
            key_store_dir,
            node_secret_key_store_name,
            None,
            Arc::new(CryptoMetrics::none()),
        );
        let public_key_store =
            ProtoPublicKeyStore::open(key_store_dir, public_key_store_name, no_op_logger());
        (
            node_secret_key_store,
            InMemorySecretKeyStore::new(None),
            public_key_store,
        )
    }
}

#[test]
fn should_have_separate_sks_and_canister_sks() {
    let rng = &mut reproducible_rng();
    let vault = LocalCspVault::builder_for_test().build();
    let key_id = make_key_id(rng);
    let secret_key = make_secret_key(rng);

    // Key should not be in the sks
    assert!(!vault.sks_read_lock().contains(&key_id));
    assert!(
        vault
            .sks_write_lock()
            .insert(key_id, secret_key, None)
            .is_ok()
    );

    // Key should be in the sks after insertion
    assert!(vault.sks_read_lock().contains(&key_id));

    // Key should not be in the canister secret key store
    assert!(!vault.canister_sks_read_lock().contains(&key_id));
}

#[test]
fn should_insert_keys_in_canister_sks() {
    let rng = &mut reproducible_rng();
    let vault = LocalCspVault::builder_for_test().build();

    let key_id = make_key_id(rng);
    let secret_key = make_secret_key(rng);

    // Key should not be in the canister secret key store yet
    assert!(!vault.canister_sks_read_lock().contains(&key_id));
    assert!(
        vault
            .canister_sks_write_lock()
            .insert(key_id, secret_key, None)
            .is_ok()
    );

    // Key should be in the canister secret key store after insertion
    assert!(vault.canister_sks_read_lock().contains(&key_id));
}
