//! Tests for Local CSP vault

use crate::secret_key_store::test_utils::{make_key_id, make_secret_key};
use crate::secret_key_store::SecretKeyStore;
use crate::server::local_csp_server::test_utils::temp_local_csp_server::TempLocalCspVault;
#[test]
#[should_panic(
    expected = "The node secret-key-store and the canister secret-key-store must use different files"
)]
fn should_panic_if_sks_and_csks_coincide() {
    let temp_file = "temp_sks_data.pb";

    TempLocalCspVault::new_from_store_files(temp_file, temp_file);
}

#[test]
fn should_have_separate_sks_and_canister_sks() {
    let temp_csp = TempLocalCspVault::new();
    let key_id = make_key_id(42);
    let secret_key = make_secret_key(42);

    // Key should not be in the sks
    assert!(!temp_csp.vault.sks_read_lock().contains(&key_id));
    assert!(temp_csp
        .vault
        .sks_write_lock()
        .insert(key_id, secret_key, None)
        .is_ok());

    // Key should be in the sks after insertion
    assert!(temp_csp.vault.sks_read_lock().contains(&key_id));

    // Key should not be in the canister secret key store
    assert!(!temp_csp.vault.canister_sks_read_lock().contains(&key_id));
}

#[test]
fn should_insert_keys_in_canister_sks() {
    let temp_csp = TempLocalCspVault::new();

    let key_id = make_key_id(42);
    let secret_key = make_secret_key(42);

    // Key should not be in the canister secret key store yet
    assert!(!temp_csp.vault.canister_sks_read_lock().contains(&key_id));
    assert!(temp_csp
        .vault
        .canister_sks_write_lock()
        .insert(key_id, secret_key, None)
        .is_ok());

    // Key should be in the canister secret key store after insertion
    assert!(temp_csp.vault.canister_sks_read_lock().contains(&key_id));
}
