#![allow(clippy::unwrap_used)]

use super::*;

use ic_test_utilities::crypto::empty_fake_registry;
use ic_test_utilities::types::ids::node_test_id;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const NODE_ID: u64 = 42;

#[test]
fn should_delete_tempdir_when_temp_crypto_goes_out_of_scope() {
    let path = {
        let temp_crypto = TempCryptoComponent::new(empty_fake_registry(), node_test_id(NODE_ID));
        temp_crypto.temp_dir.path().to_path_buf()
    };
    assert!(!path.exists());
}

#[test]
fn should_create_tempdir_as_directory() {
    let temp_crypto = TempCryptoComponent::new(empty_fake_registry(), node_test_id(NODE_ID));
    assert!(temp_crypto.temp_dir.path().is_dir());
}

#[test]
fn should_create_with_tempdir_that_exists() {
    let temp_crypto = TempCryptoComponent::new(empty_fake_registry(), node_test_id(NODE_ID));
    assert!(temp_crypto.temp_dir.path().exists());
}

#[test]
fn should_set_correct_tempdir_permissions() {
    let temp_crypto = TempCryptoComponent::new(empty_fake_registry(), node_test_id(NODE_ID));
    // the 40 indicates that this is a directory, 700 is the file permission we set.
    assert_eq!(permission_mode(&temp_crypto.temp_dir.path()), 0o40700);
}

fn permission_mode(path: &Path) -> u32 {
    let metadata = std::fs::metadata(path).unwrap();
    let permissions = metadata.permissions();
    permissions.mode()
}
