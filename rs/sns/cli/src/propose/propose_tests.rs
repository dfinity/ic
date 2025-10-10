use crate::propose::{SaveToErrors, ensure_file_exists_and_is_writeable, save_proposal_id_to_file};
use ic_nns_common::pb::v1::ProposalId;
use std::{fs, os::unix::fs::PermissionsExt, path::Path};
use tempfile::NamedTempFile;

/// read-only for owner, group, and others
const READ_ONLY_PERMISSION: u32 = 0o444;

/// read-write for owner
const READ_WRITE_PERMISSION: u32 = 0o644;

#[test]
fn test_ensure_file_exists_and_is_writeable_succeeds_with_existing_file() {
    // Setup
    let temp_file = NamedTempFile::new().expect("Failed to create tmp file");
    let temp_file_path = temp_file.path();

    // Exercise/verify
    assert_eq!(ensure_file_exists_and_is_writeable(temp_file_path), Ok(()));
}

#[test]
fn test_ensure_file_exists_and_is_writeable_succeeds_when_creating_file() {
    // Setup
    let temp_file_path = Path::new("temp_file.json");

    // Exercise/verify
    assert_eq!(ensure_file_exists_and_is_writeable(temp_file_path), Ok(()));
    assert!(temp_file_path.exists());

    // Teardown
    fs::remove_file(temp_file_path).expect("Failed to remove file");
}

#[test]
fn test_ensure_file_exists_and_is_writeable_fails_if_non_writeable() {
    // Setup
    let temp_file = NamedTempFile::new().expect("Failed to create tmp file");
    let temp_file_path = temp_file.path();
    // Set the permissions of the temp file to read-only which should trigger a
    // failure.
    let permissions = fs::Permissions::from_mode(READ_ONLY_PERMISSION);
    fs::set_permissions(temp_file_path, permissions).expect("Failed to set permissions");

    // Exercise/verify
    assert!(matches!(
        ensure_file_exists_and_is_writeable(temp_file_path),
        Err(SaveToErrors::FileOpenFailed(ref path, _)) if path == &temp_file_path.to_path_buf(),

    ));

    // Teardown
    // Reset permissions so the file can be deleted
    let permissions = fs::Permissions::from_mode(READ_WRITE_PERMISSION);
    fs::set_permissions(temp_file_path, permissions).expect("Failed to reset permissions");
}

#[test]
fn test_save_proposal_id_to_file_succeeds() {
    // Setup
    let temp_file = NamedTempFile::new().expect("Failed to create tmp file");
    let temp_file_path = temp_file.path();

    // Exercise/verify
    let expected_proposal_id = ProposalId { id: 1 };
    assert_eq!(
        save_proposal_id_to_file(temp_file_path, &expected_proposal_id),
        Ok(())
    );
    let file_string = fs::read_to_string(temp_file_path).expect("Failed to read temp file");
    let actual_proposal_id = serde_json::from_str(&file_string)
        .expect("Could not serialize JSON ProposalId to ProposalId");
    assert_eq!(expected_proposal_id, actual_proposal_id);
}

#[test]
fn test_save_proposal_id_to_file_fails_if_write_fails() {
    // Setup
    let temp_file = NamedTempFile::new().expect("Failed to create tmp file");
    let temp_file_path = temp_file.path();
    // Set the permissions of the temp file to read-only which should trigger a
    // failure.
    let permissions = fs::Permissions::from_mode(READ_ONLY_PERMISSION);
    fs::set_permissions(temp_file_path, permissions).expect("Failed to set permissions");

    // Exercise/verify
    assert!(matches!(
        save_proposal_id_to_file(temp_file_path, &ProposalId { id: 1 }),
        Err(SaveToErrors::FileWriteFailed(ref path, _)) if path == &temp_file_path.to_path_buf(),
    ));

    // Teardown
    // Reset permissions so the file can be deleted
    let permissions = fs::Permissions::from_mode(READ_WRITE_PERMISSION);
    fs::set_permissions(temp_file_path, permissions).expect("Failed to reset permissions");
}
