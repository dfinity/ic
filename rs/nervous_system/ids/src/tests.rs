use super::*;

#[test]
fn test_is_potential_full_git_commit_id_accepts_valid_ids() {
    assert!(is_potential_full_git_commit_id(&"1234567890".repeat(4)));
    assert!(is_potential_full_git_commit_id(&"aF".repeat(20)));
}

#[test]
fn test_is_potential_full_git_commit_id_rejects_wrong_length() {
    assert!(!is_potential_full_git_commit_id(""));
    assert!(!is_potential_full_git_commit_id("1234567890"));
    assert!(!is_potential_full_git_commit_id(&"1".repeat(41)));
}

#[test]
fn test_is_potential_full_git_commit_id_rejects_non_hex_characters() {
    assert!(!is_potential_full_git_commit_id(&"z".repeat(40)));
}
