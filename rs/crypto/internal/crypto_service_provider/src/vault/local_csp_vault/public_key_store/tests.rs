use crate::vault::test_utils;
use crate::LocalCspVault;

#[test]
fn should_retrieve_current_public_keys() {
    test_utils::public_key_store::should_retrieve_current_public_keys(
        LocalCspVault::builder().build_into_arc(),
    );
}

#[test]
fn should_retrieve_last_idkg_public_key() {
    test_utils::public_key_store::should_retrieve_last_idkg_public_key(
        LocalCspVault::builder().build_into_arc(),
    );
}

#[test]
fn should_return_true_for_pks_contains_if_all_keys_match_with_one_idkg_key() {
    test_utils::public_key_store::should_return_true_for_pks_contains_if_all_keys_match_with_one_idkg_key(LocalCspVault::builder().build_into_arc());
}

#[test]
fn should_return_true_for_pks_contains_for_empty_current_node_public_keys() {
    test_utils::public_key_store::should_return_true_for_pks_contains_for_empty_current_node_public_keys(LocalCspVault::builder().build_into_arc());
}

#[test]
fn should_return_false_for_pks_contains_if_node_signing_key_does_not_match() {
    test_utils::public_key_store::should_return_false_for_pks_contains_if_node_signing_key_does_not_match(LocalCspVault::builder().build_into_arc(), LocalCspVault::builder().build_into_arc());
}

#[test]
fn should_return_false_for_pks_contains_if_committee_signing_key_does_not_match() {
    test_utils::public_key_store::should_return_false_for_pks_contains_if_committee_signing_key_does_not_match(LocalCspVault::builder().build_into_arc(), LocalCspVault::builder().build_into_arc());
}

#[test]
fn should_return_false_for_pks_contains_if_dkg_dealing_encryption_key_does_not_match() {
    test_utils::public_key_store::should_return_false_for_pks_contains_if_dkg_dealing_encryption_key_does_not_match(LocalCspVault::builder().build_into_arc(), LocalCspVault::builder().build_into_arc());
}

#[test]
fn should_return_false_for_pks_contains_if_tls_certificate_does_not_match() {
    test_utils::public_key_store::should_return_false_for_pks_contains_if_tls_certificate_does_not_match(LocalCspVault::builder().build_into_arc(), LocalCspVault::builder().build_into_arc());
}

#[test]
fn should_return_false_for_pks_contains_if_idkg_dealing_encryption_key_does_not_match() {
    test_utils::public_key_store::should_return_false_for_pks_contains_if_idkg_dealing_encryption_key_does_not_match(LocalCspVault::builder().build_into_arc(), LocalCspVault::builder().build_into_arc());
}

#[test]
fn should_return_true_for_pks_contains_if_all_keys_match_with_multiple_idkg_keys() {
    test_utils::public_key_store::should_return_true_for_pks_contains_if_all_keys_match_with_multiple_idkg_keys(LocalCspVault::builder().build_into_arc());
}

#[test]
fn should_return_true_for_pks_contains_if_all_keys_match_with_multiple_idkg_keys_and_registry_key_not_first_in_vector(
) {
    test_utils::public_key_store::should_return_true_for_pks_contains_if_all_keys_match_with_multiple_idkg_keys_and_registry_key_not_first_in_vector(LocalCspVault::builder().build_into_arc());
}

#[test]
fn should_correctly_return_idkg_dealing_encryption_pubkeys_count_for_no_keys() {
    test_utils::public_key_store::should_correctly_return_idkg_dealing_encryption_pubkeys_count_for_no_keys(
        LocalCspVault::builder().build_into_arc(),
    );
}

#[test]
fn should_correctly_return_idkg_dealing_encryption_pubkeys_count_for_single_key() {
    test_utils::public_key_store::should_correctly_return_idkg_dealing_encryption_pubkeys_count_for_single_key(
        LocalCspVault::builder().build_into_arc(),
    );
}

#[test]
fn should_correctly_return_idkg_dealing_encryption_pubkeys_count_for_two_keys() {
    test_utils::public_key_store::should_correctly_return_idkg_dealing_encryption_pubkeys_count_for_two_keys(
        LocalCspVault::builder().build_into_arc(),
    );
}

#[test]
fn should_correctly_return_idkg_dealing_encryption_pubkeys_count_when_all_other_keys_exist_except_idkg_key(
) {
    test_utils::public_key_store::should_correctly_return_idkg_dealing_encryption_pubkeys_count_when_all_other_keys_exist_except_idkg_key(
        LocalCspVault::builder().build_into_arc(),
    );
}
