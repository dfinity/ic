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

mod current_node_public_keys_with_timestamps {
    use super::*;
    use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
    use crate::public_key_store::PublicKeyGenerationTimestamps;
    use crate::vault::api::PublicKeyStoreCspVault;
    use crate::vault::test_utils::public_key_store::genesis_time_source;
    use assert_matches::assert_matches;
    use ic_protobuf::registry::crypto::v1::PublicKey;
    use ic_types::time::GENESIS;
    use std::time::Duration;

    #[test]
    fn should_be_consistent_with_current_node_public_keys() {
        test_utils::public_key_store::should_be_consistent_with_current_node_public_keys(
            LocalCspVault::builder().build_into_arc(),
        );
    }

    #[test]
    fn should_retrieve_timestamp_of_generated_idkg_public_key() {
        let vault = LocalCspVault::builder()
            .with_time_source(genesis_time_source())
            .build_into_arc();
        test_utils::public_key_store::should_retrieve_timestamp_of_generated_idkg_public_key(
            vault, GENESIS,
        );
    }

    #[test]
    fn should_not_retrieve_timestamps_of_other_generated_keys_because_they_are_not_set_yet() {
        test_utils::public_key_store::should_not_retrieve_timestamps_of_other_generated_keys_because_they_are_not_set_yet(
            LocalCspVault::builder().build_into_arc(),
        );
    }

    #[test]
    fn should_retrieve_correct_timestamps_for_each_key() {
        let mut public_key_store = MockPublicKeyStore::new();
        let node_signing_pk_timestamp = GENESIS + Duration::from_secs(1);
        let committee_signing_pk_timestamp = GENESIS + Duration::from_secs(2);
        let dkg_pk_timestamp = GENESIS + Duration::from_secs(3);
        let idkg_pk_timestamp = GENESIS + Duration::from_secs(4);
        public_key_store
            .expect_generation_timestamps()
            .return_const(PublicKeyGenerationTimestamps {
                node_signing_public_key: Some(node_signing_pk_timestamp),
                committee_signing_public_key: Some(committee_signing_pk_timestamp),
                dkg_dealing_encryption_public_key: Some(dkg_pk_timestamp),
                last_idkg_dealing_encryption_public_key: Some(idkg_pk_timestamp),
            });
        public_key_store
            .expect_node_signing_pubkey()
            .return_const(Some(public_key_with_key_value(1)));
        public_key_store
            .expect_committee_signing_pubkey()
            .return_const(Some(public_key_with_key_value(2)));
        public_key_store.expect_tls_certificate().return_const(None);
        public_key_store
            .expect_ni_dkg_dealing_encryption_pubkey()
            .return_const(Some(public_key_with_key_value(3)));
        public_key_store
            .expect_idkg_dealing_encryption_pubkeys()
            .return_const(vec![public_key_with_key_value(4)]);
        let vault = LocalCspVault::builder()
            .with_public_key_store(public_key_store)
            .build();

        let pks_with_timestamps = vault
            .current_node_public_keys_with_timestamps()
            .expect("Failed to retrieve current node public keys");

        assert_matches!(pks_with_timestamps.node_signing_public_key, 
            Some(pk) if pk.timestamp == Some(node_signing_pk_timestamp.as_millis_since_unix_epoch()));
        assert_matches!(pks_with_timestamps.committee_signing_public_key,
            Some(pk) if pk.timestamp == Some(committee_signing_pk_timestamp.as_millis_since_unix_epoch()));
        assert_matches!(pks_with_timestamps.dkg_dealing_encryption_public_key,
            Some(pk) if pk.timestamp == Some(dkg_pk_timestamp.as_millis_since_unix_epoch()));
        assert_matches!(pks_with_timestamps.idkg_dealing_encryption_public_key,
            Some(pk) if pk.timestamp == Some(idkg_pk_timestamp.as_millis_since_unix_epoch()));
    }

    fn public_key_with_key_value(key_value: u8) -> PublicKey {
        use ic_types::crypto::AlgorithmId;
        PublicKey {
            version: 1,
            algorithm: AlgorithmId::Ed25519 as i32,
            key_value: [key_value; 10].to_vec(),
            proof_data: None,
            timestamp: None,
        }
    }
}
