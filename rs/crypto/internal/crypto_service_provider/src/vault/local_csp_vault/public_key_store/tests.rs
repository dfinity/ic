use crate::LocalCspVault;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_types_test_utils::ids::node_test_id;

use crate::keygen::utils::{
    committee_signing_pk_to_proto, dkg_dealing_encryption_pk_to_proto,
    idkg_dealing_encryption_pk_to_proto, node_signing_pk_to_proto,
};
use crate::vault::api::BasicSignatureCspVault;
use crate::vault::api::MultiSignatureCspVault;
use crate::vault::api::NiDkgCspVault;
use crate::vault::api::PublicKeyStoreCspVault;
use crate::vault::api::TlsHandshakeCspVault;
use crate::vault::test_utils::pks_and_sks::generate_all_keys;
use crate::vault::test_utils::pks_and_sks::generate_idkg_dealing_encryption_key_pair;
use ic_types::crypto::CurrentNodePublicKeys;

const NODE_1: u64 = 4241;

#[test]
fn should_retrieve_current_public_keys() {
    let csp_vault = LocalCspVault::builder_for_test().build();
    let node_signing_public_key = csp_vault
        .gen_node_signing_key_pair()
        .expect("Could not generate node signing keys");
    let committee_signing_public_key = csp_vault
        .gen_committee_signing_key_pair()
        .expect("Could not generate committee signing keys");
    let cert = csp_vault
        .gen_tls_key_pair(node_test_id(NODE_1))
        .expect("Generation of TLS keys failed.");
    let (nidkg_public_key, nidkg_pop) = csp_vault
        .gen_dealing_encryption_key_pair(node_test_id(NODE_1))
        .expect("Failed to generate DKG dealing encryption keys");
    let idkg_public_key = generate_idkg_dealing_encryption_key_pair(&csp_vault);

    let current_public_keys = csp_vault
        .current_node_public_keys()
        .expect("Error retrieving current node public keys");

    assert_eq!(
        current_public_keys,
        CurrentNodePublicKeys {
            node_signing_public_key: Some(node_signing_pk_to_proto(node_signing_public_key)),
            committee_signing_public_key: Some(committee_signing_pk_to_proto(
                committee_signing_public_key
            )),
            tls_certificate: Some(cert.to_proto()),
            dkg_dealing_encryption_public_key: Some(dkg_dealing_encryption_pk_to_proto(
                nidkg_public_key,
                nidkg_pop
            )),
            idkg_dealing_encryption_public_key: Some(idkg_dealing_encryption_pk_to_proto(
                idkg_public_key
            ))
        }
    )
}

#[test]
fn should_retrieve_last_idkg_public_key() {
    let csp_vault = LocalCspVault::builder_for_test().build();
    let idkg_public_key_1 = generate_idkg_dealing_encryption_key_pair(&csp_vault);
    assert_eq!(
        idkg_dealing_encryption_pk_to_proto(idkg_public_key_1.clone()),
        csp_vault
            .current_node_public_keys()
            .expect("Error retrieving current node public keys")
            .idkg_dealing_encryption_public_key
            .expect("missing iDKG key")
    );

    let idkg_public_key_2 = generate_idkg_dealing_encryption_key_pair(&csp_vault);
    assert_ne!(idkg_public_key_1, idkg_public_key_2);
    assert_eq!(
        idkg_dealing_encryption_pk_to_proto(idkg_public_key_2),
        csp_vault
            .current_node_public_keys()
            .expect("Error retrieving current node public keys")
            .idkg_dealing_encryption_public_key
            .expect("missing iDKG key")
    );
}

#[test]
fn should_correctly_return_idkg_dealing_encryption_pubkeys_count_for_no_keys() {
    let csp_vault = LocalCspVault::builder_for_test().build();

    let result = csp_vault
        .idkg_dealing_encryption_pubkeys_count()
        .expect("Error calling idkg_key_count");

    assert_eq!(0, result);
}

#[test]
fn should_correctly_return_idkg_dealing_encryption_pubkeys_count_for_single_key() {
    let csp_vault = LocalCspVault::builder_for_test().build();
    let _initial_node_public_keys = generate_all_keys(&csp_vault);

    let result = csp_vault
        .idkg_dealing_encryption_pubkeys_count()
        .expect("Error calling idkg_key_count");

    assert_eq!(1, result);
}

#[test]
fn should_correctly_return_idkg_dealing_encryption_pubkeys_count_for_two_keys() {
    let csp_vault = LocalCspVault::builder_for_test().build();
    let _initial_node_public_keys = generate_all_keys(&csp_vault);
    let _second_idkg_pk = generate_idkg_dealing_encryption_key_pair(&csp_vault);

    let result = csp_vault
        .idkg_dealing_encryption_pubkeys_count()
        .expect("Error calling idkg_key_count");

    assert_eq!(2, result);
}

#[test]
fn should_correctly_return_idkg_dealing_encryption_pubkeys_count_when_all_other_keys_exist_except_idkg_key()
 {
    let csp_vault = LocalCspVault::builder_for_test().build();
    let _node_signing_pk = csp_vault
        .gen_node_signing_key_pair()
        .expect("Failed to generate node signing key pair");
    let _committee_signing_pk = csp_vault
        .gen_committee_signing_key_pair()
        .expect("Failed to generate committee signing key pair");
    let _dkg_dealing_encryption_pk = csp_vault
        .gen_dealing_encryption_key_pair(node_test_id(NODE_1))
        .expect("Failed to generate NI-DKG dealing encryption key pair");
    let _tls_certificate = csp_vault
        .gen_tls_key_pair(node_test_id(NODE_1))
        .expect("Failed to generate TLS certificate");

    let result = csp_vault
        .idkg_dealing_encryption_pubkeys_count()
        .expect("Error calling idkg_key_count");

    assert_eq!(0, result);
}

mod current_node_public_keys_with_timestamps {
    use super::*;
    use crate::public_key_store::PublicKeyGenerationTimestamps;
    use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
    use crate::vault::api::PublicKeyStoreCspVault;
    use assert_matches::assert_matches;
    use ic_protobuf::registry::crypto::v1::PublicKey;
    use ic_test_utilities_time::FastForwardTimeSource;
    use ic_types::time::GENESIS;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn should_be_consistent_with_current_node_public_keys() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let _ = generate_all_keys(&csp_vault);

        let current_public_keys_with_timestamps = csp_vault
            .current_node_public_keys_with_timestamps()
            .expect("Error retrieving current node public keys with timestamps");
        let current_public_keys = csp_vault
            .current_node_public_keys()
            .expect("Error retrieving current node public keys");

        assert!(equal_ignoring_timestamp(
            &current_public_keys_with_timestamps,
            &current_public_keys
        ));
    }

    #[test]
    fn should_retrieve_timestamp_of_generated_idkg_public_key() {
        let vault = LocalCspVault::builder_for_test()
            .with_time_source(genesis_time_source())
            .build();
        let generated_idkg_pk = generate_idkg_dealing_encryption_key_pair(&vault);

        let retrieved_idkg_pk_with_timestamp = vault
            .current_node_public_keys_with_timestamps()
            .expect("Failed to retrieve current node public keys")
            .idkg_dealing_encryption_public_key
            .expect("missing IDKG dealing encryption public key");

        assert!(
            retrieved_idkg_pk_with_timestamp
                .equal_ignoring_timestamp(&idkg_dealing_encryption_pk_to_proto(generated_idkg_pk))
        );
        assert_matches!(
            retrieved_idkg_pk_with_timestamp.timestamp,
            Some(time) if time == GENESIS.as_millis_since_unix_epoch()
        );
    }

    //TODO CRP-1857: modify this test as needed when timestamp are introduced upon key generation for non-IDKG keys
    #[test]
    fn should_not_retrieve_timestamps_of_other_generated_keys_because_they_are_not_set_yet() {
        let csp_vault = LocalCspVault::builder_for_test().build();
        let _ = generate_all_keys(&csp_vault);

        let pks_with_timestamps = csp_vault
            .current_node_public_keys_with_timestamps()
            .expect("Failed to retrieve current node public keys");

        assert_matches!(pks_with_timestamps.node_signing_public_key, Some(pk) if pk.timestamp.is_none());
        assert_matches!(pks_with_timestamps.committee_signing_public_key, Some(pk) if pk.timestamp.is_none());
        assert_matches!(pks_with_timestamps.dkg_dealing_encryption_public_key, Some(pk) if pk.timestamp.is_none());
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
        let vault = LocalCspVault::builder_for_test()
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

    #[test]
    fn should_current_node_public_keys_be_equal_ignoring_timestamp() {
        //If you need to modify this test because for example the struct CurrentNodePublicKeys changed,
        //also modify the method equal_ignoring_timestamp!
        let public_keys = CurrentNodePublicKeys {
            node_signing_public_key: Some(public_key_with_key_value(1)),
            committee_signing_public_key: Some(public_key_with_key_value(2)),
            tls_certificate: Some(public_key_certificate_with_der(1)),
            dkg_dealing_encryption_public_key: Some(public_key_with_key_value(3)),
            idkg_dealing_encryption_public_key: Some(public_key_with_key_value(4)),
        };

        assert!(equal_ignoring_timestamp(&public_keys, &public_keys));

        let mut other_public_keys = public_keys.clone();
        other_public_keys.tls_certificate = Some(public_key_certificate_with_der(2));
        assert!(!equal_ignoring_timestamp(&public_keys, &other_public_keys));
    }

    fn equal_ignoring_timestamp(
        left: &CurrentNodePublicKeys,
        right: &CurrentNodePublicKeys,
    ) -> bool {
        equal_ignoring_timestamp_option(
            &left.node_signing_public_key,
            &right.node_signing_public_key,
        ) && equal_ignoring_timestamp_option(
            &left.committee_signing_public_key,
            &right.committee_signing_public_key,
        ) && left.tls_certificate == right.tls_certificate
            && equal_ignoring_timestamp_option(
                &left.dkg_dealing_encryption_public_key,
                &right.dkg_dealing_encryption_public_key,
            )
            && equal_ignoring_timestamp_option(
                &left.idkg_dealing_encryption_public_key,
                &right.idkg_dealing_encryption_public_key,
            )
    }

    fn equal_ignoring_timestamp_option(
        left: &Option<PublicKey>,
        right: &Option<PublicKey>,
    ) -> bool {
        match (left, right) {
            (None, None) => true,
            (Some(_), None) => false,
            (None, Some(_)) => false,
            (Some(left_pk), Some(right_pk)) => left_pk.equal_ignoring_timestamp(right_pk),
        }
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

    fn public_key_certificate_with_der(certificate_der: u8) -> X509PublicKeyCert {
        X509PublicKeyCert {
            certificate_der: [certificate_der; 10].to_vec(),
        }
    }

    fn genesis_time_source() -> Arc<FastForwardTimeSource> {
        let time_source = FastForwardTimeSource::new();
        time_source.set_time(GENESIS).expect("wrong time");
        time_source
    }
}
