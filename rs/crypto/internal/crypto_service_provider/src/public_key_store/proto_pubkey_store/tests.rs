#![allow(clippy::unwrap_used)]

use crate::public_key_store::proto_pubkey_store::ProtoPublicKeyStore;
use crate::public_key_store::{read_node_public_keys, PublicKeyAddError};
use crate::public_key_store::{PublicKeySetOnceError, PublicKeyStore};
use crate::PUBLIC_KEY_STORE_DATA_FILENAME;
use assert_matches::assert_matches;
use ic_config::crypto::CryptoConfig;
use ic_crypto_internal_csp_test_utils::files::mk_temp_dir_with_permissions;
use ic_crypto_node_key_generation::derive_node_id;
use ic_crypto_node_key_generation::get_node_keys_or_generate_if_missing;
use ic_logger::replica_logger::no_op_logger;
use ic_logger::ReplicaLogger;
use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_protobuf::registry::crypto::v1::{PublicKey, X509PublicKeyCert};
use ic_test_utilities_in_memory_logger::assertions::LogEntriesAssert;
use ic_test_utilities_in_memory_logger::InMemoryReplicaLogger;
use ic_types::crypto::AlgorithmId;
use ic_types::{NodeId, PrincipalId};
use slog::Level;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::SystemTime;
use std::{env, fs};
use tempfile::TempDir;

const PUBLIC_KEYS_FILE: &str = "public_keys.pb";

#[test]
fn should_contain_no_keys_after_opening_non_existing_pubkey_store() {
    let temp_dir = temp_dir();
    let store = public_key_store(&temp_dir);

    assert!(store.node_signing_pubkey().is_none());
    assert!(store.committee_signing_pubkey().is_none());
    assert!(store.ni_dkg_dealing_encryption_pubkey().is_none());
    assert!(store.tls_certificate().is_none());
    assert!(store.idkg_dealing_encryption_pubkeys().is_empty());
}

#[test]
fn should_contain_correct_keys_after_opening_existing_pubkey_store() {
    let (generated_keys, crypto_root) = generate_node_keys_in_temp_dir();
    assert!(generated_keys.node_signing_pk.is_some());
    assert!(generated_keys.committee_signing_pk.is_some());
    assert!(generated_keys.dkg_dealing_encryption_pk.is_some());
    assert_eq!(generated_keys.idkg_dealing_encryption_pks.len(), 1);
    assert!(generated_keys.tls_certificate.is_some());

    let store = public_key_store(&crypto_root);

    assert_eq!(store.node_signing_pubkey(), generated_keys.node_signing_pk);
    assert_eq!(
        store.committee_signing_pubkey(),
        generated_keys.committee_signing_pk
    );
    assert_eq!(
        store.ni_dkg_dealing_encryption_pubkey(),
        generated_keys.dkg_dealing_encryption_pk
    );
    assert!(equal_ignoring_timestamp(
        &store.idkg_dealing_encryption_pubkeys(),
        &generated_keys.idkg_dealing_encryption_pks
    ));
    assert_eq!(
        store.tls_certificate(),
        generated_keys.tls_certificate.as_ref()
    );
}

#[test]
fn should_set_pubkeys_if_not_set() {
    let temp_dir = temp_dir();
    let mut store = public_key_store(&temp_dir);
    let (generated_keys, _temp_dir) = generate_node_keys_in_temp_dir();

    assert!(store.node_signing_pubkey().is_none());
    assert_matches!(
        store.set_once_node_signing_pubkey(generated_keys.node_signing_pk.clone().unwrap()),
        Ok(())
    );
    assert_eq!(store.node_signing_pubkey(), generated_keys.node_signing_pk);

    assert!(store.committee_signing_pubkey().is_none());
    assert_matches!(
        store.set_once_committee_signing_pubkey(
            generated_keys.committee_signing_pk.clone().unwrap()
        ),
        Ok(())
    );
    assert_eq!(
        store.committee_signing_pubkey(),
        generated_keys.committee_signing_pk
    );

    assert!(store.ni_dkg_dealing_encryption_pubkey().is_none());
    assert_matches!(
        store.set_once_ni_dkg_dealing_encryption_pubkey(
            generated_keys.dkg_dealing_encryption_pk.clone().unwrap()
        ),
        Ok(())
    );
    assert_eq!(
        store.ni_dkg_dealing_encryption_pubkey(),
        generated_keys.dkg_dealing_encryption_pk
    );

    assert!(store.tls_certificate().is_none());
    assert_matches!(
        store.set_once_tls_certificate(generated_keys.tls_certificate.clone().unwrap()),
        Ok(())
    );
    assert_eq!(
        store.tls_certificate(),
        generated_keys.tls_certificate.as_ref()
    );

    assert!(store.idkg_dealing_encryption_pubkeys().is_empty());
    assert_matches!(
        store.add_idkg_dealing_encryption_pubkey(
            generated_keys
                .idkg_dealing_encryption_pks
                .last()
                .expect("missing IDKG public key")
                .clone()
        ),
        Ok(())
    );
    assert!(equal_ignoring_timestamp(
        &store.idkg_dealing_encryption_pubkeys(),
        &generated_keys.idkg_dealing_encryption_pks
    ));
}

#[test]
fn should_log_when_adding_idkg_public_key() {
    let in_memory_logger = InMemoryReplicaLogger::new();
    let temp_dir = temp_dir();
    let mut store = ProtoPublicKeyStore::open(
        temp_dir.path(),
        PUBLIC_KEY_STORE_DATA_FILENAME,
        ReplicaLogger::from(&in_memory_logger),
    );

    assert_matches!(
        store.add_idkg_dealing_encryption_pubkey(public_key_with_key_value(123)),
        Ok(())
    );

    let logs = in_memory_logger.drain_logs();
    LogEntriesAssert::assert_that(logs)
        .has_only_one_message_containing(&Level::Debug, "Adding new IDKG dealing encryption public key \
        'PublicKey { version: 1, algorithm: Ed25519, key_value: [123, 123, 123, 123, 123, 123, 123, 123, 123, 123], \
        proof_data: None, timestamp: None }'");
}

#[test]
fn should_set_non_rotating_pubkeys_only_once() {
    let (generated_keys, crypto_root) = generate_node_keys_in_temp_dir();
    let mut store = public_key_store(&crypto_root);
    let some_pubkey = generated_keys.node_signing_pk.unwrap();
    let some_cert = generated_keys.tls_certificate.unwrap();

    assert!(store.node_signing_pubkey().is_some());
    assert_matches!(
        store.set_once_node_signing_pubkey(some_pubkey.clone()),
        Err(PublicKeySetOnceError::AlreadySet)
    );

    assert!(store.committee_signing_pubkey().is_some());
    assert_matches!(
        store.set_once_committee_signing_pubkey(some_pubkey.clone()),
        Err(PublicKeySetOnceError::AlreadySet)
    );

    assert!(store.ni_dkg_dealing_encryption_pubkey().is_some());
    assert_matches!(
        store.set_once_ni_dkg_dealing_encryption_pubkey(some_pubkey),
        Err(PublicKeySetOnceError::AlreadySet)
    );

    assert!(store.tls_certificate().is_some());
    assert_matches!(
        store.set_once_tls_certificate(some_cert),
        Err(PublicKeySetOnceError::AlreadySet)
    );
}

#[test]
fn should_persist_pubkeys_to_disk_when_setting_them() {
    let temp_dir = temp_dir();
    let mut store = public_key_store(&temp_dir);
    let (generated_keys, _temp_dir) = generate_node_keys_in_temp_dir();

    assert!(store
        .set_once_node_signing_pubkey(generated_keys.node_signing_pk.clone().unwrap())
        .is_ok());
    assert_eq!(
        public_key_store(&temp_dir).node_signing_pubkey(),
        generated_keys.node_signing_pk
    );

    assert!(store
        .set_once_committee_signing_pubkey(generated_keys.committee_signing_pk.clone().unwrap())
        .is_ok());
    assert_eq!(
        public_key_store(&temp_dir).committee_signing_pubkey(),
        generated_keys.committee_signing_pk
    );

    assert!(store
        .set_once_ni_dkg_dealing_encryption_pubkey(
            generated_keys.dkg_dealing_encryption_pk.clone().unwrap()
        )
        .is_ok());
    assert_eq!(
        public_key_store(&temp_dir).ni_dkg_dealing_encryption_pubkey(),
        generated_keys.dkg_dealing_encryption_pk
    );

    assert!(store
        .set_once_tls_certificate(generated_keys.tls_certificate.clone().unwrap())
        .is_ok());
    assert_eq!(
        public_key_store(&temp_dir).tls_certificate(),
        generated_keys.tls_certificate.as_ref()
    );

    let generated_idkg_pk = generated_keys
        .idkg_dealing_encryption_pks
        .last()
        .expect("missing IDKG public key")
        .clone();
    assert!(store
        .add_idkg_dealing_encryption_pubkey(generated_idkg_pk)
        .is_ok());
    assert!(equal_ignoring_timestamp(
        &public_key_store(&temp_dir).idkg_dealing_encryption_pubkeys(),
        &generated_keys.idkg_dealing_encryption_pks
    ));
}

#[test]
fn should_preserve_order_of_rotating_pubkeys() {
    let temp_dir = temp_dir();
    let mut store = public_key_store(&temp_dir);
    let pubkeys = vec![
        public_key_with_key_value(42),
        public_key_with_key_value(43),
        public_key_with_key_value(44),
    ];
    add_idkg_dealing_encryption_public_keys(&mut store, pubkeys.clone());

    assert_eq!(store.idkg_dealing_encryption_pubkeys(), pubkeys);
    assert_eq!(
        public_key_store(&temp_dir).idkg_dealing_encryption_pubkeys(),
        pubkeys
    );
}

#[test]
#[should_panic(expected = "error parsing public key store data")]
fn should_panic_on_opening_corrupt_pubkey_store() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let corrupt_store_file = temp_dir.path().join(PUBLIC_KEY_STORE_DATA_FILENAME);
    fs::write(corrupt_store_file, b"corrupt store content").expect("failed to write store");

    public_key_store(&temp_dir);
}

#[test]
#[should_panic(expected = "Failed to read public key store data: Permission denied")]
fn should_fail_to_read_without_read_permissions() {
    let temp_dir = mk_temp_dir_with_permissions(0o700);
    copy_file_to_dir(pubkey_store_in_test_resources().as_path(), temp_dir.path());
    fs::set_permissions(
        temp_dir.path().join(PUBLIC_KEYS_FILE),
        fs::Permissions::from_mode(0o000),
    )
    .expect("failed to set permissions");

    public_key_store(&temp_dir);
}

#[test]
fn should_fail_to_write_without_write_permissions() {
    let temp_dir = mk_temp_dir_with_permissions(0o700);
    copy_file_to_dir(pubkey_store_in_test_resources().as_path(), temp_dir.path());
    let mut pubkey_store =
        ProtoPublicKeyStore::open(temp_dir.path(), PUBLIC_KEYS_FILE, no_op_logger());
    fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o400))
        .expect("failed to set read-only permissions");

    let result = pubkey_store.add_idkg_dealing_encryption_pubkey(public_key_with_key_value(123));

    assert_matches!(result, Err(PublicKeyAddError::Io(io_error)) if io_error.kind() == std::io::ErrorKind::PermissionDenied);

    fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o700)).expect(
        "failed to change permissions of temp_dir so that writing is possible \
               again, so that the directory can automatically be cleaned up",
    );
}

#[test]
// The public key store deserialized in this test was generated by calling
// `generate_node_keys_in_temp_dir` in a test, pausing execution directly
// afterwards (with `std::thread::sleep`) and copying the public key store
// from the temporary directory into the test resources via the terminal.
fn should_deserialize_existing_public_key_store() {
    let store =
        ProtoPublicKeyStore::open(test_resources().as_path(), PUBLIC_KEYS_FILE, no_op_logger());

    assert_eq!(
        store.node_signing_pubkey(),
        Some(PublicKey {
            version: 0,
            algorithm: AlgorithmId::Ed25519 as i32,
            key_value: hex_decode(
                "58d558c7586efb32f4667ee9a302877da97aa1136cda92af4d7a4f8873f9434f"
            ),
            proof_data: None,
            timestamp: None,
        })
    );
    //node_id is derived from node signing public key
    //so we also check here for the expected hard-coded value
    assert_eq!(
        derive_node_id(&store.node_signing_pubkey().unwrap()),
        NodeId::new(
            PrincipalId::from_str(
                "4inqb-2zcvk-f6yql-sowol-vg3es-z24jd-jrkow-mhnsd-ukvfp-fak5p-aae"
            )
            .unwrap()
        )
    );

    assert_eq!(
        store.committee_signing_pubkey(),
        Some(PublicKey {
            version: 0,
            algorithm: AlgorithmId::MultiBls12_381 as i32,
            key_value: hex_decode(
                "8dab94740858cc96e8df512d8d81730a94d0f3534f30\
                cebd35ee2006ce4a449cad611dd7d97bbc44256932da4d4a76a70b9f347e4a989a3073fc7\
                c2d51bf30804ebbc5c3c6da08b8392d2482473290aff428868caabbc26eec4e7bc59209eb0a"
            ),
            proof_data: Some(hex_decode(
                "afc3038c06223258a14af7c942428fe42f89f8d733e4f\
                5ea8d34a90c0df142697802a6f22633df890a1ce5b774b23aed"
            )),
            timestamp: None,
        })
    );
    assert_eq!(
        store.ni_dkg_dealing_encryption_pubkey(),
        Some(PublicKey {
            version: 0,
            algorithm: AlgorithmId::Groth20_Bls12_381 as i32,
            key_value: hex_decode(
                "ad36a01cbd40dcfa36ec21a96bedcab17372a9cd2b9eba6171ebeb28dd041a\
                    d5cbbdbb4bed55f59938e8ffb3dd69e386"
            ),
            proof_data: Some(hex_decode(
                "a1781847726f7468323057697468506f705f42\
                6c7331325f333831a367706f705f6b65795830b751c9585044139f80abdebf38d7f30\
                aeb282f178a5e8c284f279eaad1c90d9927e56cac0150646992bce54e08d317ea6963\
                68616c6c656e676558203bb20c5e9c75790f63aae921316912ffc80d6d03946dd21f8\
                5c35159ca030ec668726573706f6e7365582063d6cf189635c0f3111f97e69ae0af8f\
                1594b0f00938413d89dbafc326340384"
            )),
            timestamp: None,
        })
    );
    assert_eq!(
        store.idkg_dealing_encryption_pubkeys(),
        vec![
            (PublicKey {
                version: 0,
                algorithm: AlgorithmId::MegaSecp256k1 as i32,
                key_value: hex_decode(
                    "03e1e1f76e9d834221a26c4a080b65e60d3b6f9c1d6e5b880abf916a364893da2e"
                ),
                proof_data: None,
                timestamp: None,
            })
        ]
    );
    assert_eq!(
        store.tls_certificate(),
        Some(&X509PublicKeyCert {
            certificate_der: hex_decode(
                "3082015630820108a00302010202140098d074\
                7d24ca04a2f036d8665402b4ea784830300506032b6570304a3148304606035504030\
                c3f34696e71622d327a63766b2d663679716c2d736f776f6c2d76673365732d7a3234\
                6a642d6a726b6f772d6d686e73642d756b7666702d66616b35702d6161653020170d3\
                232313130343138313231345a180f39393939313233313233353935395a304a314830\
                4606035504030c3f34696e71622d327a63766b2d663679716c2d736f776f6c2d76673\
                365732d7a32346a642d6a726b6f772d6d686e73642d756b7666702d66616b35702d61\
                6165302a300506032b6570032100246acd5f38372411103768e91169dadb7370e9990\
                9a65639186ac6d1c36f3735300506032b6570034100d37e5ccfc32146767e5fd73343\
                649f5b5564eb78e6d8d424d8f01240708bc537a2a9bcbcf6c884136d18d2b475706d7\
                bb905f52faf28707735f1d90ab654380b"
            ),
        })
    );
}

fn equal_ignoring_timestamp(left: &Vec<PublicKey>, right: &Vec<PublicKey>) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right.iter())
            .all(|(left_pk, right_pk)| left_pk.equal_ignoring_timestamp(right_pk))
}

mod timestamps {
    use super::*;
    use crate::public_key_store::PublicKeyGenerationTimestamps;
    use ic_types::time::GENESIS;
    use ic_types::Time;
    use std::time::Duration;

    #[test]
    fn should_strip_timestamp_when_returning_node_signing_pubkey() {
        let temp_dir = temp_dir();
        let mut store = public_key_store(&temp_dir);
        store
            .set_once_node_signing_pubkey(public_key_with_timestamp(GENESIS))
            .expect("cannot set public key");

        let retrieved_public_key = store.node_signing_pubkey().expect("missing public key");

        assert!(retrieved_public_key.timestamp.is_none())
    }

    #[test]
    fn should_strip_timestamp_when_returning_committee_signing_pubkey() {
        let temp_dir = temp_dir();
        let mut store = public_key_store(&temp_dir);
        store
            .set_once_committee_signing_pubkey(public_key_with_timestamp(GENESIS))
            .expect("cannot set public key");

        let retrieved_public_key = store
            .committee_signing_pubkey()
            .expect("missing public key");

        assert!(retrieved_public_key.timestamp.is_none())
    }

    #[test]
    fn should_strip_timestamp_when_returning_ni_dkg_dealing_encryption_pubkey() {
        let temp_dir = temp_dir();
        let mut store = public_key_store(&temp_dir);
        store
            .set_once_ni_dkg_dealing_encryption_pubkey(public_key_with_timestamp(GENESIS))
            .expect("cannot set public key");

        let retrieved_public_key = store
            .ni_dkg_dealing_encryption_pubkey()
            .expect("missing public key");

        assert!(retrieved_public_key.timestamp.is_none())
    }

    #[test]
    fn should_strip_timestamp_when_returning_idkg_dealing_encryption_pubkeys() {
        let temp_dir = temp_dir();
        let mut store = public_key_store(&temp_dir);
        add_idkg_dealing_encryption_public_keys(
            &mut store,
            vec![
                public_key_with_timestamp(GENESIS),
                public_key_with_key_value(42),
                public_key_with_timestamp(GENESIS + Duration::from_millis(1)),
            ],
        );

        for public_key in store.idkg_dealing_encryption_pubkeys() {
            assert!(public_key.timestamp.is_none())
        }
    }

    #[test]
    fn should_retrieve_generated_public_keys_timestamps() {
        let temp_dir = temp_dir();
        let mut store = public_key_store(&temp_dir);
        let node_signing_pk_timestamp =
            Time::from_millis_since_unix_epoch(1_620_328_630_000).expect("should not overflow");
        let committee_signing_pk_timestamp = node_signing_pk_timestamp + Duration::from_millis(1);
        let nidkg_dealing_encryption_pk_timestamp =
            node_signing_pk_timestamp + Duration::from_millis(2);
        let last_idkg_dealing_encryption_pk_timestamp =
            node_signing_pk_timestamp + Duration::from_millis(3);
        store
            .set_once_node_signing_pubkey(public_key_with_timestamp(node_signing_pk_timestamp))
            .expect("error setting public key");
        store
            .set_once_committee_signing_pubkey(public_key_with_timestamp(
                committee_signing_pk_timestamp,
            ))
            .expect("error setting public key");
        store
            .set_once_ni_dkg_dealing_encryption_pubkey(public_key_with_timestamp(
                nidkg_dealing_encryption_pk_timestamp,
            ))
            .expect("error setting public key");
        store
            .add_idkg_dealing_encryption_pubkey(public_key_with_timestamp(
                last_idkg_dealing_encryption_pk_timestamp,
            ))
            .expect("error setting public key");

        let timestamps = store.generation_timestamps();

        assert_eq!(
            timestamps,
            PublicKeyGenerationTimestamps {
                node_signing_public_key: Some(node_signing_pk_timestamp),
                committee_signing_public_key: Some(committee_signing_pk_timestamp),
                dkg_dealing_encryption_public_key: Some(nidkg_dealing_encryption_pk_timestamp),
                last_idkg_dealing_encryption_public_key: Some(
                    last_idkg_dealing_encryption_pk_timestamp
                )
            }
        )
    }

    #[test]
    fn should_retrieve_timestamp_of_last_idkg_dealing_encryption_public_key() {
        let temp_dir = temp_dir();
        let mut store = public_key_store(&temp_dir);
        add_idkg_dealing_encryption_public_keys(
            &mut store,
            vec![
                public_key_with_timestamp(GENESIS),
                public_key_with_key_value(42),
                public_key_with_timestamp(GENESIS + Duration::from_millis(1)),
                public_key_with_timestamp(GENESIS + Duration::from_millis(2)),
            ],
        );

        let last_idkg_generated_pk_timestamp = store
            .generation_timestamps()
            .last_idkg_dealing_encryption_public_key
            .expect("missing IDKG timestamp");

        assert_eq!(
            last_idkg_generated_pk_timestamp,
            GENESIS + Duration::from_millis(2)
        );
    }

    #[test]
    fn should_not_have_timestamps_when_public_keys_unset() {
        let temp_dir = temp_dir();
        let store = public_key_store(&temp_dir);

        let timestamps = store.generation_timestamps();

        assert_eq!(
            timestamps,
            PublicKeyGenerationTimestamps {
                node_signing_public_key: None,
                committee_signing_public_key: None,
                dkg_dealing_encryption_public_key: None,
                last_idkg_dealing_encryption_public_key: None
            }
        )
    }

    #[test]
    fn should_not_have_timestamp_when_public_key_does_not_have_one() {
        let temp_dir = temp_dir();
        let mut store = public_key_store(&temp_dir);
        store
            .set_once_node_signing_pubkey(public_key_without_timestamp())
            .expect("error setting public key");

        let generation_timestamp = store.generation_timestamps().node_signing_public_key;

        assert!(generation_timestamp.is_none());
    }

    #[test]
    fn should_discard_timestamp_when_cannot_be_converted_to_u64_nanos() {
        let temp_dir = temp_dir();
        let mut store = public_key_store(&temp_dir);
        store
            .set_once_node_signing_pubkey(public_key_with_raw_timestamp(u64::MAX))
            .expect("error setting public key");

        let node_signing_key_timestamp = store.generation_timestamps().node_signing_public_key;

        assert!(node_signing_key_timestamp.is_none());
    }

    fn public_key_with_timestamp(time: Time) -> PublicKey {
        public_key_with_raw_timestamp(time.as_millis_since_unix_epoch())
    }

    fn public_key_with_raw_timestamp(millis_since_epoch: u64) -> PublicKey {
        PublicKey {
            version: 1,
            algorithm: AlgorithmId::Ed25519 as i32,
            key_value: [42; 10].to_vec(),
            proof_data: None,
            timestamp: Some(millis_since_epoch),
        }
    }

    fn public_key_without_timestamp() -> PublicKey {
        PublicKey {
            version: 1,
            algorithm: AlgorithmId::Ed25519 as i32,
            key_value: [42; 10].to_vec(),
            proof_data: None,
            timestamp: None,
        }
    }
}

mod retain_most_recent_idkg_public_keys_up_to_inclusive {
    use super::*;
    use crate::public_key_store::PublicKeyRetainError;
    use std::time::Duration;

    #[test]
    fn should_fail_when_idkg_oldest_public_key_not_found() {
        let temp_dir = temp_dir();
        let mut store = public_key_store(&temp_dir);
        let oldest_public_key = public_key_with_key_value(42);

        let result = store.retain_most_recent_idkg_public_keys_up_to_inclusive(&oldest_public_key);

        assert_matches!(result, Err(PublicKeyRetainError::OldestPublicKeyNotFound));
    }

    #[test]
    fn should_not_delete_single_public_key() {
        let temp_dir = temp_dir();
        let mut store = public_key_store(&temp_dir);
        let public_key = public_key_with_key_value(42);
        assert_matches!(
            store.add_idkg_dealing_encryption_pubkey(public_key.clone()),
            Ok(())
        );

        assert_matches!(
            store.retain_most_recent_idkg_public_keys_up_to_inclusive(&public_key),
            Ok(false)
        );

        assert_eq!(store.idkg_dealing_encryption_pubkeys(), vec![public_key]);
    }

    #[test]
    fn should_retain_active_public_keys() {
        let temp_dir = temp_dir();
        let mut store = public_key_store(&temp_dir);
        add_idkg_dealing_encryption_public_keys(
            &mut store,
            vec![
                public_key_with_key_value(0),
                public_key_with_key_value(1),
                public_key_with_key_value(2),
                public_key_with_key_value(3),
                public_key_with_key_value(4),
            ],
        );

        assert_matches!(
            store
                .retain_most_recent_idkg_public_keys_up_to_inclusive(&public_key_with_key_value(2)),
            Ok(true)
        );

        assert_eq!(
            store.idkg_dealing_encryption_pubkeys(),
            vec![
                public_key_with_key_value(2),
                public_key_with_key_value(3),
                public_key_with_key_value(4)
            ]
        )
    }

    #[test]
    fn should_delete_non_retained_keys_from_disk() {
        let temp_dir = temp_dir();
        let mut store = public_key_store(&temp_dir);
        add_idkg_dealing_encryption_public_keys(
            &mut store,
            vec![
                public_key_with_key_value(0),
                public_key_with_key_value(1),
                public_key_with_key_value(2),
                public_key_with_key_value(3),
                public_key_with_key_value(4),
            ],
        );

        assert_matches!(
            store
                .retain_most_recent_idkg_public_keys_up_to_inclusive(&public_key_with_key_value(2)),
            Ok(true)
        );

        assert_eq!(
            public_key_store(&temp_dir).idkg_dealing_encryption_pubkeys(),
            vec![
                public_key_with_key_value(2),
                public_key_with_key_value(3),
                public_key_with_key_value(4)
            ]
        )
    }

    #[test]
    fn should_be_idempotent() {
        let temp_dir = temp_dir();
        let mut store = public_key_store(&temp_dir);
        add_idkg_dealing_encryption_public_keys(
            &mut store,
            vec![
                public_key_with_key_value(0),
                public_key_with_key_value(1),
                public_key_with_key_value(2),
                public_key_with_key_value(3),
                public_key_with_key_value(4),
            ],
        );

        assert_matches!(
            store
                .retain_most_recent_idkg_public_keys_up_to_inclusive(&public_key_with_key_value(2)),
            Ok(true)
        );
        let keys_after_first_retain = store.idkg_dealing_encryption_pubkeys();
        assert_matches!(
            store
                .retain_most_recent_idkg_public_keys_up_to_inclusive(&public_key_with_key_value(2)),
            Ok(false)
        );
        let keys_after_second_retain = store.idkg_dealing_encryption_pubkeys();

        assert_eq!(keys_after_first_retain, keys_after_second_retain);
    }

    #[test]
    fn should_keep_largest_suffix_even_when_public_keys_not_distinct() {
        let temp_dir = temp_dir();
        let mut store = public_key_store(&temp_dir);
        add_idkg_dealing_encryption_public_keys(
            &mut store,
            vec![
                public_key_with_key_value(0),
                public_key_with_key_value(1),
                public_key_with_key_value(1),
                public_key_with_key_value(2),
            ],
        );

        assert_matches!(
            store
                .retain_most_recent_idkg_public_keys_up_to_inclusive(&public_key_with_key_value(1)),
            Ok(true)
        );

        assert_eq!(
            store.idkg_dealing_encryption_pubkeys(),
            vec![
                public_key_with_key_value(1),
                public_key_with_key_value(1),
                public_key_with_key_value(2)
            ]
        )
    }

    #[test]
    fn should_find_oldest_public_key_with_different_timestamp() {
        let temp_dir = temp_dir();
        let mut store = public_key_store(&temp_dir);
        let generated_public_key_with_timestamp = PublicKey {
            timestamp: Some(1000),
            ..public_key_with_key_value(1)
        };
        add_idkg_dealing_encryption_public_keys(
            &mut store,
            vec![
                public_key_with_key_value(0),
                generated_public_key_with_timestamp,
                public_key_with_key_value(1),
                public_key_with_key_value(2),
            ],
        );

        assert_matches!(
            store
                .retain_most_recent_idkg_public_keys_up_to_inclusive(&public_key_with_key_value(1)),
            Ok(true)
        );

        assert_eq!(
            store.idkg_dealing_encryption_pubkeys(),
            vec![
                public_key_with_key_value(1),
                public_key_with_key_value(1),
                public_key_with_key_value(2)
            ]
        )
    }

    #[test]
    fn should_not_modify_public_key_store_on_disk_when_oldest_public_key_is_first() {
        let temp_dir = temp_dir();
        let mut store = public_key_store(&temp_dir);
        add_idkg_dealing_encryption_public_keys(
            &mut store,
            vec![
                public_key_with_key_value(0),
                public_key_with_key_value(1),
                public_key_with_key_value(2),
                public_key_with_key_value(3),
                public_key_with_key_value(4),
            ],
        );

        let last_modification_time_before_retain =
            public_key_store_last_modification_time(&temp_dir);
        //ensure that system clock moved past `last_modification_time_before_retain`
        std::thread::sleep(Duration::from_millis(100));
        assert_matches!(
            store
                .retain_most_recent_idkg_public_keys_up_to_inclusive(&public_key_with_key_value(0)),
            Ok(false)
        );
        let last_modification_time_after_retain =
            public_key_store_last_modification_time(&temp_dir);

        assert_eq!(
            last_modification_time_before_retain,
            last_modification_time_after_retain
        );
    }

    #[test]
    fn should_log_deleted_and_retained_public_keys() {
        let temp_dir = temp_dir();
        let in_memory_logger = InMemoryReplicaLogger::new();
        let mut store = ProtoPublicKeyStore::open(
            temp_dir.path(),
            PUBLIC_KEY_STORE_DATA_FILENAME,
            ReplicaLogger::from(&in_memory_logger),
        );
        add_idkg_dealing_encryption_public_keys(
            &mut store,
            vec![
                public_key_with_key_value(0),
                public_key_with_key_value(1),
                public_key_with_key_value(2),
                public_key_with_key_value(3),
                public_key_with_key_value(4),
            ],
        );

        assert_matches!(
            store
                .retain_most_recent_idkg_public_keys_up_to_inclusive(&public_key_with_key_value(2)),
            Ok(true)
        );

        let logs = in_memory_logger.drain_logs();
        LogEntriesAssert::assert_that(logs)
            .has_only_one_message_containing(&Level::Debug, "Deleting IDKG dealing encryption public key 'PublicKey { version: 1, algorithm: Ed25519, key_value: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]")
            .has_only_one_message_containing(&Level::Debug, "Deleting IDKG dealing encryption public key 'PublicKey { version: 1, algorithm: Ed25519, key_value: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1]")
            .has_only_one_message_containing(&Level::Debug, "Retaining IDKG dealing encryption public key 'PublicKey { version: 1, algorithm: Ed25519, key_value: [2, 2, 2, 2, 2, 2, 2, 2, 2, 2]")
            .has_only_one_message_containing(&Level::Debug, "Retaining IDKG dealing encryption public key 'PublicKey { version: 1, algorithm: Ed25519, key_value: [3, 3, 3, 3, 3, 3, 3, 3, 3, 3]")
            .has_only_one_message_containing(&Level::Debug, "Retaining IDKG dealing encryption public key 'PublicKey { version: 1, algorithm: Ed25519, key_value: [4, 4, 4, 4, 4, 4, 4, 4, 4, 4]");
    }
}

fn add_idkg_dealing_encryption_public_keys(
    store: &mut ProtoPublicKeyStore,
    public_keys: Vec<PublicKey>,
) {
    for public_key in public_keys {
        assert_matches!(store.add_idkg_dealing_encryption_pubkey(public_key), Ok(()))
    }
}

mod idkg_dealing_encryption_pubkeys_count {
    use super::*;

    #[test]
    fn should_correctly_return_count_of_idkg_dealing_encryption_public_keys_when_no_keys_present() {
        let temp_dir = temp_dir();
        let store = public_key_store(&temp_dir);

        let key_count = store.idkg_dealing_encryption_pubkeys_count();

        assert_eq!(key_count, 0);
    }

    #[test]
    fn should_correctly_return_count_of_idkg_dealing_encryption_public_keys_when_all_keys_present()
    {
        let (_generated_keys, crypto_root) = generate_node_keys_in_temp_dir();
        let store = public_key_store(&crypto_root);

        let key_count = store.idkg_dealing_encryption_pubkeys_count();

        assert_eq!(key_count, 1);
    }

    #[test]
    fn should_correctly_return_count_of_idkg_dealing_encryption_public_keys_when_all_keys_except_idkg_dealing_encryption_key_present(
    ) {
        let temp_dir = temp_dir();
        let mut store = public_key_store(&temp_dir);
        assert_matches!(
            store.set_once_node_signing_pubkey(public_key_with_key_value(1)),
            Ok(())
        );
        assert_matches!(
            store.set_once_committee_signing_pubkey(public_key_with_key_value(2)),
            Ok(())
        );
        assert_matches!(
            store.set_once_tls_certificate(public_key_certificate_with_der_value(1)),
            Ok(())
        );
        assert_matches!(
            store.set_once_ni_dkg_dealing_encryption_pubkey(public_key_with_key_value(4)),
            Ok(())
        );

        let key_count = store.idkg_dealing_encryption_pubkeys_count();

        assert_eq!(key_count, 0);
    }

    #[test]
    fn should_correctly_return_count_of_idkg_dealing_encryption_public_keys_when_multiple_idkg_keys_present(
    ) {
        let temp_dir = temp_dir();
        let mut store = public_key_store(&temp_dir);
        add_idkg_dealing_encryption_public_keys(
            &mut store,
            vec![
                public_key_with_key_value(42),
                public_key_with_key_value(43),
                public_key_with_key_value(44),
            ],
        );

        let key_count = store.idkg_dealing_encryption_pubkeys_count();

        assert_eq!(key_count, 3);
    }
}

fn hex_decode<T: AsRef<[u8]>>(data: T) -> Vec<u8> {
    hex::decode(data).expect("failed to decode hex")
}

fn pubkey_store_in_test_resources() -> PathBuf {
    test_resources().join(PUBLIC_KEYS_FILE)
}

fn test_resources() -> PathBuf {
    let cargo_manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    Path::new(&cargo_manifest_dir).join("test_resources")
}

fn copy_file_to_dir(source_file: &Path, target_dir: &Path) {
    let filename = source_file.file_name().expect("expected file name");
    let target_file = target_dir.join(filename);
    fs::copy(source_file, target_file).expect("could not copy source file");
}

fn public_key_with_key_value(key_value: u8) -> PublicKey {
    PublicKey {
        version: 1,
        algorithm: AlgorithmId::Ed25519 as i32,
        key_value: [key_value; 10].to_vec(),
        proof_data: None,
        timestamp: None,
    }
}
fn public_key_certificate_with_der_value(certificate_der: u8) -> X509PublicKeyCert {
    X509PublicKeyCert {
        certificate_der: [certificate_der; 10].to_vec(),
    }
}

fn generate_node_keys_in_temp_dir() -> (NodePublicKeys, TempDir) {
    let (config, temp_dir) = CryptoConfig::new_in_temp_dir();
    let (_keys, _node_id) = get_node_keys_or_generate_if_missing(&config, None);
    let keys_from_disk = read_from_public_key_store_file(temp_dir.path());
    assert!(keys_from_disk.node_signing_pk.is_some());
    assert!(keys_from_disk.committee_signing_pk.is_some());
    assert!(keys_from_disk.tls_certificate.is_some());
    assert!(keys_from_disk.dkg_dealing_encryption_pk.is_some());
    assert_eq!(keys_from_disk.idkg_dealing_encryption_pks.len(), 1,);
    (keys_from_disk, temp_dir)
}

fn read_from_public_key_store_file(crypto_root: &Path) -> NodePublicKeys {
    read_node_public_keys(crypto_root).expect("failed to read public keys")
}

fn temp_dir() -> TempDir {
    tempfile::Builder::new()
        .prefix("ic_crypto_")
        .tempdir()
        .expect("failed to create temporary crypto directory")
}

fn public_key_store(temp_dir: &TempDir) -> ProtoPublicKeyStore {
    ProtoPublicKeyStore::open(
        temp_dir.path(),
        PUBLIC_KEY_STORE_DATA_FILENAME,
        no_op_logger(),
    )
}

fn public_key_store_last_modification_time(temp_dir: &TempDir) -> SystemTime {
    fs::metadata(temp_dir.path().join(PUBLIC_KEY_STORE_DATA_FILENAME))
        .expect("cannot read metadata of public key store")
        .modified()
        .expect("cannot ready system time")
}
