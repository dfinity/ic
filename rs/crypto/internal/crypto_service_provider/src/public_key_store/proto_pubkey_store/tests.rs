#![allow(clippy::unwrap_used)]

use super::super::PK_DATA_FILENAME;
use crate::public_key_store::proto_pubkey_store::ProtoPublicKeyStore;
use crate::public_key_store::{PublicKeySetOnceError, PublicKeyStore};
use crate::read_node_public_keys;
use ic_config::crypto::CryptoConfig;
use ic_crypto_node_key_generation::get_node_keys_or_generate_if_missing;
use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_types::crypto::AlgorithmId;
use std::path::Path;
use tempfile::TempDir;

#[test]
fn should_contain_no_keys_after_opening_non_existing_pubkey_store() {
    let temp_dir = temp_dir();

    let pks = ProtoPublicKeyStore::open(temp_dir.path(), PK_DATA_FILENAME);

    assert!(pks.node_signing_pubkey().is_none());
    assert!(pks.committee_signing_pubkey().is_none());
    assert!(pks.ni_dkg_dealing_encryption_pubkey().is_none());
    assert!(pks.tls_certificate().is_none());
    assert!(pks.idkg_dealing_encryption_pubkeys().is_empty());
}

#[test]
fn should_contain_correct_keys_after_opening_existing_pubkey_store() {
    let (npks, crypto_root) = generate_node_keys_in_temp_dir();
    assert!(npks.node_signing_pk.is_some());
    assert!(npks.committee_signing_pk.is_some());
    assert!(npks.dkg_dealing_encryption_pk.is_some());
    assert!(npks.idkg_dealing_encryption_pk.is_some());
    assert!(!npks.idkg_dealing_encryption_pks.is_empty());
    assert!(npks.tls_certificate.is_some());

    let pks = ProtoPublicKeyStore::open(crypto_root.path(), PK_DATA_FILENAME);

    assert_eq!(pks.node_signing_pubkey(), npks.node_signing_pk.as_ref());
    assert_eq!(
        pks.committee_signing_pubkey(),
        npks.committee_signing_pk.as_ref()
    );
    assert_eq!(
        pks.ni_dkg_dealing_encryption_pubkey(),
        npks.dkg_dealing_encryption_pk.as_ref()
    );
    assert_eq!(
        pks.idkg_dealing_encryption_pubkeys(),
        &npks.idkg_dealing_encryption_pks
    );
    assert_eq!(pks.tls_certificate(), npks.tls_certificate.as_ref());
}

#[test]
fn should_set_pubkeys_if_not_set() {
    let temp_dir = temp_dir();
    let mut pks = ProtoPublicKeyStore::open(temp_dir.path(), PK_DATA_FILENAME);
    let (npks, _temp_dir) = generate_node_keys_in_temp_dir();

    assert!(pks.node_signing_pubkey().is_none());
    assert!(matches!(
        pks.set_once_node_signing_pubkey(npks.node_signing_pk.clone().unwrap()),
        Ok(())
    ));
    assert_eq!(pks.node_signing_pubkey(), npks.node_signing_pk.as_ref());

    assert!(pks.committee_signing_pubkey().is_none());
    assert!(matches!(
        pks.set_once_committee_signing_pubkey(npks.committee_signing_pk.clone().unwrap()),
        Ok(())
    ));
    assert_eq!(
        pks.committee_signing_pubkey(),
        npks.committee_signing_pk.as_ref()
    );

    assert!(pks.ni_dkg_dealing_encryption_pubkey().is_none());
    assert!(matches!(
        pks.set_once_ni_dkg_dealing_encryption_pubkey(
            npks.dkg_dealing_encryption_pk.clone().unwrap()
        ),
        Ok(())
    ));
    assert_eq!(
        pks.ni_dkg_dealing_encryption_pubkey(),
        npks.dkg_dealing_encryption_pk.as_ref()
    );

    assert!(pks.tls_certificate().is_none());
    assert!(matches!(
        pks.set_once_tls_certificate(npks.tls_certificate.clone().unwrap()),
        Ok(())
    ));
    assert_eq!(pks.tls_certificate(), npks.tls_certificate.as_ref());

    assert!(pks.idkg_dealing_encryption_pubkeys().is_empty());
    assert!(matches!(
        pks.set_idkg_dealing_encryption_pubkeys(npks.idkg_dealing_encryption_pks.clone()),
        Ok(())
    ));
    assert_eq!(
        pks.idkg_dealing_encryption_pubkeys(),
        &npks.idkg_dealing_encryption_pks
    );
}

#[test]
fn should_set_non_rotating_pubkeys_only_once() {
    let (npks, crypto_root) = generate_node_keys_in_temp_dir();
    let mut pks = ProtoPublicKeyStore::open(crypto_root.path(), PK_DATA_FILENAME);
    let some_pubkey = npks.node_signing_pk.unwrap();
    let some_cert = npks.tls_certificate.unwrap();

    assert!(pks.node_signing_pubkey().is_some());
    assert!(matches!(
        pks.set_once_node_signing_pubkey(some_pubkey.clone()),
        Err(PublicKeySetOnceError::AlreadySet)
    ));

    assert!(pks.committee_signing_pubkey().is_some());
    assert!(matches!(
        pks.set_once_committee_signing_pubkey(some_pubkey.clone()),
        Err(PublicKeySetOnceError::AlreadySet)
    ));

    assert!(pks.ni_dkg_dealing_encryption_pubkey().is_some());
    assert!(matches!(
        pks.set_once_ni_dkg_dealing_encryption_pubkey(some_pubkey),
        Err(PublicKeySetOnceError::AlreadySet)
    ));

    assert!(pks.tls_certificate().is_some());
    assert!(matches!(
        pks.set_once_tls_certificate(some_cert),
        Err(PublicKeySetOnceError::AlreadySet)
    ));
}

#[test]
fn should_persist_pubkeys_to_disk_when_setting_them() {
    let temp_dir = temp_dir();
    let mut pks = ProtoPublicKeyStore::open(temp_dir.path(), PK_DATA_FILENAME);
    let (npks, _temp_dir) = generate_node_keys_in_temp_dir();

    assert!(pks
        .set_once_node_signing_pubkey(npks.node_signing_pk.clone().unwrap())
        .is_ok());
    assert_eq!(
        ProtoPublicKeyStore::open(temp_dir.path(), PK_DATA_FILENAME).node_signing_pubkey(),
        npks.node_signing_pk.as_ref()
    );

    assert!(pks
        .set_once_committee_signing_pubkey(npks.committee_signing_pk.clone().unwrap())
        .is_ok());
    assert_eq!(
        ProtoPublicKeyStore::open(temp_dir.path(), PK_DATA_FILENAME).committee_signing_pubkey(),
        npks.committee_signing_pk.as_ref()
    );

    assert!(pks
        .set_once_ni_dkg_dealing_encryption_pubkey(npks.dkg_dealing_encryption_pk.clone().unwrap())
        .is_ok());
    assert_eq!(
        ProtoPublicKeyStore::open(temp_dir.path(), PK_DATA_FILENAME)
            .ni_dkg_dealing_encryption_pubkey(),
        npks.dkg_dealing_encryption_pk.as_ref()
    );

    assert!(pks
        .set_once_tls_certificate(npks.tls_certificate.clone().unwrap())
        .is_ok());
    assert_eq!(
        ProtoPublicKeyStore::open(temp_dir.path(), PK_DATA_FILENAME).tls_certificate(),
        npks.tls_certificate.as_ref()
    );

    assert!(pks
        .set_idkg_dealing_encryption_pubkeys(npks.idkg_dealing_encryption_pks.clone())
        .is_ok());
    assert_eq!(
        ProtoPublicKeyStore::open(temp_dir.path(), PK_DATA_FILENAME)
            .idkg_dealing_encryption_pubkeys(),
        &npks.idkg_dealing_encryption_pks
    );
}

#[test]
fn should_preserve_order_of_rotating_pubkeys() {
    let temp_dir = temp_dir();
    let mut pks = ProtoPublicKeyStore::open(temp_dir.path(), PK_DATA_FILENAME);
    let pubkeys = vec![
        public_key_with(42),
        public_key_with(43),
        public_key_with(44),
    ];

    assert!(pks
        .set_idkg_dealing_encryption_pubkeys(pubkeys.clone())
        .is_ok());
    assert_eq!(pks.idkg_dealing_encryption_pubkeys(), &pubkeys);
    assert_eq!(
        ProtoPublicKeyStore::open(temp_dir.path(), PK_DATA_FILENAME)
            .idkg_dealing_encryption_pubkeys(),
        &pubkeys
    );
}

fn public_key_with(data: u8) -> PublicKey {
    PublicKey {
        version: 1,
        algorithm: AlgorithmId::Ed25519 as i32,
        key_value: [data; 10].to_vec(),
        proof_data: None,
        timestamp: None,
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
    assert!(keys_from_disk.idkg_dealing_encryption_pk.is_some());
    assert_eq!(keys_from_disk.idkg_dealing_encryption_pks.len(), 1,);
    assert_eq!(
        keys_from_disk.idkg_dealing_encryption_pk.as_ref(),
        keys_from_disk.idkg_dealing_encryption_pks.first()
    );
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
