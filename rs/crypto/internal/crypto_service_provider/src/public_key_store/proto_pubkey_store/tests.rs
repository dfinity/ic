#![allow(clippy::unwrap_used)]

use crate::public_key_store::proto_pubkey_store::ProtoPublicKeyStore;
use crate::public_key_store::read_node_public_keys;
use crate::public_key_store::{PublicKeySetOnceError, PublicKeyStore};
use crate::PUBLIC_KEY_STORE_DATA_FILENAME;
use ic_config::crypto::CryptoConfig;
use ic_crypto_internal_csp_test_utils::files::mk_temp_dir_with_permissions;
use ic_crypto_node_key_generation::get_node_keys_or_generate_if_missing;
use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_protobuf::registry::crypto::v1::{PublicKey, X509PublicKeyCert};
use ic_types::crypto::AlgorithmId;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::{env, fs};
use tempfile::TempDir;

const PUBLIC_KEYS_FILE: &str = "public_keys.pb";

#[test]
fn should_contain_no_keys_after_opening_non_existing_pubkey_store() {
    let temp_dir = temp_dir();

    let store = ProtoPublicKeyStore::open(temp_dir.path(), PUBLIC_KEY_STORE_DATA_FILENAME);

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

    let store = ProtoPublicKeyStore::open(crypto_root.path(), PUBLIC_KEY_STORE_DATA_FILENAME);

    assert_eq!(
        store.node_signing_pubkey(),
        generated_keys.node_signing_pk.as_ref()
    );
    assert_eq!(
        store.committee_signing_pubkey(),
        generated_keys.committee_signing_pk.as_ref()
    );
    assert_eq!(
        store.ni_dkg_dealing_encryption_pubkey(),
        generated_keys.dkg_dealing_encryption_pk.as_ref()
    );
    assert_eq!(
        store.idkg_dealing_encryption_pubkeys(),
        &generated_keys.idkg_dealing_encryption_pks
    );
    assert_eq!(
        store.tls_certificate(),
        generated_keys.tls_certificate.as_ref()
    );
}

#[test]
fn should_set_pubkeys_if_not_set() {
    let temp_dir = temp_dir();
    let mut store = ProtoPublicKeyStore::open(temp_dir.path(), PUBLIC_KEY_STORE_DATA_FILENAME);
    let (generated_keys, _temp_dir) = generate_node_keys_in_temp_dir();

    assert!(store.node_signing_pubkey().is_none());
    assert!(matches!(
        store.set_once_node_signing_pubkey(generated_keys.node_signing_pk.clone().unwrap()),
        Ok(())
    ));
    assert_eq!(
        store.node_signing_pubkey(),
        generated_keys.node_signing_pk.as_ref()
    );

    assert!(store.committee_signing_pubkey().is_none());
    assert!(matches!(
        store.set_once_committee_signing_pubkey(
            generated_keys.committee_signing_pk.clone().unwrap()
        ),
        Ok(())
    ));
    assert_eq!(
        store.committee_signing_pubkey(),
        generated_keys.committee_signing_pk.as_ref()
    );

    assert!(store.ni_dkg_dealing_encryption_pubkey().is_none());
    assert!(matches!(
        store.set_once_ni_dkg_dealing_encryption_pubkey(
            generated_keys.dkg_dealing_encryption_pk.clone().unwrap()
        ),
        Ok(())
    ));
    assert_eq!(
        store.ni_dkg_dealing_encryption_pubkey(),
        generated_keys.dkg_dealing_encryption_pk.as_ref()
    );

    assert!(store.tls_certificate().is_none());
    assert!(matches!(
        store.set_once_tls_certificate(generated_keys.tls_certificate.clone().unwrap()),
        Ok(())
    ));
    assert_eq!(
        store.tls_certificate(),
        generated_keys.tls_certificate.as_ref()
    );

    assert!(store.idkg_dealing_encryption_pubkeys().is_empty());
    assert!(matches!(
        store.set_idkg_dealing_encryption_pubkeys(
            generated_keys.idkg_dealing_encryption_pks.clone()
        ),
        Ok(())
    ));
    assert_eq!(
        store.idkg_dealing_encryption_pubkeys(),
        &generated_keys.idkg_dealing_encryption_pks
    );
}

#[test]
fn should_set_non_rotating_pubkeys_only_once() {
    let (generated_keys, crypto_root) = generate_node_keys_in_temp_dir();
    let mut store = ProtoPublicKeyStore::open(crypto_root.path(), PUBLIC_KEY_STORE_DATA_FILENAME);
    let some_pubkey = generated_keys.node_signing_pk.unwrap();
    let some_cert = generated_keys.tls_certificate.unwrap();

    assert!(store.node_signing_pubkey().is_some());
    assert!(matches!(
        store.set_once_node_signing_pubkey(some_pubkey.clone()),
        Err(PublicKeySetOnceError::AlreadySet)
    ));

    assert!(store.committee_signing_pubkey().is_some());
    assert!(matches!(
        store.set_once_committee_signing_pubkey(some_pubkey.clone()),
        Err(PublicKeySetOnceError::AlreadySet)
    ));

    assert!(store.ni_dkg_dealing_encryption_pubkey().is_some());
    assert!(matches!(
        store.set_once_ni_dkg_dealing_encryption_pubkey(some_pubkey),
        Err(PublicKeySetOnceError::AlreadySet)
    ));

    assert!(store.tls_certificate().is_some());
    assert!(matches!(
        store.set_once_tls_certificate(some_cert),
        Err(PublicKeySetOnceError::AlreadySet)
    ));
}

#[test]
fn should_persist_pubkeys_to_disk_when_setting_them() {
    let temp_dir = temp_dir();
    let mut store = ProtoPublicKeyStore::open(temp_dir.path(), PUBLIC_KEY_STORE_DATA_FILENAME);
    let (generated_keys, _temp_dir) = generate_node_keys_in_temp_dir();

    assert!(store
        .set_once_node_signing_pubkey(generated_keys.node_signing_pk.clone().unwrap())
        .is_ok());
    assert_eq!(
        ProtoPublicKeyStore::open(temp_dir.path(), PUBLIC_KEY_STORE_DATA_FILENAME)
            .node_signing_pubkey(),
        generated_keys.node_signing_pk.as_ref()
    );

    assert!(store
        .set_once_committee_signing_pubkey(generated_keys.committee_signing_pk.clone().unwrap())
        .is_ok());
    assert_eq!(
        ProtoPublicKeyStore::open(temp_dir.path(), PUBLIC_KEY_STORE_DATA_FILENAME)
            .committee_signing_pubkey(),
        generated_keys.committee_signing_pk.as_ref()
    );

    assert!(store
        .set_once_ni_dkg_dealing_encryption_pubkey(
            generated_keys.dkg_dealing_encryption_pk.clone().unwrap()
        )
        .is_ok());
    assert_eq!(
        ProtoPublicKeyStore::open(temp_dir.path(), PUBLIC_KEY_STORE_DATA_FILENAME)
            .ni_dkg_dealing_encryption_pubkey(),
        generated_keys.dkg_dealing_encryption_pk.as_ref()
    );

    assert!(store
        .set_once_tls_certificate(generated_keys.tls_certificate.clone().unwrap())
        .is_ok());
    assert_eq!(
        ProtoPublicKeyStore::open(temp_dir.path(), PUBLIC_KEY_STORE_DATA_FILENAME)
            .tls_certificate(),
        generated_keys.tls_certificate.as_ref()
    );

    assert!(store
        .set_idkg_dealing_encryption_pubkeys(generated_keys.idkg_dealing_encryption_pks.clone())
        .is_ok());
    assert_eq!(
        ProtoPublicKeyStore::open(temp_dir.path(), PUBLIC_KEY_STORE_DATA_FILENAME)
            .idkg_dealing_encryption_pubkeys(),
        &generated_keys.idkg_dealing_encryption_pks
    );
}

#[test]
fn should_preserve_order_of_rotating_pubkeys() {
    let temp_dir = temp_dir();
    let mut store = ProtoPublicKeyStore::open(temp_dir.path(), PUBLIC_KEY_STORE_DATA_FILENAME);
    let pubkeys = vec![
        public_key_with(42),
        public_key_with(43),
        public_key_with(44),
    ];

    assert!(store
        .set_idkg_dealing_encryption_pubkeys(pubkeys.clone())
        .is_ok());
    assert_eq!(store.idkg_dealing_encryption_pubkeys(), &pubkeys);
    assert_eq!(
        ProtoPublicKeyStore::open(temp_dir.path(), PUBLIC_KEY_STORE_DATA_FILENAME)
            .idkg_dealing_encryption_pubkeys(),
        &pubkeys
    );
}

#[test]
#[should_panic(expected = "error parsing public key store data")]
fn should_panic_on_opening_corrupt_pubkey_store() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let corrupt_store_file = temp_dir.path().join(PUBLIC_KEY_STORE_DATA_FILENAME);
    fs::write(corrupt_store_file, b"corrupt store content").expect("failed to write store");

    ProtoPublicKeyStore::open(temp_dir.path(), PUBLIC_KEY_STORE_DATA_FILENAME);
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

    ProtoPublicKeyStore::open(temp_dir.path(), PUBLIC_KEYS_FILE);
}

#[test]
fn should_fail_to_write_without_write_permissions() {
    let temp_dir = mk_temp_dir_with_permissions(0o700);
    copy_file_to_dir(pubkey_store_in_test_resources().as_path(), temp_dir.path());
    let mut pubkey_store = ProtoPublicKeyStore::open(temp_dir.path(), PUBLIC_KEYS_FILE);
    fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o400))
        .expect("failed to set read-only permissions");

    let result = pubkey_store.set_idkg_dealing_encryption_pubkeys(vec![public_key_with(123)]);

    assert!(
        matches!(result, Err(io_error) if io_error.kind() == std::io::ErrorKind::PermissionDenied)
    );

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
    let store = ProtoPublicKeyStore::open(test_resources().as_path(), PUBLIC_KEYS_FILE);

    assert_eq!(
        store.node_signing_pubkey(),
        Some(&PublicKey {
            version: 0,
            algorithm: AlgorithmId::Ed25519 as i32,
            key_value: hex_decode(
                "58d558c7586efb32f4667ee9a302877da97aa1136cda92af4d7a4f8873f9434f"
            ),
            proof_data: None,
            timestamp: None,
        })
    );
    assert_eq!(
        store.committee_signing_pubkey(),
        Some(&PublicKey {
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
        Some(&PublicKey {
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
        &vec![
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
