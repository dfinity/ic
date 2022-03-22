#![allow(clippy::unwrap_used)]
use crate::keygen_utils::TestKeygenCrypto;
use ic_config::crypto::CryptoConfig;
use ic_crypto::utils::{
    get_node_keys_or_generate_if_missing, NodeKeysToGenerate, TempCryptoComponent,
};
use ic_crypto::CryptoComponent;
use ic_crypto_internal_csp_test_utils::remote_csp_vault::{
    get_temp_file_path, start_new_remote_csp_vault_server_for_test,
};
use ic_crypto_test_utils::tls::x509_certificates::generate_ed25519_cert;
use ic_interfaces::crypto::KeyManager;
use ic_logger::replica_logger::no_op_logger;
use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_test_utilities::crypto::temp_dir::temp_dir;
use ic_test_utilities::types::ids::node_test_id;
use ic_types::crypto::{AlgorithmId, CryptoError, KeyPurpose};
use ic_types::RegistryVersion;
use std::sync::Arc;
use strum::IntoEnumIterator;

mod keygen_utils;

const REG_V1: RegistryVersion = RegistryVersion::new(1);
const NODE_ID: u64 = 42;

#[test]
fn should_successfully_construct_crypto_component_with_default_config() {
    CryptoConfig::run_with_temp_config(|config| {
        let registry_client = FakeRegistryClient::new(Arc::new(ProtoRegistryDataProvider::new()));
        CryptoComponent::new_with_fake_node_id(
            &config,
            Arc::new(registry_client),
            node_test_id(42),
            no_op_logger(),
        );
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn should_successfully_construct_crypto_component_with_remote_csp_vault() {
    let socket_path = start_new_remote_csp_vault_server_for_test();
    let temp_dir = temp_dir(); // temp dir with correct permissions
    let crypto_root = temp_dir.path().to_path_buf();
    let config = CryptoConfig::new_with_unix_socket_vault(crypto_root, socket_path);
    let registry_client = FakeRegistryClient::new(Arc::new(ProtoRegistryDataProvider::new()));
    CryptoComponent::new_with_fake_node_id(
        &config,
        Arc::new(registry_client),
        node_test_id(42),
        no_op_logger(),
    );
}

#[test]
#[should_panic(expected = "Could not connect to CspVault at socket")]
fn should_not_construct_crypto_component_if_remote_csp_vault_is_missing() {
    let socket_path = get_temp_file_path(); // no CSP vault server is running
    let temp_dir = temp_dir(); // temp dir with correct permissions
    let crypto_root = temp_dir.path().to_path_buf();
    let config = CryptoConfig::new_with_unix_socket_vault(crypto_root, socket_path);
    let registry_client = FakeRegistryClient::new(Arc::new(ProtoRegistryDataProvider::new()));
    CryptoComponent::new_with_fake_node_id(
        &config,
        Arc::new(registry_client),
        node_test_id(42),
        no_op_logger(),
    );
}

#[test]
#[should_panic(expected = "Missing node signing public key")]
fn should_not_construct_crypto_component_for_non_replica_process_without_keys() {
    CryptoConfig::run_with_temp_config(|config| {
        let registry_client = FakeRegistryClient::new(Arc::new(ProtoRegistryDataProvider::new()));
        let _crypto = CryptoComponent::new_for_non_replica_process(
            &config,
            Arc::new(registry_client),
            no_op_logger(),
        );
    })
}

#[test]
fn should_successfully_construct_crypto_component_for_non_replica_process_with_default_config_and_keys(
) {
    CryptoConfig::run_with_temp_config(|config| {
        // Create node keys.
        let (_created_node_pks, _node_id) =
            get_node_keys_or_generate_if_missing(&config.crypto_root);

        let registry_client = FakeRegistryClient::new(Arc::new(ProtoRegistryDataProvider::new()));
        let _crypto = CryptoComponent::new_for_non_replica_process(
            &config,
            Arc::new(registry_client),
            no_op_logger(),
        );
    })
}

#[test]
fn should_provide_public_keys_via_crypto_for_non_replica_process() {
    CryptoConfig::run_with_temp_config(|config| {
        // Create node keys.
        let (created_node_pks, _node_id) =
            get_node_keys_or_generate_if_missing(&config.crypto_root);

        let registry_client = FakeRegistryClient::new(Arc::new(ProtoRegistryDataProvider::new()));
        let crypto = CryptoComponent::new_for_non_replica_process(
            &config,
            Arc::new(registry_client),
            no_op_logger(),
        );
        let retrieved_node_pks = crypto.node_public_keys();
        assert!(all_node_keys_are_present(&retrieved_node_pks));
        assert_eq!(created_node_pks, retrieved_node_pks);
    })
}

// TODO(CRP-430): check/improve the test coverage of SKS checks.

#[test]
fn should_generate_all_keys_for_new_node() {
    CryptoConfig::run_with_temp_config(|config| {
        let (node_pks, _node_id) = get_node_keys_or_generate_if_missing(&config.crypto_root);
        assert!(all_node_keys_are_present(&node_pks));
    })
}

#[test]
fn should_not_generate_new_keys_if_all_keys_are_present() {
    CryptoConfig::run_with_temp_config(|config| {
        let (orig_node_pks, orig_node_id) =
            get_node_keys_or_generate_if_missing(&config.crypto_root);
        assert!(all_node_keys_are_present(&orig_node_pks));
        let (new_node_pks, new_node_id) = get_node_keys_or_generate_if_missing(&config.crypto_root);
        assert!(all_node_keys_are_present(&new_node_pks));
        assert_eq!(orig_node_pks, new_node_pks);
        assert_eq!(orig_node_id, new_node_id);
    })
}

fn all_node_keys_are_present(node_pks: &NodePublicKeys) -> bool {
    node_pks.node_signing_pk.is_some()
        && node_pks.committee_signing_pk.is_some()
        && node_pks.tls_certificate.is_some()
        && node_pks.dkg_dealing_encryption_pk.is_some()
        && node_pks.idkg_dealing_encryption_pk.is_some()
}

#[test]
fn should_fail_check_keys_with_registry_if_no_keys_are_present_in_registry() {
    let crypto = TestKeygenCrypto::builder()
        .with_node_keys_to_generate(NodeKeysToGenerate::all())
        .build(NODE_ID, REG_V1);

    let result = crypto.get().check_keys_with_registry(REG_V1);

    assert!(result.is_err());
}

#[test]
fn should_fail_check_keys_with_registry_if_node_signing_keys_are_missing_in_registry() {
    let crypto = TestKeygenCrypto::builder()
        .with_node_keys_to_generate(NodeKeysToGenerate::all())
        .add_generated_committee_signing_key_to_registry()
        .add_generated_dkg_dealing_enc_key_to_registry()
        .add_generated_tls_cert_to_registry()
        .build(NODE_ID, REG_V1);

    let result = crypto.get().check_keys_with_registry(REG_V1);

    assert!(result.is_err());
    let is_node_signing_public_key_err = match result.unwrap_err() {
        CryptoError::PublicKeyNotFound { key_purpose, .. } => {
            key_purpose == KeyPurpose::NodeSigning
        }
        _ => false,
    };
    assert!(is_node_signing_public_key_err);
}

#[test]
fn should_fail_check_keys_with_registry_if_committee_member_keys_are_missing_in_registry() {
    let crypto = TestKeygenCrypto::builder()
        .with_node_keys_to_generate(NodeKeysToGenerate::all())
        .add_generated_node_signing_key_to_registry()
        .add_generated_dkg_dealing_enc_key_to_registry()
        .add_generated_tls_cert_to_registry()
        .build(NODE_ID, REG_V1);

    let result = crypto.get().check_keys_with_registry(REG_V1);

    assert!(result.is_err());
    let is_committee_signing_public_key_err = match result.unwrap_err() {
        CryptoError::PublicKeyNotFound { key_purpose, .. } => {
            key_purpose == KeyPurpose::CommitteeSigning
        }
        _ => false,
    };
    assert!(is_committee_signing_public_key_err);
}

#[test]
fn should_fail_check_keys_with_registry_if_dkg_dealing_encryption_key_is_missing_in_registry() {
    let crypto = TestKeygenCrypto::builder()
        .with_node_keys_to_generate(NodeKeysToGenerate::all())
        .add_generated_node_signing_key_to_registry()
        .add_generated_committee_signing_key_to_registry()
        .add_generated_tls_cert_to_registry()
        .build(NODE_ID, REG_V1);

    let result = crypto.get().check_keys_with_registry(REG_V1);

    assert_eq!(
        result.unwrap_err(),
        CryptoError::PublicKeyNotFound {
            node_id: node_test_id(NODE_ID),
            key_purpose: KeyPurpose::DkgDealingEncryption,
            registry_version: REG_V1
        }
    );
}

#[test]
fn should_fail_check_keys_with_registry_if_tls_cert_is_missing_in_registry() {
    let crypto = TestKeygenCrypto::builder()
        .with_node_keys_to_generate(NodeKeysToGenerate::all())
        .add_generated_node_signing_key_to_registry()
        .add_generated_committee_signing_key_to_registry()
        .add_generated_dkg_dealing_enc_key_to_registry()
        .build(NODE_ID, REG_V1);

    let result = crypto.get().check_keys_with_registry(REG_V1);

    assert_eq!(
        result.unwrap_err(),
        CryptoError::TlsCertNotFound {
            node_id: node_test_id(NODE_ID),
            registry_version: REG_V1
        }
    );
}

#[test]
fn should_fail_check_keys_with_registry_if_cert_is_malformed() {
    let node_keys_to_generate = NodeKeysToGenerate {
        generate_node_signing_keys: true,
        generate_committee_signing_keys: true,
        generate_dkg_dealing_encryption_keys: true,
        generate_idkg_dealing_encryption_keys: true,
        generate_tls_keys_and_certificate: false,
    };
    let malformed_cert = X509PublicKeyCert {
        certificate_der: b"not DER".to_vec(),
    };
    let crypto = TestKeygenCrypto::builder()
        .with_node_keys_to_generate(node_keys_to_generate)
        .with_tls_cert_in_registry(malformed_cert)
        .add_generated_node_signing_key_to_registry()
        .add_generated_committee_signing_key_to_registry()
        .add_generated_dkg_dealing_enc_key_to_registry()
        .build(NODE_ID, REG_V1);

    let result = crypto.get().check_keys_with_registry(REG_V1);

    assert!(matches!(
        result,
        Err(CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::Ed25519,
            key_bytes: None,
            internal_error
        })
        if internal_error.contains("Error parsing DER")
    ));
}

#[test]
fn should_fail_check_keys_with_registry_if_node_signing_secret_key_is_missing() {
    let node_signing_pk_without_corresponding_secret_key = PublicKey {
        algorithm: AlgorithmId::Ed25519 as i32,
        key_value: [1u8; 32].to_vec(),
        version: 0,
        proof_data: None,
    };
    let crypto = TestKeygenCrypto::builder()
        .with_node_keys_to_generate(NodeKeysToGenerate::all())
        .with_node_signing_key_in_registry(node_signing_pk_without_corresponding_secret_key)
        .add_generated_committee_signing_key_to_registry()
        .add_generated_dkg_dealing_enc_key_to_registry()
        .add_generated_tls_cert_to_registry()
        .build(NODE_ID, REG_V1);

    let result = crypto.get().check_keys_with_registry(REG_V1);

    assert!(result.is_err());
    let is_secret_key_err = match result.unwrap_err() {
        CryptoError::SecretKeyNotFound { algorithm, .. } => algorithm == AlgorithmId::Ed25519,
        _ => false,
    };
    assert!(is_secret_key_err);
}

#[test]
fn should_fail_check_keys_with_registry_if_committee_member_secret_key_is_missing() {
    let committee_pk_without_corresponding_secret_key = PublicKey {
        algorithm: AlgorithmId::MultiBls12_381 as i32,
        key_value: [1u8; 96].to_vec(),
        version: 0,
        proof_data: Some(vec![1u8; 48]),
    };
    let crypto = TestKeygenCrypto::builder()
        .with_node_keys_to_generate(NodeKeysToGenerate::all())
        .add_generated_node_signing_key_to_registry()
        .with_committee_signing_key_in_registry(committee_pk_without_corresponding_secret_key)
        .add_generated_dkg_dealing_enc_key_to_registry()
        .add_generated_tls_cert_to_registry()
        .build(NODE_ID, REG_V1);

    let result = crypto.get().check_keys_with_registry(REG_V1);

    assert!(result.is_err());
    let is_secret_key_err = match result.unwrap_err() {
        CryptoError::SecretKeyNotFound { algorithm, .. } => {
            algorithm == AlgorithmId::MultiBls12_381
        }
        _ => false,
    };
    assert!(is_secret_key_err);
}

#[test]
fn should_fail_check_keys_with_registry_if_dkg_dealing_encryption_secret_key_is_missing() {
    let dkg_dealing_enc_public_key_with_valid_pop_but_without_secret_part_in_store =
        well_formed_dkg_dealing_encryption_pk();
    let crypto = TestKeygenCrypto::builder()
        .with_node_keys_to_generate(NodeKeysToGenerate::all())
        .add_generated_node_signing_key_to_registry()
        .add_generated_committee_signing_key_to_registry()
        .with_dkg_dealing_enc_key_in_registry(
            dkg_dealing_enc_public_key_with_valid_pop_but_without_secret_part_in_store,
        )
        .add_generated_tls_cert_to_registry()
        .build(NODE_ID, REG_V1);

    let result = crypto.get().check_keys_with_registry(REG_V1);

    assert!(result.is_err());
    let is_secret_key_err = match result.unwrap_err() {
        CryptoError::SecretKeyNotFound { algorithm, .. } => {
            algorithm == AlgorithmId::Groth20_Bls12_381
        }
        _ => false,
    };

    assert!(is_secret_key_err);
}

#[test]
fn should_fail_check_keys_with_registry_if_dkg_dealing_encryption_pubkey_is_malformed() {
    const MALFORMED_DEALING_ENC_KEY_DATA: &[u8; 13] = b"malformed key";
    let dkg_dealing_encryption_pubkey_with_malformed_pubkey = PublicKey {
        key_value: MALFORMED_DEALING_ENC_KEY_DATA.to_vec(),
        ..well_formed_dkg_dealing_encryption_pk()
    };
    let crypto = TestKeygenCrypto::builder()
        .with_node_keys_to_generate(NodeKeysToGenerate::all())
        .add_generated_node_signing_key_to_registry()
        .add_generated_committee_signing_key_to_registry()
        .with_dkg_dealing_enc_key_in_registry(dkg_dealing_encryption_pubkey_with_malformed_pubkey)
        .add_generated_tls_cert_to_registry()
        .build(NODE_ID, REG_V1);

    let result = crypto.get().check_keys_with_registry(REG_V1);

    assert_eq!(
        result.unwrap_err(),
        CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::Groth20_Bls12_381,
            key_bytes: Some(MALFORMED_DEALING_ENC_KEY_DATA.to_vec()),
            internal_error: "Wrong data length 13, expected length 48.".to_string()
        }
    );
}

#[test]
fn should_fail_check_keys_with_registry_if_dkg_dealing_encryption_pop_is_missing() {
    let dkg_dealing_encryption_pubkey_with_missing_pop = PublicKey {
        version: 0,
        algorithm: AlgorithmId::Groth20_Bls12_381 as i32,
        proof_data: None,
        key_value: b"irrelevant because pop validity is checked before pubkey validity".to_vec(),
    };
    let crypto = TestKeygenCrypto::builder()
        .with_node_keys_to_generate(NodeKeysToGenerate::all())
        .add_generated_node_signing_key_to_registry()
        .add_generated_committee_signing_key_to_registry()
        .with_dkg_dealing_enc_key_in_registry(dkg_dealing_encryption_pubkey_with_missing_pop)
        .add_generated_tls_cert_to_registry()
        .build(NODE_ID, REG_V1);

    let result = crypto.get().check_keys_with_registry(REG_V1);

    assert_eq!(
        result.unwrap_err(),
        CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::Groth20_Bls12_381,
            key_bytes: None,
            internal_error: "MissingProofData".to_string()
        }
    );
}

#[test]
fn should_fail_check_keys_with_registry_if_dkg_dealing_encryption_pop_is_empty() {
    let dkg_dealing_encryption_pubkey_with_empty_pop = PublicKey {
        version: 0,
        algorithm: AlgorithmId::Groth20_Bls12_381 as i32,
        proof_data: Some(vec![]),
        key_value: b"irrelevant because pop validity is checked before pubkey validity".to_vec(),
    };
    let crypto = TestKeygenCrypto::builder()
        .with_node_keys_to_generate(NodeKeysToGenerate::all())
        .add_generated_node_signing_key_to_registry()
        .add_generated_committee_signing_key_to_registry()
        .with_dkg_dealing_enc_key_in_registry(dkg_dealing_encryption_pubkey_with_empty_pop)
        .add_generated_tls_cert_to_registry()
        .build(NODE_ID, REG_V1);

    let result = crypto.get().check_keys_with_registry(REG_V1);

    assert_eq!(
        result.unwrap_err(),
        CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::Groth20_Bls12_381,
            key_bytes: None,
            internal_error:
                "MalformedPop { pop_bytes: [], internal_error: \"EOF while parsing a value\" }"
                    .to_string()
        }
    );
}

#[test]
fn should_fail_check_keys_with_registry_if_dkg_dealing_encryption_pop_is_malformed() {
    let dkg_dealing_encryption_pubkey_with_malformed_pop = PublicKey {
        version: 0,
        algorithm: AlgorithmId::Groth20_Bls12_381 as i32,
        proof_data: Some(b"malformed pop".to_vec()),
        key_value: b"irrelevant because pop validity is checked before pubkey validity".to_vec(),
    };
    let crypto = TestKeygenCrypto::builder()
        .with_node_keys_to_generate(NodeKeysToGenerate::all())
        .add_generated_node_signing_key_to_registry()
        .add_generated_committee_signing_key_to_registry()
        .with_dkg_dealing_enc_key_in_registry(dkg_dealing_encryption_pubkey_with_malformed_pop)
        .add_generated_tls_cert_to_registry()
        .build(NODE_ID, REG_V1);

    let result = crypto.get().check_keys_with_registry(REG_V1);

    assert_eq!(
        result.unwrap_err(),
        CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::Groth20_Bls12_381,
            key_bytes: None,
            internal_error: "MalformedPop { pop_bytes: [109, 97, 108, 102, 111, 114, 109, 101, 100, 32, 112, 111, 112], internal_error: \"EOF while parsing a value at offset 13\" }".to_string()
        }
    );
}

#[test]
fn should_fail_check_keys_with_registry_if_committee_key_pop_is_missing() {
    let committee_key_without_pop = PublicKey {
        algorithm: AlgorithmId::MultiBls12_381 as i32,
        key_value: b"irrelevant because pop validity is checked before pubkey validity".to_vec(),
        version: 0,
        proof_data: None,
    };
    let crypto = TestKeygenCrypto::builder()
        .with_node_keys_to_generate(NodeKeysToGenerate::all())
        .add_generated_node_signing_key_to_registry()
        .with_committee_signing_key_in_registry(committee_key_without_pop)
        .add_generated_dkg_dealing_enc_key_to_registry()
        .add_generated_tls_cert_to_registry()
        .build(NODE_ID, REG_V1);

    let result = crypto.get().check_keys_with_registry(REG_V1);

    assert_eq!(
        result.unwrap_err(),
        CryptoError::MalformedPop {
            algorithm: AlgorithmId::MultiBls12_381,
            pop_bytes: vec![0u8; 0],
            internal_error: "CspPopFromPublicKeyProtoError::MissingProofData".to_string(),
        }
    );
}

#[test]
fn should_fail_check_keys_with_registry_if_committee_key_pop_is_empty() {
    let committee_key_with_empty_pop = PublicKey {
        algorithm: AlgorithmId::MultiBls12_381 as i32,
        key_value: b"irrelevant because pop validity is checked before pubkey validity".to_vec(),
        version: 0,
        proof_data: Some(vec![]),
    };
    let crypto = TestKeygenCrypto::builder()
        .with_node_keys_to_generate(NodeKeysToGenerate::all())
        .add_generated_node_signing_key_to_registry()
        .with_committee_signing_key_in_registry(committee_key_with_empty_pop)
        .add_generated_dkg_dealing_enc_key_to_registry()
        .add_generated_tls_cert_to_registry()
        .build(NODE_ID, REG_V1);

    let result = crypto.get().check_keys_with_registry(REG_V1);

    assert_eq!(
        result.unwrap_err(),
        CryptoError::MalformedPop {
            algorithm: AlgorithmId::MultiBls12_381,
            pop_bytes: vec![0u8; 0],
            internal_error: "Wrong pop length 0, expected length 48.".to_string(),
        }
    );
}

#[test]
fn should_fail_check_keys_with_registry_if_committee_key_pop_is_malformed() {
    let committee_key_with_malformed_pop = PublicKey {
        algorithm: AlgorithmId::MultiBls12_381 as i32,
        key_value: b"irrelevant because pop validity is checked before pubkey validity".to_vec(),
        version: 0,
        proof_data: Some(b"malformed pop".to_vec()),
    };
    let crypto = TestKeygenCrypto::builder()
        .with_node_keys_to_generate(NodeKeysToGenerate::all())
        .add_generated_node_signing_key_to_registry()
        .with_committee_signing_key_in_registry(committee_key_with_malformed_pop)
        .add_generated_dkg_dealing_enc_key_to_registry()
        .add_generated_tls_cert_to_registry()
        .build(NODE_ID, REG_V1);

    let result = crypto.get().check_keys_with_registry(REG_V1);

    assert_eq!(
        result.unwrap_err(),
        CryptoError::MalformedPop {
            algorithm: AlgorithmId::MultiBls12_381,
            pop_bytes: b"malformed pop".to_vec(),
            internal_error: "Wrong pop length 13, expected length 48.".to_string(),
        }
    );
}

#[test]
fn should_fail_check_keys_with_registry_if_tls_cert_secret_key_is_missing() {
    let cert_without_corresponding_secret_key = X509PublicKeyCert {
        certificate_der: generate_ed25519_cert()
            .1
            .to_der()
            .expect("Failed to convert X509 to DER"),
    };
    let crypto = TestKeygenCrypto::builder()
        .with_node_keys_to_generate(NodeKeysToGenerate::all())
        .add_generated_node_signing_key_to_registry()
        .add_generated_committee_signing_key_to_registry()
        .add_generated_dkg_dealing_enc_key_to_registry()
        .with_tls_cert_in_registry(cert_without_corresponding_secret_key.clone())
        .build(NODE_ID, REG_V1);

    let result = crypto.get().check_keys_with_registry(REG_V1);

    assert_eq!(
        result.unwrap_err(),
        CryptoError::TlsSecretKeyNotFound {
            certificate_der: cert_without_corresponding_secret_key.certificate_der,
        }
    );
}

#[test]
fn should_succeed_check_keys_with_registry_if_all_keys_are_present() {
    let crypto = TestKeygenCrypto::builder()
        .with_node_keys_to_generate(NodeKeysToGenerate::all())
        .add_generated_node_signing_key_to_registry()
        .add_generated_committee_signing_key_to_registry()
        .add_generated_dkg_dealing_enc_key_to_registry()
        .add_generated_tls_cert_to_registry()
        .build(NODE_ID, REG_V1);

    let result = crypto.get().check_keys_with_registry(REG_V1);

    assert!(result.is_ok());
}

/// If this test fails it means that one of AlgorithmId and AlgorithmIdProto structs was updated but not the other.
/// Ensure the structs are consistent and then update the test below.
#[test]
fn algorithm_id_should_match_algorithm_id_proto() {
    let algorithm_id_variants = 17;
    assert_eq!(AlgorithmId::iter().count(), algorithm_id_variants);

    for i in 0..algorithm_id_variants {
        assert!(AlgorithmIdProto::from_i32(i as i32).is_some());
    }
    assert!(AlgorithmIdProto::from_i32(algorithm_id_variants as i32).is_none());

    assert_eq!(
        AlgorithmId::Placeholder as i32,
        AlgorithmIdProto::Unspecified as i32
    );
    assert_eq!(
        AlgorithmId::MultiBls12_381 as i32,
        AlgorithmIdProto::MultiBls12381 as i32
    );
    assert_eq!(
        AlgorithmId::ThresBls12_381 as i32,
        AlgorithmIdProto::ThresBls12381 as i32
    );
    assert_eq!(
        AlgorithmId::SchnorrSecp256k1 as i32,
        AlgorithmIdProto::SchnorrSecp256k1 as i32
    );
    assert_eq!(
        AlgorithmId::StaticDhSecp256k1 as i32,
        AlgorithmIdProto::StaticDhSecp256k1 as i32
    );
    assert_eq!(
        AlgorithmId::HashSha256 as i32,
        AlgorithmIdProto::HashSha256 as i32
    );
    assert_eq!(AlgorithmId::Tls as i32, AlgorithmIdProto::Tls as i32);
    assert_eq!(
        AlgorithmId::Ed25519 as i32,
        AlgorithmIdProto::Ed25519 as i32
    );
    assert_eq!(
        AlgorithmId::Secp256k1 as i32,
        AlgorithmIdProto::Secp256k1 as i32
    );
    assert_eq!(
        AlgorithmId::Groth20_Bls12_381 as i32,
        AlgorithmIdProto::Groth20Bls12381 as i32
    );
    assert_eq!(
        AlgorithmId::NiDkg_Groth20_Bls12_381 as i32,
        AlgorithmIdProto::NidkgGroth20Bls12381 as i32
    );
    assert_eq!(
        AlgorithmId::EcdsaP256 as i32,
        AlgorithmIdProto::EcdsaP256 as i32
    );
    assert_eq!(
        AlgorithmId::EcdsaSecp256k1 as i32,
        AlgorithmIdProto::EcdsaSecp256k1 as i32
    );
    assert_eq!(
        AlgorithmId::IcCanisterSignature as i32,
        AlgorithmIdProto::IcCanisterSignature as i32
    );
    assert_eq!(
        AlgorithmId::RsaSha256 as i32,
        AlgorithmIdProto::RsaSha256 as i32
    );
    assert_eq!(
        AlgorithmId::ThresholdEcdsaSecp256k1 as i32,
        AlgorithmIdProto::ThresholdEcdsaSecp256k1 as i32
    );
    assert_eq!(
        AlgorithmId::MegaSecp256k1 as i32,
        AlgorithmIdProto::MegaSecp256k1 as i32
    );
}

fn well_formed_dkg_dealing_encryption_pk() -> PublicKey {
    let dummy_node_id = node_test_id(NODE_ID);
    let dummy_data_provider = Arc::new(ProtoRegistryDataProvider::new());
    let dummy_registry_client = Arc::new(FakeRegistryClient::new(dummy_data_provider));
    let (_temp_crypto, node_pubkeys) = TempCryptoComponent::new_with_node_keys_generation(
        Arc::clone(&dummy_registry_client) as Arc<_>,
        dummy_node_id,
        NodeKeysToGenerate {
            generate_node_signing_keys: false,
            generate_committee_signing_keys: false,
            generate_dkg_dealing_encryption_keys: true,
            generate_idkg_dealing_encryption_keys: false,
            generate_tls_keys_and_certificate: false,
        },
    );
    node_pubkeys.dkg_dealing_encryption_pk.unwrap()
}
