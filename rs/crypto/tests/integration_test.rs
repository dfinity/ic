#![allow(clippy::unwrap_used)]

use crate::keygen_utils::TestKeygenCrypto;
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_config::crypto::CryptoConfig;
use ic_crypto::{CryptoComponent, CryptoTime};
use ic_crypto_internal_csp_test_utils::remote_csp_vault::{
    get_temp_file_path, start_new_remote_csp_vault_server_for_test,
};
use ic_crypto_internal_tls::keygen::generate_tls_key_pair_der;
use ic_crypto_node_key_generation::get_node_keys_or_generate_if_missing;
use ic_crypto_temp_crypto::{
    EcdsaSubnetConfig, FastForwardCryptoTimeSource, NodeKeysToGenerate, TempCryptoComponent,
};
use ic_crypto_test_utils::files::temp_dir;
use ic_crypto_test_utils::tls::x509_certificates::generate_ed25519_cert;
use ic_crypto_test_utils_keygen::{add_public_key_to_registry, add_tls_cert_to_registry};
use ic_interfaces::crypto::{KeyManager, PublicKeyRegistrationStatus};
use ic_interfaces::time_source::SysTimeSource;
use ic_logger::replica_logger::no_op_logger;
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::crypto::{AlgorithmId, CryptoError, CurrentNodePublicKeys, KeyPurpose};
use ic_types::{RegistryVersion, Time};
use ic_types_test_utils::ids::node_test_id;
use openssl::asn1::Asn1Time;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use std::sync::Arc;
use std::time::Duration;
use strum::IntoEnumIterator;

mod keygen_utils;

const REG_V1: RegistryVersion = RegistryVersion::new(1);
const REG_V2: RegistryVersion = RegistryVersion::new(2);
const NODE_ID: u64 = 42;
const TWO_WEEKS: Duration = Duration::from_secs(2 * 7 * 24 * 60 * 60);

#[test]
fn should_successfully_construct_crypto_component_with_default_config() {
    CryptoConfig::run_with_temp_config(|config| {
        let registry_client = FakeRegistryClient::new(Arc::new(ProtoRegistryDataProvider::new()));
        CryptoComponent::new_with_fake_node_id(
            &config,
            None,
            Arc::new(registry_client),
            node_test_id(42),
            no_op_logger(),
            Arc::new(SysTimeSource::new()),
        );
    })
}

#[test]
fn should_successfully_construct_crypto_component_with_remote_csp_vault() {
    let tokio_rt = new_tokio_runtime();
    let socket_path = start_new_remote_csp_vault_server_for_test(tokio_rt.handle());
    let temp_dir = temp_dir(); // temp dir with correct permissions
    let crypto_root = temp_dir.path().to_path_buf();
    let config = CryptoConfig::new_with_unix_socket_vault(crypto_root, socket_path);
    let registry_client = FakeRegistryClient::new(Arc::new(ProtoRegistryDataProvider::new()));
    CryptoComponent::new_with_fake_node_id(
        &config,
        Some(tokio_rt.handle().clone()),
        Arc::new(registry_client),
        node_test_id(42),
        no_op_logger(),
        Arc::new(SysTimeSource::new()),
    );
}

#[test]
#[should_panic(expected = "Could not connect to CspVault at socket")]
fn should_not_construct_crypto_component_if_remote_csp_vault_is_missing() {
    let socket_path = get_temp_file_path(); // no CSP vault server is running
    let temp_dir = temp_dir(); // temp dir with correct permissions
    let crypto_root = temp_dir.path().to_path_buf();
    let config = CryptoConfig::new_with_unix_socket_vault(crypto_root, socket_path);
    let tokio_rt = new_tokio_runtime();
    let registry_client = FakeRegistryClient::new(Arc::new(ProtoRegistryDataProvider::new()));
    CryptoComponent::new_with_fake_node_id(
        &config,
        Some(tokio_rt.handle().clone()),
        Arc::new(registry_client),
        node_test_id(42),
        no_op_logger(),
        Arc::new(SysTimeSource::new()),
    );
}

#[test]
#[should_panic(expected = "Missing node signing public key")]
fn should_not_construct_crypto_component_for_non_replica_process_without_keys() {
    CryptoConfig::run_with_temp_config(|config| {
        let registry_client = FakeRegistryClient::new(Arc::new(ProtoRegistryDataProvider::new()));
        let _crypto = CryptoComponent::new_for_non_replica_process(
            &config,
            None,
            Arc::new(registry_client),
            no_op_logger(),
            None,
        );
    })
}

#[test]
fn should_successfully_construct_crypto_component_for_non_replica_process_with_default_config_and_keys(
) {
    CryptoConfig::run_with_temp_config(|config| {
        // Create node keys.
        let (_created_node_pks, _node_id) = get_node_keys_or_generate_if_missing(&config, None);

        let registry_client = FakeRegistryClient::new(Arc::new(ProtoRegistryDataProvider::new()));
        let _crypto = CryptoComponent::new_for_non_replica_process(
            &config,
            None,
            Arc::new(registry_client),
            no_op_logger(),
            None,
        );
    })
}

#[test]
fn should_provide_public_keys_via_crypto_for_non_replica_process() {
    CryptoConfig::run_with_temp_config(|config| {
        // Create node keys.
        let (created_node_pks, _node_id) = get_node_keys_or_generate_if_missing(&config, None);

        let registry_client = FakeRegistryClient::new(Arc::new(ProtoRegistryDataProvider::new()));
        let crypto = CryptoComponent::new_for_non_replica_process(
            &config,
            None,
            Arc::new(registry_client),
            no_op_logger(),
            None,
        );

        let retrieved_node_pks = crypto.current_node_public_keys();

        assert!(all_node_keys_are_present(&retrieved_node_pks));
        assert_eq!(created_node_pks, retrieved_node_pks);
    })
}

// TODO(CRP-430): check/improve the test coverage of SKS checks.

fn all_node_keys_are_present(node_pks: &CurrentNodePublicKeys) -> bool {
    node_pks.node_signing_public_key.is_some()
        && node_pks.committee_signing_public_key.is_some()
        && node_pks.tls_certificate.is_some()
        && node_pks.dkg_dealing_encryption_public_key.is_some()
        && node_pks.idkg_dealing_encryption_public_key.is_some()
}

#[test]
fn should_fail_check_keys_with_registry_if_no_keys_are_present_in_registry() {
    let crypto = TestKeygenCrypto::builder()
        .with_node_keys_to_generate(NodeKeysToGenerate::all())
        .build(NODE_ID, REG_V1);

    let result = crypto.get().check_keys_with_registry(REG_V1);

    assert!(
        matches!(result, Err(CryptoError::PublicKeyNotFound { key_purpose, .. }) if key_purpose == KeyPurpose::NodeSigning)
    );
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
fn should_fail_check_keys_with_registry_if_idkg_dealing_encryption_key_is_missing_in_registry_and_pubkey_store(
) {
    let crypto = TestKeygenCrypto::builder()
        .with_node_keys_to_generate(NodeKeysToGenerate::all_except_idkg_dealing_encryption_key())
        .add_generated_node_signing_key_to_registry()
        .add_generated_committee_signing_key_to_registry()
        .add_generated_dkg_dealing_enc_key_to_registry()
        .add_generated_tls_cert_to_registry()
        .build(NODE_ID, REG_V1);
    let idkg_dealing_encryption_pk_in_public_key_store = crypto
        .get()
        .current_node_public_keys()
        .idkg_dealing_encryption_public_key;
    assert!(idkg_dealing_encryption_pk_in_public_key_store.is_none());

    let result = crypto.get().check_keys_with_registry(REG_V1);

    assert!(
        matches!(result, Err(CryptoError::PublicKeyNotFound { key_purpose, .. }) if key_purpose == KeyPurpose::IDkgMEGaEncryption)
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
fn should_fail_check_keys_with_registry_if_tls_cert_is_malformed() {
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
        .add_generated_idkg_dealing_enc_key_to_registry()
        .build(NODE_ID, REG_V1);

    let result = crypto.get().check_keys_with_registry(REG_V1);

    assert!(matches!(
        result,
        Err(CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::Tls,
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
        timestamp: None,
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
        timestamp: None,
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
        timestamp: None,
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
        timestamp: None,
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
        timestamp: None,
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
        timestamp: None,
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
        timestamp: None,
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
        timestamp: None,
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
fn should_fail_check_keys_with_registry_if_idkg_dealing_encryption_pubkey_algorithm_is_unsupported()
{
    let idkg_dealing_enc_pubkey_with_unsupported_algorithm = {
        let mut key = well_formed_idkg_dealing_encryption_pk();
        key.algorithm = AlgorithmIdProto::Tls as i32;
        key
    };
    let crypto = TestKeygenCrypto::builder()
        .with_node_keys_to_generate(NodeKeysToGenerate::all())
        .add_generated_node_signing_key_to_registry()
        .add_generated_committee_signing_key_to_registry()
        .add_generated_dkg_dealing_enc_key_to_registry()
        .add_generated_tls_cert_to_registry()
        .with_idkg_dealing_enc_key_in_registry(idkg_dealing_enc_pubkey_with_unsupported_algorithm)
        .build(NODE_ID, REG_V1);

    let result = crypto.get().check_keys_with_registry(REG_V1);

    assert!(
        matches!(result, Err(CryptoError::MalformedPublicKey { algorithm, internal_error, ..})
            if algorithm == AlgorithmId::MegaSecp256k1
            && internal_error.contains("unsupported algorithm")
        )
    );
}

#[test]
fn should_fail_check_keys_with_registry_if_idkg_dealing_encryption_pubkey_is_malformed() {
    let malformed_idkg_dealing_enc_pubkey = {
        let mut key = well_formed_idkg_dealing_encryption_pk();
        key.key_value = b"malformed key".to_vec();
        key
    };
    let crypto = TestKeygenCrypto::builder()
        .with_node_keys_to_generate(NodeKeysToGenerate::all())
        .add_generated_node_signing_key_to_registry()
        .add_generated_committee_signing_key_to_registry()
        .add_generated_dkg_dealing_enc_key_to_registry()
        .add_generated_tls_cert_to_registry()
        .with_idkg_dealing_enc_key_in_registry(malformed_idkg_dealing_enc_pubkey)
        .build(NODE_ID, REG_V1);

    let result = crypto.get().check_keys_with_registry(REG_V1);

    assert!(
        matches!(result, Err(CryptoError::MalformedPublicKey { algorithm, internal_error, ..})
            if algorithm == AlgorithmId::MegaSecp256k1
            && internal_error.contains("malformed")
        )
    );
}

#[test]
fn should_fail_check_keys_with_registry_if_idkg_dealing_encryption_secret_key_is_missing() {
    let idkg_dealing_enc_pubkey_with_without_secret_part_in_store =
        well_formed_idkg_dealing_encryption_pk();
    let crypto = TestKeygenCrypto::builder()
        .with_node_keys_to_generate(NodeKeysToGenerate::all())
        .add_generated_node_signing_key_to_registry()
        .add_generated_committee_signing_key_to_registry()
        .add_generated_dkg_dealing_enc_key_to_registry()
        .add_generated_tls_cert_to_registry()
        .with_idkg_dealing_enc_key_in_registry(
            idkg_dealing_enc_pubkey_with_without_secret_part_in_store,
        )
        .build(NODE_ID, REG_V1);

    let result = crypto.get().check_keys_with_registry(REG_V1);

    assert!(
        matches!(result, Err(CryptoError::SecretKeyNotFound { algorithm, ..}) if algorithm == AlgorithmId::MegaSecp256k1)
    );
}

#[test]
fn should_return_rotation_needed_from_check_keys_with_registry_if_no_idkg_timestamp_set() {
    let registry_data = Arc::new(ProtoRegistryDataProvider::new());
    let registry_client = Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));
    let time = FastForwardCryptoTimeSource::new();
    let crypto_component = TempCryptoComponent::builder()
        .with_keys(NodeKeysToGenerate::all())
        .with_registry_client_and_data(
            Arc::clone(&registry_client) as Arc<_>,
            Arc::clone(&registry_data) as Arc<_>,
        )
        .with_time_source(Arc::clone(&time) as Arc<_>)
        .with_node_id(node_id())
        .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
            subnet_id(),
            Some(node_id()),
            Some(TWO_WEEKS),
        ))
        .build();
    registry_client.reload();

    let result = crypto_component.check_keys_with_registry(REG_V1);

    assert!(matches!(
        result,
        Ok(PublicKeyRegistrationStatus::RotateIDkgDealingEncryptionKeys)
    ));
}

#[test]
fn should_return_all_keys_registered_from_check_keys_with_registry_if_no_subnet_configured() {
    let crypto = TestKeygenCrypto::builder()
        .with_node_keys_to_generate(NodeKeysToGenerate::all())
        .add_generated_node_signing_key_to_registry()
        .add_generated_committee_signing_key_to_registry()
        .add_generated_dkg_dealing_enc_key_to_registry()
        .add_generated_idkg_dealing_enc_key_to_registry()
        .add_generated_tls_cert_to_registry()
        .build(NODE_ID, REG_V1);

    let result = crypto.get().check_keys_with_registry(REG_V1);

    assert!(matches!(
        result,
        Ok(PublicKeyRegistrationStatus::AllKeysRegistered)
    ));
}

#[test]
fn should_fail_check_keys_with_registry_if_no_idkg_key_in_registry() {
    let crypto = TestKeygenCrypto::builder()
        .with_node_keys_to_generate(NodeKeysToGenerate::all())
        .add_generated_node_signing_key_to_registry()
        .add_generated_committee_signing_key_to_registry()
        .add_generated_dkg_dealing_enc_key_to_registry()
        .add_generated_tls_cert_to_registry()
        // explicitly not adding the I-DKG dealing encryption key to the registry
        .build(NODE_ID, REG_V1);
    let idkg_dealing_encryption_pk_in_public_key_store = crypto
        .get()
        .current_node_public_keys()
        .idkg_dealing_encryption_public_key;
    assert!(idkg_dealing_encryption_pk_in_public_key_store.is_some());

    let result = crypto.get().check_keys_with_registry(REG_V1);
    assert!(
        matches!(result, Err(CryptoError::PublicKeyNotFound { key_purpose, .. }) if key_purpose == KeyPurpose::IDkgMEGaEncryption)
    );
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

#[test]
fn should_fail_check_keys_with_registry_if_registry_node_signing_key_has_no_matching_secret_key() {
    let registry_data = Arc::new(ProtoRegistryDataProvider::new());
    let registry_client = Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));
    let crypto_component = TempCryptoComponent::builder()
        .with_keys(NodeKeysToGenerate::all())
        .with_registry_client_and_data(
            Arc::clone(&registry_client) as Arc<_>,
            Arc::clone(&registry_data) as Arc<_>,
        )
        .build();

    let node_signing_pk_without_corresponding_secret_key = {
        let mut nspk = crypto_component
            .current_node_public_keys()
            .node_signing_public_key
            .unwrap();
        nspk.key_value[0] ^= 0xff; // flip some bits
        nspk
    };

    add_public_key_to_registry(
        node_signing_pk_without_corresponding_secret_key,
        crypto_component.get_node_id(),
        KeyPurpose::NodeSigning,
        Arc::clone(&registry_data),
        REG_V2,
    );
    registry_client.reload();

    let result = crypto_component.check_keys_with_registry(REG_V2);

    assert!(
        matches!(result, Err(CryptoError::SecretKeyNotFound {algorithm, .. })
            if algorithm == AlgorithmId::Ed25519
        )
    );
}

#[test]
fn should_fail_check_keys_with_registry_if_registry_committee_signing_public_key_has_no_matching_secret_key(
) {
    let registry_data = Arc::new(ProtoRegistryDataProvider::new());
    let registry_client = Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));
    let crypto_component = TempCryptoComponent::builder()
        .with_keys(NodeKeysToGenerate::all())
        .with_registry_client_and_data(
            Arc::clone(&registry_client) as Arc<_>,
            Arc::clone(&registry_data) as Arc<_>,
        )
        .build();
    let committee_signing_pk_without_corresponding_secret_key = {
        let mut cspk = crypto_component
            .current_node_public_keys()
            .committee_signing_public_key
            .unwrap();
        cspk.key_value[0] ^= 0xff; // flip some bits
        cspk
    };

    add_public_key_to_registry(
        committee_signing_pk_without_corresponding_secret_key,
        crypto_component.get_node_id(),
        KeyPurpose::CommitteeSigning,
        Arc::clone(&registry_data),
        REG_V2,
    );
    registry_client.reload();

    let result = crypto_component.check_keys_with_registry(REG_V2);
    assert!(
        matches!(result, Err(CryptoError::SecretKeyNotFound {algorithm, .. })
            if algorithm == AlgorithmId::MultiBls12_381
        )
    );
}

#[test]
fn should_fail_check_keys_with_registry_if_registry_dkg_dealing_encryption_key_has_no_matching_secret_key(
) {
    let registry_data = Arc::new(ProtoRegistryDataProvider::new());
    let registry_client = Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));
    let crypto_component = TempCryptoComponent::builder()
        .with_keys(NodeKeysToGenerate::all())
        .with_registry_client_and_data(
            Arc::clone(&registry_client) as Arc<_>,
            Arc::clone(&registry_data) as Arc<_>,
        )
        .build();
    let dkg_dealing_encryption_pk_without_corresponding_secret_key = {
        let mut ddepk = crypto_component
            .current_node_public_keys()
            .dkg_dealing_encryption_public_key
            .unwrap();
        ddepk.key_value[0] ^= 0xff; // flip some bits
        ddepk
    };

    add_public_key_to_registry(
        dkg_dealing_encryption_pk_without_corresponding_secret_key,
        crypto_component.get_node_id(),
        KeyPurpose::DkgDealingEncryption,
        Arc::clone(&registry_data),
        REG_V2,
    );
    registry_client.reload();

    let result = crypto_component.check_keys_with_registry(REG_V2);

    assert!(
        matches!(result, Err(CryptoError::SecretKeyNotFound {algorithm, .. })
            if algorithm == AlgorithmId::Groth20_Bls12_381
        )
    );
}

#[test]
fn should_fail_check_keys_with_registry_if_registry_tls_cert_has_no_matching_secret_key() {
    let registry_data = Arc::new(ProtoRegistryDataProvider::new());
    let registry_client = Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));
    let crypto_component = TempCryptoComponent::builder()
        .with_keys(NodeKeysToGenerate::all())
        .with_registry_client_and_data(
            Arc::clone(&registry_client) as Arc<_>,
            Arc::clone(&registry_data) as Arc<_>,
        )
        .build();
    let (tls_cert_without_corresponding_secret_key, tls_cert_der) = {
        let mut csprng = ChaChaRng::from_seed([9u8; 32]);
        let not_after = Asn1Time::days_from_now(31).expect("unable to create Asn1Time");
        let common_name = "another_common_name";
        let (x509_cert, _key_pair) =
            generate_tls_key_pair_der(&mut csprng, common_name, &not_after)
                .expect("error generating TLS key pair");
        (
            ic_crypto_tls_interfaces::TlsPublicKeyCert::new_from_der(x509_cert.bytes.clone())
                .expect("generated X509 certificate has malformed DER encoding")
                .to_proto(),
            x509_cert.bytes,
        )
    };

    add_tls_cert_to_registry(
        tls_cert_without_corresponding_secret_key,
        crypto_component.get_node_id(),
        Arc::clone(&registry_data),
        REG_V2,
    );

    registry_client.reload();

    let result = crypto_component.check_keys_with_registry(REG_V2);

    assert_eq!(
        result.unwrap_err(),
        CryptoError::TlsSecretKeyNotFound {
            certificate_der: tls_cert_der,
        }
    );
}

#[test]
fn should_succeed_check_keys_with_registry_if_idkg_dealing_encryption_key_timestamp_recent() {
    let registry_data = Arc::new(ProtoRegistryDataProvider::new());
    let registry_client = Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));
    let time = FastForwardCryptoTimeSource::new();
    time.set_time(time.get_current_time() + Duration::from_millis(2000))
        .unwrap();
    let crypto_component = TempCryptoComponent::builder()
        .with_keys(NodeKeysToGenerate::all())
        .with_registry_client_and_data(
            Arc::clone(&registry_client) as Arc<_>,
            Arc::clone(&registry_data) as Arc<_>,
        )
        .with_time_source(Arc::clone(&time) as Arc<_>)
        .build();
    let mut idkg_dealing_encryption_pk = crypto_component
        .current_node_public_keys()
        .idkg_dealing_encryption_public_key
        .expect("no idkg dealing encryption key set");
    idkg_dealing_encryption_pk.timestamp = Some(get_timestamp_from_time(time.get_current_time()));

    add_public_key_to_registry(
        idkg_dealing_encryption_pk,
        crypto_component.get_node_id(),
        KeyPurpose::IDkgMEGaEncryption,
        Arc::clone(&registry_data),
        REG_V2,
    );
    registry_client.reload();

    time.set_time(time.get_current_time() + Duration::from_millis(2000))
        .unwrap();
    let result = crypto_component.check_keys_with_registry(REG_V2);

    assert!(matches!(
        result,
        Ok(PublicKeyRegistrationStatus::AllKeysRegistered)
    ));
}

#[test]
fn should_return_rotation_needed_from_check_keys_with_registry_if_idkg_dealing_encryption_key_timestamp_too_old(
) {
    let registry_data = Arc::new(ProtoRegistryDataProvider::new());
    let registry_client = Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));
    let time = FastForwardCryptoTimeSource::new();
    time.set_time(time.get_current_time() + Duration::from_millis(2000))
        .unwrap();
    let crypto_component = TempCryptoComponent::builder()
        .with_keys(NodeKeysToGenerate::all())
        .with_registry_client_and_data(
            Arc::clone(&registry_client) as Arc<_>,
            Arc::clone(&registry_data) as Arc<_>,
        )
        .with_time_source(Arc::clone(&time) as Arc<_>)
        .with_node_id(node_id())
        .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
            subnet_id(),
            Some(node_id()),
            Some(TWO_WEEKS),
        ))
        .build();
    let mut idkg_dealing_encryption_pk = crypto_component
        .current_node_public_keys()
        .idkg_dealing_encryption_public_key
        .expect("no idkg dealing encryption key set");
    idkg_dealing_encryption_pk.timestamp = Some(get_timestamp_from_time(time.get_current_time()));

    add_public_key_to_registry(
        idkg_dealing_encryption_pk,
        crypto_component.get_node_id(),
        KeyPurpose::IDkgMEGaEncryption,
        Arc::clone(&registry_data),
        REG_V2,
    );
    registry_client.reload();

    time.set_time(time.get_current_time() + TWO_WEEKS + Duration::from_secs(1))
        .unwrap();
    let result = crypto_component.check_keys_with_registry(REG_V2);

    assert!(matches!(
        result,
        Ok(PublicKeyRegistrationStatus::RotateIDkgDealingEncryptionKeys)
    ));
}

#[test]
fn should_return_all_keys_registered_from_check_keys_with_registry_if_no_key_rotation_period_set() {
    let registry_data = Arc::new(ProtoRegistryDataProvider::new());
    let registry_client = Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));
    let time = FastForwardCryptoTimeSource::new();
    time.set_time(time.get_current_time() + Duration::from_millis(2000))
        .unwrap();
    let crypto_component = TempCryptoComponent::builder()
        .with_keys(NodeKeysToGenerate::all())
        .with_registry_client_and_data(
            Arc::clone(&registry_client) as Arc<_>,
            Arc::clone(&registry_data) as Arc<_>,
        )
        .with_time_source(Arc::clone(&time) as Arc<_>)
        .with_node_id(node_id())
        .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(subnet_id(), Some(node_id()), None))
        .build();
    let mut idkg_dealing_encryption_pk = crypto_component
        .current_node_public_keys()
        .idkg_dealing_encryption_public_key
        .expect("no idkg dealing encryption key set");
    idkg_dealing_encryption_pk.timestamp = Some(get_timestamp_from_time(time.get_current_time()));

    add_public_key_to_registry(
        idkg_dealing_encryption_pk,
        crypto_component.get_node_id(),
        KeyPurpose::IDkgMEGaEncryption,
        Arc::clone(&registry_data),
        REG_V2,
    );
    registry_client.reload();

    // Set the current time such that the keys should be rotated if the configuration is set accordingly
    time.set_time(time.get_current_time() + TWO_WEEKS + Duration::from_secs(1))
        .unwrap();
    let result = crypto_component.check_keys_with_registry(REG_V2);

    assert!(matches!(
        result,
        Ok(PublicKeyRegistrationStatus::AllKeysRegistered)
    ));
}

#[test]
fn should_return_all_keys_registered_from_check_keys_with_registry_if_node_not_in_any_subnet() {
    let registry_data = Arc::new(ProtoRegistryDataProvider::new());
    let registry_client = Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));
    let time = FastForwardCryptoTimeSource::new();
    time.set_time(time.get_current_time() + Duration::from_millis(2000))
        .unwrap();
    let crypto_component = TempCryptoComponent::builder()
        .with_keys(NodeKeysToGenerate::all())
        .with_registry_client_and_data(
            Arc::clone(&registry_client) as Arc<_>,
            Arc::clone(&registry_data) as Arc<_>,
        )
        .with_time_source(Arc::clone(&time) as Arc<_>)
        .with_node_id(node_id())
        .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(subnet_id(), None, Some(TWO_WEEKS)))
        .build();
    let mut idkg_dealing_encryption_pk = crypto_component
        .current_node_public_keys()
        .idkg_dealing_encryption_public_key
        .expect("no idkg dealing encryption key set");
    idkg_dealing_encryption_pk.timestamp = Some(get_timestamp_from_time(time.get_current_time()));

    add_public_key_to_registry(
        idkg_dealing_encryption_pk,
        crypto_component.get_node_id(),
        KeyPurpose::IDkgMEGaEncryption,
        Arc::clone(&registry_data),
        REG_V2,
    );
    registry_client.reload();

    // Set the current time such that the keys should be rotated if the configuration is set accordingly
    time.set_time(time.get_current_time() + TWO_WEEKS + Duration::from_secs(1))
        .unwrap();
    let result = crypto_component.check_keys_with_registry(REG_V2);

    assert!(matches!(
        result,
        Ok(PublicKeyRegistrationStatus::AllKeysRegistered)
    ));
}

#[test]
fn should_return_all_keys_registered_from_check_keys_with_registry_if_no_ecdsa_key_ids_set() {
    let registry_data = Arc::new(ProtoRegistryDataProvider::new());
    let registry_client = Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));
    let time = FastForwardCryptoTimeSource::new();
    time.set_time(time.get_current_time() + Duration::from_millis(2000))
        .unwrap();
    let crypto_component = TempCryptoComponent::builder()
        .with_keys(NodeKeysToGenerate::all())
        .with_registry_client_and_data(
            Arc::clone(&registry_client) as Arc<_>,
            Arc::clone(&registry_data) as Arc<_>,
        )
        .with_time_source(Arc::clone(&time) as Arc<_>)
        .with_node_id(node_id())
        .with_ecdsa_subnet_config(EcdsaSubnetConfig::new_without_key_ids(
            subnet_id(),
            Some(node_id()),
            Some(TWO_WEEKS),
        ))
        .build();
    let mut idkg_dealing_encryption_pk = crypto_component
        .current_node_public_keys()
        .idkg_dealing_encryption_public_key
        .expect("no idkg dealing encryption key set");
    idkg_dealing_encryption_pk.timestamp = Some(get_timestamp_from_time(time.get_current_time()));

    add_public_key_to_registry(
        idkg_dealing_encryption_pk,
        crypto_component.get_node_id(),
        KeyPurpose::IDkgMEGaEncryption,
        Arc::clone(&registry_data),
        REG_V2,
    );
    registry_client.reload();

    // Set the current time such that the keys should be rotated if the configuration is set accordingly
    time.set_time(time.get_current_time() + TWO_WEEKS + Duration::from_secs(1))
        .unwrap();
    let result = crypto_component.check_keys_with_registry(REG_V2);

    assert!(matches!(
        result,
        Ok(PublicKeyRegistrationStatus::AllKeysRegistered)
    ));
}

#[test]
fn should_return_all_keys_registered_from_check_keys_with_registry_if_no_ecdsa_config_specified() {
    let registry_data = Arc::new(ProtoRegistryDataProvider::new());
    let registry_client = Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));
    let time = FastForwardCryptoTimeSource::new();
    time.set_time(time.get_current_time() + Duration::from_millis(2000))
        .unwrap();
    let crypto_component = TempCryptoComponent::builder()
        .with_keys(NodeKeysToGenerate::all())
        .with_registry_client_and_data(
            Arc::clone(&registry_client) as Arc<_>,
            Arc::clone(&registry_data) as Arc<_>,
        )
        .with_time_source(Arc::clone(&time) as Arc<_>)
        .with_node_id(node_id())
        .with_ecdsa_subnet_config(EcdsaSubnetConfig::new_without_ecdsa_config(
            subnet_id(),
            Some(node_id()),
        ))
        .build();
    let mut idkg_dealing_encryption_pk = crypto_component
        .current_node_public_keys()
        .idkg_dealing_encryption_public_key
        .expect("no idkg dealing encryption key set");
    idkg_dealing_encryption_pk.timestamp = Some(get_timestamp_from_time(time.get_current_time()));

    add_public_key_to_registry(
        idkg_dealing_encryption_pk,
        crypto_component.get_node_id(),
        KeyPurpose::IDkgMEGaEncryption,
        Arc::clone(&registry_data),
        REG_V2,
    );
    registry_client.reload();

    // Set the current time such that the keys should be rotated if the configuration is set accordingly
    time.set_time(time.get_current_time() + TWO_WEEKS + Duration::from_secs(1))
        .unwrap();
    let result = crypto_component.check_keys_with_registry(REG_V2);

    assert!(matches!(
        result,
        Ok(PublicKeyRegistrationStatus::AllKeysRegistered)
    ));
}

#[test]
fn should_return_registration_needed_from_check_keys_with_registry_if_local_idkg_dealing_encryption_key_newer_than_in_the_registry(
) {
    let registry_data = Arc::new(ProtoRegistryDataProvider::new());
    let registry_client = Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));
    let time = FastForwardCryptoTimeSource::new();
    time.set_time(time.get_current_time() + Duration::from_millis(2000))
        .unwrap();
    let crypto_component = TempCryptoComponent::builder()
        .with_keys(NodeKeysToGenerate::all())
        .with_registry_client_and_data(
            Arc::clone(&registry_client) as Arc<_>,
            Arc::clone(&registry_data) as Arc<_>,
        )
        .with_time_source(Arc::clone(&time) as Arc<_>)
        .with_node_id(node_id())
        .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
            subnet_id(),
            Some(node_id()),
            Some(TWO_WEEKS),
        ))
        .build();

    let mut idkg_dealing_encryption_pk = crypto_component
        .current_node_public_keys()
        .idkg_dealing_encryption_public_key
        .expect("no idkg dealing encryption key set");
    idkg_dealing_encryption_pk.timestamp = Some(get_timestamp_from_time(time.get_current_time()));

    add_public_key_to_registry(
        idkg_dealing_encryption_pk,
        crypto_component.get_node_id(),
        KeyPurpose::IDkgMEGaEncryption,
        Arc::clone(&registry_data),
        REG_V2,
    );
    registry_client.reload();

    time.set_time(time.get_current_time() + Duration::from_secs(60 * 60 * 24 * 15))
        .unwrap();
    let new_idkg_dealing_encryption_key_to_register = crypto_component
        .rotate_idkg_dealing_encryption_keys(REG_V2)
        .expect("Error rotating iDKG encryption key");

    time.set_time(time.get_current_time() + Duration::from_secs(60 * 60 * 24))
        .unwrap();
    let result = crypto_component.check_keys_with_registry(REG_V2);

    assert!(matches!(
        result,
        Ok(PublicKeyRegistrationStatus::IDkgDealingEncPubkeyNeedsRegistration(missing_pk))
          if missing_pk == new_idkg_dealing_encryption_key_to_register
    ));
}

#[test]
fn should_succeed_check_keys_with_registry_if_idkg_dealing_encryption_key_timestamp_only_almost_too_old(
) {
    let registry_data = Arc::new(ProtoRegistryDataProvider::new());
    let registry_client = Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));
    let time = FastForwardCryptoTimeSource::new();
    time.set_time(time.get_current_time() + Duration::from_millis(2000))
        .unwrap();
    let crypto_component = TempCryptoComponent::builder()
        .with_keys(NodeKeysToGenerate::all())
        .with_registry_client_and_data(
            Arc::clone(&registry_client) as Arc<_>,
            Arc::clone(&registry_data) as Arc<_>,
        )
        .with_time_source(Arc::clone(&time) as Arc<_>)
        .with_node_id(node_id())
        .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
            subnet_id(),
            Some(node_id()),
            Some(TWO_WEEKS),
        ))
        .build();
    let mut idkg_dealing_encryption_pk = crypto_component
        .current_node_public_keys()
        .idkg_dealing_encryption_public_key
        .expect("no idkg dealing encryption key set");
    idkg_dealing_encryption_pk.timestamp = Some(get_timestamp_from_time(time.get_current_time()));

    add_public_key_to_registry(
        idkg_dealing_encryption_pk,
        crypto_component.get_node_id(),
        KeyPurpose::IDkgMEGaEncryption,
        Arc::clone(&registry_data),
        REG_V2,
    );
    registry_client.reload();

    time.set_time(time.get_current_time() + TWO_WEEKS - Duration::from_secs(1))
        .unwrap();
    let result = crypto_component.check_keys_with_registry(REG_V2);

    assert!(matches!(
        result,
        Ok(PublicKeyRegistrationStatus::AllKeysRegistered)
    ));
}

#[test]
fn should_transition_from_all_keys_registered_to_rotation_needed_with_sys_time_source() {
    let key_rotation_period = Duration::from_secs(5);
    let registry_data = Arc::new(ProtoRegistryDataProvider::new());
    let registry_client = Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));
    let time: Arc<dyn CryptoTime> = Arc::new(SysTimeSource::new());
    let crypto_component = TempCryptoComponent::builder()
        .with_keys(NodeKeysToGenerate::all())
        .with_registry_client_and_data(
            Arc::clone(&registry_client) as Arc<_>,
            Arc::clone(&registry_data) as Arc<_>,
        )
        .with_time_source(Arc::clone(&time) as Arc<_>)
        .with_node_id(node_id())
        .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
            subnet_id(),
            Some(node_id()),
            Some(key_rotation_period),
        ))
        .build();
    let mut idkg_dealing_encryption_pk = crypto_component
        .current_node_public_keys()
        .idkg_dealing_encryption_public_key
        .expect("no idkg dealing encryption key set");
    idkg_dealing_encryption_pk.timestamp = Some(get_timestamp_from_time(time.get_current_time()));

    add_public_key_to_registry(
        idkg_dealing_encryption_pk,
        crypto_component.get_node_id(),
        KeyPurpose::IDkgMEGaEncryption,
        Arc::clone(&registry_data),
        REG_V2,
    );
    registry_client.reload();

    let result = crypto_component.check_keys_with_registry(REG_V2);

    assert!(matches!(
        result,
        Ok(PublicKeyRegistrationStatus::AllKeysRegistered)
    ));

    std::thread::sleep(key_rotation_period + Duration::from_secs(1));

    let result = crypto_component.check_keys_with_registry(REG_V2);

    assert!(matches!(
        result,
        Ok(PublicKeyRegistrationStatus::RotateIDkgDealingEncryptionKeys)
    ));
}

fn get_timestamp_from_time(time: Time) -> u64 {
    time.as_nanos_since_unix_epoch() / 1000000
}

fn new_tokio_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().expect("failed to create runtime")
}

fn well_formed_dkg_dealing_encryption_pk() -> PublicKey {
    let temp_crypto =
        new_temp_crypto_component(NodeKeysToGenerate::only_dkg_dealing_encryption_key());
    temp_crypto
        .current_node_public_keys()
        .dkg_dealing_encryption_public_key
        .unwrap()
}

fn well_formed_idkg_dealing_encryption_pk() -> PublicKey {
    let temp_crypto =
        new_temp_crypto_component(NodeKeysToGenerate::only_idkg_dealing_encryption_key());
    temp_crypto
        .current_node_public_keys()
        .idkg_dealing_encryption_public_key
        .unwrap()
}

fn new_temp_crypto_component(selector: NodeKeysToGenerate) -> TempCryptoComponent {
    let dummy_node_id = node_test_id(NODE_ID);
    let dummy_data_provider = Arc::new(ProtoRegistryDataProvider::new());
    let dummy_registry_client = Arc::new(FakeRegistryClient::new(dummy_data_provider));
    TempCryptoComponent::builder()
        .with_registry(Arc::clone(&dummy_registry_client) as Arc<_>)
        .with_node_id(dummy_node_id)
        .with_keys(selector)
        .build()
}

fn node_id() -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(NODE_ID))
}

fn subnet_id() -> SubnetId {
    SubnetId::new(PrincipalId::new(29, [0xfc; 29]))
}
