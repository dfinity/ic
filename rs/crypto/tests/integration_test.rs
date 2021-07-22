#![allow(clippy::unwrap_used)]
use crate::keygen_utils::{add_keys_to_registry, TestKeygenCrypto};
use ic_config::crypto::CryptoConfig;
use ic_crypto::utils::{
    get_node_keys_or_generate_if_missing, NodeKeysToGenerate, TempCryptoComponent,
};
use ic_crypto::CryptoComponent;
use ic_crypto_test_utils::tls::x509_certificates::generate_ed25519_cert;
use ic_interfaces::crypto::{BasicSigner, KeyManager, Keygen, SignableMock};
use ic_interfaces::registry::RegistryClient;
use ic_logger::replica_logger::no_op_logger;
use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_registry_client::fake::FakeRegistryClient;
use ic_registry_common::proto_registry_data_provider::ProtoRegistryDataProvider;
use ic_test_utilities::types::ids::node_test_id;
use ic_types::crypto::{AlgorithmId, CryptoError, KeyId, KeyPurpose, UserPublicKey};
use ic_types::{NodeId, RegistryVersion};
use std::sync::mpsc::Receiver;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

mod keygen_utils;

const NUM_THREADS: i32 = 20;
const NUM_KEY_GEN_CALLS: i32 = 25;
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

#[test]
fn should_sign_with_keys_generated_in_multiple_threads() {
    CryptoConfig::run_with_temp_config(|config| {
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client = Arc::new(FakeRegistryClient::new(data_provider.clone()));
        let crypto_component = crypto_component(
            &config,
            Arc::clone(&registry_client) as Arc<dyn RegistryClient>,
        );
        let (initial_sender, receiver) = mpsc::channel();

        for _ in 0..NUM_THREADS {
            let crypto_component = Arc::clone(&crypto_component);
            let sender = mpsc::Sender::clone(&initial_sender);
            thread::spawn(move || {
                for _ in 0..NUM_KEY_GEN_CALLS {
                    let result = crypto_component.generate_user_keys_ed25519();
                    sender.send(result).unwrap();
                }
            });
        }
        let keys = receive_keys_from_threads(receiver, NUM_THREADS * NUM_KEY_GEN_CALLS);
        let node_ids = add_keys_to_registry(Arc::clone(&data_provider), keys);

        registry_client.update_to_latest_version();
        assert_sign_is_successful_for_node_ids(crypto_component, node_ids);
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
            internal_error: "MissingProofData".to_string(),
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

fn crypto_component(
    config: &CryptoConfig,
    registry_client: Arc<dyn RegistryClient>,
) -> Arc<CryptoComponent> {
    Arc::new(CryptoComponent::new_with_fake_node_id(
        config,
        registry_client,
        node_test_id(NODE_ID), /* we set the node id to a constant since it is currently
                                * irrelevant for these tests. */
        no_op_logger(),
    ))
}

fn receive_keys_from_threads(
    receiver: Receiver<Result<(KeyId, UserPublicKey), CryptoError>>,
    num_calls: i32,
) -> Vec<(KeyId, UserPublicKey)> {
    let mut keys: Vec<(KeyId, UserPublicKey)> = Vec::new();
    for _ in 0..num_calls {
        let result = receiver.recv_timeout(Duration::from_secs(3));
        let (key_id, pk) = result
            .expect("The channel did not contain a result as expected. ")
            .expect("Generating the user key was not successful");
        keys.push((key_id, pk));
    }
    keys
}

fn assert_sign_is_successful_for_node_ids(
    crypto_component: Arc<CryptoComponent>,
    node_ids: Vec<NodeId>,
) {
    for node_id in node_ids {
        assert!(crypto_component
            .sign_basic(&dummy_message(), node_id, REG_V1)
            .is_ok());
    }
}

fn dummy_message() -> SignableMock {
    SignableMock::new(b"message".to_vec())
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
            generate_tls_keys_and_certificate: false,
        },
    );
    node_pubkeys.dkg_dealing_encryption_pk.unwrap()
}
