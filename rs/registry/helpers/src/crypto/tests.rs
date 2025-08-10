use super::*;
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::PrincipalId;
use std::sync::Arc;

const REG_V1: RegistryVersion = RegistryVersion::new(1);

#[test]
fn should_get_public_key_for_node() {
    let pubkey_proto = PublicKeyProto {
        algorithm: AlgorithmIdProto::Ed25519 as i32,
        key_value: b"public key".to_vec(),
        version: 0,
        proof_data: None,
        timestamp: Some(42),
    };
    let node_id = node_id(1);
    let key_purpose = KeyPurpose::NodeSigning;
    let data_provider = Arc::new(ProtoRegistryDataProvider::new());
    data_provider
        .add(
            &make_crypto_node_key(node_id, key_purpose),
            REG_V1,
            Some(pubkey_proto.clone()),
        )
        .unwrap();
    let registry = Arc::new(FakeRegistryClient::new(data_provider));
    registry.update_to_latest_version();

    let result = registry
        .get_crypto_key_for_node(node_id, key_purpose, REG_V1)
        .unwrap();

    assert_eq!(result, Some(pubkey_proto));
}

#[test]
fn should_get_threshold_signing_public_key_for_subnet() {
    let pubkey_proto = PublicKeyProto {
        algorithm: AlgorithmIdProto::ThresBls12381 as i32,
        key_value: [42; ThresholdSigPublicKey::SIZE].to_vec(),
        version: 0,
        proof_data: None,
        timestamp: Some(42),
    };
    let subnet_id = subnet_id(1);
    let data_provider = Arc::new(ProtoRegistryDataProvider::new());
    data_provider
        .add(
            &make_crypto_threshold_signing_pubkey_key(subnet_id),
            REG_V1,
            Some(pubkey_proto.clone()),
        )
        .unwrap();
    let registry = Arc::new(FakeRegistryClient::new(data_provider));
    registry.update_to_latest_version();

    let result = registry
        .get_threshold_signing_public_key_for_subnet(subnet_id, REG_V1)
        .unwrap();

    assert_eq!(
        result,
        Some(ThresholdSigPublicKey::try_from(pubkey_proto).unwrap())
    );
}

#[test]
#[should_panic(expected = "Failed to convert registry data to threshold signing public key")]
fn should_panic_on_getting_invalid_threshold_signing_public_key() {
    let invalid_pubkey_proto = PublicKeyProto {
        algorithm: AlgorithmIdProto::ThresBls12381 as i32,
        key_value: [42; ThresholdSigPublicKey::SIZE - 1].to_vec(),
        version: 0,
        proof_data: None,
        timestamp: None,
    };
    let subnet_id = subnet_id(1);
    let data_provider = Arc::new(ProtoRegistryDataProvider::new());
    data_provider
        .add(
            &make_crypto_threshold_signing_pubkey_key(subnet_id),
            REG_V1,
            Some(invalid_pubkey_proto),
        )
        .unwrap();
    let registry = Arc::new(FakeRegistryClient::new(data_provider));
    registry.update_to_latest_version();

    let _panic = registry.get_threshold_signing_public_key_for_subnet(subnet_id, REG_V1);
}

#[test]
fn should_get_tls_certificate_for_node() {
    let cert_proto = X509PublicKeyCert {
        certificate_der: b"DER-encoded X509 certificate".to_vec(),
    };
    let node_id = node_id(1);
    let data_provider = Arc::new(ProtoRegistryDataProvider::new());
    data_provider
        .add(
            &make_crypto_tls_cert_key(node_id),
            REG_V1,
            Some(cert_proto.clone()),
        )
        .unwrap();
    let registry = Arc::new(FakeRegistryClient::new(data_provider));
    registry.update_to_latest_version();

    let result = registry.get_tls_certificate(node_id, REG_V1).unwrap();

    assert_eq!(result, Some(cert_proto));
}

fn node_id(id: u64) -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(id))
}

fn subnet_id(id: u64) -> SubnetId {
    SubnetId::from(PrincipalId::new_subnet_test_id(id))
}
