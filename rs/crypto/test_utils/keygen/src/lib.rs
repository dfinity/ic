use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_registry_keys::{make_crypto_node_key, make_crypto_tls_cert_key};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::crypto::KeyPurpose;
use ic_types::{NodeId, RegistryVersion};
use std::sync::Arc;

pub fn add_tls_cert_to_registry(
    cert: X509PublicKeyCert,
    node_id: NodeId,
    registry: Arc<ProtoRegistryDataProvider>,
    registry_version: RegistryVersion,
) {
    registry
        .add(
            &make_crypto_tls_cert_key(node_id),
            registry_version,
            Some(cert),
        )
        .expect("Could not add TLS cert key to registry");
}

pub fn add_public_key_to_registry(
    public_key: PublicKey,
    node_id: NodeId,
    key_purpose: KeyPurpose,
    registry: Arc<ProtoRegistryDataProvider>,
    registry_version: RegistryVersion,
) {
    registry
        .add(
            &make_crypto_node_key(node_id, key_purpose),
            registry_version,
            Some(public_key),
        )
        .expect("Could not add public key to registry");
}
