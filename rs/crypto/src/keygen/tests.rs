#![allow(clippy::unwrap_used)]

use super::*;
use crate::utils::NodeKeysToGenerate;
use crate::TempCryptoComponent;
use ic_crypto_internal_tls::keygen::generate_tls_key_pair_der;
use ic_crypto_test_utils_keygen::{add_public_key_to_registry, add_tls_cert_to_registry};
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::crypto::KeyPurpose;
use ic_types::RegistryVersion;
use openssl::asn1::Asn1Time;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use std::sync::Arc;

const REG_V1: RegistryVersion = RegistryVersion::new(1);
const REG_V2: RegistryVersion = RegistryVersion::new(2);

#[test]
fn should_collect_correctly_key_count_metrics_for_all_keys() {
    let crypto_component = TempCryptoComponent::builder()
        .with_keys(NodeKeysToGenerate::all())
        .build();
    let key_counts = crypto_component.collect_key_count_metrics(REG_V1);
    assert_eq!(5, key_counts.get_pk_registry());
    assert_eq!(5, key_counts.get_pk_local());
    assert_eq!(5, key_counts.get_sk_local());
}

#[test]
fn should_collect_correctly_key_count_metrics_for_only_node_signing_key() {
    let crypto_component = TempCryptoComponent::builder()
        .with_keys(NodeKeysToGenerate::only_node_signing_key())
        .build();
    let key_counts = crypto_component.collect_key_count_metrics(REG_V1);
    assert_eq!(1, key_counts.get_pk_registry());
    assert_eq!(1, key_counts.get_pk_local());
    assert_eq!(1, key_counts.get_sk_local());
}

#[test]
fn should_count_correctly_inconsistent_numbers_of_node_signing_keys() {
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
        let mut nspk = crypto_component.node_public_keys().node_signing_pk.unwrap();
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

    let key_counts = crypto_component.collect_key_count_metrics(REG_V2);
    assert_eq!(5, key_counts.get_pk_registry());
    assert_eq!(5, key_counts.get_pk_local());
    assert_eq!(4, key_counts.get_sk_local());
}

#[test]
fn should_count_correctly_inconsistent_numbers_of_tls_certificates() {
    let registry_data = Arc::new(ProtoRegistryDataProvider::new());
    let registry_client = Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));
    let crypto_component = TempCryptoComponent::builder()
        .with_keys(NodeKeysToGenerate::all())
        .with_registry_client_and_data(
            Arc::clone(&registry_client) as Arc<_>,
            Arc::clone(&registry_data) as Arc<_>,
        )
        .build();

    let tls_cert_without_corresponding_secret_key = {
        let mut csprng = ChaChaRng::from_seed([9u8; 32]);
        let not_after = Asn1Time::days_from_now(31).expect("unable to create Asn1Time");
        let common_name = "another_common_name";
        let (x509_cert, _key_pair) =
            generate_tls_key_pair_der(&mut csprng, common_name, &not_after)
                .expect("error generating TLS key pair");
        TlsPublicKeyCert::new_from_der(x509_cert.bytes)
            .expect("generated X509 certificate has malformed DER encoding")
            .to_proto()
    };

    add_tls_cert_to_registry(
        tls_cert_without_corresponding_secret_key,
        crypto_component.get_node_id(),
        Arc::clone(&registry_data),
        REG_V2,
    );
    registry_client.reload();

    let key_counts = crypto_component.collect_key_count_metrics(REG_V2);
    assert_eq!(5, key_counts.get_pk_registry());
    assert_eq!(5, key_counts.get_pk_local());
    assert_eq!(4, key_counts.get_sk_local());
}
