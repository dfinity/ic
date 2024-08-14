use super::*;
use assert_matches::assert_matches;
use ic_base_types::{PrincipalId, RegistryVersion};
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::make_crypto_tls_cert_key;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;

const NODE_ID: u64 = 42;
const REGISTRY_VERSION_0: RegistryVersion = RegistryVersion::new(0);
const REGISTRY_VERSION_1: RegistryVersion = RegistryVersion::new(1);

struct Setup {
    registry_client: Arc<FakeRegistryClient>,
    registry_version: RegistryVersion,
}

impl Setup {
    fn builder() -> SetupBuilder {
        SetupBuilder {
            registry_tls_cert: None,
        }
    }
}

struct SetupBuilder {
    registry_tls_cert: Option<X509PublicKeyCert>,
}

impl SetupBuilder {
    fn with_registry_tls_certificate(mut self, tls_cert: X509PublicKeyCert) -> Self {
        self.registry_tls_cert = Some(tls_cert);
        self
    }

    fn build(self) -> Setup {
        let registry_data = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client =
            Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));

        let mut registry_version = REGISTRY_VERSION_0;
        if let Some(registry_tls_cert) = self.registry_tls_cert {
            registry_version = REGISTRY_VERSION_1;
            registry_data
                .add(
                    &make_crypto_tls_cert_key(node_id()),
                    registry_version,
                    Some(registry_tls_cert),
                )
                .expect("failed to add TLS certificate to registry");
            registry_client.reload();
        }

        Setup {
            registry_client,
            registry_version,
        }
    }
}

fn node_id() -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(NODE_ID))
}

mod tls_cert_from_registry_raw {
    use super::*;

    #[test]
    fn should_succeed_if_certificate_found_in_registry() {
        let dummy_certificate_der = b"dummy certificate".to_vec();
        let setup = Setup::builder()
            .with_registry_tls_certificate(X509PublicKeyCert {
                certificate_der: dummy_certificate_der.clone(),
            })
            .build();
        assert_matches!(
            tls_cert_from_registry_raw(
                setup.registry_client.as_ref(),
                node_id(),
                setup.registry_version
            ),
            Ok(X509PublicKeyCert { certificate_der }) if certificate_der == dummy_certificate_der
        );
    }

    #[test]
    fn should_fail_with_not_found_if_no_cert_found_in_registry() {
        let setup = Setup::builder().build();
        assert_matches!(
            tls_cert_from_registry_raw(
                setup.registry_client.as_ref(),
                node_id(),
                setup.registry_version
            ),
            Err(TlsCertFromRegistryError::CertificateNotInRegistry { .. })
        );
    }
}

mod tls_cert_from_registry {
    use super::*;
    use ic_crypto_test_utils_keys::public_keys::valid_tls_certificate_and_validation_time;

    #[test]
    fn should_succeed_if_valid_certificate_found_in_registry() {
        let valid_certificate = valid_tls_certificate_and_validation_time().0;
        let setup = Setup::builder()
            .with_registry_tls_certificate(valid_certificate.clone())
            .build();
        let expected_tls_cert = TlsPublicKeyCert::new_from_der(valid_certificate.certificate_der)
            .expect("failed to create cert");

        let result = tls_cert_from_registry(
            setup.registry_client.as_ref(),
            node_id(),
            setup.registry_version,
        );

        assert_matches!(result, Ok(tls_cert) if tls_cert == expected_tls_cert);
    }

    #[test]
    fn should_fail_with_not_found_if_no_cert_found_in_registry() {
        let setup = Setup::builder().build();
        assert_matches!(
            tls_cert_from_registry(
                setup.registry_client.as_ref(),
                node_id(),
                setup.registry_version
            ),
            Err(TlsCertFromRegistryError::CertificateNotInRegistry { .. })
        );
    }

    #[test]
    fn should_fail_if_certificate_in_registry_is_malformed() {
        let setup = Setup::builder()
            .with_registry_tls_certificate(X509PublicKeyCert {
                certificate_der: b"bogus certificate".to_vec(),
            })
            .build();
        assert_matches!(
            tls_cert_from_registry(
                setup.registry_client.as_ref(),
                node_id(),
                setup.registry_version
            ),
            Err(TlsCertFromRegistryError::CertificateMalformed { .. })
        );
    }
}
