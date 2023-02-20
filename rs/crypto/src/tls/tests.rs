use super::*;
use assert_matches::assert_matches;
use ic_base_types::RegistryVersion;
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

    #[test]
    fn should_succeed_if_valid_certificate_found_in_registry() {
        let valid_certificate_der = hex::decode(
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
                bb905f52faf28707735f1d90ab654380b",
        )
        .expect("failed to decode hex");
        let valid_certificate = X509PublicKeyCert {
            certificate_der: valid_certificate_der.clone(),
        };
        let setup = Setup::builder()
            .with_registry_tls_certificate(valid_certificate)
            .build();
        let expected_tls_cert =
            TlsPublicKeyCert::new_from_der(valid_certificate_der).expect("failed to create cert");

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
