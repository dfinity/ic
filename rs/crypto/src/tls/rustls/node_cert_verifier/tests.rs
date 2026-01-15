use crate::tls::rustls::node_cert_verifier::NodeClientCertVerifier;
use crate::tls::rustls::node_cert_verifier::NodeServerCertVerifier;
use assert_matches::assert_matches;
use ic_base_types::NodeId;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_crypto_test_utils_tls::registry::{REG_V1, TlsRegistry};
use ic_crypto_test_utils_tls::x509_certificates::{CertWithPrivateKey, x509_public_key_cert};
use ic_crypto_tls_interfaces::SomeOrAllNodes;
use ic_types_test_utils::ids::{NODE_1, NODE_2, NODE_3};
use maplit::btreeset;
use rustls::{
    CertificateError, Error as TLSError,
    client::danger::ServerCertVerifier,
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::danger::ClientCertVerifier,
};
use std::collections::BTreeSet;
use std::time::Duration;

mod client_cert_verifier_tests {
    use super::*;

    #[test]
    fn should_return_ok_if_node_allowed_and_certificate_in_registry() {
        let rng = &mut reproducible_rng();
        let node_1_cert = CertWithPrivateKey::builder()
            .cn(NODE_1.to_string())
            .build_ed25519(rng);
        let registry = TlsRegistry::new();
        let verifier = verifier_with_allowed_nodes(btreeset! {NODE_1, NODE_2}, &registry);
        registry
            .add_cert(NODE_1, x509_public_key_cert(&node_1_cert.x509()))
            .update();

        let result = verifier.verify_client_cert(
            &CertificateDer::from(node_1_cert.cert_der()),
            &[],
            UnixTime::now(),
        );

        assert_matches!(result, Ok(_));
    }

    #[test]
    fn should_return_ok_if_all_nodes_are_allowed_and_client_cert_in_registry() {
        let rng = &mut reproducible_rng();
        let node_1_cert = CertWithPrivateKey::builder()
            .cn(NODE_1.to_string())
            .build_ed25519(rng);
        let registry = TlsRegistry::new();
        let verifier = NodeClientCertVerifier::new_with_mandatory_client_auth(
            SomeOrAllNodes::All,
            registry.get(),
            REG_V1,
        );
        registry
            .add_cert(NODE_1, x509_public_key_cert(&node_1_cert.x509()))
            .update();

        let result = verifier.verify_client_cert(
            &CertificateDer::from(node_1_cert.cert_der()),
            &[],
            UnixTime::now(),
        );

        assert_matches!(result, Ok(_));
    }

    #[test]
    fn should_return_error_if_validation_time_is_before_notbefore_variable() {
        let rng = &mut reproducible_rng();
        const VALIDATION_TIME_SINCE_UNIX_EPOCH: Duration = Duration::ZERO;
        /// One second after now/validation time (`=UNIX_EPOCH`).
        const NOT_BEFORE: i64 = 1;

        let node_1_cert = CertWithPrivateKey::builder()
            .cn(NODE_1.to_string())
            .not_before_unix(NOT_BEFORE)
            .build_ed25519(rng);
        let registry = TlsRegistry::new();
        let verifier = verifier_with_allowed_nodes(btreeset! {NODE_1, NODE_2}, &registry);
        registry
            .add_cert(NODE_1, x509_public_key_cert(&node_1_cert.x509()))
            .update();

        let result = verifier.verify_client_cert(
            &CertificateDer::from(node_1_cert.cert_der()),
            &[],
            UnixTime::since_unix_epoch(VALIDATION_TIME_SINCE_UNIX_EPOCH),
        );

        assert_matches!(
            result, Err(TLSError::General(e)) if
                e.contains("invalid TLS certificate: notBefore date") &&
                e.contains(" is in the future compared to current time ")
        );
    }

    #[test]
    fn should_return_error_if_presented_cert_node_id_not_allowed() {
        let rng = &mut reproducible_rng();
        const UNTRUSTED_NODE_ID: NodeId = NODE_3;
        let untrusted_node_cert = CertWithPrivateKey::builder()
            .cn(UNTRUSTED_NODE_ID.to_string())
            .build_ed25519(rng);
        let registry = TlsRegistry::new();
        let verifier = verifier_with_allowed_nodes(btreeset! {NODE_1, NODE_2}, &registry);
        registry
            .add_cert(
                UNTRUSTED_NODE_ID,
                x509_public_key_cert(&untrusted_node_cert.x509()),
            )
            .update();

        let result = verifier.verify_client_cert(
            &CertificateDer::from(untrusted_node_cert.cert_der()),
            &[],
            UnixTime::now(),
        );

        assert_eq!(
            result.err(),
            Some(TLSError::General(
                "The peer certificate with node ID 32uhy-eydaa-aaaaa-aaaap-2ai is not allowed. \
                Allowed node IDs: Some({3jo2y-lqbaa-aaaaa-aaaap-2ai, gfvbo-licaa-aaaaa-aaaap-2ai})"
                    .to_string(),
            ))
        );
    }

    #[test]
    fn should_return_error_if_node_id_allowed_but_cert_does_not_match_registry_cert() {
        let rng = &mut reproducible_rng();
        let presented_node_1_cert = CertWithPrivateKey::builder()
            .cn(NODE_1.to_string())
            .build_ed25519(rng);
        let registry_node_1_cert_different_from_presented_cert = CertWithPrivateKey::builder()
            .cn(NODE_1.to_string())
            .build_ed25519(rng);
        assert_ne!(
            presented_node_1_cert.cert_der(),
            registry_node_1_cert_different_from_presented_cert.cert_der()
        );
        let registry = TlsRegistry::new();
        let verifier = verifier_with_allowed_nodes(btreeset! {NODE_1, NODE_2}, &registry);
        registry
            .add_cert(
                NODE_1,
                x509_public_key_cert(&registry_node_1_cert_different_from_presented_cert.x509()),
            )
            .update();

        let result = verifier.verify_client_cert(
            &CertificateDer::from(presented_node_1_cert.cert_der()),
            &[],
            UnixTime::now(),
        );

        assert_eq!(
            result.err(),
            Some(TLSError::General(
                "The peer certificate is not trusted since it differs from the registry certificate. \
                NodeId of presented cert: 3jo2y-lqbaa-aaaaa-aaaap-2ai".to_string(),
            ))
        );
    }

    #[test]
    fn should_return_error_if_presented_cert_node_id_cannot_be_parsed() {
        let rng = &mut reproducible_rng();
        let cert_with_no_node_id_as_cn = CertWithPrivateKey::builder()
            .cn("This CN cannot be parsed as node ID".to_string())
            .build_ed25519(rng);
        let verifier = verifier_with_allowed_nodes(btreeset! {NODE_1, NODE_2}, &TlsRegistry::new());

        let result = verifier.verify_client_cert(
            &CertificateDer::from(cert_with_no_node_id_as_cn.cert_der()),
            &[],
            UnixTime::now(),
        );

        assert_matches!(
            result,
            Err(TLSError::InvalidCertificate(CertificateError::Other(_)))
        );
    }

    #[test]
    fn should_return_error_if_presented_cert_node_id_cannot_be_parsed_since_two_subject_cns_present()
     {
        let rng = &mut reproducible_rng();
        let cert_with_duplicate_cn = CertWithPrivateKey::builder()
            .cn(NODE_1.to_string())
            .with_duplicate_subject_cn()
            .build_ed25519(rng);
        let verifier = verifier_with_allowed_nodes(btreeset! {NODE_1, NODE_2}, &TlsRegistry::new());

        let result = verifier.verify_client_cert(
            &CertificateDer::from(cert_with_duplicate_cn.cert_der()),
            &[],
            UnixTime::now(),
        );

        assert_matches!(
            result,
            Err(TLSError::InvalidCertificate(CertificateError::Other(_)))
        );
    }

    #[test]
    fn should_return_error_if_more_than_one_presented_certs() {
        let rng = &mut reproducible_rng();
        let node_1_cert_1 = CertWithPrivateKey::builder()
            .cn(NODE_1.to_string())
            .build_ed25519(rng);
        let node_1_cert_2 = CertWithPrivateKey::builder()
            .cn(NODE_1.to_string())
            .build_ed25519(rng);
        let verifier = verifier_with_allowed_nodes(btreeset! {NODE_1, NODE_2}, &TlsRegistry::new());

        let result = verifier.verify_client_cert(
            &CertificateDer::from(node_1_cert_1.cert_der()),
            &[CertificateDer::from(node_1_cert_2.cert_der())],
            UnixTime::now(),
        );

        assert_eq!(
            result.err(),
            Some(TLSError::General(
                "The peer must send exactly one self signed certificate, but it sent 2 certificates."
                    .to_string(),
            ))
        );
    }

    #[test]
    fn should_return_error_if_node_id_allowed_but_registry_is_empty() {
        let rng = &mut reproducible_rng();
        let node_1_cert = CertWithPrivateKey::builder()
            .cn(NODE_1.to_string())
            .build_ed25519(rng);
        let empty_registry = TlsRegistry::new();
        let verifier = verifier_with_allowed_nodes(btreeset! {NODE_1, NODE_2}, &empty_registry);

        let result = verifier.verify_client_cert(
            &CertificateDer::from(node_1_cert.cert_der()),
            &[],
            UnixTime::now(),
        );

        assert_eq!(
            result.err(),
            Some(TLSError::General(
                "Failed to retrieve TLS certificate for node ID 3jo2y-lqbaa-aaaaa-aaaap-2ai from the registry \
                at registry version 1: RegistryError(VersionNotAvailable { version: 1 })".to_string(),
            ))
        );
    }

    #[test]
    fn should_return_error_if_node_id_allowed_but_cert_not_in_registry() {
        let rng = &mut reproducible_rng();
        let node_1_cert = CertWithPrivateKey::builder()
            .cn(NODE_1.to_string())
            .build_ed25519(rng);
        let node_2_cert = CertWithPrivateKey::builder()
            .cn(NODE_2.to_string())
            .build_ed25519(rng);
        let registry_without_node_1_cert = TlsRegistry::new();
        let verifier =
            verifier_with_allowed_nodes(btreeset! {NODE_1, NODE_2}, &registry_without_node_1_cert);
        registry_without_node_1_cert
            .add_cert(NODE_2, x509_public_key_cert(&node_2_cert.x509()))
            .update();

        let result = verifier.verify_client_cert(
            &CertificateDer::from(node_1_cert.cert_der()),
            &[],
            UnixTime::now(),
        );

        assert_eq!(
            result.err(),
            Some(TLSError::General(
                "Failed to retrieve TLS certificate for node ID 3jo2y-lqbaa-aaaaa-aaaap-2ai from the registry \
                at registry version 1: CertificateNotInRegistry { node_id: 3jo2y-lqbaa-aaaaa-aaaap-2ai, registry_version: 1 }".to_string(),
            ))
        );
    }

    #[test]
    fn should_set_client_auth_to_mandatory_in_new_with_mandatory_client_auth() {
        let verifier = NodeClientCertVerifier::new_with_mandatory_client_auth(
            SomeOrAllNodes::All,
            TlsRegistry::new().get(),
            REG_V1,
        );

        assert!(verifier.client_auth_mandatory());
    }

    #[test]
    fn should_offer_client_auth_if_client_auth_mandatory() {
        let verifier = NodeClientCertVerifier::new_with_mandatory_client_auth(
            SomeOrAllNodes::All,
            TlsRegistry::new().get(),
            REG_V1,
        );

        assert!(verifier.offer_client_auth());
    }

    #[test]
    fn should_return_empty_root_hint_subjects() {
        let verifier = NodeClientCertVerifier::new_with_mandatory_client_auth(
            SomeOrAllNodes::All,
            TlsRegistry::new().get(),
            REG_V1,
        );
        assert!(verifier.root_hint_subjects().is_empty())
    }

    #[test]
    fn should_return_error_if_client_cert_has_bad_encoding() {
        let rng = &mut reproducible_rng();
        let node_1_cert = CertWithPrivateKey::builder()
            .cn(NODE_1.to_string())
            .build_ed25519(rng);
        let registry = TlsRegistry::new();
        let verifier = verifier_with_allowed_nodes(btreeset! {NODE_1, NODE_2}, &registry);
        registry
            .add_cert(NODE_1, x509_public_key_cert(&node_1_cert.x509()))
            .update();
        let invalid_cert_der = {
            let mut der = node_1_cert.cert_der();
            der[0] ^= 0xFF;
            der
        };

        let result = verifier.verify_client_cert(
            &CertificateDer::from(invalid_cert_der),
            &[],
            UnixTime::now(),
        );

        assert_matches!(
            result,
            Err(TLSError::InvalidCertificate(CertificateError::BadEncoding))
        );
    }

    fn verifier_with_allowed_nodes(
        allowed_nodes: BTreeSet<NodeId>,
        registry: &TlsRegistry,
    ) -> NodeClientCertVerifier {
        let allowed_nodes = SomeOrAllNodes::Some(allowed_nodes);
        NodeClientCertVerifier::new_with_mandatory_client_auth(
            allowed_nodes,
            registry.get(),
            REG_V1,
        )
    }
}

/// We only smoke test the server side with a positive and an error case since
/// the implementation calls the same method as the `ClientCertVerifier`.
mod server_cert_verifier_tests {
    use super::*;

    #[test]
    fn should_return_ok_if_node_allowed_and_certificate_in_registry() {
        let rng = &mut reproducible_rng();
        let node_1_cert = CertWithPrivateKey::builder()
            .cn(NODE_1.to_string())
            .build_ed25519(rng);
        let registry = TlsRegistry::new();
        let verifier = verifier_with_allowed_nodes(btreeset! {NODE_1, NODE_2}, &registry);
        registry
            .add_cert(NODE_1, x509_public_key_cert(&node_1_cert.x509()))
            .update();

        let result = verifier.verify_server_cert(
            &CertificateDer::from(node_1_cert.cert_der()),
            &[],
            &ServerName::try_from("www.irrelevant.com").expect("could not parse DNS name"),
            &[],
            UnixTime::now(),
        );

        assert_matches!(result, Ok(_));
    }

    #[test]
    fn should_return_error_if_validation_time_is_before_not_before_variable() {
        let rng = &mut reproducible_rng();
        const VALIDATION_TIME_SINCE_UNIX_EPOCH: Duration = Duration::ZERO;
        /// One second after now/validation time (`=UNIX_EPOCH`).
        const NOT_BEFORE: i64 = 1;
        let node_1_cert = CertWithPrivateKey::builder()
            .cn(NODE_1.to_string())
            .not_before_unix(NOT_BEFORE)
            .build_ed25519(rng);
        let registry = TlsRegistry::new();
        let verifier = verifier_with_allowed_nodes(btreeset! {NODE_1, NODE_2}, &registry);
        registry
            .add_cert(NODE_1, x509_public_key_cert(&node_1_cert.x509()))
            .update();

        let result = verifier.verify_server_cert(
            &CertificateDer::from(node_1_cert.cert_der()),
            &[],
            &ServerName::try_from("www.irrelevant.com").expect("could not parse DNS name"),
            &[],
            UnixTime::since_unix_epoch(VALIDATION_TIME_SINCE_UNIX_EPOCH),
        );

        assert_matches!(
            result, Err(TLSError::General(e)) if
                e.contains("invalid TLS certificate: notBefore date") &&
                e.contains(" is in the future compared to current time ")
        );
    }

    #[test]
    fn should_return_error_if_presented_cert_node_id_not_allowed() {
        let rng = &mut reproducible_rng();
        const UNTRUSTED_NODE_ID: NodeId = NODE_3;
        let untrusted_node_cert = CertWithPrivateKey::builder()
            .cn(UNTRUSTED_NODE_ID.to_string())
            .build_ed25519(rng);
        let registry = TlsRegistry::new();
        let verifier = verifier_with_allowed_nodes(btreeset! {NODE_1, NODE_2}, &registry);
        registry
            .add_cert(
                UNTRUSTED_NODE_ID,
                x509_public_key_cert(&untrusted_node_cert.x509()),
            )
            .update();

        let result = verifier.verify_server_cert(
            &CertificateDer::from(untrusted_node_cert.cert_der()),
            &[],
            &ServerName::try_from("www.irrelevant.com").expect("could not parse DNS name"),
            &[],
            UnixTime::now(),
        );

        assert_eq!(
            result.err(),
            Some(TLSError::General(
                "The peer certificate with node ID 32uhy-eydaa-aaaaa-aaaap-2ai is not allowed. Allowed node IDs: \
                Some({3jo2y-lqbaa-aaaaa-aaaap-2ai, gfvbo-licaa-aaaaa-aaaap-2ai})".to_string(),
            ))
        );
    }

    #[test]
    fn should_return_error_if_intermediate_certs_not_empty() {
        let rng = &mut reproducible_rng();
        let node_1_cert = CertWithPrivateKey::builder()
            .cn(NODE_1.to_string())
            .build_ed25519(rng);
        let registry = TlsRegistry::new();
        let verifier = verifier_with_allowed_nodes(btreeset! {NODE_1, NODE_2}, &registry);
        registry
            .add_cert(NODE_1, x509_public_key_cert(&node_1_cert.x509()))
            .update();

        let result = verifier.verify_server_cert(
            &CertificateDer::from(node_1_cert.cert_der()),
            &[CertificateDer::from(node_1_cert.cert_der())],
            &ServerName::try_from("www.irrelevant.com").expect("could not parse DNS name"),
            &[],
            UnixTime::now(),
        );

        assert_eq!(
            result.err(),
            Some(TLSError::General("The peer must send exactly one self signed certificate, but it sent 2 certificates.".to_string()))
        );
    }

    #[test]
    fn should_return_error_if_server_cert_has_bad_encoding() {
        let rng = &mut reproducible_rng();
        let node_1_cert = CertWithPrivateKey::builder()
            .cn(NODE_1.to_string())
            .build_ed25519(rng);
        let registry = TlsRegistry::new();
        let verifier = verifier_with_allowed_nodes(btreeset! {NODE_1, NODE_2}, &registry);
        registry
            .add_cert(NODE_1, x509_public_key_cert(&node_1_cert.x509()))
            .update();
        let invalid_cert_der = {
            let mut der = node_1_cert.cert_der();
            der[0] ^= 0xFF;
            der
        };

        let result = verifier.verify_server_cert(
            &CertificateDer::from(invalid_cert_der),
            &[],
            &ServerName::try_from("www.irrelevant.com").expect("could not parse DNS name"),
            &[],
            UnixTime::now(),
        );

        assert_matches!(
            result,
            Err(TLSError::InvalidCertificate(CertificateError::BadEncoding))
        );
    }

    fn verifier_with_allowed_nodes(
        allowed_nodes: BTreeSet<NodeId>,
        registry: &TlsRegistry,
    ) -> NodeServerCertVerifier {
        let allowed_nodes = SomeOrAllNodes::Some(allowed_nodes);
        NodeServerCertVerifier::new(allowed_nodes, registry.get(), REG_V1)
    }
}
