#![allow(clippy::unwrap_used)]
use crate::ClientAuthentication;
use ic_crypto_test_utils::tls::x509_certificates::{
    ed25519_key_pair, generate_cert, generate_ed25519_cert, prime256v1_key_pair,
};
use openssl::hash::MessageDigest;
use openssl::ssl::{SslAcceptor, SslVerifyMode};

mod acceptor {
    use super::*;
    use crate::tls_acceptor;

    #[test]
    fn should_allow_client_authentication_if_enabled() {
        let acceptor = default_acceptor();

        let verify_mode = acceptor.context().verify_mode();
        assert_eq!(verify_mode, SslVerifyMode::PEER);
    }

    #[test]
    fn should_not_authenticate_client_if_client_auth_disabled() {
        let (key_pair, server_cert) = generate_ed25519_cert();
        let acceptor = tls_acceptor(
            &key_pair,
            &server_cert,
            ClientAuthentication::NoAuthentication,
        )
        .unwrap();

        let verify_mode = acceptor.context().verify_mode();
        assert_eq!(verify_mode, SslVerifyMode::NONE);
    }

    #[test]
    fn should_set_server_certificate() {
        let (key_pair, server_cert) = generate_ed25519_cert();

        let acceptor = tls_acceptor(&key_pair, &server_cert, dummy_trusted_client_certs()).unwrap();

        let cert_der_from_acceptor = acceptor.context().certificate().unwrap().to_der().unwrap();
        assert_eq!(cert_der_from_acceptor, server_cert.to_der().unwrap());
    }

    #[test]
    fn should_set_private_key() {
        let (key_pair, server_cert) = generate_ed25519_cert();

        let acceptor = tls_acceptor(&key_pair, &server_cert, dummy_trusted_client_certs()).unwrap();

        let acceptor_private_key_bytes = acceptor
            .context()
            .private_key()
            .unwrap()
            .private_key_to_der()
            .unwrap();
        assert_eq!(
            acceptor_private_key_bytes,
            key_pair.private_key_to_der().unwrap()
        );
    }

    /// This documents OpenSSL's behavior. It would also be ok if OpenSSL failed
    /// in this case.
    #[test]
    fn should_allow_certificate_with_p256_key() {
        let key_pair = prime256v1_key_pair();
        let server_cert = generate_cert(&key_pair, MessageDigest::sha256());

        tls_acceptor(&key_pair, &server_cert, dummy_trusted_client_certs())
            .expect("unexpected error!");
    }

    /// The cert_store must be empty since the trusted peer certificates are
    /// actually in a different store called verify_cert_store.
    #[test]
    fn should_use_empty_cert_store() {
        let acceptor = default_acceptor();

        let cert_store = acceptor.context().cert_store();
        assert_eq!(cert_store.objects().len(), 0);
    }

    #[test]
    fn should_return_error_if_trusted_client_certs_empty() {
        let empty_trusted_client_certs = vec![];
        let (cert_key_pair, server_cert) = generate_ed25519_cert();

        let error = tls_acceptor(
            &cert_key_pair,
            &server_cert,
            ClientAuthentication::OptionalAuthentication {
                trusted_client_certs: empty_trusted_client_certs,
            },
        )
        .err()
        .unwrap();

        assert_eq!(
            error.description,
            "The trusted client certs must not be empty.".to_string()
        );
    }

    #[test]
    fn should_return_error_if_certificate_does_not_match_private_key() {
        let (_cert_key_pair, server_cert) = generate_ed25519_cert();
        let mismatching_key_pair = ed25519_key_pair();

        let error = tls_acceptor(
            &mismatching_key_pair,
            &server_cert,
            dummy_trusted_client_certs(),
        )
        .err()
        .unwrap();

        assert_eq!(
            error.description,
            "Inconsistent private key and certificate.".to_string()
        );
    }

    #[test]
    fn should_return_error_if_certificate_does_not_match_private_key_type() {
        let (_cert_key_pair, server_cert) = generate_ed25519_cert();
        let mismatching_type_key_pair = prime256v1_key_pair();

        let error = tls_acceptor(
            &mismatching_type_key_pair,
            &server_cert,
            dummy_trusted_client_certs(),
        )
        .err()
        .unwrap();

        assert_eq!(
            error.description,
            "Inconsistent private key and certificate.".to_string()
        );
    }

    #[test]
    #[should_panic(expected = "extra chain certs must not be null")]
    fn should_not_add_extra_chain_certs() {
        let acceptor = default_acceptor();

        let _panic = acceptor.context().extra_chain_certs();
    }

    fn default_acceptor() -> SslAcceptor {
        let (key_pair, server_cert) = generate_ed25519_cert();
        tls_acceptor(&key_pair, &server_cert, dummy_trusted_client_certs()).unwrap()
    }

    fn dummy_trusted_client_certs() -> ClientAuthentication {
        let key_pair = ed25519_key_pair();
        let some_cert = generate_cert(&key_pair, MessageDigest::null());
        ClientAuthentication::OptionalAuthentication {
            trusted_client_certs: vec![some_cert],
        }
    }
}

mod connector {
    use super::*;
    use crate::tls_connector;
    use openssl::pkey::{PKeyRef, Private};
    use openssl::ssl::{ConnectConfiguration, SslVersion};
    use openssl::x509::X509Ref;

    #[test]
    fn should_enforce_server_authentication() {
        let connector = default_connector();

        assert_eq!(connector.verify_mode(), SslVerifyMode::PEER);
        assert_eq!(connector.ssl_context().verify_mode(), SslVerifyMode::PEER);
    }

    #[test]
    fn should_set_client_certificate() {
        let (_, trusted_server_cert) = generate_ed25519_cert();
        let (key_pair, client_cert) = generate_ed25519_cert();

        let connector = tls_connector(&key_pair, &client_cert, &trusted_server_cert).unwrap();

        assert_eq!(
            cert_to_der(connector.certificate()),
            client_cert.to_der().unwrap()
        );
        assert_eq!(
            cert_to_der(connector.ssl_context().certificate()),
            client_cert.to_der().unwrap()
        );
    }

    #[test]
    fn should_set_private_key() {
        let (_, trusted_server_cert) = generate_ed25519_cert();
        let (key_pair, client_cert) = generate_ed25519_cert();

        let connector = tls_connector(&key_pair, &client_cert, &trusted_server_cert).unwrap();

        assert_eq!(
            private_key_to_der(connector.private_key()),
            key_pair.private_key_to_der().unwrap()
        );
        assert_eq!(
            private_key_to_der(connector.ssl_context().private_key()),
            key_pair.private_key_to_der().unwrap()
        );
    }

    /// This documents OpenSSL's behavior. It would also be ok if OpenSSL failed
    /// in this case.
    #[test]
    fn should_allow_certificate_with_p256_key() {
        let (_, trusted_server_cert) = generate_ed25519_cert();
        let key_pair = prime256v1_key_pair();
        let client_cert = generate_cert(&key_pair, MessageDigest::sha256());

        tls_connector(&key_pair, &client_cert, &trusted_server_cert).expect("unexpected error!");
    }

    /// The cert_store must be empty since the trusted server certificate is
    /// actually in a different store called verify_cert_store.
    #[test]
    fn should_use_empty_cert_store() {
        let connector = default_connector();

        let cert_store = connector.ssl_context().cert_store();
        assert_eq!(cert_store.objects().len(), 0);
    }

    #[test]
    fn should_set_ssl_version_to_tls_13() {
        let connector = default_connector();

        let ssl_version = connector.version2().unwrap();
        assert_eq!(ssl_version, SslVersion::TLS1_3);
    }

    #[test]
    fn should_configure_connector_as_client() {
        let connector = default_connector();

        let is_server = connector.is_server();
        assert!(!is_server);
    }

    #[test]
    fn should_return_error_if_certificate_does_not_match_private_key() {
        let (_, trusted_server_cert) = generate_ed25519_cert();
        let (_key_pair, client_cert) = generate_ed25519_cert();
        let mismatching_key_pair = ed25519_key_pair();

        let error = tls_connector(&mismatching_key_pair, &client_cert, &trusted_server_cert)
            .err()
            .unwrap();

        assert_eq!(
            error.description,
            "Inconsistent private key and certificate.".to_string()
        );
    }

    #[test]
    fn should_return_error_if_certificate_does_not_match_private_key_type() {
        let (_, trusted_server_cert) = generate_ed25519_cert();
        let (_key_pair, client_cert) = generate_ed25519_cert();
        let mismatching_type_key_pair = prime256v1_key_pair();

        let error = tls_connector(
            &mismatching_type_key_pair,
            &client_cert,
            &trusted_server_cert,
        )
        .err()
        .unwrap();

        assert_eq!(
            error.description,
            "Inconsistent private key and certificate.".to_string()
        );
    }

    #[test]
    #[should_panic(expected = "extra chain certs must not be null")]
    fn should_not_add_extra_chain_certs() {
        let connector = default_connector();

        let _panic = connector.ssl_context().extra_chain_certs();
    }

    fn cert_to_der(cert: Option<&X509Ref>) -> Vec<u8> {
        cert.unwrap().to_der().unwrap()
    }

    fn private_key_to_der(private_key: Option<&PKeyRef<Private>>) -> Vec<u8> {
        private_key.unwrap().private_key_to_der().unwrap()
    }

    fn default_connector() -> ConnectConfiguration {
        let (_, trusted_server_cert) = generate_ed25519_cert();
        let (key_pair, client_cert) = generate_ed25519_cert();
        tls_connector(&key_pair, &client_cert, &trusted_server_cert).unwrap()
    }
}
