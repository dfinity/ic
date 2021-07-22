#![allow(clippy::unwrap_used)]
use ic_crypto_tls::{generate_tls_keys, TlsPemParsingError};
const NOT_AFTER: &str = "20701231235959Z";

mod tls_private_key {
    use super::*;
    use ic_crypto_tls::TlsPrivateKey;

    #[test]
    fn should_create_private_key_from_valid_pem() {
        let (_cert, private_key) = generate_tls_keys("some common name", NOT_AFTER);
        let private_key_pem = private_key.to_pem().unwrap();

        let private_key = TlsPrivateKey::new_from_pem(private_key_pem.clone()).unwrap();

        assert_eq!(private_key_pem, private_key.to_pem().unwrap());
    }

    #[test]
    fn should_return_error_if_pem_empty() {
        let empty_pem = Vec::new();

        let error = TlsPrivateKey::new_from_pem(empty_pem).unwrap_err();

        assert!(matches!(error, TlsPemParsingError { internal_error }
            if internal_error.contains("Error parsing PEM via OpenSSL")
        ));
    }

    #[test]
    fn should_return_error_if_pem_malformed() {
        let malformed_pem = vec![42u8; 5];

        let error = TlsPrivateKey::new_from_pem(malformed_pem).unwrap_err();

        assert!(matches!(error, TlsPemParsingError { internal_error }
            if internal_error.contains("Error parsing PEM via OpenSSL")
        ));
    }

    #[test]
    fn should_redact_tls_private_key_debug() {
        let (_cert, private_key) = generate_tls_keys("some common name", NOT_AFTER);
        assert_eq!(format!("{:?}", private_key), "REDACTED");
    }
}
