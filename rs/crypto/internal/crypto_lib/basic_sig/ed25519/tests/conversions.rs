mod public_key_bytes {
    use assert_matches::assert_matches;
    use ic_crypto_internal_basic_sig_ed25519::types::PublicKeyBytes;
    use ic_types::crypto::CryptoError;

    #[test]
    fn should_convert_value() {
        let valid_value = vec![0; PublicKeyBytes::SIZE];
        let result = PublicKeyBytes::try_from(valid_value);
        assert_eq!(result, Ok(PublicKeyBytes([0; PublicKeyBytes::SIZE])));
    }

    #[test]
    fn should_error_when_input_too_short() {
        let invalid_value = vec![0; PublicKeyBytes::SIZE - 1];
        let result = PublicKeyBytes::try_from(invalid_value);
        assert_matches!(result, Err(CryptoError::MalformedPublicKey { .. }))
    }

    #[test]
    fn should_error_when_input_too_big() {
        let invalid_value = vec![0; PublicKeyBytes::SIZE + 1];
        let result = PublicKeyBytes::try_from(invalid_value);
        assert_matches!(result, Err(CryptoError::MalformedPublicKey { .. }))
    }
}

mod signature_bytes {
    use assert_matches::assert_matches;
    use ic_crypto_internal_basic_sig_ed25519::types::SignatureBytes;
    use ic_types::crypto::CryptoError;

    #[test]
    fn should_convert_value() {
        let valid_value = vec![0; SignatureBytes::SIZE];
        let result = SignatureBytes::try_from(valid_value);
        assert_eq!(result, Ok(SignatureBytes([0; SignatureBytes::SIZE])));
    }

    #[test]
    fn should_error_when_input_too_short() {
        let invalid_value = vec![0; SignatureBytes::SIZE - 1];
        let result = SignatureBytes::try_from(invalid_value);
        assert_matches!(result, Err(CryptoError::MalformedSignature { .. }));
    }

    #[test]
    fn should_error_when_input_too_big() {
        let invalid_value = vec![0; SignatureBytes::SIZE + 1];
        let result = SignatureBytes::try_from(invalid_value);
        assert_matches!(result, Err(CryptoError::MalformedSignature { .. }));
    }
}
