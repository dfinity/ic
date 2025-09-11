use crate::Secp256k1KeyPair;

// Parses pem files to secp256k1 structs.
impl Secp256k1KeyPair {
    /// Parses a secp256k1 key pair from PEM.
    pub fn from_pem(pem: &str) -> Result<Self, String> {
        let sk =
            ic_secp256k1::PrivateKey::deserialize_rfc5915_pem(pem).map_err(|e| format!("{e:?}"))?;

        let pk = sk.public_key();

        Ok(Self { sk, pk })
    }

    /// Parses a secp256k1 key pair from DER in RFC 5915 format
    pub fn from_der(der: &[u8]) -> Result<Self, String> {
        let sk =
            ic_secp256k1::PrivateKey::deserialize_rfc5915_der(der).map_err(|e| format!("{e:?}"))?;

        let pk = sk.public_key();

        Ok(Secp256k1KeyPair { sk, pk })
    }
}

#[cfg(test)]
mod tests {
    use super::Secp256k1KeyPair;
    use crate::tests::vectors;

    #[test]
    fn should_parse_key_from_pem() {
        Secp256k1KeyPair::from_pem(vectors::SAMPLE_SECP256K1_PEM)
            .expect("secp256k1 failed to read key");
    }
    #[test]
    fn should_fail_to_read_ed25519_key() {
        Secp256k1KeyPair::from_pem(vectors::SAMPLE_ED25519_PEM)
            .map(|_| ())
            .expect_err("secp256k1 parser should have failed to read an ed25519 key.");
    }
    #[test]
    fn should_fail_to_read_key_with_wrong_section_title() {
        Secp256k1KeyPair::from_pem(vectors::SECP256K1_WITH_INVALID_SECTION_NAME)
            .map(|_| ())
            .expect_err("secp256k1 parser should require 'EC PRIVATE KEY'.");
    }
    #[test]
    fn should_fail_to_read_key_with_invalid_base64() {
        Secp256k1KeyPair::from_pem(vectors::SAMPLE_MALFORMED_BASE64)
            .map(|_| ())
            .expect_err("Pem should require valid base 64.");
    }
    #[test]
    fn should_fail_to_read_key_for_wrong_curve() {
        Secp256k1KeyPair::from_pem(vectors::SAMPLE_WITH_ED25519_PAYLOAD)
            .map(|_| ())
            .expect_err("The base64 payload should be a secp256k1 key");
    }
}
