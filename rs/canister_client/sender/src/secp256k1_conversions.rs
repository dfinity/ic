use crate::Secp256k1KeyPair;
use ic_crypto_secrets_containers::SecretVec;
use simple_asn1::{oid, ASN1Block, ASN1Class};

// Parses pem files to secp256k1 structs.
impl Secp256k1KeyPair {
    /// Parses a secp256k1 key pair from PEM.
    pub fn from_pem(pem: &str) -> Result<Self, String> {
        // Note: The SecretVec zeros the internal key after use.  DO NOT REMOVE.
        let mut der =
            ic_crypto_utils_basic_sig::conversions::pem::pem_to_der(pem, "EC PRIVATE KEY")
                .map_err(|err| format!("Failed to convert PEM to DER: {err:?}"))?;

        let der = SecretVec::new_and_zeroize_argument(&mut der);
        Self::from_der(der.expose_secret())
    }

    /// Parses a secp256k1 key pair from DER.
    ///
    /// - The encoding is specified here: https://www.rfc-editor.org/rfc/rfc5915
    /// - The relevant OID is: https://www.alvestrand.no/objectid/1.3.132.0.10.html
    ///
    /// Note: There are DER parsing functions in ic_crypto_internal_basic_sig_der_utils but:
    /// - they are private to the crypt component; there is a ticket to make useful crypto code like this public but it hasn't been actioned yet.
    ///   See issue: CRP-909
    /// - they focus on basic signatures, so ed25519, and don't parse secp256k1 out of the box.  The differences may be minor but are there.
    /// It may hypothetically make sense to organise these code blocks together.  The der parsing is a straightforward application of the
    /// simple_asn1 library so there probably isn't any point in abstracting parts of the code but if the code is stored in a similar place it
    /// will be easier to find.
    pub fn from_der(der: &[u8]) -> Result<Self, String> {
        let asn1_parts = simple_asn1::from_der(der)
            .map_err(|err| format!("Could not parse DER-encoded secret key: {err}"))?;
        let rfc5915_sequence = asn1_parts
            .get(0)
            .ok_or_else(|| format!("Incorrect number of parts: {}", asn1_parts.len()))?;
        if let ASN1Block::Sequence(_len, rfc5915_sequence) = rfc5915_sequence {
            if let [_version, _private_key, parameters, public_key] = &rfc5915_sequence[..] {
                Self::check_der_oid(parameters)?;
                // Downstream code expects the whole DER to be in the secret_key field.
                // If you need just the secret key bytes, use Self::parse_der_secret_key(_private_key);
                let sk = ecdsa_secp256k1::types::SecretKeyBytes(
                    SecretVec::new_and_dont_zeroize_argument(der),
                );
                let pk = Self::parse_der_public_key(public_key)?;
                Ok(Secp256k1KeyPair { sk, pk })
            } else {
                Err("Malformed rfc5915 sequence when reading secp256k1 secret key.".to_string())
            }
        } else {
            Err("Expected rfc5915 block to be a sequence".to_string())
        }
    }

    /// Given the parameters field of an rfc5915 encoded secp256k1 secret key, checks that the OID is correct.
    ///
    /// Note: This function is useful only in the context of the included rfc5915 secp256k1 parser.
    fn check_der_oid(asn1_block: &ASN1Block) -> Result<(), String> {
        let secp256k1_oid = oid!(1, 3, 132, 0, 10);

        if let ASN1Block::Explicit(ASN1Class::ContextSpecific, _usize, _big, parameters) =
            asn1_block
        {
            if let ASN1Block::ObjectIdentifier(_, actual_oid) = &**parameters {
                if actual_oid == secp256k1_oid {
                    Ok(())
                } else {
                    Err(format!(
                        "Wrong OID.  Expected {secp256k1_oid:?} but got {actual_oid:?}"
                    ))
                }
            } else {
                Err("Expected parameters to contain an OID.".to_string())
            }
        } else {
            Err("Unexpected parameters format".to_string())
        }
    }

    /// Parses the secret key of an rfc5915 encoded secp256k1 key.
    ///
    /// Note: This function is useful only in the context of the included rfc5915 secp256k1 parser.
    #[allow(unused)] // If you need just the secret key bytes, use this.
    fn parse_der_secret_key(
        asn1_block: &ASN1Block,
    ) -> Result<ecdsa_secp256k1::types::SecretKeyBytes, String> {
        if let ASN1Block::OctetString(_size, private_key) = asn1_block {
            if private_key.len() == 32 {
                Ok(ecdsa_secp256k1::types::SecretKeyBytes(
                    SecretVec::new_and_dont_zeroize_argument(private_key),
                ))
            } else {
                Err("Unexpected secret key length".to_string())
            }
        } else {
            Err("Unexpected secret key format".to_string())
        }
    }

    /// Parses the public key of an rfc5915 encoded secp256k1 key.
    ///
    /// Note: This function is useful only in the context of the included rfc5915 secp256k1 parser.
    fn parse_der_public_key(
        asn1_block: &ASN1Block,
    ) -> Result<ecdsa_secp256k1::types::PublicKeyBytes, String> {
        match asn1_block {
            ASN1Block::OctetString(_public_key_len, public_key) => {
                Ok(ecdsa_secp256k1::types::PublicKeyBytes(public_key.to_vec()))
            }
            ASN1Block::Explicit(ASN1Class::ContextSpecific, _size, _bigsize, boxed_block) => {
                if let ASN1Block::BitString(_size, _another_size, public_key) = &**boxed_block {
                    Ok(ecdsa_secp256k1::types::PublicKeyBytes(public_key.to_vec()))
                } else {
                    Err("Unexpected public key inner format".to_string())
                }
            }
            _ => Err("Unexpected public key format".to_string()),
        }
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
