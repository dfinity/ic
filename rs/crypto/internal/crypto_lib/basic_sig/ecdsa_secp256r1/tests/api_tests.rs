// ECDSA_P256_PK_1_DER_HEX was generated via the following commands:
//   openssl ecparam -name prime256v1 -genkey -noout -out private.ec.key
//   openssl ec -in private.ec.key -pubout -outform DER -out ecpubkey.der
//   hexdump -ve '1/1 "%.2x"' ecpubkey.der
const ECDSA_P256_PK_1_DER_HEX: &str = "3059301306072a8648ce3d020106082a8648ce3d03010703420004485c32997ce7c6d38ca82c821185c689d424fac7c9695bb97786c4248aab6428949bcd163e2bcf3eeeac4f200b38fbd053f82c4e1776dc9c6dc8db9b7c35e06f";

const SIG_OF_MSG_2_WITH_ECDSA_P256_PK_1_DER_HEX: &str = "3045022100c69c75c6d6c449ea936094476e8bfcad90d831a6437a87117615add6d6a5168802201e2e4535976794286fa264eb81d7b14b3f168ab7f62ad5c0b9d6ebfc64eb0c8c";

// A DER-encoded Ed25519 public key, to test that parsing non-ECDSA keys
// gracefully fails.
const ED25519_PK_DER_BASE64: &str = "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE";

mod keygen {
    use assert_matches::assert_matches;
    use ic_crypto_internal_basic_sig_ecdsa_secp256r1::*;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_types::crypto::{AlgorithmId, CryptoError};

    #[test]
    fn should_correctly_generate_ecdsa_keys() {
        let (_sk, _pk) = test_utils::new_keypair(&mut reproducible_rng()).unwrap();
    }

    #[test]
    fn should_correctly_parse_der_encoded_pk() {
        let pk_der = hex::decode(crate::ECDSA_P256_PK_1_DER_HEX).unwrap();
        let _pk = public_key_from_der(&pk_der).unwrap();
    }

    #[test]
    fn should_fail_parsing_a_corrupted_der_encoded_pk() {
        let mut pk_der = hex::decode(crate::ECDSA_P256_PK_1_DER_HEX).unwrap();
        pk_der[0] += 1;
        let pk_result = public_key_from_der(&pk_der);
        assert!(pk_result.is_err());
        assert!(pk_result.unwrap_err().is_malformed_public_key());
    }

    #[test]
    fn should_fail_parsing_non_ecdsa_key_without_panic() {
        let pk_der = base64::decode(crate::ED25519_PK_DER_BASE64).unwrap();
        let pk_result = public_key_from_der(&pk_der);
        assert!(pk_result.is_err());
        assert!(pk_result.unwrap_err().is_malformed_public_key());
    }

    // RFC 5480 allows compressed points but we insist on canonical representations.
    // Test compressed key was generated with:
    //   $ openssl ecparam -name prime256v1 -genkey -noout -out r1.pem
    //   $ openssl ec -in r1.pem -pubout -outform DER -out r1-comp.der \
    //     -conv_form compressed
    #[test]
    fn rejects_compressed_points() {
        const COMPRESSED: &str = "3039301306072a8648ce3d020106082a8648ce3d030107032200029b18562f6d49c62626023683c31923b5b99825a05761cad69a856ee174bd879b";

        let pk_der = hex::decode(COMPRESSED).unwrap();
        let pk_result = public_key_from_der(&pk_der);
        assert_matches!(pk_result, Err(CryptoError::MalformedPublicKey{algorithm, key_bytes: _, internal_error})
             if algorithm == AlgorithmId::EcdsaP256
             && internal_error.contains(
                 "non-canonical encoding"
             )
        );
    }
}

mod sign {
    use ic_crypto_internal_basic_sig_ecdsa_secp256r1::{types, *};
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;

    #[test]
    fn should_correctly_sign_and_verify() {
        let (sk, pk) = test_utils::new_keypair(&mut reproducible_rng()).unwrap();

        let msg = b"some message to sign";
        let signature = sign(msg, &sk).unwrap();
        assert_eq!(signature.0.len(), types::SignatureBytes::SIZE);
        verify(&signature, msg, &pk).unwrap();
    }

    #[test]
    fn should_correctly_parse_der_encoded_signature() {
        let sig_der = hex::decode(crate::SIG_OF_MSG_2_WITH_ECDSA_P256_PK_1_DER_HEX).unwrap();
        let _sig = signature_from_der(&sig_der).unwrap();
    }

    #[test]
    fn should_fail_parsing_a_corrupted_der_encoded_signature() {
        let mut sig_der = hex::decode(crate::SIG_OF_MSG_2_WITH_ECDSA_P256_PK_1_DER_HEX).unwrap();
        sig_der[0] += 1;
        let sig_result = signature_from_der(&sig_der);
        assert!(sig_result.is_err());
        assert!(sig_result.unwrap_err().is_malformed_signature());
    }

    // An ECDSA signature consists of two 32-byte randomized numbers,
    // which occasionally are shorter than 32 bytes.  If a number
    // indeed is shorter than 32 bytes, then it should padded
    // with leading zeros, so that the entire signature is exactly
    // 64 bytes long, and that the big-endian encoding yields the
    // correct value.  As we cannot deterministically enforce a
    // generation of a signature with a "shorter" number, in the
    // following test we generate a set of random signatures,
    // so that with high probability (about 0.9) at least one of
    // the signatures contains a shorter number.
    // (the number of signatures = 300 has been picked empirically)
    #[test]
    fn should_correctly_generate_and_verify_shorter_signatures() {
        let (sk, pk) = test_utils::new_keypair(&mut reproducible_rng()).unwrap();

        let msg = b"some message to sign";
        for _i in 1..300 {
            let signature = sign(msg, &sk).unwrap();
            assert_eq!(signature.0.len(), types::SignatureBytes::SIZE);
            verify(&signature, msg, &pk).unwrap();
        }
    }
}

mod verify {
    use assert_matches::assert_matches;
    use ic_crypto_internal_basic_sig_ecdsa_secp256r1::{types, *};
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_types::crypto::{AlgorithmId, CryptoError};

    #[test]
    fn should_reject_truncated_ecdsa_pubkey() {
        let (sk, pk) = test_utils::new_keypair(&mut reproducible_rng()).unwrap();

        let msg = vec![0x42; 32];
        let signature = sign(&msg, &sk).unwrap();
        assert!(verify(&signature, &msg, &pk).is_ok());

        let invalid_pk = types::PublicKeyBytes(pk.0[0..pk.0.len() - 1].to_vec());
        let result = verify(&signature, &msg, &invalid_pk);

        assert_matches!(result, Err(CryptoError::MalformedPublicKey{algorithm, key_bytes, internal_error:_})
             if algorithm == AlgorithmId::EcdsaP256
             && key_bytes == Some(invalid_pk.0)
        );
    }

    #[test]
    fn should_reject_modified_ecdsa_pubkey() {
        let (sk, pk) = test_utils::new_keypair(&mut reproducible_rng()).unwrap();

        let msg = vec![0x42; 32];
        let signature = sign(&msg, &sk).unwrap();
        assert!(verify(&signature, &msg, &pk).is_ok());

        /*
        We are encoding using uncompressed coordinates so the format is (h,x,y)
        where h is a 1-byte header. The x that is valid wrt a y is unique,
        so there is no possibility that this does not fail when we modify
        the final byte of x
         */
        assert_eq!(pk.0.len(), 1 + 2 * types::FIELD_SIZE);
        let mut modified_key = pk.0;
        modified_key[types::FIELD_SIZE] ^= 0x01;
        let invalid_pk = types::PublicKeyBytes(modified_key);

        let result = verify(&signature, &msg, &invalid_pk);
        assert_matches!(result, Err(CryptoError::MalformedPublicKey{algorithm, key_bytes, internal_error: _})
             if algorithm == AlgorithmId::EcdsaP256
             && key_bytes == Some(invalid_pk.0)
        );
    }

    #[test]
    fn should_have_correct_error_for_invalid_sig() {
        let (sk, pk) = test_utils::new_keypair(&mut reproducible_rng()).unwrap();

        let msg = vec![0x42; 32];
        let signature = sign(&msg, &sk).unwrap();

        let mut invalid_signature = signature;
        invalid_signature.0[2] ^= 1;

        let result = verify(&invalid_signature, &msg, &pk);
        assert_matches!(result, Err(CryptoError::SignatureVerification{algorithm, public_key_bytes, sig_bytes, internal_error: _})
                        if algorithm == AlgorithmId::EcdsaP256 &&
                        public_key_bytes == pk.0 &&
                        sig_bytes == invalid_signature.0);
    }
}

#[cfg(test)]
mod sig_conv_tests {
    use ic_crypto_internal_basic_sig_ecdsa_secp256r1::types::SignatureBytes;
    use std::convert::TryFrom;

    #[test]
    fn should_convert_vector_to_signature_bytes() {
        let bytes = vec![0; SignatureBytes::SIZE];
        let _sig_bytes = SignatureBytes::try_from(bytes).expect("conversion failed");
    }

    #[test]
    fn should_fail_conversion_to_signature_bytes_if_vector_too_long() {
        let bytes = vec![0; SignatureBytes::SIZE + 1];
        let result = SignatureBytes::try_from(bytes);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Unexpected success.")
                .is_malformed_signature()
        );
    }

    #[test]
    fn should_fail_conversion_to_signature_bytes_if_vector_too_short() {
        let bytes = vec![0; SignatureBytes::SIZE - 1];
        let result = SignatureBytes::try_from(bytes);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Unexpected success.")
                .is_malformed_signature()
        );
    }
}
