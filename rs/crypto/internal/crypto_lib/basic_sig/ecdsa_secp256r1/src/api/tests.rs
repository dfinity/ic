#![allow(clippy::unwrap_used)]
// ECDSA_P256_PK_1_DER_HEX was generated via the following commands:
//   openssl ecparam -name prime256v1 -genkey -noout -out private.ec.key
//   openssl ec -in private.ec.key -pubout -outform DER -out ecpubkey.der
//   hexdump -ve '1/1 "%.2x"' ecpubkey.der
const ECDSA_P256_PK_1_DER_HEX : &str = "3059301306072a8648ce3d020106082a8648ce3d03010703420004485c32997ce7c6d38ca82c821185c689d424fac7c9695bb97786c4248aab6428949bcd163e2bcf3eeeac4f200b38fbd053f82c4e1776dc9c6dc8db9b7c35e06f";

const SIG_OF_MSG_2_WITH_ECDSA_P256_PK_1_DER_HEX : &str = "3045022100c69c75c6d6c449ea936094476e8bfcad90d831a6437a87117615add6d6a5168802201e2e4535976794286fa264eb81d7b14b3f168ab7f62ad5c0b9d6ebfc64eb0c8c";

// A DER-encoded Ed25519 public key, to test that parsing non-ECDSA keys
// gracefully fails.
const ED25519_PK_DER_BASE64: &str = "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE";

mod keygen {
    use super::*;
    use crate::{new_keypair, public_key_from_der};
    use ic_types::crypto::{AlgorithmId, CryptoError};

    #[test]
    fn should_correctly_generate_ecdsa_keys() {
        let (_sk, _pk) = new_keypair().unwrap();
    }

    #[test]
    fn should_correctly_parse_der_encoded_pk() {
        let pk_der = hex::decode(ECDSA_P256_PK_1_DER_HEX).unwrap();
        let _pk = public_key_from_der(&pk_der).unwrap();
    }

    #[test]
    fn should_fail_parsing_a_corrupted_der_encoded_pk() {
        let mut pk_der = hex::decode(ECDSA_P256_PK_1_DER_HEX).unwrap();
        pk_der[0] += 1;
        let pk_result = public_key_from_der(&pk_der);
        assert!(pk_result.is_err());
        assert!(pk_result.unwrap_err().is_malformed_public_key());
    }

    #[test]
    fn should_fail_parsing_non_ecdsa_key_without_panic() {
        let pk_der = base64::decode(ED25519_PK_DER_BASE64).unwrap();
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
        const COMPRESSED : &str = "3039301306072a8648ce3d020106082a8648ce3d030107032200029b18562f6d49c62626023683c31923b5b99825a05761cad69a856ee174bd879b";

        let pk_der = hex::decode(COMPRESSED).unwrap();
        let pk_result = public_key_from_der(&pk_der);
        assert!(
            matches!(pk_result, Err(CryptoError::MalformedPublicKey{algorithm, key_bytes: _, internal_error})
                     if algorithm == AlgorithmId::EcdsaP256
                     && internal_error.contains(
                         "non-canonical encoding"
                     )
            )
        );
    }
}

mod sign {
    use crate::api::tests::SIG_OF_MSG_2_WITH_ECDSA_P256_PK_1_DER_HEX;
    use crate::{new_keypair, sign, signature_from_der, types, verify};

    #[test]
    fn should_correctly_sign_and_verify() {
        let (sk, pk) = new_keypair().unwrap();

        let msg = b"some message to sign";
        let signature = sign(msg, &sk).unwrap();
        assert_eq!(signature.0.len(), types::SignatureBytes::SIZE);
        verify(&signature, msg, &pk).unwrap();
    }

    #[test]
    fn should_correctly_parse_der_encoded_signature() {
        let sig_der = hex::decode(SIG_OF_MSG_2_WITH_ECDSA_P256_PK_1_DER_HEX).unwrap();
        let _sig = signature_from_der(&sig_der).unwrap();
    }

    #[test]
    fn should_fail_parsing_a_corrupted_der_encoded_signature() {
        let mut sig_der = hex::decode(SIG_OF_MSG_2_WITH_ECDSA_P256_PK_1_DER_HEX).unwrap();
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
        let (sk, pk) = new_keypair().unwrap();

        let msg = b"some message to sign";
        for _i in 1..300 {
            let signature = sign(msg, &sk).unwrap();
            assert_eq!(signature.0.len(), types::SignatureBytes::SIZE);
            verify(&signature, msg, &pk).unwrap();
        }
    }
}

mod verify {
    use ic_crypto_internal_test_vectors::ecdsa_p256;

    use crate::api::{der_encoding_from_xy_coordinates, public_key_from_der};
    use crate::types::{PublicKeyBytes, SignatureBytes};
    use crate::verify;
    use ic_types::crypto::{AlgorithmId, CryptoError};
    use openssl::sha::sha256;
    use std::convert::TryFrom;
    use strum::IntoEnumIterator;

    fn pk_bytes_from_x_y(x: Vec<u8>, y: Vec<u8>) -> PublicKeyBytes {
        let der = der_encoding_from_xy_coordinates(&x, &y).unwrap();
        public_key_from_der(&der).unwrap()
    }

    fn sig_bytes_from_r_s(r: Vec<u8>, s: Vec<u8>) -> SignatureBytes {
        SignatureBytes::try_from([r, s].concat()).unwrap()
    }

    #[test]
    fn should_correctly_verify_test_vectors() {
        for test_vec in ecdsa_p256::EcdsaP256Sha256SigVerTestVector::iter() {
            let v = ecdsa_p256::crypto_lib_sig_ver_testvec(test_vec);
            let msg_hash = sha256(&v.msg);
            let pk = pk_bytes_from_x_y(v.q_x, v.q_y);
            let sig = sig_bytes_from_r_s(v.r, v.s);

            let verify_result = verify(&sig, &msg_hash, &pk);
            assert_eq!(
                verify_result.is_ok(),
                v.is_valid,
                "Unexpected verification result for test vector {:?}",
                test_vec
            );
            if verify_result.is_err() {
                assert!(verify_result.unwrap_err().is_signature_verification_error());
            }
        }
    }

    #[test]
    fn should_reject_truncated_ecdsa_pubkey() {
        let (sk, pk) = crate::new_keypair().unwrap();

        let msg = b"abc";
        let signature = crate::sign(msg, &sk).unwrap();
        assert!(crate::verify(&signature, msg, &pk).is_ok());

        let invalid_pk = PublicKeyBytes(pk.0[0..pk.0.len() - 1].to_vec());
        let result = verify(&signature, msg, &invalid_pk);

        assert!(
            matches!(result, Err(CryptoError::MalformedPublicKey{algorithm, key_bytes, internal_error})
                     if algorithm == AlgorithmId::EcdsaP256
                     && key_bytes == Some(invalid_pk.0)
                     && internal_error.contains(
                         ":elliptic curve routines:ec_GFp_simple_oct2point:invalid encoding:"
                     )
            )
        );
    }

    #[test]
    fn should_reject_modified_ecdsa_pubkey() {
        let (sk, pk) = crate::new_keypair().unwrap();

        let msg = b"abc";
        let signature = crate::sign(msg, &sk).unwrap();
        assert!(crate::verify(&signature, msg, &pk).is_ok());

        /*
        We are encoding using uncompressed coordinates so the format is (h,x,y)
        where h is a 1-byte header. The x that is valid wrt a y is unique,
        so there is no possibility that this does not fail when we modify
        the final byte of x
         */
        assert_eq!(pk.0.len(), 1 + 2 * crate::types::FIELD_SIZE);
        let mut modified_key = pk.0;
        modified_key[crate::types::FIELD_SIZE] ^= 0x01;
        let invalid_pk = PublicKeyBytes(modified_key);

        let result = verify(&signature, msg, &invalid_pk);
        assert!(
            matches!(result, Err(CryptoError::MalformedPublicKey{algorithm, key_bytes, internal_error})
                     if algorithm == AlgorithmId::EcdsaP256
                     && key_bytes == Some(invalid_pk.0)
                     && internal_error.contains(
                         ":elliptic curve routines:EC_POINT_set_affine_coordinates:point is not on curve:"
                     )
            )
        );
    }
}
