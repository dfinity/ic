#![allow(clippy::unwrap_used)]
// ECDSA_P256_PK_1_DER_HEX was generated via the following commands:
//   openssl ecparam -name prime256v1 -genkey -noout -out private.ec.key
//   openssl ec -in private.ec.key -pubout -outform DER -out ecpubkey.der
//   hexdump -ve '1/1 "%.2x"' ecpubkey.der
const ECDSA_P256_PK_1_DER_HEX : &str = "3059301306072a8648ce3d020106082a8648ce3d03010703420004485c32997ce7c6d38ca82c821185c689d424fac7c9695bb97786c4248aab6428949bcd163e2bcf3eeeac4f200b38fbd053f82c4e1776dc9c6dc8db9b7c35e06f";

// A COSE-encoded ECDSA-P256 public key, with a signature over an example
// message.
const ECDSA_P256_PK_2_COSE_HEX : &str = "a501020326200121582051556cab67bc37cc806d4b0666b2553a35f8a96e1ea0025942a1f140b6e42d4e2258200b203014c786088b3525fd5a41ce16cec81de536186efdbc8f9ab9bf9df2f366";
const MSG_2_HEX : &str = "2f1b671a93f444b8ec77e0211f9624c9c2612182b864f0d4ac9d335f5b4fe50201000000537f91225ffff1e2912a0f8ca7a0ef61df01ae3d8898fca283036239259bab4f82";
const SIG_OF_MSG_2_WITH_ECDSA_P256_PK_1_DER_HEX : &str = "3045022100c69c75c6d6c449ea936094476e8bfcad90d831a6437a87117615add6d6a5168802201e2e4535976794286fa264eb81d7b14b3f168ab7f62ad5c0b9d6ebfc64eb0c8c";

// A DER-encoded Ed25519 public key, to test that parsing non-ECDSA keys
// gracefully fails.
const ED25519_PK_DER_BASE64: &str = "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE";

mod keygen {
    use super::*;
    use crate::{new_keypair, public_key_from_cose, public_key_from_der};
    use ic_crypto_internal_test_vectors::test_data;

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
    fn should_correctly_parse_cose_encoded_pk() {
        let pk_cose = hex::decode(ECDSA_P256_PK_2_COSE_HEX).unwrap();
        let _pk = public_key_from_cose(&pk_cose).unwrap();
    }

    #[test]
    fn should_correctly_parse_webauthn_cose_encoded_pk() {
        let pk_cose = hex::decode(test_data::WEBAUTHN_ECDSA_P256_PK_COSE_HEX).unwrap();
        let _pk = public_key_from_cose(&pk_cose).unwrap();
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
    fn should_fail_parsing_a_corrupted_cose_encoded_pk() {
        let mut pk_cose = hex::decode(ECDSA_P256_PK_2_COSE_HEX).unwrap();
        pk_cose[0] += 1;
        let pk_result = public_key_from_cose(&pk_cose);
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
}

mod sign {
    use super::*;
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
    use super::*;
    use ic_crypto_internal_test_vectors::ecdsa_p256;

    use crate::types::{PublicKeyBytes, SignatureBytes};
    use crate::{public_key_from_cose, signature_from_der, verify};
    use ic_crypto_internal_test_vectors::test_data;
    use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult};
    use openssl::bn::{BigNum, BigNumContext};
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::sha::sha256;
    use std::convert::TryFrom;
    use strum::IntoEnumIterator;

    fn pk_bytes_from_x_y(x: Vec<u8>, y: Vec<u8>) -> PublicKeyBytes {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let x = BigNum::from_slice(&x).unwrap();
        let y = BigNum::from_slice(&y).unwrap();
        let ec_key = EcKey::from_public_key_affine_coordinates(&group, &x, &y).unwrap();

        let mut ctx = BigNumContext::new().unwrap();
        let pk_bytes = ec_key
            .public_key()
            .to_bytes(
                &group,
                openssl::ec::PointConversionForm::UNCOMPRESSED,
                &mut ctx,
            )
            .unwrap();
        PublicKeyBytes(pk_bytes)
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
    fn should_correctly_verify_der_signature() {
        let result = get_der_cose_verification_result(
            SIG_OF_MSG_2_WITH_ECDSA_P256_PK_1_DER_HEX,
            ECDSA_P256_PK_2_COSE_HEX,
            MSG_2_HEX,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn should_fail_to_verify_on_wrong_message() {
        let mut wrong_msg_hex = String::from(MSG_2_HEX);
        wrong_msg_hex.push_str("ab");
        let result = get_der_cose_verification_result(
            SIG_OF_MSG_2_WITH_ECDSA_P256_PK_1_DER_HEX,
            ECDSA_P256_PK_2_COSE_HEX,
            &wrong_msg_hex,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().is_signature_verification_error());
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

    #[test]
    fn should_fail_to_verify_corrupted_signature() {
        let mut corrupted_der_sig_hex = String::from(SIG_OF_MSG_2_WITH_ECDSA_P256_PK_1_DER_HEX);
        corrupted_der_sig_hex.truncate(corrupted_der_sig_hex.len() - 2);
        corrupted_der_sig_hex.push_str("aa");
        assert!(
            corrupted_der_sig_hex != SIG_OF_MSG_2_WITH_ECDSA_P256_PK_1_DER_HEX,
            "Signature should be different"
        );
        let result = get_der_cose_verification_result(
            &corrupted_der_sig_hex,
            ECDSA_P256_PK_2_COSE_HEX,
            MSG_2_HEX,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().is_signature_verification_error());
    }

    #[test]
    fn should_correctly_verify_webauthn_signatures() {
        let result = get_der_cose_verification_result(
            test_data::ECDSA_P256_SIG_1_DER_HEX,
            test_data::ECDSA_P256_PK_1_COSE_HEX,
            test_data::WEBAUTHN_MSG_1_HEX,
        );
        assert!(result.is_ok());

        let result = get_der_cose_verification_result(
            test_data::ECDSA_P256_SIG_2_DER_HEX,
            test_data::ECDSA_P256_PK_2_COSE_HEX,
            test_data::WEBAUTHN_MSG_2_HEX,
        );
        assert!(result.is_ok());
    }

    // Given a DER-encoded signature, a COSE-encoded ECDSA-P256 public key,
    // and a message, computes and returns a signature verification result.
    fn get_der_cose_verification_result(
        sig_der_hex: &str,
        pk_cose_hex: &str,
        msg_hex: &str,
    ) -> CryptoResult<()> {
        let sig_der = hex::decode(sig_der_hex).unwrap();
        let sig = signature_from_der(&sig_der).unwrap();
        let pk_cose = hex::decode(pk_cose_hex).unwrap();
        let pk = public_key_from_cose(&pk_cose).unwrap();
        let msg = hex::decode(msg_hex).unwrap();
        let msg_hash = sha256(&msg);
        println!("new: msg: {:?}, msg_hash {:?}", msg, msg_hash);
        verify(&sig, &msg_hash, &pk)
    }
}
