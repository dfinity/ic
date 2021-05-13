#![allow(clippy::unwrap_used)]
// SECP256K1_PK_1_DER_HEX was generated via the following commands:
//   openssl ecparam -name secp256k1 -genkey -noout -out private.ec.key
//   openssl ec -in private.ec.key -pubout -outform DER -out ecpubkey.der
//   hexdump -ve '1/1 "%.2x"' ecpubkey.der
const SECP256K1_PK_1_DER_HEX : &str = "3056301006072a8648ce3d020106052b8104000a034200049fed1d3dac50db2191af972b9fa594256b21da7437611adf2ea255b72cd442b71b9d008d602869ab5fbe24cca28ed76f2eb2a1eba7f4dfc848c3507c4ad51f97";

// A DER-encoded Ed25519 public key, to test that parsing non-SECP256K1 keys
// gracefully fails.
const ED25519_PK_DER_BASE64: &str = "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE";

mod keygen {
    use super::*;
    use crate::{new_keypair, public_key_from_der, public_key_to_der};
    #[test]
    fn should_correctly_generate_secp256k1_keys() {
        let (_sk, _pk) = new_keypair().unwrap();
    }

    #[test]
    fn should_correctly_parse_der_encoded_pk() {
        let pk_der = hex::decode(SECP256K1_PK_1_DER_HEX).unwrap();
        let _pk = public_key_from_der(&pk_der).unwrap();
    }

    #[test]
    fn should_correctly_der_encode_pk() {
        let pk_der = hex::decode(SECP256K1_PK_1_DER_HEX).unwrap();
        let pk = public_key_from_der(&pk_der).unwrap();
        let der_encoded = public_key_to_der(&pk).unwrap();
        assert_eq!(pk_der, der_encoded);
    }

    #[test]
    fn should_fail_parsing_a_corrupted_der_encoded_pk() {
        let mut pk_der = hex::decode(SECP256K1_PK_1_DER_HEX).unwrap();
        pk_der[0] += 1;
        let pk_result = public_key_from_der(&pk_der);
        assert!(pk_result.is_err());
        assert!(pk_result.unwrap_err().is_malformed_public_key());
    }

    #[test]
    fn should_fail_parsing_non_secp256k1_key_without_panic() {
        let pk_der = base64::decode(ED25519_PK_DER_BASE64).unwrap();
        let pk_result = public_key_from_der(&pk_der);
        assert!(pk_result.is_err());
        assert!(pk_result.unwrap_err().is_malformed_public_key());
    }
}

mod sign {
    use crate::{new_keypair, sign, types, verify};

    #[test]
    fn should_correctly_sign_and_verify() {
        let (sk, pk) = new_keypair().unwrap();

        let msg = b"some message to sign";
        let signature = sign(msg, &sk).unwrap();
        assert_eq!(signature.0.len(), types::SignatureBytes::SIZE);
        verify(&signature, msg, &pk).unwrap();
    }

    // An SECP256K1 signature consists of two 32-byte randomized numbers,
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
    use crate::types::{PublicKeyBytes, SignatureBytes};
    use crate::{new_keypair, sign, verify};
    use ic_crypto_internal_test_vectors::ecdsa_secp256k1;
    use openssl::bn::{BigNum, BigNumContext};
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::sha::sha256;
    use std::convert::TryFrom;
    use strum::IntoEnumIterator;

    fn pk_bytes_from_x_y(x: Vec<u8>, y: Vec<u8>) -> PublicKeyBytes {
        let group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
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
        for test_vec in ecdsa_secp256k1::Secp256k1Sha256SigVerTestVector::iter() {
            let v = ecdsa_secp256k1::crypto_lib_sig_ver_testvec(test_vec);
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
    fn should_fail_to_verify_wrong_signature() {
        let (sk, pk) = new_keypair().unwrap();
        let msg = b"some message to sign";
        let mut signature = sign(msg, &sk).unwrap();
        // Zero the last byte of the signature.
        assert_eq!(signature.0.len(), SignatureBytes::SIZE);
        signature.0[SignatureBytes::SIZE - 1] = 0;
        let result = verify(&signature, msg, &pk);
        assert!(result.is_err());
        assert!(result.unwrap_err().is_signature_verification_error());
    }

    #[test]
    fn should_fail_to_verify_wrong_message() {
        let (sk, pk) = new_keypair().unwrap();
        let msg = b"some message to sign";
        let wrong_msg = b"a different message";
        let signature = sign(msg, &sk).unwrap();
        let result = verify(&signature, wrong_msg, &pk);
        assert!(result.is_err());
        assert!(result.unwrap_err().is_signature_verification_error());
    }

    #[test]
    fn should_fail_to_verify_wrong_key() {
        let (sk, _) = new_keypair().unwrap();
        let (_, another_pk) = new_keypair().unwrap();
        let msg = b"some message to sign";
        let signature = sign(msg, &sk).unwrap();
        let result = verify(&signature, msg, &another_pk);
        assert!(result.is_err());
        assert!(result.unwrap_err().is_signature_verification_error());
    }
}
