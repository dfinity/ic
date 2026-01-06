use ic_crypto_internal_basic_sig_ecdsa_secp256k1::types;
use ic_crypto_secrets_containers::SecretVec;
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult};

// SECP256K1_PK_1_DER_HEX was generated via the following commands:
//   openssl ecparam -name secp256k1 -genkey -noout -out private.ec.key
//   openssl ec -in private.ec.key -pubout -outform DER -out ecpubkey.der
//   hexdump -ve '1/1 "%.2x"' ecpubkey.der
const SECP256K1_PK_1_DER_HEX: &str = "3056301006072a8648ce3d020106052b8104000a034200049fed1d3dac50db2191af972b9fa594256b21da7437611adf2ea255b72cd442b71b9d008d602869ab5fbe24cca28ed76f2eb2a1eba7f4dfc848c3507c4ad51f97";

// A DER-encoded Ed25519 public key, to test that parsing non-SECP256K1 keys
// gracefully fails.
const ED25519_PK_DER_BASE64: &str = "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE";

/// Create a secp256k1 secret key from raw bytes
///
/// # Arguments
/// * `sk_raw_bytes` is the big-endian encoding of unsigned integer
/// * `pk` is the public key associated with this secret key
/// # Errors
/// * `MalformedPublicKey` if the public key could not be parsed
/// * `MalformedSecretKey` if the secret key does not correspond with the public
///   key
fn secret_key_from_components(
    sk_raw_bytes: &[u8],
    pk: &types::PublicKeyBytes,
) -> CryptoResult<types::SecretKeyBytes> {
    let sk = ic_secp256k1::PrivateKey::deserialize_sec1(sk_raw_bytes).map_err(|e| {
        CryptoError::MalformedSecretKey {
            algorithm: AlgorithmId::EcdsaSecp256k1,
            internal_error: format!("{e:?}"),
        }
    })?;

    if pk.0 != sk.public_key().serialize_sec1(false) {
        return Err(CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::EcdsaSecp256k1,
            key_bytes: Some(pk.0.to_vec()),
            internal_error: "Public key does not match secret key".to_string(),
        });
    }

    let mut sk_rfc5915 = sk.serialize_rfc5915_der();

    Ok(types::SecretKeyBytes(SecretVec::new_and_zeroize_argument(
        &mut sk_rfc5915,
    )))
}

/// Create a new secp256k1 keypair.
fn new_keypair(
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> (types::SecretKeyBytes, types::PublicKeyBytes) {
    let (sk, pk) = {
        let sk = ic_secp256k1::PrivateKey::generate_using_rng(rng);

        let serialized_sk = sk.serialize_sec1();
        let serialized_pk = sk.public_key().serialize_sec1(false);
        (serialized_sk, serialized_pk)
    };

    let pk_bytes = types::PublicKeyBytes::from(pk.to_vec());
    let sk_bytes = secret_key_from_components(&sk, &pk_bytes).unwrap();

    (sk_bytes, pk_bytes)
}

mod keygen {
    use ic_crypto_internal_basic_sig_ecdsa_secp256k1::*;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;

    #[test]
    fn should_correctly_generate_secp256k1_keys() {
        let (_sk, _pk) = crate::new_keypair(&mut reproducible_rng());
    }

    #[test]
    fn should_correctly_parse_der_encoded_pk() {
        let pk_der = hex::decode(crate::SECP256K1_PK_1_DER_HEX).unwrap();
        let _pk = public_key_from_der(&pk_der).unwrap();
    }

    #[test]
    fn should_correctly_der_encode_pk() {
        let pk_der = hex::decode(crate::SECP256K1_PK_1_DER_HEX).unwrap();
        let pk = public_key_from_der(&pk_der).unwrap();
        let der_encoded = public_key_to_der(&pk).unwrap();
        assert_eq!(pk_der, der_encoded);
    }

    #[test]
    fn should_fail_parsing_a_corrupted_der_encoded_pk() {
        let mut pk_der = hex::decode(crate::SECP256K1_PK_1_DER_HEX).unwrap();
        pk_der[0] += 1;
        let pk_result = public_key_from_der(&pk_der);
        assert!(pk_result.is_err());
        assert!(pk_result.unwrap_err().is_malformed_public_key());
    }

    #[test]
    fn should_fail_parsing_non_secp256k1_key_without_panic() {
        let pk_der = base64::decode(crate::ED25519_PK_DER_BASE64).unwrap();
        let pk_result = public_key_from_der(&pk_der);
        assert!(pk_result.is_err());
        assert!(pk_result.unwrap_err().is_malformed_public_key());
    }

    // RFC 5480 allows compressed points but we insist on canonical representations.
    // Test compressed key was generated with:
    //   $ openssl ecparam -name secp256k1 -genkey -noout -out k1.pem
    //   $ openssl ec -in k1.pem -pubout -outform DER -out k1-comp.der \
    //     -conv_form compressed
    #[test]
    fn rejects_compressed_points() {
        const COMPRESSED: &str = "3036301006072a8648ce3d020106052b8104000a032200026589a94a8dd58659c16aae75abceea86990a20b883a7ebfa1435a4e4cac5221a";
        let pk_der = hex::decode(COMPRESSED).unwrap();
        let pk_result = public_key_from_der(&pk_der);
        assert!(pk_result.is_err());
        assert!(pk_result.unwrap_err().is_malformed_public_key());
    }
}

mod sign {
    use ic_crypto_internal_basic_sig_ecdsa_secp256k1::*;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;

    #[test]
    fn should_correctly_sign_and_verify() {
        let (sk, pk) = crate::new_keypair(&mut reproducible_rng());

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
        let (sk, pk) = crate::new_keypair(&mut reproducible_rng());

        let msg = b"some message to sign";
        for _i in 1..300 {
            let signature = sign(msg, &sk).unwrap();
            assert_eq!(signature.0.len(), types::SignatureBytes::SIZE);
            assert_eq!(verify(&signature, msg, &pk), Ok(()));
        }
    }
}

mod verify {
    use assert_matches::assert_matches;
    use ic_crypto_internal_basic_sig_ecdsa_secp256k1::{types::*, *};
    use ic_crypto_sha2::Sha256;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_types::crypto::{AlgorithmId, CryptoError};

    #[test]
    fn should_correctly_verify_test_vectors() {
        #[derive(Debug)]
        struct TestVector {
            msg_hash: Vec<u8>,
            sig: [u8; 64],
            pk: Vec<u8>,
            is_valid: bool,
        }

        impl TestVector {
            fn new(
                msg: &str,
                sig_r: &str,
                sig_s: &str,
                pk_x: &str,
                pk_y: &str,
                is_valid: bool,
            ) -> Self {
                let msg = hex::decode(msg).expect("Invalid hex for msg");
                let sig_r = hex::decode(sig_r).expect("Invalid hex for sig_r");
                let sig_s = hex::decode(sig_s).expect("Invalid hex for sig_s");
                let pk_x = hex::decode(pk_x).expect("Invalid hex for pk_x");
                let pk_y = hex::decode(pk_y).expect("Invalid hex for pk_y");

                let msg_hash = Sha256::hash(&msg).to_vec();

                let mut sig = Vec::with_capacity(sig_r.len() + sig_s.len());
                sig.extend_from_slice(&sig_r);
                sig.extend_from_slice(&sig_s);

                let mut pk = Vec::with_capacity(1 + pk_x.len() + pk_y.len());
                pk.push(0x04); // uncompressed
                pk.extend_from_slice(&pk_x);
                pk.extend_from_slice(&pk_y);

                let sig = sig.try_into().expect("Invalid size for sig");

                Self {
                    msg_hash,
                    sig,
                    pk,
                    is_valid,
                }
            }
        }

        let test_vectors = [
            // From https://crypto.stackexchange.com/questions/41316/complete-set-of-test-vectors-for-ecdsa-secp256k1
            TestVector::new(
                "4d61617274656e20426f64657765732067656e6572617465642074686973207465737420766563746f72206f6e20323031362d31312d3038",
                "241097efbf8b63bf145c8961dbdf10c310efbb3b2676bbc0f8b08505c9e2f795",
                "021006b7838609339e8b415a7f9acb1b661828131aef1ecbc7955dfb01f3ca0e",
                "779dd197a5df977ed2cf6cb31d82d43328b790dc6b3b7d4437a427bd5847dfcd",
                "e94b724a555b6d017bb7607c3e3281daf5b1699d6ef4124975c9237b917d426f",
                true,
            ),
            // Same as above except r and s are swapped in the signature
            TestVector::new(
                "4d61617274656e20426f64657765732067656e6572617465642074686973207465737420766563746f72206f6e20323031362d31312d3038",
                "021006b7838609339e8b415a7f9acb1b661828131aef1ecbc7955dfb01f3ca0e",
                "241097efbf8b63bf145c8961dbdf10c310efbb3b2676bbc0f8b08505c9e2f795",
                "779dd197a5df977ed2cf6cb31d82d43328b790dc6b3b7d4437a427bd5847dfcd",
                "e94b724a555b6d017bb7607c3e3281daf5b1699d6ef4124975c9237b917d426f",
                false,
            ),
            // Same as the first except the message is empty
            TestVector::new(
                "",
                "241097efbf8b63bf145c8961dbdf10c310efbb3b2676bbc0f8b08505c9e2f795",
                "021006b7838609339e8b415a7f9acb1b661828131aef1ecbc7955dfb01f3ca0e",
                "779dd197a5df977ed2cf6cb31d82d43328b790dc6b3b7d4437a427bd5847dfcd",
                "e94b724a555b6d017bb7607c3e3281daf5b1699d6ef4124975c9237b917d426f",
                false,
            ),
            // A test with the high bit set in s (since we do not verify non-malleability)
            TestVector::new(
                "74657374",
                "6471F8E5E63D6055AA6F6D3A8EBF49935D1316D6A54B9B09465B3BEB38E3AC14",
                "CE0FFBABD8E3248BEEBD568DCBCC7861126B1AB88E721D0206E9D67ECD878C7C",
                "E38257CE81AB62AB1DF591E360AB0021D2D24E737299CF48317DBF31A3996A2A",
                "78DD07EA1996F24FE829B4EE968BA2700632D8F165E793E41AE37B8911FC83C9",
                true,
            ),
        ];

        for tv in &test_vectors {
            let pk = PublicKeyBytes(tv.pk.clone());
            let sig = SignatureBytes(tv.sig);

            let verify_result = verify(&sig, &tv.msg_hash, &pk);
            assert_eq!(
                verify_result.is_ok(),
                tv.is_valid,
                "Unexpected verification result for test vector {tv:?}",
            );
            if verify_result.is_err() {
                assert!(verify_result.unwrap_err().is_signature_verification_error());
            }
        }
    }

    #[test]
    fn should_reject_truncated_ecdsa_pubkey() {
        let (sk, pk) = crate::new_keypair(&mut reproducible_rng());

        let msg = [0x42; 32];
        let signature = sign(&msg, &sk).unwrap();
        assert!(verify(&signature, &msg, &pk).is_ok());

        let invalid_pk = PublicKeyBytes(pk.0[0..pk.0.len() - 1].to_vec());
        let result = verify(&signature, &msg, &invalid_pk);

        assert_matches!(result, Err(CryptoError::MalformedPublicKey{algorithm, key_bytes, internal_error: _})
             if algorithm == AlgorithmId::EcdsaSecp256k1
             && key_bytes == Some(invalid_pk.0)
        );
    }

    #[test]
    fn should_reject_modified_ecdsa_pubkey() {
        let (sk, pk) = crate::new_keypair(&mut reproducible_rng());

        let msg = [0x42; 32];
        let signature = sign(&msg, &sk).unwrap();
        assert!(verify(&signature, &msg, &pk).is_ok());

        /*
        We are encoding using uncompressed coordinates so the format is (h,x,y)
        where h is a 1-byte header. The x that is valid wrt a y is unique,
        so there is no possibility that this does not fail.
         */
        assert_eq!(pk.0.len(), 1 + 2 * types::FIELD_SIZE);
        let mut modified_key = pk.0;
        modified_key[types::FIELD_SIZE] ^= 0x01;
        let invalid_pk = PublicKeyBytes(modified_key);

        let result = verify(&signature, &msg, &invalid_pk);
        assert_matches!(result, Err(CryptoError::MalformedPublicKey{algorithm, key_bytes, internal_error: _})
             if algorithm == AlgorithmId::EcdsaSecp256k1
             && key_bytes == Some(invalid_pk.0)
        );
    }

    #[test]
    fn should_have_correct_error_for_invalid_sig() {
        let (sk, pk) = crate::new_keypair(&mut reproducible_rng());

        let msg = vec![0x42; 32];
        let signature = sign(&msg, &sk).unwrap();

        let mut invalid_signature = signature;
        invalid_signature.0[2] ^= 1;

        let result = verify(&invalid_signature, &msg, &pk);
        assert_matches!(result, Err(CryptoError::SignatureVerification{algorithm, public_key_bytes, sig_bytes, internal_error: _})
                        if algorithm == AlgorithmId::EcdsaSecp256k1 &&
                        public_key_bytes == pk.0 &&
                        sig_bytes == invalid_signature.0);
    }

    #[test]
    fn should_fail_to_verify_wrong_signature() {
        let (sk, pk) = crate::new_keypair(&mut reproducible_rng());
        let msg = b"some message to sign";
        let mut signature = sign(msg, &sk).unwrap();
        // Modify the last byte of the signature.
        assert_eq!(signature.0.len(), SignatureBytes::SIZE);
        signature.0[SignatureBytes::SIZE - 1] = !signature.0[SignatureBytes::SIZE - 1];
        let result = verify(&signature, msg, &pk);
        assert!(result.is_err());
        assert!(result.unwrap_err().is_signature_verification_error());
    }

    #[test]
    fn should_fail_to_verify_wrong_message() {
        let (sk, pk) = crate::new_keypair(&mut reproducible_rng());
        let msg = b"some message to sign";
        let wrong_msg = b"a different message";
        let signature = sign(msg, &sk).unwrap();
        let result = verify(&signature, wrong_msg, &pk);
        assert!(result.is_err());
        assert!(result.unwrap_err().is_signature_verification_error());
    }

    #[test]
    fn should_fail_to_verify_wrong_key() {
        let rng = &mut reproducible_rng();
        let (sk, _) = crate::new_keypair(rng);
        let (_, another_pk) = crate::new_keypair(rng);
        let msg = b"some message to sign";
        let signature = sign(msg, &sk).unwrap();
        let result = verify(&signature, msg, &another_pk);
        assert!(result.is_err());
        assert!(result.unwrap_err().is_signature_verification_error());
    }
}

mod sig_conv {
    use ic_crypto_internal_basic_sig_ecdsa_secp256k1::types::SignatureBytes;

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
