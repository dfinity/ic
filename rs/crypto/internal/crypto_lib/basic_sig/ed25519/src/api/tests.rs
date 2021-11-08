#![allow(clippy::unwrap_used)]
mod keygen {

    use crate::{keypair_from_rng, public_key_from_der};
    use ic_crypto_internal_test_vectors::unhex::hex_to_32_bytes;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn should_correctly_generate_ed25519_keys() {
        let mut csprng = ChaCha20Rng::seed_from_u64(42);

        let (sk, pk) = keypair_from_rng(&mut csprng);

        assert_eq!(
            *sk.0.expose_secret(),
            hex_to_32_bytes("7848b5d711bc9883996317a3f9c90269d56771005d540a19184939c9e8d0db2a")
        );
        assert_eq!(
            pk.0,
            hex_to_32_bytes("78eda21ba04a15e2000fe8810fe3e56741d23bb9ae44aa9d5bb21b76675ff34b")
        );
    }

    // Example DER-pk from https://tools.ietf.org/html/rfc8410#section-10.1
    const PK_DER_BASE64: &str = "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE";

    // Example ECDSA DER-encoded key, for testing.
    const ECDSA_P256_PK_1_DER_HEX : &str = "3059301306072a8648ce3d020106082a8648ce3d03010703420004485c32997ce7c6d38ca82c821185c689d424fac7c9695bb97786c4248aab6428949bcd163e2bcf3eeeac4f200b38fbd053f82c4e1776dc9c6dc8db9b7c35e06f";

    #[test]
    fn should_correctly_parse_der_encoded_pk() {
        let pk_der = base64::decode(PK_DER_BASE64).unwrap();
        let _pk = public_key_from_der(&pk_der).unwrap();
    }

    #[test]
    fn should_fail_parsing_a_corrupted_der_encoded_pk() {
        let mut pk_der = base64::decode(PK_DER_BASE64).unwrap();
        pk_der[0] += 1;
        let pk_result = public_key_from_der(&pk_der);
        assert!(pk_result.is_err());
        assert!(pk_result.unwrap_err().is_malformed_public_key());
    }

    #[test]
    fn should_fail_parsing_der_encoded_pk_with_wrong_oid() {
        let mut pk_der = base64::decode(PK_DER_BASE64).unwrap();
        // OID starts at 7-th byte and is 3-bytes long.
        pk_der[6] += 1;
        let pk_result = public_key_from_der(&pk_der);
        assert!(pk_result.is_err());
        let err = pk_result.unwrap_err();
        assert!(err.is_malformed_public_key());
        assert!(err
            .to_string()
            .contains("Wrong algorithm identifier for Ed25519"));
    }

    #[test]
    fn should_fail_parsing_der_encoded_pk_of_wrong_type() {
        let pk_der = hex::decode(ECDSA_P256_PK_1_DER_HEX).unwrap();
        let pk_result = public_key_from_der(&pk_der);
        assert!(pk_result.is_err());
        assert!(pk_result.unwrap_err().is_malformed_public_key());
    }

    // TODO(CRP-616) Add more failure tests with corrupted DER-keys.
}

mod ed25519_cr_yp_to {
    use crate::types::{PublicKeyBytes, SecretKeyBytes};
    use crate::{sign, verify};
    use ic_crypto_internal_test_vectors::unhex::{hex_to_32_bytes, hex_to_byte_vec};
    use ic_crypto_secrets_containers::SecretArray;
    use std::fs::File;
    use std::io::{prelude::*, BufReader};
    use std::path::PathBuf;

    /// Performs a subset of the regression tests done in http://ed25519.cr.yp.to/python/sign.py
    /// based on the test vectors published at http://ed25519.cr.yp.to/python/sign.input.
    /// See http://ed25519.cr.yp.to/software.html.
    #[test]
    fn should_find_no_regressions_with_ed25519_cr_yp_to_test_vectors() {
        let sign_input = {
            let mut path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
            path.push("test_resources/sign.input");
            path
        };
        let sign_input = File::open(sign_input.clone())
            .unwrap_or_else(|e| panic!("Cannot open file: {}: {}", sign_input.display(), e));
        for (line_num, line) in BufReader::new(sign_input)
            .lines()
            .map(|l| l.unwrap())
            .enumerate()
        {
            let mut splitter = line.split(':');

            let sk = SecretKeyBytes(SecretArray::new_and_dont_zeroize_argument(
                &hex_to_32_bytes(&splitter.next().unwrap()[..64]),
            ));
            let pk = PublicKeyBytes(hex_to_32_bytes(splitter.next().unwrap())); // We use pk directly from the input file
            let m = hex_to_byte_vec(splitter.next().unwrap());
            let sm = splitter.next().unwrap();

            let s = sign(&m, &sk).unwrap();

            // ed25519.checkvalid(s,m,pk)
            assert!(
                verify(&s, &m, &pk).is_ok(),
                "Verification error in line {}",
                line_num + 1
            );

            // assert x[3] == binascii.hexlify(s + m)
            assert_eq!(
                sm,
                hex::encode(
                    s.0.to_vec()
                        .into_iter()
                        .chain(m.into_iter())
                        .collect::<Vec<u8>>()
                ),
                "Unexpected signature for line {}",
                line_num + 1
            );
        }
    }
}

mod sign {

    use crate::sign;
    use crate::types::{SecretKeyBytes, SignatureBytes};
    use ic_crypto_internal_test_vectors::ed25519::{crypto_lib_testvec, Ed25519TestVector};
    use ic_crypto_secrets_containers::SecretArray;
    use strum::IntoEnumIterator;

    #[test]
    fn should_correctly_sign_test_vectors() {
        for test_vec in Ed25519TestVector::iter() {
            let (sk, _, msg, sig) = crypto_lib_testvec(test_vec);
            let sk = SecretKeyBytes(SecretArray::new_and_dont_zeroize_argument(&sk));
            let sig = SignatureBytes(sig);

            assert_eq!(
                sign(&msg, &sk).unwrap(),
                sig,
                "Unexpected signature for test vector {:?}",
                test_vec
            );
        }
    }

    // At the time of writing this test, calling sign with an invalid
    // argument was not possible because only keys with length other than 32
    // bytes are invalid (see ed25519_dalek for details) but the API enforces
    // the 32 bytes. This test acts as documentation of this fact.
    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn should_fail_with_illegalargument_if_secret_key_is_invalid() {
        assert!(true)
    }
}

mod wycheproof {
    use crate::api::SecretArray;
    use crate::types::{PublicKeyBytes, SecretKeyBytes, SignatureBytes};
    use crate::{sign, verify};
    use std::convert::TryInto;

    #[test]
    fn should_pass_wycheproof_test_vectors() {
        let test_set = wycheproof::eddsa::TestSet::load(wycheproof::eddsa::TestName::Ed25519)
            .expect("Unable to load tests");

        for test_group in test_set.test_groups {
            let pk = PublicKeyBytes(test_group.key.pk.try_into().expect("Unexpected key size"));

            let sk_bytes: [u8; 32] = test_group.key.sk.try_into().expect("Unexpected key size");
            let sk = SecretKeyBytes(SecretArray::new_and_dont_zeroize_argument(&sk_bytes));

            for test in test_group.tests {
                /*
                The wycheproof tests include some invalid length signatures, but these cannot
                be represented in SignatureBytes so we simply skip those tests.
                */
                if test.sig.len() != 64 {
                    continue;
                }
                let test_sig =
                    SignatureBytes(test.sig.try_into().expect("Unexpected signature size"));

                let gen_sig = sign(&test.msg, &sk).expect("Generating signature failed");

                if test.result == wycheproof::TestResult::Valid {
                    // If test is valid verify that our generated signature matches (Ed25519 should
                    // be deterministic) and that the signature verifies
                    assert!(verify(&test_sig, &test.msg, &pk).is_ok());
                    assert_eq!(test_sig, gen_sig);
                } else {
                    // Otherwise check that the test signature fails but our generated signature
                    // is accepted
                    assert!(verify(&gen_sig, &test.msg, &pk).is_ok());
                    assert!(verify(&test_sig, &test.msg, &pk).is_err());
                }
            }
        }
    }
}

mod verify {
    use crate::types::{PublicKeyBytes, SecretKeyBytes, SignatureBytes};
    use crate::{public_key_from_der, public_key_to_der, sign, verify};
    use ic_crypto_internal_test_vectors::ed25519::Ed25519TestVector::RFC8032_ED25519_1;
    use ic_crypto_internal_test_vectors::ed25519::Ed25519TestVector::RFC8032_ED25519_SHA_ABC;
    use ic_crypto_internal_test_vectors::ed25519::{crypto_lib_testvec, Ed25519TestVector};
    use ic_crypto_secrets_containers::SecretArray;
    use strum::IntoEnumIterator;

    #[test]
    fn should_correctly_verify_test_vectors() {
        for test_vec in Ed25519TestVector::iter() {
            let (_, pk, msg, sig) = crypto_lib_testvec(test_vec);
            let pk = PublicKeyBytes(pk);
            let sig = SignatureBytes(sig);

            assert!(
                verify(&sig, &msg, &pk).is_ok(),
                "Cannot verify signature for test vector {:?}",
                test_vec
            );
        }
    }

    #[test]
    fn should_fail_to_verify_under_wrong_signature() {
        let (_, pk, msg, sig) = crypto_lib_testvec(RFC8032_ED25519_SHA_ABC);
        let (_, _, _, wrong_sig) = crypto_lib_testvec(RFC8032_ED25519_1);
        assert_ne!(sig[..], wrong_sig[..]);

        let wrong_sig = SignatureBytes(wrong_sig);
        let pk = PublicKeyBytes(pk);
        let result = verify(&wrong_sig, &msg, &pk);

        assert!(result.unwrap_err().is_signature_verification_error());
    }

    #[test]
    fn should_fail_to_verify_under_wrong_message() {
        let (sk, pk, _, _) = crypto_lib_testvec(RFC8032_ED25519_SHA_ABC);
        let sk = SecretKeyBytes(SecretArray::new_and_dont_zeroize_argument(&sk));
        let pk = PublicKeyBytes(pk);

        let result = verify(&sign(b"x", &sk).unwrap(), b"y", &pk);

        assert!(result.unwrap_err().is_signature_verification_error());
    }

    #[test]
    fn should_fail_to_verify_under_wrong_public_key() {
        let (sk, pk, msg, _) = crypto_lib_testvec(RFC8032_ED25519_SHA_ABC);
        let (_, wrong_pk, _, _) = crypto_lib_testvec(RFC8032_ED25519_1);
        let sk = SecretKeyBytes(SecretArray::new_and_dont_zeroize_argument(&sk));
        let pk = PublicKeyBytes(pk);
        let wrong_pk = PublicKeyBytes(wrong_pk);
        assert_ne!(pk, wrong_pk);

        let result = verify(&sign(&msg, &sk).unwrap(), &msg, &wrong_pk);

        assert!(result.unwrap_err().is_signature_verification_error());
    }

    #[test]
    fn should_fail_to_verify_if_signature_is_invalid() {
        // Invalid signatures are created by corrupting the first byte
        // of the valid signatures from the test vectors.
        for test_vec in Ed25519TestVector::iter() {
            let (_, pk, msg, mut sig_bytes) = crypto_lib_testvec(test_vec);
            let pk = PublicKeyBytes(pk);
            sig_bytes[0] += 1; // corrupt the first byte
            let corrupted_sig = SignatureBytes(sig_bytes);
            let result = verify(&corrupted_sig, &msg, &pk);
            assert!(result.unwrap_err().is_signature_verification_error());
        }
    }

    #[test]
    fn should_fail_with_malformed_public_key_if_public_key_is_invalid() {
        // We need a public key that is strictly not valid (malformed),
        // i.e. parsing it and/or checking the coordinates fails.
        // Minor corruptions of a key (like in the test above) sometimes
        // result in a valid key (although not matching the signature),
        // and for these keys verification fails with signature_verification_error(),
        // which is not what this test is about.
        // Below an invalid public key is created by corrupting the first byte
        // of a specific valid key from the test vectors.
        let (_, mut pk_bytes, msg, sig) = crypto_lib_testvec(RFC8032_ED25519_SHA_ABC);
        pk_bytes[0] = 0; // corrupt the first byte
        let corrupted_pk = PublicKeyBytes(pk_bytes);
        let sig = SignatureBytes(sig);
        let result = verify(&sig, &msg, &corrupted_pk);
        assert!(result.unwrap_err().is_malformed_public_key());
    }

    #[test]
    fn should_correctly_der_encode_pk_of_test_vectors() {
        for test_vec in Ed25519TestVector::iter() {
            let (_, pk, _, _) = crypto_lib_testvec(test_vec);
            let pk = PublicKeyBytes(pk);
            let der_pk = public_key_to_der(pk);

            let mut expected_der_pk = vec![
                48, 42, // A sequence of 42 bytes follows.
                48, 5, // An element of 5 bytes follows.
                6, 3, 43, 101, 112, // The OID
                3, 33, // A bitstring of 33 bytes follows.
                0,  // The bitstring (32 bytes) is divisible by 8
            ];
            expected_der_pk.extend(pk.0.to_vec());
            assert_eq!(der_pk, expected_der_pk);

            // Convert back to public key from der. Should match the original `pk`.
            assert_eq!(pk, public_key_from_der(der_pk.as_slice()).unwrap());
        }
    }
}

mod verify_public_key {
    use crate::types::PublicKeyBytes;
    use crate::{keypair_from_rng, verify_public_key};
    use curve25519_dalek::edwards::CompressedEdwardsY;

    #[test]
    fn should_fail_public_key_verification_if_point_is_not_on_curve() {
        let pubkey_not_on_curve = {
            let point_not_on_curve = [
                2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ];
            assert_eq!(CompressedEdwardsY(point_not_on_curve).decompress(), None);
            PublicKeyBytes(point_not_on_curve)
        };

        assert_eq!(verify_public_key(&pubkey_not_on_curve), false);
    }

    #[test]
    fn should_fail_public_key_verification_if_point_has_small_order() {
        let pubkey_with_small_order = {
            let pubkey_with_order_8 = PublicKeyBytes([0; 32]);
            assert!(CompressedEdwardsY(pubkey_with_order_8.0)
                .decompress()
                .expect("pubkey cannot be decompressed")
                .is_small_order());
            pubkey_with_order_8
        };

        assert_eq!(verify_public_key(&pubkey_with_small_order), false);
    }

    #[test]
    fn should_fail_public_key_verification_if_point_has_wrong_order() {
        let point_with_composite_order = {
            let (_sk_bytes, pk_bytes) = keypair_from_rng(&mut rand::thread_rng());
            let point_of_prime_order = CompressedEdwardsY(pk_bytes.0).decompress().unwrap();
            let point_of_order_8 = CompressedEdwardsY([0; 32]).decompress().unwrap();
            let point_of_composite_order = point_of_prime_order + point_of_order_8;
            assert_eq!(point_of_composite_order.is_torsion_free(), false);
            point_of_composite_order
        };
        let pubkey_with_composite_order = PublicKeyBytes(point_with_composite_order.compress().0);
        assert_eq!(verify_public_key(&pubkey_with_composite_order), false);
    }
}
