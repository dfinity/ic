use super::*;
use crate::test_utils::malformed_secret_threshold_key_test_vectors;
use crate::types::arbitrary::secret_key as arbitrary_encrypted_share;
use ic_crypto_internal_csp_test_utils::arbitrary::arbitrary_ephemeral_public_key_bytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes as ThresholdPublicKeyBytes;
use proptest::prelude::*;

mod serde {
    use super::*;

    /// Verify that converting to bytes and back again results in the original
    /// data.
    fn test_secret_key_serde(secret_key: EphemeralSecretKey) {
        let bytes = EphemeralSecretKeyBytes::from(&secret_key);
        let parsed = EphemeralSecretKey::try_from(&bytes).expect("Failed to parse");
        assert_eq!(secret_key, parsed);
    }

    /// Verify that parsing a malformed secret key results in an error.
    ///
    /// As the malformed secret key we use a value that is larger than the
    /// modulus
    #[test]
    fn test_parsing_malformed_secret_key_should_fail() {
        for (bytes, valid, name) in malformed_ephemeral_secret_keys() {
            let parsed = EphemeralSecretKey::try_from(bytes);
            assert_eq!(
                valid,
                parsed.is_ok(),
                "{} is {} but got: {:?}",
                name,
                if valid { "valid" } else { "invalid" },
                parsed
            )
        }
    }
    fn malformed_ephemeral_secret_keys() -> Vec<(EphemeralSecretKeyBytes, bool, String)> {
        // Any value larger than the modulus should fail, any smaller value should
        // succeed.
        vec![(
            EphemeralSecretKeyBytes([0xff; EphemeralSecretKeyBytes::SIZE]),
            false,
            "Maximum secret key bytes value".to_string(),
        )]
    }

    /// Verify that converting to bytes and back again results in the original
    /// data.
    fn test_public_key_serde(public_key: EphemeralPublicKey) {
        let bytes = EphemeralPublicKeyBytes::from(&public_key);
        let parsed = EphemeralPublicKey::try_from(&bytes).expect("Failed to parse");
        assert_eq!(public_key, parsed);
    }

    /// Verify that parsing a malformed public key results in an error.
    #[test]
    fn test_parsing_malformed_public_key_should_fail() {
        for (bytes, valid, name) in malformed_ephemeral_public_keys() {
            let parsed = EphemeralPublicKey::try_from(bytes);
            assert_eq!(
                valid,
                parsed.is_ok(),
                "{} is {} but got: {:?}",
                name,
                if valid { "valid" } else { "invalid" },
                parsed
            )
        }
    }
    fn malformed_ephemeral_public_keys() -> Vec<(EphemeralPublicKeyBytes, bool, String)> {
        let valid = {
            let mut valid = [0; EphemeralPublicKeyBytes::SIZE];
            valid[0] = TAG_PUBKEY_INFINITE; // This is actually zero but assuming so makes this test fragile.
            valid
        };
        let invalid_odd = {
            // All zeros does not satisfy the equation but we will claim that it is an odd
            // odd point.
            let mut invalid = valid;
            invalid[0] = TAG_PUBKEY_ODD;
            invalid
        };
        let invalid_infinity = {
            // Points at infinity should be all-zero
            let mut invalid = valid;
            invalid[9] = 11;
            invalid
        };
        let mut ans = vec![
            (
                EphemeralPublicKeyBytes(valid),
                true,
                "Point at infinity".to_string(),
            ),
            (
                EphemeralPublicKeyBytes(invalid_odd),
                false,
                "Invalid odd point".to_string(),
            ),
            (
                EphemeralPublicKeyBytes(invalid_infinity),
                false,
                "Invalid point at infinity".to_string(),
            ),
        ];
        for byte in 0..=255 {
            if (byte != TAG_PUBKEY_INFINITE)
                && (byte != TAG_PUBKEY_ODD)
                && (byte != TAG_PUBKEY_EVEN)
            {
                let mut invalid = valid;
                invalid[0] = byte;
                ans.push((
                    EphemeralPublicKeyBytes(invalid),
                    false,
                    format!("Invalid byte 0x{:x}", byte),
                ));
            }
        }
        ans
    }

    /// Verify that converting to bytes and back again results in the original
    /// data.
    fn test_pop_serde(pop: EphemeralPop) {
        let bytes = EphemeralPopBytes::from(&pop);
        let parsed = EphemeralPop::try_from(&bytes).expect("Failed to parse");
        assert_eq!(
            pop, parsed,
            "Serialising and parsing does not return the original value."
        );
    }

    /// Verify that parsing malformed PoPs fails
    #[test]
    fn test_parsing_malformed_pop_should_fail() {
        for (bytes, valid, name) in malformed_ephemeral_pops() {
            let parsed = EphemeralPop::try_from(bytes);
            assert_eq!(
                valid,
                parsed.is_ok(),
                "{} is {} but got: {:?}",
                name,
                if valid { "valid" } else { "invalid" },
                parsed
            )
        }
    }

    fn malformed_ephemeral_pops() -> Vec<(EphemeralPopBytes, bool, String)> {
        let mut ans = Vec::new();
        for (pk, pk_valid, pk_name) in malformed_ephemeral_public_keys() {
            for (sk1, sk1_valid, sk1_name) in malformed_ephemeral_secret_keys() {
                for (sk2, sk2_valid, sk2_name) in malformed_ephemeral_secret_keys() {
                    let mut bytes = [0; EphemeralPopBytes::SIZE];
                    let (offset, next) = (0, EphemeralPublicKeyBytes::SIZE);
                    bytes[offset..next].copy_from_slice(&pk.0);
                    let (offset, next) = (next, next + EphemeralSecretKeyBytes::SIZE);
                    bytes[offset..next].copy_from_slice(&sk1.0);
                    let (offset, next) = (next, next + EphemeralSecretKeyBytes::SIZE);
                    bytes[offset..next].copy_from_slice(&sk2.0);
                    let valid = pk_valid && sk1_valid && sk2_valid;
                    let name = format!("{} + {} + {}", pk_name, sk1_name, sk2_name);
                    ans.push((EphemeralPopBytes(bytes), valid, name));
                }
            }
        }
        ans
    }

    /// Verify that converting to bytes and back again results in the original
    /// data.
    fn test_encrypted_share_serde(encrypted_share: EncryptedShare) {
        let bytes = EncryptedShareBytes::from(&encrypted_share);
        let parsed = EncryptedShare::try_from(&bytes).expect("Failed to parse");
        assert_eq!(
            encrypted_share, parsed,
            "Serialising and parsing does not return the original value."
        );
    }

    /// Verify that parsing a malformed encrypted share results in an error.
    ///
    /// Encrypted shares have the same representation as threshold secret keys
    /// so we can reuse the malformed secret key generator.
    #[test]
    fn test_parsing_malformed_encrypted_share_should_fail() {
        for (bytes, valid, name) in malformed_secret_threshold_key_test_vectors() {
            let bytes = EncryptedShareBytes(bytes);
            let parsed = EncryptedShare::try_from(bytes);
            assert_eq!(
                valid,
                parsed.is_ok(),
                "{} is {} but got: {:?}",
                name,
                if valid { "valid" } else { "invalid" },
                parsed
            )
        }
    }

    /// Verify that converting to bytes and back again results in the original
    /// data.
    fn test_complaint_serde(complaint: CLibComplaint) {
        let bytes = CLibComplaintBytes::from(complaint.clone());
        let parsed = CLibComplaint::try_from(&bytes).expect("Failed to parse");
        assert_eq!(
            complaint, parsed,
            "Serialising and parsing does not return the original value."
        );
    }

    /// Verify that parsing malformed complaints fails
    ///
    /// Complaints have the same underlying data structure as
    #[test]
    fn test_parsing_malformed_complaint_should_fail() {
        for (bytes, valid, name) in malformed_complaints() {
            let parsed = CLibComplaint::try_from(bytes);
            assert_eq!(
                valid,
                parsed.is_ok(),
                "{} is {} but got: {:?}",
                name,
                if valid { "valid" } else { "invalid" },
                parsed
            )
        }
    }

    fn malformed_complaints() -> Vec<(CLibComplaintBytes, bool, String)> {
        let mut ans = Vec::new();
        for (diffie_hellman, dh_valid, dh_name) in malformed_ephemeral_public_keys() {
            for (pok_challenge, challenge_valid, challenge_name) in
                malformed_ephemeral_secret_keys()
            {
                for (pok_response, response_valid, response_name) in
                    malformed_ephemeral_secret_keys()
                {
                    let valid = dh_valid && challenge_valid && response_valid;
                    let name = format!("{} + {} + {}", dh_name, challenge_name, response_name);
                    let complaint = CLibComplaintBytes {
                        diffie_hellman,
                        pok_challenge,
                        pok_response,
                    };
                    ans.push((complaint, valid, name));
                }
            }
        }
        ans
    }

    /// Verify that parsing a malformed dealing results in an error.
    #[test]
    fn test_parsing_malformed_dealing_should_fail() {
        for (bytes, valid, name) in malformed_dealings() {
            let parsed = CLibDealing::try_from(&bytes);
            assert_eq!(
                valid,
                parsed.is_ok(),
                "{} is {} but got: {:?}",
                name,
                if valid { "valid" } else { "invalid" },
                parsed
            )
        }
    }

    fn malformed_dealings() -> Vec<(CLibDealingBytes, bool, String)> {
        let mut ans = Vec::new();
        let public_coefficients_vectors: Vec<(PublicCoefficientsBytes, bool, String)> = vec![
            (
                PublicCoefficientsBytes {
                    coefficients: Vec::new(),
                },
                true,
                "Empty".to_string(),
            ),
            (
                PublicCoefficientsBytes {
                    coefficients: vec![ThresholdPublicKeyBytes(
                        [0xff; ThresholdPublicKeyBytes::SIZE],
                    )],
                },
                false,
                "Larger than modulus".to_string(),
            ),
        ];
        for (public_coefficients, coefficients_valid, coefficients_name) in
            public_coefficients_vectors
        {
            for (share, share_valid, share_name) in malformed_secret_threshold_key_test_vectors() {
                let valid = coefficients_valid && share_valid;
                let name = format!("{} + {}", coefficients_name, share_name);
                let dealing = CLibDealingBytes {
                    public_coefficients: public_coefficients.to_owned(),
                    receiver_data: vec![Some(EncryptedShareBytes(share))],
                };
                ans.push((dealing, valid, name));
            }
        }
        ans
    }

    /// Verifies that public key serialisation corresponds to that in Secp,
    /// apart from at zero.
    fn test_public_key_serialisation_should_match_libsecp256k1(number: u32) {
        if number != 0 {
            let scalar = Scalar::from_int(number);
            let libsecp_secret_key = libsecp256k1::SecretKey::try_from(scalar)
                .expect("Should be able to obtain a libsecp secret_key from a non-zero scalar");
            let libsecp_public_key = libsecp256k1::PublicKey::from_secret_key(&libsecp_secret_key);
            let libsecp_bytes = libsecp_public_key.serialize_compressed();
            let this_secret_key = EphemeralSecretKey(scalar);
            let this_public_key = EphemeralPublicKey::from(&this_secret_key);
            let this_bytes = EphemeralPublicKeyBytes::from(&this_public_key).0;
            assert_eq!(libsecp_bytes[..], this_bytes[..]);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            max_shrink_iters: 0,
            .. ProptestConfig::default()
        })]

        #[test]
        fn secret_key_serde_should_work(
          secret_key: EphemeralSecretKey,
        ) {
            test_secret_key_serde(secret_key);
        }

        #[test]
        fn public_key_serde_should_work(
          public_key: EphemeralPublicKey,
        ) {
            test_public_key_serde(public_key);
        }

        #[test]
        fn public_key_serde_should_fail_for_nonstandard_points_at_infinity(mut nonstandard in arbitrary_ephemeral_public_key_bytes()) {
            nonstandard.0[0] = TAG_PUBKEY_INFINITE;
            prop_assume!(nonstandard !=EphemeralPublicKeyBytes::from(EphemeralPublicKey::infinity()));
            assert!(EphemeralPublicKey::try_from(&nonstandard).is_err());
        }

        #[test]
        fn pop_serde_should_work(
          pop: EphemeralPop,
        ) {
            test_pop_serde(pop);
        }

        #[test]
        fn encrypted_share_serde_should_work(
          encrypted_share in arbitrary_encrypted_share(),
        ) {
            test_encrypted_share_serde(encrypted_share);
        }

        #[test]
        fn complaint_serde_should_work(
          complaint: CLibComplaint,
        ) {
            test_complaint_serde(complaint);
        }

        #[test]
        fn public_key_serialisation_should_match_libsecp256k1(number: u32) {
            test_public_key_serialisation_should_match_libsecp256k1(number);
        }
    }

    #[test]
    fn public_key_serde_should_work_for_point_at_infinity() {
        test_public_key_serde(EphemeralPublicKey::infinity());
    }

    #[test]
    fn public_key_representation_should_be_stable() {
        assert_eq!(
            SECP256K1_PUBLIC_KEY_ONE,
            EphemeralPublicKeyBytes::from(EphemeralPublicKey::one())
        );
    }

    #[test]
    fn secret_key_representation_should_be_stable() {
        assert_eq!(
            SECP256K1_SECRET_KEY_ONE,
            EphemeralSecretKeyBytes::from(EphemeralSecretKey::one())
        );
    }
}
