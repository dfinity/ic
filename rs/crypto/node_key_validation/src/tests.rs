use super::*;
use assert_matches::assert_matches;
use ic_base_types::PrincipalId;
use ic_types::time::UNIX_EPOCH;
use std::str::FromStr;

mod all_node_public_keys_validation {
    use super::*;
    use crate::tests::node_signing_public_key_validation::{
        derived_node_id, node_id_from_node_signing_public_key,
    };
    use ic_crypto_test_utils_keys::public_keys::{
        valid_committee_signing_public_key, valid_dkg_dealing_encryption_public_key,
        valid_idkg_dealing_encryption_public_key, valid_node_signing_public_key,
        valid_tls_certificate_and_validation_time,
    };

    #[test]
    fn should_succeed_for_valid_hard_coded_keys() {
        let (hard_coded_keys, validation_time) = valid_current_node_public_keys();
        let node_id = node_id_from_node_signing_public_key(&hard_coded_keys);

        let valid_keys =
            ValidNodePublicKeys::try_from(hard_coded_keys.clone(), node_id, validation_time);

        assert_matches!(valid_keys, Ok(actual)
            if actual.node_id() == node_id &&
            actual.node_signing_key() == &hard_coded_keys.node_signing_public_key.unwrap() &&
            actual.committee_signing_key() == &hard_coded_keys.committee_signing_public_key.unwrap() &&
            actual.tls_certificate() == &hard_coded_keys.tls_certificate.unwrap() &&
            actual.dkg_dealing_encryption_key() == &hard_coded_keys.dkg_dealing_encryption_public_key.unwrap() &&
            actual.idkg_dealing_encryption_key() == &hard_coded_keys.idkg_dealing_encryption_public_key.unwrap());
    }

    #[test]
    fn should_fail_if_node_signing_key_is_missing() {
        let public_keys = CurrentNodePublicKeys {
            node_signing_public_key: None,
            ..valid_current_node_public_keys().0
        };

        let result = ValidNodePublicKeys::try_from(public_keys, derived_node_id(), UNIX_EPOCH);

        assert_matches!(result, Err(KeyValidationError { error })
            if error == "invalid node signing key: key is missing"
        );
    }

    #[test]
    fn should_fail_if_committee_signing_key_is_missing() {
        let public_keys = CurrentNodePublicKeys {
            committee_signing_public_key: None,
            ..valid_current_node_public_keys().0
        };
        let node_id = node_id_from_node_signing_public_key(&public_keys);

        let result = ValidNodePublicKeys::try_from(public_keys, node_id, UNIX_EPOCH);

        assert_matches!(result, Err(KeyValidationError { error })
            if error == "invalid committee signing key: key is missing"
        );
    }

    #[test]
    fn should_fail_if_tls_key_validation_fails_because_cert_is_missing() {
        let public_keys = CurrentNodePublicKeys {
            tls_certificate: None,
            ..valid_current_node_public_keys().0
        };
        let node_id = node_id_from_node_signing_public_key(&public_keys);

        let result = ValidNodePublicKeys::try_from(public_keys, node_id, UNIX_EPOCH);

        assert_matches!(result, Err(KeyValidationError { error })
            if error == "invalid TLS certificate: certificate is missing"
        );
    }

    #[test]
    fn should_fail_if_dkg_dealing_encryption_key_is_missing() {
        let (current_node_public_keys, validation_time) = valid_current_node_public_keys();
        let public_keys = CurrentNodePublicKeys {
            dkg_dealing_encryption_public_key: None,
            ..current_node_public_keys
        };
        let node_id = node_id_from_node_signing_public_key(&public_keys);

        let result = ValidNodePublicKeys::try_from(public_keys, node_id, validation_time);

        assert_eq!(
            result.unwrap_err(),
            KeyValidationError {
                error: "invalid DKG dealing encryption key: key is missing".to_string(),
            }
        );
    }

    #[test]
    fn should_fail_if_idkg_dealing_encryption_key_is_missing() {
        let (current_node_public_keys, validation_time) = valid_current_node_public_keys();
        let public_keys = CurrentNodePublicKeys {
            idkg_dealing_encryption_public_key: None,
            ..current_node_public_keys
        };
        let node_id = node_id_from_node_signing_public_key(&public_keys);

        let result = ValidNodePublicKeys::try_from(public_keys, node_id, validation_time);

        assert_matches!(result, Err(KeyValidationError { error })
            if error == "invalid I-DKG dealing encryption key: key is missing"
        );
    }

    fn valid_current_node_public_keys() -> (CurrentNodePublicKeys, Time) {
        let (tls_cert, validation_time) = valid_tls_certificate_and_validation_time();
        (
            CurrentNodePublicKeys {
                node_signing_public_key: Some(valid_node_signing_public_key()),
                committee_signing_public_key: Some(valid_committee_signing_public_key()),
                tls_certificate: Some(tls_cert),
                dkg_dealing_encryption_public_key: Some(valid_dkg_dealing_encryption_public_key()),
                idkg_dealing_encryption_public_key: Some(valid_idkg_dealing_encryption_public_key()),
            },
            validation_time,
        )
    }
}

mod node_signing_public_key_validation {
    use super::*;
    use ic_crypto_test_utils_keys::public_keys::valid_node_signing_public_key;

    #[test]
    fn should_succeed_for_hard_coded_valid_node_signing_public_key() {
        let public_key = valid_node_signing_public_key();

        let valid_public_key = ValidNodeSigningPublicKey::try_from(public_key.clone());

        assert_matches!(valid_public_key, Ok(actual) if actual.get() == &public_key);
    }

    #[test]
    fn should_fail_on_default_public_key() {
        let result = ValidNodeSigningPublicKey::try_from(PublicKey::default());

        assert_matches!(result, Err(KeyValidationError {error})
            if error.contains("invalid node signing key"));
    }

    #[test]
    fn should_fail_if_node_signing_key_pubkey_conversion_fails() {
        let invalid_node_signing_key = {
            let mut public_key = valid_node_signing_public_key();
            public_key.key_value.push(42);
            public_key
        };

        let result = ValidNodeSigningPublicKey::try_from(invalid_node_signing_key);

        assert_matches!(result, Err(KeyValidationError { error })
            if error.contains("invalid node signing key: PublicKeyBytesFromProtoError")
            && error.contains("Wrong data length")
        );
    }

    #[test]
    fn should_fail_if_node_signing_key_verification_fails() {
        let (corrupted_node_signing_public_key, node_id_for_corrupted_node_signing_key) = {
            let mut corrupted_public_key = valid_node_signing_public_key();
            corrupted_public_key.key_value = {
                let nspk_bytes =
                    BasicSigEd25519PublicKeyBytes::try_from(&corrupted_public_key).unwrap();
                invalidate_valid_ed25519_pubkey(nspk_bytes).0.to_vec()
            };
            let node_id_for_corrupted_node_signing_key = {
                let corrupted_key = &corrupted_public_key.key_value;
                let mut buf = [0; BasicSigEd25519PublicKeyBytes::SIZE];
                buf.copy_from_slice(corrupted_key);
                derive_node_id(BasicSigEd25519PublicKeyBytes(buf))
            };
            (corrupted_public_key, node_id_for_corrupted_node_signing_key)
        };

        let result = ValidNodeSigningPublicKey::try_from((
            corrupted_node_signing_public_key,
            node_id_for_corrupted_node_signing_key,
        ));

        assert_matches!(result, Err(KeyValidationError { error })
            if error == "invalid node signing key: verification failed"
        );
    }

    #[test]
    fn should_fail_if_node_signing_key_is_not_valid_for_the_given_node_id() {
        let wrong_node_id = node_id(1223334444);
        assert_ne!(wrong_node_id, derived_node_id());

        let result =
            ValidNodeSigningPublicKey::try_from((valid_node_signing_public_key(), wrong_node_id));

        assert_matches!(result, Err(KeyValidationError { error })
            if error.contains("invalid node signing key")
            && error.contains(format!("key not valid for node ID {wrong_node_id}").as_str())
        );
    }

    pub fn derived_node_id() -> NodeId {
        use ic_crypto_utils_basic_sig::conversions as basicsig_conversions;
        let expected_node_id = NodeId::new(
            PrincipalId::from_str(
                "4inqb-2zcvk-f6yql-sowol-vg3es-z24jd-jrkow-mhnsd-ukvfp-fak5p-aae",
            )
            .unwrap(),
        );
        let actual_node_id = basicsig_conversions::derive_node_id(&valid_node_signing_public_key())
            .expect("invalid node signing public key");
        assert_eq!(expected_node_id, actual_node_id);
        expected_node_id
    }

    pub fn node_id_from_node_signing_public_key(public_keys: &CurrentNodePublicKeys) -> NodeId {
        use ic_crypto_utils_basic_sig::conversions as basicsig_conversions;

        basicsig_conversions::derive_node_id(
            public_keys
                .node_signing_public_key
                .as_ref()
                .expect("missing node signing key required to compute NodeId"),
        )
        .expect("Corrupted node signing public key")
    }
}

mod committee_signing_public_key_validation {
    use super::*;
    use ic_crypto_test_utils_keys::public_keys::{
        valid_committee_signing_public_key, valid_committee_signing_public_key_2,
    };

    #[test]
    fn should_succeed_for_hard_coded_valid_committee_signing_public_key() {
        let public_key = valid_committee_signing_public_key();

        let valid_public_key = ValidCommitteeSigningPublicKey::try_from(public_key.clone());

        assert_matches!(valid_public_key, Ok(actual) if actual.get() == &public_key);
    }

    #[test]
    fn should_fail_on_default_public_key() {
        let result = ValidCommitteeSigningPublicKey::try_from(PublicKey::default());

        assert_matches!(result, Err(KeyValidationError {error})
            if error.contains("invalid committee signing key"));
    }

    #[test]
    fn should_fail_if_committee_signing_key_pubkey_conversion_fails() {
        let invalid_committee_signing_key = {
            let mut public_key = valid_committee_signing_public_key();
            public_key.key_value.push(42);
            public_key
        };

        let result = ValidCommitteeSigningPublicKey::try_from(invalid_committee_signing_key);

        assert_matches!(result, Err(KeyValidationError { error })
            if error.contains("invalid committee signing key: PublicKeyBytesFromProtoError")
            && error.contains("Wrong data length")
        );
    }

    #[test]
    fn should_fail_if_committee_signing_key_pubkey_is_corrupted() {
        let corrupted_committee_signing_key = {
            let mut public_key = valid_committee_signing_public_key();
            // this flips the compression flag and thus makes the encoding of the point invalid
            public_key.key_value[0] ^= 0xff;
            public_key
        };

        let result = ValidCommitteeSigningPublicKey::try_from(corrupted_committee_signing_key);

        assert_matches!(result, Err(KeyValidationError { error })
            if error.contains("invalid committee signing key: Malformed MultiBls12_381 public key")
        );
    }

    #[test]
    fn should_fail_if_committee_signing_key_pop_conversion_fails() {
        let invalid_committee_signing_key = {
            let mut public_key = valid_committee_signing_public_key();
            public_key.proof_data.as_mut().unwrap().push(42);
            public_key
        };

        let result = ValidCommitteeSigningPublicKey::try_from(invalid_committee_signing_key);

        assert_matches!(result, Err(KeyValidationError { error })
            if error.contains("invalid committee signing key: PopBytesFromProtoError")
            && error.contains("Wrong pop length")
        );
    }

    #[test]
    fn should_fail_if_committee_signing_key_pop_is_corrupted() {
        let corrupted_committee_signing_key = {
            let mut public_key = valid_committee_signing_public_key();
            public_key.proof_data.as_mut().unwrap()[0] ^= 0xff;
            public_key
        };

        let result = ValidCommitteeSigningPublicKey::try_from(corrupted_committee_signing_key);

        assert_matches!(result, Err(KeyValidationError { error })
            if error.contains("invalid committee signing key: Malformed MultiBls12_381 PoP")
        );
    }

    #[test]
    fn should_fail_if_committee_signing_key_pop_verification_fails() {
        let swapped_pop_committee_signing_key = {
            let mut committee_signing_public_key = valid_committee_signing_public_key();
            let proof_data_for_other_key = valid_committee_signing_public_key_2().proof_data;
            assert_ne!(
                committee_signing_public_key.proof_data,
                proof_data_for_other_key
            );
            committee_signing_public_key.proof_data = proof_data_for_other_key;
            committee_signing_public_key
        };

        let result = ValidCommitteeSigningPublicKey::try_from(swapped_pop_committee_signing_key);

        assert_matches!(result, Err(KeyValidationError { error })
            if error.contains("invalid committee signing key: MultiBls12_381 PoP could not be verified")
            && error.contains("PoP verification failed")
        );
    }
}

mod dkg_dealing_encryption_public_key_validation {
    use super::*;
    use crate::tests::node_signing_public_key_validation::derived_node_id;
    use ic_crypto_test_utils_keys::public_keys::{
        valid_dkg_dealing_encryption_public_key, valid_dkg_dealing_encryption_public_key_2,
    };

    #[test]
    fn should_succeed_for_hard_coded_valid_dkg_dealing_encryption_public_key() {
        let public_key = valid_dkg_dealing_encryption_public_key();

        let valid_public_key =
            ValidDkgDealingEncryptionPublicKey::try_from((public_key.clone(), derived_node_id()));

        assert_matches!(valid_public_key, Ok(actual) if actual.get() == &public_key);
    }

    #[test]
    fn should_fail_on_default_public_key() {
        let result =
            ValidDkgDealingEncryptionPublicKey::try_from((PublicKey::default(), derived_node_id()));

        assert_matches!(result, Err(KeyValidationError {error})
            if error.contains("invalid DKG dealing encryption key"));
    }

    #[test]
    fn should_fail_if_dkg_dealing_encryption_key_pop_is_missing() {
        let public_key = PublicKey {
            proof_data: None,
            ..valid_dkg_dealing_encryption_public_key()
        };

        let result = ValidDkgDealingEncryptionPublicKey::try_from((public_key, derived_node_id()));

        assert_eq!(
            result.unwrap_err(),
            KeyValidationError {
                error: "invalid DKG dealing encryption key: Failed to convert proof \
            of possession (PoP): Missing proof data"
                    .to_string(),
            }
        );
    }

    #[test]
    fn should_fail_if_dkg_dealing_encryption_key_conversion_fails() {
        let mut public_key = valid_dkg_dealing_encryption_public_key();
        public_key.key_value[0] ^= 0xff;

        let result = ValidDkgDealingEncryptionPublicKey::try_from((public_key, derived_node_id()));

        assert_eq!(
            result.unwrap_err(),
            KeyValidationError {
                error: "invalid DKG dealing encryption key: Internal conversion failed".to_string(),
            }
        );
    }

    #[test]
    fn should_fail_if_dkg_dealing_encryption_key_is_invalid() {
        let swapped_pop_dkg_dealing_encryption_key = {
            let mut public_key = valid_dkg_dealing_encryption_public_key();
            let proof_data_for_other_key = valid_dkg_dealing_encryption_public_key_2().proof_data;
            assert_ne!(public_key.proof_data, proof_data_for_other_key);
            public_key.proof_data = proof_data_for_other_key;
            public_key
        };

        let result = ValidDkgDealingEncryptionPublicKey::try_from((
            swapped_pop_dkg_dealing_encryption_key,
            derived_node_id(),
        ));

        assert_eq!(
            result.unwrap_err(),
            KeyValidationError {
                error: "invalid DKG dealing encryption key: verification failed".to_string(),
            }
        );
    }
}

mod idkg_dealing_encryption_public_key_validation {
    use super::*;
    use ic_crypto_test_utils_keys::public_keys::valid_idkg_dealing_encryption_public_key;

    #[test]
    fn should_succeed_for_hard_coded_valid_idkg_dealing_encryption_key() {
        let public_key = valid_idkg_dealing_encryption_public_key();

        let valid_public_key = ValidIDkgDealingEncryptionPublicKey::try_from(public_key.clone());

        assert_matches!(valid_public_key, Ok(actual) if actual.get() == &public_key);
    }

    #[test]
    fn should_fail_on_default_public_key() {
        let result = ValidIDkgDealingEncryptionPublicKey::try_from(PublicKey::default());

        assert_matches!(result, Err(KeyValidationError {error})
            if error == "invalid I-DKG dealing encryption key: unsupported algorithm: Some(Unspecified)");
    }

    #[test]
    fn should_fail_if_idkg_dealing_encryption_key_algorithm_unsupported() {
        let public_key = PublicKey {
            algorithm: AlgorithmIdProto::Unspecified as i32,
            ..valid_idkg_dealing_encryption_public_key()
        };

        let result = ValidIDkgDealingEncryptionPublicKey::try_from(public_key);

        assert_matches!(result, Err(KeyValidationError { error })
            if error == "invalid I-DKG dealing encryption key: unsupported algorithm: Some(Unspecified)"
        );
    }

    #[test]
    fn should_fail_if_idkg_dealing_encryption_key_is_invalid() {
        let public_key = PublicKey {
            key_value: b"invalid key".to_vec(),
            ..valid_idkg_dealing_encryption_public_key()
        };

        let result = ValidIDkgDealingEncryptionPublicKey::try_from(public_key);

        assert_matches!(result, Err(KeyValidationError { error })
        if error == "invalid I-DKG dealing encryption key: verification failed: InvalidPublicKey"
        );
    }

    #[test]
    fn should_fail_on_empty_key_value() {
        let public_key = PublicKey {
            key_value: vec![],
            ..valid_idkg_dealing_encryption_public_key()
        };

        let result = ValidIDkgDealingEncryptionPublicKey::try_from(public_key);

        assert_matches!(result, Err(KeyValidationError { error })
        if error == "invalid I-DKG dealing encryption key: verification failed: InvalidPublicKey"
        );
    }
}

#[test]
fn should_correctly_display_key_validation_error() {
    assert_eq!(
        KeyValidationError {
            error: "description".to_string(),
        }
        .to_string(),
        "KeyValidationError { error: \"description\" }".to_string()
    );
}

fn invalidate_valid_ed25519_pubkey(
    valid_pubkey: BasicSigEd25519PublicKeyBytes,
) -> BasicSigEd25519PublicKeyBytes {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    let point_of_prime_order = CompressedEdwardsY(valid_pubkey.0).decompress().unwrap();
    let point_of_order_8 = CompressedEdwardsY([0; 32]).decompress().unwrap();
    let point_of_composite_order = point_of_prime_order + point_of_order_8;
    assert!(!point_of_composite_order.is_torsion_free());
    BasicSigEd25519PublicKeyBytes(point_of_composite_order.compress().0)
}

fn node_id(n: u64) -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(n))
}
