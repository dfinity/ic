#![allow(clippy::unwrap_used)]
use super::*;
use assert_matches::assert_matches;
use ic_base_types::PrincipalId;
use ic_config::crypto::CryptoConfig;
use ic_crypto_node_key_generation::get_node_keys_or_generate_if_missing;
use ic_types::crypto::AlgorithmId;
use std::str::FromStr;

mod all_node_public_keys_validation {
    use super::*;
    use crate::tests::committee_signing_public_key_validation::valid_committee_signing_public_key;
    use crate::tests::dkg_dealing_encryption_public_key_validation::valid_dkg_dealing_encryption_public_key;
    use crate::tests::idkg_dealing_encryption_public_key_validation::valid_idkg_dealing_encryption_public_key;
    use crate::tests::node_signing_public_key_validation::{
        derived_node_id, node_id_from_node_signing_public_key, valid_node_signing_public_key,
    };

    #[test]
    fn should_succeed_for_valid_hard_coded_keys() {
        let hard_coded_keys = valid_current_node_public_keys();
        let node_id = node_id_from_node_signing_public_key(&hard_coded_keys);

        let valid_keys = ValidNodePublicKeys::try_from(hard_coded_keys.clone(), node_id);

        assert_matches!(valid_keys, Ok(actual)
            if actual.node_id() == node_id &&
            actual.node_signing_key() == &hard_coded_keys.node_signing_public_key.unwrap() &&
            actual.committee_signing_key() == &hard_coded_keys.committee_signing_public_key.unwrap() &&
            actual.tls_certificate() == &hard_coded_keys.tls_certificate.unwrap() &&
            actual.dkg_dealing_encryption_key() == &hard_coded_keys.dkg_dealing_encryption_public_key.unwrap() &&
            actual.idkg_dealing_encryption_key() == &hard_coded_keys.idkg_dealing_encryption_public_key.unwrap());
    }

    #[test]
    fn should_succeed_for_generated_node_keys() {
        let (generated_keys, node_id) = generate_node_keys_and_node_id();

        let valid_keys = ValidNodePublicKeys::try_from(generated_keys.clone(), node_id);

        assert_matches!(valid_keys, Ok(actual)
            if actual.node_id() == node_id &&
            actual.node_signing_key() == &generated_keys.node_signing_public_key.unwrap() &&
            actual.committee_signing_key() == &generated_keys.committee_signing_public_key.unwrap() &&
            actual.tls_certificate() == &generated_keys.tls_certificate.unwrap() &&
            actual.dkg_dealing_encryption_key() == &generated_keys.dkg_dealing_encryption_public_key.unwrap() &&
            actual.idkg_dealing_encryption_key() == &generated_keys.idkg_dealing_encryption_public_key.unwrap());
    }

    #[test]
    fn should_fail_if_node_signing_key_is_missing() {
        let public_keys = CurrentNodePublicKeys {
            node_signing_public_key: None,
            ..valid_current_node_public_keys()
        };

        let result = ValidNodePublicKeys::try_from(public_keys, derived_node_id());

        assert_matches!(result, Err(KeyValidationError { error })
            if error == "invalid node signing key: key is missing"
        );
    }

    #[test]
    fn should_fail_if_committee_signing_key_is_missing() {
        let public_keys = CurrentNodePublicKeys {
            committee_signing_public_key: None,
            ..valid_current_node_public_keys()
        };
        let node_id = node_id_from_node_signing_public_key(&public_keys);

        let result = ValidNodePublicKeys::try_from(public_keys, node_id);

        assert_matches!(result, Err(KeyValidationError { error })
            if error == "invalid committee signing key: key is missing"
        );
    }

    #[test]
    fn should_fail_if_tls_key_validation_fails_because_cert_is_missing() {
        let public_keys = CurrentNodePublicKeys {
            tls_certificate: None,
            ..valid_current_node_public_keys()
        };
        let node_id = node_id_from_node_signing_public_key(&public_keys);

        let result = ValidNodePublicKeys::try_from(public_keys, node_id);

        assert_matches!(result, Err(KeyValidationError { error })
            if error == "invalid TLS certificate: certificate is missing"
        );
    }

    #[test]
    fn should_fail_if_dkg_dealing_encryption_key_is_missing() {
        let public_keys = CurrentNodePublicKeys {
            dkg_dealing_encryption_public_key: None,
            ..valid_current_node_public_keys()
        };
        let node_id = node_id_from_node_signing_public_key(&public_keys);

        let result = ValidNodePublicKeys::try_from(public_keys, node_id);

        assert_eq!(
            result.unwrap_err(),
            KeyValidationError {
                error: "invalid DKG dealing encryption key: key is missing".to_string(),
            }
        );
    }

    #[test]
    fn should_fail_if_idkg_dealing_encryption_key_is_missing() {
        let public_keys = CurrentNodePublicKeys {
            idkg_dealing_encryption_public_key: None,
            ..valid_current_node_public_keys()
        };
        let node_id = node_id_from_node_signing_public_key(&public_keys);

        let result = ValidNodePublicKeys::try_from(public_keys, node_id);

        assert_matches!(result, Err(KeyValidationError { error })
            if error == "invalid I-DKG dealing encryption key: key is missing"
        );
    }

    fn valid_current_node_public_keys() -> CurrentNodePublicKeys {
        CurrentNodePublicKeys {
            node_signing_public_key: Some(valid_node_signing_public_key()),
            committee_signing_public_key: Some(valid_committee_signing_public_key()),
            tls_certificate: Some(valid_tls_certificate()),
            dkg_dealing_encryption_public_key: Some(valid_dkg_dealing_encryption_public_key()),
            idkg_dealing_encryption_public_key: Some(valid_idkg_dealing_encryption_public_key()),
        }
    }

    fn valid_tls_certificate() -> X509PublicKeyCert {
        X509PublicKeyCert {
            certificate_der: hex_decode(
                "3082015630820108a00302010202140098d074\
                7d24ca04a2f036d8665402b4ea784830300506032b6570304a3148304606035504030\
                c3f34696e71622d327a63766b2d663679716c2d736f776f6c2d76673365732d7a3234\
                6a642d6a726b6f772d6d686e73642d756b7666702d66616b35702d6161653020170d3\
                232313130343138313231345a180f39393939313233313233353935395a304a314830\
                4606035504030c3f34696e71622d327a63766b2d663679716c2d736f776f6c2d76673\
                365732d7a32346a642d6a726b6f772d6d686e73642d756b7666702d66616b35702d61\
                6165302a300506032b6570032100246acd5f38372411103768e91169dadb7370e9990\
                9a65639186ac6d1c36f3735300506032b6570034100d37e5ccfc32146767e5fd73343\
                649f5b5564eb78e6d8d424d8f01240708bc537a2a9bcbcf6c884136d18d2b475706d7\
                bb905f52faf28707735f1d90ab654380b",
            ),
        }
    }
}

mod node_signing_public_key_validation {
    use super::*;

    #[test]
    fn should_succeed_for_hard_coded_valid_node_signing_public_key() {
        let public_key = valid_node_signing_public_key();

        let valid_public_key = ValidNodeSigningPublicKey::try_from(public_key.clone());

        assert_matches!(valid_public_key, Ok(actual) if actual.get() == &public_key);
    }

    #[test]
    fn should_succeed_for_generated_node_signing_public_key() {
        let public_key = generate_node_keys()
            .node_signing_public_key
            .expect("missing node signing public key");

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
            && error.contains(format!("key not valid for node ID {}", wrong_node_id).as_str())
        );
    }

    pub fn valid_node_signing_public_key() -> PublicKey {
        PublicKey {
            version: 0,
            algorithm: AlgorithmId::Ed25519 as i32,
            key_value: hex_decode(
                "58d558c7586efb32f4667ee9a302877da97aa1136cda92af4d7a4f8873f9434f",
            ),
            proof_data: None,
            timestamp: None,
        }
    }

    pub fn derived_node_id() -> NodeId {
        let expected_node_id = NodeId::new(
            PrincipalId::from_str(
                "4inqb-2zcvk-f6yql-sowol-vg3es-z24jd-jrkow-mhnsd-ukvfp-fak5p-aae",
            )
            .unwrap(),
        );
        assert_eq!(
            expected_node_id,
            ic_crypto_node_key_generation::derive_node_id(&valid_node_signing_public_key())
        );
        expected_node_id
    }

    pub fn node_id_from_node_signing_public_key(public_keys: &CurrentNodePublicKeys) -> NodeId {
        ic_crypto_node_key_generation::derive_node_id(
            public_keys
                .node_signing_public_key
                .as_ref()
                .expect("missing node signing key required to compute NodeId"),
        )
    }
}

mod committee_signing_public_key_validation {
    use super::*;

    #[test]
    fn should_succeed_for_hard_coded_valid_committee_signing_public_key() {
        let public_key = valid_committee_signing_public_key();

        let valid_public_key = ValidCommitteeSigningPublicKey::try_from(public_key.clone());

        assert_matches!(valid_public_key, Ok(actual) if actual.get() == &public_key);
    }

    #[test]
    fn should_succeed_for_generated_committee_signing_public_key() {
        let public_key = generate_node_keys()
            .committee_signing_public_key
            .expect("missing committee signing public key");

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
            public_key.key_value[0] ^= 0xff; // this flips the compression flag and thus
                                             // makes the encoding of the point invalid
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
            let proof_data_for_other_key = generate_node_keys()
                .committee_signing_public_key
                .unwrap()
                .proof_data;
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

    pub fn valid_committee_signing_public_key() -> PublicKey {
        PublicKey {
            version: 0,
            algorithm: AlgorithmId::MultiBls12_381 as i32,
            key_value: hex_decode(
                "8dab94740858cc96e8df512d8d81730a94d0f3534f30\
                cebd35ee2006ce4a449cad611dd7d97bbc44256932da4d4a76a70b9f347e4a989a3073fc7\
                c2d51bf30804ebbc5c3c6da08b8392d2482473290aff428868caabbc26eec4e7bc59209eb0a",
            ),
            proof_data: Some(hex_decode(
                "afc3038c06223258a14af7c942428fe42f89f8d733e4f\
                5ea8d34a90c0df142697802a6f22633df890a1ce5b774b23aed",
            )),
            timestamp: None,
        }
    }
}

mod dkg_dealing_encryption_public_key_validation {
    use super::*;
    use crate::tests::node_signing_public_key_validation::derived_node_id;

    #[test]
    fn should_succeed_for_hard_coded_valid_dkg_dealing_encryption_public_key() {
        let public_key = valid_dkg_dealing_encryption_public_key();

        let valid_public_key =
            ValidDkgDealingEncryptionPublicKey::try_from((public_key.clone(), derived_node_id()));

        assert_matches!(valid_public_key, Ok(actual) if actual.get() == &public_key);
    }

    #[test]
    fn should_succeed_for_generated_dkg_dealing_encryption_public_key() {
        let (public_keys, node_id) = generate_node_keys_and_node_id();
        let public_key = public_keys
            .dkg_dealing_encryption_public_key
            .expect("missing NIDKG dealing encryption key");

        let valid_public_key =
            ValidDkgDealingEncryptionPublicKey::try_from((public_key.clone(), node_id));

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
            let proof_data_for_other_key = generate_node_keys()
                .dkg_dealing_encryption_public_key
                .unwrap()
                .proof_data;
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

    pub fn valid_dkg_dealing_encryption_public_key() -> PublicKey {
        PublicKey {
            version: 0,
            algorithm: AlgorithmId::Groth20_Bls12_381 as i32,
            key_value: hex_decode(
                "ad36a01cbd40dcfa36ec21a96bedcab17372a9cd2b9eba6171ebeb28dd041a\
                    d5cbbdbb4bed55f59938e8ffb3dd69e386",
            ),
            proof_data: Some(hex_decode(
                "a1781847726f7468323057697468506f705f42\
                6c7331325f333831a367706f705f6b65795830b751c9585044139f80abdebf38d7f30\
                aeb282f178a5e8c284f279eaad1c90d9927e56cac0150646992bce54e08d317ea6963\
                68616c6c656e676558203bb20c5e9c75790f63aae921316912ffc80d6d03946dd21f8\
                5c35159ca030ec668726573706f6e7365582063d6cf189635c0f3111f97e69ae0af8f\
                1594b0f00938413d89dbafc326340384",
            )),
            timestamp: None,
        }
    }
}

mod idkg_dealing_encryption_public_key_validation {
    use super::*;

    #[test]
    fn should_succeed_for_hard_coded_valid_idkg_dealing_encryption_key() {
        let public_key = valid_idkg_dealing_encryption_public_key();

        let valid_public_key = ValidIDkgDealingEncryptionPublicKey::try_from(public_key.clone());

        assert_matches!(valid_public_key, Ok(actual) if actual.get() == &public_key);
    }

    #[test]
    fn should_succeed_for_generated_idkg_dealing_encryption_key() {
        let public_key = generate_node_keys()
            .idkg_dealing_encryption_public_key
            .expect("missing iDKG dealing encryption key");

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

    pub fn valid_idkg_dealing_encryption_public_key() -> PublicKey {
        PublicKey {
            version: 0,
            algorithm: AlgorithmId::MegaSecp256k1 as i32,
            key_value: hex_decode(
                "03e1e1f76e9d834221a26c4a080b65e60d3b6f9c1d6e5b880abf916a364893da2e",
            ),
            proof_data: None,
            timestamp: None,
        }
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

fn generate_node_keys() -> CurrentNodePublicKeys {
    let (node_pks, _node_id) = generate_node_keys_and_node_id();
    node_pks
}

fn generate_node_keys_and_node_id() -> (CurrentNodePublicKeys, NodeId) {
    let (config, _temp_dir) = CryptoConfig::new_in_temp_dir();
    get_node_keys_or_generate_if_missing(&config, None)
}

fn node_id(n: u64) -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(n))
}

fn hex_decode<T: AsRef<[u8]>>(data: T) -> Vec<u8> {
    hex::decode(data).expect("failed to decode hex")
}
