#![allow(clippy::unwrap_used)]
use super::*;
use ic_base_types::PrincipalId;
use ic_crypto::utils::get_node_keys_or_generate_if_missing;
use ic_test_utilities::crypto::temp_dir::temp_dir;

#[test]
fn should_succeed_on_valid_keys() {
    let (keys, node_id) = valid_node_keys_and_node_id();
    assert!(keys.version >= 1);

    let valid_keys = ValidNodePublicKeys::try_from(&keys, node_id).unwrap();

    assert_eq!(valid_keys.node_id(), node_id);
    assert_eq!(
        valid_keys.node_signing_key(),
        &keys.node_signing_pk.unwrap()
    );
    assert_eq!(
        valid_keys.committee_signing_key(),
        &keys.committee_signing_pk.unwrap()
    );
    assert_eq!(
        valid_keys.dkg_dealing_encryption_key(),
        &keys.dkg_dealing_encryption_pk.unwrap()
    );
    assert!(valid_keys.idkg_dealing_encryption_key().is_some());
    assert_eq!(
        valid_keys.idkg_dealing_encryption_key().unwrap(),
        &keys.idkg_dealing_encryption_pk.unwrap()
    );
    assert_eq!(valid_keys.tls_certificate(), &keys.tls_certificate.unwrap());
}

#[test]
fn should_fail_if_node_signing_key_is_missing() {
    let (keys, node_id) = {
        let (mut keys, node_id) = valid_node_keys_and_node_id();
        keys.node_signing_pk = None;
        (keys, node_id)
    };

    let result = ValidNodePublicKeys::try_from(&keys, node_id);

    assert!(matches!(result, Err(KeyValidationError { error })
        if error == "invalid node signing key: key is missing"
    ));
}

#[test]
fn should_fail_if_node_signing_key_pubkey_conversion_fails() {
    let (keys, node_id) = {
        let (mut keys, node_id) = valid_node_keys_and_node_id();
        keys.node_signing_pk.as_mut().unwrap().key_value.push(42);
        (keys, node_id)
    };

    let result = ValidNodePublicKeys::try_from(&keys, node_id);

    assert!(matches!(result, Err(KeyValidationError { error })
        if error.contains("invalid node signing key: PublicKeyBytesFromProtoError")
        && error.contains("Wrong data length")
    ));
}

#[test]
fn should_fail_if_node_signing_key_verification_fails() {
    let (keys, node_id) = {
        let (mut keys, _node_id) = valid_node_keys_and_node_id();
        let invalid_pubkey = {
            let nspk_proto = keys.node_signing_pk.as_ref().unwrap();
            let nspk_bytes = BasicSigEd25519PublicKeyBytes::try_from(nspk_proto).unwrap();
            invalidate_valid_ed25519_pubkey(nspk_bytes)
        };
        keys.node_signing_pk.as_mut().unwrap().key_value = invalid_pubkey.0.to_vec();

        let node_id_for_corrupted_node_signing_key = {
            let corrupted_key = &keys.node_signing_pk.as_ref().unwrap().key_value;
            let mut buf = [0; BasicSigEd25519PublicKeyBytes::SIZE];
            buf.copy_from_slice(corrupted_key);
            derive_node_id(BasicSigEd25519PublicKeyBytes(buf))
        };
        (keys, node_id_for_corrupted_node_signing_key)
    };

    let result = ValidNodePublicKeys::try_from(&keys, node_id);

    assert!(matches!(result, Err(KeyValidationError { error })
        if error == "invalid node signing key: verification failed"
    ));
}

#[test]
fn should_fail_if_node_signing_key_is_not_valid_for_the_given_node_id() {
    let wrong_node_id = node_id(1223334444);
    let (keys, node_id) = valid_node_keys_and_node_id();
    assert_ne!(node_id, wrong_node_id);

    let result = ValidNodePublicKeys::try_from(&keys, wrong_node_id);

    assert!(matches!(result, Err(KeyValidationError { error })
        if error.contains("invalid node signing key")
        && error.contains(format!("key not valid for node ID {}", wrong_node_id).as_str())
    ));
}

#[test]
fn should_fail_if_committee_signing_key_is_missing() {
    let (keys, node_id) = {
        let (mut keys, node_id) = valid_node_keys_and_node_id();
        keys.committee_signing_pk = None;
        (keys, node_id)
    };

    let result = ValidNodePublicKeys::try_from(&keys, node_id);

    assert!(matches!(result, Err(KeyValidationError { error })
        if error == "invalid committee signing key: key is missing"
    ));
}

#[test]
fn should_fail_if_committee_signing_key_pubkey_conversion_fails() {
    let (keys, node_id) = {
        let (mut keys, node_id) = valid_node_keys_and_node_id();
        if let Some(pk) = keys.committee_signing_pk.as_mut() {
            pk.key_value.push(42);
        }
        (keys, node_id)
    };

    let result = ValidNodePublicKeys::try_from(&keys, node_id);

    assert!(matches!(result, Err(KeyValidationError { error })
        if error.contains("invalid committee signing key: PublicKeyBytesFromProtoError")
        && error.contains("Wrong data length")
    ));
}

#[test]
fn should_fail_if_committee_signing_key_pubkey_is_corrupted() {
    let (keys, node_id) = {
        let (mut keys, node_id) = valid_node_keys_and_node_id();
        if let Some(pk) = keys.committee_signing_pk.as_mut() {
            pk.key_value[0] ^= 0xff; // this flips the compression flag and thus
                                     // makes the encoding of the point invalid
        }
        (keys, node_id)
    };

    let result = ValidNodePublicKeys::try_from(&keys, node_id);

    assert!(matches!(result, Err(KeyValidationError { error })
        if error.contains("invalid committee signing key: Malformed MultiBls12_381 public key")
    ));
}

#[test]
fn should_fail_if_committee_signing_key_pop_conversion_fails() {
    let (keys, node_id) = {
        let (mut keys, node_id) = valid_node_keys_and_node_id();
        if let Some(pk) = keys.committee_signing_pk.as_mut() {
            pk.proof_data.as_mut().unwrap().push(42);
        }
        (keys, node_id)
    };

    let result = ValidNodePublicKeys::try_from(&keys, node_id);

    assert!(matches!(result, Err(KeyValidationError { error })
        if error.contains("invalid committee signing key: PopBytesFromProtoError")
        && error.contains("Wrong pop length")
    ));
}

#[test]
fn should_fail_if_committee_signing_key_pop_is_corrupted() {
    let (keys, node_id) = {
        let (mut keys, node_id) = valid_node_keys_and_node_id();
        if let Some(pk) = keys.committee_signing_pk.as_mut() {
            pk.proof_data.as_mut().unwrap()[0] ^= 0xff;
        }
        (keys, node_id)
    };

    let result = ValidNodePublicKeys::try_from(&keys, node_id);

    assert!(matches!(result, Err(KeyValidationError { error })
        if error.contains("invalid committee signing key: Malformed MultiBls12_381 PoP")
    ));
}

#[test]
fn should_fail_if_committee_signing_key_pop_verification_fails() {
    let (keys, node_id) = {
        let (mut keys, node_id) = valid_node_keys_and_node_id();
        if let Some(pk) = keys.committee_signing_pk.as_mut() {
            let proof_data_for_other_key =
                valid_node_keys().committee_signing_pk.unwrap().proof_data;
            assert_ne!(pk.proof_data, proof_data_for_other_key);
            pk.proof_data = proof_data_for_other_key;
        }
        (keys, node_id)
    };

    let result = ValidNodePublicKeys::try_from(&keys, node_id);

    assert!(matches!(result, Err(KeyValidationError { error })
        if error.contains("invalid committee signing key: MultiBls12_381 PoP could not be verified")
        && error.contains("PoP verification failed")
    ));
}

#[test]
fn should_fail_if_dkg_dealing_encryption_key_is_missing() {
    let (keys, node_id) = {
        let (mut keys, node_id) = valid_node_keys_and_node_id();
        keys.dkg_dealing_encryption_pk = None;
        (keys, node_id)
    };

    let result = ValidNodePublicKeys::try_from(&keys, node_id);

    assert_eq!(
        result.unwrap_err(),
        KeyValidationError {
            error: "invalid DKG dealing encryption key: key is missing".to_string(),
        }
    );
}

#[test]
fn should_fail_if_dkg_dealing_encryption_key_pop_is_missing() {
    let (keys, node_id) = {
        let (mut keys, node_id) = valid_node_keys_and_node_id();
        if let Some(pk) = keys.dkg_dealing_encryption_pk.as_mut() {
            pk.proof_data = None;
        }
        (keys, node_id)
    };

    let result = ValidNodePublicKeys::try_from(&keys, node_id);

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
    let (keys, node_id) = {
        let (mut keys, node_id) = valid_node_keys_and_node_id();
        if let Some(pk) = keys.dkg_dealing_encryption_pk.as_mut() {
            pk.key_value[0] ^= 0xff;
        }
        (keys, node_id)
    };

    let result = ValidNodePublicKeys::try_from(&keys, node_id);

    assert_eq!(
        result.unwrap_err(),
        KeyValidationError {
            error: "invalid DKG dealing encryption key: Internal conversion failed".to_string(),
        }
    );
}

#[test]
fn should_fail_if_dkg_dealing_encryption_key_is_invalid() {
    let (keys, node_id) = {
        let (mut keys, node_id) = valid_node_keys_and_node_id();
        if let Some(pk) = keys.dkg_dealing_encryption_pk.as_mut() {
            let proof_data_for_other_key = valid_node_keys()
                .dkg_dealing_encryption_pk
                .unwrap()
                .proof_data;
            assert_ne!(pk.proof_data, proof_data_for_other_key);
            pk.proof_data = proof_data_for_other_key;
        }
        (keys, node_id)
    };

    let result = ValidNodePublicKeys::try_from(&keys, node_id);

    assert_eq!(
        result.unwrap_err(),
        KeyValidationError {
            error: "invalid DKG dealing encryption key: verification failed".to_string(),
        }
    );
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

#[test]
fn should_fail_if_idkg_dealing_encryption_key_is_missing() {
    let (keys, node_id) = {
        let (mut keys, node_id) = valid_node_keys_and_node_id();
        assert!(keys.version >= 1);
        keys.idkg_dealing_encryption_pk = None;
        (keys, node_id)
    };

    let result = ValidNodePublicKeys::try_from(&keys, node_id);

    assert!(matches!(result, Err(KeyValidationError { error })
        if error == "invalid I-DKG dealing encryption key: key is missing"
    ));
}

#[test]
fn should_fail_if_idkg_dealing_encryption_key_algorithm_unsupported() {
    let (keys, node_id) = {
        let (mut keys, node_id) = valid_node_keys_and_node_id();
        assert!(keys.version >= 1);
        if let Some(pk) = keys.idkg_dealing_encryption_pk.as_mut() {
            pk.algorithm = AlgorithmIdProto::Unspecified as i32;
        }
        (keys, node_id)
    };

    let result = ValidNodePublicKeys::try_from(&keys, node_id);

    assert!(matches!(result, Err(KeyValidationError { error })
        if error == "invalid I-DKG dealing encryption key: unsupported algorithm: Some(Unspecified)"
    ));
}

#[test]
fn should_fail_if_idkg_dealing_encryption_key_is_invalid() {
    let (keys, node_id) = {
        let (mut keys, node_id) = valid_node_keys_and_node_id();
        assert!(keys.version >= 1);
        if let Some(pk) = keys.idkg_dealing_encryption_pk.as_mut() {
            pk.key_value = b"invalid key".to_vec();
        }
        (keys, node_id)
    };

    let result = ValidNodePublicKeys::try_from(&keys, node_id);

    assert!(matches!(result, Err(KeyValidationError { error })
        if error == "invalid I-DKG dealing encryption key: verification failed: InvalidPublicKey"));
}

#[test]
fn should_not_fail_if_idkg_dealing_encryption_key_is_missing_in_version_0() {
    let (keys, node_id) = {
        let (mut keys, node_id) = valid_node_keys_and_node_id();
        keys.idkg_dealing_encryption_pk = None;
        keys.version = 0;
        (keys, node_id)
    };

    let result = ValidNodePublicKeys::try_from(&keys, node_id);

    assert!(result.is_ok());
}

#[test]
fn should_not_fail_if_idkg_dealing_encryption_key_algorithm_unsupported_in_version_0() {
    let (keys, node_id) = {
        let (mut keys, node_id) = valid_node_keys_and_node_id();
        assert!(keys.idkg_dealing_encryption_pk.is_some());
        if let Some(pk) = keys.idkg_dealing_encryption_pk.as_mut() {
            pk.algorithm = AlgorithmIdProto::Unspecified as i32;
        }
        keys.version = 0;
        (keys, node_id)
    };

    let result = ValidNodePublicKeys::try_from(&keys, node_id);

    assert!(result.is_ok());
}

#[test]
fn should_not_fail_if_idkg_dealing_encryption_key_is_invalid_in_version_0() {
    let (keys, node_id) = {
        let (mut keys, node_id) = valid_node_keys_and_node_id();
        assert!(keys.idkg_dealing_encryption_pk.is_some());
        if let Some(pk) = keys.idkg_dealing_encryption_pk.as_mut() {
            pk.key_value = b"invalid key".to_vec();
        }
        keys.version = 0;
        (keys, node_id)
    };

    let result = ValidNodePublicKeys::try_from(&keys, node_id);

    assert!(result.is_ok());
}

#[test]
fn should_not_include_some_idkg_dealing_encryption_key_in_valid_keys_in_version_0() {
    let (keys, node_id) = {
        let (mut keys, node_id) = valid_node_keys_and_node_id();
        assert!(keys.version >= 1);
        assert!(keys.idkg_dealing_encryption_pk.is_some());
        keys.version = 0;
        (keys, node_id)
    };

    let result = ValidNodePublicKeys::try_from(&keys, node_id);

    assert!(matches!(result, Ok(valid_keys) if valid_keys.idkg_dealing_encryption_key().is_none()));
}

/// TLS certificate validation is only smoke tested here. Detailed tests can be
/// found in `ic_crypto_tls_cert_validation`.
mod tls_certificate_validation {
    use super::*;

    #[test]
    fn should_fail_if_tls_key_validation_fails_because_cert_is_missing() {
        let (valid_node_keys, node_id) = valid_node_keys_and_node_id();
        let keys = NodePublicKeys {
            tls_certificate: None,
            ..valid_node_keys
        };

        let result = ValidNodePublicKeys::try_from(&keys, node_id);

        assert!(matches!(result, Err(KeyValidationError { error })
            if error == "invalid TLS certificate: certificate is missing"
        ));
    }

    #[test]
    fn should_fail_if_tls_key_validation_fails_and_cert_is_present_but_invalid() {
        let (valid_node_keys, node_id) = valid_node_keys_and_node_id();
        let keys = NodePublicKeys {
            tls_certificate: Some(X509PublicKeyCert {
                certificate_der: vec![],
            }),
            ..valid_node_keys
        };

        let result = ValidNodePublicKeys::try_from(&keys, node_id);

        assert!(matches!(result, Err(KeyValidationError { error })
            if error.contains("invalid TLS certificate: failed to parse DER")
        ));
    }
}

mod idkg_dealing_encryption_public_key_validation {
    use super::*;

    #[test]
    fn should_succeed_on_valid_idkg_dealing_encryption_key() {
        let idkg_de_key = valid_node_keys()
            .idkg_dealing_encryption_pk
            .expect("missing iDKG dealing encryption key");

        let result = ValidIDkgDealingEncryptionPublicKey::try_from(idkg_de_key.clone());

        assert!(matches!(result, Ok(key) if key.get() == &idkg_de_key));
    }

    #[test]
    fn should_fail_if_idkg_dealing_encryption_key_algorithm_unsupported() {
        let mut idkg_de_key = valid_node_keys()
            .idkg_dealing_encryption_pk
            .expect("missing iDKG dealing encryption key");
        idkg_de_key.algorithm = AlgorithmIdProto::Unspecified as i32;

        let result = ValidIDkgDealingEncryptionPublicKey::try_from(idkg_de_key);

        assert!(matches!(result, Err(KeyValidationError { error })
            if error == "invalid I-DKG dealing encryption key: unsupported algorithm: Some(Unspecified)"
        ));
    }

    #[test]
    fn should_fail_if_idkg_dealing_encryption_key_is_invalid() {
        let mut idkg_de_key = valid_node_keys()
            .idkg_dealing_encryption_pk
            .expect("missing iDKG dealing encryption key");
        idkg_de_key.key_value = b"invalid key".to_vec();

        let result = ValidIDkgDealingEncryptionPublicKey::try_from(idkg_de_key);

        assert!(matches!(result, Err(KeyValidationError { error })
        if error == "invalid I-DKG dealing encryption key: verification failed: InvalidPublicKey"));
    }
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

fn valid_node_keys() -> NodePublicKeys {
    let (node_pks, _node_id) = valid_node_keys_and_node_id();
    node_pks
}

pub fn valid_node_keys_and_node_id() -> (NodePublicKeys, NodeId) {
    let temp_dir = temp_dir();
    get_node_keys_or_generate_if_missing(temp_dir.path())
}

pub fn node_id(n: u64) -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(n))
}
