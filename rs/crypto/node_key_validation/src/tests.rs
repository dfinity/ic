#![allow(clippy::unwrap_used)]
use super::*;
use ic_base_types::PrincipalId;
use ic_crypto::utils::get_node_keys_or_generate_if_missing;
use ic_crypto_test_utils::tls::x509_certificates::{
    ed25519_key_pair, CertBuilder, CertWithPrivateKey,
};
use ic_test_utilities::crypto::temp_dir::temp_dir;
use openssl::hash::MessageDigest;
use std::ops::Range;

#[test]
fn should_succeed_on_valid_keys() {
    let (keys, node_id) = valid_node_keys_and_node_id();

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

mod tls_certificate_validation {
    use super::*;
    use chrono::{Duration, Utc};
    use ic_crypto_test_utils::tls::x509_certificates::prime256v1_key_pair;

    #[test]
    fn should_fail_if_tls_certificate_is_missing() {
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
    fn should_fail_if_tls_certificate_is_empty() {
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

    #[test]
    fn should_fail_if_tls_certificate_has_invalid_der_encoding() {
        let (keys, node_id) = {
            let (mut keys, node_id) = valid_node_keys_and_node_id();
            if let Some(pk) = keys.tls_certificate.as_mut() {
                pk.certificate_der.iter_mut().for_each(|x| *x ^= 0xff);
            }
            (keys, node_id)
        };

        let result = ValidNodePublicKeys::try_from(&keys, node_id);

        assert!(matches!(result, Err(KeyValidationError { error })
            if error.contains("invalid TLS certificate: failed to parse DER")
        ));
    }

    #[test]
    fn should_fail_if_tls_certificate_der_encoding_has_remainder() {
        let (keys, node_id) = {
            let (mut keys, node_id) = valid_node_keys_and_node_id();
            keys.tls_certificate
                .as_mut()
                .unwrap()
                .certificate_der
                .push(0x42);
            (keys, node_id)
        };

        let result = ValidNodePublicKeys::try_from(&keys, node_id);

        assert!(matches!(result, Err(KeyValidationError { error })
            if error.contains("invalid TLS certificate: DER not fully consumed when parsing. Remainder: 0x42")
        ));
    }

    #[test]
    /// Tests the error class of invalid subject CNs by means
    /// of a duplicate subject CN.
    fn should_fail_if_tls_certificate_has_invalid_subject_cn() {
        let (keys, node_id) = {
            let (mut keys, node_id) = valid_node_keys_and_node_id();
            let cert = valid_cert_builder(node_id)
                .with_duplicate_subject_cn()
                .build_ed25519();
            keys.tls_certificate.as_mut().unwrap().certificate_der = cert.x509().to_der().unwrap();
            (keys, node_id)
        };

        let result = ValidNodePublicKeys::try_from(&keys, node_id);

        assert!(matches!(result, Err(KeyValidationError { error })
            if error.contains("invalid TLS certificate: invalid subject common name (CN): found second common name (CN)")
        ));
    }

    #[test]
    fn should_fail_if_tls_certificate_subject_cn_is_not_node_id() {
        let (keys, node_id) = {
            let cert = CertWithPrivateKey::builder()
                .cn("incorrect node ID".to_string())
                .build_ed25519();

            let (mut keys, node_id) = valid_node_keys_and_node_id();
            keys.tls_certificate.as_mut().unwrap().certificate_der = cert.x509().to_der().unwrap();
            (keys, node_id)
        };

        let result = ValidNodePublicKeys::try_from(&keys, node_id);

        assert!(matches!(result, Err(KeyValidationError { error })
            if error.contains("invalid TLS certificate: subject common name (CN) does not match node ID")
        ));
    }

    #[test]
    /// Tests the error class of invalid issuer CNs by means
    /// of a duplicate issuer CN.
    fn should_fail_if_tls_certificate_has_invalid_issuer_cn() {
        let (keys, node_id) = {
            let (mut keys, node_id) = valid_node_keys_and_node_id();
            let cert = valid_cert_builder(node_id)
                .with_duplicate_issuer_cn()
                .build_ed25519();
            keys.tls_certificate.as_mut().unwrap().certificate_der = cert.x509().to_der().unwrap();
            (keys, node_id)
        };

        let result = ValidNodePublicKeys::try_from(&keys, node_id);

        assert!(matches!(result, Err(KeyValidationError { error })
            if error.contains("invalid TLS certificate: invalid issuer common name (CN): found second common name (CN)")
        ));
    }

    #[test]
    fn should_fail_if_tls_certificate_issuer_cn_not_equal_subject_cn() {
        let (keys, node_id) = {
            let (mut keys, node_id) = valid_node_keys_and_node_id();
            let cert = valid_cert_builder(node_id)
                .with_ca_signing(ed25519_key_pair(), "issuer CN, not node ID".to_string())
                .build_ed25519();
            keys.tls_certificate.as_mut().unwrap().certificate_der = cert.x509().to_der().unwrap();
            (keys, node_id)
        };

        let result = ValidNodePublicKeys::try_from(&keys, node_id);

        assert!(matches!(result, Err(KeyValidationError { error })
            if error.contains("invalid TLS certificate: issuer common name (CN) does not match \
                               subject common name (CN)")
        ));
    }

    #[test]
    fn should_fail_if_tls_certificate_version_is_not_3() {
        let (keys, node_id) = {
            let (mut keys, node_id) = valid_node_keys_and_node_id();
            let cert = valid_cert_builder(node_id).version(2).build_ed25519();
            keys.tls_certificate.as_mut().unwrap().certificate_der = cert.x509().to_der().unwrap();
            (keys, node_id)
        };

        let result = ValidNodePublicKeys::try_from(&keys, node_id);

        assert!(matches!(result, Err(KeyValidationError { error })
            if error.contains("invalid TLS certificate: X509 version is not 3")
        ));
    }

    #[test]
    fn should_fail_if_tls_certificate_notbefore_date_is_not_latest_in_two_minutes_from_now() {
        let (keys, node_id) = {
            let (mut keys, node_id) = valid_node_keys_and_node_id();
            let five_minutes_from_now = Utc::now() + Duration::minutes(5);
            let cert = valid_cert_builder(node_id)
                .not_before_unix(five_minutes_from_now.timestamp())
                .build_ed25519();
            keys.tls_certificate.as_mut().unwrap().certificate_der = cert.x509().to_der().unwrap();
            (keys, node_id)
        };

        let result = ValidNodePublicKeys::try_from(&keys, node_id);

        assert!(matches!(result, Err(KeyValidationError { error })
            if error.contains("invalid TLS certificate: notBefore date")
            && error.contains("is later than two minutes from now")
        ));
    }

    #[test]
    fn should_succeed_if_tls_certificate_notbefore_date_is_one_minute_from_now() {
        let (keys, node_id) = {
            let (mut keys, node_id) = valid_node_keys_and_node_id();
            let one_minute_from_now = Utc::now() + Duration::minutes(1);
            let cert = valid_cert_builder(node_id)
                .not_before_unix(one_minute_from_now.timestamp())
                .build_ed25519();
            keys.tls_certificate.as_mut().unwrap().certificate_der = cert.x509().to_der().unwrap();
            (keys, node_id)
        };

        let result = ValidNodePublicKeys::try_from(&keys, node_id);

        assert!(result.is_ok());
    }

    #[test]
    fn should_fail_if_tls_certificate_notafter_date_is_not_99991231235959z() {
        let (keys, node_id) = {
            let (mut keys, node_id) = valid_node_keys_and_node_id();
            let cert = valid_cert_builder(node_id)
                .validity_days(42)
                .build_ed25519();
            keys.tls_certificate.as_mut().unwrap().certificate_der = cert.x509().to_der().unwrap();
            (keys, node_id)
        };

        let result = ValidNodePublicKeys::try_from(&keys, node_id);

        assert!(matches!(result, Err(KeyValidationError { error })
            if error.contains("invalid TLS certificate: notAfter date is not RFC 5280's 99991231235959Z")
        ));
    }

    #[test]
    fn should_fail_if_tls_certificate_has_expired() {
        let (keys, node_id) = {
            let (mut keys, node_id) = valid_node_keys_and_node_id();
            let cert = valid_cert_builder(node_id).validity_days(0).build_ed25519();
            keys.tls_certificate.as_mut().unwrap().certificate_der = cert.x509().to_der().unwrap();
            (keys, node_id)
        };

        let result = ValidNodePublicKeys::try_from(&keys, node_id);

        assert!(matches!(result, Err(KeyValidationError { error })
            if error.contains("invalid TLS certificate: notAfter date is not RFC 5280's 99991231235959Z")
        ));
    }

    #[test]
    fn should_fail_if_tls_certificate_signature_alg_is_not_ed25519() {
        let (keys, node_id) = {
            let (mut keys, node_id) = valid_node_keys_and_node_id();
            let cert = valid_cert_builder(node_id).build_prime256v1();
            keys.tls_certificate.as_mut().unwrap().certificate_der = cert.x509().to_der().unwrap();
            (keys, node_id)
        };

        let result = ValidNodePublicKeys::try_from(&keys, node_id);

        assert!(matches!(result, Err(KeyValidationError { error })
            if error.contains("invalid TLS certificate: signature algorithm is not Ed25519 (OID 1.3.101.112)")
        ));
    }

    #[test]
    fn should_fail_if_tls_certificate_pubkey_is_malformed() {
        let (keys, node_id) = {
            let (mut keys, node_id) = valid_node_keys_and_node_id();
            let key_pair_for_signing = ed25519_key_pair();
            let non_ed25519_key_pair = prime256v1_key_pair();
            assert_ne!(
                non_ed25519_key_pair.public_key_to_der().unwrap(),
                key_pair_for_signing.public_key_to_der().unwrap()
            );
            let cert_with_invalid_sig = valid_cert_builder(node_id)
                .with_ca_signing(key_pair_for_signing, node_id.get().to_string())
                .build(non_ed25519_key_pair, MessageDigest::null());
            keys.tls_certificate.as_mut().unwrap().certificate_der =
                cert_with_invalid_sig.x509().to_der().unwrap();
            (keys, node_id)
        };

        let result = ValidNodePublicKeys::try_from(&keys, node_id);

        assert!(matches!(result, Err(KeyValidationError { error })
            if error.contains("invalid TLS certificate: conversion to Ed25519 public key failed")
        ));
    }

    #[test]
    fn should_fail_if_tls_certificate_pubkey_verification_fails() {
        let (keys, node_id) = {
            let (mut keys, node_id) = valid_node_keys_and_node_id();
            let cert = keys.tls_certificate.as_mut().unwrap();
            replace_tls_certificate_pubkey_with_invalid_one(cert);
            (keys, node_id)
        };

        let result = ValidNodePublicKeys::try_from(&keys, node_id);

        assert!(matches!(result, Err(KeyValidationError { error })
            if error.contains("invalid TLS certificate: public key verification failed")
        ));
    }

    #[test]
    fn should_fail_if_tls_certificate_signature_verification_fails() {
        let (keys, node_id) = {
            let (mut keys, node_id) = valid_node_keys_and_node_id();
            let key_pair_for_signing = ed25519_key_pair();
            let key_pair = ed25519_key_pair();
            assert_ne!(
                key_pair.public_key_to_der().unwrap(),
                key_pair_for_signing.public_key_to_der().unwrap()
            );
            let cert_that_is_not_self_signed = valid_cert_builder(node_id)
                .with_ca_signing(key_pair_for_signing, node_id.get().to_string())
                .build(key_pair, MessageDigest::null());
            keys.tls_certificate.as_mut().unwrap().certificate_der =
                cert_that_is_not_self_signed.x509().to_der().unwrap();
            (keys, node_id)
        };

        let result = ValidNodePublicKeys::try_from(&keys, node_id);

        assert!(matches!(result, Err(KeyValidationError { error })
            if error.contains("invalid TLS certificate: signature verification failed")
        ));
    }

    #[test]
    fn should_fail_if_tls_certificate_is_ca() {
        let (keys, node_id) = {
            let (mut keys, node_id) = valid_node_keys_and_node_id();
            let cert = valid_cert_builder(node_id)
                .set_ca_key_usage_extension()
                .build_ed25519();
            keys.tls_certificate.as_mut().unwrap().certificate_der = cert.x509().to_der().unwrap();
            (keys, node_id)
        };

        let result = ValidNodePublicKeys::try_from(&keys, node_id);

        assert!(matches!(result, Err(KeyValidationError { error })
            if error.contains("BasicConstraints:CA is True")
        ));
    }

    fn valid_cert_builder(node_id: NodeId) -> CertBuilder {
        CertWithPrivateKey::builder()
            .cn(node_id.get().to_string())
            .not_after("99991231235959Z")
    }

    /// Replaces the TLS certificate's valid public key with an invalid one.
    /// The replacement is done by directly manipulating the DER encoding rather
    /// than using a respective API because such an API currently exists neither
    /// in the openssl crate nor in the x509_parser crate.
    fn replace_tls_certificate_pubkey_with_invalid_one(cert: &mut X509PublicKeyCert) {
        let x509_cert_der = &cert.certificate_der;
        let (_, x509_cert) = x509_parser::parse_x509_certificate(x509_cert_der).unwrap();
        let pubkey_raw = x509_cert
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data;
        let range_of_pubkey_raw_in_der = range_of_needle_in_haystack(pubkey_raw, x509_cert_der);
        let invalid_pubkey = invalidate_valid_ed25519_pubkey_bytes(pubkey_raw);
        cert.certificate_der
            .splice(range_of_pubkey_raw_in_der, invalid_pubkey.0.iter().copied());
    }

    fn range_of_needle_in_haystack(needle: &[u8], haystack: &[u8]) -> Range<usize> {
        let position_of_needle_in_haystack =
            find_needle_in_haystack(needle, haystack).expect("cannot find needle in haystack");
        position_of_needle_in_haystack..(position_of_needle_in_haystack + needle.len())
    }

    /// Inefficient implementation for finding a needle in a haystack that is
    /// efficient enough for our testing purposes.
    fn find_needle_in_haystack(needle: &[u8], haystack: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|win| win == needle)
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

fn invalidate_valid_ed25519_pubkey_bytes(pubkey_bytes: &[u8]) -> BasicSigEd25519PublicKeyBytes {
    let mut buf = [0u8; BasicSigEd25519PublicKeyBytes::SIZE];
    buf.copy_from_slice(pubkey_bytes);
    invalidate_valid_ed25519_pubkey(BasicSigEd25519PublicKeyBytes(buf))
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
