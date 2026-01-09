mod contains_local_public_or_secret_key_error {
    use crate::vault::api::{
        ExternalPublicKeyError, LocalPublicKeyError, NodeKeysError, SecretKeyError,
    };

    #[test]
    fn should_be_false_when_no_errors_present() {
        let node_keys_error = NodeKeysError::no_error();
        assert!(!node_keys_error.contains_local_public_or_secret_key_error());
    }

    #[test]
    fn should_be_false_when_only_external_public_key_error_present() {
        let node_keys_error = NodeKeysError {
            external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                "external public key error".to_string(),
            ))),
            ..NodeKeysError::no_error()
        };
        assert!(!node_keys_error.contains_local_public_or_secret_key_error());
    }

    #[test]
    fn should_be_true_when_both_local_public_and_secret_key_not_found() {
        let node_keys_error = NodeKeysError {
            external_public_key_error: None,
            local_public_key_error: Some(LocalPublicKeyError::NotFound),
            secret_key_error: Some(SecretKeyError::NotFound),
        };
        assert!(node_keys_error.contains_local_public_or_secret_key_error());
    }

    #[test]
    fn should_be_true_when_local_public_key_not_found() {
        let node_keys_error = NodeKeysError {
            local_public_key_error: Some(LocalPublicKeyError::NotFound),
            ..NodeKeysError::no_error()
        };
        assert!(node_keys_error.contains_local_public_or_secret_key_error());
    }

    #[test]
    fn should_be_true_when_local_secret_key_not_found() {
        let node_keys_error = NodeKeysError {
            secret_key_error: Some(SecretKeyError::NotFound),
            ..NodeKeysError::no_error()
        };
        assert!(node_keys_error.contains_local_public_or_secret_key_error());
    }

    #[test]
    fn should_be_true_when_local_public_key_mismatch() {
        let node_keys_error = NodeKeysError {
            local_public_key_error: Some(LocalPublicKeyError::Mismatch),
            ..NodeKeysError::no_error()
        };
        assert!(node_keys_error.contains_local_public_or_secret_key_error());
    }

    #[test]
    fn should_be_true_when_local_secret_key_id_not_computable() {
        let node_keys_error = NodeKeysError {
            secret_key_error: Some(SecretKeyError::CannotComputeKeyId),
            ..NodeKeysError::no_error()
        };
        assert!(node_keys_error.contains_local_public_or_secret_key_error());
    }
}

mod keys_in_registry_missing_locally {
    use crate::vault::api::ExternalPublicKeyError;
    use crate::vault::api::LocalPublicKeyError;
    use crate::vault::api::NodeKeysError;
    use crate::vault::api::NodeKeysErrors;
    use crate::vault::api::SecretKeyError;

    #[test]
    fn should_return_false_if_no_errors_present() {
        let node_keys_errors = NodeKeysErrors::no_error();
        assert!(!node_keys_errors.keys_in_registry_missing_locally());
    }

    #[test]
    fn should_return_false_if_all_errors_structs_present_but_all_empty() {
        let node_keys_errors = NodeKeysErrors {
            node_signing_key_error: Some(NodeKeysError::no_error()),
            committee_signing_key_error: Some(NodeKeysError::no_error()),
            tls_certificate_error: Some(NodeKeysError::no_error()),
            dkg_dealing_encryption_key_error: Some(NodeKeysError::no_error()),
            idkg_dealing_encryption_key_error: Some(NodeKeysError::no_error()),
        };
        assert!(!node_keys_errors.keys_in_registry_missing_locally());
    }

    #[test]
    fn should_return_false_if_only_external_errors_present() {
        let external_public_key_error =
            ExternalPublicKeyError(Box::new("external public key error".to_string()));
        let node_keys_errors = NodeKeysErrors {
            node_signing_key_error: Some(NodeKeysError {
                external_public_key_error: Some(external_public_key_error.clone()),
                ..NodeKeysError::no_error()
            }),
            committee_signing_key_error: Some(NodeKeysError {
                external_public_key_error: Some(external_public_key_error.clone()),
                ..NodeKeysError::no_error()
            }),
            tls_certificate_error: Some(NodeKeysError {
                external_public_key_error: Some(external_public_key_error.clone()),
                ..NodeKeysError::no_error()
            }),
            dkg_dealing_encryption_key_error: Some(NodeKeysError {
                external_public_key_error: Some(external_public_key_error.clone()),
                ..NodeKeysError::no_error()
            }),
            idkg_dealing_encryption_key_error: Some(NodeKeysError {
                external_public_key_error: Some(external_public_key_error),
                ..NodeKeysError::no_error()
            }),
        };
        assert!(!node_keys_errors.keys_in_registry_missing_locally());
    }

    #[test]
    fn should_return_false_if_all_node_signing_key_errors_present_but_single_external_key_error() {
        let node_keys_errors = NodeKeysErrors {
            node_signing_key_error: Some(NodeKeysError {
                external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                    "external public key error".to_string(),
                ))),
                local_public_key_error: Some(LocalPublicKeyError::NotFound),
                secret_key_error: Some(SecretKeyError::NotFound),
            }),
            ..NodeKeysErrors::no_error()
        };
        assert!(!node_keys_errors.keys_in_registry_missing_locally());
    }

    #[test]
    fn should_return_true_if_node_signing_public_key_not_found_locally() {
        let node_keys_errors = NodeKeysErrors {
            node_signing_key_error: Some(NodeKeysError {
                local_public_key_error: Some(LocalPublicKeyError::NotFound),
                ..NodeKeysError::no_error()
            }),
            ..NodeKeysErrors::no_error()
        };
        assert!(node_keys_errors.keys_in_registry_missing_locally());
    }

    #[test]
    fn should_return_true_if_node_signing_public_key_mismatch() {
        let node_keys_errors = NodeKeysErrors {
            node_signing_key_error: Some(NodeKeysError {
                local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                ..NodeKeysError::no_error()
            }),
            ..NodeKeysErrors::no_error()
        };
        assert!(node_keys_errors.keys_in_registry_missing_locally());
    }

    #[test]
    fn should_return_true_if_node_signing_secret_key_id_cannot_be_computed() {
        let node_keys_errors = NodeKeysErrors {
            node_signing_key_error: Some(NodeKeysError {
                secret_key_error: Some(SecretKeyError::CannotComputeKeyId),
                ..NodeKeysError::no_error()
            }),
            ..NodeKeysErrors::no_error()
        };
        assert!(node_keys_errors.keys_in_registry_missing_locally());
    }

    #[test]
    fn should_return_true_if_committee_signing_secret_key_error_present() {
        let node_keys_errors = NodeKeysErrors {
            committee_signing_key_error: Some(NodeKeysError {
                external_public_key_error: None,
                local_public_key_error: None,
                secret_key_error: Some(SecretKeyError::NotFound),
            }),
            ..NodeKeysErrors::no_error()
        };
        assert!(node_keys_errors.keys_in_registry_missing_locally());
    }

    #[test]
    fn should_return_true_if_tls_certificate_secret_key_error_present() {
        let node_keys_errors = NodeKeysErrors {
            tls_certificate_error: Some(NodeKeysError {
                external_public_key_error: None,
                local_public_key_error: None,
                secret_key_error: Some(SecretKeyError::NotFound),
            }),
            ..NodeKeysErrors::no_error()
        };
        assert!(node_keys_errors.keys_in_registry_missing_locally());
    }

    #[test]
    fn should_return_true_if_dkg_dealing_encryption_secret_key_error_present() {
        let node_keys_errors = NodeKeysErrors {
            dkg_dealing_encryption_key_error: Some(NodeKeysError {
                external_public_key_error: None,
                local_public_key_error: None,
                secret_key_error: Some(SecretKeyError::NotFound),
            }),
            ..NodeKeysErrors::no_error()
        };
        assert!(node_keys_errors.keys_in_registry_missing_locally());
    }

    #[test]
    fn should_return_true_if_idkg_dealing_encryption_secret_key_error_present() {
        let node_keys_errors = NodeKeysErrors {
            idkg_dealing_encryption_key_error: Some(NodeKeysError {
                external_public_key_error: None,
                local_public_key_error: None,
                secret_key_error: Some(SecretKeyError::NotFound),
            }),
            ..NodeKeysErrors::no_error()
        };
        assert!(node_keys_errors.keys_in_registry_missing_locally());
    }
}

mod node_keys_errors_to_key_counts_conversions {
    use crate::vault::api::ExternalPublicKeyError;
    use crate::vault::api::LocalPublicKeyError;
    use crate::vault::api::NodeKeysError;
    use crate::vault::api::NodeKeysErrors;
    use crate::vault::api::SecretKeyError;
    use ic_crypto_internal_logmon::metrics::KeyCounts;

    #[derive(Debug)]
    struct ParameterizedTest<U, V> {
        input: U,
        expected: V,
    }

    #[test]
    fn should_convert_ok_result() {
        assert_eq!(
            KeyCounts::from(&NodeKeysErrors {
                node_signing_key_error: None,
                committee_signing_key_error: None,
                tls_certificate_error: None,
                dkg_dealing_encryption_key_error: None,
                idkg_dealing_encryption_key_error: None,
            }),
            KeyCounts::new(5, 5, 5)
        );
    }

    #[test]
    fn should_collect_key_counts_for_single_node_keys_errors() {
        let tests = vec![
            ParameterizedTest {
                input: NodeKeysErrors {
                    node_signing_key_error: None,
                    committee_signing_key_error: None,
                    tls_certificate_error: None,
                    dkg_dealing_encryption_key_error: None,
                    idkg_dealing_encryption_key_error: None,
                },
                expected: KeyCounts::new(5, 5, 5),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    node_signing_key_error: Some(NodeKeysError {
                        external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                            "external public key error".to_string(),
                        ))),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(4, 5, 5),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    committee_signing_key_error: Some(NodeKeysError {
                        external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                            "external public key error".to_string(),
                        ))),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(4, 5, 5),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    tls_certificate_error: Some(NodeKeysError {
                        external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                            "external public key error".to_string(),
                        ))),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(4, 5, 5),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    dkg_dealing_encryption_key_error: Some(NodeKeysError {
                        external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                            "external public key error".to_string(),
                        ))),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(4, 5, 5),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    idkg_dealing_encryption_key_error: Some(NodeKeysError {
                        external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                            "external public key error".to_string(),
                        ))),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(4, 5, 5),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    node_signing_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 4, 5),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    committee_signing_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 4, 5),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    tls_certificate_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 4, 5),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    dkg_dealing_encryption_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 4, 5),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    idkg_dealing_encryption_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 4, 5),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    node_signing_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 4, 5),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    committee_signing_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 4, 5),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    tls_certificate_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 4, 5),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    dkg_dealing_encryption_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 4, 5),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    idkg_dealing_encryption_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 4, 5),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    node_signing_key_error: Some(NodeKeysError {
                        secret_key_error: Some(SecretKeyError::CannotComputeKeyId),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 5, 4),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    committee_signing_key_error: Some(NodeKeysError {
                        secret_key_error: Some(SecretKeyError::CannotComputeKeyId),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 5, 4),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    tls_certificate_error: Some(NodeKeysError {
                        secret_key_error: Some(SecretKeyError::CannotComputeKeyId),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 5, 4),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    dkg_dealing_encryption_key_error: Some(NodeKeysError {
                        secret_key_error: Some(SecretKeyError::CannotComputeKeyId),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 5, 4),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    idkg_dealing_encryption_key_error: Some(NodeKeysError {
                        secret_key_error: Some(SecretKeyError::CannotComputeKeyId),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 5, 4),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    node_signing_key_error: Some(NodeKeysError {
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 5, 4),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    committee_signing_key_error: Some(NodeKeysError {
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 5, 4),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    tls_certificate_error: Some(NodeKeysError {
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 5, 4),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    dkg_dealing_encryption_key_error: Some(NodeKeysError {
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 5, 4),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    idkg_dealing_encryption_key_error: Some(NodeKeysError {
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 5, 4),
            },
        ];

        for (i, test) in tests.iter().enumerate() {
            assert_eq!(
                KeyCounts::from(&test.input),
                test.expected,
                "for ParameterizedTest #{}: {:?}",
                i,
                &test
            );
        }
    }

    #[test]
    fn should_collect_key_counts_for_single_local_key_pair_error() {
        let tests = vec![
            ParameterizedTest {
                input: NodeKeysErrors {
                    node_signing_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::NotFound),
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 4, 4),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    committee_signing_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::NotFound),
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 4, 4),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    tls_certificate_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::NotFound),
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 4, 4),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    dkg_dealing_encryption_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::NotFound),
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 4, 4),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    idkg_dealing_encryption_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::NotFound),
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 4, 4),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    node_signing_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 4, 4),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    committee_signing_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 4, 4),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    tls_certificate_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 4, 4),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    dkg_dealing_encryption_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 4, 4),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    idkg_dealing_encryption_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 4, 4),
            },
        ];

        for (i, test) in tests.iter().enumerate() {
            assert_eq!(
                KeyCounts::from(&test.input),
                test.expected,
                "for ParameterizedTest #{}: {:?}",
                i,
                &test
            );
        }
    }

    #[test]
    fn should_collect_key_counts_for_single_external_malformed_key() {
        let tests = [
            ParameterizedTest {
                input: NodeKeysErrors {
                    node_signing_key_error: Some(NodeKeysError {
                        external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                            "malformed external public key".to_string(),
                        ))),
                        local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                        secret_key_error: Some(SecretKeyError::CannotComputeKeyId),
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(4, 4, 4),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    committee_signing_key_error: Some(NodeKeysError {
                        external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                            "malformed external public key".to_string(),
                        ))),
                        local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                        secret_key_error: Some(SecretKeyError::CannotComputeKeyId),
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(4, 4, 4),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    tls_certificate_error: Some(NodeKeysError {
                        external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                            "malformed external public key".to_string(),
                        ))),
                        local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                        secret_key_error: Some(SecretKeyError::CannotComputeKeyId),
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(4, 4, 4),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    dkg_dealing_encryption_key_error: Some(NodeKeysError {
                        external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                            "malformed external public key".to_string(),
                        ))),
                        local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                        secret_key_error: Some(SecretKeyError::CannotComputeKeyId),
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(4, 4, 4),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    idkg_dealing_encryption_key_error: Some(NodeKeysError {
                        external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                            "malformed external public key".to_string(),
                        ))),
                        local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                        secret_key_error: Some(SecretKeyError::CannotComputeKeyId),
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(4, 4, 4),
            },
        ];

        for (i, test) in tests.iter().enumerate() {
            assert_eq!(
                KeyCounts::from(&test.input),
                test.expected,
                "for ParameterizedTest #{}: {:?}",
                i,
                &test
            );
        }
    }

    #[test]
    fn should_collect_key_counts_for_increasing_number_of_single_key_type_errors() {
        let tests = vec![
            ParameterizedTest {
                input: NodeKeysErrors {
                    node_signing_key_error: Some(NodeKeysError {
                        external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                            "external public key error".to_string(),
                        ))),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(4, 5, 5),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    node_signing_key_error: Some(NodeKeysError {
                        external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                            "external public key error".to_string(),
                        ))),
                        ..NodeKeysError::no_error()
                    }),
                    committee_signing_key_error: Some(NodeKeysError {
                        external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                            "external public key error".to_string(),
                        ))),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(3, 5, 5),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    node_signing_key_error: Some(NodeKeysError {
                        external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                            "external public key error".to_string(),
                        ))),
                        ..NodeKeysError::no_error()
                    }),
                    committee_signing_key_error: Some(NodeKeysError {
                        external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                            "external public key error".to_string(),
                        ))),
                        ..NodeKeysError::no_error()
                    }),
                    tls_certificate_error: Some(NodeKeysError {
                        external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                            "external public key error".to_string(),
                        ))),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(2, 5, 5),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    node_signing_key_error: Some(NodeKeysError {
                        external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                            "external public key error".to_string(),
                        ))),
                        ..NodeKeysError::no_error()
                    }),
                    committee_signing_key_error: Some(NodeKeysError {
                        external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                            "external public key error".to_string(),
                        ))),
                        ..NodeKeysError::no_error()
                    }),
                    tls_certificate_error: Some(NodeKeysError {
                        external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                            "external public key error".to_string(),
                        ))),
                        ..NodeKeysError::no_error()
                    }),
                    dkg_dealing_encryption_key_error: Some(NodeKeysError {
                        external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                            "external public key error".to_string(),
                        ))),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(1, 5, 5),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    node_signing_key_error: Some(NodeKeysError {
                        external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                            "external public key error".to_string(),
                        ))),
                        ..NodeKeysError::no_error()
                    }),
                    committee_signing_key_error: Some(NodeKeysError {
                        external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                            "external public key error".to_string(),
                        ))),
                        ..NodeKeysError::no_error()
                    }),
                    tls_certificate_error: Some(NodeKeysError {
                        external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                            "external public key error".to_string(),
                        ))),
                        ..NodeKeysError::no_error()
                    }),
                    dkg_dealing_encryption_key_error: Some(NodeKeysError {
                        external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                            "external public key error".to_string(),
                        ))),
                        ..NodeKeysError::no_error()
                    }),
                    idkg_dealing_encryption_key_error: Some(NodeKeysError {
                        external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                            "external public key error".to_string(),
                        ))),
                        ..NodeKeysError::no_error()
                    }),
                },
                expected: KeyCounts::new(0, 5, 5),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    node_signing_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 4, 5),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    node_signing_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    committee_signing_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 3, 5),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    node_signing_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    committee_signing_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    tls_certificate_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 2, 5),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    node_signing_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    committee_signing_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    tls_certificate_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    dkg_dealing_encryption_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 1, 5),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    node_signing_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    committee_signing_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    tls_certificate_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    dkg_dealing_encryption_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    idkg_dealing_encryption_key_error: Some(NodeKeysError {
                        local_public_key_error: Some(LocalPublicKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                },
                expected: KeyCounts::new(5, 0, 5),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    node_signing_key_error: Some(NodeKeysError {
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 5, 4),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    node_signing_key_error: Some(NodeKeysError {
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    committee_signing_key_error: Some(NodeKeysError {
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 5, 3),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    node_signing_key_error: Some(NodeKeysError {
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    committee_signing_key_error: Some(NodeKeysError {
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    tls_certificate_error: Some(NodeKeysError {
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 5, 2),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    node_signing_key_error: Some(NodeKeysError {
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    committee_signing_key_error: Some(NodeKeysError {
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    tls_certificate_error: Some(NodeKeysError {
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    dkg_dealing_encryption_key_error: Some(NodeKeysError {
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    ..NodeKeysErrors::no_error()
                },
                expected: KeyCounts::new(5, 5, 1),
            },
            ParameterizedTest {
                input: NodeKeysErrors {
                    node_signing_key_error: Some(NodeKeysError {
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    committee_signing_key_error: Some(NodeKeysError {
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    tls_certificate_error: Some(NodeKeysError {
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    dkg_dealing_encryption_key_error: Some(NodeKeysError {
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                    idkg_dealing_encryption_key_error: Some(NodeKeysError {
                        secret_key_error: Some(SecretKeyError::NotFound),
                        ..NodeKeysError::no_error()
                    }),
                },
                expected: KeyCounts::new(5, 5, 0),
            },
        ];

        for (i, test) in tests.iter().enumerate() {
            assert_eq!(
                KeyCounts::from(&test.input),
                test.expected,
                "for ParameterizedTest #{}: {:?}",
                i,
                &test
            );
        }
    }
}
