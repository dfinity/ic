use super::*;
use crate::common::test_utils::crypto_component::crypto_component_with_csp_and_vault;
use assert_matches::assert_matches;
use ic_base_types::SubnetId;
use ic_base_types::{NodeId, PrincipalId};
use ic_crypto_internal_csp::api::CspCreateMEGaKeyError;
use ic_crypto_internal_csp::vault::api::ExternalPublicKeyError;
use ic_crypto_internal_csp::vault::api::LocalPublicKeyError;
use ic_crypto_internal_csp::vault::api::NodeKeysError;
use ic_crypto_internal_csp::vault::api::NodeKeysErrors;
use ic_crypto_internal_csp::vault::api::PksAndSksContainsErrors;
use ic_crypto_internal_csp::vault::api::SecretKeyError;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_internal_threshold_sig_canister_threshold_sig::MEGaPublicKey;
use ic_crypto_temp_crypto::EcdsaSubnetConfig;
use ic_crypto_test_utils_csp::MockAllCryptoServiceProvider;
use ic_crypto_test_utils_keys::public_keys::{
    valid_committee_signing_public_key, valid_dkg_dealing_encryption_public_key,
    valid_idkg_dealing_encryption_public_key, valid_node_signing_public_key,
    valid_tls_certificate_and_validation_time,
};
use ic_crypto_test_utils_local_csp_vault::MockLocalCspVault;
use ic_crypto_test_utils_metrics::assertions::MetricsObservationsAssert;
use ic_interfaces::crypto::KeyManager;
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_registry_mocks::MockRegistryClient;
use ic_logger::ReplicaLogger;
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::subnet::v1::SubnetListRecord;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::make_subnet_list_record_key;
use ic_registry_keys::make_subnet_record_key;
use ic_registry_keys::{make_crypto_node_key, make_crypto_tls_cert_key};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_test_utilities_in_memory_logger::InMemoryReplicaLogger;
use ic_test_utilities_in_memory_logger::assertions::LogEntriesAssert;
use ic_test_utilities_time::FastForwardTimeSource;
use ic_types::{RegistryVersion, crypto::KeyPurpose};
use slog::Level;
use std::sync::Arc;

const ALL_KEYS_PRESENT: u8 = 5;
const UNEXPECTED_NUM_KEYS: u32 = 42;
const REGISTRY_VERSION_1: RegistryVersion = RegistryVersion::new(1);
const NODE_ID: u64 = 42;

mod check_keys_with_registry {
    use super::*;

    mod crypto_key_counts {
        use super::*;

        #[test]
        fn should_collect_key_count_metrics_for_all_keys() {
            let setup = Setup::builder()
                .with_registry_public_keys(valid_current_node_public_keys())
                .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
                .with_csp_pks_and_sks_contains_result(Ok(()))
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_crypto_key_counts(
                    ALL_KEYS_PRESENT,
                    ALL_KEYS_PRESENT,
                    ALL_KEYS_PRESENT,
                    MetricsResult::Ok,
                )
                .contains_crypto_idkg_dealing_encryption_pubkey_count(1, MetricsResult::Ok);
        }

        #[test]
        fn should_collect_key_count_metrics_for_transient_error_calling_pks_and_sks_contains() {
            let setup = Setup::builder()
                .with_registry_public_keys(valid_current_node_public_keys())
                .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
                .with_csp_pks_and_sks_contains_result(Err(
                    PksAndSksContainsErrors::TransientInternalError(
                        "error calling remote csp vault".to_string(),
                    ),
                ))
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_crypto_key_counts(0, 0, 0, MetricsResult::Err)
                .contains_crypto_idkg_dealing_encryption_pubkey_count(1, MetricsResult::Ok);
        }

        #[test]
        fn should_collect_key_count_metrics_for_node_signing_secret_key_not_found() {
            let setup = Setup::builder()
                .with_registry_public_keys(valid_current_node_public_keys())
                .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
                .with_csp_pks_and_sks_contains_result(Err(PksAndSksContainsErrors::NodeKeysErrors(
                    NodeKeysErrors {
                        node_signing_key_error: Some(NodeKeysError {
                            secret_key_error: Some(SecretKeyError::NotFound),
                            ..NodeKeysError::no_error()
                        }),
                        ..NodeKeysErrors::no_error()
                    },
                )))
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_crypto_key_counts(
                    ALL_KEYS_PRESENT,
                    ALL_KEYS_PRESENT,
                    ALL_KEYS_PRESENT - 1,
                    MetricsResult::Ok,
                )
                .contains_crypto_idkg_dealing_encryption_pubkey_count(1, MetricsResult::Ok);
        }

        #[test]
        fn should_collect_key_count_metrics_for_node_signing_public_key_mismatch() {
            let setup = Setup::builder()
                .with_registry_public_keys(valid_current_node_public_keys())
                .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
                .with_csp_pks_and_sks_contains_result(Err(PksAndSksContainsErrors::NodeKeysErrors(
                    NodeKeysErrors {
                        node_signing_key_error: Some(NodeKeysError {
                            local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                            ..NodeKeysError::no_error()
                        }),
                        ..NodeKeysErrors::no_error()
                    },
                )))
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_crypto_key_counts(
                    ALL_KEYS_PRESENT,
                    ALL_KEYS_PRESENT - 1,
                    ALL_KEYS_PRESENT,
                    MetricsResult::Ok,
                )
                .contains_crypto_idkg_dealing_encryption_pubkey_count(1, MetricsResult::Ok);
        }

        #[test]
        fn should_collect_key_count_metrics_for_node_signing_public_key_mismatch_and_secret_key_missing()
         {
            let setup = Setup::builder()
                .with_registry_public_keys(valid_current_node_public_keys())
                .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
                .with_csp_pks_and_sks_contains_result(Err(PksAndSksContainsErrors::NodeKeysErrors(
                    NodeKeysErrors {
                        node_signing_key_error: Some(NodeKeysError {
                            local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                            secret_key_error: Some(SecretKeyError::NotFound),
                            ..NodeKeysError::no_error()
                        }),
                        ..NodeKeysErrors::no_error()
                    },
                )))
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_crypto_key_counts(
                    ALL_KEYS_PRESENT,
                    ALL_KEYS_PRESENT - 1,
                    ALL_KEYS_PRESENT - 1,
                    MetricsResult::Ok,
                )
                .contains_crypto_idkg_dealing_encryption_pubkey_count(1, MetricsResult::Ok);
        }

        #[test]
        fn should_collect_key_count_metrics_for_node_signing_public_key_cannot_compute_key_id() {
            let setup = Setup::builder()
                .with_registry_public_keys(valid_current_node_public_keys())
                .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
                .with_csp_pks_and_sks_contains_result(Err(PksAndSksContainsErrors::NodeKeysErrors(
                    NodeKeysErrors {
                        node_signing_key_error: Some(NodeKeysError {
                            secret_key_error: Some(SecretKeyError::CannotComputeKeyId),
                            ..NodeKeysError::no_error()
                        }),
                        ..NodeKeysErrors::no_error()
                    },
                )))
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_crypto_key_counts(
                    ALL_KEYS_PRESENT,
                    ALL_KEYS_PRESENT,
                    ALL_KEYS_PRESENT - 1,
                    MetricsResult::Ok,
                )
                .contains_crypto_idkg_dealing_encryption_pubkey_count(1, MetricsResult::Ok);
        }

        #[test]
        fn should_collect_key_count_metrics_for_idkg_dealing_encryption_public_key_mismatch_secret_key_missing()
         {
            let setup = Setup::builder()
                .with_registry_public_keys(valid_current_node_public_keys())
                .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
                .with_csp_pks_and_sks_contains_result(Err(PksAndSksContainsErrors::NodeKeysErrors(
                    NodeKeysErrors {
                        idkg_dealing_encryption_key_error: Some(NodeKeysError {
                            local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                            secret_key_error: Some(SecretKeyError::NotFound),
                            ..NodeKeysError::no_error()
                        }),
                        ..NodeKeysErrors::no_error()
                    },
                )))
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_crypto_key_counts(
                    ALL_KEYS_PRESENT,
                    ALL_KEYS_PRESENT - 1,
                    ALL_KEYS_PRESENT - 1,
                    MetricsResult::Ok,
                )
                .contains_crypto_idkg_dealing_encryption_pubkey_count(1, MetricsResult::Ok);
        }

        #[test]
        fn should_count_multiple_idkg_dealing_encryption_keys() {
            let setup = Setup::builder()
                .with_registry_public_keys(valid_current_node_public_keys())
                .with_csp_pks_and_sks_contains_result(Ok(()))
                .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(2))
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_crypto_key_counts(
                    ALL_KEYS_PRESENT,
                    ALL_KEYS_PRESENT,
                    ALL_KEYS_PRESENT,
                    MetricsResult::Ok,
                )
                .contains_crypto_idkg_dealing_encryption_pubkey_count(2, MetricsResult::Ok);
        }

        #[test]
        fn should_count_multiple_idkg_dealing_encryption_keys_with_vault_transient_error() {
            let setup = Setup::builder()
                .with_registry_public_keys(valid_current_node_public_keys())
                .with_csp_pks_and_sks_contains_result(Ok(()))
                .with_csp_idkg_dealing_encryption_public_keys_count_result(Err(
                    CspPublicKeyStoreError::TransientInternalError(
                        "error calling remote csp vault".to_string(),
                    ),
                ))
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_crypto_key_counts(
                    ALL_KEYS_PRESENT,
                    ALL_KEYS_PRESENT,
                    ALL_KEYS_PRESENT,
                    MetricsResult::Ok,
                )
                .contains_crypto_idkg_dealing_encryption_pubkey_count(0, MetricsResult::Err);
        }

        #[test]
        fn should_observe_metrics_if_all_keys_present() {
            let setup = Setup::builder()
                .with_registry_public_keys(valid_current_node_public_keys())
                .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
                .with_csp_pks_and_sks_contains_result(Ok(()))
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_crypto_key_counts(
                    ALL_KEYS_PRESENT,
                    ALL_KEYS_PRESENT,
                    ALL_KEYS_PRESENT,
                    MetricsResult::Ok,
                )
                .contains_crypto_idkg_dealing_encryption_pubkey_count(1, MetricsResult::Ok);
        }

        #[test]
        fn should_observe_metrics_if_node_signing_public_key_missing_from_registry() {
            let registry_public_keys = CurrentNodePublicKeys {
                node_signing_public_key: None,
                ..valid_current_node_public_keys()
            };
            let setup = Setup::builder()
                .with_registry_public_keys(registry_public_keys)
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_crypto_key_counts(ALL_KEYS_PRESENT - 1, 0, 0, MetricsResult::Err);
        }

        #[test]
        fn should_observe_metrics_if_committee_signing_public_key_missing_from_registry() {
            let registry_public_keys = CurrentNodePublicKeys {
                committee_signing_public_key: None,
                ..valid_current_node_public_keys()
            };
            let setup = Setup::builder()
                .with_registry_public_keys(registry_public_keys)
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_crypto_key_counts(ALL_KEYS_PRESENT - 1, 0, 0, MetricsResult::Err);
        }

        #[test]
        fn should_observe_metrics_if_tls_certificate_missing_from_registry() {
            let registry_public_keys = CurrentNodePublicKeys {
                tls_certificate: None,
                ..valid_current_node_public_keys()
            };
            let setup = Setup::builder()
                .with_registry_public_keys(registry_public_keys)
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_crypto_key_counts(ALL_KEYS_PRESENT - 1, 0, 0, MetricsResult::Err);
        }

        #[test]
        fn should_observe_metrics_if_dkg_dealing_encryption_public_key_missing_from_registry() {
            let registry_public_keys = CurrentNodePublicKeys {
                dkg_dealing_encryption_public_key: None,
                ..valid_current_node_public_keys()
            };
            let setup = Setup::builder()
                .with_registry_public_keys(registry_public_keys)
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_crypto_key_counts(ALL_KEYS_PRESENT - 1, 0, 0, MetricsResult::Err);
        }

        #[test]
        fn should_observe_metrics_if_idkg_dealing_encryption_public_key_missing_from_registry() {
            let registry_public_keys = CurrentNodePublicKeys {
                idkg_dealing_encryption_public_key: None,
                ..valid_current_node_public_keys()
            };
            let setup = Setup::builder()
                .with_registry_public_keys(registry_public_keys)
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_crypto_key_counts(ALL_KEYS_PRESENT - 1, 0, 0, MetricsResult::Err);
        }

        #[test]
        fn should_observe_metrics_for_node_signing_public_key_in_registry_but_missing_locally() {
            let setup = Setup::builder()
                .with_registry_public_keys(valid_current_node_public_keys())
                .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
                .with_csp_pks_and_sks_contains_result(Err(PksAndSksContainsErrors::NodeKeysErrors(
                    NodeKeysErrors {
                        node_signing_key_error: Some(NodeKeysError {
                            local_public_key_error: Some(LocalPublicKeyError::NotFound),
                            secret_key_error: Some(SecretKeyError::NotFound),
                            ..NodeKeysError::no_error()
                        }),
                        ..NodeKeysErrors::no_error()
                    },
                )))
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_crypto_key_counts(
                    ALL_KEYS_PRESENT,
                    ALL_KEYS_PRESENT - 1,
                    ALL_KEYS_PRESENT - 1,
                    MetricsResult::Ok,
                )
                .contains_crypto_idkg_dealing_encryption_pubkey_count(1, MetricsResult::Ok);
        }

        #[test]
        fn should_observe_metrics_for_committee_signing_public_key_in_registry_but_missing_locally()
        {
            let setup = Setup::builder()
                .with_registry_public_keys(valid_current_node_public_keys())
                .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
                .with_csp_pks_and_sks_contains_result(Err(PksAndSksContainsErrors::NodeKeysErrors(
                    NodeKeysErrors {
                        committee_signing_key_error: Some(NodeKeysError {
                            local_public_key_error: Some(LocalPublicKeyError::NotFound),
                            secret_key_error: Some(SecretKeyError::NotFound),
                            ..NodeKeysError::no_error()
                        }),
                        ..NodeKeysErrors::no_error()
                    },
                )))
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_crypto_key_counts(
                    ALL_KEYS_PRESENT,
                    ALL_KEYS_PRESENT - 1,
                    ALL_KEYS_PRESENT - 1,
                    MetricsResult::Ok,
                )
                .contains_crypto_idkg_dealing_encryption_pubkey_count(1, MetricsResult::Ok);
        }

        #[test]
        fn should_observe_metrics_for_tls_certificate_in_registry_but_missing_locally() {
            let setup = Setup::builder()
                .with_registry_public_keys(valid_current_node_public_keys())
                .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
                .with_csp_pks_and_sks_contains_result(Err(PksAndSksContainsErrors::NodeKeysErrors(
                    NodeKeysErrors {
                        tls_certificate_error: Some(NodeKeysError {
                            local_public_key_error: Some(LocalPublicKeyError::NotFound),
                            secret_key_error: Some(SecretKeyError::NotFound),
                            ..NodeKeysError::no_error()
                        }),
                        ..NodeKeysErrors::no_error()
                    },
                )))
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_crypto_key_counts(
                    ALL_KEYS_PRESENT,
                    ALL_KEYS_PRESENT - 1,
                    ALL_KEYS_PRESENT - 1,
                    MetricsResult::Ok,
                )
                .contains_crypto_idkg_dealing_encryption_pubkey_count(1, MetricsResult::Ok);
        }

        #[test]
        fn should_observe_metrics_for_dkg_dealing_encryption_public_key_in_registry_but_missing_locally()
         {
            let setup = Setup::builder()
                .with_registry_public_keys(valid_current_node_public_keys())
                .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
                .with_csp_pks_and_sks_contains_result(Err(PksAndSksContainsErrors::NodeKeysErrors(
                    NodeKeysErrors {
                        dkg_dealing_encryption_key_error: Some(NodeKeysError {
                            local_public_key_error: Some(LocalPublicKeyError::NotFound),
                            secret_key_error: Some(SecretKeyError::NotFound),
                            ..NodeKeysError::no_error()
                        }),
                        ..NodeKeysErrors::no_error()
                    },
                )))
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_crypto_key_counts(
                    ALL_KEYS_PRESENT,
                    ALL_KEYS_PRESENT - 1,
                    ALL_KEYS_PRESENT - 1,
                    MetricsResult::Ok,
                )
                .contains_crypto_idkg_dealing_encryption_pubkey_count(1, MetricsResult::Ok);
        }

        #[test]
        fn should_observe_metrics_for_idkg_dealing_encryption_public_key_in_registry_but_missing_locally()
         {
            let setup = Setup::builder()
                .with_registry_public_keys(valid_current_node_public_keys())
                .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
                .with_csp_pks_and_sks_contains_result(Err(PksAndSksContainsErrors::NodeKeysErrors(
                    NodeKeysErrors {
                        idkg_dealing_encryption_key_error: Some(NodeKeysError {
                            local_public_key_error: Some(LocalPublicKeyError::NotFound),
                            secret_key_error: Some(SecretKeyError::NotFound),
                            ..NodeKeysError::no_error()
                        }),
                        ..NodeKeysErrors::no_error()
                    },
                )))
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_crypto_key_counts(
                    ALL_KEYS_PRESENT,
                    ALL_KEYS_PRESENT - 1,
                    ALL_KEYS_PRESENT - 1,
                    MetricsResult::Ok,
                )
                .contains_crypto_idkg_dealing_encryption_pubkey_count(1, MetricsResult::Ok);
        }
    }

    mod logs {
        use super::*;

        #[test]
        fn should_not_log_a_warning_if_all_keys_present() {
            let in_memory_logger = InMemoryReplicaLogger::new();
            let setup = Setup::builder()
                .with_registry_public_keys(valid_current_node_public_keys())
                .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
                .with_csp_pks_and_sks_contains_result(Ok(()))
                .with_logger(&in_memory_logger)
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            let logs = in_memory_logger.drain_logs();
            LogEntriesAssert::assert_that(logs).has_len(0);
        }

        #[test]
        fn should_log_a_warning_if_not_all_keys_present() {
            let in_memory_logger = InMemoryReplicaLogger::new();
            let setup = Setup::builder()
                .with_registry_public_keys(valid_current_node_public_keys())
                .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
                .with_csp_pks_and_sks_contains_result(Err(PksAndSksContainsErrors::NodeKeysErrors(
                    NodeKeysErrors {
                        node_signing_key_error: Some(NodeKeysError {
                            local_public_key_error: Some(LocalPublicKeyError::NotFound),
                            secret_key_error: Some(SecretKeyError::NotFound),
                            ..NodeKeysError::no_error()
                        }),
                        ..NodeKeysErrors::no_error()
                    },
                )))
                .with_logger(&in_memory_logger)
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            let logs = in_memory_logger.drain_logs();
            LogEntriesAssert::assert_that(logs)
                .has_len(2)
                .has_only_one_message_containing(
                    &Level::Warning,
                    "error while checking keys with registry",
                );
        }
    }

    mod alerts {
        use super::*;

        #[derive(Debug)]
        struct ParameterizedTest<U> {
            input: U,
        }

        #[test]
        fn should_raise_alert_on_local_key_errors() {
            let tests = vec![
                ParameterizedTest {
                    input: NodeKeysErrors {
                        node_signing_key_error: Some(NodeKeysError {
                            local_public_key_error: Some(LocalPublicKeyError::NotFound),
                            ..NodeKeysError::no_error()
                        }),
                        ..NodeKeysErrors::no_error()
                    },
                },
                ParameterizedTest {
                    input: NodeKeysErrors {
                        committee_signing_key_error: Some(NodeKeysError {
                            local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                            ..NodeKeysError::no_error()
                        }),
                        ..NodeKeysErrors::no_error()
                    },
                },
                ParameterizedTest {
                    input: NodeKeysErrors {
                        tls_certificate_error: Some(NodeKeysError {
                            local_public_key_error: Some(LocalPublicKeyError::NotFound),
                            ..NodeKeysError::no_error()
                        }),
                        ..NodeKeysErrors::no_error()
                    },
                },
                ParameterizedTest {
                    input: NodeKeysErrors {
                        dkg_dealing_encryption_key_error: Some(NodeKeysError {
                            local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                            ..NodeKeysError::no_error()
                        }),
                        ..NodeKeysErrors::no_error()
                    },
                },
                ParameterizedTest {
                    input: NodeKeysErrors {
                        idkg_dealing_encryption_key_error: Some(NodeKeysError {
                            local_public_key_error: Some(LocalPublicKeyError::NotFound),
                            ..NodeKeysError::no_error()
                        }),
                        ..NodeKeysErrors::no_error()
                    },
                },
                ParameterizedTest {
                    input: NodeKeysErrors {
                        node_signing_key_error: Some(NodeKeysError {
                            secret_key_error: Some(SecretKeyError::CannotComputeKeyId),
                            ..NodeKeysError::no_error()
                        }),
                        ..NodeKeysErrors::no_error()
                    },
                },
                ParameterizedTest {
                    input: NodeKeysErrors {
                        committee_signing_key_error: Some(NodeKeysError {
                            secret_key_error: Some(SecretKeyError::NotFound),
                            ..NodeKeysError::no_error()
                        }),
                        ..NodeKeysErrors::no_error()
                    },
                },
                ParameterizedTest {
                    input: NodeKeysErrors {
                        tls_certificate_error: Some(NodeKeysError {
                            secret_key_error: Some(SecretKeyError::CannotComputeKeyId),
                            ..NodeKeysError::no_error()
                        }),
                        ..NodeKeysErrors::no_error()
                    },
                },
                ParameterizedTest {
                    input: NodeKeysErrors {
                        dkg_dealing_encryption_key_error: Some(NodeKeysError {
                            secret_key_error: Some(SecretKeyError::NotFound),
                            ..NodeKeysError::no_error()
                        }),
                        ..NodeKeysErrors::no_error()
                    },
                },
                ParameterizedTest {
                    input: NodeKeysErrors {
                        idkg_dealing_encryption_key_error: Some(NodeKeysError {
                            secret_key_error: Some(SecretKeyError::CannotComputeKeyId),
                            ..NodeKeysError::no_error()
                        }),
                        ..NodeKeysErrors::no_error()
                    },
                },
                ParameterizedTest {
                    input: NodeKeysErrors {
                        idkg_dealing_encryption_key_error: Some(NodeKeysError {
                            local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                            secret_key_error: Some(SecretKeyError::CannotComputeKeyId),
                            ..NodeKeysError::no_error()
                        }),
                        ..NodeKeysErrors::no_error()
                    },
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
                },
            ];

            for test in tests {
                let setup = Setup::builder()
                    .with_registry_public_keys(valid_current_node_public_keys())
                    .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
                    .with_csp_pks_and_sks_contains_result(Err(
                        PksAndSksContainsErrors::NodeKeysErrors(test.input.clone()),
                    ))
                    .build();

                let _check_keys_with_registry_result = setup
                    .crypto
                    .check_keys_with_registry(setup.registry_client.get_latest_version());

                MetricsObservationsAssert::assert_that(setup.metrics_registry)
                    .contains_keys_missing_locally_alert_metrics(1);
            }
        }

        #[test]
        fn should_raise_no_alert_when_all_keys_present() {
            let setup = Setup::builder()
                .with_registry_public_keys(valid_current_node_public_keys())
                .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
                .with_csp_pks_and_sks_contains_result(Ok(()))
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_keys_missing_locally_alert_metrics(0);
        }

        #[test]
        fn should_raise_no_alert_when_registry_idkg_dealing_encryption_public_key_is_malformed() {
            let setup = Setup::builder()
                .with_registry_public_keys(valid_current_node_public_keys())
                .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
                .with_csp_pks_and_sks_contains_result(Err(PksAndSksContainsErrors::NodeKeysErrors(
                    NodeKeysErrors {
                        idkg_dealing_encryption_key_error: Some(NodeKeysError {
                            external_public_key_error: Some(ExternalPublicKeyError(Box::new(
                                "Malformed iDKG dealing encryption public key".to_string(),
                            ))),
                            ..NodeKeysError::no_error()
                        }),
                        ..NodeKeysErrors::no_error()
                    },
                )))
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_keys_missing_locally_alert_metrics(0);
        }
    }

    #[test]
    fn should_return_all_keys_registered_if_all_keys_present() {
        let setup = Setup::builder()
            .with_registry_public_keys(valid_current_node_public_keys())
            .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
            .with_csp_pks_and_sks_contains_result(Ok(()))
            .build();

        assert_matches!(
            setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version()),
            Ok(())
        );
    }

    #[test]
    fn should_fail_with_public_key_not_found_if_node_signing_public_key_missing_from_registry() {
        let registry_public_keys = CurrentNodePublicKeys {
            node_signing_public_key: None,
            ..valid_current_node_public_keys()
        };
        let setup = Setup::builder()
            .with_registry_public_keys(registry_public_keys)
            .build();

        let expected_node_id = node_id();
        assert_matches!(
            setup.crypto.check_keys_with_registry(setup.registry_client.get_latest_version()),
            Err(CheckKeysWithRegistryError::PublicKeyNotFound {
                node_id,
                key_purpose,
                registry_version,
            }) if node_id == expected_node_id && key_purpose == KeyPurpose::NodeSigning && registry_version == REGISTRY_VERSION_1
        );
    }

    #[test]
    fn should_fail_with_public_key_not_found_if_committee_signing_public_key_missing_from_registry()
    {
        let registry_public_keys = CurrentNodePublicKeys {
            committee_signing_public_key: None,
            ..valid_current_node_public_keys()
        };
        let setup = Setup::builder()
            .with_registry_public_keys(registry_public_keys)
            .build();

        let expected_node_id = node_id();
        assert_matches!(
            setup.crypto.check_keys_with_registry(setup.registry_client.get_latest_version()),
            Err(CheckKeysWithRegistryError::PublicKeyNotFound {
                node_id,
                key_purpose,
                registry_version,
            }) if node_id == expected_node_id && key_purpose == KeyPurpose::CommitteeSigning && registry_version == REGISTRY_VERSION_1
        );
    }

    #[test]
    fn should_fail_with_cert_key_not_found_if_tls_certificate_missing_from_registry() {
        let registry_public_keys = CurrentNodePublicKeys {
            tls_certificate: None,
            ..valid_current_node_public_keys()
        };
        let setup = Setup::builder()
            .with_registry_public_keys(registry_public_keys)
            .build();

        let expected_node_id = node_id();
        assert_matches!(
            setup.crypto.check_keys_with_registry(setup.registry_client.get_latest_version()),
            Err(CheckKeysWithRegistryError::TlsCertNotFound {
                node_id,
                registry_version,
            }) if node_id == expected_node_id && registry_version == REGISTRY_VERSION_1
        );
    }

    #[test]
    fn should_fail_with_public_key_not_found_if_dkg_dealing_encryption_public_key_missing_from_registry()
     {
        let registry_public_keys = CurrentNodePublicKeys {
            dkg_dealing_encryption_public_key: None,
            ..valid_current_node_public_keys()
        };
        let setup = Setup::builder()
            .with_registry_public_keys(registry_public_keys)
            .build();

        let expected_node_id = node_id();
        assert_matches!(
            setup.crypto.check_keys_with_registry(setup.registry_client.get_latest_version()),
            Err(CheckKeysWithRegistryError::PublicKeyNotFound {
                node_id,
                key_purpose,
                registry_version,
            }) if node_id == expected_node_id && key_purpose == KeyPurpose::DkgDealingEncryption && registry_version == REGISTRY_VERSION_1
        );
    }

    #[test]
    fn should_fail_with_public_key_not_found_if_idkg_dealing_encryption_public_key_missing_from_registry()
     {
        let registry_public_keys = CurrentNodePublicKeys {
            idkg_dealing_encryption_public_key: None,
            ..valid_current_node_public_keys()
        };
        let setup = Setup::builder()
            .with_registry_public_keys(registry_public_keys)
            .build();

        let expected_node_id = node_id();
        assert_matches!(
            setup.crypto.check_keys_with_registry(setup.registry_client.get_latest_version()),
            Err(CheckKeysWithRegistryError::PublicKeyNotFound {
                node_id,
                key_purpose,
                registry_version,
            }) if node_id == expected_node_id && key_purpose == KeyPurpose::IDkgMEGaEncryption && registry_version == REGISTRY_VERSION_1
        );
    }
}

mod rotate_idkg_dealing_encryption_keys {
    use super::*;
    use ic_crypto_internal_threshold_sig_canister_threshold_sig::EccCurveType;
    use ic_crypto_test_utils_keys::public_keys::valid_idkg_dealing_encryption_public_key_2;
    use ic_crypto_test_utils_keys::public_keys::valid_idkg_dealing_encryption_public_key_3;
    use ic_test_utilities_in_memory_logger::{InMemoryReplicaLogger, assertions::LogEntriesAssert};
    use slog::Level;

    const TWO_WEEKS: Duration = Duration::from_secs(2 * 7 * 24 * 60 * 60);

    #[test]
    fn should_return_public_key_not_found_error_when_no_idkg_public_key_available_locally() {
        let setup = Setup::builder()
            .with_csp_current_node_public_keys_result(Ok(CurrentNodePublicKeys {
                idkg_dealing_encryption_public_key: None,
                ..valid_current_node_public_keys()
            }))
            .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
                subnet_id(),
                Some(node_id()),
                Some(TWO_WEEKS),
            ))
            .with_registry_public_keys(valid_current_node_public_keys())
            .build();

        let rotate_idkg_dealing_encryption_keys_result = setup
            .crypto
            .rotate_idkg_dealing_encryption_keys(setup.registry_client.get_latest_version());
        assert_matches!(
            rotate_idkg_dealing_encryption_keys_result,
            Err(IDkgDealingEncryptionKeyRotationError::PublicKeyNotFound)
        );
    }

    #[test]
    fn should_return_current_idkg_public_key_when_other_key_in_registry() {
        let local_public_keys = valid_current_node_public_keys();
        let registry_public_keys = CurrentNodePublicKeys {
            idkg_dealing_encryption_public_key: Some(valid_idkg_dealing_encryption_public_key_2()),
            ..valid_current_node_public_keys()
        };
        assert_ne!(local_public_keys, registry_public_keys);
        let setup = Setup::builder()
            .with_csp_current_node_public_keys_result(Ok(local_public_keys.clone()))
            .with_csp_current_node_public_keys_with_timestamps_result(Ok(
                valid_current_node_public_keys_with_timestamps(),
            ))
            .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
                subnet_id(),
                Some(node_id()),
                Some(TWO_WEEKS),
            ))
            .with_registry_public_keys(registry_public_keys)
            .build();

        let key_to_register = setup
            .crypto
            .rotate_idkg_dealing_encryption_keys(setup.registry_client.get_latest_version());
        assert_matches!(
            key_to_register,
            Ok(IDkgKeyRotationResult::IDkgDealingEncPubkeyNeedsRegistration(KeyRotationOutcome::KeyNotRotated {existing_key}))
            if existing_key.equal_ignoring_timestamp(
                &local_public_keys.idkg_dealing_encryption_public_key.expect(
                    "no local idkg dealing encryption public key"))
        );
    }

    #[test]
    fn should_rotate_idkg_public_key_when_key_from_registry_does_not_have_timestamp() {
        let new_local_idkg_dealing_encryption_public_key =
            valid_idkg_dealing_encryption_public_key_2();
        let setup = Setup::builder()
            .with_registry_public_keys(valid_current_node_public_keys())
            .with_csp_current_node_public_keys_result(Ok(valid_current_node_public_keys()))
            .with_csp_current_node_public_keys_with_timestamps_result(Ok(
                valid_current_node_public_keys_with_timestamps(),
            ))
            .with_csp_idkg_gen_dealing_encryption_key_pair_result(Ok(
                deserialize_mega_public_key_or_panic(&new_local_idkg_dealing_encryption_public_key),
            ))
            .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
                subnet_id(),
                Some(node_id()),
                Some(TWO_WEEKS),
            ))
            .build();

        let rotate_idkg_dealing_encryption_keys_result = setup
            .crypto
            .rotate_idkg_dealing_encryption_keys(setup.registry_client.get_latest_version());

        assert_matches!(
            rotate_idkg_dealing_encryption_keys_result,
            Ok(IDkgKeyRotationResult::IDkgDealingEncPubkeyNeedsRegistration(KeyRotationOutcome::KeyRotated {new_key}))
            if new_key.equal_ignoring_timestamp(&new_local_idkg_dealing_encryption_public_key)
        );
    }

    #[test]
    fn should_not_rotate_key_when_last_rotation_too_recent() {
        let setup = Setup::builder()
            .with_registry_public_keys(valid_current_node_public_keys_with_timestamps())
            .with_csp_current_node_public_keys_result(Ok(valid_current_node_public_keys()))
            .with_csp_current_node_public_keys_with_timestamps_result(Ok(
                valid_current_node_public_keys_with_timestamps(),
            ))
            .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
                subnet_id(),
                Some(node_id()),
                Some(TWO_WEEKS),
            ))
            .build();

        let rotate_idkg_dealing_encryption_keys_result = setup
            .crypto
            .rotate_idkg_dealing_encryption_keys(setup.registry_client.get_latest_version());

        assert_matches!(
            rotate_idkg_dealing_encryption_keys_result,
            Ok(IDkgKeyRotationResult::LatestRotationTooRecent)
        );
    }

    #[test]
    fn should_not_rotate_key_when_local_key_too_old_but_not_in_registry() {
        let old_local_idkg_dealing_encryption_public_key =
            valid_idkg_dealing_encryption_public_key_2();
        let setup = Setup::builder()
            .with_registry_public_keys(valid_current_node_public_keys_with_timestamps())
            .with_csp_current_node_public_keys_result(Ok(CurrentNodePublicKeys {
                idkg_dealing_encryption_public_key: Some(
                    old_local_idkg_dealing_encryption_public_key.clone(),
                ),
                ..valid_current_node_public_keys()
            }))
            .with_csp_current_node_public_keys_with_timestamps_result(Ok(CurrentNodePublicKeys {
                idkg_dealing_encryption_public_key: Some(PublicKeyProto {
                    timestamp: Some(0),
                    ..old_local_idkg_dealing_encryption_public_key.clone()
                }),
                ..valid_current_node_public_keys_with_timestamps()
            }))
            .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
                subnet_id(),
                Some(node_id()),
                Some(TWO_WEEKS),
            ))
            .build();

        setup
            .time_source
            .advance_time(TWO_WEEKS + Duration::from_secs(1));

        let rotate_idkg_dealing_encryption_keys_result = setup
            .crypto
            .rotate_idkg_dealing_encryption_keys(setup.registry_client.get_latest_version());

        assert_matches!(
            rotate_idkg_dealing_encryption_keys_result,
            Ok(IDkgKeyRotationResult::IDkgDealingEncPubkeyNeedsRegistration(KeyRotationOutcome::KeyNotRotatedButTooOld {existing_key}))
            if existing_key.equal_ignoring_timestamp(&old_local_idkg_dealing_encryption_public_key)
        );
    }

    #[test]
    fn should_not_rotate_key_when_node_not_on_any_subnet() {
        let setup = Setup::builder().build();

        let rotate_idkg_dealing_encryption_keys_result = setup
            .crypto
            .rotate_idkg_dealing_encryption_keys(setup.registry_client.get_latest_version());

        assert_matches!(
            rotate_idkg_dealing_encryption_keys_result,
            Err(IDkgDealingEncryptionKeyRotationError::KeyRotationNotEnabled)
        );
    }

    #[test]
    fn should_not_rotate_key_when_node_not_on_ecdsa_subnet() {
        let setup = Setup::builder()
            .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
                subnet_id(),
                Some(NodeId::from(PrincipalId::new_node_test_id(182))),
                Some(TWO_WEEKS),
            ))
            .build();

        let rotate_idkg_dealing_encryption_keys_result = setup
            .crypto
            .rotate_idkg_dealing_encryption_keys(setup.registry_client.get_latest_version());

        assert_matches!(
            rotate_idkg_dealing_encryption_keys_result,
            Err(IDkgDealingEncryptionKeyRotationError::KeyRotationNotEnabled)
        );
    }

    #[test]
    fn should_not_rotate_key_when_key_rotation_period_not_set() {
        let setup = Setup::builder()
            .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(subnet_id(), Some(node_id()), None))
            .build();

        let rotate_idkg_dealing_encryption_keys_result = setup
            .crypto
            .rotate_idkg_dealing_encryption_keys(setup.registry_client.get_latest_version());

        assert_matches!(
            rotate_idkg_dealing_encryption_keys_result,
            Err(IDkgDealingEncryptionKeyRotationError::KeyRotationNotEnabled)
        );
    }

    #[test]
    fn should_not_rotate_key_when_no_ecdsa_config_exists() {
        let setup = Setup::builder()
            .with_ecdsa_subnet_config(EcdsaSubnetConfig::new_without_chain_key_config(
                subnet_id(),
                Some(node_id()),
            ))
            .build();

        let rotate_idkg_dealing_encryption_keys_result = setup
            .crypto
            .rotate_idkg_dealing_encryption_keys(setup.registry_client.get_latest_version());

        assert_matches!(
            rotate_idkg_dealing_encryption_keys_result,
            Err(IDkgDealingEncryptionKeyRotationError::KeyRotationNotEnabled)
        );
    }

    #[test]
    fn should_not_rotate_key_when_no_ecdsa_key_ids_configured() {
        let setup = Setup::builder()
            .with_ecdsa_subnet_config(EcdsaSubnetConfig::new_without_key_ids(
                subnet_id(),
                Some(node_id()),
                Some(TWO_WEEKS),
            ))
            .build();

        let rotate_idkg_dealing_encryption_keys_result = setup
            .crypto
            .rotate_idkg_dealing_encryption_keys(setup.registry_client.get_latest_version());

        assert_matches!(
            rotate_idkg_dealing_encryption_keys_result,
            Err(IDkgDealingEncryptionKeyRotationError::KeyRotationNotEnabled)
        );
    }

    #[test]
    fn should_rotate_if_keys_match_and_registry_key_is_too_old() {
        let setup = Setup::builder()
            .with_csp_current_node_public_keys_with_timestamps_result(Ok(
                valid_current_node_public_keys_with_timestamps(),
            ))
            .with_csp_current_node_public_keys_result(Ok(valid_current_node_public_keys()))
            .with_csp_idkg_gen_dealing_encryption_key_pair_result(Ok(
                deserialize_mega_public_key_or_panic(&valid_idkg_dealing_encryption_public_key_2()),
            ))
            .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
                subnet_id(),
                Some(node_id()),
                Some(TWO_WEEKS),
            ))
            .with_registry_public_keys(valid_current_node_public_keys_with_timestamps())
            .build();
        setup
            .time_source
            .advance_time(TWO_WEEKS + Duration::from_secs(1));

        let rotate_idkg_dealing_encryption_keys_result = setup
            .crypto
            .rotate_idkg_dealing_encryption_keys(setup.registry_client.get_latest_version());

        assert_matches!(
            rotate_idkg_dealing_encryption_keys_result,
            Ok(IDkgKeyRotationResult::IDkgDealingEncPubkeyNeedsRegistration(KeyRotationOutcome::KeyRotated {new_key}))
            if new_key.equal_ignoring_timestamp(&valid_idkg_dealing_encryption_public_key_2())
        );
    }

    #[test]
    fn should_return_error_when_registry_error() {
        const ERROR_STR: &str = "registry client poll lock failed!";
        let mut mock_registry_client = MockRegistryClient::new();
        mock_registry_client
            .expect_get_value()
            .returning(move |_, _| {
                Err(RegistryClientError::PollLockFailed {
                    error: ERROR_STR.to_string(),
                })
            });
        let arc_registry_client: Arc<dyn RegistryClient> = Arc::new(mock_registry_client);
        let setup = Setup::builder()
            .with_registry_client_override(arc_registry_client)
            .build();

        let rotate_idkg_dealing_encryption_keys_result = setup
            .crypto
            .rotate_idkg_dealing_encryption_keys(REGISTRY_VERSION_1);

        assert_matches!(
            rotate_idkg_dealing_encryption_keys_result,
            Err(IDkgDealingEncryptionKeyRotationError::RegistryClientError(
                RegistryClientError::PollLockFailed { error }
            )) if error.contains(ERROR_STR)
        );
    }

    #[test]
    fn should_return_transient_error_if_csp_fails_to_get_current_node_public_keys() {
        const ERROR_MSG: &str = "transient error getting current node public keys";
        let setup = Setup::builder()
            .with_csp_current_node_public_keys_result(Err(
                CspPublicKeyStoreError::TransientInternalError(ERROR_MSG.to_string()),
            ))
            .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
                subnet_id(),
                Some(node_id()),
                Some(TWO_WEEKS),
            ))
            .with_registry_public_keys(valid_current_node_public_keys_with_timestamps())
            .build();

        let rotate_idkg_dealing_encryption_keys_result = setup
            .crypto
            .rotate_idkg_dealing_encryption_keys(setup.registry_client.get_latest_version());

        assert_matches!(
            rotate_idkg_dealing_encryption_keys_result,
            Err(IDkgDealingEncryptionKeyRotationError::TransientInternalError(internal_error))
            if internal_error.contains(ERROR_MSG)
        );
    }

    #[test]
    fn should_return_transient_error_if_key_mismatch_then_latest_rotation_too_recent_with_retry() {
        use ic_crypto_test_utils_csp::MockAllCryptoServiceProvider;
        use ic_interfaces::crypto::KeyManager;
        use ic_protobuf::registry::subnet::v1::SubnetListRecord;
        use ic_registry_keys::{make_subnet_list_record_key, make_subnet_record_key};

        let mut vault = MockLocalCspVault::new();
        let mut counter = 0_u8;
        vault
            .expect_current_node_public_keys()
            .times(2)
            .returning(move || match counter {
                0 => {
                    counter += 1;
                    Ok(CurrentNodePublicKeys {
                        idkg_dealing_encryption_public_key: Some(
                            valid_idkg_dealing_encryption_public_key_2(),
                        ),
                        ..valid_current_node_public_keys()
                    })
                }
                1 => {
                    counter += 1;
                    Ok(valid_current_node_public_keys())
                }
                _ => panic!("current_node_public_keys called too many times!"),
            });
        vault
            .expect_current_node_public_keys_with_timestamps()
            .times(2)
            .return_const(Ok(valid_current_node_public_keys_with_timestamps()));

        let ecdsa_subnet_config =
            EcdsaSubnetConfig::new(subnet_id(), Some(node_id()), Some(TWO_WEEKS));

        let registry_data = Arc::new(ProtoRegistryDataProvider::new());

        let registry_client =
            Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));

        registry_data
            .add(
                make_subnet_record_key(ecdsa_subnet_config.subnet_id).as_str(),
                REGISTRY_VERSION_1,
                Some(ecdsa_subnet_config.subnet_record),
            )
            .expect("Failed to add subnet record key");
        registry_data
            .add(
                &make_crypto_node_key(node_id(), KeyPurpose::IDkgMEGaEncryption),
                REGISTRY_VERSION_1,
                Some(PublicKeyProto {
                    timestamp: Some(0),
                    ..valid_idkg_dealing_encryption_public_key()
                }),
            )
            .expect("Failed to add iDKG dealing encryption public key to registry");

        let subnet_list_record = SubnetListRecord {
            subnets: vec![ecdsa_subnet_config.subnet_id.get().into_vec()],
        };

        registry_data
            .add(
                make_subnet_list_record_key().as_str(),
                REGISTRY_VERSION_1,
                Some(subnet_list_record),
            )
            .expect("Failed to add subnet list record key");

        let time_source = FastForwardTimeSource::new();
        let crypto_component = CryptoComponentImpl::new_for_test(
            MockAllCryptoServiceProvider::new(),
            Arc::new(vault),
            no_op_logger(),
            registry_client.clone(),
            node_id(),
            Arc::new(CryptoMetrics::none()),
            Some(Arc::clone(&time_source) as Arc<_>),
        );
        registry_client.reload();

        let result = crypto_component.rotate_idkg_dealing_encryption_keys(REGISTRY_VERSION_1);

        assert_matches!(
            result,
            Err(IDkgDealingEncryptionKeyRotationError::TransientInternalError(details))
            if details == "Race condition: current_node_public_keys() and current_node_public_keys_with_timestamps() returned different iDKG dealing encryption public keys"
        );

        let retry_result = crypto_component.rotate_idkg_dealing_encryption_keys(REGISTRY_VERSION_1);
        assert_matches!(
            retry_result,
            Ok(IDkgKeyRotationResult::LatestRotationTooRecent)
        );
    }

    #[test]
    fn should_return_transient_error_if_key_mismatch_then_rotate_with_retry() {
        use ic_crypto_test_utils_csp::MockAllCryptoServiceProvider;
        use ic_interfaces::crypto::KeyManager;
        use ic_protobuf::registry::subnet::v1::SubnetListRecord;
        use ic_registry_keys::{make_subnet_list_record_key, make_subnet_record_key};

        let mut vault = MockLocalCspVault::new();
        let mut counter = 0_u8;
        vault
            .expect_current_node_public_keys()
            .times(2)
            .returning(move || match counter {
                0 => {
                    counter += 1;
                    Ok(CurrentNodePublicKeys {
                        idkg_dealing_encryption_public_key: Some(
                            valid_idkg_dealing_encryption_public_key_2(),
                        ),
                        ..valid_current_node_public_keys()
                    })
                }
                1 => {
                    counter += 1;
                    Ok(valid_current_node_public_keys())
                }
                _ => panic!("current_node_public_keys called too many times!"),
            });
        vault
            .expect_current_node_public_keys_with_timestamps()
            .times(2)
            .return_const(Ok(valid_current_node_public_keys_with_timestamps()));
        vault
            .expect_idkg_gen_dealing_encryption_key_pair()
            .times(1)
            .return_const(Ok(MEGaPublicKey::deserialize(
                EccCurveType::K256,
                &valid_idkg_dealing_encryption_public_key_3().key_value,
            )
            .expect("error deserializing MEGaPublicKey")));

        let ecdsa_subnet_config =
            EcdsaSubnetConfig::new(subnet_id(), Some(node_id()), Some(TWO_WEEKS));

        let registry_data = Arc::new(ProtoRegistryDataProvider::new());

        let registry_client =
            Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));

        registry_data
            .add(
                make_subnet_record_key(ecdsa_subnet_config.subnet_id).as_str(),
                REGISTRY_VERSION_1,
                Some(ecdsa_subnet_config.subnet_record),
            )
            .expect("Failed to add subnet record key");
        registry_data
            .add(
                &make_crypto_node_key(node_id(), KeyPurpose::IDkgMEGaEncryption),
                REGISTRY_VERSION_1,
                Some(valid_idkg_dealing_encryption_public_key()),
            )
            .expect("Failed to add iDKG dealing encryption public key to registry");

        let subnet_list_record = SubnetListRecord {
            subnets: vec![ecdsa_subnet_config.subnet_id.get().into_vec()],
        };

        registry_data
            .add(
                make_subnet_list_record_key().as_str(),
                REGISTRY_VERSION_1,
                Some(subnet_list_record),
            )
            .expect("Failed to add subnet list record key");

        let crypto_component = crypto_component_with_csp_and_vault(
            MockAllCryptoServiceProvider::new(),
            vault,
            registry_client.clone(),
        );

        registry_client.reload();

        let result = crypto_component.rotate_idkg_dealing_encryption_keys(REGISTRY_VERSION_1);

        assert_matches!(
            result,
            Err(IDkgDealingEncryptionKeyRotationError::TransientInternalError(details))
            if details == "Race condition: current_node_public_keys() and current_node_public_keys_with_timestamps() returned different iDKG dealing encryption public keys"
        );

        let retry_result = crypto_component.rotate_idkg_dealing_encryption_keys(REGISTRY_VERSION_1);
        assert_matches!(
            retry_result,
            Ok(IDkgKeyRotationResult::IDkgDealingEncPubkeyNeedsRegistration(KeyRotationOutcome::KeyRotated {new_key}))
            if new_key.equal_ignoring_timestamp(&valid_idkg_dealing_encryption_public_key_3())
        );
    }

    mod latest_key_exists_in_registry {
        use super::*;

        #[test]
        fn should_observe_metric_for_latest_local_key_exists_in_registry_if_keys_match_and_registry_key_has_no_timestamp()
         {
            let setup = crate::keygen::tests::Setup::builder()
                .with_registry_public_keys(valid_current_node_public_keys())
                .with_csp_current_node_public_keys_result(Ok(valid_current_node_public_keys()))
                .with_csp_current_node_public_keys_with_timestamps_result(Ok(
                    valid_current_node_public_keys_with_timestamps(),
                ))
                .with_csp_idkg_gen_dealing_encryption_key_pair_result(Ok(
                    deserialize_mega_public_key_or_panic(
                        &valid_idkg_dealing_encryption_public_key_2(),
                    ),
                ))
                .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
                    subnet_id(),
                    Some(node_id()),
                    Some(TWO_WEEKS),
                ))
                .build();

            let _rotate_idkg_dealing_encryption_keys_result = setup
                .crypto
                .rotate_idkg_dealing_encryption_keys(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_latest_key_exists_in_registry(true);
        }

        #[test]
        fn should_observe_latest_key_does_not_exist_in_registry_and_return_key_needs_registration_if_keys_do_not_match()
         {
            let mut registry_public_keys = valid_current_node_public_keys();
            if let Some(idkg_dealing_encryption_public_key) =
                &mut registry_public_keys.idkg_dealing_encryption_public_key
            {
                idkg_dealing_encryption_public_key.key_value = b"samesamebutdifferent".to_vec();
            }
            let setup = crate::keygen::tests::Setup::builder()
                .with_csp_current_node_public_keys_result(Ok(valid_current_node_public_keys()))
                .with_csp_current_node_public_keys_with_timestamps_result(Ok(
                    valid_current_node_public_keys_with_timestamps(),
                ))
                .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
                    subnet_id(),
                    Some(node_id()),
                    Some(TWO_WEEKS),
                ))
                .with_registry_public_keys(registry_public_keys)
                .build();

            let _rotate_idkg_dealing_encryption_keys_result = setup
                .crypto
                .rotate_idkg_dealing_encryption_keys(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_latest_key_exists_in_registry(false);
        }
    }

    mod latest_key_too_old_but_not_in_registry {
        use super::*;

        #[test]
        fn should_observe_metric_for_latest_local_key_too_old_but_still_not_in_registry() {
            let local_current_node_public_keys = CurrentNodePublicKeys {
                idkg_dealing_encryption_public_key: Some(PublicKeyProto {
                    key_value: b"local key not in registry".to_vec(),
                    timestamp: Some(0),
                    ..valid_idkg_dealing_encryption_public_key()
                }),
                ..valid_current_node_public_keys_with_timestamps()
            };
            let local_current_node_public_keys_with_timestamps = CurrentNodePublicKeys {
                idkg_dealing_encryption_public_key: Some(PublicKeyProto {
                    key_value: b"local key not in registry".to_vec(),
                    timestamp: Some(0),
                    ..valid_idkg_dealing_encryption_public_key()
                }),
                ..valid_current_node_public_keys_with_timestamps()
            };
            let setup = crate::keygen::tests::Setup::builder()
                .with_registry_public_keys(valid_current_node_public_keys())
                .with_csp_current_node_public_keys_result(Ok(local_current_node_public_keys))
                .with_csp_current_node_public_keys_with_timestamps_result(Ok(
                    local_current_node_public_keys_with_timestamps,
                ))
                .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
                    subnet_id(),
                    Some(node_id()),
                    Some(TWO_WEEKS),
                ))
                .build();

            setup
                .time_source
                .advance_time(TWO_WEEKS + Duration::from_secs(1));

            let _rotate_idkg_dealing_encryption_keys_result = setup
                .crypto
                .rotate_idkg_dealing_encryption_keys(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_key_too_old_but_not_in_registry(1);
        }
    }

    mod logs {
        use super::*;

        #[test]
        fn should_log_info_if_keys_match_and_registry_key_has_no_timestamp() {
            let in_memory_logger = InMemoryReplicaLogger::new();
            let setup = crate::keygen::tests::Setup::builder()
                .with_registry_public_keys(valid_current_node_public_keys())
                .with_csp_current_node_public_keys_result(Ok(valid_current_node_public_keys()))
                .with_csp_current_node_public_keys_with_timestamps_result(Ok(
                    valid_current_node_public_keys_with_timestamps(),
                ))
                .with_csp_idkg_gen_dealing_encryption_key_pair_result(Ok(
                    deserialize_mega_public_key_or_panic(
                        &valid_idkg_dealing_encryption_public_key_2(),
                    ),
                ))
                .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
                    subnet_id(),
                    Some(node_id()),
                    Some(TWO_WEEKS),
                ))
                .with_logger(&in_memory_logger)
                .build();

            let _rotate_idkg_dealing_encryption_keys_result = setup
                .crypto
                .rotate_idkg_dealing_encryption_keys(setup.registry_client.get_latest_version());

            let logs = in_memory_logger.drain_logs();
            LogEntriesAssert::assert_that(logs)
                .has_len(1)
                .has_only_one_message_containing(
                    &Level::Info,
                    "iDKG dealing encryption key has no timestamp and needs rotating",
                );
        }

        #[test]
        fn should_log_info_and_rotate_keys_if_keys_match_and_registry_key_is_too_old() {
            let in_memory_logger = InMemoryReplicaLogger::new();
            let setup = crate::keygen::tests::Setup::builder()
                .with_csp_current_node_public_keys_with_timestamps_result(Ok(
                    valid_current_node_public_keys_with_timestamps(),
                ))
                .with_csp_current_node_public_keys_result(Ok(valid_current_node_public_keys()))
                .with_csp_idkg_gen_dealing_encryption_key_pair_result(Ok(
                    deserialize_mega_public_key_or_panic(
                        &valid_idkg_dealing_encryption_public_key_2(),
                    ),
                ))
                .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
                    subnet_id(),
                    Some(node_id()),
                    Some(TWO_WEEKS),
                ))
                .with_registry_public_keys(valid_current_node_public_keys_with_timestamps())
                .with_logger(&in_memory_logger)
                .build();
            setup
                .time_source
                .advance_time(TWO_WEEKS + Duration::from_secs(1));

            let _rotate_idkg_dealing_encryption_keys_result = setup
                .crypto
                .rotate_idkg_dealing_encryption_keys(setup.registry_client.get_latest_version());

            let logs = in_memory_logger.drain_logs();
            LogEntriesAssert::assert_that(logs)
                .has_len(1)
                .has_only_one_message_containing(
                    &Level::Info,
                    "iDKG dealing encryption key too old and needs rotating",
                );
        }

        #[test]
        fn should_log_info_if_keys_do_not_match() {
            let in_memory_logger = InMemoryReplicaLogger::new();
            let mut registry_public_keys = valid_current_node_public_keys();
            if let Some(idkg_dealing_encryption_public_key) =
                &mut registry_public_keys.idkg_dealing_encryption_public_key
            {
                idkg_dealing_encryption_public_key.key_value = b"samesamebutdifferent".to_vec();
            }
            let setup = crate::keygen::tests::Setup::builder()
                .with_csp_current_node_public_keys_result(Ok(valid_current_node_public_keys()))
                .with_csp_current_node_public_keys_with_timestamps_result(Ok(
                    valid_current_node_public_keys_with_timestamps(),
                ))
                .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
                    subnet_id(),
                    Some(node_id()),
                    Some(TWO_WEEKS),
                ))
                .with_registry_public_keys(registry_public_keys)
                .with_logger(&in_memory_logger)
                .build();

            let _rotate_idkg_dealing_encryption_keys_result = setup
                .crypto
                .rotate_idkg_dealing_encryption_keys(setup.registry_client.get_latest_version());

            let logs = in_memory_logger.drain_logs();
            LogEntriesAssert::assert_that(logs)
                .has_len(1)
                .has_only_one_message_containing(
                    &Level::Info,
                    "Local iDKG dealing encryption key needs registration",
                );
        }

        #[test]
        fn should_log_warning_if_rotated_local_idkg_public_key_is_too_old_but_not_in_registry_with_mocked_csp()
         {
            let in_memory_logger = InMemoryReplicaLogger::new();
            let setup = Setup::builder()
                .with_registry_public_keys(valid_current_node_public_keys_with_timestamps())
                .with_csp_current_node_public_keys_result(Ok(CurrentNodePublicKeys {
                    idkg_dealing_encryption_public_key: Some(
                        valid_idkg_dealing_encryption_public_key_2(),
                    ),
                    ..valid_current_node_public_keys()
                }))
                .with_csp_current_node_public_keys_with_timestamps_result(Ok(
                    CurrentNodePublicKeys {
                        idkg_dealing_encryption_public_key: Some(PublicKeyProto {
                            timestamp: Some(0),
                            ..valid_idkg_dealing_encryption_public_key_2()
                        }),
                        ..valid_current_node_public_keys_with_timestamps()
                    },
                ))
                .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
                    subnet_id(),
                    Some(node_id()),
                    Some(TWO_WEEKS),
                ))
                .with_logger(&in_memory_logger)
                .build();

            setup
                .time_source
                .advance_time(TWO_WEEKS + Duration::from_secs(1));

            let _rotate_idkg_dealing_encryption_keys_result = setup
                .crypto
                .rotate_idkg_dealing_encryption_keys(setup.registry_client.get_latest_version());

            let logs = in_memory_logger.drain_logs();
            LogEntriesAssert::assert_that(logs)
                .has_len(2)
                .has_only_one_message_containing(
                    &Level::Info,
                    "Local iDKG dealing encryption key needs registration",
                )
                .has_only_one_message_containing(
                    &Level::Warning,
                    "Local iDKG dealing encryption key is too old",
                );
        }
    }

    fn deserialize_mega_public_key_or_panic(mega_public_key: &PublicKeyProto) -> MEGaPublicKey {
        MEGaPublicKey::deserialize(EccCurveType::K256, &mega_public_key.key_value)
            .expect("error deserializing MEGaPublicKey")
    }
}

struct Setup {
    metrics_registry: MetricsRegistry,
    crypto: CryptoComponentImpl<MockAllCryptoServiceProvider>,
    registry_client: Arc<dyn RegistryClient>,
    time_source: Arc<FastForwardTimeSource>,
}

impl Setup {
    fn builder() -> SetupBuilder {
        SetupBuilder {
            csp_current_node_public_keys_result: None,
            csp_current_node_public_keys_with_timestamps_result: None,
            csp_pks_and_sks_contains_result: None,
            registry_client_override: None,
            registry_public_keys: None,
            csp_idkg_dealing_encryption_public_keys_count_result: None,
            csp_idkg_gen_dealing_encryption_key_pair_result: None,
            logger: None,
            ecdsa_subnet_config: None,
        }
    }
}

struct SetupBuilder {
    csp_current_node_public_keys_result:
        Option<Result<CurrentNodePublicKeys, CspPublicKeyStoreError>>,
    csp_current_node_public_keys_with_timestamps_result:
        Option<Result<CurrentNodePublicKeys, CspPublicKeyStoreError>>,
    csp_pks_and_sks_contains_result: Option<Result<(), PksAndSksContainsErrors>>,
    registry_client_override: Option<Arc<dyn RegistryClient>>,
    registry_public_keys: Option<CurrentNodePublicKeys>,
    csp_idkg_dealing_encryption_public_keys_count_result:
        Option<Result<usize, CspPublicKeyStoreError>>,
    csp_idkg_gen_dealing_encryption_key_pair_result:
        Option<Result<MEGaPublicKey, CspCreateMEGaKeyError>>,
    logger: Option<ReplicaLogger>,
    ecdsa_subnet_config: Option<EcdsaSubnetConfig>,
}

impl SetupBuilder {
    fn with_csp_current_node_public_keys_result(
        mut self,
        csp_current_node_public_keys: Result<CurrentNodePublicKeys, CspPublicKeyStoreError>,
    ) -> Self {
        self.csp_current_node_public_keys_result = Some(csp_current_node_public_keys);
        self
    }

    fn with_csp_current_node_public_keys_with_timestamps_result(
        mut self,
        csp_current_node_public_keys_with_timestamps: Result<
            CurrentNodePublicKeys,
            CspPublicKeyStoreError,
        >,
    ) -> Self {
        self.csp_current_node_public_keys_with_timestamps_result =
            Some(csp_current_node_public_keys_with_timestamps);
        self
    }

    fn with_csp_pks_and_sks_contains_result(
        mut self,
        pks_and_sks_contains_result: Result<(), PksAndSksContainsErrors>,
    ) -> Self {
        self.csp_pks_and_sks_contains_result = Some(pks_and_sks_contains_result);
        self
    }

    // if `with_registry_client_override` is used, then `with_registry_public_keys` and
    // `with_ecdsa_subnet_config` cannot be used.
    fn with_registry_client_override(
        mut self,
        registry_client_override: Arc<dyn RegistryClient>,
    ) -> Self {
        self.registry_client_override = Some(registry_client_override);
        self
    }

    // `with_registry_public_keys` cannot be used together with `with_registry_client_override`
    fn with_registry_public_keys(mut self, registry_public_keys: CurrentNodePublicKeys) -> Self {
        self.registry_public_keys = Some(registry_public_keys);
        self
    }

    fn with_csp_idkg_dealing_encryption_public_keys_count_result(
        mut self,
        idkg_dealing_encryption_public_keys_count: Result<usize, CspPublicKeyStoreError>,
    ) -> Self {
        self.csp_idkg_dealing_encryption_public_keys_count_result =
            Some(idkg_dealing_encryption_public_keys_count);
        self
    }

    fn with_csp_idkg_gen_dealing_encryption_key_pair_result(
        mut self,
        idkg_gen_dealing_encryption_key_pair_result: Result<MEGaPublicKey, CspCreateMEGaKeyError>,
    ) -> Self {
        self.csp_idkg_gen_dealing_encryption_key_pair_result =
            Some(idkg_gen_dealing_encryption_key_pair_result);
        self
    }

    fn with_logger(mut self, in_memory_logger: &InMemoryReplicaLogger) -> Self {
        self.logger = Some(ReplicaLogger::from(in_memory_logger));
        self
    }

    // `with_ecdsa_subnet_config` cannot be used together with `with_registry_client_override`
    fn with_ecdsa_subnet_config(mut self, ecdsa_subnet_config: EcdsaSubnetConfig) -> Self {
        self.ecdsa_subnet_config = Some(ecdsa_subnet_config);
        self
    }

    fn build(self) -> Setup {
        let mut mock_vault = MockLocalCspVault::new();

        if let Some(csp_pks_and_sks_contains_result) = self.csp_pks_and_sks_contains_result {
            mock_vault
                .expect_pks_and_sks_contains()
                .times(1)
                .return_const(csp_pks_and_sks_contains_result);
        }
        if let Some(csp_current_node_public_keys_result) = self.csp_current_node_public_keys_result
        {
            mock_vault
                .expect_current_node_public_keys()
                .times(1)
                .return_const(csp_current_node_public_keys_result);
        }
        if let Some(csp_current_node_public_keys_with_timestamps_result) =
            self.csp_current_node_public_keys_with_timestamps_result
        {
            mock_vault
                .expect_current_node_public_keys_with_timestamps()
                .times(1)
                .return_const(csp_current_node_public_keys_with_timestamps_result);
        }
        if let Some(csp_idkg_dealing_encryption_public_keys_count_result) =
            self.csp_idkg_dealing_encryption_public_keys_count_result
        {
            mock_vault
                .expect_idkg_dealing_encryption_pubkeys_count()
                .times(1)
                .return_const(csp_idkg_dealing_encryption_public_keys_count_result);
        }
        if let Some(csp_idkg_gen_dealing_encryption_key_pair_result) =
            self.csp_idkg_gen_dealing_encryption_key_pair_result
        {
            mock_vault
                .expect_idkg_gen_dealing_encryption_key_pair()
                .times(1)
                .return_const(csp_idkg_gen_dealing_encryption_key_pair_result);
        }

        let registry_client: Arc<dyn RegistryClient> = match self.registry_client_override {
            None => {
                let registry_data = Arc::new(ProtoRegistryDataProvider::new());
                let registry_client = FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>);

                if let Some(registry_public_keys) = self.registry_public_keys {
                    add_keys_to_registry(&registry_data, &registry_public_keys);
                }

                if let Some(ecdsa_subnet_config) = self.ecdsa_subnet_config {
                    registry_data
                        .add(
                            &make_subnet_record_key(ecdsa_subnet_config.subnet_id),
                            REGISTRY_VERSION_1,
                            Some(ecdsa_subnet_config.subnet_record),
                        )
                        .expect("Failed to add subnet record.");
                    let subnet_list_record = SubnetListRecord {
                        subnets: vec![ecdsa_subnet_config.subnet_id.get().into_vec()],
                    };
                    // Set subnetwork list
                    registry_data
                        .add(
                            make_subnet_list_record_key().as_str(),
                            REGISTRY_VERSION_1,
                            Some(subnet_list_record),
                        )
                        .expect("Failed to add subnet list record key");
                }
                registry_client.reload();

                Arc::new(registry_client)
            }
            Some(registry_client_override) => {
                assert!(
                    self.registry_public_keys.is_none() && self.ecdsa_subnet_config.is_none(),
                    "registry client override specified, cannot explicitly specify registry public keys or ECDSA subnet config"
                );
                registry_client_override
            }
        };

        let metrics = MetricsRegistry::new();
        let crypto_metrics = Arc::new(CryptoMetrics::new(Some(&metrics)));
        // Initialize the metrics key counts to an unexpected value, so that we can later easily
        // see if the values were set correctly, rather than having been initialized to the same
        // expected values.
        crypto_metrics.observe_node_key_counts(
            &KeyCounts::new(
                UNEXPECTED_NUM_KEYS,
                UNEXPECTED_NUM_KEYS,
                UNEXPECTED_NUM_KEYS,
            ),
            MetricsResult::Ok,
        );
        crypto_metrics.observe_idkg_dealing_encryption_pubkey_count(
            UNEXPECTED_NUM_KEYS as usize,
            MetricsResult::Ok,
        );

        let time_source = FastForwardTimeSource::new();
        let crypto = CryptoComponentImpl::new_for_test(
            MockAllCryptoServiceProvider::new(),
            Arc::new(mock_vault),
            self.logger.unwrap_or_else(no_op_logger),
            Arc::clone(&registry_client),
            node_id(),
            crypto_metrics,
            Some(Arc::clone(&time_source) as Arc<_>),
        );

        Setup {
            metrics_registry: metrics,
            crypto,
            registry_client,
            time_source: Arc::clone(&time_source) as Arc<_>,
        }
    }
}

fn add_keys_to_registry(
    registry_data: &Arc<ProtoRegistryDataProvider>,
    current_node_public_keys: &CurrentNodePublicKeys,
) {
    registry_data
        .add(
            &make_crypto_node_key(node_id(), KeyPurpose::NodeSigning),
            REGISTRY_VERSION_1,
            current_node_public_keys.node_signing_public_key.to_owned(),
        )
        .expect("failed to add node signing key to registry");
    registry_data
        .add(
            &make_crypto_node_key(node_id(), KeyPurpose::CommitteeSigning),
            REGISTRY_VERSION_1,
            current_node_public_keys
                .committee_signing_public_key
                .to_owned(),
        )
        .expect("failed to add committee signing key to registry");
    registry_data
        .add(
            &make_crypto_node_key(node_id(), KeyPurpose::DkgDealingEncryption),
            REGISTRY_VERSION_1,
            current_node_public_keys
                .dkg_dealing_encryption_public_key
                .to_owned(),
        )
        .expect("failed to add NI-DKG dealing encryption key to registry");
    registry_data
        .add(
            &make_crypto_node_key(node_id(), KeyPurpose::IDkgMEGaEncryption),
            REGISTRY_VERSION_1,
            current_node_public_keys
                .idkg_dealing_encryption_public_key
                .to_owned(),
        )
        .expect("failed to add iDKG dealing encryption key to registry");
    registry_data
        .add(
            &make_crypto_tls_cert_key(node_id()),
            REGISTRY_VERSION_1,
            current_node_public_keys.tls_certificate.clone(),
        )
        .expect("failed to add TLS certificate to registry");
}

fn valid_current_node_public_keys_with_timestamps() -> CurrentNodePublicKeys {
    CurrentNodePublicKeys {
        node_signing_public_key: Some(valid_node_signing_public_key()),
        committee_signing_public_key: Some(valid_committee_signing_public_key()),
        tls_certificate: Some(valid_tls_certificate_and_validation_time().0),
        dkg_dealing_encryption_public_key: Some(valid_dkg_dealing_encryption_public_key()),
        idkg_dealing_encryption_public_key: Some(PublicKeyProto {
            timestamp: Some(0),
            ..valid_idkg_dealing_encryption_public_key()
        }),
    }
}

fn valid_current_node_public_keys() -> CurrentNodePublicKeys {
    CurrentNodePublicKeys {
        node_signing_public_key: Some(valid_node_signing_public_key()),
        committee_signing_public_key: Some(valid_committee_signing_public_key()),
        tls_certificate: Some(valid_tls_certificate_and_validation_time().0),
        dkg_dealing_encryption_public_key: Some(valid_dkg_dealing_encryption_public_key()),
        idkg_dealing_encryption_public_key: Some(valid_idkg_dealing_encryption_public_key()),
    }
}

fn subnet_id() -> SubnetId {
    SubnetId::new(PrincipalId::new(29, [0xfc; 29]))
}

fn node_id() -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(NODE_ID))
}
