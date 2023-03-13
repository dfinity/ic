#![allow(clippy::unwrap_used)]

use super::*;
use assert_matches::assert_matches;
use ic_base_types::{NodeId, PrincipalId};
use ic_crypto_internal_csp::vault::api::LocalPublicKeyError;
use ic_crypto_internal_csp::vault::api::NodeKeysError;
use ic_crypto_internal_csp::vault::api::NodeKeysErrors;
use ic_crypto_internal_csp::vault::api::PksAndSksContainsErrors;
use ic_crypto_internal_csp::vault::api::SecretKeyError;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_temp_crypto::{
    EcdsaSubnetConfig, NodeKeysToGenerate, TempCryptoBuilder, TempCryptoComponent,
};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_registry_mocks::MockRegistryClient;
use ic_metrics::MetricsRegistry;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::{make_crypto_node_key, make_crypto_tls_cert_key};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::{crypto::KeyPurpose, RegistryVersion};
use std::sync::Arc;

const ALL_KEYS_PRESENT: u8 = 5;
const UNEXPECTED_NUM_KEYS: u32 = 42;
const REGISTRY_VERSION_1: RegistryVersion = RegistryVersion::new(1);
const NODE_ID: u64 = 42;

mod check_keys_with_registry {
    use super::*;
    use ic_base_types::SubnetId;
    use ic_crypto_internal_csp::api::NodePublicKeyDataError;
    use ic_crypto_internal_csp::vault::api::ExternalPublicKeyError;
    use ic_crypto_internal_logmon::metrics::CryptoMetrics;
    use ic_crypto_test_utils_csp::MockAllCryptoServiceProvider;
    use ic_crypto_test_utils_keys::public_keys::{
        valid_committee_signing_public_key, valid_dkg_dealing_encryption_public_key,
        valid_idkg_dealing_encryption_public_key, valid_node_signing_public_key,
        valid_tls_certificate,
    };
    use ic_crypto_test_utils_metrics::assertions::MetricsObservationsAssert;
    use ic_interfaces::crypto::KeyManager;
    use ic_logger::replica_logger::no_op_logger;
    use ic_logger::ReplicaLogger;
    use ic_protobuf::registry::subnet::v1::SubnetListRecord;
    use ic_registry_keys::make_subnet_list_record_key;
    use ic_registry_keys::make_subnet_record_key;
    use ic_test_utilities::FastForwardTimeSource;
    use ic_test_utilities_in_memory_logger::assertions::LogEntriesAssert;
    use ic_test_utilities_in_memory_logger::InMemoryReplicaLogger;
    use slog::Level;

    const TWO_WEEKS: Duration = Duration::from_secs(2 * 7 * 24 * 60 * 60);

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
        fn should_collect_key_count_metrics_for_node_signing_public_key_mismatch_and_secret_key_missing(
        ) {
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
        fn should_collect_key_count_metrics_for_idkg_dealing_encryption_public_key_mismatch_secret_key_missing(
        ) {
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
                    NodePublicKeyDataError::TransientInternalError(
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
        fn should_observe_metrics_for_dkg_dealing_encryption_public_key_in_registry_but_missing_locally(
        ) {
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
        fn should_observe_metrics_for_idkg_dealing_encryption_public_key_in_registry_but_missing_locally(
        ) {
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
            LogEntriesAssert::assert_that(logs)
                .has_len(1)
                .has_only_one_message_containing(
                    &Level::Info,
                    "iDKG dealing encryption key rotation not enabled",
                );
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

        #[test]
        fn should_log_info_if_keys_match_and_registry_key_has_no_timestamp() {
            let in_memory_logger = InMemoryReplicaLogger::new();
            let setup = Setup::builder()
                .with_registry_public_keys(valid_current_node_public_keys())
                .with_csp_current_node_public_keys_with_timestamps_result(Ok(
                    valid_current_node_public_keys_with_timestamps(),
                ))
                .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
                .with_csp_pks_and_sks_contains_result(Ok(()))
                .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
                    subnet_id(),
                    Some(node_id()),
                    Some(TWO_WEEKS),
                ))
                .with_logger(&in_memory_logger)
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            let logs = in_memory_logger.drain_logs();
            LogEntriesAssert::assert_that(logs)
                .has_len(1)
                .has_only_one_message_containing(
                    &Level::Info,
                    "iDKG dealing encryption key has no timestamp and needs rotating",
                );
        }

        #[test]
        fn should_log_info_and_return_key_needs_rotating_if_keys_match_and_registry_key_is_too_old()
        {
            let in_memory_logger = InMemoryReplicaLogger::new();
            let mut registry_public_keys = valid_current_node_public_keys();
            if let Some(idkg_dealing_encryption_public_key) =
                &mut registry_public_keys.idkg_dealing_encryption_public_key
            {
                idkg_dealing_encryption_public_key.timestamp = Some(0);
            }
            let setup = Setup::builder()
                .with_csp_current_node_public_keys_with_timestamps_result(Ok(
                    valid_current_node_public_keys_with_timestamps(),
                ))
                .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
                .with_csp_pks_and_sks_contains_result(Ok(()))
                .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
                    subnet_id(),
                    Some(node_id()),
                    Some(TWO_WEEKS),
                ))
                .with_registry_public_keys(registry_public_keys)
                .with_logger(&in_memory_logger)
                .build();
            setup
                .time_source
                .advance_time(TWO_WEEKS + Duration::from_secs(1));

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

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
            let setup = Setup::builder()
                .with_csp_current_node_public_keys_with_timestamps_result(Ok(
                    valid_current_node_public_keys_with_timestamps(),
                ))
                .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
                .with_csp_pks_and_sks_contains_result(Ok(()))
                .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
                    subnet_id(),
                    Some(node_id()),
                    Some(TWO_WEEKS),
                ))
                .with_registry_public_keys(registry_public_keys)
                .with_logger(&in_memory_logger)
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            let logs = in_memory_logger.drain_logs();
            LogEntriesAssert::assert_that(logs)
                .has_len(1)
                .has_only_one_message_containing(
                    &Level::Info,
                    "Local iDKG dealing encryption key needs registration",
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

    mod latest_key_exists_in_registry {
        use super::*;

        #[test]
        fn should_observe_metric_for_latest_local_key_exists_in_registry_if_keys_match_and_registry_key_has_no_timestamp(
        ) {
            let setup = Setup::builder()
                .with_registry_public_keys(valid_current_node_public_keys())
                .with_csp_current_node_public_keys_with_timestamps_result(Ok(
                    valid_current_node_public_keys_with_timestamps(),
                ))
                .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
                .with_csp_pks_and_sks_contains_result(Ok(()))
                .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
                    subnet_id(),
                    Some(node_id()),
                    Some(TWO_WEEKS),
                ))
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_latest_key_exists_in_registry(true);
        }

        #[test]
        fn should_observe_latest_key_does_not_exist_in_registry_and_return_key_needs_registration_if_keys_do_not_match(
        ) {
            let mut registry_public_keys = valid_current_node_public_keys();
            if let Some(idkg_dealing_encryption_public_key) =
                &mut registry_public_keys.idkg_dealing_encryption_public_key
            {
                idkg_dealing_encryption_public_key.key_value = b"samesamebutdifferent".to_vec();
            }
            let setup = Setup::builder()
                .with_csp_current_node_public_keys_with_timestamps_result(Ok(
                    valid_current_node_public_keys_with_timestamps(),
                ))
                .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
                .with_csp_pks_and_sks_contains_result(Ok(()))
                .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
                    subnet_id(),
                    Some(node_id()),
                    Some(TWO_WEEKS),
                ))
                .with_registry_public_keys(registry_public_keys)
                .build();

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_latest_key_exists_in_registry(false);
        }
    }

    mod latest_key_too_old_but_not_in_registry {
        use super::*;

        #[test]
        fn should_observe_metric_for_latest_local_key_too_old_but_still_not_in_registry() {
            let setup = Setup::builder()
                .with_registry_public_keys(valid_current_node_public_keys())
                .with_csp_current_node_public_keys_with_timestamps_result(Ok(
                    CurrentNodePublicKeys {
                        idkg_dealing_encryption_public_key: Some(PublicKeyProto {
                            key_value: b"local key not in registry".to_vec(),
                            timestamp: Some(0),
                            ..valid_idkg_dealing_encryption_public_key()
                        }),
                        ..valid_current_node_public_keys_with_timestamps()
                    },
                ))
                .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
                .with_csp_pks_and_sks_contains_result(Ok(()))
                .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
                    subnet_id(),
                    Some(node_id()),
                    Some(TWO_WEEKS),
                ))
                .build();

            setup
                .time_source
                .advance_time(TWO_WEEKS + Duration::from_secs(1));

            let _check_keys_with_registry_result = setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version());

            MetricsObservationsAssert::assert_that(setup.metrics_registry)
                .contains_key_too_old_but_not_in_registry(1);
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
            Ok(PublicKeyRegistrationStatus::AllKeysRegistered)
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
            Err(CryptoError::PublicKeyNotFound {
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
            Err(CryptoError::PublicKeyNotFound {
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
            Err(CryptoError::TlsCertNotFound {
                node_id,
                registry_version,
            }) if node_id == expected_node_id && registry_version == REGISTRY_VERSION_1
        );
    }

    #[test]
    fn should_fail_with_public_key_not_found_if_dkg_dealing_encryption_public_key_missing_from_registry(
    ) {
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
            Err(CryptoError::PublicKeyNotFound {
                node_id,
                key_purpose,
                registry_version,
            }) if node_id == expected_node_id && key_purpose == KeyPurpose::DkgDealingEncryption && registry_version == REGISTRY_VERSION_1
        );
    }

    #[test]
    fn should_fail_with_public_key_not_found_if_idkg_dealing_encryption_public_key_missing_from_registry(
    ) {
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
            Err(CryptoError::PublicKeyNotFound {
                node_id,
                key_purpose,
                registry_version,
            }) if node_id == expected_node_id && key_purpose == KeyPurpose::IDkgMEGaEncryption && registry_version == REGISTRY_VERSION_1
        );
    }

    #[test]
    fn should_return_error_if_current_node_public_keys_fails_with_transient_error_with_key_rotation_enabled(
    ) {
        let setup = Setup::builder()
            .with_registry_public_keys(valid_current_node_public_keys())
            .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
            .with_csp_pks_and_sks_contains_result(Ok(()))
            .with_csp_current_node_public_keys_with_timestamps_result(Err(
                NodePublicKeyDataError::TransientInternalError(
                    "error retrieving current node public keys from remote csp vault".to_string(),
                ),
            ))
            .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
                subnet_id(),
                Some(node_id()),
                Some(TWO_WEEKS),
            ))
            .build();

        assert_matches!(
            setup.crypto.check_keys_with_registry(setup.registry_client.get_latest_version()),
            Err(CryptoError::TransientInternalError{ internal_error })
            if internal_error.contains("error retrieving current node public keys from remote csp vault")
        );
    }

    #[test]
    fn should_return_key_needs_rotating_if_keys_match_and_registry_key_has_no_timestamp() {
        let setup = Setup::builder()
            .with_registry_public_keys(valid_current_node_public_keys())
            .with_csp_current_node_public_keys_with_timestamps_result(Ok(
                valid_current_node_public_keys_with_timestamps(),
            ))
            .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
            .with_csp_pks_and_sks_contains_result(Ok(()))
            .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
                subnet_id(),
                Some(node_id()),
                Some(TWO_WEEKS),
            ))
            .build();

        assert_matches!(
            setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version()),
            Ok(PublicKeyRegistrationStatus::RotateIDkgDealingEncryptionKeys)
        );
    }

    #[test]
    fn should_return_key_needs_rotating_if_keys_match_and_registry_key_is_too_old() {
        let mut registry_public_keys = valid_current_node_public_keys();
        if let Some(idkg_dealing_encryption_public_key) =
            &mut registry_public_keys.idkg_dealing_encryption_public_key
        {
            idkg_dealing_encryption_public_key.timestamp = Some(0);
        }
        let setup = Setup::builder()
            .with_csp_current_node_public_keys_with_timestamps_result(Ok(
                valid_current_node_public_keys_with_timestamps(),
            ))
            .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
            .with_csp_pks_and_sks_contains_result(Ok(()))
            .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
                subnet_id(),
                Some(node_id()),
                Some(TWO_WEEKS),
            ))
            .with_registry_public_keys(registry_public_keys)
            .build();
        setup
            .time_source
            .advance_time(TWO_WEEKS + Duration::from_secs(1));

        assert_matches!(
            setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version()),
            Ok(PublicKeyRegistrationStatus::RotateIDkgDealingEncryptionKeys)
        );
    }

    #[test]
    fn should_return_key_needs_registration_if_keys_do_not_match() {
        let mut registry_public_keys = valid_current_node_public_keys();
        let idkg_dealing_encryption_public_key_to_register = registry_public_keys
            .idkg_dealing_encryption_public_key
            .clone()
            .expect("iDKG dealing encryption public key missing");
        if let Some(idkg_dealing_encryption_public_key) =
            &mut registry_public_keys.idkg_dealing_encryption_public_key
        {
            idkg_dealing_encryption_public_key.key_value = b"samesamebutdifferent".to_vec();
        }
        let setup = Setup::builder()
            .with_csp_current_node_public_keys_with_timestamps_result(Ok(
                valid_current_node_public_keys_with_timestamps(),
            ))
            .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
            .with_csp_pks_and_sks_contains_result(Ok(()))
            .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
                subnet_id(),
                Some(node_id()),
                Some(TWO_WEEKS),
            ))
            .with_registry_public_keys(registry_public_keys)
            .build();

        assert_matches!(
            setup.crypto.check_keys_with_registry(setup.registry_client.get_latest_version()),
            Ok(PublicKeyRegistrationStatus::IDkgDealingEncPubkeyNeedsRegistration(key_to_register))
            if key_to_register.equal_ignoring_timestamp(&idkg_dealing_encryption_public_key_to_register)
        );
    }

    #[test]
    fn should_return_all_keys_registered_if_registry_key_is_not_too_old() {
        use std::time::SystemTime;

        let mut registry_public_keys = valid_current_node_public_keys();
        if let Some(idkg_dealing_encryption_public_key) =
            &mut registry_public_keys.idkg_dealing_encryption_public_key
        {
            idkg_dealing_encryption_public_key.timestamp = Some(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("error getting current time")
                    .as_millis() as u64,
            );
        }
        let setup = Setup::builder()
            .with_csp_idkg_dealing_encryption_public_keys_count_result(Ok(1))
            .with_csp_current_node_public_keys_with_timestamps_result(Ok(
                valid_current_node_public_keys_with_timestamps(),
            ))
            .with_csp_pks_and_sks_contains_result(Ok(()))
            .with_ecdsa_subnet_config(EcdsaSubnetConfig::new(
                subnet_id(),
                Some(node_id()),
                Some(TWO_WEEKS),
            ))
            .with_registry_public_keys(registry_public_keys)
            .build();

        assert_matches!(
            setup
                .crypto
                .check_keys_with_registry(setup.registry_client.get_latest_version()),
            Ok(PublicKeyRegistrationStatus::AllKeysRegistered)
        );
    }

    struct Setup {
        metrics_registry: MetricsRegistry,
        crypto: CryptoComponentImpl<MockAllCryptoServiceProvider>,
        registry_client: Arc<FakeRegistryClient>,
        time_source: Arc<FastForwardTimeSource>,
    }

    impl Setup {
        fn builder() -> SetupBuilder {
            SetupBuilder {
                csp_current_node_public_keys_with_timestamps_result: None,
                csp_pks_and_sks_contains_result: None,
                registry_public_keys: None,
                csp_idkg_dealing_encryption_public_keys_count_result: None,
                logger: None,
                ecdsa_subnet_config: None,
            }
        }
    }

    struct SetupBuilder {
        csp_current_node_public_keys_with_timestamps_result:
            Option<Result<CurrentNodePublicKeys, NodePublicKeyDataError>>,
        csp_pks_and_sks_contains_result: Option<Result<(), PksAndSksContainsErrors>>,
        registry_public_keys: Option<CurrentNodePublicKeys>,
        csp_idkg_dealing_encryption_public_keys_count_result:
            Option<Result<usize, NodePublicKeyDataError>>,
        logger: Option<ReplicaLogger>,
        ecdsa_subnet_config: Option<EcdsaSubnetConfig>,
    }

    impl SetupBuilder {
        fn with_csp_current_node_public_keys_with_timestamps_result(
            mut self,
            csp_current_node_public_keys_with_timestamps: Result<
                CurrentNodePublicKeys,
                NodePublicKeyDataError,
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

        fn with_registry_public_keys(
            mut self,
            registry_public_keys: CurrentNodePublicKeys,
        ) -> Self {
            self.registry_public_keys = Some(registry_public_keys);
            self
        }

        fn with_csp_idkg_dealing_encryption_public_keys_count_result(
            mut self,
            idkg_dealing_encryption_public_keys_count: Result<usize, NodePublicKeyDataError>,
        ) -> Self {
            self.csp_idkg_dealing_encryption_public_keys_count_result =
                Some(idkg_dealing_encryption_public_keys_count);
            self
        }

        fn with_logger(mut self, in_memory_logger: &InMemoryReplicaLogger) -> Self {
            self.logger = Some(ReplicaLogger::from(in_memory_logger));
            self
        }

        fn with_ecdsa_subnet_config(mut self, ecdsa_subnet_config: EcdsaSubnetConfig) -> Self {
            self.ecdsa_subnet_config = Some(ecdsa_subnet_config);
            self
        }

        fn build(self) -> Setup {
            let registry_data = Arc::new(ProtoRegistryDataProvider::new());
            let registry_client =
                Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));

            let mut mock_csp = MockAllCryptoServiceProvider::new();

            if let Some(csp_pks_and_sks_contains_result) = self.csp_pks_and_sks_contains_result {
                mock_csp
                    .expect_pks_and_sks_contains()
                    .times(1)
                    .return_const(csp_pks_and_sks_contains_result);
            }
            if let Some(csp_current_node_public_keys_with_timestamps_result) =
                self.csp_current_node_public_keys_with_timestamps_result
            {
                mock_csp
                    .expect_current_node_public_keys_with_timestamps()
                    .times(1)
                    .return_const(csp_current_node_public_keys_with_timestamps_result);
            }
            if let Some(csp_idkg_dealing_encryption_public_keys_count_result) =
                self.csp_idkg_dealing_encryption_public_keys_count_result
            {
                mock_csp
                    .expect_idkg_dealing_encryption_pubkeys_count()
                    .times(1)
                    .return_const(csp_idkg_dealing_encryption_public_keys_count_result);
            }

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
            let crypto = CryptoComponentImpl::new_with_csp_and_fake_node_id(
                mock_csp,
                self.logger.unwrap_or_else(|| no_op_logger()),
                registry_client.clone(),
                node_id(),
                crypto_metrics,
                Some(Arc::clone(&time_source) as Arc<_>),
            );
            registry_client.reload();

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
            tls_certificate: Some(valid_tls_certificate()),
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
            tls_certificate: Some(valid_tls_certificate()),
            dkg_dealing_encryption_public_key: Some(valid_dkg_dealing_encryption_public_key()),
            idkg_dealing_encryption_public_key: Some(valid_idkg_dealing_encryption_public_key()),
        }
    }

    fn subnet_id() -> SubnetId {
        SubnetId::new(PrincipalId::new(29, [0xfc; 29]))
    }
}

mod rotate_idkg_dealing_encryption_keys {
    use super::*;
    use ic_base_types::{NodeId, PrincipalId, SubnetId};
    use ic_crypto_internal_csp::keygen::utils::idkg_dealing_encryption_pk_to_proto;
    use ic_crypto_internal_threshold_sig_ecdsa::{EccCurveType, MEGaPublicKey};
    use ic_logger::ReplicaLogger;
    use ic_protobuf::registry::crypto::v1::PublicKey;
    use ic_registry_keys::{make_crypto_node_key, make_crypto_tls_cert_key};
    use ic_test_utilities::FastForwardTimeSource;
    use ic_test_utilities_in_memory_logger::{assertions::LogEntriesAssert, InMemoryReplicaLogger};
    use slog::Level;

    pub(crate) const REGISTRY_VERSION_1: RegistryVersion = RegistryVersion::new(1);
    pub(crate) const REGISTRY_VERSION_2: RegistryVersion = RegistryVersion::new(2);
    const TWO_WEEKS: Duration = Duration::from_secs(2 * 7 * 24 * 60 * 60);

    #[test]
    #[should_panic(expected = "missing local IDKG public key")]
    fn should_panic_when_no_idkg_public_key_available_locally() {
        let setup = Setup::new_with_keys_to_generate(
            NodeKeysToGenerate::all_except_idkg_dealing_encryption_key(),
        );

        let _ = setup
            .crypto
            .rotate_idkg_dealing_encryption_keys(REGISTRY_VERSION_1);
    }

    #[test]
    fn should_return_current_idkg_public_key_when_other_key_in_registry() {
        let setup = Setup::new();
        let idkg_public_key_from_registry = an_idkg_dealing_encryption_public_key();
        setup.register_idkg_public_key(idkg_public_key_from_registry.clone(), REGISTRY_VERSION_2);
        let current_idkg_public_key = setup.current_local_idkg_dealing_encryption_public_key();
        assert!(!idkg_public_key_from_registry.equal_ignoring_timestamp(&current_idkg_public_key));

        let rotated_idkg_key = setup
            .crypto
            .rotate_idkg_dealing_encryption_keys(REGISTRY_VERSION_2)
            .unwrap();

        assert_eq!(current_idkg_public_key, rotated_idkg_key);
    }

    #[test]
    fn should_rotate_idkg_public_key_when_key_from_registry_does_not_have_timestamp() {
        let setup = Setup::new();
        let idkg_public_key_before_rotation =
            setup.current_local_idkg_dealing_encryption_public_key();
        let idkg_public_key_from_registry = PublicKey {
            timestamp: None,
            ..idkg_public_key_before_rotation.clone()
        };
        setup.register_idkg_public_key(idkg_public_key_from_registry.clone(), REGISTRY_VERSION_2);
        assert!(idkg_public_key_from_registry
            .equal_ignoring_timestamp(&idkg_public_key_before_rotation));

        let rotated_idkg_key = setup
            .crypto
            .rotate_idkg_dealing_encryption_keys(REGISTRY_VERSION_2)
            .unwrap();

        assert_ne!(idkg_public_key_before_rotation, rotated_idkg_key);
        assert_eq!(
            setup.current_local_idkg_dealing_encryption_public_key(),
            rotated_idkg_key
        );
    }

    #[test]
    fn should_not_rotate_key_when_last_rotation_too_recent() {
        let setup = Setup::new();
        let idkg_public_key_before_rotation =
            setup.current_local_idkg_dealing_encryption_public_key();
        let idkg_public_key_from_registry = PublicKey {
            timestamp: Some(0),
            ..idkg_public_key_before_rotation
        };
        setup
            .register_idkg_public_key(idkg_public_key_from_registry, REGISTRY_VERSION_2)
            .set_time(Time::try_from(TWO_WEEKS - Duration::from_nanos(1)).unwrap());

        let rotated_idkg_key = setup
            .crypto
            .rotate_idkg_dealing_encryption_keys(REGISTRY_VERSION_2);

        assert_matches!(
            rotated_idkg_key,
            Err(IDkgDealingEncryptionKeyRotationError::LatestLocalRotationTooRecent)
        )
    }

    #[test]
    fn should_not_rotate_key_when_node_not_on_any_subnet() {
        let setup = Setup::new_with_ecdsa_subnet_config(None);
        let idkg_public_key_before_rotation =
            setup.current_local_idkg_dealing_encryption_public_key();
        let idkg_public_key_from_registry = PublicKey {
            timestamp: Some(0),
            ..idkg_public_key_before_rotation
        };
        setup
            .register_idkg_public_key(idkg_public_key_from_registry, REGISTRY_VERSION_2)
            .set_time(Time::try_from(TWO_WEEKS + Duration::from_nanos(1)).unwrap());

        let rotated_idkg_key = setup
            .crypto
            .rotate_idkg_dealing_encryption_keys(REGISTRY_VERSION_2);

        assert_matches!(
            rotated_idkg_key,
            Err(IDkgDealingEncryptionKeyRotationError::KeyRotationNotEnabled)
        );
    }

    #[test]
    fn should_not_rotate_key_when_node_not_on_ecdsa_subnet() {
        let setup = Setup::new_with_ecdsa_subnet_config(Some(EcdsaSubnetConfig::new(
            subnet_id(),
            Some(NodeId::from(PrincipalId::new_node_test_id(182))),
            Some(TWO_WEEKS),
        )));
        let idkg_public_key_before_rotation =
            setup.current_local_idkg_dealing_encryption_public_key();
        let idkg_public_key_from_registry = PublicKey {
            timestamp: Some(0),
            ..idkg_public_key_before_rotation
        };
        setup
            .register_idkg_public_key(idkg_public_key_from_registry, REGISTRY_VERSION_2)
            .set_time(Time::try_from(TWO_WEEKS + Duration::from_nanos(1)).unwrap());

        let rotated_idkg_key = setup
            .crypto
            .rotate_idkg_dealing_encryption_keys(REGISTRY_VERSION_2);

        assert_matches!(
            rotated_idkg_key,
            Err(IDkgDealingEncryptionKeyRotationError::KeyRotationNotEnabled)
        );
    }

    #[test]
    fn should_not_rotate_key_when_key_rotation_period_not_set() {
        let setup = Setup::new_with_ecdsa_subnet_config(Some(EcdsaSubnetConfig::new(
            subnet_id(),
            Some(node_id()),
            None,
        )));
        let idkg_public_key_before_rotation =
            setup.current_local_idkg_dealing_encryption_public_key();
        let idkg_public_key_from_registry = PublicKey {
            timestamp: Some(0),
            ..idkg_public_key_before_rotation
        };
        setup
            .register_idkg_public_key(idkg_public_key_from_registry, REGISTRY_VERSION_2)
            .set_time(Time::try_from(TWO_WEEKS + Duration::from_nanos(1)).unwrap());

        let rotated_idkg_key = setup
            .crypto
            .rotate_idkg_dealing_encryption_keys(REGISTRY_VERSION_2);

        assert_matches!(
            rotated_idkg_key,
            Err(IDkgDealingEncryptionKeyRotationError::KeyRotationNotEnabled)
        );
    }

    #[test]
    fn should_not_rotate_key_when_no_ecdsa_config_exists() {
        let setup = Setup::new_with_ecdsa_subnet_config(Some(
            EcdsaSubnetConfig::new_without_ecdsa_config(subnet_id(), Some(node_id())),
        ));
        let idkg_public_key_before_rotation =
            setup.current_local_idkg_dealing_encryption_public_key();
        let idkg_public_key_from_registry = PublicKey {
            timestamp: Some(0),
            ..idkg_public_key_before_rotation
        };
        setup
            .register_idkg_public_key(idkg_public_key_from_registry, REGISTRY_VERSION_2)
            .set_time(Time::try_from(TWO_WEEKS + Duration::from_nanos(1)).unwrap());

        let rotated_idkg_key = setup
            .crypto
            .rotate_idkg_dealing_encryption_keys(REGISTRY_VERSION_2);

        assert_matches!(
            rotated_idkg_key,
            Err(IDkgDealingEncryptionKeyRotationError::KeyRotationNotEnabled)
        );
    }

    #[test]
    fn should_not_rotate_key_when_no_ecdsa_key_ids_configured() {
        let setup = Setup::new_with_ecdsa_subnet_config(Some(
            EcdsaSubnetConfig::new_without_key_ids(subnet_id(), Some(node_id()), Some(TWO_WEEKS)),
        ));
        let idkg_public_key_before_rotation =
            setup.current_local_idkg_dealing_encryption_public_key();
        let idkg_public_key_from_registry = PublicKey {
            timestamp: Some(0),
            ..idkg_public_key_before_rotation
        };
        setup
            .register_idkg_public_key(idkg_public_key_from_registry, REGISTRY_VERSION_2)
            .set_time(Time::try_from(TWO_WEEKS - Duration::from_nanos(1)).unwrap());

        let rotated_idkg_key = setup
            .crypto
            .rotate_idkg_dealing_encryption_keys(REGISTRY_VERSION_2);

        assert_matches!(
            rotated_idkg_key,
            Err(IDkgDealingEncryptionKeyRotationError::KeyRotationNotEnabled)
        );
    }

    #[test]
    fn should_rotate_idkg_public_key() {
        let setup = Setup::new();
        let idkg_public_key_before_rotation =
            setup.current_local_idkg_dealing_encryption_public_key();
        let idkg_public_key_from_registry = PublicKey {
            timestamp: Some(0),
            ..idkg_public_key_before_rotation.clone()
        };
        setup
            .register_idkg_public_key(idkg_public_key_from_registry, REGISTRY_VERSION_2)
            .set_time(Time::try_from(TWO_WEEKS + Duration::from_nanos(1)).unwrap());

        let rotated_idkg_key = setup
            .crypto
            .rotate_idkg_dealing_encryption_keys(REGISTRY_VERSION_2)
            .expect("could not rotate key");

        assert_ne!(idkg_public_key_before_rotation, rotated_idkg_key);
        assert_eq!(
            setup.current_local_idkg_dealing_encryption_public_key(),
            rotated_idkg_key
        );
    }

    #[test]
    fn should_correctly_get_idkg_dealing_encryption_pubkeys_count_for_multiple_keys() {
        let setup = Setup::new();
        let idkg_public_key_before_rotation =
            setup.current_local_idkg_dealing_encryption_public_key();
        let idkg_public_key_from_registry = PublicKey {
            timestamp: Some(0),
            ..idkg_public_key_before_rotation
        };
        setup
            .register_idkg_public_key(idkg_public_key_from_registry, REGISTRY_VERSION_2)
            .set_time(Time::try_from(TWO_WEEKS + Duration::from_nanos(1)).unwrap());

        let _rotated_idkg_key = setup
            .crypto
            .rotate_idkg_dealing_encryption_keys(REGISTRY_VERSION_2)
            .expect("could not rotate key");

        let idkg_dealing_encryption_pubkeys_count = setup
            .crypto
            .idkg_dealing_encryption_pubkeys_count()
            .expect("Failed to get iDKG dealing encryption pubkeys count");
        assert_eq!(2, idkg_dealing_encryption_pubkeys_count);
    }

    #[test]
    fn should_return_error_when_registry_error() {
        let mock_registry_client = registry_returning(RegistryClientError::PollLockFailed {
            error: "oh no!".to_string(),
        });
        let crypto = temp_crypto_builder()
            .with_registry(Arc::new(mock_registry_client))
            .build();

        let rotated_idkg_key = crypto.rotate_idkg_dealing_encryption_keys(REGISTRY_VERSION_1);

        assert_matches!(
            rotated_idkg_key,
            Err(IDkgDealingEncryptionKeyRotationError::RegistryError(
                RegistryClientError::PollLockFailed { error }
            )) if error.contains("oh no!")
        );
    }

    #[test]
    fn should_have_rotate_idkg_dealing_encryption_keys_returning_transient_error_if_csp_fails_to_get_current_node_public_keys(
    ) {
        use ic_crypto_internal_csp::api::NodePublicKeyDataError;
        use ic_crypto_test_utils_csp::MockAllCryptoServiceProvider;
        use ic_interfaces::crypto::KeyManager;
        use ic_logger::replica_logger::no_op_logger;
        use ic_protobuf::registry::subnet::v1::SubnetListRecord;
        use ic_registry_keys::{make_subnet_list_record_key, make_subnet_record_key};

        let mut csp = MockAllCryptoServiceProvider::new();
        const DETAILS_STR: &str = "test";
        csp.expect_current_node_public_keys().return_const(Err(
            NodePublicKeyDataError::TransientInternalError(DETAILS_STR.to_string()),
        ));

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

        let crypto_component = CryptoComponentImpl::new_with_csp_and_fake_node_id(
            csp,
            no_op_logger(),
            registry_client.clone(),
            node_id(),
            Arc::new(CryptoMetrics::none()),
            None,
        );
        registry_client.reload();

        let result = crypto_component.rotate_idkg_dealing_encryption_keys(REGISTRY_VERSION_1);

        assert_matches!(result, Err(IDkgDealingEncryptionKeyRotationError::TransientInternalError(details)) if details == DETAILS_STR);
    }

    #[test]
    fn should_log_warning_if_rotated_local_idkg_public_key_is_too_old_but_not_in_registry_with_mocked_csp(
    ) {
        use ic_crypto_test_utils_csp::MockAllCryptoServiceProvider;
        use ic_interfaces::crypto::KeyManager;
        use ic_protobuf::registry::subnet::v1::SubnetListRecord;
        use ic_registry_keys::{make_subnet_list_record_key, make_subnet_record_key};

        let setup = Setup::new_with_keys_to_generate(NodeKeysToGenerate::all());
        let mut current_node_public_keys = setup
            .crypto
            .current_node_public_keys()
            .expect("error getting current node public keys");
        let mut current_node_public_keys_with_timestamps = current_node_public_keys.clone();
        if let Some(idkg_dealing_encryption_public_key) =
            &mut current_node_public_keys_with_timestamps.idkg_dealing_encryption_public_key
        {
            idkg_dealing_encryption_public_key.timestamp = Some(0);
        }
        current_node_public_keys.idkg_dealing_encryption_public_key =
            Some(an_idkg_dealing_encryption_public_key());

        let registry_data = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client =
            Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));

        let mut mock_csp = MockAllCryptoServiceProvider::new();

        mock_csp
            .expect_pks_and_sks_contains()
            .times(1)
            .return_const(Ok(()));
        mock_csp
            .expect_idkg_dealing_encryption_pubkeys_count()
            .times(1)
            .return_const(Ok(1));
        mock_csp
            .expect_current_node_public_keys_with_timestamps()
            .times(1)
            .return_const(Ok(current_node_public_keys_with_timestamps.clone()));

        let in_memory_logger = InMemoryReplicaLogger::new();

        add_keys_to_registry(&registry_data, &current_node_public_keys);
        let ecdsa_subnet_config =
            EcdsaSubnetConfig::new(subnet_id(), Some(node_id()), Some(TWO_WEEKS));
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
        registry_data
            .add(
                make_subnet_list_record_key().as_str(),
                REGISTRY_VERSION_1,
                Some(subnet_list_record),
            )
            .expect("Failed to add subnet list record key");

        registry_client.reload();

        let crypto_component = CryptoComponentImpl::new_with_csp_and_fake_node_id(
            mock_csp,
            ReplicaLogger::from(&in_memory_logger),
            registry_client.clone(),
            node_id(),
            Arc::new(CryptoMetrics::none()),
            None,
        );
        registry_client.reload();

        assert_matches!(
            crypto_component.check_keys_with_registry(REGISTRY_VERSION_1),
            Ok(PublicKeyRegistrationStatus::IDkgDealingEncPubkeyNeedsRegistration(
                latest_local_idkg_dealing_encryption_key,
            )) if latest_local_idkg_dealing_encryption_key.equal_ignoring_timestamp(&current_node_public_keys_with_timestamps
                    .idkg_dealing_encryption_public_key.expect("no idkg dealing encryption key"))
        );

        let logs = in_memory_logger.drain_logs();

        LogEntriesAssert::assert_that(logs)
            .has_only_one_message_containing(
                &Level::Warning,
                "Local iDKG dealing encryption key is too old (1970-01-01 00:00:00 UTC), but it still has not been registered in the registry");
    }

    struct Setup {
        registry_data: Arc<ProtoRegistryDataProvider>,
        registry_client: Arc<FakeRegistryClient>,
        time_source: Arc<FastForwardTimeSource>,
        crypto: TempCryptoComponent,
    }

    impl Setup {
        fn new() -> Self {
            Self::new_with_ecdsa_subnet_config(Some(EcdsaSubnetConfig::new(
                subnet_id(),
                Some(node_id()),
                Some(TWO_WEEKS),
            )))
        }

        fn new_with_keys_to_generate(node_keys_to_generate: NodeKeysToGenerate) -> Self {
            Self::new_internal(
                node_keys_to_generate,
                Some(EcdsaSubnetConfig::new(
                    subnet_id(),
                    Some(node_id()),
                    Some(TWO_WEEKS),
                )),
                None,
            )
        }

        fn new_with_ecdsa_subnet_config(ecdsa_subnet_config: Option<EcdsaSubnetConfig>) -> Self {
            Self::new_internal(
                NodeKeysToGenerate::only_idkg_dealing_encryption_key(),
                ecdsa_subnet_config,
                None,
            )
        }

        fn new_internal(
            node_keys_to_generate: NodeKeysToGenerate,
            ecdsa_subnet_config: Option<EcdsaSubnetConfig>,
            logger: Option<ReplicaLogger>,
        ) -> Self {
            let registry_data = Arc::new(ProtoRegistryDataProvider::new());
            let registry_client =
                Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));
            let time_source = FastForwardTimeSource::new();
            let mut crypto_builder = temp_crypto_builder()
                .with_keys(node_keys_to_generate)
                .with_registry_client_and_data(
                    Arc::clone(&registry_client) as Arc<_>,
                    Arc::clone(&registry_data) as Arc<_>,
                )
                .with_time_source(Arc::clone(&time_source) as Arc<_>);
            if let Some(logger) = logger {
                crypto_builder = crypto_builder.with_logger(logger);
            }
            if let Some(ecdsa_subnet_config) = ecdsa_subnet_config {
                crypto_builder = crypto_builder.with_ecdsa_subnet_config(ecdsa_subnet_config);
            }

            let setup = Setup {
                registry_data: Arc::clone(&registry_data) as Arc<_>,
                registry_client: Arc::clone(&registry_client) as Arc<_>,
                time_source: Arc::clone(&time_source) as Arc<_>,
                crypto: crypto_builder.build(),
            };
            registry_client.reload();
            setup
        }

        fn register_idkg_public_key(
            &self,
            idkg_public_key: PublicKey,
            version: RegistryVersion,
        ) -> &Self {
            let _ = &self
                .registry_data
                .add(
                    &make_crypto_node_key(node_id(), KeyPurpose::IDkgMEGaEncryption),
                    version,
                    Some(idkg_public_key),
                )
                .unwrap();
            let _ = &self.registry_client.update_to_latest_version();
            self
        }

        fn set_time(&self, time: Time) -> &Self {
            let _ = &self.time_source.set_time(time).unwrap();
            self
        }

        fn current_local_idkg_dealing_encryption_public_key(&self) -> PublicKey {
            self.crypto
                .current_node_public_keys()
                .expect("Failed to retrieve node public keys")
                .idkg_dealing_encryption_public_key
                .unwrap()
        }
    }

    fn node_id() -> NodeId {
        NodeId::from(PrincipalId::new_node_test_id(NODE_ID))
    }

    fn subnet_id() -> SubnetId {
        SubnetId::new(PrincipalId::new(29, [0xfc; 29]))
    }

    fn an_idkg_dealing_encryption_public_key() -> PublicKey {
        idkg_dealing_encryption_pk_to_proto(
            MEGaPublicKey::deserialize(
                EccCurveType::K256,
                &hex::decode("039a6f8ffe8e8d252f0ba25230a77ed334da43a8661480c07e85db88dde355f096")
                    .expect("invalid hex string"),
            )
            .unwrap(),
        )
    }

    fn registry_returning(error: RegistryClientError) -> impl RegistryClient {
        let mut registry = MockRegistryClient::new();
        registry
            .expect_get_value()
            .returning(move |_, _| Err(error.clone()));
        registry
    }

    fn temp_crypto_builder() -> TempCryptoBuilder {
        TempCryptoComponent::builder()
            .with_keys(NodeKeysToGenerate::only_idkg_dealing_encryption_key())
            // callers of rotate_idkg_dealing_encryption_keys use a CryptoComponent with a remote vault
            .with_remote_vault()
            .with_node_id(node_id())
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
}

mod idkg_dealing_encryption_pubkeys_count {
    use super::*;
    use ic_base_types::{NodeId, PrincipalId};

    #[test]
    fn should_correctly_count_idkg_dealing_encryption_pubkeys_when_all_keys_present() {
        let crypto_component = TempCryptoComponent::builder()
            .with_keys(NodeKeysToGenerate::all())
            .build();
        let key_counts = crypto_component
            .idkg_dealing_encryption_pubkeys_count()
            .expect("Error calling idkg_dealing_encryption_pubkeys_count");
        assert_eq!(1, key_counts);
    }

    #[test]
    fn should_correctly_count_idkg_dealing_encryption_pubkeys_when_no_keys_present() {
        let crypto_component = TempCryptoComponent::builder()
            .with_keys(NodeKeysToGenerate::none())
            .build();
        let key_counts = crypto_component
            .idkg_dealing_encryption_pubkeys_count()
            .expect("Error calling idkg_dealing_encryption_pubkeys_count");
        assert_eq!(0, key_counts);
    }

    #[test]
    fn should_have_idkg_dealing_encryption_pubkeys_count_returning_transient_error_if_csp_call_fails(
    ) {
        use ic_crypto_internal_csp::api::NodePublicKeyDataError;
        use ic_crypto_test_utils_csp::MockAllCryptoServiceProvider;
        use ic_interfaces::crypto::KeyManager;
        use ic_logger::replica_logger::no_op_logger;

        let mut csp = MockAllCryptoServiceProvider::new();
        const DETAILS_STR: &str = "test";
        csp.expect_idkg_dealing_encryption_pubkeys_count()
            .return_const(Err(NodePublicKeyDataError::TransientInternalError(
                DETAILS_STR.to_string(),
            )));

        let registry_data = Arc::new(ProtoRegistryDataProvider::new());

        let registry_client =
            Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));

        let crypto_component = CryptoComponentImpl::new_with_csp_and_fake_node_id(
            csp,
            no_op_logger(),
            registry_client.clone(),
            NodeId::from(PrincipalId::new_node_test_id(42)),
            Arc::new(CryptoMetrics::none()),
            None,
        );
        registry_client.reload();

        let result = crypto_component.idkg_dealing_encryption_pubkeys_count();

        assert_matches!(result, Err(IdkgDealingEncPubKeysCountError::TransientInternalError(details)) if details == DETAILS_STR);
    }
}

fn node_id() -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(NODE_ID))
}
