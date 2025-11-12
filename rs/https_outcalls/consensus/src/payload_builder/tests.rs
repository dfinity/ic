//! This module contains unit tests for the payload building and verification
//! of the canister http feature.
//!
//! Some tests are run over a range of subnet configurations to check for corner cases.

use super::{CanisterHttpPayloadBuilderImpl, parse};
use crate::payload_builder::{
    divergence_response_into_reject,
    parse::{bytes_to_payload, payload_to_bytes},
};
use ic_artifact_pool::canister_http_pool::CanisterHttpPoolImpl;
use ic_consensus_mocks::{Dependencies, dependencies_with_subnet_params};
use ic_error_types::RejectCode;
use ic_interfaces::{
    batch_payload::{BatchPayloadBuilder, PastPayload, ProposalContext},
    canister_http::{
        CanisterHttpChangeAction, CanisterHttpChangeSet, CanisterHttpPayloadValidationFailure,
        InvalidCanisterHttpPayloadReason,
    },
    consensus::{InvalidPayloadReason, PayloadValidationError, PayloadValidationFailure},
    p2p::consensus::{MutablePool, UnvalidatedArtifact},
    validation::ValidationError,
};
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_features::SubnetFeatures;
use ic_test_utilities::state_manager::RefMockStateManager;
use ic_test_utilities_registry::SubnetRecordBuilder;
use ic_test_utilities_types::{
    ids::{canister_test_id, node_id_to_u64, node_test_id, subnet_test_id},
    messages::RequestBuilder,
};
use ic_types::{
    Height, NumBytes, RegistryVersion, ReplicaVersion, Time,
    batch::{CanisterHttpPayload, MAX_CANISTER_HTTP_PAYLOAD_SIZE, ValidationContext},
    canister_http::{
        CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK, CANISTER_HTTP_TIMEOUT_INTERVAL, CanisterHttpMethod,
        CanisterHttpRequestContext, CanisterHttpResponse, CanisterHttpResponseArtifact,
        CanisterHttpResponseContent, CanisterHttpResponseDivergence, CanisterHttpResponseMetadata,
        CanisterHttpResponseShare, CanisterHttpResponseWithConsensus,
    },
    consensus::get_faults_tolerated,
    crypto::{BasicSig, BasicSigOf, CryptoHash, CryptoHashOf, Signed, crypto_hash},
    messages::{CallbackId, Payload, RejectContext},
    registry::RegistryClientError,
    signature::{BasicSignature, BasicSignatureBatch},
    time::UNIX_EPOCH,
};
use rand::Rng;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use std::{
    collections::BTreeMap,
    ops::DerefMut,
    sync::{Arc, RwLock},
    time::Duration,
};

/// The maximum subnet size up to which we will check the functionality of the canister http feature.
const MAX_SUBNET_SIZE: usize = 40;

#[test]
fn default_payload_serializes_to_empty_vec() {
    assert!(
        parse::payload_to_bytes(
            &CanisterHttpPayload::default(),
            NumBytes::new(MAX_CANISTER_HTTP_PAYLOAD_SIZE as u64)
        )
        .is_empty()
    );
}

/// Check that a single well formed request with shares makes it through the block maker
#[test]
fn single_request_test() {
    let context = default_validation_context();

    for subnet_size in 1..MAX_SUBNET_SIZE {
        test_config_with_http_feature(true, subnet_size, |payload_builder, canister_http_pool| {
            let (response, metadata) = test_response_and_metadata(0);
            let shares = metadata_to_shares(subnet_size, &metadata);

            {
                // Add response and shares to pool
                // NOTE: We are only adding the required minimum of shares to the pool
                let mut pool_access = canister_http_pool.write().unwrap();
                add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &response);
                add_received_shares_to_pool(
                    pool_access.deref_mut(),
                    shares[1..subnet_size - get_faults_tolerated(subnet_size)].to_vec(),
                );
            }

            // Build a payload
            let payload = payload_builder.build_payload(
                Height::new(1),
                NumBytes::new(4 * 1024 * 1024),
                &[],
                &context,
            );

            //  Make sure the response is contained in the payload
            let parsed_payload = bytes_to_payload(&payload).expect("Failed to parse the payload");
            assert_eq!(parsed_payload.num_responses(), 1);
            assert_eq!(parsed_payload.responses[0].content, response);

            assert!(
                payload_builder
                    .validate_payload(
                        Height::new(1),
                        &test_proposal_context(&context),
                        &payload,
                        &[],
                    )
                    .is_ok()
            );
        });

        // TODO: Test that the payload building fails, if the use threshold -1 many shares.
    }
}

/// Submit a number of requests to the payload builder:
///
/// - One has insufficient support
/// - One has timed out
/// - One has wrong registry version
/// - One is oversized (Larger than 2 MiB)
/// - Two are valid, but one is already in pasts payloads
///
/// Expect:
/// - Only one response to make it into the payload
#[test]
fn multiple_payload_test() {
    // Initialize a CanisterHttpPayloadBuilder with the pool
    let (valid_response, valid_metadata) = test_response_and_metadata(0);

    // Run the test over a range of subnet configurations
    for subnet_size in 1..MAX_SUBNET_SIZE {
        test_config_with_http_feature(true, subnet_size, |payload_builder, canister_http_pool| {
            // Add response and shares to pool
            let (past_response, past_metadata) = {
                let mut pool_access = canister_http_pool.write().unwrap();

                // Add the valid response into the pool
                let shares = metadata_to_shares(subnet_size, &valid_metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &valid_response);
                add_received_shares_to_pool(
                    pool_access.deref_mut(),
                    shares[1..subnet_size].to_vec(),
                );

                // NOTE: This makes only sense for 3+ Nodes and is skipped for less
                if subnet_size > 2 {
                    // Add a valid response into the pool but only half of the shares
                    let (response, metadata) = test_response_and_metadata(1);
                    let shares = metadata_to_shares(subnet_size, &metadata);
                    add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &response);
                    add_received_shares_to_pool(
                        pool_access.deref_mut(),
                        shares[1..subnet_size / 2].to_vec(),
                    );
                }

                // Add a response that is already timed out
                let (mut response, mut metadata) = test_response_and_metadata(2);
                response.timeout = UNIX_EPOCH;
                metadata.timeout = UNIX_EPOCH;
                let shares = metadata_to_shares(subnet_size, &metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &response);
                add_received_shares_to_pool(
                    pool_access.deref_mut(),
                    shares[1..subnet_size].to_vec(),
                );

                // Add a response with mismatching registry version
                let (response, mut metadata) = test_response_and_metadata(3);
                metadata.registry_version = RegistryVersion::new(5);
                let shares = metadata_to_shares(subnet_size, &metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &response);
                add_received_shares_to_pool(
                    pool_access.deref_mut(),
                    shares[1..subnet_size].to_vec(),
                );

                // Add a oversized response
                let (mut response, metadata) = test_response_and_metadata(4);
                response.content = CanisterHttpResponseContent::Success(vec![123; 2 * 1024 * 1024]);
                let shares = metadata_to_shares(subnet_size, &metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &response);
                add_received_shares_to_pool(
                    pool_access.deref_mut(),
                    shares[1..subnet_size].to_vec(),
                );

                // Add response which is valid but we will put it into past_payloads
                let (past_response, past_metadata) = test_response_and_metadata(5);
                let shares = metadata_to_shares(subnet_size, &past_metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &past_response);
                add_received_shares_to_pool(
                    pool_access.deref_mut(),
                    shares[1..subnet_size].to_vec(),
                );

                (past_response, past_metadata)
            };

            // Set up past payload
            let past_payload = CanisterHttpPayload {
                responses: vec![CanisterHttpResponseWithConsensus {
                    content: past_response,
                    proof: Signed {
                        content: past_metadata,
                        signature: BasicSignatureBatch {
                            signatures_map: BTreeMap::new(),
                        },
                    },
                }],
                timeouts: vec![],
                divergence_responses: vec![],
            };
            let past_payload = payload_to_bytes(&past_payload, NumBytes::new(4 * 1024 * 1024));

            let past_payloads = vec![PastPayload {
                height: Height::from(0),
                time: UNIX_EPOCH,
                block_hash: CryptoHashOf::from(CryptoHash(vec![])),
                payload: &past_payload,
            }];

            let validation_context = ValidationContext {
                registry_version: RegistryVersion::new(1),
                certified_height: Height::new(0),
                time: UNIX_EPOCH + Duration::from_secs(3),
            };

            // Build a payload
            let payload = payload_builder.build_payload(
                Height::new(1),
                NumBytes::new(4 * 1024 * 1024),
                &past_payloads,
                &validation_context,
            );

            //  Make sure the response is not contained in the payload
            payload_builder
                .validate_payload(
                    Height::new(1),
                    &test_proposal_context(&validation_context),
                    &payload,
                    &past_payloads,
                )
                .unwrap();

            let parsed_payload = bytes_to_payload(&payload).expect("Failed to parse payload");
            assert_eq!(parsed_payload.num_responses(), 1);
            assert_eq!(parsed_payload.responses[0].content, valid_response);
        });
    }
}

#[test]
fn multiple_share_same_source_test() {
    for subnet_size in 3..MAX_SUBNET_SIZE {
        test_config_with_http_feature(true, subnet_size, |payload_builder, canister_http_pool| {
            {
                let mut pool_access = canister_http_pool.write().unwrap();

                let (response, metadata) = test_response_and_metadata(1);

                let shares = metadata_to_shares(10, &metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &response);

                // Ensure that multiple shares from a single source does not result in inclusion
                add_received_shares_to_pool(
                    pool_access.deref_mut(),
                    (0..subnet_size)
                        .map(|i| {
                            metadata_to_share_with_signature(7, &metadata, i.to_be_bytes().to_vec())
                        })
                        .collect(),
                );
            }

            let validation_context = ValidationContext {
                registry_version: RegistryVersion::new(1),
                certified_height: Height::new(0),
                time: UNIX_EPOCH + Duration::from_secs(3),
            };

            // Build a payload
            let payload = payload_builder.build_payload(
                Height::new(1),
                NumBytes::new(4 * 1024 * 1024),
                &[],
                &validation_context,
            );

            let parsed_payload = bytes_to_payload(&payload).expect("Failed to parse payload");
            assert_eq!(parsed_payload.num_responses(), 0);
        });
    }
}

/// Submit a group of requests (50% timeouts, 100% other), so that the total
/// request count exceeds the capacity of a single payload.
///
/// Expect: Timeout requests are given priority, so they are included in the
///         payload. That means that 50% of the payload should consist of timeouts
///         while the rest is filled with the remaining requests.
#[test]
fn timeout_priority() {
    // the time used for the validation context.
    let context_time = UNIX_EPOCH + CANISTER_HTTP_TIMEOUT_INTERVAL + Duration::from_secs(1);
    let mut init_state = ic_test_utilities_state::get_initial_state(0, 0);

    let response_count = 10;
    let timeout_count = 100;

    test_config_with_http_feature(true, 4, |mut payload_builder, canister_http_pool| {
        {
            let mut pool_access = canister_http_pool.write().unwrap();
            // add 100% capacity of normal (non-timeout) requests to the pool
            for i in 0..response_count {
                let (response, metadata) = test_response_and_metadata_with_timeout(
                    i as u64,
                    context_time + Duration::from_secs(10),
                );
                let shares = metadata_to_shares(4, &metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &response);
                add_received_shares_to_pool(pool_access.deref_mut(), shares[1..4].to_vec());
            }
            // Fill 50% of a single blocks maximum request capacity with timeouts
            for i in 0..timeout_count {
                let k = CallbackId::from(i + 2 * (response_count as u64) + 1);
                let v = CanisterHttpRequestContext {
                    request: RequestBuilder::default().build(),
                    url: String::new(),
                    max_response_bytes: None,
                    headers: vec![],
                    body: None,
                    http_method: CanisterHttpMethod::GET,
                    transform: None,
                    // this is the important one
                    time: UNIX_EPOCH,
                    replication: ic_types::canister_http::Replication::FullyReplicated,
                    pricing_version: ic_types::canister_http::PricingVersion::Legacy,
                };
                init_state
                    .metadata
                    .subnet_call_context_manager
                    .canister_http_request_contexts
                    .insert(k, v);
            }

            let state_manager = Arc::new(RefMockStateManager::default());
            state_manager
                .get_mut()
                .expect_get_state_at()
                .return_const(Ok(ic_interfaces_state_manager::Labeled::new(
                    Height::new(0),
                    Arc::new(init_state),
                )));
            payload_builder.state_reader = state_manager;
        }

        let validation_context = ValidationContext {
            registry_version: RegistryVersion::new(1),
            certified_height: Height::new(0),
            time: UNIX_EPOCH + CANISTER_HTTP_TIMEOUT_INTERVAL + Duration::from_secs(1),
        };

        // Build a payload
        let payload = payload_builder.build_payload(
            Height::new(1),
            NumBytes::new(1024),
            &[],
            &validation_context,
        );

        // Responses get evicted, and timeouts fill most of the available space
        let parsed_payload = bytes_to_payload(&payload).expect("Failed to parse payload");
        assert!(parsed_payload.timeouts.len() == timeout_count as usize);
        assert!(parsed_payload.responses.len() < response_count as usize);
    });
}

/// Check that the payload builder includes a divergence responses
#[test]
fn divergence_response_inclusion_test() {
    test_config_with_http_feature(true, 10, |payload_builder, canister_http_pool| {
        {
            let mut pool_access = canister_http_pool.write().unwrap();

            let (response, metadata) = test_response_and_metadata(1);

            let shares = metadata_to_shares(10, &metadata);
            add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &response);
            add_received_shares_to_pool(pool_access.deref_mut(), shares[1..4].to_vec());

            // Ensure that one bad apple can't cause us to report divergence
            add_received_shares_to_pool(
                pool_access.deref_mut(),
                (0..10_u8)
                    .map(|i| {
                        let (_, metadata) = test_response_and_metadata_with_content(
                            1,
                            CanisterHttpResponseContent::Success(vec![i]),
                        );
                        metadata_to_share(7, &metadata)
                    })
                    .collect(),
            );
        }

        let validation_context = ValidationContext {
            registry_version: RegistryVersion::new(1),
            certified_height: Height::new(0),
            time: UNIX_EPOCH + Duration::from_secs(3),
        };

        // Build a payload
        let payload = payload_builder.build_payload(
            Height::new(1),
            NumBytes::new(4 * 1024 * 1024),
            &[],
            &validation_context,
        );

        let parsed_payload = bytes_to_payload(&payload).expect("Failed to parse payload");
        assert_eq!(parsed_payload.divergence_responses.len(), 0);

        // But that if we actually get divergence, we report it
        {
            let mut pool_access = canister_http_pool.write().unwrap();

            add_received_shares_to_pool(
                pool_access.deref_mut(),
                (4..8_u8)
                    .map(|i| {
                        let (_, metadata) = test_response_and_metadata_with_content(
                            1,
                            CanisterHttpResponseContent::Success(vec![i]),
                        );
                        metadata_to_share(i.into(), &metadata)
                    })
                    .collect(),
            );
        }

        // Build a payload
        let payload = payload_builder.build_payload(
            Height::new(1),
            NumBytes::new(4 * 1024 * 1024),
            &[],
            &validation_context,
        );

        let parsed_payload = bytes_to_payload(&payload).expect("Failed to parse payload");
        assert_eq!(parsed_payload.divergence_responses.len(), 1);
    });
}

/// Submit a very large number of valid responses, then check that the
/// payload builder does not process all of them but only CANISTER_HTTP_RESPONSES_PER_BLOCK
#[test]
fn max_responses() {
    test_config_with_http_feature(true, 4, |payload_builder, canister_http_pool| {
        // Add a high number of possible responses to the pool
        (0..CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK + 200)
            .map(|callback| test_response_and_metadata(callback as u64))
            .map(|(response, metadata)| (response, metadata_to_shares(4, &metadata)))
            .for_each(|(response, shares)| {
                let mut pool_access = canister_http_pool.write().unwrap();
                add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &response);
                add_received_shares_to_pool(pool_access.deref_mut(), shares[1..4].to_vec());
            });

        let validation_context = ValidationContext {
            registry_version: RegistryVersion::new(1),
            certified_height: Height::new(0),
            time: UNIX_EPOCH + Duration::from_secs(3),
        };

        // Build a payload
        let payload = payload_builder.build_payload(
            Height::new(1),
            NumBytes::new(4 * 1024 * 1024),
            &[],
            &validation_context,
        );

        let parsed_payload = bytes_to_payload(&payload).expect("Failed to parse payload");
        assert!(
            parsed_payload.num_non_timeout_responses() <= CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK
        );

        //  Make sure the response is not contained in the payload
        payload_builder
            .validate_payload(
                Height::new(1),
                &test_proposal_context(&validation_context),
                &payload,
                &[],
            )
            .unwrap();
    })
}

/// Test that oversized payloads don't validate
#[test]
fn oversized_validation() {
    let validation_result = run_validatation_test(
        true,
        |response, _| {
            // Give response oversized content
            response.content = CanisterHttpResponseContent::Success(vec![123; 2 * 1024 * 1024]);
        },
        &default_validation_context(),
    );
    match validation_result {
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::PayloadTooBig { expected, received },
            ),
        )) if expected == 2 * 1024 * 1024 && received > expected => (),
        x => panic!("Expected PayloadTooBig, got {x:?}"),
    }
}

/// Test that payloads with wrong registry version don't validate
#[test]
fn registry_version_validation() {
    let validation_result = run_validatation_test(
        true,
        |_, metadata| {
            // Set metadata to a newer registry version
            metadata.registry_version = RegistryVersion::new(2);
        },
        &ValidationContext {
            ..default_validation_context()
        },
    );
    match validation_result {
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::RegistryVersionMismatch { .. },
            ),
        )) => (),
        x => panic!("Expected RegistryVersionMismatch, got {x:?}"),
    }
}

/// Test that payloads with wrong hash don't validate
#[test]
fn hash_validation() {
    let validation_result = run_validatation_test(
        true,
        |response, _| {
            // Change response content to have a different hash
            response.content = CanisterHttpResponseContent::Success(b"cba".to_vec());
        },
        &default_validation_context(),
    );
    match validation_result {
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::ContentHashMismatch { .. },
            ),
        )) => (),
        x => panic!("Expected ContentHashMismatch, got {x:?}"),
    }
}

/// Test that payloads which are timed out don't validate
#[test]
fn timeout_validation() {
    let validation_result = run_validatation_test(
        true,
        |_, _| { /* Nothing to modify */ },
        &ValidationContext {
            // Set the time further in the future, such that this payload is timed out
            time: UNIX_EPOCH + Duration::from_secs(20),
            ..default_validation_context()
        },
    );
    match validation_result {
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::Timeout {
                    timed_out_at,
                    validation_time,
                },
            ),
        )) if timed_out_at < validation_time => (),
        x => panic!("Expected Timeout, got {x:?}"),
    }
}

/// Test that payloads don't validate, if registry for height does not exist
#[test]
fn registry_unavailable_validation() {
    let validation_result = run_validatation_test(
        true,
        |_, _| { /* Nothing to modify */ },
        &ValidationContext {
            // Use a higher registry version, that does not exist yet
            registry_version: RegistryVersion::new(2),
            ..default_validation_context()
        },
    );
    match validation_result {
        Err(ValidationError::ValidationFailed(PayloadValidationFailure::RegistryUnavailable(
            RegistryClientError::VersionNotAvailable { version },
        ))) if version == RegistryVersion::new(2) => (),
        x => panic!("Expected RegistryUnavailable, got {x:?}"),
    }
}

/// Test that payloads don't validate when feature is disabled
///
/// NOTE: We use the fact that the feature is disabled for registry version 0, so we can still reuse
/// the existing helper functions
#[test]
fn feature_disabled_validation() {
    let validation_result = run_validatation_test(false, |_, _| {}, &default_validation_context());
    match validation_result {
        Err(ValidationError::ValidationFailed(
            PayloadValidationFailure::CanisterHttpPayloadValidationFailed(
                CanisterHttpPayloadValidationFailure::Disabled,
            ),
        )) => (),
        x => panic!("Expected Disabled, got {x:?}"),
    }
}

/// Test that duplicate payloads don't validate
#[test]
fn duplicate_validation() {
    test_config_with_http_feature(true, 4, |payload_builder, _| {
        let (response, metadata) = test_response_and_metadata(0);

        let payload = CanisterHttpPayload {
            responses: vec![response_and_metadata_to_proof(&response, &metadata)],
            timeouts: vec![],
            divergence_responses: vec![],
        };
        let payload = payload_to_bytes(&payload, NumBytes::new(4 * 1024 * 1024));
        let past_payloads = vec![PastPayload {
            height: Height::new(1),
            time: UNIX_EPOCH,
            block_hash: CryptoHashOf::from(CryptoHash(vec![])),
            payload: &payload,
        }];

        let validation_result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload,
            &past_payloads,
        );

        match validation_result {
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::DuplicateResponse(id),
                ),
            )) if id == CallbackId::new(0) => (),
            x => panic!("Expected DuplicateResponse, got {x:?}"),
        }
    });
}

/// Test the divergence response detection validation.
///
/// - Test that a divergence (50%/50% split) response validates
/// - Test that insufficient reports (50% don't respond) do not validate
/// - Test that insufficient reports (50%/25% split on 25% don't respond) do not validate
#[test]
fn divergence_response_validation_test() {
    for subnet_size in 3..MAX_SUBNET_SIZE {
        test_config_with_http_feature(true, subnet_size, |payload_builder, _| {
            let (_, metadata) = test_response_and_metadata(0);
            let (_, other_metadata) = test_response_and_metadata_with_content(
                0,
                CanisterHttpResponseContent::Success(b"other".to_vec()),
            );

            let payload = CanisterHttpPayload {
                responses: vec![],
                timeouts: vec![],
                divergence_responses: vec![CanisterHttpResponseDivergence {
                    shares: (0..subnet_size / 2)
                        .map(|node_id| metadata_to_share(node_id.try_into().unwrap(), &metadata))
                        .chain((subnet_size / 2..subnet_size).map(|node_id| {
                            metadata_to_share(node_id.try_into().unwrap(), &other_metadata)
                        }))
                        .collect(),
                }],
            };
            let payload = payload_to_bytes(&payload, NumBytes::new(4 * 1024 * 1024));

            let validation_result = payload_builder.validate_payload(
                Height::from(1),
                &test_proposal_context(&default_validation_context()),
                &payload,
                &[],
            );

            assert!(validation_result.is_ok());

            let payload = CanisterHttpPayload {
                responses: vec![],
                timeouts: vec![],
                divergence_responses: vec![CanisterHttpResponseDivergence {
                    shares: (0..subnet_size / 2)
                        .map(|node_id| metadata_to_share(node_id.try_into().unwrap(), &metadata))
                        .collect(),
                }],
            };
            let payload = payload_to_bytes(&payload, NumBytes::new(4 * 1024 * 1024));

            let validation_result = payload_builder.validate_payload(
                Height::from(1),
                &test_proposal_context(&default_validation_context()),
                &payload,
                &[],
            );

            match validation_result {
                Err(ValidationError::InvalidArtifact(
                    InvalidPayloadReason::InvalidCanisterHttpPayload(
                        InvalidCanisterHttpPayloadReason::DivergenceProofDoesNotMeetDivergenceCriteria,
                    ),
                )) => (),
                x => panic!(
                    "Expected DivergenceProofDoesNotMeetDivergenceCriteria, got {x:?}"
                ),
            }

            let (_, other_callback_id_metadata) = test_response_and_metadata(1);

            let payload = CanisterHttpPayload {
                responses: vec![],
                timeouts: vec![],
                divergence_responses: vec![CanisterHttpResponseDivergence {
                    shares: (0..subnet_size / 2)
                        .map(|node_id| metadata_to_share(node_id.try_into().unwrap(), &metadata))
                        .chain((subnet_size / 2..3 * subnet_size / 4).map(|node_id| {
                            metadata_to_share(
                                node_id.try_into().unwrap(),
                                &other_callback_id_metadata,
                            )
                        }))
                        .collect(),
                }],
            };
            let payload = payload_to_bytes(&payload, NumBytes::new(4 * 1024 * 1024));

            let validation_result = payload_builder.validate_payload(
                Height::from(1),
                &test_proposal_context(&default_validation_context()),
                &payload,
                &[],
            );

            match validation_result {
                Err(ValidationError::InvalidArtifact(
                    InvalidPayloadReason::InvalidCanisterHttpPayload(
                        InvalidCanisterHttpPayloadReason::DivergenceProofContainsMultipleCallbackIds,
                    ),
                )) => (),
                x => panic!(
                    "Expected DivergenceProofContainsMultipleCallbackIds, got {x:?}"
                ),
            }
        });
    }
}

/// Check that the divergence error message is constructed correctly and readable
#[test]
fn divergence_error_message() {
    let (_, metadata) = test_response_and_metadata(1);

    let mut rng = ChaCha20Rng::seed_from_u64(1337);
    let mut response_shares = (0..6)
        .map(|node_id| {
            let mut sample = metadata.clone();
            let mut new_hash = [0; 32];
            rng.fill(&mut new_hash);

            sample.content_hash = CryptoHashOf::from(CryptoHash(new_hash.to_vec()));

            Signed {
                content: sample,
                signature: BasicSignature {
                    signature: BasicSigOf::new(BasicSig(vec![])),
                    signer: node_test_id(node_id),
                },
            }
        })
        .collect::<Vec<_>>();

    // Duplicate some responses
    response_shares.push(response_shares[0].clone());
    response_shares.push(response_shares[0].clone());
    response_shares.push(response_shares[1].clone());

    let divergence_response = CanisterHttpResponseDivergence {
        shares: response_shares,
    };

    let divergence_reject = divergence_response_into_reject(&divergence_response).unwrap();

    assert_eq!(
        divergence_reject.payload,
        Payload::Reject(RejectContext::new(
            RejectCode::SysTransient,
            "No consensus could be reached. Replicas had different responses. \
            Details: request_id: 1, timeout: 10000000000, hashes: \
            [30bb6555f891c35fbc820c74a7db7c1ae621f924340712e12febe78a9be0a908: 3], \
            [e93edfdefc581e2bdb54a08b55dd67bc675afafbbb32697ef6b8bf9cc75fe69b: 2], \
            [af4dcbc617e83bc998190e3031123dbd26bcf0c5a5013b5465017234a98f7d74: 1], \
            [51a9af560377af0994fe4be465ea5adff3372623c6ac692c4d3e23b323ef8486: 1], \
            [2b7e888246a3b450c67396062e53c8b6c4b776e082e7d2a81c5536e89fe6013e: 1], \
            [000b3b9ca14f1136c076b7f681b0a496f5108f721833e6465d0671c014e60b43: 1]"
                .to_string()
        ))
    );
}

#[test]
fn non_replicated_request_response_coming_in_gossip_payload_created() {
    // This test ensures that when a non-replicated request is delegated to
    // a different node than the block maker, and the response is gossiped
    // back to the block maker, the payload builder correctly includes the response.

    test_config_with_http_feature(true, 4, |mut payload_builder, canister_http_pool| {
        // In the test setup, the block maker is node 0. We'll make node 1 delegated.
        let delegated_node_id = node_test_id(1);
        let callback_id = CallbackId::from(42);

        let request_context = CanisterHttpRequestContext {
            request: RequestBuilder::default().build(),
            url: "https://example.com".to_string(),
            max_response_bytes: None,
            headers: vec![],
            body: None,
            http_method: CanisterHttpMethod::GET,
            transform: None,
            time: UNIX_EPOCH,
            replication: ic_types::canister_http::Replication::NonReplicated(delegated_node_id),
            pricing_version: ic_types::canister_http::PricingVersion::Legacy,
        };

        // Insert the context in the replicated state
        let mut init_state = ic_test_utilities_state::get_initial_state(0, 0);
        init_state
            .metadata
            .subnet_call_context_manager
            .canister_http_request_contexts
            .insert(callback_id, request_context);

        let state_manager = Arc::new(RefMockStateManager::default());
        state_manager
            .get_mut()
            .expect_get_state_at()
            .return_const(Ok(ic_interfaces_state_manager::Labeled::new(
                Height::new(0),
                Arc::new(init_state),
            )));
        payload_builder.state_reader = state_manager;

        // Create artifact containing response.
        let (response, metadata) = test_response_and_metadata(callback_id.get());
        let share = metadata_to_share(node_id_to_u64(delegated_node_id), &metadata);

        // Add the artifact to the pool.
        {
            let mut pool_access = canister_http_pool.write().unwrap();
            add_received_artifacts_to_pool(
                pool_access.deref_mut(),
                vec![CanisterHttpResponseArtifact {
                    share,
                    response: Some(response),
                }],
            );
        }

        // ACT
        let payload = payload_builder.build_payload(
            Height::new(1),
            NumBytes::new(MAX_CANISTER_HTTP_PAYLOAD_SIZE as u64),
            &[],
            &default_validation_context(),
        );

        // ASSERT
        payload_builder
            .validate_payload(
                Height::from(1),
                &test_proposal_context(&default_validation_context()),
                &payload,
                &[],
            )
            .unwrap();

        let parsed_payload = bytes_to_payload(&payload).expect("Failed to parse payload");

        // We should have exactly one response in the payload.
        assert_eq!(
            parsed_payload.responses.len(),
            1,
            "Expected exactly one response in the payload"
        );

        // The response must contain one signature.
        let proof = &parsed_payload.responses[0].proof;
        assert_eq!(
            proof.signature.signatures_map.len(),
            1,
            "Proof should contain exactly one signature"
        );
        assert!(
            proof
                .signature
                .signatures_map
                .contains_key(&delegated_node_id),
            "The single signature must be from the delegated node"
        );
    });
}

#[test]
fn non_replicated_request_with_extra_share_includes_only_delegated_share() {
    // This test ensures that if the pool contains both a valid share from the
    // delegated node and a stray share from another node for the same non-replicated
    // request, the logic correctly includes ONLY the valid share in the proof.

    test_config_with_http_feature(true, 4, |mut payload_builder, canister_http_pool| {
        // In the test setup, the block maker is node 0. We'll make this the delegated node.
        let delegated_node_id = node_test_id(0);
        let other_node_id = node_test_id(1);
        let callback_id = CallbackId::from(42);

        // Setup a non-replicated request delegated to our block maker (`delegated_node_id`).
        let request_context = CanisterHttpRequestContext {
            request: RequestBuilder::default().build(),
            url: "https://example.com".to_string(),
            max_response_bytes: None,
            headers: vec![],
            body: None,
            http_method: CanisterHttpMethod::GET,
            transform: None,
            time: UNIX_EPOCH,
            replication: ic_types::canister_http::Replication::NonReplicated(delegated_node_id),
            pricing_version: ic_types::canister_http::PricingVersion::Legacy,
        };

        // Insert the context in the replicated state
        let mut init_state = ic_test_utilities_state::get_initial_state(0, 0);
        init_state
            .metadata
            .subnet_call_context_manager
            .canister_http_request_contexts
            .insert(callback_id, request_context);

        let state_manager = Arc::new(RefMockStateManager::default());
        state_manager
            .get_mut()
            .expect_get_state_at()
            .return_const(Ok(ic_interfaces_state_manager::Labeled::new(
                Height::new(0),
                Arc::new(init_state),
            )));
        payload_builder.state_reader = state_manager;

        // Create two shares for the same metadata: one from the correct delegated
        // node, and one from another "malicious" node.
        let (response, metadata) = test_response_and_metadata(callback_id.get());
        let correct_share = metadata_to_share(node_id_to_u64(delegated_node_id), &metadata);
        let extra_share = metadata_to_share(node_id_to_u64(other_node_id), &metadata);

        // Add both shares to the pool.
        //    - The block maker (which is the delegated_node_id) adds its own share and content.
        //    - It also receives the "extra" share from the other node.
        {
            let mut pool_access = canister_http_pool.write().unwrap();
            add_own_share_to_pool(pool_access.deref_mut(), &correct_share, &response);
            add_received_shares_to_pool(pool_access.deref_mut(), vec![extra_share]);
        }

        // ACT
        let payload = payload_builder.build_payload(
            Height::new(1),
            NumBytes::new(MAX_CANISTER_HTTP_PAYLOAD_SIZE as u64),
            &[],
            &default_validation_context(),
        );

        // ASSERT
        payload_builder
            .validate_payload(
                Height::from(1),
                &test_proposal_context(&default_validation_context()),
                &payload,
                &[],
            )
            .unwrap();

        let parsed_payload = bytes_to_payload(&payload).expect("Failed to parse payload");

        // We should have exactly one response in the payload.
        assert_eq!(
            parsed_payload.responses.len(),
            1,
            "Expected exactly one response in the payload"
        );

        // The response must contain EXACTLY ONE signature, proving the "extra" share was ignored.
        let proof = &parsed_payload.responses[0].proof;
        assert_eq!(
            proof.signature.signatures_map.len(),
            1,
            "Proof should contain exactly one signature"
        );
        assert!(
            proof
                .signature
                .signatures_map
                .contains_key(&delegated_node_id),
            "The single signature must be from the delegated node"
        );
    });
}

#[test]
fn non_replicated_share_is_ignored_if_content_is_missing() {
    // This test verifies that even if a valid share for a non-replicated request
    // is in the pool, if the block maker does not also have the corresponding
    // content, the response is not included in the payload.
    // As shares are still gossiped, this will occur in production, whenever a
    // node that is not delegated becomes block maker.

    // ARRANGE
    test_config_with_http_feature(true, 4, |mut payload_builder, canister_http_pool| {
        // The request is delegated to node 1. The block maker is node 0.
        let delegated_node_id = node_test_id(1);
        let callback_id = CallbackId::from(55);

        // 1. Setup the NonReplicated request context in the state.
        let request_context = CanisterHttpRequestContext {
            request: RequestBuilder::default().build(),
            url: "https://example.com".to_string(),
            max_response_bytes: None,
            headers: vec![],
            body: None,
            http_method: CanisterHttpMethod::GET,
            transform: None,
            time: UNIX_EPOCH,
            replication: ic_types::canister_http::Replication::NonReplicated(delegated_node_id),
            pricing_version: ic_types::canister_http::PricingVersion::Legacy,
        };

        let mut init_state = ic_test_utilities_state::get_initial_state(0, 0);
        init_state
            .metadata
            .subnet_call_context_manager
            .canister_http_request_contexts
            .insert(callback_id, request_context);

        let state_manager = Arc::new(RefMockStateManager::default());
        state_manager
            .get_mut()
            .expect_get_state_at()
            .return_const(Ok(ic_interfaces_state_manager::Labeled::new(
                Height::new(0),
                Arc::new(init_state),
            )));
        payload_builder.state_reader = state_manager;

        // 2. Create a valid share from the delegated node.
        let (_, metadata) = test_response_and_metadata(callback_id.get());
        let correct_share = metadata_to_share(node_id_to_u64(delegated_node_id), &metadata);

        // 3. Add the share to the pool.
        // This adds the metadata but NOT the content.
        {
            let mut pool_access = canister_http_pool.write().unwrap();
            add_received_shares_to_pool(pool_access.deref_mut(), vec![correct_share]);
        }

        // ACT
        let payload = payload_builder.build_payload(
            Height::new(1),
            NumBytes::new(MAX_CANISTER_HTTP_PAYLOAD_SIZE as u64),
            &[],
            &default_validation_context(),
        );

        // ASSERT
        // The builder will find the valid share, but the subsequent call to
        // `get_response_content_by_hash` will fail, so the payload must be empty.
        payload_builder
            .validate_payload(
                Height::from(1),
                &test_proposal_context(&default_validation_context()),
                &payload,
                &[],
            )
            .unwrap();

        let parsed_payload = bytes_to_payload(&payload).expect("Failed to parse payload");
        assert_eq!(
            parsed_payload,
            CanisterHttpPayload::default(),
            "Payload should be empty as the content for the valid share is missing."
        );
    });
}

#[test]
fn validate_payload_succeeds_for_valid_non_replicated_response() {
    // ARRANGE
    test_config_with_http_feature(true, 4, |mut payload_builder, _| {
        let delegated_node_id = node_test_id(1);
        let callback_id = CallbackId::from(77);

        // 1. Create a context where the request is delegated to `delegated_node_id`.
        // This context will be used during validation.
        let request_context = CanisterHttpRequestContext {
            request: RequestBuilder::default().build(),
            url: String::new(),
            max_response_bytes: None,
            headers: vec![],
            body: None,
            http_method: CanisterHttpMethod::GET,
            transform: None,
            time: UNIX_EPOCH,
            replication: ic_types::canister_http::Replication::NonReplicated(delegated_node_id),
            pricing_version: ic_types::canister_http::PricingVersion::Legacy,
        };

        // Inject this context into the state reader used by the validator.
        let mut init_state = ic_test_utilities_state::get_initial_state(0, 0);
        init_state
            .metadata
            .subnet_call_context_manager
            .canister_http_request_contexts
            .insert(callback_id, request_context);
        let state_manager = Arc::new(RefMockStateManager::default());
        state_manager
            .get_mut()
            .expect_get_state_at()
            .return_const(Ok(ic_interfaces_state_manager::Labeled::new(
                Height::new(0),
                Arc::new(init_state),
            )));
        payload_builder.state_reader = state_manager;

        // 2. Craft a perfect payload containing one non-replicated response.
        let (response, metadata) = test_response_and_metadata(callback_id.get());
        let mut proof = response_and_metadata_to_proof(&response, &metadata);
        // The proof must contain exactly ONE signature, from the DELEGATED node.
        proof
            .proof
            .signature
            .signatures_map
            .insert(delegated_node_id, BasicSigOf::new(BasicSig(vec![])));

        let payload = CanisterHttpPayload {
            responses: vec![proof],
            ..Default::default()
        };
        let payload_bytes = payload_to_bytes(&payload, NumBytes::new(4 * 1024 * 1024));

        // ACT & ASSERT
        let validation_result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload_bytes,
            &[],
        );

        assert!(validation_result.is_ok());
    });
}

#[test]
fn validate_payload_fails_for_non_replicated_response_with_wrong_signer() {
    // ARRANGE
    test_config_with_http_feature(true, 4, |mut payload_builder, _| {
        let delegated_node_id = node_test_id(1);
        let wrong_signer_node_id = node_test_id(2); // The node that incorrectly signs
        let callback_id = CallbackId::from(88);

        // 1. Create a context delegating the request to `delegated_node_id`.
        let request_context = CanisterHttpRequestContext {
            request: RequestBuilder::default().build(),
            url: String::new(),
            max_response_bytes: None,
            headers: vec![],
            body: None,
            http_method: CanisterHttpMethod::GET,
            transform: None,
            time: UNIX_EPOCH,
            replication: ic_types::canister_http::Replication::NonReplicated(delegated_node_id),
            pricing_version: ic_types::canister_http::PricingVersion::Legacy,
        };

        // Inject this context into the state reader.
        let mut init_state = ic_test_utilities_state::get_initial_state(0, 0);
        init_state
            .metadata
            .subnet_call_context_manager
            .canister_http_request_contexts
            .insert(callback_id, request_context);
        let state_manager = Arc::new(RefMockStateManager::default());
        state_manager
            .get_mut()
            .expect_get_state_at()
            .return_const(Ok(ic_interfaces_state_manager::Labeled::new(
                Height::new(0),
                Arc::new(init_state),
            )));
        payload_builder.state_reader = state_manager;

        // 2. Craft a malicious payload where the proof contains only one signature,
        //    but it's from the wrong node.
        let (response, metadata) = test_response_and_metadata(callback_id.get());
        let mut proof = response_and_metadata_to_proof(&response, &metadata);

        proof.proof.signature.signatures_map.insert(
            wrong_signer_node_id, // The illegal signature
            BasicSigOf::new(BasicSig(vec![])),
        );

        let payload = CanisterHttpPayload {
            responses: vec![proof],
            ..Default::default()
        };
        let payload_bytes = payload_to_bytes(&payload, NumBytes::new(4 * 1024 * 1024));

        // ACT
        let validation_result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload_bytes,
            &[],
        );

        // ASSERT
        // Validation must fail because the effective committee for this request is just
        // `[delegated_node_id]`. Since the only signature present is from
        // `wrong_signer_node_id`, there will be no valid signers and one invalid signer.
        match validation_result {
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::SignersNotMembers {
                        invalid_signers, ..
                    },
                ),
            )) => {
                // The `invalid_signers` list should contain our one wrong signer.
                assert_eq!(invalid_signers, vec![wrong_signer_node_id]);
            }
            res => panic!("Expected SignersNotMembers error, but got {res:?}"),
        }
    });
}

#[test]
fn validate_payload_fails_for_response_with_no_signatures() {
    // ARRANGE
    test_config_with_http_feature(true, 4, |mut payload_builder, _| {
        let delegated_node_id = node_test_id(1);
        let callback_id = CallbackId::from(99);

        // 1. A request context is still needed for the validator to determine the
        //    effective committee and threshold.
        let request_context = CanisterHttpRequestContext {
            request: RequestBuilder::default().build(),
            url: String::new(),
            max_response_bytes: None,
            headers: vec![],
            body: None,
            http_method: CanisterHttpMethod::GET,
            transform: None,
            time: UNIX_EPOCH,
            replication: ic_types::canister_http::Replication::NonReplicated(delegated_node_id),
            pricing_version: ic_types::canister_http::PricingVersion::Legacy,
        };

        // Inject this context into the state reader used by the validator.
        let mut init_state = ic_test_utilities_state::get_initial_state(0, 0);
        init_state
            .metadata
            .subnet_call_context_manager
            .canister_http_request_contexts
            .insert(callback_id, request_context);
        let state_manager = Arc::new(RefMockStateManager::default());
        state_manager
            .get_mut()
            .expect_get_state_at()
            .return_const(Ok(ic_interfaces_state_manager::Labeled::new(
                Height::new(0),
                Arc::new(init_state),
            )));
        payload_builder.state_reader = state_manager;

        // 2. Craft a payload where the proof for the response contains no signatures.
        let (response, metadata) = test_response_and_metadata(callback_id.get());
        let mut proof = response_and_metadata_to_proof(&response, &metadata);

        // Ensure the signature map is empty.
        proof.proof.signature.signatures_map = BTreeMap::new();

        let payload = CanisterHttpPayload {
            responses: vec![proof],
            ..Default::default()
        };
        let payload_bytes = payload_to_bytes(&payload, NumBytes::new(4 * 1024 * 1024));

        // ACT
        let validation_result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload_bytes,
            &[],
        );

        // ASSERT
        // Validation must fail because the number of valid signers (0) is less
        // than the required threshold (1 for a NonReplicated request).
        match validation_result {
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::NotEnoughSigners {
                        signers,
                        expected_threshold,
                        ..
                    },
                ),
            )) => {
                assert!(signers.is_empty(), "There should be no valid signers");
                assert_eq!(expected_threshold, 1, "Expected threshold should be 1");
            }
            res => panic!("Expected NotEnoughSigners error, but got {res:?}"),
        }
    });
}

#[test]
fn validate_payload_fails_when_non_replicated_proof_is_for_fully_replicated_request() {
    // This test ensures the validator rejects a payload that provides a single-signature
    // proof (as if for a NonReplicated request) when the true context in the state
    // indicates the request was actually FullyReplicated, thus requiring more signatures.

    // ARRANGE
    // Use a subnet of 4, where the threshold for a replicated request is 2f+1 = 3.
    let subnet_size = 4;
    test_config_with_http_feature(true, subnet_size, |mut payload_builder, _| {
        let signer_node_id = node_test_id(1);
        let callback_id = CallbackId::from(101);

        // 1. Create a context where the request is FullyReplicated. This is what
        //    the validator will see in the certified state and treat as the source of truth.
        let request_context = CanisterHttpRequestContext {
            request: RequestBuilder::default().build(),
            url: String::new(),
            max_response_bytes: None,
            headers: vec![],
            body: None,
            http_method: CanisterHttpMethod::GET,
            transform: None,
            time: UNIX_EPOCH,
            // The state says the request is replicated.
            replication: ic_types::canister_http::Replication::FullyReplicated,
            pricing_version: ic_types::canister_http::PricingVersion::Legacy,
        };

        // Inject this context into the state reader.
        let mut init_state = ic_test_utilities_state::get_initial_state(0, 0);
        init_state
            .metadata
            .subnet_call_context_manager
            .canister_http_request_contexts
            .insert(callback_id, request_context);
        let state_manager = Arc::new(RefMockStateManager::default());
        state_manager
            .get_mut()
            .expect_get_state_at()
            .return_const(Ok(ic_interfaces_state_manager::Labeled::new(
                Height::new(0),
                Arc::new(init_state),
            )));
        payload_builder.state_reader = state_manager;

        // 2. Craft a payload that provides a proof with only a single signature,
        //    as if it were for a NonReplicated request.
        let (response, metadata) = test_response_and_metadata(callback_id.get());
        let mut proof = response_and_metadata_to_proof(&response, &metadata);

        // The proof only contains one signature.
        proof
            .proof
            .signature
            .signatures_map
            .insert(signer_node_id, BasicSigOf::new(BasicSig(vec![])));

        let payload = CanisterHttpPayload {
            responses: vec![proof],
            ..Default::default()
        };
        let payload_bytes = payload_to_bytes(&payload, NumBytes::new(4 * 1024 * 1024));

        // ACT
        let validation_result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload_bytes,
            &[],
        );

        // ASSERT
        // Validation must fail. The validator looks at the state, sees the request
        // is FullyReplicated, and determines the threshold is 3. The payload only
        // provides 1 signature, so it fails with NotEnoughSigners.
        match validation_result {
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::NotEnoughSigners {
                        signers,
                        expected_threshold,
                        ..
                    },
                ),
            )) => {
                assert_eq!(signers.len(), 1, "There should be one valid signer found");
                // For a subnet of 4, faults tolerated f=1, threshold 2f+1=3
                assert_eq!(
                    expected_threshold, 3,
                    "Expected threshold for replicated request was not met"
                );
            }
            res => panic!("Expected NotEnoughSigners error, but got {res:?}"),
        }
    });
}

#[test]
fn validate_payload_fails_for_duplicate_non_replicated_response() {
    // This test ensures the validator rejects a payload containing two identical
    // proofs for the same NonReplicated request.

    // ARRANGE
    test_config_with_http_feature(true, 4, |mut payload_builder, _| {
        let delegated_node_id = node_test_id(1);
        let duplicate_callback_id = CallbackId::from(102);

        // 1. Define the context for the NonReplicated request.
        let request_context = CanisterHttpRequestContext {
            request: RequestBuilder::default().build(),
            url: String::new(),
            max_response_bytes: None,
            headers: vec![],
            body: None,
            http_method: CanisterHttpMethod::GET,
            transform: None,
            time: UNIX_EPOCH,
            replication: ic_types::canister_http::Replication::NonReplicated(delegated_node_id),
            pricing_version: ic_types::canister_http::PricingVersion::Legacy,
        };

        // 2. Inject this context into the state reader
        let mut init_state = ic_test_utilities_state::get_initial_state(0, 0);
        init_state
            .metadata
            .subnet_call_context_manager
            .canister_http_request_contexts
            .insert(duplicate_callback_id, request_context);
        let state_manager = Arc::new(RefMockStateManager::default());
        state_manager
            .get_mut()
            .expect_get_state_at()
            .return_const(Ok(ic_interfaces_state_manager::Labeled::new(
                Height::new(0),
                Arc::new(init_state),
            )));
        payload_builder.state_reader = state_manager;

        // 3. Craft a valid proof for the NonReplicated response.
        let (response, metadata) = test_response_and_metadata(duplicate_callback_id.get());
        let mut proof = response_and_metadata_to_proof(&response, &metadata);
        proof
            .proof
            .signature
            .signatures_map
            .insert(delegated_node_id, BasicSigOf::new(BasicSig(vec![])));

        // 4. Create a payload that includes this same proof twice.
        let payload = CanisterHttpPayload {
            responses: vec![proof.clone(), proof], // Duplicate the proof
            ..Default::default()
        };
        let payload_bytes = payload_to_bytes(&payload, NumBytes::new(4 * 1024 * 1024));

        // ACT
        let validation_result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload_bytes,
            &[],
        );

        // ASSERT
        // Validation must fail because two responses for the same NonReplicated
        // request ID are not allowed.
        match validation_result {
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::DuplicateResponse(callback_id),
                ),
            )) => {
                assert_eq!(
                    callback_id, duplicate_callback_id,
                    "The error should report the correct duplicate callback ID"
                );
            }
            res => panic!("Expected DuplicateResponse error, but got {res:?}"),
        }
    });
}

/// Build some test metadata and response, which is valid and can be used in
/// different tests
pub(crate) fn test_response_and_metadata(
    callback_id: u64,
) -> (CanisterHttpResponse, CanisterHttpResponseMetadata) {
    test_response_and_metadata_with_content(
        callback_id,
        CanisterHttpResponseContent::Success(b"abc".to_vec()),
    )
}

/// Create response and metadata objects, with specified callback AND timeout
fn test_response_and_metadata_with_timeout(
    callback_id: u64,
    timeout: Time,
) -> (CanisterHttpResponse, CanisterHttpResponseMetadata) {
    test_response_and_metadata_full(
        callback_id,
        timeout,
        CanisterHttpResponseContent::Success(b"abc".to_vec()),
    )
}

/// Create response and metadata with a specified content, with
/// a 10-second timeout default.
fn test_response_and_metadata_with_content(
    callback_id: u64,
    content: CanisterHttpResponseContent,
) -> (CanisterHttpResponse, CanisterHttpResponseMetadata) {
    test_response_and_metadata_full(callback_id, UNIX_EPOCH + Duration::from_secs(10), content)
}

/// Create a response and a supporting metadata object from the response content.
fn test_response_and_metadata_full(
    callback_id: u64,
    timeout: Time,
    content: CanisterHttpResponseContent,
) -> (CanisterHttpResponse, CanisterHttpResponseMetadata) {
    // Build a response
    let response = CanisterHttpResponse {
        id: CallbackId::new(callback_id),
        timeout,
        canister_id: canister_test_id(0),
        content,
    };
    // Create metadata of response
    let metadata = CanisterHttpResponseMetadata {
        id: response.id,
        timeout: response.timeout,
        content_hash: crypto_hash(&response),
        registry_version: RegistryVersion::new(1),
        replica_version: ReplicaVersion::default(),
    };
    (response, metadata)
}

pub(crate) fn add_received_artifacts_to_pool(
    pool: &mut dyn MutablePool<CanisterHttpResponseArtifact, Mutations = CanisterHttpChangeSet>,
    artifacts: Vec<CanisterHttpResponseArtifact>,
) {
    for artifact in artifacts {
        pool.insert(UnvalidatedArtifact {
            message: artifact.clone(),
            peer_id: node_test_id(0),
            timestamp: UNIX_EPOCH,
        });

        pool.apply(vec![CanisterHttpChangeAction::MoveToValidated(
            artifact.share,
        )]);
    }
}

/// Replicates the behaviour of receiving and successfully validating a share over the network
pub(crate) fn add_received_shares_to_pool(
    pool: &mut dyn MutablePool<CanisterHttpResponseArtifact, Mutations = CanisterHttpChangeSet>,
    shares: Vec<CanisterHttpResponseShare>,
) {
    for share in shares {
        let artifact = artifact_from_share(share);

        pool.insert(UnvalidatedArtifact {
            message: artifact.clone(),
            peer_id: node_test_id(0),
            timestamp: UNIX_EPOCH,
        });

        pool.apply(vec![CanisterHttpChangeAction::MoveToValidated(
            artifact.share,
        )]);
    }
}

/// Replicates the behaviour of adding your own share (and content) to the pool
pub(crate) fn add_own_share_to_pool(
    pool: &mut dyn MutablePool<CanisterHttpResponseArtifact, Mutations = CanisterHttpChangeSet>,
    share: &CanisterHttpResponseShare,
    content: &CanisterHttpResponse,
) {
    pool.apply(vec![CanisterHttpChangeAction::AddToValidated(
        share.clone(),
        content.clone(),
    )]);
}

pub(crate) fn artifact_from_share(
    share: CanisterHttpResponseShare,
) -> CanisterHttpResponseArtifact {
    // Fully replicated behaviour.
    CanisterHttpResponseArtifact {
        share,
        response: None,
    }
}

/// Creates a [`CanisterHttpResponseShare`] from [`CanisterHttpResponseMetadata`]
pub(crate) fn metadata_to_share(
    from_node: u64,
    metadata: &CanisterHttpResponseMetadata,
) -> CanisterHttpResponseShare {
    metadata_to_share_with_signature(from_node, metadata, vec![])
}

pub(crate) fn metadata_to_share_with_signature(
    from_node: u64,
    metadata: &CanisterHttpResponseMetadata,
    signature: Vec<u8>,
) -> CanisterHttpResponseShare {
    Signed {
        content: metadata.clone(),
        signature: BasicSignature {
            signature: BasicSigOf::new(BasicSig(signature)),
            signer: node_test_id(from_node),
        },
    }
}

/// Creates a [`CanisterHttpResponseWithConsensus`] from a [`CanisterHttpResponse`] and [`CanisterHttpResponseMetadata`]
pub(crate) fn response_and_metadata_to_proof(
    response: &CanisterHttpResponse,
    metadata: &CanisterHttpResponseMetadata,
) -> CanisterHttpResponseWithConsensus {
    CanisterHttpResponseWithConsensus {
        content: response.clone(),
        proof: Signed {
            content: metadata.clone(),
            signature: BasicSignatureBatch {
                signatures_map: BTreeMap::new(),
            },
        },
    }
}

/// Creates a vector of [`CanisterHttpResponseShare`]s by calling [`metadata_to_share`]
pub(crate) fn metadata_to_shares(
    num_nodes: usize,
    metadata: &CanisterHttpResponseMetadata,
) -> Vec<CanisterHttpResponseShare> {
    (0..num_nodes)
        .map(|id| metadata_to_share(id.try_into().unwrap(), metadata))
        .collect()
}

/// Mock up a test node, which has the feature enabled
pub(crate) fn test_config_with_http_feature<T>(
    https_feature_flag: bool,
    num_nodes: usize,
    run: impl FnOnce(CanisterHttpPayloadBuilderImpl, Arc<RwLock<CanisterHttpPoolImpl>>) -> T,
) -> T {
    let committee = (0..num_nodes)
        .map(|id| node_test_id(id as u64))
        .collect::<Vec<_>>();
    ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
        let mut subnet_record = SubnetRecordBuilder::from(&committee).build();

        subnet_record.features = Some(
            SubnetFeatures {
                http_requests: https_feature_flag,
                ..SubnetFeatures::default()
            }
            .into(),
        );

        let Dependencies {
            crypto,
            registry,
            pool,
            canister_http_pool,
            state_manager,
            ..
        } = dependencies_with_subnet_params(
            pool_config,
            subnet_test_id(0),
            vec![(1, subnet_record)],
        );

        let payload_builder = CanisterHttpPayloadBuilderImpl::new(
            canister_http_pool.clone(),
            pool.get_cache(),
            crypto,
            state_manager,
            subnet_test_id(0),
            registry,
            &MetricsRegistry::new(),
            no_op_logger(),
        );

        run(payload_builder, canister_http_pool)
    })
}

/// The [`ProposalContext`] used in the validation tests
pub(crate) fn test_proposal_context(validation_context: &ValidationContext) -> ProposalContext<'_> {
    ProposalContext {
        proposer: node_test_id(0),
        validation_context,
    }
}

/// The default validation context used in the validation tests
pub(crate) fn default_validation_context() -> ValidationContext {
    ValidationContext {
        registry_version: RegistryVersion::new(1),
        certified_height: Height::new(0),
        time: UNIX_EPOCH + Duration::from_secs(5),
    }
}

/// Mocks up a test environment and test response and metadata. Lets the caller modify them and
/// then runs validation on it and returns the validation result.
///
/// This is useful to run a number of tests against the payload validator, without the need
/// to mock up all needed structures again and again.
fn run_validatation_test<F>(
    https_feature_flag: bool,
    mut modify: F,
    validation_context: &ValidationContext,
) -> Result<(), PayloadValidationError>
where
    F: FnMut(&mut CanisterHttpResponse, &mut CanisterHttpResponseMetadata),
{
    test_config_with_http_feature(https_feature_flag, 4, |payload_builder, _| {
        let (mut response, mut metadata) = test_response_and_metadata(0);
        modify(&mut response, &mut metadata);

        let payload = CanisterHttpPayload {
            responses: vec![response_and_metadata_to_proof(&response, &metadata)],
            timeouts: vec![],
            divergence_responses: vec![],
        };

        let payload = payload_to_bytes(&payload, NumBytes::new(4 * 1024 * 1024));
        payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(validation_context),
            &payload,
            &[],
        )
    })
}
