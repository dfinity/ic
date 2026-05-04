//! This module contains unit tests for the payload building and verification
//! of the canister http feature.
//!
//! Some tests are run over a range of subnet configurations to check for corner cases.

use super::{CanisterHttpPayloadBuilderImpl, parse};
use crate::payload_builder::{
    divergence_response_into_reject,
    parse::{bytes_to_payload, payload_to_bytes},
};
use assert_matches::assert_matches;
use candid::{Decode, Encode};
use ic_artifact_pool::canister_http_pool::CanisterHttpPoolImpl;
use ic_consensus_mocks::{Dependencies, dependencies_with_subnet_params};
use ic_error_types::RejectCode;
use ic_interfaces::{
    batch_payload::{BatchPayloadBuilder, IntoMessages, PastPayload, ProposalContext},
    canister_http::{
        CanisterHttpChangeAction, CanisterHttpChangeSet, CanisterHttpPayloadValidationFailure,
        InvalidCanisterHttpPayloadReason,
    },
    consensus::{InvalidPayloadReason, PayloadValidationError, PayloadValidationFailure},
    p2p::consensus::{MutablePool, UnvalidatedArtifact},
    validation::ValidationError,
};
use ic_interfaces_mocks::crypto::MockCrypto;
use ic_logger::replica_logger::no_op_logger;
use ic_management_canister_types_private::{
    CanisterHttpResponsePayload, FlexibleHttpGlobalError, FlexibleHttpRequestResult, HttpHeader,
    HttpRequestResourceReport,
};
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_features::SubnetFeatures;
use ic_test_utilities::state_manager::RefMockStateManager;
use ic_test_utilities_registry::SubnetRecordBuilder;
use ic_test_utilities_types::{
    ids::{canister_test_id, node_id_to_u64, node_test_id, subnet_test_id},
    messages::RequestBuilder,
};
use ic_types::{
    CountBytes, Height, NodeId, NumBytes, RegistryVersion, ReplicaVersion,
    batch::{
        CanisterHttpPayload, FlexibleCanisterHttpError, FlexibleCanisterHttpResponseWithProof,
        FlexibleCanisterHttpResponses, MAX_CANISTER_HTTP_PAYLOAD_SIZE, ValidationContext,
    },
    canister_http::{
        CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK, CANISTER_HTTP_TIMEOUT_INTERVAL, CanisterHttpMethod,
        CanisterHttpReject, CanisterHttpRequestContext, CanisterHttpResponse,
        CanisterHttpResponseArtifact, CanisterHttpResponseContent, CanisterHttpResponseDivergence,
        CanisterHttpResponseMetadata, CanisterHttpResponseShare, CanisterHttpResponseWithConsensus,
        Replication,
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
    collections::{BTreeMap, BTreeSet},
    ops::DerefMut,
    sync::{Arc, RwLock},
    time::Duration,
};

/// The maximum subnet size up to which we will check the functionality of the canister http feature.
const MAX_SUBNET_SIZE: usize = 40;

/// Byte budget used in tests, intentionally larger than [`MAX_CANISTER_HTTP_PAYLOAD_SIZE`]
/// so that test payloads are never truncated due to size limits.
const TEST_MAX_PAYLOAD_BYTES: NumBytes = NumBytes::new(2 * MAX_CANISTER_HTTP_PAYLOAD_SIZE as u64);

#[test]
fn default_payload_serializes_to_empty_vec() {
    assert!(
        parse::payload_to_bytes(
            CanisterHttpPayload::default(),
            NumBytes::new(MAX_CANISTER_HTTP_PAYLOAD_SIZE as u64)
        )
        .is_empty()
    );
}

/// Check that a single well formed request with shares makes it through the block maker
#[test]
fn single_request_test() {
    for subnet_size in 1..MAX_SUBNET_SIZE {
        test_config_with_http_feature(
            true,
            subnet_size,
            |mut payload_builder, canister_http_pool| {
                let cb_id = 0;
                inject_request_contexts(&mut payload_builder, fully_replicated_contexts([cb_id]));

                let (response, metadata) = test_response_and_metadata(cb_id);
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

                let parsed_payload = build_and_validate_and_parse_payload(&payload_builder);
                assert_eq!(parsed_payload.num_responses(), 1);
                assert_eq!(parsed_payload.responses[0].content, response);
            },
        );

        // TODO: Test that the payload building fails, if the use threshold -1 many shares.
    }
}

/// Submit a number of requests to the payload builder:
///
/// - One has insufficient support
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
        test_config_with_http_feature(
            true,
            subnet_size,
            |mut payload_builder, canister_http_pool| {
                inject_request_contexts(&mut payload_builder, fully_replicated_contexts(0..=4));

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

                    // Add a response with mismatching registry version
                    let (response, mut metadata) = test_response_and_metadata(2);
                    metadata.registry_version = RegistryVersion::new(5);
                    let shares = metadata_to_shares(subnet_size, &metadata);
                    add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &response);
                    add_received_shares_to_pool(
                        pool_access.deref_mut(),
                        shares[1..subnet_size].to_vec(),
                    );

                    // Add a oversized response
                    let (mut response, metadata) = test_response_and_metadata(3);
                    response.content =
                        CanisterHttpResponseContent::Success(vec![123; 2 * 1024 * 1024]);
                    let shares = metadata_to_shares(subnet_size, &metadata);
                    add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &response);
                    add_received_shares_to_pool(
                        pool_access.deref_mut(),
                        shares[1..subnet_size].to_vec(),
                    );

                    // Add response which is valid but we will put it into past_payloads
                    let (past_response, past_metadata) = test_response_and_metadata(4);
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
                    flexible_responses: vec![],
                    flexible_errors: vec![],
                };
                let past_payload = payload_to_bytes(past_payload, TEST_MAX_PAYLOAD_BYTES);

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
                    TEST_MAX_PAYLOAD_BYTES,
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
            },
        );
    }
}

#[test]
fn multiple_share_same_source_test() {
    for subnet_size in 3..MAX_SUBNET_SIZE {
        test_config_with_http_feature(
            true,
            subnet_size,
            |mut payload_builder, canister_http_pool| {
                let cb_id = 1;
                inject_request_contexts(&mut payload_builder, fully_replicated_contexts([cb_id]));

                {
                    let mut pool_access = canister_http_pool.write().unwrap();

                    let (response, metadata) = test_response_and_metadata(cb_id);

                    let shares = metadata_to_shares(10, &metadata);
                    add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &response);

                    // Ensure that multiple shares from a single source does not result in inclusion
                    add_received_shares_to_pool(
                        pool_access.deref_mut(),
                        (0..subnet_size)
                            .map(|i| {
                                metadata_to_share_with_signature(
                                    7,
                                    &metadata,
                                    i.to_be_bytes().to_vec(),
                                )
                            })
                            .collect(),
                    );
                }

                let parsed_payload = build_and_validate_and_parse_payload(&payload_builder);
                assert_eq!(parsed_payload.num_responses(), 0);
            },
        );
    }
}

/// Check that the payload builder includes a divergence responses
#[test]
fn divergence_response_inclusion_test() {
    test_config_with_http_feature(true, 10, |mut payload_builder, canister_http_pool| {
        let cb_id = 1;
        inject_request_contexts(&mut payload_builder, fully_replicated_contexts([cb_id]));

        {
            let mut pool_access = canister_http_pool.write().unwrap();

            let (response, metadata) = test_response_and_metadata(cb_id);

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

        let parsed_payload = build_and_validate_and_parse_payload(&payload_builder);
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

        let parsed_payload = build_and_validate_and_parse_payload(&payload_builder);
        assert_eq!(parsed_payload.divergence_responses.len(), 1);
    });
}

/// Submit a very large number of valid responses, then check that the
/// payload builder does not process all of them but only CANISTER_HTTP_RESPONSES_PER_BLOCK
#[test]
fn max_responses() {
    test_config_with_http_feature(true, 4, |mut payload_builder, canister_http_pool| {
        inject_request_contexts(
            &mut payload_builder,
            fully_replicated_contexts(0..(CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK + 200) as u64),
        );

        // Add a high number of possible responses to the pool
        (0..CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK + 200)
            .map(|callback| test_response_and_metadata(callback as u64))
            .map(|(response, metadata)| (response, metadata_to_shares(4, &metadata)))
            .for_each(|(response, shares)| {
                let mut pool_access = canister_http_pool.write().unwrap();
                add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &response);
                add_received_shares_to_pool(pool_access.deref_mut(), shares[1..4].to_vec());
            });

        let parsed_payload = build_and_validate_and_parse_payload(&payload_builder);
        assert!(
            parsed_payload.num_non_timeout_responses() <= CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK
        );
    })
}

/// Timeouts must not count against CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK.
/// Create MAX + 50 timed-out request contexts. The builder should include
/// all of them, and the resulting payload must pass validation.
#[test]
fn timeouts_bypass_max_responses_per_block() {
    let subnet_size = 4;
    let num_contexts = CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK + 50;

    test_config_with_http_feature(
        true,
        subnet_size,
        |mut payload_builder, _canister_http_pool| {
            let callback_ids = 0..num_contexts as u64;

            let contexts = fully_replicated_contexts(callback_ids.clone());
            inject_request_contexts(&mut payload_builder, contexts);

            // The contexts created above use the default time = UNIX_EPOCH, so any
            // validation time beyond UNIX_EPOCH + CANISTER_HTTP_TIMEOUT_INTERVAL
            // makes those contexts time out.
            let validation_context = ValidationContext {
                registry_version: RegistryVersion::new(1),
                certified_height: Height::new(0),
                time: UNIX_EPOCH + CANISTER_HTTP_TIMEOUT_INTERVAL + Duration::from_secs(1),
            };

            let payload = payload_builder.build_payload(
                Height::new(1),
                TEST_MAX_PAYLOAD_BYTES,
                &[],
                &validation_context,
            );

            let parsed = bytes_to_payload(&payload).expect("Failed to parse payload");

            assert_eq!(parsed.num_non_timeout_responses(), 0);
            assert_eq!(parsed.timeouts.len(), num_contexts);

            payload_builder
                .validate_payload(
                    Height::new(1),
                    &test_proposal_context(&validation_context),
                    &payload,
                    &[],
                )
                .unwrap();
        },
    );
}

/// Divergence responses must be counted by num_non_timeout_responses() and
/// therefore be subject to the CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK limit
/// during validation.
#[test]
fn divergence_responses_count_toward_max_responses() {
    test_config_with_http_feature(true, 4, |payload_builder, _| {
        let over_limit = CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK + 1;
        let divergence_responses: Vec<_> = (0..over_limit)
            .map(|i| CanisterHttpResponseDivergence {
                shares: vec![metadata_to_share(
                    0,
                    &test_response_and_metadata(i as u64).1,
                )],
            })
            .collect();

        let payload = CanisterHttpPayload {
            responses: vec![],
            timeouts: vec![],
            divergence_responses,
            flexible_responses: vec![],
            flexible_errors: vec![],
        };

        let result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes(payload, TEST_MAX_PAYLOAD_BYTES),
            &[],
        );

        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::TooManyResponses { expected, received }
                )
            )) if expected == CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK && received == over_limit
        );
    });
}

/// Test that oversized payloads don't validate
#[test]
fn oversized_validation() {
    let validation_result = run_non_flexible_validation_test(
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
    let validation_result = run_non_flexible_validation_test(
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
    let validation_result = run_non_flexible_validation_test(
        true,
        |response, _| {
            // Change response content to have a different hash
            response.content = CanisterHttpResponseContent::Success(b"cba".to_vec());
        },
        &default_validation_context(),
    );
    assert_matches!(
        validation_result,
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::ContentHashMismatch { .. },
            ),
        ))
    );
}

/// Test that payloads with wrong content size don't validate
#[test]
fn content_size_validation() {
    let validation_result = run_non_flexible_validation_test(
        true,
        |_response, metadata| {
            metadata.content_size = metadata.content_size.wrapping_add(1);
        },
        &default_validation_context(),
    );
    assert_matches!(
        validation_result,
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::ContentSizeMismatch { .. },
            ),
        ))
    );
}

/// Test that payloads with wrong is_reject flag don't validate
#[test]
fn is_reject_validation() {
    let validation_result = run_non_flexible_validation_test(
        true,
        |_response, metadata| {
            metadata.is_reject = !metadata.is_reject;
        },
        &default_validation_context(),
    );
    assert_matches!(
        validation_result,
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::IsRejectMismatch { .. },
            ),
        ))
    );
}

/// Test that payloads don't validate, if registry for height does not exist
#[test]
fn registry_unavailable_validation() {
    let validation_result = run_non_flexible_validation_test(
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
    let validation_result =
        run_non_flexible_validation_test(false, |_, _| {}, &default_validation_context());
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
            flexible_responses: vec![],
            flexible_errors: vec![],
        };
        let payload = payload_to_bytes(payload, TEST_MAX_PAYLOAD_BYTES);
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
        test_config_with_http_feature(true, subnet_size, |mut payload_builder, _| {
            inject_request_contexts(&mut payload_builder, fully_replicated_contexts([0]));
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
                flexible_responses: vec![],
                flexible_errors: vec![],
            };
            let payload = payload_to_bytes(payload, TEST_MAX_PAYLOAD_BYTES);

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
                flexible_responses: vec![],
                flexible_errors: vec![],
            };
            let payload = payload_to_bytes(payload, TEST_MAX_PAYLOAD_BYTES);

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
                flexible_responses: vec![],
                flexible_errors: vec![],
            };
            let payload = payload_to_bytes(payload, TEST_MAX_PAYLOAD_BYTES);

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

    let divergence_reject = divergence_response_into_reject(divergence_response).unwrap();

    assert_eq!(
        divergence_reject.payload,
        Payload::Reject(RejectContext::new(
            RejectCode::SysTransient,
            "No consensus could be reached. Replicas had different responses. \
            Details: request_id: 1, hashes: \
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
            refund_status: ic_types::canister_http::RefundStatus::default(),
        };

        // Insert the context in the replicated state
        inject_request_contexts(&mut payload_builder, [(callback_id, request_context)]);

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
        let parsed_payload = build_and_validate_and_parse_payload(&payload_builder);

        // ASSERT
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
            refund_status: ic_types::canister_http::RefundStatus::default(),
        };

        // Insert the context in the replicated state
        inject_request_contexts(&mut payload_builder, [(callback_id, request_context)]);

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
        let parsed_payload = build_and_validate_and_parse_payload(&payload_builder);

        // ASSERT
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
            refund_status: ic_types::canister_http::RefundStatus::default(),
        };

        inject_request_contexts(&mut payload_builder, [(callback_id, request_context)]);

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
        // The builder will find the valid share, but the subsequent call to
        // `get_response_content_by_hash` will fail, so the payload must be empty.
        let parsed_payload = build_and_validate_and_parse_payload(&payload_builder);

        // ASSERT
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
            refund_status: ic_types::canister_http::RefundStatus::default(),
        };

        // Inject this context into the state reader used by the validator.
        inject_request_contexts(&mut payload_builder, [(callback_id, request_context)]);

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
        let payload_bytes = payload_to_bytes(payload, TEST_MAX_PAYLOAD_BYTES);

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
            refund_status: ic_types::canister_http::RefundStatus::default(),
        };

        // Inject this context into the state reader.
        inject_request_contexts(&mut payload_builder, [(callback_id, request_context)]);

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
        let payload_bytes = payload_to_bytes(payload, TEST_MAX_PAYLOAD_BYTES);

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
            refund_status: ic_types::canister_http::RefundStatus::default(),
        };

        // Inject this context into the state reader used by the validator.
        inject_request_contexts(&mut payload_builder, [(callback_id, request_context)]);

        // 2. Craft a payload where the proof for the response contains no signatures.
        let (response, metadata) = test_response_and_metadata(callback_id.get());
        let mut proof = response_and_metadata_to_proof(&response, &metadata);

        // Ensure the signature map is empty.
        proof.proof.signature.signatures_map = BTreeMap::new();

        let payload = CanisterHttpPayload {
            responses: vec![proof],
            ..Default::default()
        };
        let payload_bytes = payload_to_bytes(payload, TEST_MAX_PAYLOAD_BYTES);

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
            refund_status: ic_types::canister_http::RefundStatus::default(),
        };

        // Inject this context into the state reader.
        inject_request_contexts(&mut payload_builder, [(callback_id, request_context)]);

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
        let payload_bytes = payload_to_bytes(payload, TEST_MAX_PAYLOAD_BYTES);

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
            refund_status: ic_types::canister_http::RefundStatus::default(),
        };

        // 2. Inject this context into the state reader
        inject_request_contexts(
            &mut payload_builder,
            [(duplicate_callback_id, request_context)],
        );

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
        let payload_bytes = payload_to_bytes(payload, TEST_MAX_PAYLOAD_BYTES);

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

/// Create response and metadata with a specified content.
fn test_response_and_metadata_with_content(
    callback_id: u64,
    content: CanisterHttpResponseContent,
) -> (CanisterHttpResponse, CanisterHttpResponseMetadata) {
    let response = CanisterHttpResponse {
        id: CallbackId::new(callback_id),
        canister_id: canister_test_id(0),
        content,
    };
    let metadata = CanisterHttpResponseMetadata {
        id: response.id,
        content_hash: crypto_hash(&response),
        content_size: response.content.count_bytes() as u32,
        is_reject: response.content.is_reject(),
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
fn run_non_flexible_validation_test<F>(
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
            flexible_responses: vec![],
            flexible_errors: vec![],
        };

        let payload = payload_to_bytes(payload, TEST_MAX_PAYLOAD_BYTES);
        payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(validation_context),
            &payload,
            &[],
        )
    })
}
#[test]
fn flexible_build_excludes_group_below_min_responses() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(num_nodes, callback_id, committee, 3, 4, |pb, pool| {
        // Only 2 shares, but min_responses = 3
        add_flexible_shares_to_pool(&pool, callback_id, 0..2);
        let parsed = build_and_validate_and_parse_payload(&pb);
        assert!(parsed.flexible_responses.is_empty());
    });
}

#[test]
fn flexible_build_filters_non_committee_signers() {
    let num_nodes = 5;
    // Committee is nodes 0..3; nodes 3..5 are outsiders
    let committee: BTreeSet<_> = (0..3).map(node_test_id).collect();
    let cb_id = CallbackId::from(42);

    setup_test_with_flexible_context(num_nodes, cb_id, committee.clone(), 2, 4, |pb, pool| {
        add_flexible_shares_to_pool(&pool, cb_id, 0..4);
        let parsed = build_and_validate_and_parse_payload(&pb);

        assert_eq!(parsed.flexible_responses.len(), 1);
        let group = &parsed.flexible_responses[0];
        assert!(group.responses.len() <= 3);
        for entry in &group.responses {
            assert!(committee.contains(&entry.proof.signature.signer),);
        }
    });
}

#[test]
fn flexible_build_filters_duplicate_signers() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(num_nodes, callback_id, committee, 1, 4, |pb, pool| {
        {
            let mut pool_access = pool.write().unwrap();
            // Node 0 submits two shares with different content
            for content in [b"first".as_slice(), b"second".as_slice()] {
                let (response, metadata) = test_response_and_metadata_with_content(
                    callback_id.get(),
                    CanisterHttpResponseContent::Success(content.to_vec()),
                );
                let share = metadata_to_share(0, &metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &share, &response);
            }
            // Node 1 submits one share
            let (response, metadata) = test_response_and_metadata_with_content(
                callback_id.get(),
                CanisterHttpResponseContent::Success(b"from_node_1".to_vec()),
            );
            let share = metadata_to_share(1, &metadata);
            add_own_share_to_pool(pool_access.deref_mut(), &share, &response);
        }

        let parsed = build_and_validate_and_parse_payload(&pb);
        assert_eq!(parsed.flexible_responses.len(), 1);
        let group = &parsed.flexible_responses[0];
        let signers: BTreeSet<_> = group
            .responses
            .iter()
            .map(|e| e.proof.signature.signer)
            .collect();
        assert_eq!(signers.len(), group.responses.len());
        assert_eq!(group.responses.len(), 2);
    });
}

#[test]
fn flexible_build_caps_at_max_responses() {
    let num_nodes = 6;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(num_nodes, callback_id, committee, 1, 2, |pb, pool| {
        // All 6 committee members submit shares, but max_responses = 2
        add_flexible_shares_to_pool(&pool, callback_id, 0..num_nodes as u64);
        let parsed = build_and_validate_and_parse_payload(&pb);

        assert_eq!(parsed.flexible_responses.len(), 1);
        let flexible_responses_len = parsed.flexible_responses[0].responses.len();
        assert_eq!(flexible_responses_len, 2);
    });
}

#[test]
fn flexible_build_with_zero_min_and_max_responses() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(num_nodes, callback_id, committee, 0, 0, |pb, pool| {
        add_flexible_shares_to_pool(&pool, callback_id, 0..num_nodes as u64);
        let parsed = build_and_validate_and_parse_payload(&pb);

        assert_eq!(parsed.flexible_responses.len(), 1);
        let group = &parsed.flexible_responses[0];
        assert_eq!(group.callback_id, callback_id);
        assert!(group.responses.is_empty());
    });
}

#[test]
fn flexible_build_mixed_with_regular_responses() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let flex_cb_id = CallbackId::from(42);
    let regular_cb_id = CallbackId::from(100);

    setup_test_with_contexts(
        num_nodes,
        vec![
            (flex_cb_id, flexible_request_context(committee, 1, 4)),
            (regular_cb_id, request_context(Replication::FullyReplicated)),
        ],
        |pb, pool| {
            add_flexible_shares_to_pool(&pool, flex_cb_id, 0..2);
            {
                let mut pool_access = pool.write().unwrap();
                let (response, metadata) = test_response_and_metadata(regular_cb_id.get());
                let shares = metadata_to_shares(num_nodes, &metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &response);
                add_received_shares_to_pool(pool_access.deref_mut(), shares[1..num_nodes].to_vec());
            }

            let parsed = build_and_validate_and_parse_payload(&pb);

            assert_eq!(parsed.responses.len(), 1);
            assert_eq!(parsed.responses[0].content.id, regular_cb_id);
            assert_eq!(parsed.flexible_responses.len(), 1);
            assert_eq!(parsed.flexible_responses[0].callback_id, flex_cb_id);
        },
    );
}

#[test]
fn flexible_build_respects_payload_size_limit() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(num_nodes, callback_id, committee, 1, 4, |pb, pool| {
        add_flexible_shares_to_pool(&pool, callback_id, 0..num_nodes as u64);

        let context = default_validation_context();
        let one_byte = NumBytes::new(1);
        let payload = pb.build_payload(Height::new(1), one_byte, &[], &context);
        pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&context),
            &payload,
            &[],
        )
        .expect("built payload must pass validation");
        let parsed = bytes_to_payload(&payload).expect("parse error");

        assert!(parsed.flexible_responses.is_empty(),);
    });
}

#[test]
fn flexible_build_delivers_ok_with_fewer_than_max_when_size_limited() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);
    let min = 2_u32;
    let max = 4_u32;

    setup_test_with_flexible_context(num_nodes, callback_id, committee, min, max, |pb, pool| {
        // For responses just under half of MAX_CANISTER_HTTP_PAYLOAD_SIZE, only exactly 2 fit.
        let content_size = MAX_CANISTER_HTTP_PAYLOAD_SIZE / 2 - 1000;
        {
            let mut pool_access = pool.write().unwrap();
            for node_idx in 0..num_nodes as u64 {
                let (response, metadata) = test_response_and_metadata_with_content(
                    callback_id.get(),
                    CanisterHttpResponseContent::Success(vec![0xAB; content_size]),
                );
                let share = metadata_to_share(node_idx, &metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &share, &response);
            }
        }

        let parsed = build_and_validate_and_parse_payload(&pb);

        assert_eq!(parsed.flexible_responses.len(), 1);
        assert_eq!(parsed.flexible_responses[0].responses.len(), 2);
    });
}

#[test]
fn flexible_build_respects_max_responses_per_block() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let regular_count = CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK;
    let flex_cb = CallbackId::from(regular_count as u64 + 1000);

    let mut contexts: Vec<_> = (0..regular_count)
        .map(|i| {
            (
                CallbackId::from(i as u64),
                request_context(Replication::FullyReplicated),
            )
        })
        .collect();
    contexts.push((flex_cb, flexible_request_context(committee, 1, 4)));

    setup_test_with_contexts(num_nodes, contexts, |pb, pool| {
        {
            let mut pool_access = pool.write().unwrap();
            for i in 0..regular_count {
                let cb = CallbackId::from(i as u64);
                let (response, metadata) = test_response_and_metadata(cb.get());
                let shares = metadata_to_shares(num_nodes, &metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &response);
                add_received_shares_to_pool(pool_access.deref_mut(), shares[1..num_nodes].to_vec());
            }
        }
        add_flexible_shares_to_pool(&pool, flex_cb, 0..num_nodes as u64);

        let parsed = build_and_validate_and_parse_payload(&pb);

        assert_eq!(
            parsed.num_non_timeout_responses(),
            CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK
        );
    });
}

#[test]
fn flexible_build_filters_rejects_in_ok_responses() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(num_nodes, callback_id, committee, 2, 4, |pb, pool| {
        {
            let mut pool_access = pool.write().unwrap();
            // Nodes 0 and 1 produce Reject responses
            for node_idx in 0..2_u64 {
                let (response, metadata) = test_response_and_metadata_with_content(
                    callback_id.get(),
                    CanisterHttpResponseContent::Reject(CanisterHttpReject {
                        reject_code: RejectCode::SysTransient,
                        message: format!("error_{node_idx}"),
                    }),
                );
                let share = metadata_to_share(node_idx, &metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &share, &response);
            }
            // Nodes 2 and 3 produce Success responses
            for node_idx in 2..4_u64 {
                let (response, metadata) = test_response_and_metadata_with_content(
                    callback_id.get(),
                    CanisterHttpResponseContent::Success(format!("resp_{node_idx}").into_bytes()),
                );
                let share = metadata_to_share(node_idx, &metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &share, &response);
            }
        }

        let parsed = build_and_validate_and_parse_payload(&pb);

        assert_eq!(parsed.flexible_responses.len(), 1);
        let group = &parsed.flexible_responses[0];
        assert_eq!(group.responses.len(), 2);
        for entry in &group.responses {
            assert!(matches!(
                entry.response.content,
                CanisterHttpResponseContent::Success(_)
            ));
        }
    });
}

#[test]
fn flexible_build_and_validate_round_trip() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(num_nodes, callback_id, committee, 2, 4, |pb, pool| {
        add_flexible_shares_to_pool(&pool, callback_id, 0..num_nodes as u64);

        let parsed = build_and_validate_and_parse_payload(&pb);

        assert_eq!(parsed.flexible_responses.len(), 1);
        let group = &parsed.flexible_responses[0];
        assert_eq!(group.callback_id, callback_id);
        assert!(group.responses.len() >= 2);
        assert!(group.responses.len() <= 4);
    });
}

#[test]
fn flexible_valid_mixed_content_responses() {
    let committee: BTreeSet<_> = (0..4).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(4, callback_id, committee, 2, 4, |payload_builder, _pool| {
        let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
            callback_id,
            responses: vec![
                flexible_response(42, 0, b"response_a"),
                flexible_response(42, 1, b"response_b"),
                flexible_response(42, 2, b"response_c"),
            ],
        }]);

        let result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(result, Ok(_));
    });
}

#[test]
fn flexible_valid_at_min_responses_boundary() {
    let committee: BTreeSet<_> = (0..4).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(4, callback_id, committee, 2, 4, |payload_builder, _pool| {
        let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
            callback_id,
            responses: vec![
                flexible_response(42, 0, b"a"),
                flexible_response(42, 1, b"b"),
            ],
        }]);

        let result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(result, Ok(_));
    });
}

#[test]
fn flexible_valid_at_max_responses_boundary() {
    let committee: BTreeSet<_> = (0..4).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(4, callback_id, committee, 2, 4, |payload_builder, _pool| {
        let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
            callback_id,
            responses: vec![
                flexible_response(42, 0, b"a"),
                flexible_response(42, 1, b"b"),
                flexible_response(42, 2, b"c"),
                flexible_response(42, 3, b"d"),
            ],
        }]);

        let result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(result, Ok(_));
    });
}

#[test]
fn flexible_valid_with_zero_min_and_max_responses() {
    let committee: BTreeSet<_> = (0..4).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(4, callback_id, committee, 0, 0, |payload_builder, _pool| {
        let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
            callback_id,
            responses: vec![],
        }]);

        let result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(result, Ok(_));
    });
}

#[test]
fn flexible_invalid_duplicate_callback_id_within_payload() {
    let committee: BTreeSet<_> = (0..4).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(4, callback_id, committee, 1, 4, |payload_builder, _pool| {
        let payload = flexible_payload(vec![
            FlexibleCanisterHttpResponses {
                callback_id,
                responses: vec![flexible_response(42, 0, b"a")],
            },
            FlexibleCanisterHttpResponses {
                callback_id,
                responses: vec![flexible_response(42, 1, b"b")],
            },
        ]);

        let result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::DuplicateResponse(id),
                ),
            )) if id == callback_id
        );
    });
}

#[test]
fn flexible_invalid_already_delivered_callback_id() {
    let committee: BTreeSet<_> = (0..4).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(4, callback_id, committee, 1, 4, |payload_builder, _pool| {
        let group = FlexibleCanisterHttpResponses {
            callback_id,
            responses: vec![flexible_response(42, 0, b"a")],
        };
        let past_payload = flexible_payload(vec![group.clone()]);
        let past_payload_bytes = payload_to_bytes_max_4mb(past_payload);
        let past_payloads = vec![PastPayload {
            height: Height::new(1),
            time: UNIX_EPOCH,
            block_hash: CryptoHashOf::from(CryptoHash(vec![])),
            payload: &past_payload_bytes,
        }];

        let current_payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
            callback_id,
            responses: vec![flexible_response(42, 1, b"b")],
        }]);

        let result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(current_payload),
            &past_payloads,
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::DuplicateResponse(id),
                ),
            )) if id == callback_id
        );
    });
}

#[test]
fn flexible_invalid_fewer_than_min_responses() {
    let committee: BTreeSet<_> = (0..4).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(4, callback_id, committee, 2, 4, |payload_builder, _pool| {
        let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
            callback_id,
            responses: vec![flexible_response(42, 0, b"only_one")],
        }]);

        let result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::FlexibleResponseCountOutOfRange {
                        callback_id, count, min_responses, max_responses
                    }
                )
            )) if callback_id == callback_id
                && count == 1
                && min_responses == 2
                && max_responses == 4
        );
    });
}

#[test]
fn flexible_invalid_more_than_max_responses() {
    let committee: BTreeSet<_> = (0..5_u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(5, callback_id, committee, 1, 2, |payload_builder, _pool| {
        let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
            callback_id,
            responses: vec![
                flexible_response(42, 0, b"a"),
                flexible_response(42, 1, b"b"),
                flexible_response(42, 2, b"c"),
            ],
        }]);

        let result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::FlexibleResponseCountOutOfRange {
                        callback_id, count, min_responses, max_responses
                    }
                )
            )) if callback_id == callback_id
                && count == 3
                && min_responses == 1
                && max_responses == 2
        );
    });
}

#[test]
fn flexible_invalid_empty_group_with_nonzero_min() {
    let committee: BTreeSet<_> = (0..4).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(4, callback_id, committee, 1, 4, |payload_builder, _pool| {
        let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
            callback_id,
            responses: vec![],
        }]);

        let result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::FlexibleResponseCountOutOfRange {
                        callback_id, count, min_responses, max_responses
                    }
                )
            )) if callback_id == callback_id
                && count == 0
                && min_responses == 1
                && max_responses == 4
        );
    });
}

#[test]
fn flexible_valid_empty_group_with_zero_min() {
    let committee: BTreeSet<_> = (0..4).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(4, callback_id, committee, 0, 4, |payload_builder, _pool| {
        let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
            callback_id,
            responses: vec![],
        }]);

        let result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(result, Ok(_));
    });
}

#[test]
fn flexible_invalid_callback_id_mismatch_in_proof() {
    let committee: BTreeSet<_> = (0..4).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);
    let mismatched_id = CallbackId::from(99);

    setup_test_with_flexible_context(4, callback_id, committee, 1, 4, |payload_builder, _pool| {
        let mut entry = flexible_response(42, 0, b"data");
        entry.proof.content.id = mismatched_id;

        let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
            callback_id,
            responses: vec![entry],
        }]);

        let result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::FlexibleCallbackIdMismatch { callback_id: cb_id, mismatched_id: mm_id }
                )
            )) if cb_id == callback_id && mm_id == mismatched_id
        );
    });
}

#[test]
fn flexible_invalid_duplicate_signer() {
    let committee: BTreeSet<_> = (0..4).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(4, callback_id, committee, 2, 4, |payload_builder, _pool| {
        let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
            callback_id,
            responses: vec![
                flexible_response(42, 0, b"a"),
                flexible_response(42, 0, b"b"), // same signer
            ],
        }]);

        let result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::FlexibleDuplicateSigner { callback_id, signer }
                )
            )) if callback_id == callback_id && signer == node_test_id(0)
        );
    });
}

#[test]
fn flexible_invalid_signer_not_in_committee() {
    let committee: BTreeSet<_> = (0..=2).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(4, callback_id, committee, 1, 3, |payload_builder, _pool| {
        let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
            callback_id,
            responses: vec![
                flexible_response(42, 0, b"a"),
                flexible_response(42, 3, b"b"), // node 3 not in committee
            ],
        }]);

        let result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::FlexibleSignerNotInCommittee { callback_id, signer }
                )
            )) if callback_id == callback_id && signer == node_test_id(3)
        );
    });
}

#[test]
fn flexible_invalid_content_hash_mismatch() {
    let committee: BTreeSet<_> = (0..4).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(4, callback_id, committee, 1, 4, |payload_builder, _pool| {
        let mut entry = flexible_response(42, 0, b"data");
        let expected_calculated_hash = crypto_hash(&entry.response);
        let wrong_metadata_hash = CryptoHashOf::new(CryptoHash(vec![0xff; 32]));
        entry.proof.content.content_hash = wrong_metadata_hash.clone();

        let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
            callback_id,
            responses: vec![entry],
        }]);

        let result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::ContentHashMismatch {
                        metadata_hash,
                        calculated_hash,
                    }
                )
            )) if metadata_hash == wrong_metadata_hash && calculated_hash == expected_calculated_hash
        );
    });
}

#[test]
fn flexible_invalid_content_size_mismatch() {
    let committee: BTreeSet<_> = (0..4).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(4, callback_id, committee, 1, 4, |payload_builder, _pool| {
        let mut entry = flexible_response(42, 0, b"data");
        let expected_size = entry.response.content.count_bytes() as u32;
        entry.proof.content.content_size = expected_size.wrapping_add(1);
        let wrong_size = entry.proof.content.content_size;

        let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
            callback_id,
            responses: vec![entry],
        }]);

        let result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::ContentSizeMismatch {
                        metadata_size,
                        calculated_size,
                    }
                )
            )) if metadata_size == wrong_size && calculated_size == expected_size
        );
    });
}

#[test]
fn flexible_invalid_is_reject_mismatch() {
    let committee: BTreeSet<_> = (0..4).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(4, callback_id, committee, 1, 4, |payload_builder, _pool| {
        let mut entry = flexible_response(42, 0, b"data");
        entry.proof.content.is_reject = !entry.proof.content.is_reject;

        let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
            callback_id,
            responses: vec![entry],
        }]);

        let result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::IsRejectMismatch { .. }
                )
            ))
        );
    });
}

#[test]
fn flexible_response_in_regular_section_rejected() {
    // A response whose context is Flexible must not appear in `payload.responses`.
    let committee: BTreeSet<_> = (0..4).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(4, callback_id, committee, 2, 4, |payload_builder, _pool| {
        let (response, metadata) = test_response_and_metadata(callback_id.get());
        let mut proof = response_and_metadata_to_proof(&response, &metadata);
        proof
            .proof
            .signature
            .signatures_map
            .insert(node_test_id(0), BasicSigOf::new(BasicSig(vec![])));

        let payload = CanisterHttpPayload {
            responses: vec![proof],
            ..Default::default()
        };

        let result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::InvalidPayloadSection(id),
                ),
            )) if id == callback_id
        );
    });
}

#[test]
fn non_flexible_response_in_flexible_section_rejected() {
    // A response whose context is FullyReplicated must not appear in `payload.flexible_responses`.
    let callback_id = CallbackId::from(42);
    setup_test_with_contexts(
        4,
        vec![(callback_id, request_context(Replication::FullyReplicated))],
        |payload_builder, _pool| {
            let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
                callback_id,
                responses: vec![
                    flexible_response(42, 0, b"a"),
                    flexible_response(42, 1, b"b"),
                ],
            }]);

            let result = payload_builder.validate_payload(
                Height::from(1),
                &test_proposal_context(&default_validation_context()),
                &payload_to_bytes_max_4mb(payload),
                &[],
            );
            assert_matches!(
                result,
                Err(ValidationError::InvalidArtifact(
                    InvalidPayloadReason::InvalidCanisterHttpPayload(
                        InvalidCanisterHttpPayloadReason::InvalidPayloadSection(id),
                    ),
                )) if id == callback_id
            );
        },
    );
}

#[test]
fn flexible_invalid_unknown_callback_id() {
    test_config_with_http_feature(true, 4, |mut payload_builder, _| {
        let empty_state_without_contexts = ic_test_utilities_state::get_initial_state(0, 0);
        let state_manager = Arc::new(RefMockStateManager::default());
        state_manager
            .get_mut()
            .expect_get_state_at()
            .return_const(Ok(ic_interfaces_state_manager::Labeled::new(
                Height::new(0),
                Arc::new(empty_state_without_contexts),
            )));
        payload_builder.state_reader = state_manager;

        let unknown_id = CallbackId::from(999);
        let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
            callback_id: unknown_id,
            responses: vec![flexible_response(999, 0, b"a")],
        }]);

        let result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::UnknownCallbackId(id),
                ),
            )) if id == unknown_id
        );
    });
}

#[test]
fn flexible_invalid_rejects_in_ok_responses() {
    let committee: BTreeSet<_> = (0..4).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(4, callback_id, committee, 2, 4, |payload_builder, _pool| {
        let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
            callback_id,
            responses: vec![
                flexible_response(42, 0, b"good_response"),
                flexible_reject_response(42, 1),
                flexible_response(42, 2, b"another_good"),
            ],
        }]);

        let result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::FlexibleRejectNotAllowedInOkResponses {
                        callback_id: id,
                    },
                ),
            )) if id == CallbackId::from(42)
        );
    });
}

#[test]
fn flexible_invalid_callback_id_mismatch_in_response() {
    let committee: BTreeSet<_> = (0..4).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);
    let mismatched_id = CallbackId::from(99);

    setup_test_with_flexible_context(4, callback_id, committee, 1, 4, |payload_builder, _pool| {
        let mut entry = flexible_response(42, 0, b"data");
        entry.response.id = mismatched_id;

        let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
            callback_id,
            responses: vec![entry],
        }]);

        let result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::FlexibleCallbackIdMismatch { callback_id: cb_id, mismatched_id: mm_id }
                )
            )) if cb_id == callback_id && mm_id == mismatched_id
        );
    });
}

#[test]
fn flexible_invalid_registry_version_mismatch() {
    let committee: BTreeSet<_> = (0..4).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(4, callback_id, committee, 1, 4, |payload_builder, _pool| {
        let wrong_registry_version = RegistryVersion::new(999);
        let mut entry = flexible_response(42, 0, b"data");
        entry.proof.content.registry_version = wrong_registry_version;
        let validation_context = default_validation_context();
        let expected_registry_version = validation_context.registry_version;

        let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
            callback_id,
            responses: vec![entry],
        }]);

        let result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&validation_context),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::RegistryVersionMismatch {
                        expected,
                        received,
                    }
                )
            )) if expected == expected_registry_version && received == wrong_registry_version
        );
    });
}

#[test]
fn flexible_invalid_signature_error() {
    let committee: BTreeSet<_> = (0..4).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(
        4,
        callback_id,
        committee,
        1,
        4,
        |mut payload_builder, _pool| {
            payload_builder.crypto = Arc::new(mock_crypto_rejecting_signatures());

            let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
                callback_id,
                responses: vec![flexible_response(42, 0, b"data")],
            }]);

            let result = payload_builder.validate_payload(
                Height::from(1),
                &test_proposal_context(&default_validation_context()),
                &payload_to_bytes_max_4mb(payload),
                &[],
            );
            assert_matches!(
                result,
                Err(ValidationError::InvalidArtifact(
                    InvalidPayloadReason::InvalidCanisterHttpPayload(
                        InvalidCanisterHttpPayloadReason::SignatureError(_)
                    )
                ))
            );
        },
    );
}

#[test]
fn flexible_ok_responses_into_messages_success_round_trip() {
    let callback_id = CallbackId::from(42);

    let payload_a = CanisterHttpResponsePayload {
        status: 200,
        headers: vec![HttpHeader {
            name: "content-type".to_string(),
            value: "text/plain".to_string(),
        }],
        body: b"hello from node A".to_vec(),
    };
    let payload_b = CanisterHttpResponsePayload {
        status: 201,
        headers: vec![],
        body: b"hello from node B".to_vec(),
    };

    let entry_a = flexible_response(42, 0, &Encode!(&payload_a).unwrap());
    let entry_b = flexible_response(42, 1, &Encode!(&payload_b).unwrap());

    let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
        callback_id,
        responses: vec![entry_a, entry_b],
    }]);
    let bytes = payload_to_bytes_max_4mb(payload);

    let (responses, stats) = CanisterHttpPayloadBuilderImpl::into_messages(&bytes);

    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].callback, callback_id);
    let Payload::Data(ref data) = responses[0].payload else {
        panic!("Expected Payload::Data, got {:?}", responses[0].payload);
    };
    let result = Decode!(data, FlexibleHttpRequestResult).unwrap();
    let FlexibleHttpRequestResult::Ok(payloads) = result else {
        panic!("Expected Ok variant, got {result:?}");
    };
    assert_eq!(payloads.len(), 2);
    assert_eq!(payloads[0], payload_a);
    assert_eq!(payloads[1], payload_b);
    assert_eq!(stats.flexible_ok_responses, 1);
    assert_eq!(stats.flexible_ok_responses_candid_failures, 0);
}

#[test]
fn flexible_ok_responses_into_messages_skips_reject_entries() {
    let callback_id = CallbackId::from(99);

    let good_payload = CanisterHttpResponsePayload {
        status: 200,
        headers: vec![],
        body: b"ok".to_vec(),
    };
    let success_entry = flexible_response(99, 0, &Encode!(&good_payload).unwrap());

    let (reject_response, reject_metadata) = test_response_and_metadata_with_content(
        99,
        CanisterHttpResponseContent::Reject(CanisterHttpReject {
            reject_code: RejectCode::SysTransient,
            message: "adapter error".to_string(),
        }),
    );
    let reject_entry = FlexibleCanisterHttpResponseWithProof {
        response: reject_response,
        proof: metadata_to_share(1, &reject_metadata),
    };

    let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
        callback_id,
        responses: vec![success_entry, reject_entry],
    }]);
    let bytes = payload_to_bytes_max_4mb(payload);

    let (responses, stats) = CanisterHttpPayloadBuilderImpl::into_messages(&bytes);

    assert_eq!(responses.len(), 1);
    let Payload::Data(ref data) = responses[0].payload else {
        panic!("Expected Payload::Data");
    };
    let result = Decode!(data, FlexibleHttpRequestResult).unwrap();
    let FlexibleHttpRequestResult::Ok(payloads) = result else {
        panic!("Expected Ok variant, got {result:?}");
    };
    assert_eq!(payloads.len(), 1, "Reject entry should be filtered out");
    assert_eq!(payloads[0], good_payload);
    assert_eq!(stats.flexible_ok_responses, 1);
    assert_eq!(stats.flexible_ok_responses_candid_failures, 0);
}

#[test]
fn flexible_ok_responses_into_messages_stats_count_multiple_groups() {
    let payload_data = Encode!(&CanisterHttpResponsePayload {
        status: 200,
        headers: vec![],
        body: vec![],
    })
    .unwrap();

    let group_a = FlexibleCanisterHttpResponses {
        callback_id: CallbackId::from(1),
        responses: vec![flexible_response(1, 0, &payload_data)],
    };
    let group_b = FlexibleCanisterHttpResponses {
        callback_id: CallbackId::from(2),
        responses: vec![flexible_response(2, 1, &payload_data)],
    };
    let group_c = FlexibleCanisterHttpResponses {
        callback_id: CallbackId::from(3),
        responses: vec![flexible_response(3, 2, &payload_data)],
    };

    let payload = flexible_payload(vec![group_a, group_b, group_c]);
    let bytes = payload_to_bytes_max_4mb(payload);

    let (responses, stats) = CanisterHttpPayloadBuilderImpl::into_messages(&bytes);

    assert_eq!(responses.len(), 3);
    assert_eq!(stats.flexible_ok_responses, 3);
    assert_eq!(stats.flexible_ok_responses_candid_failures, 0);
}

#[test]
fn flexible_ok_responses_into_messages_decode_failure_is_skipped() {
    let callback_id = CallbackId::from(42);

    let valid_data = Encode!(&CanisterHttpResponsePayload {
        status: 200,
        headers: vec![],
        body: vec![],
    })
    .unwrap();
    let valid_entry = flexible_response(42, 0, &valid_data);
    let invalid_entry = flexible_response(42, 1, b"this is invalid candid");

    let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
        callback_id,
        responses: vec![valid_entry, invalid_entry],
    }]);
    let bytes = payload_to_bytes_max_4mb(payload);

    let (responses, stats) = CanisterHttpPayloadBuilderImpl::into_messages(&bytes);

    assert_eq!(responses.len(), 0);
    assert_eq!(stats.flexible_ok_responses, 0);
    assert_eq!(stats.flexible_ok_responses_candid_failures, 1);
}

#[test]
fn flexible_error_into_messages_timeout() {
    let callback_id = CallbackId::from(42);

    let payload = CanisterHttpPayload {
        flexible_errors: vec![FlexibleCanisterHttpError::Timeout { callback_id }],
        ..Default::default()
    };
    let bytes = payload_to_bytes_max_4mb(payload);

    let (responses, stats) = CanisterHttpPayloadBuilderImpl::into_messages(&bytes);

    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].callback, callback_id);
    assert_eq!(stats.flexible_errors, 1);
    assert_eq!(stats.flexible_errors_candid_failures, 0);

    let Payload::Data(ref data) = responses[0].payload else {
        panic!("Expected Payload::Data, got {:?}", responses[0].payload);
    };
    let result = Decode!(data, FlexibleHttpRequestResult).unwrap();
    let FlexibleHttpRequestResult::Err(err) = result else {
        panic!("Expected Err variant, got {result:?}");
    };
    assert_eq!(
        err.global_error,
        Some(FlexibleHttpGlobalError::Timeout(candid::Reserved))
    );
    assert!(err.node_details.is_empty());
    assert!(err.message.contains("timed out"));
}

#[test]
fn flexible_error_into_messages_too_many_rejects() {
    let callback_id = CallbackId::from(42);

    let reject_entries: Vec<_> = (0..2_u64)
        .map(|node_idx| flexible_reject_response(callback_id.get(), node_idx))
        .collect();

    let payload = CanisterHttpPayload {
        flexible_errors: vec![FlexibleCanisterHttpError::TooManyRejects {
            callback_id,
            reject_responses: reject_entries,
        }],
        ..Default::default()
    };
    let bytes = payload_to_bytes_max_4mb(payload);

    let (responses, stats) = CanisterHttpPayloadBuilderImpl::into_messages(&bytes);

    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].callback, callback_id);
    assert_eq!(stats.flexible_errors, 1);
    assert_eq!(stats.flexible_errors_candid_failures, 0);

    let Payload::Data(ref data) = responses[0].payload else {
        panic!("Expected Payload::Data, got {:?}", responses[0].payload);
    };
    let result = Decode!(data, FlexibleHttpRequestResult).unwrap();
    let FlexibleHttpRequestResult::Err(err) = result else {
        panic!("Expected Err variant, got {result:?}");
    };
    assert_eq!(
        err.global_error,
        Some(FlexibleHttpGlobalError::TooManyRejects(candid::Reserved))
    );
    assert_eq!(err.node_details.len(), 2);
    for (i, detail) in err.node_details.iter().enumerate() {
        assert_eq!(
            detail.node_id,
            candid::Principal::from(node_test_id(i as u64).get())
        );
        assert_eq!(detail.report, HttpRequestResourceReport::default());
        let error = detail.error.as_ref().unwrap();
        assert_eq!(error.code, format!("{:?}", RejectCode::SysTransient));
        assert_eq!(error.message, "could not connect");
    }
    assert!(err.message.contains("Too many rejects"));
    assert!(err.message.contains("2 responses are rejects"));
}

#[test]
fn flexible_error_into_messages_responses_too_large() {
    let callback_id = CallbackId::from(42);

    // Deliberately construct OK shares in non-ascending size order so that
    // `into_messages` must sort them to report the correct "smallest" sizes.
    let share_a = metadata_share_with_content_size(callback_id.get(), 0, 1_400_000);
    let share_b = metadata_share_with_content_size(callback_id.get(), 1, 1_200_000);
    let share_c = metadata_share_with_content_size(callback_id.get(), 2, 1_300_000);
    let share_reject = reject_metadata_share(callback_id.get(), 3);

    let payload = CanisterHttpPayload {
        flexible_errors: vec![FlexibleCanisterHttpError::ResponsesTooLarge {
            callback_id,
            all_seen_shares: vec![share_a, share_b, share_c, share_reject],
            total_requests: 5,
            min_responses: 3,
        }],
        ..Default::default()
    };
    let bytes = payload_to_bytes_max_4mb(payload);

    let (responses, stats) = CanisterHttpPayloadBuilderImpl::into_messages(&bytes);

    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].callback, callback_id);
    assert_eq!(stats.flexible_errors, 1);
    assert_eq!(stats.flexible_errors_candid_failures, 0);

    let Payload::Data(ref data) = responses[0].payload else {
        panic!("Expected Payload::Data, got {:?}", responses[0].payload);
    };
    let result = Decode!(data, FlexibleHttpRequestResult).unwrap();
    let FlexibleHttpRequestResult::Err(err) = result else {
        panic!("Expected Err variant, got {result:?}");
    };
    assert_eq!(
        err.global_error,
        Some(FlexibleHttpGlobalError::ResponsesTooLarge(candid::Reserved))
    );
    // All 4 shares (3 ok + 1 reject) are in node_details
    assert_eq!(err.node_details.len(), 4);
    for detail in &err.node_details {
        assert_eq!(detail.report, HttpRequestResourceReport::default());
    }

    assert_eq!(
        err.node_details[0].node_id,
        candid::Principal::from(node_test_id(0).get())
    );
    assert_eq!(err.node_details[0].error.as_ref().unwrap().code, "ok");
    assert_eq!(
        err.node_details[0].error.as_ref().unwrap().message,
        "1400000 bytes"
    );

    assert_eq!(
        err.node_details[1].node_id,
        candid::Principal::from(node_test_id(1).get())
    );
    assert_eq!(err.node_details[1].error.as_ref().unwrap().code, "ok");
    assert_eq!(
        err.node_details[1].error.as_ref().unwrap().message,
        "1200000 bytes"
    );

    assert_eq!(
        err.node_details[2].node_id,
        candid::Principal::from(node_test_id(2).get())
    );
    assert_eq!(err.node_details[2].error.as_ref().unwrap().code, "ok");
    assert_eq!(
        err.node_details[2].error.as_ref().unwrap().message,
        "1300000 bytes"
    );

    assert_eq!(
        err.node_details[3].node_id,
        candid::Principal::from(node_test_id(3).get())
    );
    assert_eq!(err.node_details[3].error.as_ref().unwrap().code, "reject");
    assert_eq!(
        err.node_details[3].error.as_ref().unwrap().message,
        "50 bytes"
    );
    // min_known_ok_needed = 3 - 1 unseen = 2, so message lists only the 2 smallest OK sizes
    assert!(err.message.contains("3 min_responses"));
    assert!(err.message.contains("5 total_requests"));
    assert!(err.message.contains("3 ok"));
    assert!(err.message.contains("1 reject"));
    assert!(err.message.contains("1 unseen"));
    assert!(err.message.contains("[1200000, 1300000]"));
    assert!(!err.message.contains("1400000"));
}

#[test]
fn flexible_build_timeout() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(num_nodes, callback_id, committee, 2, 4, |pb, _pool| {
        let timed_out_context = ValidationContext {
            registry_version: RegistryVersion::new(1),
            certified_height: Height::new(0),
            time: UNIX_EPOCH + CANISTER_HTTP_TIMEOUT_INTERVAL + Duration::from_secs(1),
        };
        let parsed = build_and_validate_and_parse_payload_with_context(&pb, &timed_out_context);

        // Should NOT be in regular timeouts
        assert!(parsed.timeouts.is_empty());
        // Should be a flexible timeout error
        assert_eq!(parsed.flexible_errors.len(), 1);
        assert_matches!(
            &parsed.flexible_errors[0],
            FlexibleCanisterHttpError::Timeout { callback_id: cb } => {
                assert_eq!(*cb, callback_id);
            }
        );
    });
}

#[test]
fn flexible_build_responses_too_large() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    // min_responses = 2; all 4 nodes submit OK responses each >1 MiB so that
    // the smallest 2 exceed MAX_CANISTER_HTTP_PAYLOAD_SIZE when summed.
    // All members must respond so that num_unseen=0, otherwise the check
    // correctly stays Pending (unseen members could still send small responses).
    let body_size = (MAX_CANISTER_HTTP_PAYLOAD_SIZE / 2) + 100_000;
    setup_test_with_flexible_context(num_nodes, callback_id, committee, 2, 4, |pb, pool| {
        {
            let mut pool_access = pool.write().unwrap();
            for node_idx in 0..4_u64 {
                let body = vec![0xAA_u8; body_size];
                let (response, metadata) = test_response_and_metadata_with_content(
                    callback_id.get(),
                    CanisterHttpResponseContent::Success(body),
                );
                let share = metadata_to_share(node_idx, &metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &share, &response);
            }
        }

        let parsed = build_and_validate_and_parse_payload(&pb);

        assert!(parsed.flexible_responses.is_empty());
        assert_eq!(parsed.flexible_errors.len(), 1);
        assert_matches!(
            &parsed.flexible_errors[0],
            FlexibleCanisterHttpError::ResponsesTooLarge {
                callback_id: cb,
                all_seen_shares,
                total_requests,
                min_responses,
            } => {
                assert_eq!(*cb, callback_id);
                assert_eq!(all_seen_shares.len(), 4);
                assert!(all_seen_shares.iter().all(|s| !s.content.is_reject));
                assert_eq!(*total_requests, 4);
                assert_eq!(*min_responses, 2);
            }
        );
    });
}

#[test]
fn flexible_build_responses_too_large_stays_pending_when_unseen_members_could_help() {
    let num_nodes = 6;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    // min_responses=3, committee=6. We submit 3 large OK shares that individually exceed
    // MAX/3, making their sum exceed MAX. But 3 committee members are still unseen and
    // could submit small responses, so the result should be Pending, not ResponsesTooLarge.
    let body_size = (MAX_CANISTER_HTTP_PAYLOAD_SIZE / 3) + 100_000;
    setup_test_with_flexible_context(num_nodes, callback_id, committee, 3, 6, |pb, pool| {
        {
            let mut pool_access = pool.write().unwrap();
            for node_idx in 0..3_u64 {
                let body = vec![0xAA_u8; body_size];
                let (response, metadata) = test_response_and_metadata_with_content(
                    callback_id.get(),
                    CanisterHttpResponseContent::Success(body),
                );
                let share = metadata_to_share(node_idx, &metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &share, &response);
            }
        }

        let parsed = build_and_validate_and_parse_payload(&pb);

        // Unseen members could still submit small OK responses → Pending.
        assert!(parsed.flexible_responses.is_empty());
        assert!(parsed.flexible_errors.is_empty());
    });
}

#[test]
fn flexible_build_responses_too_large_with_rejects_reducing_unseen() {
    let num_nodes = 6;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    // min_responses=3, committee=6.
    // 3 large OK shares (sum > MAX) from nodes 0..3.
    // 2 rejects from nodes 3..5 → only 1 unseen member remains.
    // min_minus_unseen = 3 - 1 = 2, and even the 2 smallest known OK shares exceed MAX.
    let body_size = (MAX_CANISTER_HTTP_PAYLOAD_SIZE / 2) + 100_000;
    setup_test_with_flexible_context(num_nodes, callback_id, committee, 3, 6, |pb, pool| {
        {
            let mut pool_access = pool.write().unwrap();
            for node_idx in 0..3_u64 {
                let body = vec![0xAA_u8; body_size];
                let (response, metadata) = test_response_and_metadata_with_content(
                    callback_id.get(),
                    CanisterHttpResponseContent::Success(body),
                );
                let share = metadata_to_share(node_idx, &metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &share, &response);
            }
            for node_idx in 3..5_u64 {
                let (response, metadata) = test_response_and_metadata_with_content(
                    callback_id.get(),
                    CanisterHttpResponseContent::Reject(CanisterHttpReject {
                        reject_code: RejectCode::SysTransient,
                        message: format!("error_{node_idx}"),
                    }),
                );
                let share = metadata_to_share(node_idx, &metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &share, &response);
            }
        }

        let parsed = build_and_validate_and_parse_payload(&pb);

        // Rejects reduce unseen count, making it impossible to fit → ResponsesTooLarge.
        // The error includes min_responses (3) shares for validation, even though
        // only min_minus_unseen (2) were needed to prove impossibility.
        assert!(parsed.flexible_responses.is_empty());
        assert_eq!(parsed.flexible_errors.len(), 1);
        assert_matches!(
            &parsed.flexible_errors[0],
            FlexibleCanisterHttpError::ResponsesTooLarge {
                callback_id: cb,
                all_seen_shares,
                total_requests,
                min_responses,
            } => {
                assert_eq!(*cb, callback_id);
                assert_eq!(all_seen_shares.len(), 5);
                let ok_count = all_seen_shares.iter().filter(|s| !s.content.is_reject).count();
                let reject_count = all_seen_shares.iter().filter(|s| s.content.is_reject).count();
                assert_eq!(ok_count, 3);
                assert_eq!(reject_count, 2);
                assert_eq!(*total_requests, 6);
                assert_eq!(*min_responses, 3);
            }
        );
    });
}

#[test]
fn flexible_build_responses_too_large_fewer_ok_than_min_responses() {
    let num_nodes = 6;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    // min_responses=4, committee=6.
    // 3 large OK shares (sum > MAX) from nodes 0..3.
    // 2 rejects from nodes 3..5 → only 1 unseen member remains.
    // min_known_ok_needed = 4 - 1 = 3, and we have exactly 3 OK shares whose sum exceeds MAX.
    // Even though num_ok (3) < min_responses (4), we can already prove impossibility.
    let body_size = (MAX_CANISTER_HTTP_PAYLOAD_SIZE / 3) + 100_000;
    setup_test_with_flexible_context(num_nodes, callback_id, committee, 4, 6, |pb, pool| {
        {
            let mut pool_access = pool.write().unwrap();
            for node_idx in 0..3_u64 {
                let body = vec![0xAA_u8; body_size];
                let (response, metadata) = test_response_and_metadata_with_content(
                    callback_id.get(),
                    CanisterHttpResponseContent::Success(body),
                );
                let share = metadata_to_share(node_idx, &metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &share, &response);
            }
            for node_idx in 3..5_u64 {
                let (response, metadata) = test_response_and_metadata_with_content(
                    callback_id.get(),
                    CanisterHttpResponseContent::Reject(CanisterHttpReject {
                        reject_code: RejectCode::SysTransient,
                        message: format!("error_{node_idx}"),
                    }),
                );
                let share = metadata_to_share(node_idx, &metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &share, &response);
            }
        }

        let parsed = build_and_validate_and_parse_payload(&pb);

        assert!(parsed.flexible_responses.is_empty());
        assert_eq!(parsed.flexible_errors.len(), 1);
        assert_matches!(
            &parsed.flexible_errors[0],
            FlexibleCanisterHttpError::ResponsesTooLarge {
                callback_id: cb,
                all_seen_shares,
                total_requests,
                min_responses,
            } => {
                assert_eq!(*cb, callback_id);
                assert_eq!(all_seen_shares.len(), 5);
                let ok_count = all_seen_shares.iter().filter(|s| !s.content.is_reject).count();
                let reject_count = all_seen_shares.iter().filter(|s| s.content.is_reject).count();
                assert_eq!(ok_count, 3);
                assert_eq!(reject_count, 2);
                assert_eq!(*total_requests, 6);
                assert_eq!(*min_responses, 4);
            }
        );
    });
}

#[test]
fn flexible_build_too_many_rejects() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    // min_responses=3, so at most 1 reject is tolerable. 2 rejects should trigger TooManyRejects.
    setup_test_with_flexible_context(num_nodes, callback_id, committee, 3, 4, |pb, pool| {
        {
            let mut pool_access = pool.write().unwrap();
            // Nodes 0 and 1 produce Reject responses
            for node_idx in 0..2_u64 {
                let (response, metadata) = test_response_and_metadata_with_content(
                    callback_id.get(),
                    CanisterHttpResponseContent::Reject(CanisterHttpReject {
                        reject_code: RejectCode::SysTransient,
                        message: format!("error_{node_idx}"),
                    }),
                );
                let share = metadata_to_share(node_idx, &metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &share, &response);
            }
            // Nodes 2 and 3 produce OK responses
            for node_idx in 2..4_u64 {
                let (response, metadata) = test_response_and_metadata_with_content(
                    callback_id.get(),
                    CanisterHttpResponseContent::Success(format!("resp_{node_idx}").into_bytes()),
                );
                let share = metadata_to_share(node_idx, &metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &share, &response);
            }
        }

        let parsed = build_and_validate_and_parse_payload(&pb);

        assert!(parsed.flexible_responses.is_empty());
        assert_eq!(parsed.flexible_errors.len(), 1);
        assert_matches!(
            &parsed.flexible_errors[0],
            FlexibleCanisterHttpError::TooManyRejects {
                callback_id: cb,
                reject_responses,
            } => {
                assert_eq!(*cb, callback_id);
                assert_eq!(reject_responses.len(), 2);
                for entry in reject_responses {
                    assert_matches!(
                        entry.response.content,
                        CanisterHttpResponseContent::Reject(_)
                    );
                }
            }
        );
    });
}

#[test]
fn flexible_build_not_enough_rejects_stays_pending() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    // min_responses=3, so at most 1 reject is tolerable. Only 1 reject + 1 OK → pending.
    setup_test_with_flexible_context(num_nodes, callback_id, committee, 3, 4, |pb, pool| {
        {
            let mut pool_access = pool.write().unwrap();
            // Node 0 produces a Reject
            let (response, metadata) = test_response_and_metadata_with_content(
                callback_id.get(),
                CanisterHttpResponseContent::Reject(CanisterHttpReject {
                    reject_code: RejectCode::SysTransient,
                    message: "error".to_string(),
                }),
            );
            let share = metadata_to_share(0, &metadata);
            add_own_share_to_pool(pool_access.deref_mut(), &share, &response);
            // Node 1 produces an OK response
            let (response, metadata) = test_response_and_metadata_with_content(
                callback_id.get(),
                CanisterHttpResponseContent::Success(b"ok_resp".to_vec()),
            );
            let share = metadata_to_share(1, &metadata);
            add_own_share_to_pool(pool_access.deref_mut(), &share, &response);
        }

        let parsed = build_and_validate_and_parse_payload(&pb);

        assert_eq!(parsed.flexible_responses, vec![]);
        assert_eq!(parsed.flexible_errors, vec![]);
    });
}

#[test]
fn flexible_build_ok_takes_precedence_over_rejects() {
    let num_nodes = 5;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    // min_responses=2, max_responses=5. 2 rejects + 3 OK → OkResponses even though
    // reject_count(2) > committee.len()-min_responses(3). Because we have enough OK responses.
    setup_test_with_flexible_context(num_nodes, callback_id, committee, 2, 5, |pb, pool| {
        {
            let mut pool_access = pool.write().unwrap();
            for node_idx in 0..2_u64 {
                let (response, metadata) = test_response_and_metadata_with_content(
                    callback_id.get(),
                    CanisterHttpResponseContent::Reject(CanisterHttpReject {
                        reject_code: RejectCode::SysTransient,
                        message: format!("error_{node_idx}"),
                    }),
                );
                let share = metadata_to_share(node_idx, &metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &share, &response);
            }
            for node_idx in 2..5_u64 {
                let (response, metadata) = test_response_and_metadata_with_content(
                    callback_id.get(),
                    CanisterHttpResponseContent::Success(format!("resp_{node_idx}").into_bytes()),
                );
                let share = metadata_to_share(node_idx, &metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &share, &response);
            }
        }

        let parsed = build_and_validate_and_parse_payload(&pb);

        assert_eq!(parsed.flexible_responses.len(), 1);
        assert_eq!(parsed.flexible_errors, vec![]);
    });
}

#[test]
fn flexible_build_prioritizes_smaller_responses() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    // max_responses = 2 so only 2 of the 3 responses can be included.
    setup_test_with_flexible_context(num_nodes, callback_id, committee, 2, 2, |pb, pool| {
        let small = b"s";
        let medium = b"medium_content";
        let large = b"large_content_that_is_significantly_bigger";

        {
            let mut pool_access = pool.write().unwrap();
            // Insert shares from 3 different nodes with different content sizes.
            // Deliberately insert large before small to ensure it's the sort,
            // not insertion order, that determines the result.
            for (node, content) in [(0_u64, large.as_slice()), (1, small), (2, medium)] {
                let (response, metadata) = test_response_and_metadata_with_content(
                    callback_id.get(),
                    CanisterHttpResponseContent::Success(content.to_vec()),
                );
                let share = metadata_to_share(node, &metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &share, &response);
            }
        }

        let parsed = build_and_validate_and_parse_payload(&pb);
        assert_eq!(parsed.flexible_responses.len(), 1);
        let group = &parsed.flexible_responses[0];
        assert_eq!(group.responses.len(), 2);

        let included_bodies: Vec<_> = group
            .responses
            .iter()
            .filter_map(|e| match &e.response.content {
                CanisterHttpResponseContent::Success(bytes) => Some(bytes.clone()),
                _ => None,
            })
            .collect();

        assert_eq!(included_bodies[0], small);
        assert_eq!(included_bodies[1], medium);
    });
}

#[test]
fn flexible_error_timeout_valid() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_contexts(
        num_nodes,
        vec![(callback_id, flexible_request_context(committee, 2, 4))],
        |pb, _pool| {
            let timed_out_context = ValidationContext {
                registry_version: RegistryVersion::new(1),
                certified_height: Height::new(0),
                time: UNIX_EPOCH + CANISTER_HTTP_TIMEOUT_INTERVAL + Duration::from_secs(1),
            };
            let payload = CanisterHttpPayload {
                flexible_errors: vec![FlexibleCanisterHttpError::Timeout { callback_id }],
                ..Default::default()
            };
            let result = pb.validate_payload(
                Height::new(1),
                &test_proposal_context(&timed_out_context),
                &payload_to_bytes_max_4mb(payload),
                &[],
            );
            assert_matches!(result, Ok(()));
        },
    );
}

#[test]
fn flexible_error_timeout_invalid_not_expired() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(num_nodes, callback_id, committee, 2, 4, |pb, _pool| {
        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::Timeout { callback_id }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::NotTimedOut(id)
                )
            )) if id == callback_id
        );
    });
}

#[test]
fn flexible_error_timeout_invalid_non_flexible_request() {
    let num_nodes = 4;
    let callback_id = CallbackId::from(42);

    // A non-flexible request should not be able to produce a flexible timeout error
    setup_test_with_contexts(num_nodes, fully_replicated_contexts([42]), |pb, _pool| {
        let timed_out_context = ValidationContext {
            registry_version: RegistryVersion::new(1),
            certified_height: Height::new(0),
            time: UNIX_EPOCH + CANISTER_HTTP_TIMEOUT_INTERVAL + Duration::from_secs(1),
        };
        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::Timeout { callback_id }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&timed_out_context),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::InvalidPayloadSection(id)
                )
            )) if id == callback_id
        );
    });
}

#[test]
fn flexible_error_duplicate_callback_id() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(num_nodes, callback_id, committee, 2, 4, |pb, _pool| {
        let timed_out_context = ValidationContext {
            registry_version: RegistryVersion::new(1),
            certified_height: Height::new(0),
            time: UNIX_EPOCH + CANISTER_HTTP_TIMEOUT_INTERVAL + Duration::from_secs(1),
        };
        let payload = CanisterHttpPayload {
            flexible_errors: vec![
                FlexibleCanisterHttpError::Timeout { callback_id },
                FlexibleCanisterHttpError::Timeout { callback_id },
            ],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&timed_out_context),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::DuplicateResponse(id)
                )
            )) if id == callback_id
        );
    });
}

#[test]
fn flexible_error_duplicate_callback_id_cross_type() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(num_nodes, callback_id, committee, 1, 4, |pb, _pool| {
        let timed_out_context = ValidationContext {
            registry_version: RegistryVersion::new(1),
            certified_height: Height::new(0),
            time: UNIX_EPOCH + CANISTER_HTTP_TIMEOUT_INTERVAL + Duration::from_secs(1),
        };
        let payload = CanisterHttpPayload {
            flexible_responses: vec![FlexibleCanisterHttpResponses {
                callback_id,
                responses: vec![flexible_response(42, 0, b"a")],
            }],
            flexible_errors: vec![FlexibleCanisterHttpError::Timeout { callback_id }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&timed_out_context),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::DuplicateResponse(id)
                )
            )) if id == callback_id
        );
    });
}

#[test]
fn flexible_error_responses_too_large_valid() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    // min_responses=2, all 4 committee members responded with huge OK →
    // num_unseen=0, min_known_ok_needed=2, smallest 2 × ~1.1 MiB > 2 MiB.
    let huge_content_size = (MAX_CANISTER_HTTP_PAYLOAD_SIZE as u32 / 2) + 100_000;
    setup_test_with_flexible_context(num_nodes, callback_id, committee, 2, 4, |pb, _pool| {
        let all_seen_shares: Vec<_> = (0..4)
            .map(|i| metadata_share_with_content_size(callback_id.get(), i, huge_content_size))
            .collect();

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::ResponsesTooLarge {
                callback_id,
                all_seen_shares,
                total_requests: 4,
                min_responses: 2,
            }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(result, Ok(()));
    });
}

#[test]
fn flexible_error_responses_too_large_valid_with_unseen_members() {
    let num_nodes = 6;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    // min_responses=4, committee=6. 4 huge OK + 1 reject = 5 seen, 1 unseen.
    // min_known_ok_needed = 4 - 1 = 3. Sum of smallest 3 OK > MAX → valid.
    let huge = (MAX_CANISTER_HTTP_PAYLOAD_SIZE as u32 / 3) + 100_000;
    setup_test_with_flexible_context(num_nodes, callback_id, committee, 4, 6, |pb, _pool| {
        let ok_shares: Vec<_> = (0..4)
            .map(|i| metadata_share_with_content_size(callback_id.get(), i, huge))
            .collect();
        let reject_share = reject_metadata_share(callback_id.get(), 4);

        let mut all_seen_shares = ok_shares;
        all_seen_shares.push(reject_share);

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::ResponsesTooLarge {
                callback_id,
                all_seen_shares,
                total_requests: 6,
                min_responses: 4,
            }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(result, Ok(()));
    });
}

#[test]
fn flexible_error_responses_too_large_valid_with_mixed_ok_and_reject() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    // min_responses=2, committee=4. 2 huge OK + 2 reject → all 4 seen,
    // num_unseen=0, min_known_ok_needed=2, sum of 2 OK > MAX → valid.
    let huge = (MAX_CANISTER_HTTP_PAYLOAD_SIZE as u32 / 2) + 100_000;
    setup_test_with_flexible_context(num_nodes, callback_id, committee, 2, 4, |pb, _pool| {
        let ok_a = metadata_share_with_content_size(callback_id.get(), 0, huge);
        let ok_b = metadata_share_with_content_size(callback_id.get(), 1, huge);
        let reject_c = reject_metadata_share(callback_id.get(), 2);
        let reject_d = reject_metadata_share(callback_id.get(), 3);

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::ResponsesTooLarge {
                callback_id,
                all_seen_shares: vec![ok_a, ok_b, reject_c, reject_d],
                total_requests: 4,
                min_responses: 2,
            }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(result, Ok(()));
    });
}

#[test]
fn flexible_error_responses_too_large_wrong_total_requests() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    let huge = (MAX_CANISTER_HTTP_PAYLOAD_SIZE as u32 / 2) + 100_000;
    setup_test_with_flexible_context(num_nodes, callback_id, committee, 2, 4, |pb, _pool| {
        let all_seen_shares: Vec<_> = (0..4)
            .map(|i| metadata_share_with_content_size(callback_id.get(), i, huge))
            .collect();

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::ResponsesTooLarge {
                callback_id,
                all_seen_shares,
                total_requests: 99,
                min_responses: 2,
            }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::FlexibleResponsesTooLargeParamMismatch {
                        field: "total_requests",
                        expected: 4,
                        actual: 99,
                        ..
                    }
                )
            ))
        );
    });
}

#[test]
fn flexible_error_responses_too_large_wrong_min_responses() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    let huge = (MAX_CANISTER_HTTP_PAYLOAD_SIZE as u32 / 2) + 100_000;
    setup_test_with_flexible_context(num_nodes, callback_id, committee, 2, 4, |pb, _pool| {
        let all_seen_shares: Vec<_> = (0..4)
            .map(|i| metadata_share_with_content_size(callback_id.get(), i, huge))
            .collect();

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::ResponsesTooLarge {
                callback_id,
                all_seen_shares,
                total_requests: 4,
                min_responses: 99,
            }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::FlexibleResponsesTooLargeParamMismatch {
                        field: "min_responses",
                        expected: 2,
                        actual: 99,
                        ..
                    }
                )
            ))
        );
    });
}

#[test]
fn flexible_error_responses_too_large_invalid_when_small() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    // Only 2 small OK shares out of committee=4 → num_unseen=2,
    // min_known_ok_needed=0, sum=0 ≤ MAX → rejected.
    setup_test_with_flexible_context(num_nodes, callback_id, committee, 2, 4, |pb, _pool| {
        let entry_a = flexible_response(callback_id.get(), 0, b"small_a");
        let entry_b = flexible_response(callback_id.get(), 1, b"small_b");

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::ResponsesTooLarge {
                callback_id,
                all_seen_shares: vec![entry_a.proof.clone(), entry_b.proof.clone()],
                total_requests: 4,
                min_responses: 2,
            }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::FlexibleResponsesNotTooLarge(id)
                )
            )) if id == callback_id
        );
    });
}

#[test]
fn flexible_error_responses_too_large_invalid_when_committee_members_omitted() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    // Attack: proposer includes only 2 large OK shares, omits 2 small OK shares.
    // num_unseen=2, min_known_ok_needed = 2 - 2 = 0, sum of 0 entries = 0 ≤ MAX → rejected.
    let huge = (MAX_CANISTER_HTTP_PAYLOAD_SIZE as u32 / 2) + 100_000;
    setup_test_with_flexible_context(num_nodes, callback_id, committee, 2, 4, |pb, _pool| {
        let share_a = metadata_share_with_content_size(callback_id.get(), 0, huge);
        let share_b = metadata_share_with_content_size(callback_id.get(), 1, huge);

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::ResponsesTooLarge {
                callback_id,
                all_seen_shares: vec![share_a, share_b],
                total_requests: 4,
                min_responses: 2,
            }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::FlexibleResponsesNotTooLarge(id)
                )
            )) if id == callback_id
        );
    });
}

#[test]
fn flexible_error_responses_too_large_too_few_ok_shares() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    // min_responses=3, committee=4. All 4 members present (0 unseen),
    // so min_known_ok_needed=3. But only 2 OK + 2 reject → 2 OK is insufficient.
    let huge = (MAX_CANISTER_HTTP_PAYLOAD_SIZE as u32 / 2) + 100_000;
    setup_test_with_flexible_context(num_nodes, callback_id, committee, 3, 4, |pb, _pool| {
        let ok_a = metadata_share_with_content_size(callback_id.get(), 0, huge);
        let ok_b = metadata_share_with_content_size(callback_id.get(), 1, huge);
        let reject_c = reject_metadata_share(callback_id.get(), 2);
        let reject_d = reject_metadata_share(callback_id.get(), 3);

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::ResponsesTooLarge {
                callback_id,
                all_seen_shares: vec![ok_a, ok_b, reject_c, reject_d],
                total_requests: 4,
                min_responses: 3,
            }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::FlexibleResponsesTooLargeInsufficientEvidence {
                        callback_id: id,
                        ok_count: 2,
                        min_known_ok_needed: 3,
                    }
                )
            )) if id == callback_id
        );
    });
}

#[test]
fn flexible_error_responses_too_large_callback_id_mismatch() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    let huge = (MAX_CANISTER_HTTP_PAYLOAD_SIZE as u32 / 2) + 100_000;
    setup_test_with_flexible_context(num_nodes, callback_id, committee, 2, 4, |pb, _pool| {
        let share_ok = metadata_share_with_content_size(callback_id.get(), 0, huge);
        // Share with wrong callback_id
        let mismatched_id = CallbackId::new(999);
        let share_wrong = metadata_share_with_content_size(mismatched_id.get(), 1, huge);

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::ResponsesTooLarge {
                callback_id,
                all_seen_shares: vec![share_ok, share_wrong],
                total_requests: 4,
                min_responses: 2,
            }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::FlexibleCallbackIdMismatch { callback_id: cb_id, mismatched_id: mm_id }
                )
            )) if cb_id == callback_id && mm_id == mismatched_id
        );
    });
}

#[test]
fn flexible_error_responses_too_large_duplicate_signer() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    let huge = (MAX_CANISTER_HTTP_PAYLOAD_SIZE as u32 / 2) + 100_000;
    setup_test_with_flexible_context(num_nodes, callback_id, committee, 2, 4, |pb, _pool| {
        // Both shares from the same signer (node 0)
        let share_a = metadata_share_with_content_size(callback_id.get(), 0, huge);
        let share_b = metadata_share_with_content_size(callback_id.get(), 0, huge);

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::ResponsesTooLarge {
                callback_id,
                all_seen_shares: vec![share_a, share_b],
                total_requests: 4,
                min_responses: 2,
            }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::FlexibleDuplicateSigner { callback_id: cb_id, signer: s }
                )
            )) if cb_id == callback_id && s == node_test_id(0)
        );
    });
}

#[test]
fn flexible_error_responses_too_large_signer_not_in_committee() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    let huge = (MAX_CANISTER_HTTP_PAYLOAD_SIZE as u32 / 2) + 100_000;
    setup_test_with_flexible_context(num_nodes, callback_id, committee, 2, 4, |pb, _pool| {
        let share_ok = metadata_share_with_content_size(callback_id.get(), 0, huge);
        let share_bad = metadata_share_with_content_size(callback_id.get(), 99, huge);

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::ResponsesTooLarge {
                callback_id,
                all_seen_shares: vec![share_ok, share_bad],
                total_requests: 4,
                min_responses: 2,
            }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::FlexibleSignerNotInCommittee { callback_id: cb_id, signer: s }
                )
            )) if cb_id == callback_id && s == node_test_id(99)
        );
    });
}

#[test]
fn flexible_error_responses_too_large_registry_version_mismatch() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    let huge = (MAX_CANISTER_HTTP_PAYLOAD_SIZE as u32 / 2) + 100_000;
    setup_test_with_flexible_context(num_nodes, callback_id, committee, 2, 4, |pb, _pool| {
        let share_ok = metadata_share_with_content_size(callback_id.get(), 0, huge);
        // Share with wrong registry version
        let mut share_bad = metadata_share_with_content_size(callback_id.get(), 1, huge);
        share_bad.content.registry_version = RegistryVersion::new(999);

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::ResponsesTooLarge {
                callback_id,
                all_seen_shares: vec![share_ok, share_bad],
                total_requests: 4,
                min_responses: 2,
            }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::RegistryVersionMismatch { expected: e, received: r }
                )
            )) if e == RegistryVersion::new(1) && r == RegistryVersion::new(999)
        );
    });
}

#[test]
fn flexible_error_responses_too_large_invalid_signature() {
    let committee: BTreeSet<_> = (0..4).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    let huge = (MAX_CANISTER_HTTP_PAYLOAD_SIZE as u32 / 2) + 100_000;
    setup_test_with_flexible_context(4, callback_id, committee, 2, 4, |mut pb, _pool| {
        pb.crypto = Arc::new(mock_crypto_rejecting_signatures());

        let share_a = metadata_share_with_content_size(callback_id.get(), 0, huge);
        let share_b = metadata_share_with_content_size(callback_id.get(), 1, huge);

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::ResponsesTooLarge {
                callback_id,
                all_seen_shares: vec![share_a, share_b],
                total_requests: 4,
                min_responses: 2,
            }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::SignatureError(_)
                )
            ))
        );
    });
}

#[test]
fn flexible_error_too_many_rejects_valid() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    // min_responses=3, committee=4. max_allowed_rejects = 4-3 = 1.
    // 2 rejects should be valid for TooManyRejects.
    setup_test_with_flexible_context(num_nodes, callback_id, committee, 3, 4, |pb, _pool| {
        let reject_entries: Vec<_> = (0..2_u64)
            .map(|node_idx| flexible_reject_response(callback_id.get(), node_idx))
            .collect();

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::TooManyRejects {
                callback_id,
                reject_responses: reject_entries,
            }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(result, Ok(()));
    });
}

#[test]
fn flexible_error_too_many_rejects_insufficient_rejects() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    // min_responses=3, committee=4. max_allowed_rejects = 1.
    // Only 1 reject → not enough for TooManyRejects.
    setup_test_with_flexible_context(num_nodes, callback_id, committee, 3, 4, |pb, _pool| {
        let reject_entries: Vec<_> = (0..1_u64)
            .map(|node_idx| flexible_reject_response(callback_id.get(), node_idx))
            .collect();

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::TooManyRejects {
                callback_id,
                reject_responses: reject_entries,
            }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::FlexibleInsufficientRejectCount {
                        callback_id: cb_id,
                        reject_count: rc,
                        min_needed: mn,
                    }
                )
            )) if cb_id == callback_id && rc == 1 && mn == 2
        );
    });
}

#[test]
fn flexible_error_too_many_rejects_non_reject_content() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(num_nodes, callback_id, committee, 3, 4, |pb, _pool| {
        let ok_entry = flexible_response(callback_id.get(), 0, b"ok data");
        let reject_entry = flexible_reject_response(callback_id.get(), 1);

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::TooManyRejects {
                callback_id,
                reject_responses: vec![ok_entry, reject_entry],
            }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::FlexibleRejectExpectedInErrorResponse(cb_id)
                )
            )) if cb_id == callback_id
        );
    });
}

#[test]
fn flexible_error_too_many_rejects_duplicate_signer() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(num_nodes, callback_id, committee, 3, 4, |pb, _pool| {
        let entry_a = flexible_reject_response(callback_id.get(), 0);
        let entry_b = flexible_reject_response(callback_id.get(), 0);

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::TooManyRejects {
                callback_id,
                reject_responses: vec![entry_a, entry_b],
            }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::FlexibleDuplicateSigner { callback_id: cb_id, signer: s }
                )
            )) if cb_id == callback_id && s == node_test_id(0)
        );
    });
}

#[test]
fn flexible_error_too_many_rejects_signer_not_in_committee() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(num_nodes, callback_id, committee, 3, 4, |pb, _pool| {
        // Node 99 is not in the committee
        let entry_a = flexible_reject_response(callback_id.get(), 0);
        let entry_b = flexible_reject_response(callback_id.get(), 99);

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::TooManyRejects {
                callback_id,
                reject_responses: vec![entry_a, entry_b],
            }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::FlexibleSignerNotInCommittee { callback_id: cb_id, signer: s }
                )
            )) if cb_id == callback_id && s == node_test_id(99)
        );
    });
}

#[test]
fn flexible_error_too_many_rejects_callback_id_mismatch_in_response() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(num_nodes, callback_id, committee, 3, 4, |pb, _pool| {
        let entry_ok = flexible_reject_response(callback_id.get(), 0);
        // Entry with wrong callback_id
        let entry_wrong = flexible_reject_response(999, 1);

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::TooManyRejects {
                callback_id,
                reject_responses: vec![entry_ok, entry_wrong],
            }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::FlexibleCallbackIdMismatch { callback_id: cb_id, mismatched_id: mm_id }
                )
            )) if cb_id == callback_id && mm_id == CallbackId::new(999)
        );
    });
}

#[test]
fn flexible_error_too_many_rejects_registry_version_mismatch() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(num_nodes, callback_id, committee, 3, 4, |pb, _pool| {
        let entry_ok = flexible_reject_response(callback_id.get(), 0);
        let mut entry_bad = flexible_reject_response(callback_id.get(), 1);
        entry_bad.proof.content.registry_version = RegistryVersion::new(999);

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::TooManyRejects {
                callback_id,
                reject_responses: vec![entry_ok, entry_bad],
            }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::RegistryVersionMismatch { expected: e, received: r }
                )
            )) if e == RegistryVersion::new(1) && r == RegistryVersion::new(999)
        );
    });
}

#[test]
fn flexible_error_too_many_rejects_content_hash_mismatch() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(num_nodes, callback_id, committee, 3, 4, |pb, _pool| {
        let entry_ok = flexible_reject_response(callback_id.get(), 0);
        let mut entry_bad = flexible_reject_response(callback_id.get(), 1);
        entry_bad.proof.content.content_hash = CryptoHashOf::new(CryptoHash(vec![0xFF; 32]));

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::TooManyRejects {
                callback_id,
                reject_responses: vec![entry_ok, entry_bad],
            }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::ContentHashMismatch { metadata_hash: mh, calculated_hash: ch }
                )
            )) if mh == CryptoHashOf::new(CryptoHash(vec![0xFF; 32])) && ch != mh
        );
    });
}

#[test]
fn flexible_error_too_many_rejects_content_size_mismatch() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(num_nodes, callback_id, committee, 3, 4, |pb, _pool| {
        let entry_ok = flexible_reject_response(callback_id.get(), 0);
        let mut entry_bad = flexible_reject_response(callback_id.get(), 1);
        entry_bad.proof.content.content_size = 999_999;

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::TooManyRejects {
                callback_id,
                reject_responses: vec![entry_ok, entry_bad],
            }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::ContentSizeMismatch { metadata_size: ms, calculated_size: cs }
                )
            )) if ms == 999_999 && cs < ms && cs != 0
        );
    });
}

#[test]
fn flexible_error_too_many_rejects_is_reject_mismatch() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(num_nodes, callback_id, committee, 3, 4, |pb, _pool| {
        let entry_ok = flexible_reject_response(callback_id.get(), 0);
        let mut entry_bad = flexible_reject_response(callback_id.get(), 1);
        entry_bad.proof.content.is_reject = !entry_bad.proof.content.is_reject;

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::TooManyRejects {
                callback_id,
                reject_responses: vec![entry_ok, entry_bad],
            }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::IsRejectMismatch { .. }
                )
            ))
        );
    });
}

#[test]
fn flexible_error_too_many_rejects_proof_id_mismatch() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(num_nodes, callback_id, committee, 3, 4, |pb, _pool| {
        let entry_ok = flexible_reject_response(callback_id.get(), 0);
        let mut entry_bad = flexible_reject_response(callback_id.get(), 1);
        // response.id stays correct, but proof.content.id is wrong
        entry_bad.proof.content.id = CallbackId::new(999);

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::TooManyRejects {
                callback_id,
                reject_responses: vec![entry_ok, entry_bad],
            }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::FlexibleCallbackIdMismatch {
                        callback_id: cb_id,
                        mismatched_id: mm_id,
                        ..
                    }
                )
            )) if cb_id == callback_id && mm_id == CallbackId::new(999)
        );
    });
}

#[test]
fn flexible_error_too_many_rejects_invalid_signature() {
    let committee: BTreeSet<_> = (0..4).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(4, callback_id, committee, 3, 4, |mut pb, _pool| {
        pb.crypto = Arc::new(mock_crypto_rejecting_signatures());

        let reject_entries: Vec<_> = (0..2_u64)
            .map(|node_idx| flexible_reject_response(callback_id.get(), node_idx))
            .collect();

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::TooManyRejects {
                callback_id,
                reject_responses: reject_entries,
            }],
            ..Default::default()
        };
        let result = pb.validate_payload(
            Height::new(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::SignatureError(_)
                )
            ))
        );
    });
}

fn setup_test_with_contexts(
    num_nodes: usize,
    contexts: Vec<(CallbackId, CanisterHttpRequestContext)>,
    run: impl FnOnce(CanisterHttpPayloadBuilderImpl, Arc<RwLock<CanisterHttpPoolImpl>>),
) {
    test_config_with_http_feature(true, num_nodes, |mut payload_builder, pool| {
        inject_request_contexts(&mut payload_builder, contexts);
        run(payload_builder, pool);
    });
}

fn setup_test_with_flexible_context(
    num_nodes: usize,
    callback_id: CallbackId,
    committee: BTreeSet<NodeId>,
    min_responses: u32,
    max_responses: u32,
    run: impl FnOnce(CanisterHttpPayloadBuilderImpl, Arc<RwLock<CanisterHttpPoolImpl>>),
) {
    setup_test_with_contexts(
        num_nodes,
        vec![(
            callback_id,
            flexible_request_context(committee, min_responses, max_responses),
        )],
        run,
    );
}

/// Replaces the payload_builder's state_reader with one containing the given request contexts.
pub(crate) fn inject_request_contexts(
    payload_builder: &mut CanisterHttpPayloadBuilderImpl,
    contexts: impl IntoIterator<Item = (CallbackId, CanisterHttpRequestContext)>,
) {
    let mut init_state = ic_test_utilities_state::get_initial_state(0, 0);
    for (cb, ctx) in contexts {
        init_state
            .metadata
            .subnet_call_context_manager
            .canister_http_request_contexts
            .insert(cb, ctx);
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

fn fully_replicated_contexts(
    ids: impl IntoIterator<Item = u64>,
) -> Vec<(CallbackId, CanisterHttpRequestContext)> {
    ids.into_iter()
        .map(|id| {
            (
                CallbackId::new(id),
                request_context(Replication::FullyReplicated),
            )
        })
        .collect()
}

pub(crate) fn request_context(replication: Replication) -> CanisterHttpRequestContext {
    CanisterHttpRequestContext {
        request: RequestBuilder::default().build(),
        url: "https://example.com".to_string(),
        max_response_bytes: None,
        headers: vec![],
        body: None,
        http_method: CanisterHttpMethod::GET,
        transform: None,
        time: UNIX_EPOCH,
        replication,
        pricing_version: ic_types::canister_http::PricingVersion::Legacy,
        refund_status: ic_types::canister_http::RefundStatus::default(),
    }
}

fn flexible_request_context(
    committee: BTreeSet<NodeId>,
    min_responses: u32,
    max_responses: u32,
) -> CanisterHttpRequestContext {
    CanisterHttpRequestContext {
        request: RequestBuilder::default().build(),
        url: "https://example.com".to_string(),
        max_response_bytes: None,
        headers: vec![],
        body: None,
        http_method: CanisterHttpMethod::GET,
        transform: None,
        time: UNIX_EPOCH,
        replication: Replication::Flexible {
            committee,
            min_responses,
            max_responses,
        },
        pricing_version: ic_types::canister_http::PricingVersion::PayAsYouGo,
        refund_status: ic_types::canister_http::RefundStatus::default(),
    }
}

fn flexible_response(
    callback_id: u64,
    signer_node: u64,
    content: &[u8],
) -> FlexibleCanisterHttpResponseWithProof {
    let (response, metadata) = test_response_and_metadata_with_content(
        callback_id,
        CanisterHttpResponseContent::Success(content.to_vec()),
    );
    FlexibleCanisterHttpResponseWithProof {
        response,
        proof: metadata_to_share(signer_node, &metadata),
    }
}

fn flexible_reject_response(
    callback_id: u64,
    signer_node: u64,
) -> FlexibleCanisterHttpResponseWithProof {
    let (response, metadata) = test_response_and_metadata_with_content(
        callback_id,
        CanisterHttpResponseContent::Reject(CanisterHttpReject {
            reject_code: RejectCode::SysTransient,
            message: "could not connect".to_string(),
        }),
    );
    FlexibleCanisterHttpResponseWithProof {
        response,
        proof: metadata_to_share(signer_node, &metadata),
    }
}

fn flexible_payload(groups: Vec<FlexibleCanisterHttpResponses>) -> CanisterHttpPayload {
    CanisterHttpPayload {
        responses: vec![],
        timeouts: vec![],
        divergence_responses: vec![],
        flexible_responses: groups,
        flexible_errors: vec![],
    }
}

fn metadata_share_with_content_size(
    callback_id: u64,
    signer_node: u64,
    content_size: u32,
) -> CanisterHttpResponseShare {
    let metadata = CanisterHttpResponseMetadata {
        id: CallbackId::new(callback_id),
        content_hash: CryptoHashOf::new(CryptoHash(vec![0xAB; 32])),
        content_size,
        is_reject: false,
        registry_version: RegistryVersion::new(1),
        replica_version: ReplicaVersion::default(),
    };
    metadata_to_share(signer_node, &metadata)
}

fn reject_metadata_share(callback_id: u64, signer_node: u64) -> CanisterHttpResponseShare {
    let metadata = CanisterHttpResponseMetadata {
        id: CallbackId::new(callback_id),
        content_hash: CryptoHashOf::new(CryptoHash(vec![0xCD; 32])),
        content_size: 50,
        is_reject: true,
        registry_version: RegistryVersion::new(1),
        replica_version: ReplicaVersion::default(),
    };
    metadata_to_share(signer_node, &metadata)
}

fn add_flexible_shares_to_pool(
    pool: &Arc<RwLock<CanisterHttpPoolImpl>>,
    callback_id: CallbackId,
    node_range: std::ops::Range<u64>,
) {
    let mut pool_access = pool.write().unwrap();
    for node_idx in node_range {
        let (response, metadata) = test_response_and_metadata_with_content(
            callback_id.get(),
            CanisterHttpResponseContent::Success(format!("resp_{node_idx}").into_bytes()),
        );
        let share = metadata_to_share(node_idx, &metadata);
        add_own_share_to_pool(pool_access.deref_mut(), &share, &response);
    }
}

fn build_and_validate_and_parse_payload(
    payload_builder: &CanisterHttpPayloadBuilderImpl,
) -> CanisterHttpPayload {
    build_and_validate_and_parse_payload_with_context(
        payload_builder,
        &default_validation_context(),
    )
}

fn build_and_validate_and_parse_payload_with_context(
    payload_builder: &CanisterHttpPayloadBuilderImpl,
    context: &ValidationContext,
) -> CanisterHttpPayload {
    let max_size = NumBytes::new(MAX_CANISTER_HTTP_PAYLOAD_SIZE as u64);
    let payload = payload_builder.build_payload(Height::new(1), max_size, &[], context);
    assert_matches!(
        payload_builder.validate_payload(
            Height::new(1),
            &test_proposal_context(context),
            &payload,
            &[],
        ),
        Ok(())
    );
    bytes_to_payload(&payload).expect("parse error")
}

fn payload_to_bytes_max_4mb(payload: CanisterHttpPayload) -> Vec<u8> {
    payload_to_bytes(payload, TEST_MAX_PAYLOAD_BYTES)
}

fn mock_crypto_rejecting_signatures() -> MockCrypto {
    let mut mock_crypto = MockCrypto::new();
    mock_crypto
        .expect_verify_basic_sig_http()
        .returning(|_, _, _, _| {
            Err(ic_types::crypto::CryptoError::SignatureVerification {
                algorithm: ic_types::crypto::AlgorithmId::Ed25519,
                public_key_bytes: vec![],
                sig_bytes: vec![],
                internal_error: "mock rejection".to_string(),
            })
        });
    mock_crypto
}
