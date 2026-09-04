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
use ic_consensus_mocks::{Dependencies, DependenciesBuilder};
use ic_error_types::RejectCode;
use ic_https_outcalls_pricing::fees::{
    consensus_fee, flexible_initial_spent, max_usage_fee, min_flexible_consensus_cost,
    non_flexible_initial_spent,
};
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
use ic_replicated_state::metadata_state::subnet_call_context_manager::DELIVERED_CANISTER_HTTP_REQUEST_CONTEXT_TIMEOUT;
use ic_test_utilities::state_manager::RefMockStateManager;
use ic_test_utilities_consensus::fake::FakeContentSigner;
use ic_test_utilities_registry::SubnetRecordBuilder;
use ic_test_utilities_types::{
    ids::{node_id_to_u64, node_test_id, subnet_test_id, test_replica_version},
    messages::RequestBuilder,
};
use ic_types::{
    CountBytes, Height, NodeId, NumBytes, NumberOfNodes, RegistryVersion,
    batch::{
        CanisterHttpOutOfCycles, CanisterHttpPayload, FlexibleCanisterHttpError,
        FlexibleCanisterHttpResponseWithProof, FlexibleCanisterHttpResponses,
        MAX_CANISTER_HTTP_PAYLOAD_SIZE, ValidationContext,
    },
    canister_http::{
        CANDID_OVERHEAD_RESERVE_BYTES, CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK,
        CANISTER_HTTP_TIMEOUT_INTERVAL, CanisterHttpMethod, CanisterHttpPaymentReceipt,
        CanisterHttpReject, CanisterHttpRequestContext, CanisterHttpResponse,
        CanisterHttpResponseArtifact, CanisterHttpResponseContent, CanisterHttpResponseDivergence,
        CanisterHttpResponseMetadata, CanisterHttpResponseProof, CanisterHttpResponseReceipt,
        CanisterHttpResponseShare, CanisterHttpResponseSignature,
        CanisterHttpResponseWithConsensus, MAX_CANISTER_HTTP_RESPONSE_BYTES,
        MAXIMUM_CANISTER_HTTP_ERROR_MESSAGE_BYTES, PricingVersion, RefundStatus, Replication,
        canister_http_threshold, max_http_outcall_response_size,
    },
    consensus::get_faults_tolerated,
    crypto::{BasicSig, BasicSigOf, CryptoHash, CryptoHashOf, Signed, crypto_hash},
    messages::{CallbackId, Payload, RejectContext},
    registry::RegistryClientError,
    signature::BasicSignature,
    time::UNIX_EPOCH,
};
use ic_types_cycles::{CanisterCyclesCostSchedule, Cycles};
use rand::Rng;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use rayon::{ThreadPool, ThreadPoolBuilder};
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
                        shares[1..canister_http_threshold(subnet_size)].to_vec(),
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
                    out_of_cycles: vec![],
                    responses: vec![CanisterHttpResponseWithConsensus {
                        content: past_response,
                        proof: CanisterHttpResponseProof {
                            metadata: past_metadata,
                            signatures: BTreeMap::new(),
                        },
                        initial_spent: Cycles::zero(),
                    }],
                    timeouts: vec![],
                    divergence_responses: vec![],
                    flexible_responses: vec![],
                    flexible_errors: vec![],
                    async_receipts: vec![],
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

            // Ensure that one bad apple can't cause us to report divergence: a
            // single node returning a different response is below the divergence
            // threshold.
            add_received_shares_to_pool(pool_access.deref_mut(), {
                let (_, metadata) = test_response_and_metadata_with_content(
                    1,
                    CanisterHttpResponseContent::Success(vec![0]),
                );
                vec![metadata_to_share(7, &metadata)]
            });
        }

        let parsed_payload = build_and_validate_and_parse_payload(&payload_builder);
        assert_eq!(parsed_payload.divergence_responses.len(), 0);

        // But if enough distinct nodes disagree, we report divergence. Nodes 4,
        // 5 and 6 each return their own distinct response which, together with
        // node 7 above, pushes the number of diverging signers past the fault
        // tolerance.
        {
            let mut pool_access = canister_http_pool.write().unwrap();

            add_received_shares_to_pool(
                pool_access.deref_mut(),
                (4..7_u8)
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

#[test]
fn flexible_timeouts_bypass_max_responses_per_block() {
    let subnet_size = 4;
    let num_contexts = CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK + 50;

    test_config_with_http_feature(
        true,
        subnet_size,
        |mut payload_builder, _canister_http_pool| {
            let committee: BTreeSet<_> = (0..subnet_size as u64).map(node_test_id).collect();

            // `num_contexts` flexible request contexts, all at time = UNIX_EPOCH.
            let contexts: Vec<_> = (0..num_contexts as u64)
                .map(|id| {
                    (
                        CallbackId::new(id),
                        flexible_request_context(committee.clone(), 1, subnet_size as u32),
                    )
                })
                .collect();
            inject_request_contexts(&mut payload_builder, contexts);

            // Validation time past the timeout interval so every context times out.
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

            // The builder emits all timed-out flexible requests, ungated by the cap.
            assert_eq!(parsed.flexible_errors.len(), num_contexts);
            assert!(parsed.responses.is_empty());
            assert!(parsed.timeouts.is_empty());
            // Flexible timeouts must not count against the per-block response cap.
            assert_eq!(parsed.num_non_timeout_responses(), 0);

            // The builder's own honest payload must pass validation.
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
            out_of_cycles: vec![],
            responses: vec![],
            timeouts: vec![],
            divergence_responses,
            flexible_responses: vec![],
            flexible_errors: vec![],
            async_receipts: vec![],
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
            out_of_cycles: vec![],
            responses: vec![response_and_metadata_to_proof(&response, &metadata)],
            timeouts: vec![],
            divergence_responses: vec![],
            flexible_responses: vec![],
            flexible_errors: vec![],
            async_receipts: vec![],
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
                out_of_cycles: vec![],
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
                async_receipts: vec![],
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
                out_of_cycles: vec![],
                responses: vec![],
                timeouts: vec![],
                divergence_responses: vec![CanisterHttpResponseDivergence {
                    shares: (0..subnet_size / 2)
                        .map(|node_id| metadata_to_share(node_id.try_into().unwrap(), &metadata))
                        .collect(),
                }],
                flexible_responses: vec![],
                flexible_errors: vec![],
                async_receipts: vec![],
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
                out_of_cycles: vec![],
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
                async_receipts: vec![],
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

/// A divergence proof must not contain more than one share from the same
/// signer. A byzantine block maker could otherwise include an equivocating
/// node twice; since `into_messages` sums the initial spend over every share
/// but deduplicates the signer set, this would inflate the reported spend
/// relative to the number of nodes and break the spend/refund accounting.
#[test]
fn divergence_duplicate_signer_rejected() {
    for subnet_size in 3..MAX_SUBNET_SIZE {
        test_config_with_http_feature(true, subnet_size, |mut payload_builder, _| {
            inject_request_contexts(&mut payload_builder, fully_replicated_contexts([0]));
            let (_, metadata) = test_response_and_metadata(0);
            let (_, other_metadata) = test_response_and_metadata_with_content(
                0,
                CanisterHttpResponseContent::Success(b"other".to_vec()),
            );

            // A valid divergence (each half of the nodes votes for one of two
            // hashes), plus a duplicate: node 0 also votes for the second hash,
            // so it now signs two shares.
            let payload = CanisterHttpPayload {
                out_of_cycles: vec![],
                responses: vec![],
                timeouts: vec![],
                divergence_responses: vec![CanisterHttpResponseDivergence {
                    shares: (0..subnet_size / 2)
                        .map(|node_id| metadata_to_share(node_id.try_into().unwrap(), &metadata))
                        .chain((subnet_size / 2..subnet_size).map(|node_id| {
                            metadata_to_share(node_id.try_into().unwrap(), &other_metadata)
                        }))
                        .chain(std::iter::once(metadata_to_share(0, &other_metadata)))
                        .collect(),
                }],
                flexible_responses: vec![],
                flexible_errors: vec![],
                async_receipts: vec![],
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
                        InvalidCanisterHttpPayloadReason::DivergenceDuplicateSigner {
                            signer, ..
                        },
                    ),
                )) => assert_eq!(signer, node_test_id(0)),
                x => panic!("Expected DivergenceDuplicateSigner, got {x:?}"),
            }
        });
    }
}

#[test]
fn divergence_oversized_share_rejected() {
    let subnet_size = 4;
    test_config_with_http_feature(true, subnet_size, |mut payload_builder, _| {
        inject_request_contexts(&mut payload_builder, fully_replicated_contexts([0]));
        let (_, metadata) = test_response_and_metadata(0);
        // A share claiming one byte more than the replica could have produced, among an
        // otherwise valid divergence of two equal halves.
        let oversized =
            (MAX_CANISTER_HTTP_RESPONSE_BYTES + CANDID_OVERHEAD_RESERVE_BYTES) as u32 + 1;
        let payload =
            CanisterHttpPayload {
                divergence_responses: vec![CanisterHttpResponseDivergence {
                    shares: (0..subnet_size / 2)
                        .map(|node| metadata_to_share(node as u64, &metadata))
                        .chain((subnet_size / 2..subnet_size).map(|node| {
                            metadata_share_with_content_size(0, node as u64, oversized)
                        }))
                        .collect(),
                }],
                ..Default::default()
            };

        assert_matches!(
            payload_builder.validate_payload(
                Height::from(1),
                &test_proposal_context(&default_validation_context()),
                &payload_to_bytes(payload, TEST_MAX_PAYLOAD_BYTES),
                &[],
            ),
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::ContentSizeExceedsLimit {
                        content_size,
                        limit,
                        ..
                    },
                ),
            )) if content_size == oversized && limit == oversized as u64 - 1
        );
    });
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
                content: CanisterHttpResponseReceipt {
                    metadata: sample,
                    payment_receipt: CanisterHttpPaymentReceipt::default(),
                },
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

        let request_context = request_context(Replication::NonReplicated(delegated_node_id));

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
            proof.signatures.len(),
            1,
            "Proof should contain exactly one signature"
        );
        assert!(
            proof.signatures.contains_key(&delegated_node_id),
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
        let request_context = request_context(Replication::NonReplicated(delegated_node_id));

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
            proof.signatures.len(),
            1,
            "Proof should contain exactly one signature"
        );
        assert!(
            proof.signatures.contains_key(&delegated_node_id),
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
        let request_context = request_context(Replication::NonReplicated(delegated_node_id));

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
    let subnet_size = 4;
    test_config_with_http_feature(true, subnet_size, |mut payload_builder, _| {
        let delegated_node_id = node_test_id(1);
        let callback_id = CallbackId::from(77);

        // 1. Create a context where the request is delegated to `delegated_node_id`.
        // This context will be used during validation.
        let request_context = CanisterHttpRequestContext {
            subnet_size: NumberOfNodes::from(subnet_size as u32),
            ..request_context(Replication::NonReplicated(delegated_node_id))
        };

        // Inject this context into the state reader used by the validator.
        inject_request_contexts(&mut payload_builder, [(callback_id, request_context)]);

        // 2. Craft a perfect payload containing one non-replicated response.
        let (response, metadata) = test_response_and_metadata(callback_id.get());
        let mut proof = response_and_metadata_to_proof(&response, &metadata);
        // The proof must contain exactly ONE signature, from the DELEGATED node.
        add_signer_to_proof(&mut proof, delegated_node_id);
        proof.initial_spent =
            non_flexible_initial_spent(&proof.proof, NumberOfNodes::from(subnet_size as u32));

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
fn validate_payload_fails_for_initial_spent_mismatch() {
    // ARRANGE
    let subnet_size = 4;
    test_config_with_http_feature(true, subnet_size, |mut payload_builder, _| {
        let delegated_node_id = node_test_id(1);
        let callback_id = CallbackId::from(77);

        let request_context = CanisterHttpRequestContext {
            subnet_size: NumberOfNodes::from(subnet_size as u32),
            ..request_context(Replication::NonReplicated(delegated_node_id))
        };
        inject_request_contexts(&mut payload_builder, [(callback_id, request_context)]);

        // Build an otherwise-valid response, then claim a collective initial spend
        // that differs from what the receipts and subnet size recompute to.
        let (response, metadata) = test_response_and_metadata(callback_id.get());
        let mut proof = response_and_metadata_to_proof(&response, &metadata);
        add_signer_to_proof(&mut proof, delegated_node_id);
        let computed =
            non_flexible_initial_spent(&proof.proof, NumberOfNodes::from(subnet_size as u32));
        // A content-bearing response has a nonzero consensus cost, so the honest
        // value is nonzero; claim one cycle too many.
        proof.initial_spent = computed + Cycles::new(1);

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
        assert_matches!(
            validation_result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::InitialSpentMismatch {
                        callback_id: cb,
                        received,
                        expected,
                    }
                )
            )) if cb == callback_id
                && received == computed + Cycles::new(1)
                && expected == computed
        );
    });
}

#[test]
fn validate_payload_fails_for_initial_spent_mismatch_fully_replicated() {
    // ARRANGE
    let subnet_size = 4;
    test_config_with_http_feature(true, subnet_size, |mut payload_builder, _| {
        let callback_id = CallbackId::from(77);

        let request_context = CanisterHttpRequestContext {
            subnet_size: NumberOfNodes::from(subnet_size as u32),
            ..request_context(Replication::FullyReplicated)
        };
        inject_request_contexts(&mut payload_builder, [(callback_id, request_context)]);

        // Build a response signed by the whole committee, then claim a collective
        // initial spend that differs from what the receipts and subnet size
        // recompute to.
        let (response, metadata) = test_response_and_metadata(callback_id.get());
        let mut proof = response_and_metadata_to_proof(&response, &metadata);
        for node in 0..subnet_size as u64 {
            add_signer_to_proof(&mut proof, node_test_id(node));
        }
        let computed =
            non_flexible_initial_spent(&proof.proof, NumberOfNodes::from(subnet_size as u32));
        // A content-bearing response has a nonzero consensus cost, so the honest
        // value is nonzero; claim one cycle too many.
        proof.initial_spent = computed + Cycles::new(1);

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
        assert_matches!(
            validation_result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::InitialSpentMismatch {
                        callback_id: cb,
                        received,
                        expected,
                    }
                )
            )) if cb == callback_id
                && received == computed + Cycles::new(1)
                && expected == computed
        );
    });
}

#[test]
fn validate_payload_fails_for_spent_exceeding_allowance_non_replicated() {
    let delegated_node_id = node_test_id(1);
    let callback_id = CallbackId::from(99);

    let (response, metadata) = test_response_and_metadata(callback_id.get());
    let mut proof = response_and_metadata_to_proof(&response, &metadata);
    add_signer_with_excess_spent_to_proof(&mut proof, delegated_node_id);

    assert_payload_rejected_for_excess_spent(
        4,
        vec![(
            callback_id,
            request_context(Replication::NonReplicated(delegated_node_id)),
        )],
        default_validation_context(),
        CanisterHttpPayload {
            responses: vec![proof],
            ..Default::default()
        },
    );
}

#[test]
fn validate_payload_fails_for_spent_exceeding_allowance_fully_replicated() {
    let num_nodes = 4;
    let callback_id = CallbackId::from(99);

    let (response, metadata) = test_response_and_metadata(callback_id.get());
    let mut proof = response_and_metadata_to_proof(&response, &metadata);
    for node in 0..num_nodes as u64 {
        add_signer_with_excess_spent_to_proof(&mut proof, node_test_id(node));
    }

    assert_payload_rejected_for_excess_spent(
        num_nodes,
        vec![(callback_id, request_context(Replication::FullyReplicated))],
        default_validation_context(),
        CanisterHttpPayload {
            responses: vec![proof],
            ..Default::default()
        },
    );
}

#[test]
fn validate_payload_accepts_spent_exceeding_allowance_on_free_subnet() {
    let num_nodes = 4;
    let callback_id = CallbackId::from(99);

    let (response, metadata) = test_response_and_metadata(callback_id.get());
    let mut proof = response_and_metadata_to_proof(&response, &metadata);
    for node in 0..num_nodes as u64 {
        add_signer_with_excess_spent_to_proof(&mut proof, node_test_id(node));
    }

    test_config_with_http_feature(true, num_nodes, |mut payload_builder, _| {
        // Pin the validating replica's own subnet to a `Free` cost schedule, so
        // the spend limit becomes `MAX_HTTP_OUTCALL_SPEND_FREE_SUBNET` rather
        // than the (zero) per-replica allowance.
        inject_request_contexts_with_cost_schedule(
            &mut payload_builder,
            vec![(callback_id, request_context(Replication::FullyReplicated))],
            Some(CanisterCyclesCostSchedule::Free),
        );
        let validation_result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&default_validation_context()),
            &payload_to_bytes_max_4mb(CanisterHttpPayload {
                responses: vec![proof],
                ..Default::default()
            }),
            &[],
        );
        // The receipt's spend exceeds the (zero) allowance, so on the default
        // (`Normal`) schedule this same payload is rejected (see
        // `validate_payload_fails_for_spent_exceeding_allowance_fully_replicated`).
        // On a free subnet it must NOT be rejected as overspending. (The payload
        // still fails later, unrelated signature verification of the fake shares,
        // but must never fail with `SpentExceedsLimit`.)
        assert!(
            !matches!(
                validation_result,
                Err(ValidationError::InvalidArtifact(
                    InvalidPayloadReason::InvalidCanisterHttpPayload(
                        InvalidCanisterHttpPayloadReason::SpentExceedsLimit { .. },
                    ),
                ))
            ),
            "free-subnet payload wrongly rejected for overspending: {validation_result:?}"
        );
    });
}

#[test]
fn validate_payload_fails_for_spent_exceeding_allowance_divergence() {
    let callback_id = CallbackId::from(99);

    let (_response, metadata) = test_response_and_metadata(callback_id.get());
    let payload = CanisterHttpPayload {
        divergence_responses: vec![CanisterHttpResponseDivergence {
            shares: vec![share_with_excess_spent(0, &metadata)],
        }],
        ..Default::default()
    };

    assert_payload_rejected_for_excess_spent(
        4,
        vec![(callback_id, request_context(Replication::FullyReplicated))],
        default_validation_context(),
        payload,
    );
}

#[test]
fn validate_payload_fails_for_spent_exceeding_allowance_flexible_response() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(99);

    let (response, metadata) = test_response_and_metadata_with_content(
        callback_id.get(),
        CanisterHttpResponseContent::Success(b"flexible".to_vec()),
    );
    let payload = CanisterHttpPayload {
        flexible_responses: vec![FlexibleCanisterHttpResponses {
            extra_shares: vec![],
            callback_id,
            initial_spent: Cycles::zero(),
            responses: vec![FlexibleCanisterHttpResponseWithProof {
                response,
                proof: share_with_excess_spent(0, &metadata),
            }],
        }],
        ..Default::default()
    };

    assert_payload_rejected_for_excess_spent(
        num_nodes,
        vec![(
            callback_id,
            flexible_request_context_without_allowance(committee, 1, 4),
        )],
        default_validation_context(),
        payload,
    );
}

#[test]
fn validate_payload_fails_for_spent_exceeding_allowance_too_many_rejects() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(99);

    let (response, metadata) = test_response_and_metadata_with_content(
        callback_id.get(),
        CanisterHttpResponseContent::Reject(CanisterHttpReject {
            reject_code: RejectCode::SysTransient,
            message: "could not connect".to_string(),
        }),
    );
    let payload = CanisterHttpPayload {
        flexible_errors: vec![FlexibleCanisterHttpError::TooManyRejects {
            extra_shares: vec![],
            callback_id,
            initial_spent: Cycles::zero(),
            reject_responses: vec![FlexibleCanisterHttpResponseWithProof {
                response,
                proof: share_with_excess_spent(0, &metadata),
            }],
        }],
        ..Default::default()
    };

    assert_payload_rejected_for_excess_spent(
        num_nodes,
        vec![(
            callback_id,
            flexible_request_context_without_allowance(committee, 1, 4),
        )],
        default_validation_context(),
        payload,
    );
}

#[test]
fn validate_payload_fails_for_spent_exceeding_allowance_responses_too_large() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(99);

    let (_response, metadata) = test_response_and_metadata(callback_id.get());
    let payload = CanisterHttpPayload {
        flexible_errors: vec![FlexibleCanisterHttpError::ResponsesTooLarge {
            callback_id,
            all_seen_shares: vec![share_with_excess_spent(0, &metadata)],
            // Match the committee size and context `min_responses` so validation
            // reaches the per-share spent check.
            total_requests: num_nodes as u32,
            min_responses: 2,
        }],
        ..Default::default()
    };

    assert_payload_rejected_for_excess_spent(
        num_nodes,
        vec![(
            callback_id,
            flexible_request_context_without_allowance(committee, 2, 4),
        )],
        default_validation_context(),
        payload,
    );
}

#[test]
fn validate_payload_fails_for_non_replicated_response_with_wrong_signer() {
    // ARRANGE
    test_config_with_http_feature(true, 4, |mut payload_builder, _| {
        let delegated_node_id = node_test_id(1);
        let wrong_signer_node_id = node_test_id(2); // The node that incorrectly signs
        let callback_id = CallbackId::from(88);

        // 1. Create a context delegating the request to `delegated_node_id`.
        let request_context = request_context(Replication::NonReplicated(delegated_node_id));

        // Inject this context into the state reader.
        inject_request_contexts(&mut payload_builder, [(callback_id, request_context)]);

        // 2. Craft a malicious payload where the proof contains only one signature,
        //    but it's from the wrong node.
        let (response, metadata) = test_response_and_metadata(callback_id.get());
        let mut proof = response_and_metadata_to_proof(&response, &metadata);

        // The illegal signature from a non-member node.
        add_signer_to_proof(&mut proof, wrong_signer_node_id);

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
        let request_context = request_context(Replication::NonReplicated(delegated_node_id));

        // Inject this context into the state reader used by the validator.
        inject_request_contexts(&mut payload_builder, [(callback_id, request_context)]);

        // 2. Craft a payload where the proof for the response contains no signatures.
        let (response, metadata) = test_response_and_metadata(callback_id.get());
        let mut proof = response_and_metadata_to_proof(&response, &metadata);

        // Ensure the signature map is empty.
        proof.proof.signatures = BTreeMap::new();

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
        let request_context = request_context(Replication::FullyReplicated);

        // Inject this context into the state reader.
        inject_request_contexts(&mut payload_builder, [(callback_id, request_context)]);

        // 2. Craft a payload that provides a proof with only a single signature,
        //    as if it were for a NonReplicated request.
        let (response, metadata) = test_response_and_metadata(callback_id.get());
        let mut proof = response_and_metadata_to_proof(&response, &metadata);

        // The proof only contains one signature.
        add_signer_to_proof(&mut proof, signer_node_id);

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
    let subnet_size = 4;
    test_config_with_http_feature(true, subnet_size, |mut payload_builder, _| {
        let delegated_node_id = node_test_id(1);
        let duplicate_callback_id = CallbackId::from(102);

        // 1. Define the context for the NonReplicated request.
        let request_context = CanisterHttpRequestContext {
            subnet_size: NumberOfNodes::from(subnet_size as u32),
            ..request_context(Replication::NonReplicated(delegated_node_id))
        };

        // 2. Inject this context into the state reader
        inject_request_contexts(
            &mut payload_builder,
            [(duplicate_callback_id, request_context)],
        );

        // 3. Craft a valid proof for the NonReplicated response.
        let (response, metadata) = test_response_and_metadata(duplicate_callback_id.get());
        let mut proof = response_and_metadata_to_proof(&response, &metadata);
        add_signer_to_proof(&mut proof, delegated_node_id);
        proof.initial_spent =
            non_flexible_initial_spent(&proof.proof, NumberOfNodes::from(subnet_size as u32));

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
        content,
    };
    let metadata = CanisterHttpResponseMetadata {
        id: response.id,
        content_hash: crypto_hash(&response),
        content_size: response.content.count_bytes() as u32,
        is_reject: response.content.is_reject(),
        replica_version: test_replica_version(),
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

/// Creates a [`CanisterHttpResponseShare`] for `metadata` claiming `spent` cycles.
fn metadata_to_share_with_spent(
    from_node: u64,
    metadata: &CanisterHttpResponseMetadata,
    spent: Cycles,
) -> CanisterHttpResponseShare {
    let mut share = metadata_to_share(from_node, metadata);
    share.content.payment_receipt = CanisterHttpPaymentReceipt { spent };
    share
}

pub(crate) fn metadata_to_share_with_signature(
    from_node: u64,
    metadata: &CanisterHttpResponseMetadata,
    signature: Vec<u8>,
) -> CanisterHttpResponseShare {
    let signer = node_test_id(from_node);
    Signed {
        content: CanisterHttpResponseReceipt {
            metadata: metadata.clone(),
            payment_receipt: CanisterHttpPaymentReceipt::default(),
        },
        signature: BasicSignature {
            signature: BasicSigOf::new(BasicSig(signature)),
            signer,
        },
    }
}

/// Creates a [`CanisterHttpResponseWithConsensus`] from a [`CanisterHttpResponse`] and [`CanisterHttpResponseMetadata`].
///
/// The proof starts out with an empty signatures map; tests insert
/// per-signer receipt + signature pairs via [`add_signer_to_proof`].
pub(crate) fn response_and_metadata_to_proof(
    response: &CanisterHttpResponse,
    metadata: &CanisterHttpResponseMetadata,
) -> CanisterHttpResponseWithConsensus {
    CanisterHttpResponseWithConsensus {
        content: response.clone(),
        proof: CanisterHttpResponseProof {
            metadata: metadata.clone(),
            signatures: BTreeMap::new(),
        },
        initial_spent: Cycles::zero(),
    }
}

/// Inserts a fake signature together with a default payment receipt for
/// `signer` into an aggregated proof.
pub(crate) fn add_signer_to_proof(proof: &mut CanisterHttpResponseWithConsensus, signer: NodeId) {
    proof.proof.signatures.insert(
        signer,
        CanisterHttpResponseSignature {
            payment_receipt: CanisterHttpPaymentReceipt::default(),
            signature: BasicSigOf::new(BasicSig(vec![])),
        },
    );
}

/// A payment receipt whose spent cycles exceed the default (zero) per-replica
/// allowance.
fn receipt_exceeding_allowance() -> CanisterHttpPaymentReceipt {
    CanisterHttpPaymentReceipt {
        spent: Cycles::new(1),
    }
}

/// Builds a share for `metadata` signed by `signer_node` whose payment receipt
/// claims spent cycles exceeding the default per-replica allowance.
fn share_with_excess_spent(
    signer_node: u64,
    metadata: &CanisterHttpResponseMetadata,
) -> CanisterHttpResponseShare {
    CanisterHttpResponseShare::fake(
        CanisterHttpResponseReceipt {
            metadata: metadata.clone(),
            payment_receipt: receipt_exceeding_allowance(),
        },
        node_test_id(signer_node),
    )
}

/// Inserts a fake signature for `signer` together with a payment receipt whose
/// spent cycles exceed the default per-replica allowance into an aggregated proof.
fn add_signer_with_excess_spent_to_proof(
    proof: &mut CanisterHttpResponseWithConsensus,
    signer: NodeId,
) {
    proof.proof.signatures.insert(
        signer,
        CanisterHttpResponseSignature {
            payment_receipt: receipt_exceeding_allowance(),
            signature: BasicSigOf::new(BasicSig(vec![])),
        },
    );
}

/// Configures a payload builder with `num_nodes` nodes and the given request
/// `contexts`, validates `payload`, and asserts that it is rejected because a
/// payment receipt's spent cycles exceed the per-replica allowance.
fn assert_payload_rejected_for_excess_spent(
    num_nodes: usize,
    contexts: Vec<(CallbackId, CanisterHttpRequestContext)>,
    validation_context: ValidationContext,
    payload: CanisterHttpPayload,
) {
    test_config_with_http_feature(true, num_nodes, |mut payload_builder, _| {
        inject_request_contexts(&mut payload_builder, contexts);
        let validation_result = payload_builder.validate_payload(
            Height::from(1),
            &test_proposal_context(&validation_context),
            &payload_to_bytes_max_4mb(payload),
            &[],
        );
        assert_matches!(
            validation_result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::SpentExceedsLimit {
                        spent,
                        limit,
                    },
                ),
            )) if spent == receipt_exceeding_allowance().spent
                && limit == Cycles::new(0)
        );
    });
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

/// The thread pool the payload builder under test verifies signatures on.
/// We use only 1 thread to avoid non-deterministic test failures.
fn test_thread_pool() -> Arc<ThreadPool> {
    Arc::new(
        ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .expect("Failed to create thread pool"),
    )
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
        } = DependenciesBuilder::single_subnet(
            pool_config,
            subnet_test_id(0),
            vec![(1, subnet_record)],
        )
        .build();

        let payload_builder = CanisterHttpPayloadBuilderImpl::new(
            canister_http_pool.clone(),
            pool.get_cache(),
            crypto,
            state_manager,
            test_thread_pool(),
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
            out_of_cycles: vec![],
            responses: vec![response_and_metadata_to_proof(&response, &metadata)],
            timeouts: vec![],
            divergence_responses: vec![],
            flexible_responses: vec![],
            flexible_errors: vec![],
            async_receipts: vec![],
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
    let subnet_size = 4;
    let committee: BTreeSet<_> = (0..subnet_size).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);
    let (min, max) = (2, subnet_size as u32);

    setup_test_with_flexible_context(
        subnet_size as usize,
        callback_id,
        committee,
        min,
        max,
        |payload_builder, _pool| {
            let payload = flexible_payload(vec![flexible_group(
                callback_id,
                subnet_size as u32,
                min,
                vec![
                    flexible_response(42, 0, b"response_a"),
                    flexible_response(42, 1, b"response_b"),
                    flexible_response(42, 2, b"response_c"),
                ],
            )]);

            let result = payload_builder.validate_payload(
                Height::from(1),
                &test_proposal_context(&default_validation_context()),
                &payload_to_bytes_max_4mb(payload),
                &[],
            );
            assert_matches!(result, Ok(_));
        },
    );
}

#[test]
fn flexible_valid_at_min_responses_boundary() {
    let subnet_size = 4;
    let committee: BTreeSet<_> = (0..subnet_size).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);
    let (min, max) = (2, subnet_size as u32);

    setup_test_with_flexible_context(
        subnet_size as usize,
        callback_id,
        committee,
        min,
        max,
        |payload_builder, _pool| {
            let payload = flexible_payload(vec![flexible_group(
                callback_id,
                subnet_size as u32,
                min,
                vec![
                    flexible_response(42, 0, b"a"),
                    flexible_response(42, 1, b"b"),
                ],
            )]);

            let result = payload_builder.validate_payload(
                Height::from(1),
                &test_proposal_context(&default_validation_context()),
                &payload_to_bytes_max_4mb(payload),
                &[],
            );
            assert_matches!(result, Ok(_));
        },
    );
}

#[test]
fn flexible_valid_at_max_responses_boundary() {
    let subnet_size = 4;
    let committee: BTreeSet<_> = (0..subnet_size).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);
    let (min, max) = (2, subnet_size as u32);

    setup_test_with_flexible_context(
        subnet_size as usize,
        callback_id,
        committee,
        min,
        max,
        |payload_builder, _pool| {
            let payload = flexible_payload(vec![flexible_group(
                callback_id,
                subnet_size as u32,
                min,
                vec![
                    flexible_response(42, 0, b"a"),
                    flexible_response(42, 1, b"b"),
                    flexible_response(42, 2, b"c"),
                    flexible_response(42, 3, b"d"),
                ],
            )]);

            let result = payload_builder.validate_payload(
                Height::from(1),
                &test_proposal_context(&default_validation_context()),
                &payload_to_bytes_max_4mb(payload),
                &[],
            );
            assert_matches!(result, Ok(_));
        },
    );
}

#[test]
fn validate_payload_fails_for_initial_spent_mismatch_flexible_response() {
    let subnet_size = 4;
    let committee: BTreeSet<_> = (0..subnet_size).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);
    let (min, max) = (2, subnet_size as u32);

    setup_test_with_flexible_context(
        subnet_size as usize,
        callback_id,
        committee,
        min,
        max,
        |payload_builder, _pool| {
            // Build an otherwise-valid group, then claim a collective initial
            // spend that differs from what the receipts and subnet size
            // recompute to.
            let mut group = flexible_group(
                callback_id,
                subnet_size as u32,
                min,
                vec![
                    flexible_response(42, 0, b"a"),
                    flexible_response(42, 1, b"b"),
                ],
            );
            // A content-bearing group has a nonzero consensus cost, so the honest
            // value is nonzero; claim one cycle too many.
            let computed = group.initial_spent;
            group.initial_spent = computed + Cycles::new(1);

            let result = payload_builder.validate_payload(
                Height::from(1),
                &test_proposal_context(&default_validation_context()),
                &payload_to_bytes_max_4mb(flexible_payload(vec![group])),
                &[],
            );

            assert_matches!(
                result,
                Err(ValidationError::InvalidArtifact(
                    InvalidPayloadReason::InvalidCanisterHttpPayload(
                        InvalidCanisterHttpPayloadReason::InitialSpentMismatch {
                            callback_id: cb,
                            received,
                            expected,
                        }
                    )
                )) if cb == callback_id
                    && received == computed + Cycles::new(1)
                    && expected == computed
            );
        },
    );
}

#[test]
fn flexible_valid_with_zero_min_and_max_responses() {
    let committee: BTreeSet<_> = (0..4).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(4, callback_id, committee, 0, 0, |payload_builder, _pool| {
        let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
            extra_shares: vec![],
            callback_id,
            initial_spent: Cycles::zero(),
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
    let subnet_size = 4;
    let committee: BTreeSet<_> = (0..subnet_size).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);
    let (min, max) = (1, subnet_size as u32);

    setup_test_with_flexible_context(
        subnet_size as usize,
        callback_id,
        committee,
        min,
        max,
        |payload_builder, _pool| {
            let payload = flexible_payload(vec![
                flexible_group(
                    callback_id,
                    subnet_size as u32,
                    min,
                    vec![flexible_response(42, 0, b"a")],
                ),
                flexible_group(
                    callback_id,
                    subnet_size as u32,
                    min,
                    vec![flexible_response(42, 1, b"b")],
                ),
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
        },
    );
}

#[test]
fn flexible_invalid_already_delivered_callback_id() {
    let committee: BTreeSet<_> = (0..4).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(4, callback_id, committee, 1, 4, |payload_builder, _pool| {
        let group = FlexibleCanisterHttpResponses {
            extra_shares: vec![],
            callback_id,
            initial_spent: Cycles::zero(),
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
            extra_shares: vec![],
            callback_id,
            initial_spent: Cycles::zero(),
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
            extra_shares: vec![],
            callback_id,
            initial_spent: Cycles::zero(),
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
                        callback_id: reported, count, min_responses, max_responses
                    }
                )
            )) if reported == callback_id
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
            extra_shares: vec![],
            callback_id,
            initial_spent: Cycles::zero(),
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
                        callback_id: reported, count, min_responses, max_responses
                    }
                )
            )) if reported == callback_id
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
            extra_shares: vec![],
            callback_id,
            initial_spent: Cycles::zero(),
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
                        callback_id: reported, count, min_responses, max_responses
                    }
                )
            )) if reported == callback_id
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
            extra_shares: vec![],
            callback_id,
            initial_spent: Cycles::zero(),
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
        entry.proof.content.metadata.id = mismatched_id;

        let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
            extra_shares: vec![],
            callback_id,
            initial_spent: Cycles::zero(),
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
                    InvalidCanisterHttpPayloadReason::ShareCallbackIdMismatch { callback_id: cb_id, mismatched_id: mm_id }
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
            extra_shares: vec![],
            callback_id,
            initial_spent: Cycles::zero(),
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
                    InvalidCanisterHttpPayloadReason::DuplicateShareSigner { callback_id: reported, signer }
                )
            )) if reported == callback_id && signer == node_test_id(0)
        );
    });
}

#[test]
fn flexible_invalid_signer_not_in_committee() {
    let committee: BTreeSet<_> = (0..=2).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    setup_test_with_flexible_context(4, callback_id, committee, 1, 3, |payload_builder, _pool| {
        let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
            extra_shares: vec![],
            callback_id,
            initial_spent: Cycles::zero(),
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
                    InvalidCanisterHttpPayloadReason::ShareSignerNotInCommittee { callback_id: reported, signer }
                )
            )) if reported == callback_id && signer == node_test_id(3)
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
        entry.proof.content.metadata.content_hash = wrong_metadata_hash.clone();

        let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
            extra_shares: vec![],
            callback_id,
            initial_spent: Cycles::zero(),
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
        entry.proof.content.metadata.content_size = expected_size.wrapping_add(1);
        let wrong_size = entry.proof.content.metadata.content_size;

        let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
            extra_shares: vec![],
            callback_id,
            initial_spent: Cycles::zero(),
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
        entry.proof.content.metadata.is_reject = !entry.proof.content.metadata.is_reject;

        let payload = flexible_payload(vec![FlexibleCanisterHttpResponses {
            extra_shares: vec![],
            callback_id,
            initial_spent: Cycles::zero(),
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
        add_signer_to_proof(&mut proof, node_test_id(0));

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
                extra_shares: vec![],
                callback_id,
                initial_spent: Cycles::zero(),
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
            extra_shares: vec![],
            callback_id: unknown_id,
            initial_spent: Cycles::zero(),
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
            extra_shares: vec![],
            callback_id,
            initial_spent: Cycles::zero(),
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
            extra_shares: vec![],
            callback_id,
            initial_spent: Cycles::zero(),
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
                    InvalidCanisterHttpPayloadReason::ShareCallbackIdMismatch { callback_id: cb_id, mismatched_id: mm_id }
                )
            )) if cb_id == callback_id && mm_id == mismatched_id
        );
    });
}

#[test]
fn flexible_invalid_signature_error() {
    let subnet_size = 4;
    let committee: BTreeSet<_> = (0..subnet_size).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);
    let (min, max) = (1, subnet_size as u32);

    setup_test_with_flexible_context(
        subnet_size as usize,
        callback_id,
        committee,
        min,
        max,
        |mut payload_builder, _pool| {
            payload_builder.crypto = Arc::new(mock_crypto_rejecting_signatures());

            let payload = flexible_payload(vec![flexible_group(
                callback_id,
                subnet_size as u32,
                min,
                vec![flexible_response(42, 0, b"data")],
            )]);

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
        extra_shares: vec![],
        callback_id,
        initial_spent: Cycles::zero(),
        responses: vec![entry_a, entry_b],
    }]);
    let bytes = payload_to_bytes_max_4mb(payload);

    let (responses, _spent, stats) = CanisterHttpPayloadBuilderImpl::into_messages(&bytes);

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
fn into_messages_emits_initial_spend_reports() {
    // Every delivered outcome that carries signed shares yields one initial spend
    // report tagged with the reporting callback, the amount, and the signing
    // nodes: a fully-replicated response, a flexible ok group, a too-many-rejects
    // error, a divergence, a responses-too-large error, and a non-flexible
    // out-of-cycles error. A plain timeout carries no shares and yields none.
    let fr_callback = CallbackId::from(100);
    let (response, metadata) = test_response_and_metadata(fr_callback.get());
    let mut fr_proof = response_and_metadata_to_proof(&response, &metadata);
    add_signer_to_proof(&mut fr_proof, node_test_id(0));
    add_signer_to_proof(&mut fr_proof, node_test_id(1));
    fr_proof.initial_spent = Cycles::new(7_000);

    let flex_callback = CallbackId::from(42);
    let content = Encode!(&CanisterHttpResponsePayload {
        status: 200,
        headers: vec![],
        body: vec![],
    })
    .unwrap();
    let flex_group = FlexibleCanisterHttpResponses {
        extra_shares: vec![],
        callback_id: flex_callback,
        initial_spent: Cycles::new(3_000),
        responses: vec![
            flexible_response(flex_callback.get(), 0, &content),
            flexible_response(flex_callback.get(), 1, &content),
        ],
    };

    let err_callback = CallbackId::from(200);
    let flex_error = FlexibleCanisterHttpError::TooManyRejects {
        extra_shares: vec![],
        callback_id: err_callback,
        reject_responses: vec![
            flexible_reject_response(err_callback.get(), 0),
            flexible_reject_response(err_callback.get(), 1),
        ],
        initial_spent: Cycles::new(5_000),
    };

    // A plain timeout carries no shares and yields no spend report. A divergence
    // and a responses-too-large error carry signed shares but deliver no body
    // (consensus cost zero), so each reports the sum of its shares' spend.
    let timeout_callback = CallbackId::from(300);

    let div_callback = CallbackId::from(400);
    let (_, div_metadata) = test_response_and_metadata(div_callback.get());
    let divergent_share = |node: u64, hash: u8, spent: u128| {
        let mut metadata = div_metadata.clone();
        metadata.content_hash = CryptoHashOf::from(CryptoHash(vec![hash; 32]));
        Signed {
            content: CanisterHttpResponseReceipt {
                metadata,
                payment_receipt: CanisterHttpPaymentReceipt {
                    spent: Cycles::new(spent),
                },
            },
            signature: BasicSignature {
                signature: BasicSigOf::new(BasicSig(vec![])),
                signer: node_test_id(node),
            },
        }
    };
    // divergence spend = 400 + 600 = 1_000.
    let divergence = CanisterHttpResponseDivergence {
        shares: vec![divergent_share(0, 1, 400), divergent_share(1, 2, 600)],
    };

    let too_large_callback = CallbackId::from(500);
    let (_, tl_metadata) = test_response_and_metadata(too_large_callback.get());
    let seen_share = |node: u64, spent: u128| Signed {
        content: CanisterHttpResponseReceipt {
            metadata: tl_metadata.clone(),
            payment_receipt: CanisterHttpPaymentReceipt {
                spent: Cycles::new(spent),
            },
        },
        signature: BasicSignature {
            signature: BasicSigOf::new(BasicSig(vec![])),
            signer: node_test_id(node),
        },
    };
    // responses-too-large spend = 250 + 350 = 600.
    let too_large = FlexibleCanisterHttpError::ResponsesTooLarge {
        callback_id: too_large_callback,
        all_seen_shares: vec![seen_share(0, 250), seen_share(1, 350)],
        total_requests: 2,
        min_responses: 1,
    };

    let ooc_callback = CallbackId::from(600);
    let (_, ooc_metadata) = test_response_and_metadata(ooc_callback.get());
    // out-of-cycles spend = 150 + 450 = 600, as it delivers no body either.
    let out_of_cycles = CanisterHttpOutOfCycles {
        callback_id: ooc_callback,
        shares: vec![
            metadata_to_share_with_spent(0, &ooc_metadata, Cycles::new(150)),
            metadata_to_share_with_spent(1, &ooc_metadata, Cycles::new(450)),
        ],
        min_cost: Cycles::new(1_234),
        unspent_allowance: Cycles::new(56),
    };

    let payload = CanisterHttpPayload {
        responses: vec![fr_proof],
        flexible_responses: vec![flex_group],
        flexible_errors: vec![flex_error, too_large],
        timeouts: vec![timeout_callback],
        divergence_responses: vec![divergence],
        out_of_cycles: vec![out_of_cycles],
        async_receipts: vec![],
    };
    let bytes = payload_to_bytes_max_4mb(payload);

    let (responses, spent, stats) = CanisterHttpPayloadBuilderImpl::into_messages(&bytes);

    // All seven callbacks are delivered as consensus responses...
    let delivered: BTreeSet<CallbackId> = responses.iter().map(|r| r.callback).collect();
    assert_eq!(
        delivered,
        [
            fr_callback,
            flex_callback,
            err_callback,
            timeout_callback,
            div_callback,
            too_large_callback,
            ooc_callback,
        ]
        .into_iter()
        .collect()
    );
    // ...and every one except the timeout reports an initial spend.
    assert_eq!(spent.initial.len(), 6);
    assert!(spent.initial.iter().all(|r| r.callback != timeout_callback));
    assert!(spent.asynchronous.is_empty());
    assert_eq!(stats.out_of_cycles, 1);

    let signers: BTreeSet<NodeId> = [node_test_id(0), node_test_id(1)].into_iter().collect();
    let report = |callback: CallbackId| {
        spent
            .initial
            .iter()
            .find(|r| r.callback == callback)
            .unwrap_or_else(|| panic!("report for {callback} missing"))
    };

    let fr = report(fr_callback);
    assert_eq!(fr.amount, Cycles::new(7_000));
    assert_eq!(fr.nodes, signers);

    let flex = report(flex_callback);
    assert_eq!(flex.amount, Cycles::new(3_000));
    assert_eq!(flex.nodes, signers);

    let err = report(err_callback);
    assert_eq!(err.amount, Cycles::new(5_000));
    assert_eq!(err.nodes, signers);

    let div = report(div_callback);
    assert_eq!(div.amount, Cycles::new(1_000));
    assert_eq!(div.nodes, signers);

    let too_large = report(too_large_callback);
    assert_eq!(too_large.amount, Cycles::new(600));
    assert_eq!(too_large.nodes, signers);

    let out_of_cycles = report(ooc_callback);
    assert_eq!(out_of_cycles.amount, Cycles::new(600));
    assert_eq!(out_of_cycles.nodes, signers);
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
        extra_shares: vec![],
        callback_id,
        initial_spent: Cycles::zero(),
        responses: vec![success_entry, reject_entry],
    }]);
    let bytes = payload_to_bytes_max_4mb(payload);

    let (responses, _spent, stats) = CanisterHttpPayloadBuilderImpl::into_messages(&bytes);

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
        extra_shares: vec![],
        callback_id: CallbackId::from(1),
        initial_spent: Cycles::zero(),
        responses: vec![flexible_response(1, 0, &payload_data)],
    };
    let group_b = FlexibleCanisterHttpResponses {
        extra_shares: vec![],
        callback_id: CallbackId::from(2),
        initial_spent: Cycles::zero(),
        responses: vec![flexible_response(2, 1, &payload_data)],
    };
    let group_c = FlexibleCanisterHttpResponses {
        extra_shares: vec![],
        callback_id: CallbackId::from(3),
        initial_spent: Cycles::zero(),
        responses: vec![flexible_response(3, 2, &payload_data)],
    };

    let payload = flexible_payload(vec![group_a, group_b, group_c]);
    let bytes = payload_to_bytes_max_4mb(payload);

    let (responses, _spent, stats) = CanisterHttpPayloadBuilderImpl::into_messages(&bytes);

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
        extra_shares: vec![],
        callback_id,
        initial_spent: Cycles::zero(),
        responses: vec![valid_entry, invalid_entry],
    }]);
    let bytes = payload_to_bytes_max_4mb(payload);

    let (responses, spent, stats) = CanisterHttpPayloadBuilderImpl::into_messages(&bytes);

    assert_eq!(responses.len(), 0);
    assert_eq!(stats.flexible_ok_responses, 0);
    assert_eq!(stats.flexible_ok_responses_candid_failures, 1);
    // A candid-decode failure delivers nothing, hence reports no spend.
    assert!(spent.initial.is_empty());
    assert!(spent.asynchronous.is_empty());
}

#[test]
fn flexible_error_into_messages_timeout() {
    let callback_id = CallbackId::from(42);

    let payload = CanisterHttpPayload {
        flexible_errors: vec![FlexibleCanisterHttpError::Timeout { callback_id }],
        ..Default::default()
    };
    let bytes = payload_to_bytes_max_4mb(payload);

    let (responses, spent, stats) = CanisterHttpPayloadBuilderImpl::into_messages(&bytes);

    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].callback, callback_id);
    assert_eq!(stats.flexible_errors, BTreeMap::from([("timeout", 1)]));
    assert_eq!(stats.flexible_errors_candid_failures, 0);
    // A flexible timeout carries no full response body, hence reports no spend.
    assert!(spent.initial.is_empty());
    assert!(spent.asynchronous.is_empty());

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
            extra_shares: vec![],
            callback_id,
            initial_spent: Cycles::zero(),
            reject_responses: reject_entries,
        }],
        ..Default::default()
    };
    let bytes = payload_to_bytes_max_4mb(payload);

    let (responses, _spent, stats) = CanisterHttpPayloadBuilderImpl::into_messages(&bytes);

    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].callback, callback_id);
    assert_eq!(
        stats.flexible_errors,
        BTreeMap::from([("too_many_rejects", 1)])
    );
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

    let (responses, spent, stats) = CanisterHttpPayloadBuilderImpl::into_messages(&bytes);

    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].callback, callback_id);
    assert_eq!(
        stats.flexible_errors,
        BTreeMap::from([("responses_too_large", 1)])
    );
    assert_eq!(stats.flexible_errors_candid_failures, 0);
    // A responses-too-large error delivers no body (consensus cost zero), so it
    // reports the sum of its seen shares' per-replica spend. Here every share
    // carries a default (zero) receipt, so the reported amount is zero, but a
    // report is still emitted for all signing nodes.
    assert_eq!(spent.initial.len(), 1);
    let report = &spent.initial[0];
    assert_eq!(report.callback, callback_id);
    assert_eq!(report.amount, Cycles::zero());
    assert_eq!(
        report.nodes,
        (0..4).map(node_test_id).collect::<BTreeSet<_>>()
    );
    assert!(spent.asynchronous.is_empty());

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
                assert!(all_seen_shares.iter().all(|s| !s.content.is_reject()));
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
                let ok_count = all_seen_shares.iter().filter(|s| !s.content.is_reject()).count();
                let reject_count = all_seen_shares.iter().filter(|s| s.content.is_reject()).count();
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
                let ok_count = all_seen_shares.iter().filter(|s| !s.content.is_reject()).count();
                let reject_count = all_seen_shares.iter().filter(|s| s.content.is_reject()).count();
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
                ..
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
    let (min, max) = (1, 4);

    setup_test_with_flexible_context(num_nodes, callback_id, committee, min, max, |pb, _pool| {
        let timed_out_context = ValidationContext {
            registry_version: RegistryVersion::new(1),
            certified_height: Height::new(0),
            time: UNIX_EPOCH + CANISTER_HTTP_TIMEOUT_INTERVAL + Duration::from_secs(1),
        };
        let payload = CanisterHttpPayload {
            flexible_responses: vec![flexible_group(
                callback_id,
                num_nodes as u32,
                min,
                vec![flexible_response(42, 0, b"a")],
            )],
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
                    InvalidCanisterHttpPayloadReason::ShareCallbackIdMismatch { callback_id: cb_id, mismatched_id: mm_id }
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
                    InvalidCanisterHttpPayloadReason::DuplicateShareSigner { callback_id: cb_id, signer: s }
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
                    InvalidCanisterHttpPayloadReason::ShareSignerNotInCommittee { callback_id: cb_id, signer: s }
                )
            )) if cb_id == callback_id && s == node_test_id(99)
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

        let all_seen_shares = (0..4)
            .map(|node| metadata_share_with_content_size(callback_id.get(), node, huge))
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
    let (min, max) = (3, 4);

    // min_responses=3, committee=4. max_allowed_rejects = 4-3 = 1.
    // 2 rejects should be valid for TooManyRejects.
    setup_test_with_flexible_context(num_nodes, callback_id, committee, min, max, |pb, _pool| {
        let reject_entries: Vec<_> = (0..2_u64)
            .map(|node_idx| flexible_reject_response(callback_id.get(), node_idx))
            .collect();

        let payload = CanisterHttpPayload {
            flexible_errors: vec![too_many_rejects(
                callback_id,
                num_nodes as u32,
                min,
                reject_entries,
            )],
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
fn validate_payload_fails_for_initial_spent_mismatch_too_many_rejects() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);

    let (min, max) = (3, 4);
    // min_responses=3, committee=4. max_allowed_rejects = 1, so 2 rejects form an
    // otherwise-valid TooManyRejects error.
    setup_test_with_flexible_context(num_nodes, callback_id, committee, min, max, |pb, _pool| {
        let reject_entries: Vec<_> = (0..2_u64)
            .map(|node_idx| flexible_reject_response(callback_id.get(), node_idx))
            .collect();
        // The honest collective initial spend the validator recomputes from the
        // receipts and subnet size...
        let computed = flexible_initial_spent(
            reject_entries.iter().map(|r| &r.proof),
            std::iter::empty(),
            NumberOfNodes::from(num_nodes as u32),
            min,
        );
        // ...but the payload claims one cycle more.
        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::TooManyRejects {
                extra_shares: vec![],
                callback_id,
                reject_responses: reject_entries,
                initial_spent: computed + Cycles::new(1),
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
                    InvalidCanisterHttpPayloadReason::InitialSpentMismatch {
                        callback_id: cb,
                        received,
                        expected,
                    }
                )
            )) if cb == callback_id
                && received == computed + Cycles::new(1)
                && expected == computed
        );
    });
}

#[test]
fn flexible_error_too_many_rejects_insufficient_rejects() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);
    let (min, max) = (3, 4);

    // min_responses=3, committee=4. max_allowed_rejects = 1.
    // Only 1 reject → not enough for TooManyRejects.
    setup_test_with_flexible_context(num_nodes, callback_id, committee, min, max, |pb, _pool| {
        let reject_entries: Vec<_> = (0..1_u64)
            .map(|node_idx| flexible_reject_response(callback_id.get(), node_idx))
            .collect();

        let payload = CanisterHttpPayload {
            flexible_errors: vec![too_many_rejects(
                callback_id,
                num_nodes as u32,
                min,
                reject_entries,
            )],
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
                extra_shares: vec![],
                callback_id,
                initial_spent: Cycles::zero(),
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
                extra_shares: vec![],
                callback_id,
                initial_spent: Cycles::zero(),
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
                    InvalidCanisterHttpPayloadReason::DuplicateShareSigner { callback_id: cb_id, signer: s }
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
                extra_shares: vec![],
                callback_id,
                initial_spent: Cycles::zero(),
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
                    InvalidCanisterHttpPayloadReason::ShareSignerNotInCommittee { callback_id: cb_id, signer: s }
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
                extra_shares: vec![],
                callback_id,
                initial_spent: Cycles::zero(),
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
                    InvalidCanisterHttpPayloadReason::ShareCallbackIdMismatch { callback_id: cb_id, mismatched_id: mm_id }
                )
            )) if cb_id == callback_id && mm_id == CallbackId::new(999)
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
        entry_bad.proof.content.metadata.content_hash =
            CryptoHashOf::new(CryptoHash(vec![0xFF; 32]));

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::TooManyRejects {
                extra_shares: vec![],
                callback_id,
                initial_spent: Cycles::zero(),
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
        let mismatched_size = MAXIMUM_CANISTER_HTTP_ERROR_MESSAGE_BYTES as u32;
        entry_bad.proof.content.metadata.content_size = mismatched_size;

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::TooManyRejects {
                extra_shares: vec![],
                callback_id,
                initial_spent: Cycles::zero(),
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
            )) if ms == mismatched_size && cs < ms && cs != 0
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
        entry_bad.proof.content.metadata.is_reject = !entry_bad.proof.content.metadata.is_reject;

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::TooManyRejects {
                extra_shares: vec![],
                callback_id,
                initial_spent: Cycles::zero(),
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
        entry_bad.proof.content.metadata.id = CallbackId::new(999);

        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::TooManyRejects {
                extra_shares: vec![],
                callback_id,
                initial_spent: Cycles::zero(),
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
                    InvalidCanisterHttpPayloadReason::ShareCallbackIdMismatch {
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
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);
    let (min, max) = (3, 4);

    setup_test_with_flexible_context(
        num_nodes,
        callback_id,
        committee,
        min,
        max,
        |mut pb, _pool| {
            pb.crypto = Arc::new(mock_crypto_rejecting_signatures());

            let reject_entries: Vec<_> = (0..2_u64)
                .map(|node_idx| flexible_reject_response(callback_id.get(), node_idx))
                .collect();

            let payload = CanisterHttpPayload {
                flexible_errors: vec![too_many_rejects(
                    callback_id,
                    num_nodes as u32,
                    min,
                    reject_entries,
                )],
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
        },
    );
}

// ===================================================================
// Keeping the collective initial spend within the collective allowance
// ===================================================================

/// Prices `context` with pay-as-you-go, granting each of its replicas
/// `per_replica_allowance`.
fn with_payg_allowance(
    mut context: CanisterHttpRequestContext,
    per_replica_allowance: Cycles,
) -> CanisterHttpRequestContext {
    context.pricing_version = PricingVersion::PayAsYouGo;
    context.refund_status.per_replica_allowance = per_replica_allowance;
    context.refund_status.refundable_cycles =
        per_replica_allowance * context.replication.node_count(context.subnet_size);
    context
}

/// The consensus cost of a fully-replicated response of `content_size` bytes on
/// a subnet of `num_nodes` nodes, i.e. the part of the collective initial spend
/// that the signing replicas' unspent allowances have to cover.
fn non_flexible_consensus_cost(num_nodes: usize, content_size: u32) -> Cycles {
    consensus_fee(content_size as u128, NumberOfNodes::from(num_nodes as u32))
}

/// Adds a share (and its response) for every node in `nodes` to the pool, all
/// agreeing on the same successful response `content` and claiming no spend.
fn add_flexible_ok_shares(
    pool: &Arc<RwLock<CanisterHttpPoolImpl>>,
    callback_id: CallbackId,
    nodes: impl IntoIterator<Item = u64>,
    content: &[u8],
) {
    add_flexible_shares(
        pool,
        callback_id,
        nodes,
        CanisterHttpResponseContent::Success(content.to_vec()),
        Cycles::zero(),
    );
}

/// Adds a reject share (and its response) for every node in `nodes` to the pool.
fn add_flexible_reject_shares(
    pool: &Arc<RwLock<CanisterHttpPoolImpl>>,
    callback_id: CallbackId,
    nodes: impl IntoIterator<Item = u64>,
) {
    add_flexible_shares(
        pool,
        callback_id,
        nodes,
        CanisterHttpResponseContent::Reject(CanisterHttpReject {
            reject_code: RejectCode::SysTransient,
            message: "could not connect".to_string(),
        }),
        Cycles::zero(),
    );
}

fn add_flexible_shares(
    pool: &Arc<RwLock<CanisterHttpPoolImpl>>,
    callback_id: CallbackId,
    nodes: impl IntoIterator<Item = u64>,
    content: CanisterHttpResponseContent,
    spent: Cycles,
) {
    let (response, metadata) = test_response_and_metadata_with_content(callback_id.get(), content);
    let mut pool_access = pool.write().unwrap();
    for node in nodes {
        let share = metadata_to_share_with_spent(node, &metadata, spent);
        add_own_share_to_pool(pool_access.deref_mut(), &share, &response);
    }
}

/// A replica may only contribute its allowance once: the group shrinks from
/// `max_responses` until it is covered, and the shares funding it must exclude
/// whichever signers end up delivering a response.
#[test]
fn flexible_response_group_is_not_funded_by_a_delivering_replica() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);
    let (min, max) = (1, 4);

    // Response size and claimed spend are deliberately at odds: the replica whose
    // response is delivered first spent the most, and the one that funds it spent
    // the least while being next in line to be delivered.
    let replicas = [
        (0_u64, 100_usize, 50_u128),
        (1, 200, 0),
        (2, 300, 10),
        (3, 400, 20),
    ];
    let share_of = |(node, len, spent): (u64, usize, u128)| {
        let (_, metadata) = test_response_and_metadata_with_content(
            callback_id.get(),
            CanisterHttpResponseContent::Success(vec![0xAB_u8; len]),
        );
        metadata_to_share_with_spent(node, &metadata, Cycles::new(spent))
    };
    let spend_of = |delivered: &[usize], extra: &[usize]| {
        let delivered: Vec<_> = delivered.iter().map(|&i| share_of(replicas[i])).collect();
        let extra: Vec<_> = extra.iter().map(|&i| share_of(replicas[i])).collect();
        flexible_initial_spent(
            delivered.iter(),
            extra.iter(),
            NumberOfNodes::from(num_nodes as u32),
            min,
        )
    };

    let allowance = Cycles::new(600_000);
    // Three responses are not covered even by the whole committee, two are, so the
    // group shrinks to exactly two and is funded by the other two replicas — never
    // by replica 1, which delivers the second response.
    assert!(spend_of(&[0, 1, 2], &[3]) > allowance * 4_usize);
    let group_spend = spend_of(&[0, 1], &[2, 3]);
    assert!(group_spend <= allowance * 4_usize);

    setup_test_with_contexts(
        num_nodes,
        vec![(
            callback_id,
            flexible_request_context_with_allowance(committee, min, max, allowance),
        )],
        |payload_builder, pool| {
            for (node, len, spent) in replicas {
                add_flexible_shares(
                    &pool,
                    callback_id,
                    [node],
                    CanisterHttpResponseContent::Success(vec![0xAB_u8; len]),
                    Cycles::new(spent),
                );
            }

            let payload = build_and_validate_and_parse_payload(&payload_builder);
            assert_eq!(payload.flexible_responses.len(), 1);
            let group = &payload.flexible_responses[0];
            assert_eq!(group.responses.len(), 2);
            assert_eq!(group.extra_shares.len(), 2);
            assert_eq!(group.initial_spent, group_spend);

            // No replica contributes its allowance twice: replica 1, the cheapest
            // extra share, delivers a response instead of funding one.
            let delivering: BTreeSet<_> = group
                .responses
                .iter()
                .map(|r| r.proof.signature.signer)
                .collect();
            let funding: BTreeSet<_> = group
                .extra_shares
                .iter()
                .map(|share| share.signature.signer)
                .collect();
            assert_eq!(
                delivering,
                BTreeSet::from([node_test_id(0), node_test_id(1)])
            );
            assert_eq!(funding, BTreeSet::from([node_test_id(2), node_test_id(3)]));
        },
    );
}

/// A fully-replicated response is only delivered once the signing replicas have
/// left enough of their allowances unspent to cover its consensus cost: with
/// `threshold` many shares their collective allowance falls short, so the
/// response is held back until the remaining shares have arrived.
#[test]
fn fully_replicated_response_waits_for_shares_covering_consensus_cost() {
    let num_nodes = 4;
    let threshold = canister_http_threshold(num_nodes);
    let cb_id = 0;
    let (response, metadata) = test_response_and_metadata(cb_id);
    let consensus_cost = non_flexible_consensus_cost(num_nodes, metadata.content_size);
    // An allowance that all `num_nodes` replicas together just cover, while the
    // `threshold` many that suffice to reach consensus do not.
    let allowance = Cycles::new(consensus_cost.get() / num_nodes as u128 + 1);
    assert!(allowance * threshold < consensus_cost);
    assert!(consensus_cost <= allowance * num_nodes);

    setup_test_with_contexts(
        num_nodes,
        vec![(
            CallbackId::new(cb_id),
            with_payg_allowance(request_context(Replication::FullyReplicated), allowance),
        )],
        |payload_builder, canister_http_pool| {
            let shares = metadata_to_shares(num_nodes, &metadata);
            {
                let mut pool_access = canister_http_pool.write().unwrap();
                add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &response);
                add_received_shares_to_pool(pool_access.deref_mut(), shares[1..threshold].to_vec());
            }

            // Consensus is reached, but the signers' collective allowance does
            // not cover the consensus cost yet.
            let payload = build_and_validate_and_parse_payload(&payload_builder);
            assert_eq!(payload.num_responses(), 0);

            // The remaining shares tip the collective allowance over the cost.
            {
                let mut pool_access = canister_http_pool.write().unwrap();
                add_received_shares_to_pool(pool_access.deref_mut(), shares[threshold..].to_vec());
            }
            let payload = build_and_validate_and_parse_payload(&payload_builder);
            assert_eq!(payload.num_responses(), 1);
            assert_eq!(payload.responses[0].content, response);
            assert_eq!(payload.responses[0].initial_spent, consensus_cost);
        },
    );
}

/// Builds a payload from `threshold` many fully-replicated shares for a request with
/// the given `context`, and asserts that it carries `expected_responses` many
/// responses and `expected_out_of_cycles` many out-of-cycles errors. The latter tells
/// a response the committee can never afford from one that is merely held back until
/// the shares still outstanding contribute their allowances.
fn assert_responses_from_threshold_shares(
    num_nodes: usize,
    context: CanisterHttpRequestContext,
    expected_responses: usize,
    expected_out_of_cycles: usize,
) {
    let cb_id = 0;
    let threshold = canister_http_threshold(num_nodes);
    let (response, metadata) = test_response_and_metadata(cb_id);
    // Ensure that the consensus cost is nonzero, so that the test only passes if the unspent
    // allowance is sufficient, or if the consensus cost isn't enforced (free and legacy requests).
    assert!(!non_flexible_consensus_cost(num_nodes, metadata.content_size).is_zero());

    setup_test_with_contexts(
        num_nodes,
        vec![(CallbackId::new(cb_id), context)],
        |payload_builder, canister_http_pool| {
            let shares = metadata_to_shares(num_nodes, &metadata);
            {
                let mut pool_access = canister_http_pool.write().unwrap();
                add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &response);
                add_received_shares_to_pool(pool_access.deref_mut(), shares[1..threshold].to_vec());
            }
            let payload = build_and_validate_and_parse_payload(&payload_builder);
            assert_eq!(
                (payload.responses.len(), payload.out_of_cycles.len()),
                (expected_responses, expected_out_of_cycles)
            );
        },
    );
}

/// Legacy-priced requests are not refunded from a per-replica allowance, so
/// their responses are delivered no matter how small that allowance is.
#[test]
fn initial_spent_is_not_limited_under_legacy_pricing() {
    // `request_context` is priced with legacy pricing and has a zero allowance.
    assert_responses_from_threshold_shares(4, request_context(Replication::FullyReplicated), 1, 0);
}

/// Free subnets charge — and hence refund — nothing, so their responses are
/// delivered despite the (zero) collective allowance.
#[test]
fn initial_spent_is_not_limited_on_a_free_subnet() {
    let mut context = with_payg_allowance(
        request_context(Replication::FullyReplicated),
        Cycles::zero(),
    );
    context.cost_schedule = CanisterCyclesCostSchedule::Free;
    assert_responses_from_threshold_shares(4, context, 1, 0);
}

/// On a charging subnet with pay-as-you-go pricing, a zero collective
/// allowance holds the response back.
#[test]
fn initial_spent_is_limited_under_pay_as_you_go_pricing() {
    assert_responses_from_threshold_shares(
        4,
        with_payg_allowance(
            request_context(Replication::FullyReplicated),
            Cycles::zero(),
        ),
        0,
        // A zero allowance can never cover any response, so the outcall is reported as
        // out of cycles rather than held back for allowances that would not help.
        1,
    );
}

/// On a charging subnet with pay-as-you-go pricing, the pay-as-you-go response
/// is delivered as soon as the collective allowance covers the consensus cost.
#[test]
fn initial_spent_is_covered_under_pay_as_you_go_pricing() {
    let num_nodes = 4;
    let threshold = canister_http_threshold(num_nodes);
    let (_, metadata) = test_response_and_metadata(0);
    let consensus_cost = non_flexible_consensus_cost(num_nodes, metadata.content_size);
    let allowance = Cycles::new(consensus_cost.get().div_ceil(threshold as u128));
    assert!(allowance * threshold >= consensus_cost);
    assert!((allowance - Cycles::new(1)) * threshold < consensus_cost);

    assert_responses_from_threshold_shares(
        num_nodes,
        with_payg_allowance(request_context(Replication::FullyReplicated), allowance),
        1,
        0,
    );

    assert_responses_from_threshold_shares(
        num_nodes,
        with_payg_allowance(
            request_context(Replication::FullyReplicated),
            allowance - Cycles::new(1),
        ),
        0,
        // Held back, not doomed: the replica yet to be seen contributes another
        // allowance, which together with the three seen would cover the cost.
        0,
    );
}

#[test]
fn out_of_cycles_is_delivered_as_a_reject_with_the_spend_reported() {
    let num_nodes = 4;
    let cb_id = 0;
    let designated = node_test_id(0);
    let (response, metadata) = test_response_and_metadata(cb_id);
    // The designated replica spent its whole allowance, leaving nothing for the
    // consensus cost of delivering its response.
    let allowance = TEST_PER_REPLICA_ALLOWANCE;
    let share = metadata_to_share_with_spent(node_id_to_u64(designated), &metadata, allowance);

    setup_test_with_contexts(
        num_nodes,
        vec![(
            CallbackId::new(cb_id),
            with_payg_allowance(
                request_context(Replication::NonReplicated(designated)),
                allowance,
            ),
        )],
        |payload_builder, canister_http_pool| {
            {
                let mut pool_access = canister_http_pool.write().unwrap();
                add_own_share_to_pool(pool_access.deref_mut(), &share, &response);
            }

            let payload = build_and_validate_and_parse_payload(&payload_builder);
            assert_eq!(payload.responses.len(), 0);
            assert_eq!(payload.out_of_cycles.len(), 1);
            let error = &payload.out_of_cycles[0];
            assert_eq!(error.shares.len(), 1);
            assert_eq!(error.unspent_allowance, Cycles::zero());
            assert!(!error.min_cost.is_zero());
            let (min_cost, spent) = (error.min_cost, allowance);

            let (responses, spent_report, stats) = CanisterHttpPayloadBuilderImpl::into_messages(
                &payload_to_bytes_max_4mb(payload.clone()),
            );
            assert_eq!(stats.out_of_cycles, 1);
            assert_eq!(responses.len(), 1);
            let Payload::Reject(ref reject) = responses[0].payload else {
                panic!("Expected Payload::Reject, got {:?}", responses[0].payload);
            };
            // The caller is told what was spent and what a response would have cost, so
            // that it can tell how much more it would have had to attach.
            assert!(
                reject.message().contains(&format!("{spent}"))
                    && reject.message().contains(&format!("{min_cost}")),
                "figures missing from {}",
                reject.message()
            );

            // And the spend is recorded, rather than refunded in full at timeout.
            assert_eq!(spent_report.initial.len(), 1);
            assert_eq!(spent_report.initial[0].callback, CallbackId::new(cb_id));
            assert_eq!(spent_report.initial[0].amount, allowance);
            assert_eq!(spent_report.initial[0].nodes, BTreeSet::from([designated]));
        },
    );
}

/// The out-of-cycles error that a fully-replicated and a non-replicated outcall
/// produce is delivered as a reject spelling out the figures it is proved by, with
/// the spend its shares report recorded rather than refunded.
#[test]
fn into_messages_delivers_out_of_cycles_as_rejects() {
    // A fully-replicated outcall, three of whose assigned replicas have signed a
    // receipt, between them accounting for 300 + 500 + 700 = 1_500 cycles of spend.
    let replicated_callback = CallbackId::from(42);
    let (_, replicated_metadata) = test_response_and_metadata(replicated_callback.get());
    let replicated = CanisterHttpOutOfCycles {
        callback_id: replicated_callback,
        shares: vec![
            metadata_to_share_with_spent(0, &replicated_metadata, Cycles::new(300)),
            metadata_to_share_with_spent(1, &replicated_metadata, Cycles::new(500)),
            metadata_to_share_with_spent(2, &replicated_metadata, Cycles::new(700)),
        ],
        min_cost: Cycles::new(9_000),
        unspent_allowance: Cycles::new(1_100),
    };

    // A non-replicated outcall, where only the designated replica ever answers, so its
    // single share is all the evidence there is and no allowance is left unspent.
    let non_replicated_callback = CallbackId::from(43);
    let (_, non_replicated_metadata) = test_response_and_metadata(non_replicated_callback.get());
    let designated = 3;
    let non_replicated = CanisterHttpOutOfCycles {
        callback_id: non_replicated_callback,
        shares: vec![metadata_to_share_with_spent(
            designated,
            &non_replicated_metadata,
            Cycles::new(2_500),
        )],
        min_cost: Cycles::new(4_000),
        unspent_allowance: Cycles::zero(),
    };

    let payload = CanisterHttpPayload {
        out_of_cycles: vec![replicated, non_replicated],
        ..Default::default()
    };

    let (responses, spent, stats) =
        CanisterHttpPayloadBuilderImpl::into_messages(&payload_to_bytes_max_4mb(payload));

    assert_eq!(stats.out_of_cycles, 2);
    assert_eq!(responses.len(), 2);
    assert_eq!(spent.initial.len(), 2);
    assert!(spent.asynchronous.is_empty());

    let reject_message = |callback: CallbackId| {
        let response = responses
            .iter()
            .find(|response| response.callback == callback)
            .unwrap_or_else(|| panic!("response for {callback} missing"));
        let Payload::Reject(ref reject) = response.payload else {
            panic!("Expected Payload::Reject, got {:?}", response.payload);
        };
        assert_eq!(reject.code(), RejectCode::CanisterReject);
        reject.message().clone()
    };
    let report = |callback: CallbackId| {
        spent
            .initial
            .iter()
            .find(|report| report.callback == callback)
            .unwrap_or_else(|| panic!("report for {callback} missing"))
    };
    // Each figure is checked in its own slot of the message, so that reporting the
    // allowance where the cost belongs (or vice versa) does not pass.
    let assert_figures = |message: &str, fragments: [String; 4]| {
        for fragment in fragments {
            assert!(
                message.contains(&fragment),
                "{fragment:?} missing from {message}"
            );
        }
    };

    // The caller is told how many replicas answered, what they spent between them,
    // what is left of the collective allowance, and what a response would have cost
    // at least, so that it can tell how much more it would have had to attach.
    assert_figures(
        &reject_message(replicated_callback),
        [
            "3 of the assigned replicas".to_string(),
            format!("collective spend of {} cycles", Cycles::new(1_500)),
            format!("leaving {} cycles", Cycles::new(1_100)),
            format!("cost at least {} cycles", Cycles::new(9_000)),
        ],
    );
    assert_figures(
        &reject_message(non_replicated_callback),
        [
            "1 of the assigned replicas".to_string(),
            format!("collective spend of {} cycles", Cycles::new(2_500)),
            format!("leaving {} cycles", Cycles::zero()),
            format!("cost at least {} cycles", Cycles::new(4_000)),
        ],
    );

    // Neither error delivers a body, so each reports just what its own shares spent,
    // charged to exactly the replicas that signed them.
    let replicated_report = report(replicated_callback);
    assert_eq!(replicated_report.amount, Cycles::new(1_500));
    assert_eq!(
        replicated_report.nodes,
        (0..3).map(node_test_id).collect::<BTreeSet<_>>()
    );

    let non_replicated_report = report(non_replicated_callback);
    assert_eq!(non_replicated_report.amount, Cycles::new(2_500));
    assert_eq!(
        non_replicated_report.nodes,
        BTreeSet::from([node_test_id(designated)])
    );
}

/// A fully-replicated outcall keeps waiting while replicas that have not answered yet
/// could still contribute an allowance, and is only reported once enough of them have
/// answered that the response is pinned and unaffordable.
#[test]
fn fully_replicated_out_of_cycles_waits_until_the_response_is_pinned() {
    let num_nodes = 4;
    let cb_id = 0;
    let faults_tolerated = get_faults_tolerated(num_nodes);
    let (response, metadata) = test_response_and_metadata(cb_id);
    let consensus_cost = non_flexible_consensus_cost(num_nodes, metadata.content_size);
    // Nobody has spent anything, so the collective allowance is the same however many
    // replicas have answered — and it does not cover the cost. What flips the verdict
    // is therefore the response becoming pinned, and nothing else.
    let allowance = Cycles::new((consensus_cost.get() - 1) / num_nodes as u128);
    assert!(allowance * num_nodes < consensus_cost);
    let shares = metadata_to_shares(num_nodes, &metadata);

    // While at most `faults_tolerated` have answered, some other response could still
    // win with an empty body, which costs nothing to deliver.
    for seen in 0..=num_nodes {
        setup_test_with_contexts(
            num_nodes,
            vec![(
                CallbackId::new(cb_id),
                with_payg_allowance(request_context(Replication::FullyReplicated), allowance),
            )],
            |payload_builder, canister_http_pool| {
                {
                    let mut pool_access = canister_http_pool.write().unwrap();
                    if seen > 0 {
                        add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &response);
                        add_received_shares_to_pool(
                            pool_access.deref_mut(),
                            shares[1..seen].to_vec(),
                        );
                    }
                }
                let payload = build_and_validate_and_parse_payload(&payload_builder);
                let expected = usize::from(seen > faults_tolerated);
                assert_eq!(
                    payload.out_of_cycles.len(),
                    expected,
                    "unexpected verdict with {seen} of {num_nodes} shares seen"
                );
                if let [error] = payload.out_of_cycles.as_slice() {
                    // Every share seen is included as evidence, and the figures it
                    // proves the error by are the whole (unspent) collective
                    // allowance against the cost of the one response left.
                    assert_eq!(error.callback_id, CallbackId::new(cb_id));
                    assert_eq!(error.shares.len(), seen);
                    assert_eq!(error.unspent_allowance, allowance * num_nodes);
                    assert_eq!(error.min_cost, consensus_cost);
                }
            },
        );
    }
}

/// Validates a payload carrying nothing but the given non-flexible out-of-cycles
/// `error`, against a request with the given `context` on a subnet of `num_nodes`
/// nodes.
fn validate_out_of_cycles_payload(
    num_nodes: usize,
    callback_id: CallbackId,
    context: CanisterHttpRequestContext,
    error: CanisterHttpOutOfCycles,
) -> Result<(), PayloadValidationError> {
    let payload = CanisterHttpPayload {
        out_of_cycles: vec![error],
        ..Default::default()
    };
    let mut result = None;
    setup_test_with_contexts(
        num_nodes,
        vec![(callback_id, context)],
        |payload_builder, _pool| {
            result = Some(payload_builder.validate_payload(
                Height::new(1),
                &test_proposal_context(&default_validation_context()),
                &payload_to_bytes_max_4mb(payload),
                &[],
            ));
        },
    );
    result.expect("validation did not run")
}

#[test]
fn validate_payload_fails_for_a_non_flexible_out_of_cycles_that_does_not_hold() {
    let num_nodes = 4;
    let cb_id = 0;
    let designated = node_test_id(0);
    let (_, metadata) = test_response_and_metadata(cb_id);
    let share = metadata_to_share(node_id_to_u64(designated), &metadata);
    let consensus_cost = non_flexible_consensus_cost(num_nodes, metadata.content_size);

    let validate = |allowance, min_cost, unspent_allowance| {
        validate_out_of_cycles_payload(
            num_nodes,
            CallbackId::new(cb_id),
            with_payg_allowance(
                request_context(Replication::NonReplicated(designated)),
                allowance,
            ),
            CanisterHttpOutOfCycles {
                callback_id: CallbackId::new(cb_id),
                shares: vec![share.clone()],
                min_cost,
                unspent_allowance,
            },
        )
    };

    // An allowance that comfortably covers the cost: nothing has run out.
    assert_matches!(
        validate(consensus_cost, consensus_cost, Cycles::zero()),
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::NotOutOfCycles { .. },
            ),
        ))
    );
    // With a zero allowance the error holds, so validation gets as far as the figures.
    assert_matches!(
        validate(Cycles::zero(), consensus_cost + Cycles::new(1), Cycles::zero()),
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::OutOfCyclesFigureMismatch { field, .. },
            ),
        )) if field == "min_cost"
    );
    // And the honest figures validate.
    assert_matches!(
        validate(Cycles::zero(), consensus_cost, Cycles::zero()),
        Ok(())
    );
}

/// Legacy-priced and free-subnet outcalls refund nothing from an allowance, so they
/// can never run out of one: an out-of-cycles error for them is invalid, however
/// little of their (zero) allowance is left.
#[test]
fn validate_payload_fails_for_a_non_flexible_out_of_cycles_without_a_refundable_allowance() {
    let num_nodes = 4;
    let cb_id = 0;
    let designated = node_test_id(0);
    let (_, metadata) = test_response_and_metadata(cb_id);
    let share = metadata_to_share(node_id_to_u64(designated), &metadata);

    for (pricing_version, cost_schedule) in [
        (PricingVersion::Legacy, CanisterCyclesCostSchedule::Normal),
        (PricingVersion::PayAsYouGo, CanisterCyclesCostSchedule::Free),
    ] {
        let mut context = with_payg_allowance(
            request_context(Replication::NonReplicated(designated)),
            Cycles::zero(),
        );
        context.pricing_version = pricing_version.clone();
        context.cost_schedule = cost_schedule;

        assert_matches!(
            validate_out_of_cycles_payload(
                num_nodes,
                CallbackId::new(cb_id),
                context,
                CanisterHttpOutOfCycles {
                    callback_id: CallbackId::new(cb_id),
                    shares: vec![share.clone()],
                    // Rejected before the figures are compared, so these do not matter.
                    min_cost: Cycles::zero(),
                    unspent_allowance: Cycles::zero(),
                },
            ),
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::NotOutOfCycles {
                        unspent_allowance,
                        ..
                    },
                ),
            // There is no per-replica allowance here at all, rather than an exhausted one.
            )) if unspent_allowance.is_none(),
            "expected no refundable allowance for {pricing_version:?} pricing on a \
             {cost_schedule:?} cost schedule"
        );
    }
}

/// A flexible outcall reports running out of cycles through its own error type, so it
/// has no business in the non-flexible out-of-cycles section.
#[test]
fn validate_payload_fails_for_a_non_flexible_out_of_cycles_of_a_flexible_request() {
    let num_nodes = 4;
    let cb_id = 0;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let (_, metadata) = test_response_and_metadata(cb_id);

    assert_matches!(
        validate_out_of_cycles_payload(
            num_nodes,
            CallbackId::new(cb_id),
            flexible_request_context_with_allowance(committee, 1, num_nodes as u32, Cycles::zero()),
            CanisterHttpOutOfCycles {
                callback_id: CallbackId::new(cb_id),
                shares: vec![metadata_to_share(0, &metadata)],
                min_cost: Cycles::zero(),
                unspent_allowance: Cycles::zero(),
            },
        ),
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::InvalidPayloadSection(callback_id),
            ),
        )) if callback_id == CallbackId::new(cb_id)
    );
}

/// The shares proving an out-of-cycles error are what the reported figures are
/// recomputed from, so a proposer must not be able to pad them: a second share from
/// the same signer would double-count that replica's spend, and one from outside the
/// committee would count an allowance the request never granted.
#[test]
fn validate_payload_fails_for_a_non_flexible_out_of_cycles_with_padded_shares() {
    let num_nodes = 4;
    let cb_id = 0;
    let designated = node_test_id(0);
    let (_, metadata) = test_response_and_metadata(cb_id);
    // Two shares that together claim the whole allowance, which one replica alone
    // could never have spent.
    let half_allowance = TEST_PER_REPLICA_ALLOWANCE / 2_u64;
    let spent_half = |node| metadata_to_share_with_spent(node, &metadata, half_allowance);

    let validate = |shares| {
        validate_out_of_cycles_payload(
            num_nodes,
            CallbackId::new(cb_id),
            with_payg_allowance(
                request_context(Replication::NonReplicated(designated)),
                TEST_PER_REPLICA_ALLOWANCE,
            ),
            CanisterHttpOutOfCycles {
                callback_id: CallbackId::new(cb_id),
                shares,
                min_cost: Cycles::zero(),
                unspent_allowance: Cycles::zero(),
            },
        )
    };

    // The designated replica's share, twice over.
    assert_matches!(
        validate(vec![
            spent_half(node_id_to_u64(designated)),
            spent_half(node_id_to_u64(designated)),
        ]),
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::DuplicateShareSigner { signer, .. },
            ),
        )) if signer == designated
    );
    // A second replica's share, which a non-replicated request never assigned.
    assert_matches!(
        validate(vec![spent_half(node_id_to_u64(designated)), spent_half(1)]),
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::ShareSignerNotInCommittee { signer, .. },
            ),
        )) if signer == node_test_id(1)
    );
}

/// A non-replicated response is only delivered once the designated replica's own
/// allowance covers the consensus cost. No other replica contributes an allowance to
/// a non-replicated outcall, so falling short of it can never be made good and the
/// outcall is reported as out of cycles right away.
#[test]
fn non_replicated_response_needs_the_designated_replicas_allowance() {
    let num_nodes = 4;
    let cb_id = 0;
    let designated = node_test_id(0);
    let (response, metadata) = test_response_and_metadata(cb_id);
    let consensus_cost = non_flexible_consensus_cost(num_nodes, metadata.content_size);

    // Once the single allowance covers the consensus cost, the response is delivered;
    // one cycle short of it, it never can be — no other replica contributes an
    // allowance to a non-replicated request — so the outcall is reported as out of
    // cycles instead of being left to time out.
    for (allowance, expected_responses, expected_out_of_cycles) in [
        (consensus_cost, 1, 0),
        (consensus_cost - Cycles::new(1), 0, 1),
        (Cycles::zero(), 0, 1),
    ] {
        setup_test_with_contexts(
            num_nodes,
            vec![(
                CallbackId::new(cb_id),
                with_payg_allowance(
                    request_context(Replication::NonReplicated(designated)),
                    allowance,
                ),
            )],
            |payload_builder, canister_http_pool| {
                let share = metadata_to_share(node_id_to_u64(designated), &metadata);
                {
                    let mut pool_access = canister_http_pool.write().unwrap();
                    add_own_share_to_pool(pool_access.deref_mut(), &share, &response);
                }
                let payload = build_and_validate_and_parse_payload(&payload_builder);
                assert_eq!(
                    (payload.responses.len(), payload.out_of_cycles.len()),
                    (expected_responses, expected_out_of_cycles),
                    "unexpected payload for allowance {allowance}"
                );
            },
        );
    }
}

/// A flexible response group whose delivering replica cannot cover the group's
/// consensus cost on its own is topped up with extra shares from the committee
/// members whose responses are not delivered. Those replicas contribute their
/// allowance and are reported as contributors of the collective spend.
#[test]
fn flexible_response_group_is_topped_up_with_extra_shares() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);
    // `max_responses` of 1 means exactly one response is delivered, leaving the
    // other three committee members' shares as extra-share candidates.
    let (min, max) = (1, 1);

    // Candid-encoded, so that the delivered response can be turned into a
    // consensus response (and hence a spend report) further down.
    let content = Encode!(&CanisterHttpResponsePayload {
        status: 200,
        headers: vec![],
        body: vec![],
    })
    .unwrap();
    let (_, metadata) = test_response_and_metadata_with_content(
        callback_id.get(),
        CanisterHttpResponseContent::Success(content.clone()),
    );
    let group_spend = flexible_initial_spent(
        std::iter::once(&metadata_to_share(0, &metadata)),
        std::iter::empty(),
        NumberOfNodes::from(num_nodes as u32),
        min,
    );
    // An allowance that the delivering replica and two extra shares together
    // just cover, while fewer replicas do not.
    let allowance = Cycles::new(group_spend.get() / 3 + 1);
    assert!(allowance * 2_usize < group_spend);
    assert!(group_spend <= allowance * 3_usize);

    setup_test_with_contexts(
        num_nodes,
        vec![(
            callback_id,
            flexible_request_context_with_allowance(committee, min, max, allowance),
        )],
        |payload_builder, pool| {
            add_flexible_ok_shares(&pool, callback_id, 0..num_nodes as u64, &content);

            let payload = build_and_validate_and_parse_payload(&payload_builder);
            assert_eq!(payload.flexible_responses.len(), 1);
            let group = &payload.flexible_responses[0];
            assert_eq!(group.responses.len(), 1);
            assert_eq!(group.extra_shares.len(), 2);
            assert_eq!(group.initial_spent, group_spend);

            // Each contributing replica is counted exactly once.
            let signers: BTreeSet<_> = group
                .responses
                .iter()
                .map(|r| r.proof.signature.signer)
                .chain(group.extra_shares.iter().map(|s| s.signature.signer))
                .collect();
            assert_eq!(signers.len(), 3);

            // The spend report covers all three of them, so the caller is
            // refunded their three allowances minus the collective spend.
            let (_, spent, _) = CanisterHttpPayloadBuilderImpl::into_messages(
                &payload_to_bytes_max_4mb(payload.clone()),
            );
            assert_eq!(spent.initial.len(), 1);
            assert_eq!(spent.initial[0].callback, callback_id);
            assert_eq!(spent.initial[0].amount, group_spend);
            assert_eq!(spent.initial[0].nodes, signers);
        },
    );
}

/// The `initial_spent` of a group delivering the first `delivered` of the shares
/// for `metadata`, as payload validation recomputes it.
fn flexible_group_spend(
    num_nodes: usize,
    min_responses: u32,
    metadata: &CanisterHttpResponseMetadata,
    delivered: usize,
) -> Cycles {
    let shares: Vec<_> = (0..delivered as u64)
        .map(|node| metadata_to_share(node, metadata))
        .collect();
    flexible_initial_spent(
        shares.iter(),
        std::iter::empty(),
        NumberOfNodes::from(num_nodes as u32),
        min_responses,
    )
}

#[test]
fn flexible_response_group_delivers_only_as_many_responses_as_are_covered() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);
    let (min, max) = (1, 4);

    let content = b"flexible-response".to_vec();
    let (_, metadata) = test_response_and_metadata_with_content(
        callback_id.get(),
        CanisterHttpResponseContent::Success(content.clone()),
    );
    let one_response = flexible_group_spend(num_nodes, min, &metadata, 1);
    let two_responses = flexible_group_spend(num_nodes, min, &metadata, 2);
    // The smallest allowance that the whole committee together still covers one
    // response with; two must be out of reach even then.
    let allowance = Cycles::new(one_response.get().div_ceil(num_nodes as u128));
    assert!(two_responses > allowance * num_nodes);

    setup_test_with_contexts(
        num_nodes,
        vec![(
            callback_id,
            flexible_request_context_with_allowance(committee, min, max, allowance),
        )],
        |payload_builder, pool| {
            add_flexible_ok_shares(&pool, callback_id, 0..num_nodes as u64, &content);

            let payload = build_and_validate_and_parse_payload(&payload_builder);
            assert_eq!(payload.flexible_responses.len(), 1);
            let group = &payload.flexible_responses[0];
            assert_eq!(group.responses.len(), min as usize);
            // The replicas that do not deliver a response contribute their
            // allowance as extra shares instead.
            assert_eq!(group.extra_shares.len(), num_nodes - min as usize);
            assert_eq!(group.initial_spent, one_response);
        },
    );
}

#[test]
fn flexible_response_group_grows_to_max_responses_when_covered() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);
    let (min, max) = (1, 4);

    let content = b"flexible-response".to_vec();
    let (_, metadata) = test_response_and_metadata_with_content(
        callback_id.get(),
        CanisterHttpResponseContent::Success(content.clone()),
    );

    setup_test_with_contexts(
        num_nodes,
        vec![(
            callback_id,
            flexible_request_context_with_allowance(
                committee,
                min,
                max,
                TEST_PER_REPLICA_ALLOWANCE,
            ),
        )],
        |payload_builder, pool| {
            add_flexible_ok_shares(&pool, callback_id, 0..num_nodes as u64, &content);

            let payload = build_and_validate_and_parse_payload(&payload_builder);
            assert_eq!(payload.flexible_responses.len(), 1);
            let group = &payload.flexible_responses[0];
            assert_eq!(group.responses.len(), max as usize);
            assert!(group.extra_shares.is_empty());
            assert_eq!(
                group.initial_spent,
                flexible_group_spend(num_nodes, min, &metadata, max as usize)
            );
        },
    );
}

/// How many responses a group delivers is also capped by the block space left:
/// with room for two of the four available responses, two are delivered.
#[test]
fn flexible_response_group_delivers_only_as_many_responses_as_fit() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);
    let (min, max) = (1, 4);

    // Bodies large enough that their serialized size dominates the group.
    let content = vec![0xAB_u8; 4096];
    let (response, metadata) = test_response_and_metadata_with_content(
        callback_id.get(),
        CanisterHttpResponseContent::Success(content.clone()),
    );
    let entry_size = FlexibleCanisterHttpResponseWithProof::count_bytes(
        &response,
        &metadata_to_share(0, &metadata),
    );
    // Room for two entries and half of a third, so that the third does not fit.
    let max_size = NumBytes::new(
        (FlexibleCanisterHttpResponses::base_count_bytes() + 2 * entry_size + entry_size / 2)
            as u64,
    );

    setup_test_with_contexts(
        num_nodes,
        vec![(
            callback_id,
            flexible_request_context_with_allowance(
                committee,
                min,
                max,
                TEST_PER_REPLICA_ALLOWANCE,
            ),
        )],
        |payload_builder, pool| {
            add_flexible_ok_shares(&pool, callback_id, 0..num_nodes as u64, &content);

            let payload =
                build_and_validate_and_parse_payload_with_max_size(&payload_builder, max_size);
            assert_eq!(payload.flexible_responses.len(), 1);
            let group = &payload.flexible_responses[0];
            assert_eq!(group.responses.len(), 2);
            assert!(group.extra_shares.is_empty());
            assert_eq!(
                group.initial_spent,
                flexible_group_spend(num_nodes, min, &metadata, 2)
            );
        },
    );
}

/// The extra shares funding a group take up block space too, so a group that only
/// fits once they are left out is shrunk rather than emitted oversized.
#[test]
fn flexible_response_group_counts_extra_shares_against_the_block_space() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);
    let (min, max) = (1, 4);

    let content = vec![0xAB_u8; 4096];
    let (response, metadata) = test_response_and_metadata_with_content(
        callback_id.get(),
        CanisterHttpResponseContent::Success(content.clone()),
    );
    let share = metadata_to_share(0, &metadata);
    let entry_size = FlexibleCanisterHttpResponseWithProof::count_bytes(&response, &share);
    let base = FlexibleCanisterHttpResponses::base_count_bytes();

    // An allowance so tight that a single response needs all three remaining
    // replicas as extra shares to be covered.
    let one_response = flexible_group_spend(num_nodes, min, &metadata, 1);
    let allowance = Cycles::new(one_response.get().div_ceil(num_nodes as u128));
    assert!(flexible_group_spend(num_nodes, min, &metadata, 2) > allowance * num_nodes);
    let num_extra_shares = num_nodes - 1;

    setup_test_with_contexts(
        num_nodes,
        vec![(
            callback_id,
            flexible_request_context_with_allowance(committee, min, max, allowance),
        )],
        |payload_builder, pool| {
            add_flexible_ok_shares(&pool, callback_id, 0..num_nodes as u64, &content);

            // With room for the one response the allowance affords and all of the
            // extra shares funding it, the group is delivered.
            let roomy = NumBytes::new(
                (base + entry_size + num_extra_shares * share.count_bytes() + 1) as u64,
            );
            let payload =
                build_and_validate_and_parse_payload_with_max_size(&payload_builder, roomy);
            assert_eq!(payload.flexible_responses.len(), 1, "{payload:?}");
            let group = &payload.flexible_responses[0];
            assert_eq!(group.responses.len(), 1);
            assert_eq!(group.extra_shares.len(), num_extra_shares);

            // One extra share less, and the funded group no longer fits. There is no
            // smaller group to fall back on, so nothing is delivered.
            let tight = NumBytes::new(
                (base + entry_size + (num_extra_shares - 1) * share.count_bytes() + 1) as u64,
            );
            let payload =
                build_and_validate_and_parse_payload_with_max_size(&payload_builder, tight);
            assert_eq!(payload.num_responses(), 0, "{payload:?}");
        },
    );
}

/// The smallest responses are delivered first, so that both the block space and
/// the allowance a group takes go as far as they can.
#[test]
fn flexible_response_group_delivers_the_smallest_responses_first() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);
    // Exactly one response is delivered, so it has to be the smallest one.
    let (min, max) = (1, 1);
    let smallest = vec![0xBB_u8; 100];

    setup_test_with_contexts(
        num_nodes,
        vec![(
            callback_id,
            flexible_request_context_with_allowance(
                committee,
                min,
                max,
                TEST_PER_REPLICA_ALLOWANCE,
            ),
        )],
        |payload_builder, pool| {
            add_flexible_ok_shares(&pool, callback_id, [0], &[0xAA_u8; 300]);
            add_flexible_ok_shares(&pool, callback_id, [1], &smallest);
            add_flexible_ok_shares(&pool, callback_id, [2], &[0xCC_u8; 200]);

            let payload = build_and_validate_and_parse_payload(&payload_builder);
            assert_eq!(payload.flexible_responses.len(), 1);
            let group = &payload.flexible_responses[0];
            assert_eq!(group.responses.len(), 1);
            assert_eq!(
                group.responses[0].response.content,
                CanisterHttpResponseContent::Success(smallest.clone())
            );
        },
    );
}

/// A `TooManyRejects` error carries only the rejects it takes to prove the error
/// while the allowance covers no more, even though the whole committee rejected.
#[test]
fn too_many_rejects_delivers_only_as_many_rejects_as_are_covered() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);
    // With `min_responses` of 2, `committee.len() - 2 + 1 = 3` rejects prove that
    // two OK responses are out of reach.
    let (min, max) = (2, 4);
    let min_rejects = num_nodes - min as usize + 1;

    let (_, reject_metadata) = test_response_and_metadata_with_content(
        callback_id.get(),
        CanisterHttpResponseContent::Reject(CanisterHttpReject {
            reject_code: RejectCode::SysTransient,
            message: "could not connect".to_string(),
        }),
    );
    let proving_rejects = flexible_group_spend(num_nodes, min, &reject_metadata, min_rejects);
    let all_rejects = flexible_group_spend(num_nodes, min, &reject_metadata, num_nodes);
    // The smallest allowance that the whole committee together still covers the
    // proving rejects with; all of them must be out of reach even then.
    let allowance = Cycles::new(proving_rejects.get().div_ceil(num_nodes as u128));
    assert!(all_rejects > allowance * num_nodes);

    setup_test_with_contexts(
        num_nodes,
        vec![(
            callback_id,
            flexible_request_context_with_allowance(committee, min, max, allowance),
        )],
        |payload_builder, pool| {
            add_flexible_reject_shares(&pool, callback_id, 0..num_nodes as u64);

            let payload = build_and_validate_and_parse_payload(&payload_builder);
            assert_eq!(payload.flexible_errors.len(), 1);
            let FlexibleCanisterHttpError::TooManyRejects {
                reject_responses,
                extra_shares,
                initial_spent,
                ..
            } = &payload.flexible_errors[0]
            else {
                panic!(
                    "expected TooManyRejects, got {:?}",
                    payload.flexible_errors[0]
                );
            };
            assert_eq!(reject_responses.len(), min_rejects);
            // The reject that is not delivered still contributes its allowance.
            assert_eq!(extra_shares.len(), num_nodes - min_rejects);
            assert_eq!(*initial_spent, proving_rejects);
        },
    );
}

/// With allowance to spare, a `TooManyRejects` error carries every reject the
/// committee produced, so that the caller sees all of them.
#[test]
fn too_many_rejects_grows_to_all_rejects_when_covered() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);
    let (min, max) = (2, 4);

    setup_test_with_contexts(
        num_nodes,
        vec![(
            callback_id,
            flexible_request_context_with_allowance(
                committee,
                min,
                max,
                TEST_PER_REPLICA_ALLOWANCE,
            ),
        )],
        |payload_builder, pool| {
            add_flexible_reject_shares(&pool, callback_id, 0..num_nodes as u64);

            let payload = build_and_validate_and_parse_payload(&payload_builder);
            assert_eq!(payload.flexible_errors.len(), 1);
            let FlexibleCanisterHttpError::TooManyRejects {
                reject_responses,
                extra_shares,
                ..
            } = &payload.flexible_errors[0]
            else {
                panic!(
                    "expected TooManyRejects, got {:?}",
                    payload.flexible_errors[0]
                );
            };
            assert_eq!(reject_responses.len(), num_nodes);
            assert!(extra_shares.is_empty());
        },
    );
}

/// While the shares seen so far do not cover a flexible response group's
/// consensus cost, but committee members that have yet to respond could still
/// contribute the allowance it takes, the group is held back.
#[test]
fn flexible_response_group_waits_for_shares_covering_consensus_cost() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);
    let (min, max) = (1, 1);

    let content = Encode!(&CanisterHttpResponsePayload {
        status: 200,
        headers: vec![],
        body: vec![],
    })
    .unwrap();
    let (_, metadata) = test_response_and_metadata_with_content(
        callback_id.get(),
        CanisterHttpResponseContent::Success(content.clone()),
    );
    let group_spend = flexible_initial_spent(
        std::iter::once(&metadata_to_share(0, &metadata)),
        std::iter::empty(),
        NumberOfNodes::from(num_nodes as u32),
        min,
    );
    // Three replicas' allowances are needed to cover the group's spend.
    let allowance = Cycles::new(group_spend.get() / 3 + 1);
    assert!(allowance * 2_usize < group_spend);
    assert!(group_spend <= allowance * 3_usize);

    setup_test_with_contexts(
        num_nodes,
        vec![(
            callback_id,
            flexible_request_context_with_allowance(committee, min, max, allowance),
        )],
        |payload_builder, pool| {
            // Only two replicas have responded so far, so the group cannot be
            // paid for yet.
            add_flexible_ok_shares(&pool, callback_id, 0..2, &content);
            let payload = build_and_validate_and_parse_payload(&payload_builder);
            assert_eq!(payload.num_responses(), 0);

            // A third replica's share tips the collective allowance over.
            add_flexible_ok_shares(&pool, callback_id, [2], &content);
            let payload = build_and_validate_and_parse_payload(&payload_builder);
            assert_eq!(payload.flexible_responses.len(), 1);
            let group = &payload.flexible_responses[0];
            assert_eq!(group.responses.len(), 1);
            assert_eq!(group.extra_shares.len(), 2);
            assert_eq!(group.initial_spent, group_spend);
        },
    );
}

/// Once the committee's remaining allowances can no longer cover the consensus
/// cost of any response — here because every committee member has spent its
/// whole allowance — the outcall is reported as out of cycles rather than left to
/// time out.
#[test]
fn flexible_outcall_is_out_of_cycles_when_allowances_are_exhausted() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);
    let allowance = TEST_PER_REPLICA_ALLOWANCE;

    setup_test_with_contexts(
        num_nodes,
        vec![(
            callback_id,
            flexible_request_context_with_allowance(committee, 1, 4, allowance),
        )],
        |payload_builder, pool| {
            // Every committee member reports having spent its whole allowance,
            // leaving nothing to pay for delivering a response with.
            add_flexible_shares(
                &pool,
                callback_id,
                0..num_nodes as u64,
                CanisterHttpResponseContent::Success(b"response".to_vec()),
                allowance,
            );

            let payload = build_and_validate_and_parse_payload(&payload_builder);
            assert_eq!(payload.flexible_errors.len(), 1);
            let FlexibleCanisterHttpError::OutOfCycles {
                all_seen_shares,
                min_cost,
                unspent_allowance,
                ..
            } = &payload.flexible_errors[0]
            else {
                panic!("expected OutOfCycles, got {:?}", payload.flexible_errors[0]);
            };
            // Every replica's share is included as evidence, and the figures
            // that prove the error are reported: nothing of the allowance is
            // left, against a nonzero cost of delivering a response.
            assert_eq!(all_seen_shares.len(), num_nodes);
            assert_eq!(*unspent_allowance, Cycles::zero());
            assert!(!min_cost.is_zero());
            let min_cost = *min_cost;

            let (responses, spent, stats) = CanisterHttpPayloadBuilderImpl::into_messages(
                &payload_to_bytes_max_4mb(payload.clone()),
            );
            assert_eq!(
                stats.flexible_errors,
                BTreeMap::from([("out_of_cycles", 1)])
            );
            assert_eq!(responses.len(), 1);
            let Payload::Data(ref data) = responses[0].payload else {
                panic!("Expected Payload::Data, got {:?}", responses[0].payload);
            };
            let FlexibleHttpRequestResult::Err(err) =
                Decode!(data, FlexibleHttpRequestResult).unwrap()
            else {
                panic!("Expected Err variant");
            };
            assert_eq!(
                err.global_error,
                Some(FlexibleHttpGlobalError::OutOfCycles(candid::Reserved))
            );
            assert_eq!(err.node_details.len(), num_nodes);
            // The caller is told what the committee spent and what a response would
            // have cost, so that it can tell how much more it would have had to pay.
            // (The unspent allowance is zero here, which no assertion could tell
            // apart from any other digit in the message.)
            assert!(
                err.message.contains(&format!("{}", allowance * num_nodes))
                    && err.message.contains(&format!("{min_cost}")),
                "figures missing from {}",
                err.message
            );

            // The error delivers no body, so its spend is just what the replicas
            // reported: their whole allowances, and nothing is refunded.
            assert_eq!(spent.initial.len(), 1);
            assert_eq!(spent.initial[0].amount, allowance * num_nodes);
            assert_eq!(spent.initial[0].nodes.len(), num_nodes);
        },
    );
}

/// The figures an `OutOfCycles` error reports to the caller have to be the ones it
/// is proved by, so that a proposer cannot tell the caller an arbitrary cost.
#[test]
fn validate_payload_fails_for_out_of_cycles_with_a_wrong_figure() {
    let num_nodes = 4;
    let callback_id = CallbackId::from(42);
    let (_, metadata) = test_response_and_metadata(callback_id.get());
    let share = metadata_to_share(0, &metadata);
    // With a zero allowance the error itself is justified, so validation gets as
    // far as comparing the figures: nothing of the allowance is left, against a
    // nonzero cost of delivering a response.
    let expected_min_cost = min_flexible_consensus_cost(
        std::iter::once(&share),
        NumberOfNodes::from(num_nodes as u32),
        num_nodes,
        1,
    )
    .expect("a bound exists");
    assert!(!expected_min_cost.is_zero());
    let expected_unspent = Cycles::zero();
    let out_of_cycles = |min_cost, unspent_allowance| CanisterHttpPayload {
        flexible_errors: vec![FlexibleCanisterHttpError::OutOfCycles {
            callback_id,
            all_seen_shares: vec![share.clone()],
            min_cost,
            unspent_allowance,
        }],
        ..Default::default()
    };
    let off_by_one = Cycles::new(1);

    // Either figure being off on its own has to be caught, reported as the field it
    // is, and with both the figure received and the one it should have been.
    for (field, payload, received, expected) in [
        (
            "min_cost",
            out_of_cycles(expected_min_cost + off_by_one, expected_unspent),
            expected_min_cost + off_by_one,
            expected_min_cost,
        ),
        (
            "unspent_allowance",
            out_of_cycles(expected_min_cost, expected_unspent + off_by_one),
            expected_unspent + off_by_one,
            expected_unspent,
        ),
    ] {
        assert_matches!(
            validate_flexible_payload_with_allowance(
                num_nodes,
                callback_id,
                1,
                Cycles::zero(),
                payload
            ),
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::OutOfCyclesFigureMismatch {
                        field: mismatched_field,
                        received: reported,
                        expected: recomputed,
                        ..
                    },
                ),
            )) if mismatched_field == field && reported == received && recomputed == expected,
            "expected a {field} mismatch"
        );
    }
}

/// An outcall is out of cycles only once it can pay for none of the results that
/// are still reachable, so the cheapest one decides. A committee that could not
/// afford to prove a `TooManyRejects` may well afford the single successful
/// response it is still waiting for, and must then keep waiting.
#[test]
fn flexible_outcall_is_not_out_of_cycles_while_the_cheapest_result_is_affordable() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);
    // One replica has rejected and three have yet to answer, so one successful
    // response would settle the outcall, while proving `TooManyRejects` would take
    // all four.
    let empty_ok = metadata_share_with_content_size(callback_id.get(), 1, 0);
    let ok_cost = flexible_initial_spent(
        std::iter::once(&empty_ok),
        std::iter::empty(),
        NumberOfNodes::from(num_nodes as u32),
        1,
    );
    // The smallest per-replica allowance the whole committee covers that with.
    let affordable = Cycles::new(ok_cost.get().div_ceil(num_nodes as u128));
    assert!(affordable * num_nodes >= ok_cost);
    assert!((affordable - Cycles::new(1)) * num_nodes < ok_cost);

    for (allowance, out_of_cycles) in [(affordable, false), (affordable - Cycles::new(1), true)] {
        setup_test_with_contexts(
            num_nodes,
            vec![(
                callback_id,
                flexible_request_context_with_allowance(
                    committee.clone(),
                    1,
                    num_nodes as u32,
                    allowance,
                ),
            )],
            |payload_builder, pool| {
                add_flexible_reject_shares(&pool, callback_id, [0]);
                let payload = build_and_validate_and_parse_payload(&payload_builder);
                if out_of_cycles {
                    assert_matches!(
                        payload.flexible_errors.as_slice(),
                        [FlexibleCanisterHttpError::OutOfCycles { .. }],
                        "expected out of cycles for allowance {allowance}"
                    );
                } else {
                    assert!(
                        payload.is_empty(),
                        "expected to keep waiting for allowance {allowance}"
                    );
                }
            },
        );
    }
}

/// The validator rejects an `OutOfCycles` error while the committee's remaining
/// allowances could still cover the cost of delivering a response.
#[test]
fn validate_payload_fails_for_out_of_cycles_that_can_still_be_paid_for() {
    let num_nodes = 4;
    let callback_id = CallbackId::from(42);
    let (_, metadata) = test_response_and_metadata(callback_id.get());
    let payload = CanisterHttpPayload {
        flexible_errors: vec![FlexibleCanisterHttpError::OutOfCycles {
            callback_id,
            // A single replica that spent nothing; the rest of the committee is
            // credited a full allowance each.
            all_seen_shares: vec![metadata_to_share(0, &metadata)],
            // Rejected before the figures are compared, so these do not matter.
            min_cost: Cycles::zero(),
            unspent_allowance: Cycles::zero(),
        }],
        ..Default::default()
    };

    assert_matches!(
        validate_flexible_payload_with_allowance(
            num_nodes,
            callback_id,
            1,
            TEST_PER_REPLICA_ALLOWANCE,
            payload,
        ),
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::NotOutOfCycles {
                    unspent_allowance,
                    min_cost,
                    ..
                },
            ),
        )) if unspent_allowance == Some(TEST_PER_REPLICA_ALLOWANCE * num_nodes)
            && min_cost.is_some_and(|min_cost| min_cost <= TEST_PER_REPLICA_ALLOWANCE * num_nodes)
    );
}

/// Legacy-priced and free-subnet outcalls refund nothing from an allowance, so
/// they can never run out of one: an `OutOfCycles` error for them is invalid.
#[test]
fn validate_payload_fails_for_out_of_cycles_without_a_refundable_allowance() {
    let num_nodes = 4;
    let callback_id = CallbackId::from(42);
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let (_, metadata) = test_response_and_metadata(callback_id.get());

    // A zero allowance would be exhausted under pay-as-you-go pricing on a charging
    // subnet. Legacy pricing refunds the unspent payment instead, and free subnets
    // refund nothing at all, so neither has an allowance to run out of.
    for (pricing_version, cost_schedule) in [
        (PricingVersion::Legacy, CanisterCyclesCostSchedule::Normal),
        (PricingVersion::PayAsYouGo, CanisterCyclesCostSchedule::Free),
    ] {
        let payload = CanisterHttpPayload {
            flexible_errors: vec![FlexibleCanisterHttpError::OutOfCycles {
                callback_id,
                all_seen_shares: vec![metadata_to_share(0, &metadata)],
                min_cost: Cycles::zero(),
                unspent_allowance: Cycles::zero(),
            }],
            ..Default::default()
        };
        let mut context = flexible_request_context_with_allowance(
            committee.clone(),
            1,
            num_nodes as u32,
            Cycles::zero(),
        );
        context.pricing_version = pricing_version.clone();
        context.cost_schedule = cost_schedule;

        let mut result = None;
        setup_test_with_contexts(
            num_nodes,
            vec![(callback_id, context)],
            |payload_builder, _pool| {
                result = Some(payload_builder.validate_payload(
                    Height::new(1),
                    &test_proposal_context(&default_validation_context()),
                    &payload_to_bytes_max_4mb(payload),
                    &[],
                ));
            },
        );
        assert_matches!(
            result.expect("validation did not run"),
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::NotOutOfCycles {
                        unspent_allowance,
                        ..
                    },
                ),
            // There is no per-replica allowance here at all, rather than an exhausted one.
            )) if unspent_allowance.is_none(),
            "expected no refundable allowance for {pricing_version:?} pricing on a \
             {cost_schedule:?} cost schedule"
        );
    }
}

#[test]
fn validate_payload_fails_for_out_of_cycles_with_an_oversized_share() {
    let num_nodes = 4;
    let callback_id = CallbackId::from(42);
    let min_responses = 2;
    // One byte more than the largest response the replica could have returned.
    let oversized = (MAX_CANISTER_HTTP_RESPONSE_BYTES + CANDID_OVERHEAD_RESERVE_BYTES) as u32 + 1;
    // Two of the four have rejected, which is one short of the three that would
    // prove a `TooManyRejects`, so that cheaper result is out of reach and the two
    // remaining OK responses are the group whose cost decides. Both of them have to
    // be delivered, so the inflated size lands in the bound in full.
    let shares = |first_ok_size| {
        vec![
            metadata_share_with_content_size(callback_id.get(), 0, first_ok_size),
            metadata_share_with_content_size(callback_id.get(), 1, 1_000),
            reject_metadata_share(callback_id.get(), 2),
            reject_metadata_share(callback_id.get(), 3),
        ]
    };
    let bound = |shares: &[CanisterHttpResponseShare]| {
        min_flexible_consensus_cost(
            shares.iter(),
            NumberOfNodes::from(num_nodes as u32),
            num_nodes,
            min_responses,
        )
        .expect("a bound exists")
    };
    let min_cost = bound(&shares(oversized));
    // An allowance that the inflated size puts a response out of reach of, while an
    // honestly sized one stays comfortably affordable: without the size limit this
    // error would validate.
    let allowance = Cycles::new((min_cost.get() - 1) / num_nodes as u128);
    assert!(allowance * num_nodes < min_cost);
    assert!(bound(&shares(1_000)) < allowance * num_nodes);

    let payload = CanisterHttpPayload {
        flexible_errors: vec![FlexibleCanisterHttpError::OutOfCycles {
            callback_id,
            all_seen_shares: shares(oversized),
            min_cost,
            unspent_allowance: allowance * num_nodes,
        }],
        ..Default::default()
    };

    assert_matches!(
        validate_flexible_payload_with_allowance(
            num_nodes,
            callback_id,
            min_responses,
            allowance,
            payload,
        ),
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::ContentSizeExceedsLimit {
                    content_size,
                    limit,
                    ..
                },
            ),
        )) if content_size == oversized && limit == oversized as u64 - 1
    );
}

/// An `OutOfCycles` error may only rest on shares from distinct committee
/// members, since it credits every replica it does not mention a full allowance.
#[test]
fn validate_payload_fails_for_out_of_cycles_with_a_duplicate_share() {
    let num_nodes = 4;
    let callback_id = CallbackId::from(42);
    let (_, metadata) = test_response_and_metadata(callback_id.get());
    let payload = CanisterHttpPayload {
        flexible_errors: vec![FlexibleCanisterHttpError::OutOfCycles {
            callback_id,
            all_seen_shares: vec![
                metadata_to_share(0, &metadata),
                metadata_to_share(0, &metadata),
            ],
            min_cost: Cycles::zero(),
            unspent_allowance: Cycles::zero(),
        }],
        ..Default::default()
    };

    assert_matches!(
        validate_flexible_payload_with_allowance(
            num_nodes,
            callback_id,
            1,
            Cycles::zero(),
            payload
        ),
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::DuplicateShareSigner { signer, .. },
            ),
        )) if signer == node_test_id(0)
    );
}

/// A `TooManyRejects` error delivers reject bodies, so it is topped up with
/// extra shares just like a group of successful responses.
#[test]
fn too_many_rejects_is_topped_up_with_extra_shares() {
    let num_nodes = 4;
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let callback_id = CallbackId::from(42);
    // Three of the four committee members reject, which is more than the
    // `committee.len() - min_responses` = 2 that the request tolerates. The
    // fourth member's OK share is left as an extra-share candidate.
    let (min, max) = (2, 4);
    let num_rejects = 3;

    let (_, reject_metadata) = test_response_and_metadata_with_content(
        callback_id.get(),
        CanisterHttpResponseContent::Reject(CanisterHttpReject {
            reject_code: RejectCode::SysTransient,
            message: "could not connect".to_string(),
        }),
    );
    let reject_shares: Vec<_> = (0..num_rejects as u64)
        .map(|node| metadata_to_share(node, &reject_metadata))
        .collect();
    let error_spend = flexible_initial_spent(
        reject_shares.iter(),
        std::iter::empty(),
        NumberOfNodes::from(num_nodes as u32),
        min,
    );
    // An allowance that the three rejecting replicas and one extra share
    // together just cover, while the three rejecting ones alone do not.
    let allowance = Cycles::new(error_spend.get() / 4 + 1);
    assert!(allowance * num_rejects < error_spend);

    setup_test_with_contexts(
        num_nodes,
        vec![(
            callback_id,
            flexible_request_context_with_allowance(committee, min, max, allowance),
        )],
        |payload_builder, pool| {
            add_flexible_reject_shares(&pool, callback_id, 0..num_rejects as u64);
            add_flexible_ok_shares(&pool, callback_id, [num_rejects as u64], b"ok");

            let payload = build_and_validate_and_parse_payload(&payload_builder);
            assert_eq!(payload.flexible_errors.len(), 1);
            let FlexibleCanisterHttpError::TooManyRejects {
                reject_responses,
                extra_shares,
                initial_spent,
                ..
            } = &payload.flexible_errors[0]
            else {
                panic!(
                    "expected TooManyRejects, got {:?}",
                    payload.flexible_errors[0]
                );
            };
            assert_eq!(reject_responses.len(), num_rejects);
            assert_eq!(extra_shares.len(), 1);
            assert_eq!(*initial_spent, error_spend);

            // The extra share's signer is reported as a contributor too, so the
            // caller's refund is derived from all four allowances.
            let (_, spent, _) = CanisterHttpPayloadBuilderImpl::into_messages(
                &payload_to_bytes_max_4mb(payload.clone()),
            );
            assert_eq!(spent.initial.len(), 1);
            assert_eq!(spent.initial[0].callback, callback_id);
            assert_eq!(spent.initial[0].amount, error_spend);
            let contributors: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
            assert_eq!(spent.initial[0].nodes, contributors);
        },
    );
}

#[test]
fn validate_payload_fails_for_an_oversized_non_flexible_response() {
    let num_nodes = 4;
    let cb_id = 0;
    let designated = node_test_id(0);
    let threshold = canister_http_threshold(num_nodes);
    // One byte more than the largest response the replica could have returned.
    let oversized = (MAX_CANISTER_HTTP_RESPONSE_BYTES + CANDID_OVERHEAD_RESERVE_BYTES) as usize + 1;
    let (response, metadata) = test_response_and_metadata_with_content(
        cb_id,
        CanisterHttpResponseContent::Success(vec![0; oversized]),
    );

    for (replication, signers) in [
        (Replication::NonReplicated(designated), vec![designated]),
        (
            Replication::FullyReplicated,
            (0..threshold as u64).map(node_test_id).collect(),
        ),
    ] {
        let mut proof = response_and_metadata_to_proof(&response, &metadata);
        for signer in &signers {
            add_signer_to_proof(&mut proof, *signer);
        }
        proof.initial_spent =
            non_flexible_initial_spent(&proof.proof, NumberOfNodes::from(num_nodes as u32));
        // An allowance the oversized body's consensus cost stays well within, so that
        // the size limit is the only thing standing in the way of delivering it.
        let allowance = TEST_PER_REPLICA_ALLOWANCE;
        assert!(proof.initial_spent <= allowance * signers.len());

        let mut result = None;
        setup_test_with_contexts(
            num_nodes,
            vec![(
                CallbackId::new(cb_id),
                with_payg_allowance(request_context(replication.clone()), allowance),
            )],
            |payload_builder, _pool| {
                let payload = CanisterHttpPayload {
                    responses: vec![proof.clone()],
                    ..Default::default()
                };
                result = Some(payload_builder.validate_payload(
                    Height::new(1),
                    &test_proposal_context(&default_validation_context()),
                    &payload_to_bytes_max_4mb(payload),
                    &[],
                ));
            },
        );
        assert_matches!(
            result.expect("validation did not run"),
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::ContentSizeExceedsLimit {
                        content_size,
                        limit,
                        ..
                    },
                ),
            )) if content_size as usize == oversized && limit as usize == oversized - 1,
            "expected an oversized {replication:?} response to be rejected"
        );
    }
}

/// The validator rejects a fully-replicated response whose collective initial
/// spend exceeds the signers' collective allowance.
#[test]
fn validate_payload_fails_for_initial_spent_exceeding_allowance() {
    let num_nodes = 4;
    let threshold = canister_http_threshold(num_nodes);
    let cb_id = 0;
    let (response, metadata) = test_response_and_metadata(cb_id);
    let mut proof = response_and_metadata_to_proof(&response, &metadata);
    for signer in 0..threshold as u64 {
        add_signer_to_proof(&mut proof, node_test_id(signer));
    }
    // An honestly computed spend, which a zero collective allowance still cannot
    // cover.
    proof.initial_spent =
        non_flexible_initial_spent(&proof.proof, NumberOfNodes::from(num_nodes as u32));

    setup_test_with_contexts(
        num_nodes,
        vec![(
            CallbackId::new(cb_id),
            with_payg_allowance(
                request_context(Replication::FullyReplicated),
                Cycles::zero(),
            ),
        )],
        |payload_builder, _pool| {
            let payload = CanisterHttpPayload {
                responses: vec![proof.clone()],
                ..Default::default()
            };
            let result = payload_builder.validate_payload(
                Height::new(1),
                &test_proposal_context(&default_validation_context()),
                &payload_to_bytes_max_4mb(payload),
                &[],
            );
            assert_matches!(
                result,
                Err(ValidationError::InvalidArtifact(
                    InvalidPayloadReason::InvalidCanisterHttpPayload(
                        InvalidCanisterHttpPayloadReason::InitialSpentExceedsLimit {
                            callback_id,
                            initial_spent,
                            per_replica_allowance,
                            num_replicas,
                        },
                    ),
                )) if callback_id == CallbackId::new(cb_id)
                    && initial_spent == proof.initial_spent
                    && per_replica_allowance == Cycles::zero()
                    && num_replicas == threshold
            );
        },
    );
}

#[test]
fn validate_payload_accepts_initial_spent_within_the_collective_allowance() {
    let num_nodes = 4;
    let threshold = canister_http_threshold(num_nodes);
    let cb_id = 0;
    let (response, metadata) = test_response_and_metadata(cb_id);
    let mut proof = response_and_metadata_to_proof(&response, &metadata);
    for signer in 0..threshold as u64 {
        add_signer_to_proof(&mut proof, node_test_id(signer));
    }
    proof.initial_spent =
        non_flexible_initial_spent(&proof.proof, NumberOfNodes::from(num_nodes as u32));

    // The smallest per-replica allowance whose `threshold` many copies cover the
    // spend...
    let allowance = Cycles::new(proof.initial_spent.get().div_ceil(threshold as u128));
    assert!(allowance * threshold >= proof.initial_spent);
    // ...one cycle less per replica no longer does.
    assert!((allowance - Cycles::new(1)) * threshold < proof.initial_spent);

    let validate = |per_replica_allowance| {
        let mut result = None;
        setup_test_with_contexts(
            num_nodes,
            vec![(
                CallbackId::new(cb_id),
                with_payg_allowance(
                    request_context(Replication::FullyReplicated),
                    per_replica_allowance,
                ),
            )],
            |payload_builder, _pool| {
                let payload = CanisterHttpPayload {
                    responses: vec![proof.clone()],
                    ..Default::default()
                };
                result = Some(payload_builder.validate_payload(
                    Height::new(1),
                    &test_proposal_context(&default_validation_context()),
                    &payload_to_bytes_max_4mb(payload),
                    &[],
                ));
            },
        );
        result.expect("validation did not run")
    };

    assert_matches!(validate(allowance), Ok(()));
    assert_matches!(
        validate(allowance - Cycles::new(1)),
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::InitialSpentExceedsLimit { .. },
            ),
        ))
    );
}

/// The allowance a fully-replicated request receives leaves its response
/// deliverable by the fewest replicas that can produce the response.
#[test]
fn validate_payload_accepts_a_threshold_signed_response_at_the_quoted_price() {
    let num_nodes = 13;
    let threshold = canister_http_threshold(num_nodes);
    let cb_id = 0;
    let subnet_size = NumberOfNodes::from(num_nodes as u32);

    // The per-replica allowance `ExecutionEnvironment` withholds from a request that
    // attached the recommended amount of cycles.
    let allowance = max_usage_fee(&Replication::FullyReplicated, None, subnet_size) / num_nodes;

    // The largest response an outcall without a response limit may deliver, which is
    // the one whose consensus fee the allowances have to stretch to.
    let content_size = max_http_outcall_response_size(None);
    let (response, metadata) = test_response_and_metadata_with_content(
        cb_id,
        CanisterHttpResponseContent::Success(vec![0; content_size as usize]),
    );
    let mut proof = response_and_metadata_to_proof(&response, &metadata);
    for signer in 0..threshold as u64 {
        add_signer_to_proof(&mut proof, node_test_id(signer));
    }
    proof.initial_spent = non_flexible_initial_spent(&proof.proof, subnet_size);
    assert_eq!(
        proof.initial_spent,
        consensus_fee(content_size as u128, subnet_size),
        "the signers claim no spend, so the whole initial spend is the consensus fee"
    );

    setup_test_with_contexts(
        num_nodes,
        vec![(
            CallbackId::new(cb_id),
            with_payg_allowance(request_context(Replication::FullyReplicated), allowance),
        )],
        |payload_builder, _pool| {
            let payload = CanisterHttpPayload {
                responses: vec![proof.clone()],
                ..Default::default()
            };
            assert_matches!(
                payload_builder.validate_payload(
                    Height::new(1),
                    &test_proposal_context(&default_validation_context()),
                    &payload_to_bytes_max_4mb(payload),
                    &[],
                ),
                Ok(())
            );
        },
    );
}

/// Validates `payload` against a flexible request with the given allowance and
/// returns the validation result.
fn validate_flexible_payload_with_allowance(
    num_nodes: usize,
    callback_id: CallbackId,
    min_responses: u32,
    per_replica_allowance: Cycles,
    payload: CanisterHttpPayload,
) -> Result<(), PayloadValidationError> {
    let committee: BTreeSet<_> = (0..num_nodes as u64).map(node_test_id).collect();
    let mut result = None;
    setup_test_with_contexts(
        num_nodes,
        vec![(
            callback_id,
            flexible_request_context_with_allowance(
                committee,
                min_responses,
                num_nodes as u32,
                per_replica_allowance,
            ),
        )],
        |payload_builder, _pool| {
            result = Some(payload_builder.validate_payload(
                Height::new(1),
                &test_proposal_context(&default_validation_context()),
                &payload_to_bytes_max_4mb(payload),
                &[],
            ));
        },
    );
    result.expect("validation did not run")
}

/// The validator rejects a flexible response group whose collective initial
/// spend exceeds the collective allowance of its contributors.
#[test]
fn validate_payload_fails_for_flexible_initial_spent_exceeding_allowance() {
    let num_nodes = 4;
    let callback_id = CallbackId::from(42);
    let group = flexible_group(
        callback_id,
        num_nodes as u32,
        1,
        vec![flexible_response(callback_id.get(), 0, b"a")],
    );
    let initial_spent = group.initial_spent;

    let result = validate_flexible_payload_with_allowance(
        num_nodes,
        callback_id,
        1,
        Cycles::zero(),
        flexible_payload(vec![group]),
    );
    assert_matches!(
        result,
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::InitialSpentExceedsLimit {
                    per_replica_allowance,
                    ..
                },
            ),
        )) if per_replica_allowance == Cycles::zero()
    );
    // With an allowance covering it, the very same group is accepted.
    let group = flexible_group(
        callback_id,
        num_nodes as u32,
        1,
        vec![flexible_response(callback_id.get(), 0, b"a")],
    );
    assert_matches!(
        validate_flexible_payload_with_allowance(
            num_nodes,
            callback_id,
            1,
            initial_spent,
            flexible_payload(vec![group]),
        ),
        Ok(())
    );
}

/// An extra share funding a flexible response group carries no response body, so
/// nothing but the size limit stops it from claiming an arbitrarily large
/// `content_size`.
#[test]
fn validate_payload_fails_for_a_flexible_group_with_an_oversized_share() {
    let num_nodes = 4;
    let callback_id = CallbackId::from(42);
    // One byte more than the largest response the replica could have returned.
    let oversized = (MAX_CANISTER_HTTP_RESPONSE_BYTES + CANDID_OVERHEAD_RESERVE_BYTES) as u32 + 1;
    let group = flexible_group_with_extra_shares(
        callback_id,
        num_nodes as u32,
        1,
        vec![flexible_response(callback_id.get(), 0, b"data")],
        vec![metadata_share_with_content_size(
            callback_id.get(),
            1,
            oversized,
        )],
    );

    assert_matches!(
        validate_flexible_payload_with_allowance(
            num_nodes,
            callback_id,
            1,
            TEST_PER_REPLICA_ALLOWANCE,
            flexible_payload(vec![group]),
        ),
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::ContentSizeExceedsLimit {
                    content_size,
                    limit,
                    ..
                },
            ),
        )) if content_size == oversized && limit == oversized as u64 - 1
    );
}

/// The validator rejects a `TooManyRejects` error whose collective initial spend
/// exceeds the collective allowance of its contributors.
#[test]
fn validate_payload_fails_for_too_many_rejects_initial_spent_exceeding_allowance() {
    let num_nodes = 4;
    let callback_id = CallbackId::from(42);
    let reject_responses = (0..3)
        .map(|node| flexible_reject_response(callback_id.get(), node))
        .collect();
    let payload = CanisterHttpPayload {
        flexible_errors: vec![too_many_rejects(
            callback_id,
            num_nodes as u32,
            2,
            reject_responses,
        )],
        ..Default::default()
    };

    assert_matches!(
        validate_flexible_payload_with_allowance(
            num_nodes,
            callback_id,
            2,
            Cycles::zero(),
            payload
        ),
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::InitialSpentExceedsLimit {
                    per_replica_allowance,
                    ..
                },
            ),
        )) if per_replica_allowance == Cycles::zero()
    );
}

/// The extra shares' claimed spends are part of the collective initial spend, so
/// a group that leaves them out is rejected.
#[test]
fn validate_payload_fails_for_initial_spent_ignoring_extra_shares() {
    let num_nodes = 4;
    let callback_id = CallbackId::from(42);
    let extra_spent = Cycles::new(7);
    let (_, metadata) = test_response_and_metadata(callback_id.get());
    let extra_share = metadata_to_share_with_spent(1, &metadata, extra_spent);

    // The `initial_spent` is computed without the extra share's spend...
    let mut group = flexible_group(
        callback_id,
        num_nodes as u32,
        1,
        vec![flexible_response(callback_id.get(), 0, b"a")],
    );
    let claimed = group.initial_spent;
    // ...while the group does carry it.
    group.extra_shares = vec![extra_share];

    assert_matches!(
        validate_flexible_payload_with_allowance(
            num_nodes,
            callback_id,
            1,
            TEST_PER_REPLICA_ALLOWANCE,
            flexible_payload(vec![group]),
        ),
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::InitialSpentMismatch {
                    received,
                    expected,
                    ..
                },
            ),
        )) if received == claimed && expected == claimed + extra_spent
    );
}

/// A replica may only contribute its allowance once, so an extra share signed by
/// a replica that already delivers a response is rejected.
#[test]
fn validate_payload_fails_for_extra_share_of_a_responding_signer() {
    let num_nodes = 4;
    let callback_id = CallbackId::from(42);
    let (_, metadata) = test_response_and_metadata(callback_id.get());
    let group = flexible_group_with_extra_shares(
        callback_id,
        num_nodes as u32,
        1,
        vec![flexible_response(callback_id.get(), 0, b"a")],
        vec![metadata_to_share(0, &metadata)],
    );

    assert_matches!(
        validate_flexible_payload_with_allowance(
            num_nodes,
            callback_id,
            1,
            TEST_PER_REPLICA_ALLOWANCE,
            flexible_payload(vec![group]),
        ),
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::DuplicateShareSigner { signer, .. },
            ),
        )) if signer == node_test_id(0)
    );
}

/// Only committee members were granted an allowance, so an extra share signed by
/// a non-member is rejected.
#[test]
fn validate_payload_fails_for_extra_share_outside_the_committee() {
    let num_nodes = 4;
    let callback_id = CallbackId::from(42);
    let outsider = node_test_id(num_nodes as u64);
    let (_, metadata) = test_response_and_metadata(callback_id.get());
    let group = flexible_group_with_extra_shares(
        callback_id,
        num_nodes as u32,
        1,
        vec![flexible_response(callback_id.get(), 0, b"a")],
        vec![metadata_to_share(node_id_to_u64(outsider), &metadata)],
    );

    assert_matches!(
        validate_flexible_payload_with_allowance(
            num_nodes,
            callback_id,
            1,
            TEST_PER_REPLICA_ALLOWANCE,
            flexible_payload(vec![group]),
        ),
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::ShareSignerNotInCommittee { signer, .. },
            ),
        )) if signer == outsider
    );
}

/// As for a group of OK responses, the extra shares' claimed spends are part of a
/// `TooManyRejects` error's collective initial spend, so one that leaves them out
/// is rejected.
#[test]
fn validate_payload_fails_for_too_many_rejects_initial_spent_ignoring_extra_shares() {
    let num_nodes = 4;
    let min_responses = 2;
    let callback_id = CallbackId::from(42);
    let extra_spent = Cycles::new(7);
    let (_, metadata) = test_response_and_metadata(callback_id.get());
    // The one committee member that does not reject contributes its allowance.
    let extra_share = metadata_to_share_with_spent(3, &metadata, extra_spent);
    let reject_responses = (0..3)
        .map(|node| flexible_reject_response(callback_id.get(), node))
        .collect();

    // The `initial_spent` is computed without the extra share's spend...
    let mut error = too_many_rejects(
        callback_id,
        num_nodes as u32,
        min_responses,
        reject_responses,
    );
    let FlexibleCanisterHttpError::TooManyRejects {
        extra_shares,
        initial_spent,
        ..
    } = &mut error
    else {
        panic!("expected TooManyRejects");
    };
    let claimed = *initial_spent;
    // ...while the error does carry it.
    *extra_shares = vec![extra_share];

    assert_matches!(
        validate_flexible_payload_with_allowance(
            num_nodes,
            callback_id,
            min_responses,
            TEST_PER_REPLICA_ALLOWANCE,
            CanisterHttpPayload {
                flexible_errors: vec![error],
                ..Default::default()
            },
        ),
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::InitialSpentMismatch {
                    received,
                    expected,
                    ..
                },
            ),
        )) if received == claimed && expected == claimed + extra_spent
    );
}

/// A replica may only contribute its allowance once, so an extra share signed by a
/// replica that already delivers one of the rejects is rejected.
#[test]
fn validate_payload_fails_for_too_many_rejects_extra_share_of_a_rejecting_signer() {
    let num_nodes = 4;
    let min_responses = 2;
    let callback_id = CallbackId::from(42);
    let (_, metadata) = test_response_and_metadata(callback_id.get());
    let error = too_many_rejects_with_extra_shares(
        callback_id,
        num_nodes as u32,
        min_responses,
        (0..3)
            .map(|node| flexible_reject_response(callback_id.get(), node))
            .collect(),
        vec![metadata_to_share(0, &metadata)],
    );

    assert_matches!(
        validate_flexible_payload_with_allowance(
            num_nodes,
            callback_id,
            min_responses,
            TEST_PER_REPLICA_ALLOWANCE,
            CanisterHttpPayload {
                flexible_errors: vec![error],
                ..Default::default()
            },
        ),
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::DuplicateShareSigner { signer, .. },
            ),
        )) if signer == node_test_id(0)
    );
}

fn setup_test_with_contexts(
    num_nodes: usize,
    contexts: Vec<(CallbackId, CanisterHttpRequestContext)>,
    run: impl FnOnce(CanisterHttpPayloadBuilderImpl, Arc<RwLock<CanisterHttpPoolImpl>>),
) {
    // The context's subnet size must match the subnet the test registers, since
    // payload building and validation source the subnet size from the context.
    let contexts: Vec<_> = contexts
        .into_iter()
        .map(|(cb, mut ctx)| {
            ctx.subnet_size = NumberOfNodes::from(num_nodes as u32);
            (cb, ctx)
        })
        .collect();
    test_config_with_http_feature(true, num_nodes, |mut payload_builder, pool| {
        inject_request_contexts(&mut payload_builder, contexts);
        run(payload_builder, pool);
    });
}

/// Like [`setup_test_with_contexts`], but the contexts are injected as already
/// responded to, i.e. as delivered contexts awaiting their asynchronous receipts.
fn setup_test_with_delivered_contexts(
    num_nodes: usize,
    delivered: Vec<(CallbackId, CanisterHttpRequestContext)>,
    run: impl FnOnce(CanisterHttpPayloadBuilderImpl, Arc<RwLock<CanisterHttpPoolImpl>>),
) {
    // The context's subnet size must match the subnet the test registers, since
    // payload building and validation source the subnet size from the context.
    let delivered: Vec<_> = delivered
        .into_iter()
        .map(|(cb, mut ctx)| {
            ctx.subnet_size = NumberOfNodes::from(num_nodes as u32);
            (cb, ctx)
        })
        .collect();
    test_config_with_http_feature(true, num_nodes, |mut payload_builder, pool| {
        inject_contexts(&mut payload_builder, [], delivered, None);
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
    inject_request_contexts_with_cost_schedule(payload_builder, contexts, None);
}

/// Like [`inject_request_contexts`], but also overrides the cost schedule pinned
/// in each injected request context. When `cost_schedule` is `Some`, every
/// context's `cost_schedule` is set to that value (the single source of truth
/// used during validation); when `None`, the contexts are left unchanged.
pub(crate) fn inject_request_contexts_with_cost_schedule(
    payload_builder: &mut CanisterHttpPayloadBuilderImpl,
    contexts: impl IntoIterator<Item = (CallbackId, CanisterHttpRequestContext)>,
    cost_schedule: Option<CanisterCyclesCostSchedule>,
) {
    inject_contexts(payload_builder, contexts, [], cost_schedule);
}

/// Replaces the payload_builder's state_reader with one containing the given
/// request contexts, split into the ones still awaiting a response and the
/// `delivered` ones, which have already been responded to and are only kept
/// around for their asynchronous receipts.
pub(crate) fn inject_contexts(
    payload_builder: &mut CanisterHttpPayloadBuilderImpl,
    contexts: impl IntoIterator<Item = (CallbackId, CanisterHttpRequestContext)>,
    delivered: impl IntoIterator<Item = (CallbackId, CanisterHttpRequestContext)>,
    cost_schedule: Option<CanisterCyclesCostSchedule>,
) {
    let mut init_state = ic_test_utilities_state::get_initial_state(0, 0);
    let with_cost_schedule = |mut ctx: CanisterHttpRequestContext| {
        if let Some(cost_schedule) = cost_schedule {
            ctx.cost_schedule = cost_schedule;
        }
        ctx
    };
    for (cb, ctx) in contexts {
        init_state
            .metadata
            .subnet_call_context_manager
            .canister_http_request_contexts
            .insert(cb, with_cost_schedule(ctx));
    }
    for (cb, ctx) in delivered {
        init_state
            .metadata
            .subnet_call_context_manager
            .delivered_canister_http_request_contexts
            .insert(cb, with_cost_schedule(ctx));
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
        pricing_version: PricingVersion::Legacy,
        refund_status: RefundStatus::default(),
        registry_version: RegistryVersion::from(1),
        subnet_size: NumberOfNodes::from(13),
        cost_schedule: CanisterCyclesCostSchedule::Normal,
    }
}

/// A per-replica allowance for pay-as-you-go contexts in tests, generous enough
/// that the collective allowance of the contributing replicas always covers the
/// consensus cost. Tests that exercise that limit pin their own allowance.
const TEST_PER_REPLICA_ALLOWANCE: Cycles = Cycles::new(1_000_000_000_000_000);

fn flexible_request_context(
    committee: BTreeSet<NodeId>,
    min_responses: u32,
    max_responses: u32,
) -> CanisterHttpRequestContext {
    flexible_request_context_with_allowance(
        committee,
        min_responses,
        max_responses,
        TEST_PER_REPLICA_ALLOWANCE,
    )
}

/// A flexible request context whose per-replica allowance is zero, so that any
/// nonzero claimed spend exceeds it (see [`share_with_excess_spent`]).
fn flexible_request_context_without_allowance(
    committee: BTreeSet<NodeId>,
    min_responses: u32,
    max_responses: u32,
) -> CanisterHttpRequestContext {
    flexible_request_context_with_allowance(committee, min_responses, max_responses, Cycles::zero())
}

fn flexible_request_context_with_allowance(
    committee: BTreeSet<NodeId>,
    min_responses: u32,
    max_responses: u32,
    per_replica_allowance: Cycles,
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
        pricing_version: PricingVersion::PayAsYouGo,
        refund_status: RefundStatus {
            per_replica_allowance,
            ..RefundStatus::default()
        },
        registry_version: RegistryVersion::from(1),
        subnet_size: NumberOfNodes::from(13),
        cost_schedule: CanisterCyclesCostSchedule::Normal,
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

/// Builds a flexible response group with the `initial_spent` that payload
/// validation will recompute for a subnet of `subnet_size` nodes.
fn flexible_group(
    callback_id: CallbackId,
    subnet_size: u32,
    min_responses: u32,
    responses: Vec<FlexibleCanisterHttpResponseWithProof>,
) -> FlexibleCanisterHttpResponses {
    flexible_group_with_extra_shares(callback_id, subnet_size, min_responses, responses, vec![])
}

/// Same as [`flexible_group`], but with extra shares contributing their unspent
/// allowance to the group.
fn flexible_group_with_extra_shares(
    callback_id: CallbackId,
    subnet_size: u32,
    min_responses: u32,
    responses: Vec<FlexibleCanisterHttpResponseWithProof>,
    extra_shares: Vec<CanisterHttpResponseShare>,
) -> FlexibleCanisterHttpResponses {
    let initial_spent = flexible_initial_spent(
        responses.iter().map(|r| &r.proof),
        extra_shares.iter(),
        NumberOfNodes::from(subnet_size),
        min_responses,
    );
    FlexibleCanisterHttpResponses {
        callback_id,
        responses,
        extra_shares,
        initial_spent,
    }
}

/// Builds a `TooManyRejects` error with the `initial_spent` that payload
/// validation will recompute for a subnet of `subnet_size` nodes.
fn too_many_rejects(
    callback_id: CallbackId,
    subnet_size: u32,
    min_responses: u32,
    reject_responses: Vec<FlexibleCanisterHttpResponseWithProof>,
) -> FlexibleCanisterHttpError {
    too_many_rejects_with_extra_shares(
        callback_id,
        subnet_size,
        min_responses,
        reject_responses,
        vec![],
    )
}

/// Same as [`too_many_rejects`], but with extra shares contributing their unspent
/// allowance to the error.
fn too_many_rejects_with_extra_shares(
    callback_id: CallbackId,
    subnet_size: u32,
    min_responses: u32,
    reject_responses: Vec<FlexibleCanisterHttpResponseWithProof>,
    extra_shares: Vec<CanisterHttpResponseShare>,
) -> FlexibleCanisterHttpError {
    let initial_spent = flexible_initial_spent(
        reject_responses.iter().map(|r| &r.proof),
        extra_shares.iter(),
        NumberOfNodes::from(subnet_size),
        min_responses,
    );
    FlexibleCanisterHttpError::TooManyRejects {
        callback_id,
        reject_responses,
        extra_shares,
        initial_spent,
    }
}

fn flexible_payload(groups: Vec<FlexibleCanisterHttpResponses>) -> CanisterHttpPayload {
    CanisterHttpPayload {
        out_of_cycles: vec![],
        responses: vec![],
        timeouts: vec![],
        divergence_responses: vec![],
        flexible_responses: groups,
        flexible_errors: vec![],
        async_receipts: vec![],
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
        replica_version: test_replica_version(),
    };
    metadata_to_share(signer_node, &metadata)
}

fn reject_metadata_share(callback_id: u64, signer_node: u64) -> CanisterHttpResponseShare {
    let metadata = CanisterHttpResponseMetadata {
        id: CallbackId::new(callback_id),
        content_hash: CryptoHashOf::new(CryptoHash(vec![0xCD; 32])),
        content_size: 50,
        is_reject: true,
        replica_version: test_replica_version(),
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

/// Same as [`build_and_validate_and_parse_payload`], but with a `max_size` byte
/// budget for the payload rather than the maximum one.
fn build_and_validate_and_parse_payload_with_max_size(
    payload_builder: &CanisterHttpPayloadBuilderImpl,
    max_size: NumBytes,
) -> CanisterHttpPayload {
    let context = default_validation_context();
    let payload = payload_builder.build_payload(Height::new(1), max_size, &[], &context);
    assert_matches!(
        payload_builder.validate_payload(
            Height::new(1),
            &test_proposal_context(&context),
            &payload,
            &[],
        ),
        Ok(())
    );
    bytes_to_payload(&payload).expect("parse error")
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
        .expect_verify_basic_sig_batch_multi_msg_http()
        .returning(|_| {
            Err(ic_types::crypto::CryptoError::SignatureVerification {
                algorithm: ic_types::crypto::AlgorithmId::Ed25519,
                public_key_bytes: vec![],
                sig_bytes: vec![],
                internal_error: "mock rejection".to_string(),
            })
        });
    mock_crypto
}

// ===================================================================
// Asynchronous receipts
// ===================================================================

/// A delivered (already responded to) pay-as-you-go context whose replicas each
/// got `TEST_PER_REPLICA_ALLOWANCE`, with `refunding_nodes` already accounted for
/// by the response that was delivered.
fn delivered_context(
    replication: Replication,
    refunding_nodes: impl IntoIterator<Item = NodeId>,
) -> CanisterHttpRequestContext {
    let mut context = with_payg_allowance(request_context(replication), TEST_PER_REPLICA_ALLOWANCE);
    context.refund_status.refunding_nodes = refunding_nodes.into_iter().collect();
    context
}

/// The signers of the payload's asynchronous receipts, all of which must be for
/// `callback_id`.
fn async_receipt_signers(
    payload: &CanisterHttpPayload,
    callback_id: CallbackId,
) -> BTreeSet<NodeId> {
    payload
        .async_receipts
        .iter()
        .map(|share| {
            assert_eq!(share.content.id(), callback_id);
            share.signature.signer
        })
        .collect()
}

/// Builds a payload against a delivered context of the given `replication` whose
/// response was signed by `refunding_nodes`, with `shares_in_pool` many replicas
/// having produced a share, and returns it.
fn build_async_receipt_payload(
    num_nodes: usize,
    callback_id: CallbackId,
    replication: Replication,
    refunding_nodes: impl IntoIterator<Item = NodeId>,
    shares_in_pool: usize,
    past_payloads: &[PastPayload],
) -> CanisterHttpPayload {
    let (response, metadata) = test_response_and_metadata(callback_id.get());
    let shares = metadata_to_shares(shares_in_pool, &metadata);
    let mut payload = None;
    setup_test_with_delivered_contexts(
        num_nodes,
        vec![(callback_id, delivered_context(replication, refunding_nodes))],
        |payload_builder, canister_http_pool| {
            {
                let mut pool_access = canister_http_pool.write().unwrap();
                if let Some(own) = shares.first() {
                    add_own_share_to_pool(pool_access.deref_mut(), own, &response);
                    add_received_shares_to_pool(pool_access.deref_mut(), shares[1..].to_vec());
                }
            }
            let context = default_validation_context();
            let bytes = payload_builder.build_payload(
                Height::new(1),
                TEST_MAX_PAYLOAD_BYTES,
                past_payloads,
                &context,
            );
            assert_matches!(
                payload_builder.validate_payload(
                    Height::new(1),
                    &test_proposal_context(&context),
                    &bytes,
                    past_payloads,
                ),
                Ok(())
            );
            payload = Some(bytes_to_payload(&bytes).expect("parse error"));
        },
    );
    payload.expect("payload was not built")
}

/// A delivered context is only reported on until it times out: from then on message
/// routing settles whatever is left of the allowances — refunding every replica that
/// has not been accounted for in full — and drops the context, so a receipt would
/// only be spending block space on cycles that are refunded anyway.
///
/// The boundary matters: message routing applies the receipts of a block before
/// timing out the contexts, so a receipt included exactly at the timeout would
/// still be applied, which is precisely what the payload builder avoids here.
#[test]
fn async_receipt_is_not_reported_once_the_delivered_context_times_out() {
    let num_nodes = 4;
    let callback_id = CallbackId::new(0);
    let (response, metadata) = test_response_and_metadata(callback_id.get());
    let shares = metadata_to_shares(num_nodes, &metadata);

    // The context is stamped at `UNIX_EPOCH`, so the block time alone decides
    // whether it has timed out. Check either side of the boundary, so that the
    // negative case cannot pass just because nothing was refundable anyway.
    for (elapsed, expect_refunds) in [
        (
            DELIVERED_CANISTER_HTTP_REQUEST_CONTEXT_TIMEOUT - Duration::from_nanos(1),
            true,
        ),
        (DELIVERED_CANISTER_HTTP_REQUEST_CONTEXT_TIMEOUT, false),
    ] {
        setup_test_with_delivered_contexts(
            num_nodes,
            vec![(
                callback_id,
                delivered_context(Replication::FullyReplicated, []),
            )],
            |payload_builder, canister_http_pool| {
                {
                    let mut pool_access = canister_http_pool.write().unwrap();
                    add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &response);
                    add_received_shares_to_pool(pool_access.deref_mut(), shares[1..].to_vec());
                }
                let context = ValidationContext {
                    time: UNIX_EPOCH + elapsed,
                    ..default_validation_context()
                };
                let payload =
                    build_and_validate_and_parse_payload_with_context(&payload_builder, &context);
                assert_eq!(
                    !payload.async_receipts.is_empty(),
                    expect_refunds,
                    "unexpected refunds {:?} after {elapsed:?}",
                    payload.async_receipts,
                );
            },
        );
    }
}

/// A replica is left out for either of two reasons: it was already accounted for by
/// the delivered response, or it never produced a receipt at all — the latter is
/// refunded in full when the delivered context times out instead.
#[test]
fn async_receipt_reports_the_replicas_that_answered_and_are_unaccounted_for() {
    let num_nodes = 4;
    let callback_id = CallbackId::new(0);
    // Node 0 signed the response that was delivered; nodes 1 and 2 answered too
    // late to be part of it; node 3 never answered at all.
    let payload = build_async_receipt_payload(
        num_nodes,
        callback_id,
        Replication::FullyReplicated,
        [node_test_id(0)],
        /* shares_in_pool = */ 3,
        &[],
    );

    assert_eq!(
        async_receipt_signers(&payload, callback_id),
        BTreeSet::from([node_test_id(1), node_test_id(2)])
    );
}

/// Once every replica has been accounted for, there is nothing left to report.
#[test]
fn async_receipt_is_not_reported_when_every_replica_has_been_accounted_for() {
    let num_nodes = 4;
    let callback_id = CallbackId::new(0);
    let all_nodes: Vec<_> = (0..num_nodes as u64).map(node_test_id).collect();

    let payload = build_async_receipt_payload(
        num_nodes,
        callback_id,
        Replication::FullyReplicated,
        all_nodes,
        num_nodes,
        &[],
    );

    assert!(payload.async_receipts.is_empty(), "{payload:?}");
    // A payload with nothing to report is empty, i.e. not put into the block at all.
    assert!(payload.is_empty(), "{payload:?}");
}

/// A refund reported by a payload above the certified height is not repeated, even
/// though the certified state does not reflect it yet.
#[test]
fn async_receipt_is_not_repeated_after_a_past_payload_reported_it() {
    let num_nodes = 4;
    let callback_id = CallbackId::new(0);
    let (_, metadata) = test_response_and_metadata(callback_id.get());

    // A past payload already reported node 2.
    let past = payload_to_bytes_max_4mb(CanisterHttpPayload {
        async_receipts: vec![metadata_to_share(2, &metadata)],
        ..Default::default()
    });
    let past_payloads = vec![PastPayload {
        height: Height::new(1),
        time: UNIX_EPOCH,
        block_hash: CryptoHashOf::from(CryptoHash(vec![])),
        payload: &past,
    }];

    let payload = build_async_receipt_payload(
        num_nodes,
        callback_id,
        Replication::FullyReplicated,
        [node_test_id(0)],
        num_nodes,
        &past_payloads,
    );

    // Node 0 was accounted for by the delivered response, node 2 by the past
    // payload; only nodes 1 and 3 are left.
    assert_eq!(
        async_receipt_signers(&payload, callback_id),
        BTreeSet::from([node_test_id(1), node_test_id(3)])
    );
}

/// The replicas an asynchronous receipt may come from are the ones the request
/// pins: the whole subnet for a fully replicated request, the designated replica
/// for a non-replicated one, and the recorded committee for a flexible one.
#[test]
fn async_receipts_are_reported_for_the_committee_of_every_replication() {
    let num_nodes = 4;
    let callback_id = CallbackId::new(0);

    for (replication, refunding_nodes, expected) in [
        // The response was signed by node 0; every other replica of the subnet that
        // answered is still unaccounted for.
        (
            Replication::FullyReplicated,
            vec![node_test_id(0)],
            BTreeSet::from([node_test_id(1), node_test_id(2), node_test_id(3)]),
        ),
        // The request timed out before the designated replica answered, so nobody is
        // accounted for yet — and only that replica can report anything.
        (
            Replication::NonReplicated(node_test_id(2)),
            vec![],
            BTreeSet::from([node_test_id(2)]),
        ),
        // Node 3 is not part of the flexible committee, so its share is ignored even
        // though it is in the pool.
        (
            Replication::Flexible {
                committee: BTreeSet::from([node_test_id(0), node_test_id(1), node_test_id(2)]),
                min_responses: 2,
                max_responses: 3,
            },
            vec![node_test_id(0)],
            BTreeSet::from([node_test_id(1), node_test_id(2)]),
        ),
    ] {
        let payload = build_async_receipt_payload(
            num_nodes,
            callback_id,
            replication.clone(),
            refunding_nodes,
            /* shares_in_pool = */ num_nodes,
            &[],
        );

        assert_eq!(
            async_receipt_signers(&payload, callback_id),
            expected,
            "unexpected receipts for {replication:?}"
        );
    }
}

/// Receipts count towards the per-block response limit like any other message, and
/// are collected across delivered contexts until it is reached.
#[test]
fn async_receipts_of_many_delivered_contexts_stop_at_the_per_block_limit() {
    // Enough delivered contexts, each answered by every replica, to produce more
    // receipts than a single block may carry. The subnet size deliberately does not
    // divide the limit, so that it is reached part-way through a context.
    let num_nodes = 3;
    let num_contexts = CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK / num_nodes + 1;
    let contexts: Vec<_> = (0..num_contexts as u64)
        .map(|id| {
            (
                CallbackId::new(id),
                delivered_context(Replication::FullyReplicated, []),
            )
        })
        .collect();

    setup_test_with_delivered_contexts(num_nodes, contexts, |payload_builder, pool| {
        {
            let mut pool_access = pool.write().unwrap();
            for id in 0..num_contexts as u64 {
                let (_, metadata) = test_response_and_metadata(id);
                add_received_shares_to_pool(
                    pool_access.deref_mut(),
                    metadata_to_shares(num_nodes, &metadata),
                );
            }
        }

        let payload = build_and_validate_and_parse_payload(&payload_builder);

        assert_eq!(
            payload.async_receipts.len(),
            CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK
        );
        // The last context that fits is only partly reported, i.e. collecting stops
        // mid-context rather than at a context boundary.
        assert_eq!(
            payload
                .async_receipts
                .iter()
                .map(|share| share.content.id())
                .collect::<BTreeSet<_>>()
                .len(),
            CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK.div_ceil(num_nodes)
        );
    });
}

/// An asynchronous receipt reported for a callback that has not been responded to is
/// invalid: only a delivered context can be refunded this way.
#[test]
fn validate_payload_fails_for_an_async_receipt_of_an_unanswered_request() {
    let num_nodes = 4;
    let callback_id = CallbackId::new(0);
    let (_, metadata) = test_response_and_metadata(callback_id.get());
    let payload = CanisterHttpPayload {
        async_receipts: vec![metadata_to_share(0, &metadata)],
        ..Default::default()
    };

    let mut result = None;
    setup_test_with_contexts(
        num_nodes,
        vec![(
            callback_id,
            delivered_context(Replication::FullyReplicated, []),
        )],
        |payload_builder, _pool| {
            result = Some(payload_builder.validate_payload(
                Height::new(1),
                &test_proposal_context(&default_validation_context()),
                &payload_to_bytes_max_4mb(payload),
                &[],
            ));
        },
    );

    assert_matches!(
        result.expect("validation did not run"),
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::UnknownDeliveredCallbackId(id),
            ),
        )) if id == callback_id
    );
}

/// Validates a payload carrying nothing but the given asynchronous receipts,
/// against a delivered request with the given `context` and the given `past_payloads`.
fn validate_async_receipt_payload(
    num_nodes: usize,
    callback_id: CallbackId,
    context: CanisterHttpRequestContext,
    refunds: Vec<CanisterHttpResponseShare>,
    past_payloads: &[PastPayload],
) -> Result<(), PayloadValidationError> {
    validate_async_receipt_payload_at(
        num_nodes,
        callback_id,
        context,
        refunds,
        past_payloads,
        &default_validation_context(),
    )
}

/// Same as [`validate_async_receipt_payload`], but for a block proposed in the
/// given `validation_context` rather than the default one.
fn validate_async_receipt_payload_at(
    num_nodes: usize,
    callback_id: CallbackId,
    context: CanisterHttpRequestContext,
    refunds: Vec<CanisterHttpResponseShare>,
    past_payloads: &[PastPayload],
    validation_context: &ValidationContext,
) -> Result<(), PayloadValidationError> {
    let payload = CanisterHttpPayload {
        async_receipts: refunds,
        ..Default::default()
    };
    let mut result = None;
    setup_test_with_delivered_contexts(
        num_nodes,
        vec![(callback_id, context)],
        |payload_builder, _pool| {
            result = Some(payload_builder.validate_payload(
                Height::new(1),
                &test_proposal_context(validation_context),
                &payload_to_bytes_max_4mb(payload),
                past_payloads,
            ));
        },
    );
    result.expect("validation did not run")
}

#[test]
fn validate_payload_fails_for_an_async_receipt_of_a_timed_out_delivered_context() {
    let callback_id = CallbackId::new(0);
    let (_, metadata) = test_response_and_metadata(callback_id.get());

    // The context is stamped at `UNIX_EPOCH`, so the block time alone decides
    // whether it has timed out.
    let validate_at = |elapsed| {
        validate_async_receipt_payload_at(
            4,
            callback_id,
            delivered_context(Replication::FullyReplicated, []),
            vec![metadata_to_share(1, &metadata)],
            &[],
            &ValidationContext {
                time: UNIX_EPOCH + elapsed,
                ..default_validation_context()
            },
        )
    };

    // Just short of the timeout the very same receipt is still accepted, so the
    // rejection below cannot be down to anything else about it.
    assert_matches!(
        validate_at(DELIVERED_CANISTER_HTTP_REQUEST_CONTEXT_TIMEOUT - Duration::from_nanos(1)),
        Ok(())
    );
    assert_matches!(
        validate_at(DELIVERED_CANISTER_HTTP_REQUEST_CONTEXT_TIMEOUT),
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::DeliveredCallbackTimedOut(id),
            ),
        )) if id == callback_id
    );
}

fn assert_already_refunded(result: Result<(), PayloadValidationError>, expected_signer: NodeId) {
    assert_matches!(
        result,
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::AlreadyRefunded { signer, .. },
            ),
        )) if signer == expected_signer
    );
}

/// A replica already accounted for by the delivered response must not be refunded
/// a second time.
#[test]
fn validate_payload_fails_for_an_async_receipt_of_an_accounted_replica() {
    let callback_id = CallbackId::new(0);
    let (_, metadata) = test_response_and_metadata(callback_id.get());

    let result = validate_async_receipt_payload(
        4,
        callback_id,
        delivered_context(Replication::FullyReplicated, [node_test_id(1)]),
        vec![metadata_to_share(1, &metadata)],
        &[],
    );

    assert_already_refunded(result, node_test_id(1));
}

/// A replica already reported by a payload above the certified height must not be
/// refunded again, even though the certified state does not reflect it yet.
#[test]
fn validate_payload_fails_for_an_async_receipt_repeated_from_a_past_payload() {
    let callback_id = CallbackId::new(0);
    let (_, metadata) = test_response_and_metadata(callback_id.get());
    let refund = metadata_to_share(1, &metadata);
    let past = payload_to_bytes_max_4mb(CanisterHttpPayload {
        async_receipts: vec![refund.clone()],
        ..Default::default()
    });
    let past_payloads = vec![PastPayload {
        height: Height::new(1),
        time: UNIX_EPOCH,
        block_hash: CryptoHashOf::from(CryptoHash(vec![])),
        payload: &past,
    }];

    let result = validate_async_receipt_payload(
        4,
        callback_id,
        delivered_context(Replication::FullyReplicated, []),
        vec![refund],
        &past_payloads,
    );

    assert_already_refunded(result, node_test_id(1));
}

/// The same replica must not be refunded twice by the same payload, whether the two
/// receipts are byte-identical or merely share a signer.
#[test]
fn validate_payload_fails_for_an_async_receipt_repeated_within_the_payload() {
    let callback_id = CallbackId::new(0);
    let (_, metadata) = test_response_and_metadata(callback_id.get());
    let share = metadata_to_share(1, &metadata);
    let same_signer = metadata_to_share_with_spent(1, &metadata, Cycles::new(1));

    for refunds in [vec![share.clone(), share.clone()], vec![share, same_signer]] {
        let result = validate_async_receipt_payload(
            4,
            callback_id,
            delivered_context(Replication::FullyReplicated, []),
            refunds,
            &[],
        );

        assert_matches!(
            result,
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::DuplicateShareSigner { signer, .. },
                ),
            )) if signer == node_test_id(1)
        );
    }
}

/// Only the request's committee can be refunded for it.
#[test]
fn validate_payload_fails_for_an_async_receipt_of_a_non_committee_replica() {
    let callback_id = CallbackId::new(0);
    let (_, metadata) = test_response_and_metadata(callback_id.get());
    let designated = node_test_id(0);
    let outsider = node_test_id(1);

    let result = validate_async_receipt_payload(
        4,
        callback_id,
        // Only the designated replica of a non-replicated request ever spends.
        delivered_context(Replication::NonReplicated(designated), []),
        vec![metadata_to_share(node_id_to_u64(outsider), &metadata)],
        &[],
    );

    assert_matches!(
        result,
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::ShareSignerNotInCommittee { signer, .. },
            ),
        )) if signer == outsider
    );
}

/// A receipt claiming a spend beyond the replica's allowance is rejected here as
/// everywhere else.
#[test]
fn validate_payload_fails_for_an_async_receipt_with_an_excessive_spend() {
    let callback_id = CallbackId::new(0);
    let (_, metadata) = test_response_and_metadata(callback_id.get());

    let result = validate_async_receipt_payload(
        4,
        callback_id,
        delivered_context(Replication::FullyReplicated, []),
        vec![metadata_to_share_with_spent(
            1,
            &metadata,
            TEST_PER_REPLICA_ALLOWANCE + Cycles::new(1),
        )],
        &[],
    );

    assert_matches!(
        result,
        Err(ValidationError::InvalidArtifact(
            InvalidPayloadReason::InvalidCanisterHttpPayload(
                InvalidCanisterHttpPayloadReason::SpentExceedsLimit { .. },
            ),
        ))
    );
}

/// An asynchronous receipt reports what its replicas spent, without delivering a
/// response: the response it belongs to is already out. Receipts are regrouped by
/// the callback they are signed for, one report per callback.
#[test]
fn into_messages_emits_asynchronous_spend_reports() {
    let (first, second) = (CallbackId::new(7), CallbackId::new(8));
    let (_, first_metadata) = test_response_and_metadata(first.get());
    let (_, second_metadata) = test_response_and_metadata(second.get());
    let spent = Cycles::new(1_234);
    let payload = CanisterHttpPayload {
        // Deliberately interleaved, to show that the grouping does not rely on order.
        async_receipts: vec![
            metadata_to_share_with_spent(1, &first_metadata, spent),
            metadata_to_share_with_spent(1, &second_metadata, Cycles::new(7)),
            metadata_to_share_with_spent(2, &first_metadata, Cycles::zero()),
        ],
        ..Default::default()
    };

    let (responses, spent_report, stats) =
        CanisterHttpPayloadBuilderImpl::into_messages(&payload_to_bytes_max_4mb(payload));

    assert!(responses.is_empty(), "{responses:?}");
    assert_eq!(stats.async_receipts, 3);
    assert!(spent_report.initial.is_empty());
    let reported: BTreeMap<_, _> = spent_report
        .asynchronous
        .iter()
        .map(|report| (report.callback, report.shares.clone()))
        .collect();
    assert_eq!(
        reported,
        BTreeMap::from([
            (
                first,
                BTreeMap::from([(node_test_id(1), spent), (node_test_id(2), Cycles::zero())])
            ),
            (second, BTreeMap::from([(node_test_id(1), Cycles::new(7))])),
        ])
    );
}
