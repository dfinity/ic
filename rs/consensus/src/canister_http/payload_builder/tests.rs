//! This module contains unit tests for the payload building and verification
//! of the canister http feature.
//!
//! Some tests are run over a range of subnet configurations to check for corner cases.

use super::*;
use crate::consensus::mocks::{dependencies_with_subnet_params, Dependencies};
use ic_artifact_pool::canister_http_pool::CanisterHttpPoolImpl;
use ic_interfaces::{
    artifact_pool::UnvalidatedArtifact,
    canister_http::{CanisterHttpChangeAction, MutableCanisterHttpPool},
    validation::ValidationError,
};
use ic_logger::replica_logger::no_op_logger;
use ic_protobuf::registry::subnet::v1::SubnetFeatures;
use ic_test_utilities::{
    mock_time,
    state_manager::RefMockStateManager,
    types::{
        ids::{canister_test_id, node_test_id, subnet_test_id},
        messages::RequestBuilder,
    },
};
use ic_test_utilities_registry::SubnetRecordBuilder;
use ic_types::{
    canister_http::{CanisterHttpMethod, CanisterHttpRequestContext, CanisterHttpResponseContent},
    consensus::get_faults_tolerated,
    crypto::{crypto_hash, BasicSig, BasicSigOf},
    signature::BasicSignatureBatch,
    time::UNIX_EPOCH,
    Time,
};
use std::{collections::BTreeMap, ops::DerefMut, time::Duration};

/// The maximum subnet size up to which we will check the functionality of the canister http feature.
const MAX_SUBNET_SIZE: usize = 40;

/// Check that a single well formed request with shares makes it through the block maker
#[test]
fn single_request_test() {
    let context = default_validation_context();

    for subnet_size in 1..MAX_SUBNET_SIZE {
        test_config_with_http_feature(subnet_size, |payload_builder, canister_http_pool| {
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
            let payload = payload_builder.get_canister_http_payload(
                Height::new(1),
                &context,
                &[],
                NumBytes::new(4 * 1024 * 1024),
            );

            //  Make sure the response is contained in the payload
            assert_eq!(payload.num_responses(), 1);
            assert_eq!(payload.responses[0].content, response);

            assert!(payload_builder
                .validate_canister_http_payload(Height::new(1), &payload, &context, &[])
                .is_ok());
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
        test_config_with_http_feature(subnet_size, |payload_builder, canister_http_pool| {
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
                response.timeout = mock_time();
                metadata.timeout = mock_time();
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

            let validation_context = ValidationContext {
                registry_version: RegistryVersion::new(1),
                certified_height: Height::new(0),
                time: mock_time() + Duration::from_secs(3),
            };

            // Build a payload
            let payload = payload_builder.get_canister_http_payload(
                Height::new(1),
                &validation_context,
                &[&past_payload],
                NumBytes::new(4 * 1024 * 1024),
            );

            //  Make sure the response is not contained in the payload
            payload_builder
                .validate_canister_http_payload(
                    Height::new(1),
                    &payload,
                    &validation_context,
                    &[&past_payload],
                )
                .unwrap();
            assert_eq!(payload.num_responses(), 1);
            assert_eq!(payload.responses[0].content, valid_response);
        });
    }
}

#[test]
fn multiple_share_same_source_test() {
    for subnet_size in 3..MAX_SUBNET_SIZE {
        test_config_with_http_feature(subnet_size, |payload_builder, canister_http_pool| {
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
                time: mock_time() + Duration::from_secs(3),
            };

            // Build a payload
            let payload = payload_builder.get_canister_http_payload(
                Height::new(1),
                &validation_context,
                &[],
                NumBytes::new(4 * 1024 * 1024),
            );

            assert_eq!(payload.num_responses(), 0);
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
    let context_time = mock_time() + CANISTER_HTTP_TIMEOUT_INTERVAL + Duration::from_secs(1);
    let mut init_state = ic_test_utilities::state::get_initial_state(0, 0);

    let response_count = 10;
    let timeout_count = 100;

    test_config_with_http_feature(4, |mut payload_builder, canister_http_pool| {
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
                    time: mock_time(),
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
            payload_builder.state_manager = state_manager;
        }

        let validation_context = ValidationContext {
            registry_version: RegistryVersion::new(1),
            certified_height: Height::new(0),
            time: mock_time() + CANISTER_HTTP_TIMEOUT_INTERVAL + Duration::from_secs(1),
        };

        // Build a payload
        let payload = payload_builder.get_canister_http_payload(
            Height::new(1),
            &validation_context,
            &[],
            NumBytes::new(1024),
        );
        // Responses get evicted, and timeouts fill most of the available space
        assert!(payload.timeouts.len() == timeout_count as usize);
        assert!(payload.responses.len() < response_count as usize);
    });
}

/// Check that the payload builder includes a divergence responses
#[test]
fn divergence_response_inclusion_test() {
    test_config_with_http_feature(10, |payload_builder, canister_http_pool| {
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
            time: mock_time() + Duration::from_secs(3),
        };

        // Build a payload
        let payload = payload_builder.get_canister_http_payload(
            Height::new(1),
            &validation_context,
            &[],
            NumBytes::new(4 * 1024 * 1024),
        );

        assert_eq!(payload.divergence_responses.len(), 0);

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
        let payload = payload_builder.get_canister_http_payload(
            Height::new(1),
            &validation_context,
            &[],
            NumBytes::new(4 * 1024 * 1024),
        );

        assert_eq!(payload.divergence_responses.len(), 1);
    });
}

/// Submit a very large number of valid responses, then check that the
/// payload builder does not process all of them but only CANISTER_HTTP_RESPONSES_PER_BLOCK
#[test]
fn max_responses() {
    test_config_with_http_feature(4, |payload_builder, canister_http_pool| {
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
            time: mock_time() + Duration::from_secs(3),
        };

        // Build a payload
        let payload = payload_builder.get_canister_http_payload(
            Height::new(1),
            &validation_context,
            &[],
            NumBytes::new(4 * 1024 * 1024),
        );

        //  Make sure the response is not contained in the payload
        payload_builder
            .validate_canister_http_payload(Height::new(1), &payload, &validation_context, &[])
            .unwrap();

        assert!(payload.num_non_timeout_responses() <= CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK);
    })
}

/// Test that oversized payloads don't validate
#[test]
fn oversized_validation() {
    let validation_result = run_validatation_test(
        |response, _| {
            // Give response oversized content
            response.content = CanisterHttpResponseContent::Success(vec![123; 2 * 1024 * 1024]);
        },
        &default_validation_context(),
    );
    match validation_result {
        Err(ValidationError::Permanent(CanisterHttpPermanentValidationError::PayloadTooBig {
            expected,
            received,
        })) if expected == 2 * 1024 * 1024 && received > expected => (),
        x => panic!("Expected PayloadTooBig, got {:?}", x),
    }
}

/// Test that inconsistent payloads don't validate
#[test]
fn inconsistend_validation() {
    let validation_result = run_validatation_test(
        |_, metadata| {
            // Set metadata callback id to a different id
            metadata.id = CallbackId::new(2);
        },
        &default_validation_context(),
    );
    match validation_result {
        Err(ValidationError::Permanent(
            CanisterHttpPermanentValidationError::InvalidMetadata {
                metadata_id,
                content_id,
                ..
            },
        )) if metadata_id == CallbackId::new(2) && content_id == CallbackId::new(0) => (),
        x => panic!("Expected InvalidMetadata, got {:?}", x),
    }
}

/// Test that payloads with wrong registry version don't validate
#[test]
fn registry_version_validation() {
    let validation_result = run_validatation_test(
        |_, metadata| {
            // Set metadata to a newer registry version
            metadata.registry_version = RegistryVersion::new(2);
        },
        &ValidationContext {
            ..default_validation_context()
        },
    );
    match validation_result {
        Err(ValidationError::Permanent(
            CanisterHttpPermanentValidationError::RegistryVersionMismatch { .. },
        )) => (),
        x => panic!("Expected RegistryVersionMismatch, got {:?}", x),
    }
}

/// Test that payloads with wrong hash don't validate
#[test]
fn hash_validation() {
    let validation_result = run_validatation_test(
        |response, _| {
            // Change response content to have a different hash
            response.content = CanisterHttpResponseContent::Success(b"cba".to_vec());
        },
        &default_validation_context(),
    );
    match validation_result {
        Err(ValidationError::Permanent(
            CanisterHttpPermanentValidationError::ContentHashMismatch { .. },
        )) => (),
        x => panic!("Expected ContentHashMismatch, got {:?}", x),
    }
}

/// Test that payloads which are timed out don't validate
#[test]
fn timeout_validation() {
    let validation_result = run_validatation_test(
        |_, _| { /* Nothing to modify */ },
        &ValidationContext {
            // Set the time further in the future, such that this payload is timed out
            time: mock_time() + Duration::from_secs(20),
            ..default_validation_context()
        },
    );
    match validation_result {
        Err(ValidationError::Permanent(CanisterHttpPermanentValidationError::Timeout {
            timed_out_at,
            validation_time,
        })) if timed_out_at < validation_time => (),
        x => panic!("Expected Timeout, got {:?}", x),
    }
}

/// Test that payloads don't validate, if registry for height does not exist
#[test]
fn registry_unavailable_validation() {
    let validation_result = run_validatation_test(
        |_, _| { /* Nothing to modify */ },
        &ValidationContext {
            // Use a higher registry version, that does not exist yet
            registry_version: RegistryVersion::new(2),
            ..default_validation_context()
        },
    );
    match validation_result {
        Err(ValidationError::Transient(
            CanisterHttpTransientValidationError::RegistryUnavailable(
                RegistryClientError::VersionNotAvailable { version },
            ),
        )) if version == RegistryVersion::new(2) => (),
        x => panic!("Expected RegistryUnavailable, got {:?}", x),
    }
}

/// Test that payloads don't validate when feature is disabled
///
/// NOTE: We use the fact that the feature is disabled for registry version 0, so we can still reuse
/// the existing helper functions
#[test]
fn feature_disabled_validation() {
    let validation_result = run_validatation_test(
        |_, mut metadata| {
            // Set registry version to 0
            metadata.registry_version = RegistryVersion::new(0);
        },
        &ValidationContext {
            // Use registry version 0
            registry_version: RegistryVersion::new(0),
            ..default_validation_context()
        },
    );
    match validation_result {
        Err(ValidationError::Transient(CanisterHttpTransientValidationError::Disabled)) => (),
        x => panic!("Expected Disabled, got {:?}", x),
    }
}

/// Test that duplicate payloads don't validate
#[test]
fn duplicate_validation() {
    test_config_with_http_feature(4, |payload_builder, _| {
        let (response, metadata) = test_response_and_metadata(0);

        let payload = CanisterHttpPayload {
            responses: vec![response_and_metadata_to_proof(&response, &metadata)],
            timeouts: vec![],
            divergence_responses: vec![],
        };

        let validation_result = payload_builder.validate_canister_http_payload(
            Height::from(1),
            &payload,
            &default_validation_context(),
            &[&payload],
        );

        match validation_result {
            Err(ValidationError::Permanent(
                CanisterHttpPermanentValidationError::DuplicateResponse(id),
            )) if id == CallbackId::new(0) => (),
            x => panic!("Expected DuplicateResponse, got {:?}", x),
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
        test_config_with_http_feature(subnet_size, |payload_builder, _| {
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

            let validation_result = payload_builder.validate_canister_http_payload(
                Height::from(1),
                &payload,
                &default_validation_context(),
                &[&payload],
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

            let validation_result = payload_builder.validate_canister_http_payload(
                Height::from(1),
                &payload,
                &default_validation_context(),
                &[&payload],
            );

            match validation_result {
            Err(CanisterHttpPayloadValidationError::Permanent(
                CanisterHttpPermanentValidationError::DivergenceProofDoesNotMeetDivergenceCriteria,
            )) => (),
            x => panic!(
                "Expected DivergenceProofDoesNotMeetDivergenceCriteria, got {:?}",
                x
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

            let validation_result = payload_builder.validate_canister_http_payload(
                Height::from(1),
                &payload,
                &default_validation_context(),
                &[&payload],
            );

            match validation_result {
            Err(CanisterHttpPayloadValidationError::Permanent(
                CanisterHttpPermanentValidationError::DivergenceProofContainsMultipleCallbackIds,
            )) => (),
            x => panic!(
                "Expected DivergenceProofContainsMultipleCallbackIds, got {:?}",
                x
            ),
        }
        });
    }
}

/// Build some test metadata and response, which is valid and can be used in
/// different tests
fn test_response_and_metadata(
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
    test_response_and_metadata_full(callback_id, mock_time() + Duration::from_secs(10), content)
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
    };
    (response, metadata)
}
/// Replicates the behaviour of receiving and successfully validating a share over the network
fn add_received_shares_to_pool(
    pool: &mut dyn MutableCanisterHttpPool,
    shares: Vec<CanisterHttpResponseShare>,
) {
    for share in shares {
        let hash = crypto_hash(&share);

        pool.insert(UnvalidatedArtifact {
            message: share,
            peer_id: node_test_id(0),
            timestamp: mock_time(),
        });

        pool.apply_changes(vec![CanisterHttpChangeAction::MoveToValidated(hash)])
    }
}

/// Replicates the behaviour of adding your own share (and content) to the pool
fn add_own_share_to_pool(
    pool: &mut dyn MutableCanisterHttpPool,
    share: &CanisterHttpResponseShare,
    content: &CanisterHttpResponse,
) {
    pool.apply_changes(vec![CanisterHttpChangeAction::AddToValidated(
        share.clone(),
        content.clone(),
    )]);
}

/// Creates a [`CanisterHttpResponseShare`] from [`CanisterHttpResponseMetadata`]
fn metadata_to_share(
    from_node: u64,
    metadata: &CanisterHttpResponseMetadata,
) -> CanisterHttpResponseShare {
    metadata_to_share_with_signature(from_node, metadata, vec![])
}

fn metadata_to_share_with_signature(
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
fn response_and_metadata_to_proof(
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
fn metadata_to_shares(
    num_nodes: usize,
    metadata: &CanisterHttpResponseMetadata,
) -> Vec<CanisterHttpResponseShare> {
    (0..num_nodes)
        .into_iter()
        .map(|id| metadata_to_share(id.try_into().unwrap(), metadata))
        .collect()
}

/// Mock up a test node, which has the feauture enabled
fn test_config_with_http_feature<T>(
    num_nodes: usize,
    run: impl FnOnce(CanisterHttpPayloadBuilderImpl, Arc<RwLock<CanisterHttpPoolImpl>>) -> T,
) -> T {
    let committee = (0..num_nodes)
        .into_iter()
        .map(|id| node_test_id(id as u64))
        .collect::<Vec<_>>();
    ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
        let mut subnet_record = SubnetRecordBuilder::from(&committee).build();
        subnet_record.features = Some(SubnetFeatures {
            http_requests: true,
            ..SubnetFeatures::default()
        });

        let Dependencies {
            crypto,
            registry,
            membership,
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
            membership,
            subnet_test_id(0),
            registry,
            &MetricsRegistry::new(),
            no_op_logger(),
        );

        run(payload_builder, canister_http_pool)
    })
}

/// The default validation context used in the validation tests
fn default_validation_context() -> ValidationContext {
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
    mut modify: F,
    validation_context: &ValidationContext,
) -> Result<NumBytes, CanisterHttpPayloadValidationError>
where
    F: FnMut(&mut CanisterHttpResponse, &mut CanisterHttpResponseMetadata),
{
    test_config_with_http_feature(4, |payload_builder, _| {
        let (mut response, mut metadata) = test_response_and_metadata(0);
        modify(&mut response, &mut metadata);

        let payload = CanisterHttpPayload {
            responses: vec![response_and_metadata_to_proof(&response, &metadata)],
            timeouts: vec![],
            divergence_responses: vec![],
        };

        payload_builder.validate_canister_http_payload(
            Height::from(1),
            &payload,
            validation_context,
            &[],
        )
    })
}
