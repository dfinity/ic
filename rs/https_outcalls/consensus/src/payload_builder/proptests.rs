use crate::payload_builder::tests::{
    add_own_share_to_pool, add_received_shares_to_pool, default_validation_context,
    metadata_to_share, metadata_to_shares, test_config_with_http_feature, test_proposal_context,
};
use ic_error_types::RejectCode;
use ic_interfaces::batch_payload::{BatchPayloadBuilder, PastPayload};
use ic_test_utilities_types::ids::canister_test_id;
use ic_types::{
    Height, NumBytes, RegistryVersion, ReplicaVersion,
    canister_http::{
        CanisterHttpReject, CanisterHttpResponse, CanisterHttpResponseContent,
        CanisterHttpResponseMetadata, CanisterHttpResponseShare,
    },
    crypto::{CryptoHash, CryptoHashOf, crypto_hash},
    messages::CallbackId,
    time::UNIX_EPOCH,
};
use proptest::{arbitrary::any, prelude::*};
use std::{ops::DerefMut, time::Duration};

const SUBNET_SIZE: usize = 13;
const MAX_PAYLOAD_SIZE_BYTES: usize = 4 * 1024 * 1024;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        max_shrink_time: 60000,
        ..ProptestConfig::default()
    })]

    #[test]
    fn proptest_payload_size_validation(
        (responses, shares) in prop_artifacts(
            100,
            4_000,
            4_000,
            10_000,
            MAX_PAYLOAD_SIZE_BYTES,
            SUBNET_SIZE
        )) {
            run_proptest(10, responses, shares);
    }
}

fn run_proptest(
    number_of_rounds: u64,
    responses: Vec<(CanisterHttpResponse, CanisterHttpResponseShare)>,
    shares: Vec<CanisterHttpResponseShare>,
) {
    let context = default_validation_context();
    test_config_with_http_feature(true, SUBNET_SIZE, |payload_builder, canister_http_pool| {
        {
            let mut pool_access = canister_http_pool.write().unwrap();

            for (response, share) in responses {
                add_own_share_to_pool(pool_access.deref_mut(), &share, &response);
            }

            add_received_shares_to_pool(pool_access.deref_mut(), shares);
        }

        let mut past_payloads: Vec<Vec<u8>> = vec![];

        for height in 1..=number_of_rounds {
            let pp = past_payloads
                .iter()
                .enumerate()
                .map(|(height, payload)| PastPayload {
                    height: Height::new(height as u64 + 1),
                    time: UNIX_EPOCH,
                    block_hash: CryptoHashOf::new(CryptoHash([0; 32].to_vec())),
                    payload,
                })
                .collect::<Vec<_>>();

            // Build a payload
            let payload = payload_builder.build_payload(
                Height::new(height),
                NumBytes::new(MAX_PAYLOAD_SIZE_BYTES as u64),
                &pp,
                &context,
            );

            assert!(payload_builder.metrics.unique_responses.get() != 0);
            assert!(payload.len() <= MAX_PAYLOAD_SIZE_BYTES);

            let validation_result = payload_builder.validate_payload(
                Height::new(height),
                &test_proposal_context(&context),
                &payload,
                &pp,
            );
            assert!(validation_result.is_ok());

            past_payloads.push(payload);
        }
    });
}

/// Generate artifacts to put into the pool to simulate a normal production environment
///
/// Currently, this includes responses with any number of supporting shares, as well as
/// a number of random shares, that don't correspond to any responses known to this node.
///
fn prop_artifacts(
    max_responses: usize,
    max_random_shares: usize,
    max_divergences: usize,
    max_timeout: u64,
    max_size: usize,
    subnet_size: usize,
) -> impl Strategy<
    Value = (
        Vec<(CanisterHttpResponse, CanisterHttpResponseShare)>,
        Vec<CanisterHttpResponseShare>,
    ),
> {
    (
        prop::collection::vec(
            prop_response_with_shares(max_timeout, max_size, subnet_size),
            1..=max_responses,
        ),
        prop::collection::vec(
            prop_random_shares(max_timeout, subnet_size),
            0..=max_random_shares,
        ),
        prop::collection::vec(
            prop_divergence(max_timeout, subnet_size),
            0..=max_divergences,
        ),
    )
        .prop_map(|(prop_responses, random_shares, divergence_shares)| {
            let mut collected_responses = vec![];
            let mut collected_shares = vec![];

            for (response, mut shares) in prop_responses {
                collected_responses.push((response, shares[0].clone()));
                collected_shares.extend(shares.drain(1..).collect::<Vec<_>>());
            }
            for shares in random_shares {
                collected_shares.extend(shares);
            }
            for shares in divergence_shares {
                collected_shares.extend(shares);
            }

            (collected_responses, collected_shares)
        })
}

/// Generate a response and metadata supporting that response too
fn prop_response_with_shares(
    max_timeout: u64,
    max_size: usize,
    subnet_size: usize,
) -> impl Strategy<Value = (CanisterHttpResponse, Vec<CanisterHttpResponseShare>)> {
    (1..subnet_size, prop_response(max_timeout, max_size)).prop_map(
        move |(num_shares, response)| {
            let metadata = CanisterHttpResponseMetadata {
                id: response.id,
                timeout: response.timeout,
                content_hash: crypto_hash(&response),
                registry_version: RegistryVersion::new(1),
                replica_version: ReplicaVersion::default(),
            };
            let shares = metadata_to_shares(num_shares, &metadata);
            (response, shares)
        },
    )
}

/// Generate a number of shares for a random metadata.
///
/// This means that the node will not have the content of the response ans should not
/// be able to include it in a block, no matter how many other nodes have sent their response
fn prop_random_shares(
    max_timeout: u64,
    subnet_size: usize,
) -> impl Strategy<Value = Vec<CanisterHttpResponseShare>> {
    (1..=subnet_size, prop_random_metadata(max_timeout))
        .prop_map(|(num_shares, metadata)| metadata_to_shares(num_shares, &metadata))
}

/// Generate a response with random `callback_id` and `canister_id` and a
/// `timeout` and length between 0 and the specified maximum value
fn prop_response(max_timeout: u64, max_size: usize) -> impl Strategy<Value = CanisterHttpResponse> {
    (
        any::<(u64, u64)>(),
        100..max_timeout,
        prop_content(max_size),
    )
        .prop_map(
            |((id, canister_id), timeout, content)| CanisterHttpResponse {
                id: CallbackId::new(id),
                timeout: UNIX_EPOCH + Duration::from_millis(timeout),
                canister_id: canister_test_id(canister_id),
                content,
            },
        )
}

/// Generate a random metadata with a timeout and registry version value between 0 and
/// the specified value
fn prop_random_metadata(max_timeout: u64) -> impl Strategy<Value = CanisterHttpResponseMetadata> {
    (any::<(u64, [u8; 32])>(), 100..max_timeout).prop_map(|((id, hash), timeout)| {
        CanisterHttpResponseMetadata {
            id: CallbackId::new(id),
            timeout: UNIX_EPOCH + Duration::from_millis(timeout),
            content_hash: CryptoHashOf::new(CryptoHash(hash.to_vec())),
            registry_version: RegistryVersion::new(1),
            replica_version: ReplicaVersion::default(),
        }
    })
}

/// Generate random content that is either a success message of `max_size` length
/// or a reject message, where the description has `max_size` length
fn prop_content(max_size: usize) -> impl Strategy<Value = CanisterHttpResponseContent> {
    prop_oneof![
        (0..max_size).prop_map(|size| CanisterHttpResponseContent::Success(vec![0; size])),
        (0..max_size).prop_map(
            |size| CanisterHttpResponseContent::Reject(CanisterHttpReject {
                reject_code: RejectCode::SysFatal,
                message: "a".repeat(size),
            })
        )
    ]
}

/// Props a number of [`CanisterHttpResponseShare`]s of the same [`CanisterId`] but with
/// different hash values, indicating that the other nodes did not see the same response.
///
/// If there are enough of such responses, a properly working payload builder will
/// turn these into a divergence response
fn prop_divergence(
    max_timeout: u64,
    subnet_size: usize,
) -> impl Strategy<Value = Vec<CanisterHttpResponseShare>> {
    (
        1..subnet_size,
        prop_random_metadata(max_timeout),
        any::<[u8; 32]>(),
    )
        .prop_map(|(num_nodes, metadata, new_hash)| {
            (1..=num_nodes)
                .map(|node_id| {
                    let mut metadata = metadata.clone();
                    metadata.content_hash =
                        CryptoHashOf::<CanisterHttpResponse>::new(CryptoHash(new_hash.to_vec()));
                    metadata_to_share(node_id as u64, &metadata)
                })
                .collect::<Vec<CanisterHttpResponseShare>>()
        })
}

// TODO: Prop timeouts
