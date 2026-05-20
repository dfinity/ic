use crate::payload_builder::tests::{
    add_own_share_to_pool, add_received_shares_to_pool, inject_request_contexts, metadata_to_share,
    metadata_to_shares, request_context, test_config_with_http_feature, test_proposal_context,
};
use ic_error_types::RejectCode;
use ic_interfaces::batch_payload::{BatchPayloadBuilder, PastPayload};
use ic_test_utilities_types::ids::{canister_test_id, node_test_id};
use ic_types::{
    CountBytes, Height, NodeId, NumBytes, RegistryVersion, ReplicaVersion,
    batch::ValidationContext,
    canister_http::{
        CanisterHttpReject, CanisterHttpRequestContext, CanisterHttpResponse,
        CanisterHttpResponseContent, CanisterHttpResponseMetadata, CanisterHttpResponseShare,
        Replication,
    },
    crypto::{CryptoHash, CryptoHashOf, crypto_hash},
    messages::CallbackId,
    time::UNIX_EPOCH,
};
use proptest::{arbitrary::any, prelude::*};
use std::{collections::BTreeSet, ops::DerefMut, time::Duration};

const SUBNET_SIZE: usize = 13;
const MAX_PAYLOAD_SIZE_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESPONSE_BODY_BYTES: usize = 4_000;

/// Validation context time used by the proptest. Picked large enough that
/// requests timestamped at `UNIX_EPOCH` time out (since
/// `CANISTER_HTTP_TIMEOUT_INTERVAL` is 60 seconds), while requests timestamped
/// at `UNIX_EPOCH + NOT_TIMED_OUT_OFFSET_SECS` do not.
const VALIDATION_TIME_SECS: u64 = 200;
const NOT_TIMED_OUT_OFFSET_SECS: u64 = 150;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        max_shrink_time: 60000,
        ..ProptestConfig::default()
    })]

    /// For arbitrary randomized pool/state content, building a payload must
    /// always produce a payload that passes validation, across multiple rounds
    /// (so that the past-payload dedup logic is exercised too) and for all
    /// three replication modes (`FullyReplicated`, `NonReplicated`, `Flexible`)
    /// as well as timed-out requests.
    #[test]
    fn proptest_payload_build_validate_roundtrip(
        (scenarios, random_shares) in prop_artifacts(
            /*max_scenarios=*/ 32,
            /*max_random_share_groups=*/ 500,
            /*max_divergence_groups=*/ 500,
            MAX_RESPONSE_BODY_BYTES,
            SUBNET_SIZE,
        )
    ) {
        run_proptest(10, scenarios, random_shares);
    }
}

/// Per-callback blueprint that's independent of the (eventually assigned)
/// callback id, so that callback ids can be made unique at run time.
#[derive(Clone, Debug)]
struct ScenarioInput {
    kind: ScenarioKind,
    /// If true, the request context will be timestamped such that the request
    /// is considered timed out by the validation context.
    timed_out: bool,
}

#[derive(Clone, Debug)]
enum ScenarioKind {
    FullyReplicated {
        /// Number of shares (from distinct signers) that agree on `content`.
        num_main_shares: usize,
        content: CanisterHttpResponseContent,
        /// Number of shares (from disjoint signers) that disagree, all using
        /// `divergent_hash` as their content hash. Used to (potentially) trip
        /// the divergence-detection path. The associated content is never
        /// added to the pool.
        num_divergent_shares: usize,
        divergent_hash: [u8; 32],
    },
    NonReplicated {
        designated_node: u64,
        /// If `Some`, add the designated node's share together with its
        /// content. If `None`, nothing is added (e.g. simulating the case
        /// where the local node hasn't received any response yet).
        own_content: Option<CanisterHttpResponseContent>,
    },
    Flexible {
        /// Committee size; the committee is `0..committee_size`.
        committee_size: usize,
        min_responses: u32,
        max_responses: u32,
        /// One entry per committee member (in order). `Some(content)` means
        /// the member produced a share signed by it with that content (and
        /// the content was stored locally). `None` means no share from that
        /// member.
        member_contents: Vec<Option<CanisterHttpResponseContent>>,
    },
}

/// A fully resolved scenario, derived from a [`ScenarioInput`] by
/// [`build_scenario`].
struct Scenario {
    request_context: CanisterHttpRequestContext,
    /// `(response, share)` pairs that should be added to the pool with content
    /// (as if the local node had produced them).
    own: Vec<(CanisterHttpResponse, CanisterHttpResponseShare)>,
    /// Shares that should be added to the pool without content (as if they had
    /// been received from peers).
    received: Vec<CanisterHttpResponseShare>,
}

fn run_proptest(
    number_of_rounds: u64,
    scenario_inputs: Vec<ScenarioInput>,
    extra_random_shares: Vec<CanisterHttpResponseShare>,
) {
    let context = ValidationContext {
        registry_version: RegistryVersion::new(1),
        certified_height: Height::new(0),
        time: UNIX_EPOCH + Duration::from_secs(VALIDATION_TIME_SECS),
    };

    test_config_with_http_feature(
        true,
        SUBNET_SIZE,
        |mut payload_builder, canister_http_pool| {
            let scenarios: Vec<_> = scenario_inputs
                .into_iter()
                .enumerate()
                .map(|(idx, input)| build_scenario(CallbackId::new(idx as u64 + 1), input))
                .collect();

            inject_request_contexts(
                &mut payload_builder,
                scenarios.iter().enumerate().map(|(idx, scenario)| {
                    (
                        CallbackId::new(idx as u64 + 1),
                        scenario.request_context.clone(),
                    )
                }),
            );

            {
                let mut pool_access = canister_http_pool.write().unwrap();
                for scenario in &scenarios {
                    for (response, share) in &scenario.own {
                        add_own_share_to_pool(pool_access.deref_mut(), share, response);
                    }
                }
                let received_shares: Vec<_> = scenarios
                    .iter()
                    .flat_map(|s| s.received.iter().cloned())
                    .chain(extra_random_shares)
                    .collect();
                add_received_shares_to_pool(pool_access.deref_mut(), received_shares);
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

                assert!(payload.len() <= MAX_PAYLOAD_SIZE_BYTES);

                let validation_result = payload_builder.validate_payload(
                    Height::new(height),
                    &test_proposal_context(&context),
                    &payload,
                    &pp,
                );
                assert!(
                    validation_result.is_ok(),
                    "built payload failed validation: {validation_result:?}",
                );

                past_payloads.push(payload);
            }
        },
    );
}

fn build_scenario(callback_id: CallbackId, input: ScenarioInput) -> Scenario {
    let request_time = if input.timed_out {
        UNIX_EPOCH
    } else {
        UNIX_EPOCH + Duration::from_secs(NOT_TIMED_OUT_OFFSET_SECS)
    };

    let (replication, own, received) = match input.kind {
        ScenarioKind::FullyReplicated {
            num_main_shares,
            content,
            num_divergent_shares,
            divergent_hash,
        } => build_fully_replicated(
            callback_id,
            num_main_shares,
            content,
            num_divergent_shares,
            divergent_hash,
        ),
        ScenarioKind::NonReplicated {
            designated_node,
            own_content,
        } => build_non_replicated(callback_id, designated_node, own_content),
        ScenarioKind::Flexible {
            committee_size,
            min_responses,
            max_responses,
            member_contents,
        } => build_flexible(
            callback_id,
            committee_size,
            min_responses,
            max_responses,
            member_contents,
        ),
    };

    let mut request_context = request_context(replication);
    request_context.time = request_time;

    Scenario {
        request_context,
        own,
        received,
    }
}

#[allow(clippy::type_complexity)]
fn build_fully_replicated(
    callback_id: CallbackId,
    num_main_shares: usize,
    content: CanisterHttpResponseContent,
    num_divergent_shares: usize,
    divergent_hash: [u8; 32],
) -> (
    Replication,
    Vec<(CanisterHttpResponse, CanisterHttpResponseShare)>,
    Vec<CanisterHttpResponseShare>,
) {
    let response = CanisterHttpResponse {
        id: callback_id,
        canister_id: canister_test_id(0),
        content,
    };
    let metadata = make_metadata(&response);
    let main_shares = metadata_to_shares(num_main_shares, &metadata);

    // Build a metadata group with a different content hash; signers are taken
    // from a disjoint range so signer sets don't overlap.
    let divergent_metadata = CanisterHttpResponseMetadata {
        content_hash: CryptoHashOf::new(CryptoHash(divergent_hash.to_vec())),
        ..metadata
    };
    let divergent_shares: Vec<_> = (num_main_shares..num_main_shares + num_divergent_shares)
        .map(|id| metadata_to_share(id as u64, &divergent_metadata))
        .collect();

    let mut own = vec![];
    let mut received = vec![];
    if let Some(own_share) = main_shares.first().cloned() {
        own.push((response, own_share));
        received.extend(main_shares.into_iter().skip(1));
    }
    received.extend(divergent_shares);

    (Replication::FullyReplicated, own, received)
}

#[allow(clippy::type_complexity)]
fn build_non_replicated(
    callback_id: CallbackId,
    designated_node: u64,
    own_content: Option<CanisterHttpResponseContent>,
) -> (
    Replication,
    Vec<(CanisterHttpResponse, CanisterHttpResponseShare)>,
    Vec<CanisterHttpResponseShare>,
) {
    let mut own = vec![];
    if let Some(content) = own_content {
        let response = CanisterHttpResponse {
            id: callback_id,
            canister_id: canister_test_id(0),
            content,
        };
        let metadata = make_metadata(&response);
        let share = metadata_to_share(designated_node, &metadata);
        own.push((response, share));
    }
    let replication = Replication::NonReplicated(node_test_id(designated_node));
    (replication, own, vec![])
}

#[allow(clippy::type_complexity)]
fn build_flexible(
    callback_id: CallbackId,
    committee_size: usize,
    min_responses: u32,
    max_responses: u32,
    member_contents: Vec<Option<CanisterHttpResponseContent>>,
) -> (
    Replication,
    Vec<(CanisterHttpResponse, CanisterHttpResponseShare)>,
    Vec<CanisterHttpResponseShare>,
) {
    let committee: BTreeSet<NodeId> = (0..committee_size as u64).map(node_test_id).collect();
    let mut own = vec![];
    for (idx, maybe_content) in member_contents.into_iter().enumerate() {
        let Some(content) = maybe_content else {
            continue;
        };
        let response = CanisterHttpResponse {
            id: callback_id,
            canister_id: canister_test_id(0),
            content,
        };
        let metadata = make_metadata(&response);
        let share = metadata_to_share(idx as u64, &metadata);
        own.push((response, share));
    }
    let replication = Replication::Flexible {
        committee,
        min_responses,
        max_responses,
    };
    (replication, own, vec![])
}

fn make_metadata(response: &CanisterHttpResponse) -> CanisterHttpResponseMetadata {
    CanisterHttpResponseMetadata {
        id: response.id,
        content_hash: crypto_hash(response),
        content_size: response.content.count_bytes() as u32,
        is_reject: response.content.is_reject(),
        registry_version: RegistryVersion::new(1),
        replica_version: ReplicaVersion::default(),
    }
}

/// Generates a pool/state blueprint: a list of [`ScenarioInput`]s (one per
/// known callback id) plus a list of additional shares with random callback
/// ids that the payload builder doesn't know about.
fn prop_artifacts(
    max_scenarios: usize,
    max_random_share_groups: usize,
    max_divergence_groups: usize,
    max_size: usize,
    subnet_size: usize,
) -> impl Strategy<Value = (Vec<ScenarioInput>, Vec<CanisterHttpResponseShare>)> {
    (
        prop::collection::vec(
            prop_scenario_input(max_size, subnet_size),
            1..=max_scenarios,
        ),
        prop::collection::vec(prop_random_shares(subnet_size), 0..=max_random_share_groups),
        prop::collection::vec(prop_divergence(subnet_size), 0..=max_divergence_groups),
    )
        .prop_map(|(scenarios, random_share_groups, divergence_groups)| {
            let mut random_shares = vec![];
            for shares in random_share_groups {
                random_shares.extend(shares);
            }
            for shares in divergence_groups {
                random_shares.extend(shares);
            }
            (scenarios, random_shares)
        })
}

fn prop_scenario_input(
    max_size: usize,
    subnet_size: usize,
) -> impl Strategy<Value = ScenarioInput> {
    (prop_scenario_kind(max_size, subnet_size), any::<bool>())
        .prop_map(|(kind, timed_out)| ScenarioInput { kind, timed_out })
}

fn prop_scenario_kind(max_size: usize, subnet_size: usize) -> impl Strategy<Value = ScenarioKind> {
    prop_oneof![
        prop_fully_replicated_kind(max_size, subnet_size),
        prop_non_replicated_kind(max_size, subnet_size),
        prop_flexible_kind(max_size, subnet_size),
    ]
}

fn prop_fully_replicated_kind(
    max_size: usize,
    subnet_size: usize,
) -> impl Strategy<Value = ScenarioKind> {
    // Generate `num_main_shares` first, then `num_divergent_shares` constrained
    // to the remaining signer budget so signer sets between the two groups stay
    // disjoint.
    (prop_content(max_size), any::<[u8; 32]>(), 0..=subnet_size)
        .prop_flat_map(move |(content, divergent_hash, num_main_shares)| {
            let remaining = subnet_size - num_main_shares;
            (
                Just(content),
                Just(divergent_hash),
                Just(num_main_shares),
                0..=remaining,
            )
        })
        .prop_map(
            |(content, divergent_hash, num_main_shares, num_divergent_shares)| {
                ScenarioKind::FullyReplicated {
                    num_main_shares,
                    content,
                    num_divergent_shares,
                    divergent_hash,
                }
            },
        )
}

fn prop_non_replicated_kind(
    max_size: usize,
    subnet_size: usize,
) -> impl Strategy<Value = ScenarioKind> {
    (
        0..subnet_size as u64,
        prop::option::of(prop_content(max_size)),
    )
        .prop_map(
            |(designated_node, own_content)| ScenarioKind::NonReplicated {
                designated_node,
                own_content,
            },
        )
}

fn prop_flexible_kind(max_size: usize, subnet_size: usize) -> impl Strategy<Value = ScenarioKind> {
    // committee_size -> min_responses -> max_responses -> member_contents.
    (1..=subnet_size)
        .prop_flat_map(move |committee_size| (Just(committee_size), 0_u32..=committee_size as u32))
        .prop_flat_map(move |(committee_size, min_responses)| {
            (
                Just(committee_size),
                Just(min_responses),
                min_responses..=committee_size as u32,
                prop::collection::vec(prop::option::of(prop_content(max_size)), committee_size),
            )
        })
        .prop_map(
            |(committee_size, min_responses, max_responses, member_contents)| {
                ScenarioKind::Flexible {
                    committee_size,
                    min_responses,
                    max_responses,
                    member_contents,
                }
            },
        )
}

/// Generates random content that is either a success message of `max_size`
/// length or a reject message whose description has `max_size` length.
fn prop_content(max_size: usize) -> impl Strategy<Value = CanisterHttpResponseContent> {
    prop_oneof![
        (0..max_size).prop_map(|size| CanisterHttpResponseContent::Success(vec![0; size])),
        (0..max_size).prop_map(
            |size| CanisterHttpResponseContent::Reject(CanisterHttpReject {
                reject_code: RejectCode::SysFatal,
                message: "a".repeat(size),
            })
        ),
    ]
}

/// Generates a number of shares (from distinct signers) for a single random
/// metadata. Such shares will have callback ids that don't correspond to any
/// known request context, so the payload builder must ignore them.
fn prop_random_shares(subnet_size: usize) -> impl Strategy<Value = Vec<CanisterHttpResponseShare>> {
    (1..=subnet_size, prop_random_metadata())
        .prop_map(|(num_shares, metadata)| metadata_to_shares(num_shares, &metadata))
}

fn prop_random_metadata() -> impl Strategy<Value = CanisterHttpResponseMetadata> {
    any::<(u64, [u8; 32], u32, bool)>().prop_map(|(id, hash, content_size, is_reject)| {
        CanisterHttpResponseMetadata {
            id: CallbackId::new(id),
            content_hash: CryptoHashOf::new(CryptoHash(hash.to_vec())),
            content_size,
            is_reject,
            registry_version: RegistryVersion::new(1),
            replica_version: ReplicaVersion::default(),
        }
    })
}

/// Generates a number of [`CanisterHttpResponseShare`]s for the same random
/// callback id but with a single (different) content hash. As with
/// [`prop_random_shares`] the callback id won't match any known request
/// context, so the payload builder is expected to ignore them.
fn prop_divergence(subnet_size: usize) -> impl Strategy<Value = Vec<CanisterHttpResponseShare>> {
    (1..subnet_size, prop_random_metadata(), any::<[u8; 32]>()).prop_map(
        |(num_nodes, metadata, new_hash)| {
            (1..=num_nodes)
                .map(|node_id| {
                    let mut metadata = metadata.clone();
                    metadata.content_hash =
                        CryptoHashOf::<CanisterHttpResponse>::new(CryptoHash(new_hash.to_vec()));
                    metadata_to_share(node_id as u64, &metadata)
                })
                .collect::<Vec<CanisterHttpResponseShare>>()
        },
    )
}
