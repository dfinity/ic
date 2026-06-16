use crate::payload_builder::tests::{
    add_own_share_to_pool, add_received_shares_to_pool, inject_request_contexts, metadata_to_share,
    metadata_to_shares, request_context, test_config_with_http_feature, test_proposal_context,
};
use ic_error_types::RejectCode;
use ic_interfaces::batch_payload::{BatchPayloadBuilder, PastPayload};
use ic_test_utilities_types::ids::{canister_test_id, node_test_id};
use ic_types::{
    CountBytes, Height, NodeId, NumBytes, RegistryVersion, ReplicaVersion, Time,
    batch::ValidationContext,
    canister_http::{
        CANISTER_HTTP_TIMEOUT_INTERVAL, CanisterHttpReject, CanisterHttpRequestContext,
        CanisterHttpResponse, CanisterHttpResponseContent, CanisterHttpResponseMetadata,
        CanisterHttpResponseShare, Replication,
    },
    crypto::{CryptoHash, CryptoHashOf, crypto_hash},
    messages::CallbackId,
    time::UNIX_EPOCH,
};
use proptest::{arbitrary::any, prelude::*};
use std::{
    collections::BTreeSet,
    ops::DerefMut,
    sync::atomic::{AtomicUsize, Ordering},
};

const SUBNET_SIZE: usize = 13;
const MAX_PAYLOAD_SIZE_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESPONSE_BODY_BYTES: usize = 4_000;

/// Validation context time used by the proptest
/// - a request timestamped at `UNIX_EPOCH` is considered timed out, since
///   `UNIX_EPOCH + CANISTER_HTTP_TIMEOUT_INTERVAL < validation_time()`;
/// - a request timestamped at `validation_time()` is not, since
///   `validation_time() + CANISTER_HTTP_TIMEOUT_INTERVAL > validation_time()`.
fn validation_time() -> Time {
    UNIX_EPOCH + 2 * CANISTER_HTTP_TIMEOUT_INTERVAL
}

const PROPTEST_CASES: u32 = 256;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: PROPTEST_CASES,
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
        /// where no response has reached the local node's pool yet).
        designated_content: Option<CanisterHttpResponseContent>,
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
    /// `(response, share)` pairs to load into the pool so that the share is
    /// validated and its body lands in the `content` section. In production
    /// this corresponds either to the local node having produced the share
    /// itself, or — for `NonReplicated`/`Flexible` — to a peer gossiping the
    /// share bundled with its content.
    with_content: Vec<(CanisterHttpResponse, CanisterHttpResponseShare)>,
    /// Shares to load into the pool with no associated content body. In
    /// production this is what `FullyReplicated` peer-gossip looks like (the
    /// content is expected to be reachable via the local node's own copy by
    /// hash). The other modes never gossip content-less shares, so this is
    /// always empty.
    share_only: Vec<CanisterHttpResponseShare>,
}

fn run_proptest(
    number_of_rounds: u64,
    scenario_inputs: Vec<ScenarioInput>,
    extra_random_shares: Vec<CanisterHttpResponseShare>,
) {
    let context = ValidationContext {
        registry_version: RegistryVersion::new(1),
        certified_height: Height::new(0),
        time: validation_time(),
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
                    for (response, share) in &scenario.with_content {
                        add_own_share_to_pool(pool_access.deref_mut(), share, response);
                    }
                }
                let share_only: Vec<_> = scenarios
                    .iter()
                    .flat_map(|s| s.share_only.iter().cloned())
                    .chain(extra_random_shares)
                    .collect();
                add_received_shares_to_pool(pool_access.deref_mut(), share_only);
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

            // Sanity check: Across all cases, at least one must have produced a non-empty payload.
            static CASES_RUN: AtomicUsize = AtomicUsize::new(0);
            static CASES_NONEMPTY: AtomicUsize = AtomicUsize::new(0);
            if past_payloads.iter().any(|p| !p.is_empty()) {
                CASES_NONEMPTY.fetch_add(1, Ordering::Relaxed);
            }
            let cases = CASES_RUN.fetch_add(1, Ordering::Relaxed) + 1;
            if cases == PROPTEST_CASES as usize {
                assert!(
                    CASES_NONEMPTY.load(Ordering::Relaxed) > 0,
                    "all {PROPTEST_CASES} proptest cases produced empty payloads",
                );
            }
        },
    );
}

fn build_scenario(callback_id: CallbackId, input: ScenarioInput) -> Scenario {
    let mut scenario = match input.kind {
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
            designated_content,
        } => build_non_replicated(callback_id, designated_node, designated_content),
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

    scenario.request_context.time = if input.timed_out {
        UNIX_EPOCH
    } else {
        validation_time()
    };
    scenario
}

fn build_fully_replicated(
    callback_id: CallbackId,
    num_main_shares: usize,
    content: CanisterHttpResponseContent,
    num_divergent_shares: usize,
    divergent_hash: [u8; 32],
) -> Scenario {
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

    let mut with_content = vec![];
    let mut share_only = vec![];
    if let Some(first_share) = main_shares.first().cloned() {
        with_content.push((response, first_share));
        share_only.extend(main_shares.into_iter().skip(1));
    }
    share_only.extend(divergent_shares);

    Scenario {
        request_context: request_context(Replication::FullyReplicated),
        with_content,
        share_only,
    }
}

fn build_non_replicated(
    callback_id: CallbackId,
    designated_node: u64,
    designated_content: Option<CanisterHttpResponseContent>,
) -> Scenario {
    let with_content = designated_content
        .map(|content| {
            let response = CanisterHttpResponse {
                id: callback_id,
                canister_id: canister_test_id(0),
                content,
            };
            let share = metadata_to_share(designated_node, &make_metadata(&response));
            (response, share)
        })
        .into_iter()
        .collect();
    Scenario {
        request_context: request_context(Replication::NonReplicated(node_test_id(designated_node))),
        with_content,
        share_only: vec![],
    }
}

fn build_flexible(
    callback_id: CallbackId,
    committee_size: usize,
    min_responses: u32,
    max_responses: u32,
    member_contents: Vec<Option<CanisterHttpResponseContent>>,
) -> Scenario {
    let with_content: Vec<_> = member_contents
        .into_iter()
        .enumerate()
        .filter_map(|(idx, maybe_content)| {
            let content = maybe_content?;
            let response = CanisterHttpResponse {
                id: callback_id,
                canister_id: canister_test_id(0),
                content,
            };
            let share = metadata_to_share(idx as u64, &make_metadata(&response));
            Some((response, share))
        })
        .collect();
    let committee: BTreeSet<NodeId> = (0..committee_size as u64).map(node_test_id).collect();
    Scenario {
        request_context: request_context(Replication::Flexible {
            committee,
            min_responses,
            max_responses,
        }),
        with_content,
        share_only: vec![],
    }
}

fn make_metadata(response: &CanisterHttpResponse) -> CanisterHttpResponseMetadata {
    CanisterHttpResponseMetadata {
        id: response.id,
        content_hash: crypto_hash(response),
        content_size: response.content.count_bytes() as u32,
        is_reject: response.content.is_reject(),
        registry_version: RegistryVersion::new(1),
        replica_version: ReplicaVersion::default(),
        subnet_size: 4,
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
            let random_shares = random_share_groups
                .into_iter()
                .chain(divergence_groups)
                .flatten()
                .collect();
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
    (0..=subnet_size)
        .prop_flat_map(move |num_main_shares| {
            (
                Just(num_main_shares),
                0..=subnet_size - num_main_shares,
                prop_content(max_size),
                any::<[u8; 32]>(),
            )
        })
        .prop_map(
            |(num_main_shares, num_divergent_shares, content, divergent_hash)| {
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
            |(designated_node, designated_content)| ScenarioKind::NonReplicated {
                designated_node,
                designated_content,
            },
        )
}

fn prop_flexible_kind(max_size: usize, subnet_size: usize) -> impl Strategy<Value = ScenarioKind> {
    // committee_size -> min_responses -> max_responses -> member_contents.
    (1..=subnet_size)
        .prop_flat_map(|committee_size| (Just(committee_size), 0_u32..=committee_size as u32))
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

/// Generates random content that is either a success message of length up to
/// `max_size` bytes or a reject message whose description has length up to
/// `max_size` bytes.
fn prop_content(max_size: usize) -> impl Strategy<Value = CanisterHttpResponseContent> {
    prop_oneof![
        (0..=max_size).prop_map(|size| CanisterHttpResponseContent::Success(vec![0; size])),
        (0..=max_size).prop_map(
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
            subnet_size: 4,
        }
    })
}

/// Generates a number of [`CanisterHttpResponseShare`]s for the same random
/// callback id but with a freshly randomized content hash. As with
/// [`prop_random_shares`], the callback id won't match any known request
/// context, so the payload builder is expected to ignore them.
fn prop_divergence(subnet_size: usize) -> impl Strategy<Value = Vec<CanisterHttpResponseShare>> {
    (1..subnet_size, prop_random_metadata(), any::<[u8; 32]>()).prop_map(
        |(num_nodes, mut metadata, new_hash)| {
            metadata.content_hash = CryptoHashOf::new(CryptoHash(new_hash.to_vec()));
            (1..=num_nodes)
                .map(|node_id| metadata_to_share(node_id as u64, &metadata))
                .collect()
        },
    )
}
