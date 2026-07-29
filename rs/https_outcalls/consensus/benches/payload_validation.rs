//! Benchmark for the validation of canister HTTP outcall
//! payloads.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

use ic_consensus_mocks::{Dependencies, dependencies_with_subnet_params};
use ic_crypto_temp_crypto::{NodeKeysToGenerate, TempCryptoComponent};
use ic_https_outcalls_consensus::payload_builder::CanisterHttpPayloadBuilderImpl;
use ic_interfaces::crypto::BasicSigner;
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::Labeled;
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_features::SubnetFeatures;
use ic_test_utilities::artifact_pool_config::with_test_pool_config;
use ic_test_utilities::state_manager::RefMockStateManager;
use ic_test_utilities_registry::SubnetRecordBuilder;
use ic_test_utilities_types::{
    ids::{canister_test_id, node_test_id, subnet_test_id},
    messages::RequestBuilder,
};
use ic_types::{
    CountBytes, Height, NodeId, NumberOfNodes, RegistryVersion, ReplicaVersion,
    batch::{
        CanisterHttpPayload, FlexibleCanisterHttpResponseWithProof, FlexibleCanisterHttpResponses,
        ValidationContext,
    },
    canister_http::{
        CanisterHttpMethod, CanisterHttpPaymentReceipt, CanisterHttpRequestContext,
        CanisterHttpResponse, CanisterHttpResponseContent, CanisterHttpResponseDivergence,
        CanisterHttpResponseMetadata, CanisterHttpResponseProof, CanisterHttpResponseReceipt,
        CanisterHttpResponseShare, CanisterHttpResponseSignature,
        CanisterHttpResponseWithConsensus, PricingVersion, RefundStatus, Replication,
    },
    consensus::get_faults_tolerated,
    crypto::{BasicSigOf, crypto_hash},
    messages::CallbackId,
    signature::BasicSignature,
    time::UNIX_EPOCH,
};
use ic_types_cycles::CanisterCyclesCostSchedule;

/// Registry version that the whole benchmark operates at. The subnet record,
/// the node signing keys and the responses' metadata all use this version.
const REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(1);

/// A single benchmark configuration. Adjust the counts and `response_size` to
/// benchmark different payload shapes.
#[derive(Clone, Copy)]
struct Config {
    /// Short, human-readable label used as the Criterion benchmark id.
    label: &'static str,
    /// Number of nodes on the subnet (the canister HTTP committee).
    subnet_size: usize,
    /// Number of fully-replicated responses (each verified via an aggregated
    /// `threshold`-of-`subnet_size` basic signature batch).
    num_replicated: usize,
    /// Number of non-replicated responses (each verified via a single-signer
    /// basic signature batch).
    num_non_replicated: usize,
    /// Number of divergence responses (each carries `f + 2` distinct
    /// single-signer shares so that the divergence criterion is met).
    num_divergence: usize,
    /// Number of flexible responses. Each is a group carrying `threshold`
    /// single-signer entries (one per distinct committee node).
    num_flexible: usize,
    /// Size, in bytes, of the (success) content body of every replicated,
    /// non-replicated and flexible response. Divergence shares carry only
    /// metadata, so this size does not affect them.
    response_size: usize,
}

/// The set of payload shapes that get benchmarked. Add or tweak entries here.
const CONFIGS: &[Config] = &[
    Config {
        label: "mixed_subnet34",
        subnet_size: 34,
        num_replicated: 125,
        num_non_replicated: 125,
        num_divergence: 125,
        num_flexible: 125,
        response_size: 4096,
    },
    Config {
        label: "many_replicated_responses_subnet34",
        subnet_size: 34,
        num_replicated: 500,
        num_non_replicated: 0,
        num_divergence: 0,
        num_flexible: 0,
        response_size: 4096,
    },
    Config {
        label: "many_non_replicated_responses_subnet34",
        subnet_size: 34,
        num_replicated: 0,
        num_non_replicated: 500,
        num_divergence: 0,
        num_flexible: 0,
        response_size: 4096,
    },
    Config {
        label: "many_divergence_responses_subnet34",
        subnet_size: 34,
        num_replicated: 0,
        num_non_replicated: 0,
        num_divergence: 500,
        num_flexible: 0,
        response_size: 4096,
    },
    Config {
        label: "many_flexible_responses_subnet34",
        subnet_size: 34,
        num_replicated: 0,
        num_non_replicated: 0,
        num_divergence: 0,
        num_flexible: 500,
        response_size: 4096,
    },
];

/// Everything needed to repeatedly verify a single prebuilt payload.
struct BenchTarget {
    builder: CanisterHttpPayloadBuilderImpl,
    payload: CanisterHttpPayload,
    validation_context: ValidationContext,
    // Kept alive for the lifetime of the benchmark so that the consensus pool
    // (and its cache, held by the builder) and the registry remain valid.
    _deps: Dependencies,
}

fn bench_payload_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("canister_http_payload_verification");

    for config in CONFIGS {
        // Each configuration gets its own temporary consensus pool.
        with_test_pool_config(|pool_config| {
            let target = build_target(pool_config, config);
            group.bench_with_input(BenchmarkId::from_parameter(config.label), config, |b, _| {
                b.iter(|| {
                    black_box(target.builder.validate_canister_http_payload_impl(
                        black_box(&target.payload),
                        black_box(&target.validation_context),
                        black_box(HashSet::new()),
                    ))
                    .expect("validation failed");
                })
            });
        });
    }

    group.finish();
}

/// Builds the payload builder, a valid payload and the matching validation
/// context for the given configuration.
fn build_target(
    pool_config: ic_config::artifact_pool::ArtifactPoolConfig,
    config: &Config,
) -> BenchTarget {
    let subnet_id = subnet_test_id(0);
    let committee: Vec<NodeId> = (0..config.subnet_size)
        .map(|i| node_test_id(i as u64))
        .collect();

    // Subnet record with the canister HTTP feature enabled, at REGISTRY_VERSION.
    let subnet_record = SubnetRecordBuilder::from(&committee)
        .with_features(SubnetFeatures {
            http_requests: true,
            ..SubnetFeatures::default()
        })
        .build();

    let deps = dependencies_with_subnet_params(
        pool_config,
        subnet_id,
        vec![(REGISTRY_VERSION.get(), subnet_record)],
    );

    let registry_client: Arc<dyn RegistryClient> = deps.registry.clone();

    // Give every committee node its own crypto component, each of which
    // generates a node-signing key and registers the corresponding public key
    // in the (shared) registry. These are used to produce real signatures over
    // the responses.
    let signers: Vec<TempCryptoComponent> = committee
        .iter()
        .map(|node_id| {
            TempCryptoComponent::builder()
                .with_registry_client_and_data(
                    registry_client.clone(),
                    deps.registry_data_provider.clone(),
                )
                .with_node_id(*node_id)
                .with_keys_in_registry_version(
                    NodeKeysToGenerate::only_node_signing_key(),
                    REGISTRY_VERSION,
                )
                .build()
        })
        .collect();
    deps.registry.reload();

    // A crypto component used by the payload builder to verify the signatures.
    let crypto = Arc::new(
        TempCryptoComponent::builder()
            .with_registry(registry_client.clone())
            .with_node_id(node_test_id(0))
            .build(),
    );

    let signer = Signer { crypto: &signers };
    let mut builder_state = PayloadAssembler::new(config, &committee);
    let payload = builder_state.assemble(&signer);
    let contexts = builder_state.contexts;

    // State reader holding the request contexts for every callback in the
    // payload. The payload builder reads these at `certified_height`.
    let state_manager = make_state_reader(contexts);

    let builder = CanisterHttpPayloadBuilderImpl::new(
        deps.canister_http_pool.clone(),
        deps.pool.get_cache(),
        crypto,
        state_manager,
        subnet_id,
        registry_client.clone(),
        &MetricsRegistry::new(),
        no_op_logger(),
    );

    BenchTarget {
        builder,
        payload,
        validation_context: validation_context(),
        _deps: deps,
    }
}

/// Helper that signs `CanisterHttpResponseReceipt` with a committee
/// node's crypto component.
struct Signer<'a> {
    crypto: &'a [TempCryptoComponent],
}

impl Signer<'_> {
    fn sign(
        &self,
        node_index: usize,
        receipt_share: &CanisterHttpResponseReceipt,
    ) -> BasicSigOf<CanisterHttpResponseReceipt> {
        self.crypto[node_index]
            .sign_basic(receipt_share)
            .expect("failed to sign response receipt share")
    }
}

/// Accumulates the payload sections and the matching request contexts while
/// keeping track of callback-id allocation.
struct PayloadAssembler<'a> {
    config: &'a Config,
    committee: &'a [NodeId],
    next_callback_id: u64,
    contexts: Vec<(CallbackId, CanisterHttpRequestContext)>,
}

impl<'a> PayloadAssembler<'a> {
    fn new(config: &'a Config, committee: &'a [NodeId]) -> Self {
        Self {
            config,
            committee,
            next_callback_id: 0,
            contexts: Vec::new(),
        }
    }

    fn alloc_callback_id(&mut self) -> u64 {
        let id = self.next_callback_id;
        self.next_callback_id += 1;
        id
    }

    /// Builds a node's contribution to an aggregated proof: a default (zero
    /// spent) payment receipt together with that node's signature over the
    /// corresponding receipt share.
    fn signature(
        &self,
        signer: &Signer,
        node: usize,
        metadata: &CanisterHttpResponseMetadata,
    ) -> CanisterHttpResponseSignature {
        let receipt_share = CanisterHttpResponseReceipt {
            metadata: metadata.clone(),
            payment_receipt: CanisterHttpPaymentReceipt::default(),
        };
        let signature = signer.sign(node, &receipt_share);
        CanisterHttpResponseSignature {
            payment_receipt: receipt_share.payment_receipt,
            signature,
        }
    }

    /// Builds a single signed [`CanisterHttpResponseShare`] (receipt share with
    /// a default, zero-spent payment receipt) for the given node.
    fn share(
        &self,
        signer: &Signer,
        node: usize,
        metadata: CanisterHttpResponseMetadata,
    ) -> CanisterHttpResponseShare {
        let receipt_share = CanisterHttpResponseReceipt {
            metadata,
            payment_receipt: CanisterHttpPaymentReceipt::default(),
        };
        let signature = signer.sign(node, &receipt_share);
        CanisterHttpResponseShare {
            signature: BasicSignature {
                signature,
                signer: self.committee[node],
            },
            content: receipt_share,
        }
    }

    fn assemble(&mut self, signer: &Signer) -> CanisterHttpPayload {
        let subnet_size = self.config.subnet_size;
        let threshold = subnet_size - get_faults_tolerated(subnet_size);
        let faults_tolerated = get_faults_tolerated(subnet_size);
        // A divergence proof needs enough distinctly-signed shares that even
        // adding all remaining (unseen) committee members cannot push any
        // single response above the threshold. Using `f + 2` distinct shares
        // (each its own singleton group) guarantees the criterion is met.
        let divergence_shares = faults_tolerated + 2;
        assert!(
            divergence_shares <= subnet_size,
            "subnet_size {subnet_size} too small for divergence (need >= {divergence_shares})"
        );

        let response_size = self.config.response_size;
        let success_content = || CanisterHttpResponseContent::Success(vec![0_u8; response_size]);

        let mut responses = Vec::new();

        // Fully-replicated responses.
        for _ in 0..self.config.num_replicated {
            let callback_id = self.alloc_callback_id();
            let (response, metadata) = response_and_metadata(callback_id, success_content());
            let signatures = (0..threshold)
                .map(|node| {
                    (
                        self.committee[node],
                        self.signature(signer, node, &metadata),
                    )
                })
                .collect();
            responses.push(CanisterHttpResponseWithConsensus {
                content: response,
                proof: CanisterHttpResponseProof {
                    metadata,
                    signatures,
                },
            });
            self.contexts.push((
                CallbackId::new(callback_id),
                request_context(Replication::FullyReplicated),
            ));
        }

        // Non-replicated responses (a single designated signer).
        for _ in 0..self.config.num_non_replicated {
            let callback_id = self.alloc_callback_id();
            let designated = (callback_id as usize) % subnet_size;
            let (response, metadata) = response_and_metadata(callback_id, success_content());
            let mut signatures = BTreeMap::new();
            signatures.insert(
                self.committee[designated],
                self.signature(signer, designated, &metadata),
            );
            responses.push(CanisterHttpResponseWithConsensus {
                content: response,
                proof: CanisterHttpResponseProof {
                    metadata,
                    signatures,
                },
            });
            self.contexts.push((
                CallbackId::new(callback_id),
                request_context(Replication::NonReplicated(self.committee[designated])),
            ));
        }

        // Divergence responses.
        let mut divergence_responses = Vec::new();
        for _ in 0..self.config.num_divergence {
            let callback_id = self.alloc_callback_id();
            let shares: Vec<CanisterHttpResponseShare> = (0..divergence_shares)
                .map(|node| {
                    // Distinct content per node => distinct content hash =>
                    // every share forms its own singleton group.
                    let content = CanisterHttpResponseContent::Success(
                        format!("divergent-{callback_id}-{node}").into_bytes(),
                    );
                    let (_, metadata) = response_and_metadata(callback_id, content);
                    self.share(signer, node, metadata)
                })
                .collect();
            divergence_responses.push(CanisterHttpResponseDivergence { shares });
            self.contexts.push((
                CallbackId::new(callback_id),
                request_context(Replication::FullyReplicated),
            ));
        }

        // Flexible responses: each group carries `threshold` entries, each
        // signed by a distinct committee node (the nodes agree on the same
        // response content).
        let committee_set: BTreeSet<NodeId> = self.committee.iter().copied().collect();
        let mut flexible_responses = Vec::new();
        for _ in 0..self.config.num_flexible {
            let callback_id = self.alloc_callback_id();
            let (response, metadata) = response_and_metadata(callback_id, success_content());
            let entries = (0..threshold)
                .map(|node| FlexibleCanisterHttpResponseWithProof {
                    response: response.clone(),
                    proof: self.share(signer, node, metadata.clone()),
                })
                .collect();
            flexible_responses.push(FlexibleCanisterHttpResponses {
                callback_id: CallbackId::new(callback_id),
                responses: entries,
            });
            self.contexts.push((
                CallbackId::new(callback_id),
                flexible_request_context(committee_set.clone(), 1, subnet_size as u32),
            ));
        }

        let payload = CanisterHttpPayload {
            responses,
            timeouts: vec![],
            divergence_responses,
            flexible_responses,
            flexible_errors: vec![],
        };

        assert!(
            payload.num_non_timeout_responses()
                <= ic_types::canister_http::CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK,
            "too many responses for a single block"
        );

        payload
    }
}

/// Builds a response and the matching (consistent) metadata at REGISTRY_VERSION.
fn response_and_metadata(
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
        replica_version: ReplicaVersion::default(),
    };
    (response, metadata)
}

fn request_context(replication: Replication) -> CanisterHttpRequestContext {
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

fn flexible_request_context(
    committee: BTreeSet<NodeId>,
    min_responses: u32,
    max_responses: u32,
) -> CanisterHttpRequestContext {
    let mut context = request_context(Replication::Flexible {
        committee,
        min_responses,
        max_responses,
    });
    context.pricing_version = PricingVersion::PayAsYouGo;
    context
}

fn validation_context() -> ValidationContext {
    ValidationContext {
        registry_version: REGISTRY_VERSION,
        certified_height: Height::new(0),
        time: UNIX_EPOCH + std::time::Duration::from_secs(5),
    }
}

/// Builds a state reader whose state at certified height 0 contains the given
/// canister HTTP request contexts.
fn make_state_reader(
    contexts: Vec<(CallbackId, CanisterHttpRequestContext)>,
) -> Arc<RefMockStateManager> {
    let mut state = ic_test_utilities_state::get_initial_state(0, 0);
    for (callback_id, context) in contexts {
        state
            .metadata
            .subnet_call_context_manager
            .canister_http_request_contexts
            .insert(callback_id, context);
    }

    let state_manager = Arc::new(RefMockStateManager::default());
    state_manager
        .get_mut()
        .expect_get_state_at()
        .return_const(Ok(Labeled::new(Height::new(0), Arc::new(state))));
    state_manager
}

criterion_group!(benches, bench_payload_verification);
criterion_main!(benches);
