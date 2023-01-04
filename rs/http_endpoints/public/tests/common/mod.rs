use ic_crypto_tree_hash::MixedHashTree;
use ic_error_types::UserError;
use ic_interfaces::execution_environment::{IngressFilterService, QueryExecutionService};
use ic_interfaces_p2p::{IngressError, IngressIngestionService};
use ic_interfaces_registry_mocks::MockRegistryClient;
use ic_interfaces_state_manager::Labeled;
use ic_interfaces_state_manager_mocks::MockStateManager;
use ic_protobuf::registry::{
    crypto::v1::{AlgorithmId as AlgorithmIdProto, PublicKey as PublicKeyProto},
    provisional_whitelist::v1::ProvisionalWhitelist as ProvisionalWhitelistProto,
    subnet::v1::SubnetRecord,
};
use ic_registry_keys::{
    make_crypto_threshold_signing_pubkey_key, make_provisional_whitelist_record_key,
    make_subnet_record_key,
};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_routing_table::{CanisterMigrations, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    BitcoinState, CanisterQueues, NetworkTopology, ReplicatedState, SystemMetadata,
};
use ic_test_utilities::{
    consensus::MockConsensusCache, mock_time, state::ReplicatedStateBuilder,
    types::ids::subnet_test_id,
};
use ic_types::{
    batch::{BatchPayload, ValidationContext},
    consensus::{
        certification::{Certification, CertificationContent},
        dkg::Dealings,
        Block, Payload, Rank,
    },
    crypto::{
        threshold_sig::{
            ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetSubnet},
            ThresholdSigPublicKey,
        },
        CombinedThresholdSig, CombinedThresholdSigOf, CryptoHash, CryptoHashOf, Signed,
    },
    messages::{
        CertificateDelegation, HttpQueryResponse, SignedIngress, SignedIngressContent, UserQuery,
    },
    signature::ThresholdSignature,
    CryptoHashOfPartialState, Height, RegistryVersion,
};
use prost::Message;
use std::{collections::BTreeMap, sync::Arc};
use tower::{util::BoxCloneService, Service, ServiceExt};
use tower_test::mock::Handle;

pub(crate) type IngressFilterHandle =
    Handle<(ProvisionalWhitelist, SignedIngressContent), Result<(), UserError>>;
pub(crate) type IngressIngestionHandle = Handle<SignedIngress, Result<(), IngressError>>;
pub(crate) type QueryExecutionHandle =
    Handle<(UserQuery, Option<CertificateDelegation>), HttpQueryResponse>;

pub(crate) fn setup_query_execution_mock() -> (QueryExecutionService, QueryExecutionHandle) {
    let (service, handle) =
        tower_test::mock::pair::<(UserQuery, Option<CertificateDelegation>), HttpQueryResponse>();

    let infallible_service =
        tower::service_fn(move |request: (UserQuery, Option<CertificateDelegation>)| {
            let mut service_clone = service.clone();
            async move {
                Ok::<HttpQueryResponse, std::convert::Infallible>({
                    service_clone
                        .ready()
                        .await
                        .expect("Mocking Infallible service. Waiting for readiness failed.")
                        .call(request)
                        .await
                        .expect("Mocking Infallible service and can therefore not return an error.")
                })
            }
        });
    (
        tower::ServiceBuilder::new()
            .concurrency_limit(1)
            .service(BoxCloneService::new(infallible_service)),
        handle,
    )
}

#[allow(clippy::type_complexity)]
pub(crate) fn setup_ingress_filter_mock() -> (IngressFilterService, IngressFilterHandle) {
    let (service, handle) = tower_test::mock::pair::<
        (ProvisionalWhitelist, SignedIngressContent),
        Result<(), UserError>,
    >();

    let infallible_service = tower::service_fn(
        move |request: (ProvisionalWhitelist, SignedIngressContent)| {
            let mut service_clone = service.clone();
            async move {
                Ok::<Result<(), UserError>, std::convert::Infallible>({
                    service_clone
                        .ready()
                        .await
                        .expect("Mocking Infallible service. Waiting for readiness failed.")
                        .call(request)
                        .await
                        .expect("Mocking Infallible service and can therefore not return an error.")
                })
            }
        },
    );
    (
        tower::ServiceBuilder::new()
            .concurrency_limit(1)
            .service(BoxCloneService::new(infallible_service)),
        handle,
    )
}

pub(crate) fn setup_ingress_ingestion_mock() -> (IngressIngestionService, IngressIngestionHandle) {
    let (service, handle) = tower_test::mock::pair::<SignedIngress, Result<(), IngressError>>();

    let infallible_service = tower::service_fn(move |request: SignedIngress| {
        let mut service_clone = service.clone();
        async move {
            Ok::<Result<(), IngressError>, std::convert::Infallible>({
                service_clone
                    .ready()
                    .await
                    .expect("Mocking Infallible service. Waiting for readiness failed.")
                    .call(request)
                    .await
                    .expect("Mocking Infallible service and can therefore not return an error.")
            })
        }
    });
    (
        tower::ServiceBuilder::new().service(BoxCloneService::new(infallible_service)),
        handle,
    )
}

// Basic state manager with one subnet (nns) at height 1.
pub(crate) fn basic_state_manager_mock() -> MockStateManager {
    let mut mock_state_manager = MockStateManager::new();
    let mut metadata = SystemMetadata::new(subnet_test_id(1), SubnetType::Application);
    let network_topology = NetworkTopology {
        subnets: BTreeMap::new(),
        routing_table: Arc::new(RoutingTable::default()),
        canister_migrations: Arc::new(CanisterMigrations::default()),
        nns_subnet_id: subnet_test_id(1),
        ecdsa_signing_subnets: Default::default(),
        bitcoin_mainnet_canister_id: None,
        bitcoin_testnet_canister_id: None,
    };
    metadata.network_topology = network_topology;
    mock_state_manager
        .expect_get_latest_state()
        .returning(move || {
            let mut metadata = SystemMetadata::new(subnet_test_id(1), SubnetType::Application);
            metadata.batch_time = mock_time();
            Labeled::new(
                Height::from(1),
                Arc::new(ReplicatedState::new_from_checkpoint(
                    BTreeMap::new(),
                    metadata,
                    CanisterQueues::default(),
                    BitcoinState::default(),
                )),
            )
        });
    mock_state_manager
        .expect_latest_certified_height()
        .returning(move || Height::from(1));
    mock_state_manager
        .expect_read_certified_state()
        .returning(move |_labeled_tree| {
            let rs: Arc<ReplicatedState> = Arc::new(ReplicatedStateBuilder::new().build());
            let mht = MixedHashTree::Leaf(Vec::new());
            let cert = Certification {
                height: Height::from(1),
                signed: Signed {
                    signature: ThresholdSignature {
                        signer: NiDkgId {
                            start_block_height: Height::from(0),
                            dealer_subnet: subnet_test_id(0),
                            dkg_tag: NiDkgTag::HighThreshold,
                            target_subnet: NiDkgTargetSubnet::Local,
                        },
                        signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![])),
                    },
                    content: CertificationContent::new(CryptoHashOfPartialState::from(CryptoHash(
                        vec![],
                    ))),
                },
            };
            Some((rs, mht, cert))
        });
    mock_state_manager
}

// Basic mock consensus pool cache at height 1.
pub(crate) fn basic_consensus_pool_cache() -> MockConsensusCache {
    let mut mock_consensus_cache = MockConsensusCache::new();
    mock_consensus_cache
        .expect_finalized_block()
        .returning(move || {
            Block::new(
                CryptoHashOf::from(CryptoHash(Vec::new())),
                Payload::new(
                    ic_types::crypto::crypto_hash,
                    (
                        BatchPayload::default(),
                        Dealings::new_empty(Height::from(1)),
                        None,
                    )
                        .into(),
                ),
                Height::from(1),
                Rank(456),
                ValidationContext {
                    registry_version: RegistryVersion::from(1),
                    certified_height: Height::from(1),
                    time: mock_time(),
                },
            )
        });
    mock_consensus_cache
}

// Basic registry client mock at version 1
pub(crate) fn basic_registry_client() -> MockRegistryClient {
    let mut mock_registry_client = MockRegistryClient::new();
    mock_registry_client
        .expect_get_latest_version()
        .return_const(RegistryVersion::from(1));
    mock_registry_client
        .expect_get_value()
        .withf(move |key, version| {
            key == make_crypto_threshold_signing_pubkey_key(subnet_test_id(1)).as_str()
                && version == &RegistryVersion::from(1)
        })
        .return_const({
            let pk = PublicKeyProto {
                algorithm: AlgorithmIdProto::ThresBls12381 as i32,
                key_value: [42; ThresholdSigPublicKey::SIZE].to_vec(),
                version: 0,
                proof_data: None,
                timestamp: Some(42),
            };
            let mut v = Vec::new();
            pk.encode(&mut v).unwrap();
            Ok(Some(v))
        });
    // Needed for call requests.
    mock_registry_client
        .expect_get_value()
        .withf(move |key, version| {
            key == make_subnet_record_key(subnet_test_id(1)).as_str()
                && version == &RegistryVersion::from(1)
        })
        .return_const({
            let pk = SubnetRecord {
                max_ingress_bytes_per_message: 1000,
                max_ingress_messages_per_block: 10,
                ..Default::default()
            };
            let mut v = Vec::new();
            pk.encode(&mut v).unwrap();
            Ok(Some(v))
        });
    mock_registry_client
        .expect_get_value()
        .withf(move |key, version| {
            key == make_provisional_whitelist_record_key().as_str()
                && version == &RegistryVersion::from(1)
        })
        .return_const({
            let pk = ProvisionalWhitelistProto {
                list_type: 1,
                ..Default::default()
            };
            let mut v = Vec::new();
            pk.encode(&mut v).unwrap();
            Ok(Some(v))
        });

    mock_registry_client
}
