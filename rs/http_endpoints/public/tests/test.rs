// Using a `pub mod` works around spurious dead code warnings; see
// https://users.rust-lang.org/t/invalid-dead-code-warning-for-submodule-in-integration-test/80259/2 and
// https://github.com/rust-lang/rust/issues/46379
pub mod common;

use crate::common::{
    create_conn_and_send_request, default_get_latest_state, default_latest_certified_height,
    get_free_localhost_socket_addr,
    test_agent::{self, wait_for_status_healthy},
    HttpEndpointBuilder,
};
use axum::body::{to_bytes, Body};
use bytes::Bytes;
use futures_util::{future::BoxFuture, FutureExt, StreamExt};
use http_body::Frame;
use http_body_util::StreamBody;
use hyper::{body::Incoming, Method, Request, StatusCode};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use ic_agent::{
    agent::http_transport::reqwest_transport::ReqwestTransport, agent_error::HttpErrorPayload,
    export::Principal, hash_tree::Label, Agent, AgentError,
};
use ic_canister_client::{parse_subnet_read_state_response, prepare_read_state};
use ic_canister_client_sender::Sender;
use ic_canonical_state::encoding::types::{Cycles, SubnetMetrics};
use ic_certification_test_utils::{
    serialize_to_cbor, Certificate, CertificateBuilder, CertificateData,
};
use ic_config::http_handler::Config;
use ic_crypto_tree_hash::{
    flatmap, Label as CryptoTreeHashLabel, LabeledTree, MixedHashTree, Path,
};
use ic_error_types::{ErrorCode, RejectCode, UserError};
use ic_interfaces::execution_environment::QueryExecutionError;
use ic_interfaces_mocks::consensus_pool::MockConsensusPoolCache;
use ic_interfaces_registry_mocks::MockRegistryClient;
use ic_interfaces_state_manager::CertifiedStateSnapshot;
use ic_interfaces_state_manager_mocks::MockStateManager;
use ic_protobuf::registry::crypto::v1::{
    AlgorithmId as AlgorithmIdProto, PublicKey as PublicKeyProto,
};
use ic_registry_keys::make_crypto_threshold_signing_pubkey_key;
use ic_replicated_state::ReplicatedState;
use ic_test_utilities_state::ReplicatedStateBuilder;
use ic_test_utilities_types::ids::{canister_test_id, subnet_test_id, user_test_id};
use ic_types::{
    consensus::certification::{Certification, CertificationContent},
    crypto::{
        threshold_sig::{
            ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetSubnet},
            ThresholdSigPublicKey,
        },
        CombinedThresholdSig, CombinedThresholdSigOf, CryptoHash, Signed,
    },
    ingress::WasmResult,
    messages::{Blob, CertificateDelegation},
    signature::ThresholdSignature,
    time::current_time,
    CryptoHashOfPartialState, Height, PrincipalId, RegistryVersion,
};
use prost::Message;
use reqwest::header::CONTENT_TYPE;
use serde_bytes::ByteBuf;
use serde_cbor::value::Value as CBOR;
use std::{
    collections::BTreeMap,
    convert::Infallible,
    net::TcpStream,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::{
    runtime::Runtime,
    time::{sleep, Duration},
};

const TEXT_PLAIN: &str = "text/plain; charset=utf-8";

#[test]
fn test_healthy_behind() {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();
    let config = Config {
        listen_addr: addr,
        ..Default::default()
    };

    // We use this atomic to make sure that the health transition is from healthy -> certified_state_behind
    let healthy = Arc::new(AtomicBool::new(false));
    let healthy_c = healthy.clone();
    let mut mock_consensus_cache = MockConsensusPoolCache::new();
    mock_consensus_cache
        .expect_is_replica_behind()
        .returning(move |_| healthy_c.load(Ordering::SeqCst));

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

    HttpEndpointBuilder::new(rt.handle().clone(), config)
        .with_registry_client(mock_registry_client)
        .with_consensus_cache(mock_consensus_cache)
        .run();

    let agent = Agent::builder()
        .with_transport(ReqwestTransport::create(format!("http://{}", addr)).unwrap())
        .build()
        .unwrap();

    let status = rt.block_on(async {
        wait_for_status_healthy(&addr).await.unwrap();
        healthy.store(true, Ordering::SeqCst);
        agent.status().await.unwrap()
    });

    assert_eq!(
        status.replica_health_status,
        Some("certified_state_behind".to_string())
    );
}

// Check spec enforcement for read_state requests. https://internetcomputer.org/docs/current/references/ic-interface-spec#http-read-state
// Paths containing `.../canister_id/..` require the `canister_id` to be the same as the effective canister id
// specified through the url `/api/v2/canister/<effective_canister_id>/read_state`. Read state requests that request paths
// with different canister ids should be rejected.
#[test]
fn test_unauthorized_controller() {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();
    let config = Config {
        listen_addr: addr,
        ..Default::default()
    };

    HttpEndpointBuilder::new(rt.handle().clone(), config).run();

    let agent = Agent::builder()
        .with_transport(ReqwestTransport::create(format!("http://{}", addr)).unwrap())
        .build()
        .unwrap();

    let canister1 = Principal::from_text("223xb-saaaa-aaaaf-arlqa-cai").unwrap();
    let canister2 = Principal::from_text("224lq-3aaaa-aaaaf-ase7a-cai").unwrap();
    let paths: Vec<Vec<Label<Vec<u8>>>> = vec![vec![
        "canister".into(),
        canister2.as_slice().into(),
        "metadata".into(),
        "time".into(),
    ]];

    let expected_error = AgentError::HttpError(HttpErrorPayload {
        status: 400,
        content_type: Some(TEXT_PLAIN.to_string()),
        content: format!(
            "Effective principal id in URL {} does not match requested principal id: {}.",
            canister1, canister2
        )
        .as_bytes()
        .to_vec(),
    });
    rt.block_on(async {
        wait_for_status_healthy(&addr).await.unwrap();
        assert_eq!(
            agent.read_state_raw(paths.clone(), canister1).await,
            Err(expected_error)
        );
    });
}

// Test that that http endpoint rejects queries with mismatch between canister id an effective canister id.
#[test]
fn test_unauthorized_query() {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();
    let config = Config {
        listen_addr: addr,
        ..Default::default()
    };

    let (_, _, mut query_handler) = HttpEndpointBuilder::new(rt.handle().clone(), config).run();

    let canister1 = "223xb-saaaa-aaaaf-arlqa-cai".parse().unwrap();
    let canister2 = "224lq-3aaaa-aaaaf-ase7a-cai".parse().unwrap();

    // Query mock that returns empty Ok("success") response.
    rt.spawn(async move {
        loop {
            let (_, resp) = query_handler.next_request().await.unwrap();
            resp.send_response(Ok((
                Ok(WasmResult::Reply("success".into())),
                current_time(),
            )))
        }
    });

    rt.block_on(async {
        wait_for_status_healthy(&addr)
            .await
            .expect("Service should become healthy");
    });

    // Valid query call with canister_id = effective_canister_id
    rt.block_on(async move {
        let response = test_agent::Query::new(canister1, canister1)
            .query(addr)
            .await;

        assert_eq!(StatusCode::OK, response.status());
    });

    // Invalid query call with canister_id != effective_canister_id
    rt.block_on(async move {
        let response = test_agent::Query::new(canister1, canister2)
            .query(addr)
            .await;

        assert_eq!(StatusCode::BAD_REQUEST, response.status());

        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .expect("Content type is set.");

        assert_eq!(TEXT_PLAIN, content_type);

        assert_eq!(
            format!(
                "Specified CanisterId {} does not match effective canister id in URL {}",
                canister1, canister2
            ),
            response.text().await.unwrap()
        )
    });
}

// Test that that http endpoint rejects calls with mismatch between canister id an effective canister id.
#[test]
fn test_unauthorized_call() {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();
    let config = Config {
        listen_addr: addr,
        ..Default::default()
    };

    let (mut ingress_filter, _ingress_rx, _) =
        HttpEndpointBuilder::new(rt.handle().clone(), config).run();

    let canister1 = "223xb-saaaa-aaaaf-arlqa-cai".parse().unwrap();
    let canister2 = "224lq-3aaaa-aaaaf-ase7a-cai".parse().unwrap();

    // Ingress filter mock that returns empty Ok(()) response.
    rt.spawn(async move {
        loop {
            let (_, resp) = ingress_filter.next_request().await.unwrap();
            resp.send_response(Ok(()))
        }
    });

    // Wait for the endpoint to be healthy.
    rt.block_on(async {
        wait_for_status_healthy(&addr).await.unwrap();
    });

    // Valid update call with canister_id = effective_canister_id
    rt.block_on(async move {
        let valid_update_call = test_agent::Call::new(canister1, canister1).call(addr).await;

        assert_eq!(
            StatusCode::ACCEPTED,
            valid_update_call.status(),
            "Valid update with, canister_id = effective_canister_id, failed."
        );
    });

    // Invalid update call with canister_id != effective_canister_id
    rt.block_on(async move {
        let invalid_update_call = test_agent::Call::new(canister1, canister2).call(addr).await;

        assert_eq!(
            StatusCode::BAD_REQUEST,
            invalid_update_call.status(),
            "Invalid update with, canister_id != effective_canister_id, succeeded."
        );

        let content_type = invalid_update_call
            .headers()
            .get(CONTENT_TYPE)
            .expect("Content type is set.");

        assert_eq!(TEXT_PLAIN, content_type);

        assert_eq!(
            format!(
                "Specified CanisterId {} does not match effective canister id in URL {}",
                canister1, canister2
            ),
            invalid_update_call.text().await.unwrap()
        );
    });

    let management_canister = PrincipalId::default();
    // Update call to management canister with different effective canister id.
    rt.block_on(async move {
        let valid_update_call = test_agent::Call::new(management_canister, canister2)
            .call(addr)
            .await;

        assert_eq!(
            StatusCode::ACCEPTED,
            valid_update_call.status(),
            "Update call to management canister with different effective canister id failed."
        );
    });

    // Update call to management canister.
    rt.block_on(async move {
        let valid_update_call = test_agent::Call::new(management_canister, management_canister)
            .call(addr)
            .await;

        assert_eq!(
            StatusCode::ACCEPTED,
            valid_update_call.status(),
            "Update call to management canister with same effective canister id failed."
        );
    });
}

/// Once no bytes are read for the duration of 'connection_read_timeout_seconds', then
/// the connection is dropped.
#[tokio::test]
async fn test_connection_read_timeout() {
    let rt_handle = tokio::runtime::Handle::current();
    let addr = get_free_localhost_socket_addr();
    let config = Config {
        listen_addr: addr,
        connection_read_timeout_seconds: 2,
        ..Default::default()
    };

    HttpEndpointBuilder::new(rt_handle.clone(), config.clone()).run();

    let (mut request_sender, status_code) = create_conn_and_send_request(addr).await;
    assert!(status_code == StatusCode::OK);

    sleep(Duration::from_secs(
        config.connection_read_timeout_seconds + 1,
    ))
    .await;
    assert!(request_sender.ready().await.err().unwrap().is_closed());
}

/// If the downstream service is stuck return 504.
#[test]
fn test_request_timeout() {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();
    let request_timeout_seconds = 2;
    let config = Config {
        listen_addr: addr,
        request_timeout_seconds,
        ..Default::default()
    };

    let (_, _, mut query_handler) = HttpEndpointBuilder::new(rt.handle().clone(), config).run();

    rt.spawn(async move {
        loop {
            let (_, resp) = query_handler.next_request().await.unwrap();
            sleep(Duration::from_secs(request_timeout_seconds + 1)).await;
            resp.send_response(Ok((
                Ok(WasmResult::Reply("success".into())),
                current_time(),
            )))
        }
    });

    rt.block_on(async {
        wait_for_status_healthy(&addr).await.unwrap();
        let response = test_agent::Query::default().query(addr).await;
        assert_eq!(StatusCode::GATEWAY_TIMEOUT, response.status());
    });
}

/// Iff a http request body is greater than the configured limit, the endpoints responds with `413`.
#[test]
fn test_payload_too_large() {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();
    let config = Config {
        listen_addr: addr,
        max_request_size_bytes: 2048,
        ..Default::default()
    };

    HttpEndpointBuilder::new(rt.handle().clone(), config.clone()).run();

    let request = |body: Vec<u8>| {
        rt.block_on(async {
            let client = Client::builder(TokioExecutor::new()).build_http();

            let req = Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "http://{}/api/v2/canister/{}/query",
                    addr, "223xb-saaaa-aaaaf-arlqa-cai"
                ))
                .header("Content-Type", "application/cbor")
                .body(Body::from(body))
                .expect("request builder");

            let response = client.request(req).await.unwrap();

            response.status()
        })
    };

    let mut body = vec![0; config.max_request_size_bytes.try_into().unwrap()];
    assert_ne!(StatusCode::PAYLOAD_TOO_LARGE, request(body.clone()));

    body.push(1);
    assert_eq!(StatusCode::PAYLOAD_TOO_LARGE, request(body.clone()));
}

// /// Iff a http request body is slower to arrive than the configured limit, the endpoints responds with `408`.
#[test]
fn test_request_too_slow() {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();
    let config = Config {
        listen_addr: addr,
        request_timeout_seconds: 1,
        ..Default::default()
    };
    HttpEndpointBuilder::new(rt.handle().clone(), config).run();

    rt.block_on(async {
        wait_for_status_healthy(&addr).await.unwrap();
        let initial_fut: BoxFuture<'static, Result<Frame<Bytes>, Infallible>> =
            async { Ok(Frame::data(Bytes::from("hello".as_bytes()))) }.boxed();
        let body =
            StreamBody::new(futures::stream::once(initial_fut).chain(futures::stream::pending()));
        let client = Client::builder(TokioExecutor::new()).build_http();

        let req = Request::builder()
            .method(Method::POST)
            .uri(format!(
                "http://{}/api/v2/canister/{}/query",
                addr, "223xb-saaaa-aaaaf-arlqa-cai"
            ))
            .header("Content-Type", "application/cbor")
            .body(body)
            .expect("request builder");

        let response = client.request(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    })
}

#[test]
fn test_status_code_when_ingress_filter_fails() {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();
    let config = Config {
        listen_addr: addr,
        ..Default::default()
    };

    let (mut ingress_filter, _, _) = HttpEndpointBuilder::new(rt.handle().clone(), config).run();

    // handle the update call
    rt.spawn(async move {
        let request = ingress_filter.next_request().await;
        let (_, send_response) = request.unwrap();

        let response = UserError::new(ErrorCode::IngressHistoryFull, "Test reject message");
        send_response.send_response(Err(response));
    });

    rt.block_on(async move {
        let call_response = test_agent::Call::default().call(addr).await;

        assert_eq!(
            call_response.status(),
            StatusCode::OK,
            "{:?}",
            call_response.text().await.unwrap()
        );

        let expected_response: CBOR = CBOR::Map(BTreeMap::from([
            (
                CBOR::Text("error_code".to_string()),
                CBOR::Text("IC0204".to_string()),
            ),
            (
                CBOR::Text("reject_message".to_string()),
                CBOR::Text("Test reject message".to_string()),
            ),
            (
                CBOR::Text("reject_code".to_string()),
                CBOR::Integer(RejectCode::SysTransient as i128),
            ),
        ]));

        let response_body = call_response.bytes().await.unwrap();
        let cbor_decoded_body = serde_cbor::from_slice::<CBOR>(&response_body)
            .expect("Failed to decode response body.");

        assert_eq!(expected_response, cbor_decoded_body)
    });
}

/// This test verifies that the endpoint can be shutdown gracefully by dropping the runtime.
/// If the shutdown process is not graceful, the test will timeout and fail as dropping the
/// runtime will block until all tasks (including the endpoint) are completed.
#[test]
fn test_graceful_shutdown_of_the_endpoint() {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();
    let config = Config {
        listen_addr: addr,
        ..Default::default()
    };

    HttpEndpointBuilder::new(rt.handle().clone(), config).run();

    rt.block_on(wait_for_status_healthy(&addr)).unwrap();

    let connection_to_endpoint = TcpStream::connect(addr);
    assert!(
        connection_to_endpoint.is_ok(),
        "Connecting to endpoint failed: {:?}.",
        connection_to_endpoint
    );

    // If the shutdown of the endpoint is not "graceful" then the test will timeout
    // because the thread initiating the shutdown blocks until all spawned work has
    // been stopped. This is not ideal.
    // It is unclear if it is possible to set a deadline on the drop operation in order
    // to fail the test instead of timing out.
    drop(rt);

    let connection_to_endpoint = TcpStream::connect(addr);
    assert!(
        connection_to_endpoint.is_err(),
        "Connected to endpoint after shutting down the runtime."
    );
}

/// If a requested path is too long, the endpoint should return early with 404 (NOT FOUND) status code.
#[test]
fn test_too_long_paths_are_rejected() {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();
    let config = Config {
        listen_addr: addr,
        ..Default::default()
    };

    HttpEndpointBuilder::new(rt.handle().clone(), config).run();

    let canister = Principal::from_text("223xb-saaaa-aaaaf-arlqa-cai").unwrap();

    let agent = Agent::builder()
        .with_transport(ReqwestTransport::create(format!("http://{}", addr)).unwrap())
        .build()
        .unwrap();

    let long_path: Vec<Label<Vec<u8>>> = (0..100).map(|i| format!("hallo{}", i).into()).collect();
    let paths = vec![long_path];

    let expected_error_response = AgentError::HttpError(HttpErrorPayload {
        status: 404,
        content_type: Some(TEXT_PLAIN.to_string()),
        content: b"Invalid path requested.".to_vec(),
    });

    let actual_response = rt.block_on(async {
        wait_for_status_healthy(&addr).await.unwrap();
        agent.read_state_raw(paths.clone(), canister).await
    });

    assert_eq!(Err(expected_error_response), actual_response);
}

/// This test verifies that the http endpoint returns 503 (SERVICE_UNAVAILABLE) when the
/// per canister certified state is unavailable. I.e. when the
/// [`QueryExecutionService`](ic_interfaces::execution_environment::QueryExecutionService)
/// returns [QueryExecutionError::CertifiedStateUnavailable`].
#[test]
fn test_query_endpoint_returns_service_unavailable_on_missing_state() {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();
    let config = Config {
        listen_addr: addr,
        ..Default::default()
    };

    let (_, _, mut query_handler) = HttpEndpointBuilder::new(rt.handle().clone(), config).run();

    // Mock the query handler to return CertifiedStateUnavailable.
    rt.spawn(async move {
        loop {
            let (_, resp) = query_handler.next_request().await.unwrap();
            resp.send_response(Err(QueryExecutionError::CertifiedStateUnavailable))
        }
    });

    rt.block_on(async {
        wait_for_status_healthy(&addr).await.unwrap();

        let response = test_agent::Query::default().query(addr).await;
        let expected_status_code = StatusCode::SERVICE_UNAVAILABLE;

        assert_eq!(expected_status_code, response.status());
    })
}

#[test]
fn can_retrieve_subnet_metrics() {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();
    let config = Config {
        listen_addr: addr,
        max_request_size_bytes: 2048,
        ..Default::default()
    };

    let subnet_id = subnet_test_id(1);

    let expected_subnet_metrics = SubnetMetrics {
        num_canisters: 100,
        canister_state_bytes: 5 * 1024 * 1024,
        consumed_cycles_total: Cycles {
            low: 40_000_000_000,
            high: Some(0),
        },
        update_transactions_total: 4235,
    };

    let delegation_from_nns = CertificateBuilder::new(CertificateData::SubnetData {
        subnet_id,
        canister_id_ranges: vec![(canister_test_id(0), canister_test_id(10))],
    });

    let (certificate, root_pk, _cbor) =
        CertificateBuilder::new(CertificateData::CustomTree(LabeledTree::SubTree(flatmap![
            CryptoTreeHashLabel::from("subnet") => LabeledTree::SubTree(flatmap![
                CryptoTreeHashLabel::from(subnet_id.get_ref().to_vec()) => LabeledTree::SubTree(flatmap![
                    CryptoTreeHashLabel::from("metrics") => LabeledTree::Leaf(serialize_to_cbor(&expected_subnet_metrics)),
                ])
            ]),
        ])))
        .with_delegation(delegation_from_nns)
        .build();

    let mock_certified_state = |certificate: Certificate| {
        let hash_tree = certificate.clone().tree();

        let state: Arc<ReplicatedState> = Arc::new(ReplicatedStateBuilder::new().build());
        let certification = Certification {
            height: Height::from(1),
            signed: Signed {
                signature: ThresholdSignature {
                    signer: NiDkgId {
                        start_block_height: Height::from(0),
                        dealer_subnet: subnet_test_id(0),
                        dkg_tag: NiDkgTag::HighThreshold,
                        target_subnet: NiDkgTargetSubnet::Local,
                    },
                    signature: CombinedThresholdSigOf::new(CombinedThresholdSig(
                        certificate.signature().to_vec(),
                    )),
                },
                content: CertificationContent::new(CryptoHashOfPartialState::from(CryptoHash(
                    hash_tree.digest().to_vec(),
                ))),
            },
        };

        (state, hash_tree, certification)
    };

    let mut mock_state_manager = MockStateManager::new();
    mock_state_manager
        .expect_get_latest_state()
        .returning(default_get_latest_state);

    let cloned_certificate = certificate.clone();
    mock_state_manager
        .expect_read_certified_state()
        .returning(move |_| Some(mock_certified_state(cloned_certificate.clone())));
    mock_state_manager
        .expect_latest_certified_height()
        .returning(default_latest_certified_height);

    let cloned_certificate = certificate.clone();
    mock_state_manager
        .expect_get_certified_state_snapshot()
        .returning(move || {
            struct FakeCertifiedStateSnapshot(Arc<ReplicatedState>, MixedHashTree, Certification);

            impl CertifiedStateSnapshot for FakeCertifiedStateSnapshot {
                type State = ReplicatedState;

                fn get_state(&self) -> &ReplicatedState {
                    &self.0
                }

                fn get_height(&self) -> Height {
                    self.2.height
                }

                fn read_certified_state(
                    &self,
                    _paths: &LabeledTree<()>,
                ) -> Option<(MixedHashTree, Certification)> {
                    Some((self.1.clone(), self.2.clone()))
                }
            }

            let (state, hash_tree, certification) = mock_certified_state(certificate.clone());

            Some(Box::new(FakeCertifiedStateSnapshot(
                state,
                hash_tree,
                certification,
            )))
        });

    HttpEndpointBuilder::new(rt.handle().clone(), config)
        .with_state_manager(mock_state_manager)
        .with_delegation_from_nns(
            cloned_certificate
                .delegation()
                .map(|d| CertificateDelegation {
                    subnet_id: d.subnet_id,
                    certificate: d.certificate,
                })
                .expect("Delegation should be present."),
        )
        .run();

    let subnet_id = subnet_test_id(1);

    let request = |body: Vec<u8>| {
        rt.block_on(async {
            wait_for_status_healthy(&addr).await.unwrap();
            let client = Client::builder(TokioExecutor::new()).build_http();

            let req = Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "http://{}/api/v2/subnet/{}/read_state",
                    addr, subnet_id,
                ))
                .header("Content-Type", "application/cbor")
                .body(Body::from(body))
                .expect("request builder");

            client.request(req).await.unwrap()
        })
    };

    let sender = Sender::from_principal_id(user_test_id(1).get());
    let body = prepare_read_state(
        &sender,
        &[Path::new(vec![
            CryptoTreeHashLabel::from("subnet"),
            ByteBuf::from(subnet_id.get().to_vec()).into(),
            CryptoTreeHashLabel::from("metrics"),
        ])],
        Blob(sender.get_principal_id().to_vec()),
    )
    .unwrap();

    let response = request(body.as_ref().to_vec());
    assert_eq!(StatusCode::OK, response.status());

    let bytes = |body: Incoming| rt.block_on(async { to_bytes(Body::new(body), usize::MAX).await });
    let subnet_metrics = parse_subnet_read_state_response(
        &subnet_id,
        Some(&root_pk),
        serde_cbor::from_slice(&bytes(response.into_body()).unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(expected_subnet_metrics, subnet_metrics);
}

#[test]
fn subnet_metrics_not_supported_via_canister_read_state() {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();
    let config = Config {
        listen_addr: addr,
        max_request_size_bytes: 2048,
        ..Default::default()
    };

    HttpEndpointBuilder::new(rt.handle().clone(), config).run();

    let subnet_id = subnet_test_id(1);

    let request = |body: Vec<u8>| {
        rt.block_on(async {
            wait_for_status_healthy(&addr).await.unwrap();
            let client = Client::builder(TokioExecutor::new()).build_http();

            let req = Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "http://{}/api/v2/canister/{}/read_state",
                    addr, "223xb-saaaa-aaaaf-arlqa-cai",
                ))
                .header("Content-Type", "application/cbor")
                .body(Body::from(body))
                .expect("request builder");

            client.request(req).await.unwrap()
        })
    };

    let sender = Sender::from_principal_id(PrincipalId::new_anonymous());
    let body = prepare_read_state(
        &sender,
        &[Path::new(vec![
            CryptoTreeHashLabel::from("subnet"),
            ByteBuf::from(subnet_id.get().to_vec()).into(),
            CryptoTreeHashLabel::from("metrics"),
        ])],
        Blob(sender.get_principal_id().to_vec()),
    )
    .unwrap();

    let response = request(body.as_ref().to_vec());
    assert_eq!(StatusCode::NOT_FOUND, response.status());
}

/// Assert that the endpoint accepts HTTP/2 requests.
#[test]
fn test_http_2_requests_are_accepted() {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();
    let config = Config {
        listen_addr: addr,
        ..Default::default()
    };

    HttpEndpointBuilder::new(rt.handle().clone(), config).run();

    let client = reqwest::ClientBuilder::new()
        .http2_prior_knowledge()
        .build()
        .unwrap();

    let response = rt.block_on(async move {
        client
            .get(format!("http://{}/api/v2/status", addr))
            .header("Content-Type", "application/cbor")
            .send()
            .await
            .unwrap()
    });

    assert!(
        response.status().is_success(),
        "Response was not successful: {:?}.",
        response
    );
    assert_eq!(response.version(), reqwest::Version::HTTP_2);
}

/// Assert that the endpoint accepts HTTP/1.1 requests.
#[test]
fn test_http_1_requests_are_accepted() {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();
    let config = Config {
        listen_addr: addr,
        ..Default::default()
    };

    HttpEndpointBuilder::new(rt.handle().clone(), config).run();

    let client = reqwest::ClientBuilder::new().http1_only().build().unwrap();

    let response = rt.block_on(async move {
        client
            .get(format!("http://{}/api/v2/status", addr))
            .header("Content-Type", "application/cbor")
            .send()
            .await
            .unwrap()
    });

    assert!(
        response.status().is_success(),
        "Response was not successful: {:?}.",
        response
    );
    assert_eq!(response.version(), reqwest::Version::HTTP_11);
}
