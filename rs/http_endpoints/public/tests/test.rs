// Using a `pub mod` works around spurious dead code warnings; see
// https://users.rust-lang.org/t/invalid-dead-code-warning-for-submodule-in-integration-test/80259/2 and
// https://github.com/rust-lang/rust/issues/46379
pub mod common;

use crate::common::{
    create_conn_and_send_request, default_get_latest_state, default_latest_certified_height,
    default_read_certified_state, get_free_localhost_socket_addr,
    test_agent::{self, wait_for_status_healthy, IngressMessage},
    HttpEndpointBuilder,
};
use axum::body::{to_bytes, Body};
use bytes::Bytes;
use common::test_agent::APPLICATION_CBOR;
use futures_util::{future::BoxFuture, FutureExt, StreamExt};
use http_body::Frame;
use http_body_util::StreamBody;
use hyper::{body::Incoming, Method, Request, StatusCode};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use ic_canister_client::{parse_subnet_read_state_response, prepare_read_state};
use ic_canister_client_sender::Sender;
use ic_canonical_state::encoding::types::{Cycles, SubnetMetrics};
use ic_certification_test_utils::{
    serialize_to_cbor, Certificate as TestCertificate, CertificateBuilder, CertificateData,
};
use ic_config::http_handler::Config;
use ic_crypto_temp_crypto::{NodeKeysToGenerate, TempCryptoComponent};
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
use ic_test_utilities_types::ids::{canister_test_id, subnet_test_id, user_test_id, NODE_1};
use ic_types::{
    artifact::UnvalidatedArtifactMutation,
    consensus::certification::{Certification, CertificationContent},
    crypto::{
        threshold_sig::{
            ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetSubnet},
            ThresholdSigPublicKey,
        },
        CombinedThresholdSig, CombinedThresholdSigOf, CryptoHash, Signed,
    },
    ingress::WasmResult,
    messages::{Blob, Certificate, CertificateDelegation},
    signature::ThresholdSignature,
    time::current_time,
    CryptoHashOfPartialState, Height, PrincipalId, RegistryVersion,
};
use prost::Message;
use reqwest::header::CONTENT_TYPE;
use rstest::rstest;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, SignatureScheme,
};
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
    net::TcpSocket,
    runtime::Runtime,
    time::{sleep, Duration},
};
use tokio_rustls::TlsConnector;

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

    rt.block_on(async {
        wait_for_status_healthy(&addr).await.unwrap();
        healthy.store(true, Ordering::SeqCst);

        let url = format!("http://{}/api/v2/status", addr);

        let response = reqwest::Client::new()
            .get(url)
            .header(CONTENT_TYPE, test_agent::APPLICATION_CBOR)
            .send()
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, response.status());

        let response_body = response.bytes().await.unwrap();

        let replica_status = serde_cbor::from_slice::<CBOR>(&response_body)
            .expect("Status endpoint is a valid CBOR.");

        let CBOR::Map(replica_status) = replica_status else {
            panic!("Expected a map, got {:?}", replica_status);
        };

        let replica_health_status = replica_status
            .get(&CBOR::Text("replica_health_status".to_string()))
            .expect("replica_health_status is present.");

        assert_eq!(
            replica_health_status,
            &CBOR::Text("certified_state_behind".to_string())
        );
    })
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

    let canister1: PrincipalId = "223xb-saaaa-aaaaf-arlqa-cai".parse().unwrap();
    let canister2: PrincipalId = "224lq-3aaaa-aaaaf-ase7a-cai".parse().unwrap();

    let path: Path = vec![
        "canister".into(),
        canister2.as_slice().into(),
        "metadata".into(),
        "time".into(),
    ]
    .into();

    rt.block_on(async {
        wait_for_status_healthy(&addr).await.unwrap();

        let response = test_agent::CanisterReadState::new(vec![path], canister1)
            .read_state(addr)
            .await;

        assert_eq!(StatusCode::BAD_REQUEST, response.status());
        assert_eq!(TEXT_PLAIN, response.headers().get(CONTENT_TYPE).unwrap());
        assert_eq!(
            format!(
                "Effective principal id in URL {} does not match requested principal id: {}.",
                canister1, canister2
            ),
            response.text().await.unwrap()
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

    let mut handlers = HttpEndpointBuilder::new(rt.handle().clone(), config).run();

    let canister1 = "223xb-saaaa-aaaaf-arlqa-cai".parse().unwrap();
    let canister2 = "224lq-3aaaa-aaaaf-ase7a-cai".parse().unwrap();

    // Query mock that returns empty Ok("success") response.
    rt.spawn(async move {
        loop {
            let (_, resp) = handlers.query_execution.next_request().await.unwrap();
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

/// Tests that the HTTP endpoints accepts update calls to the management canister,
/// regardless of the effective canister id.
#[rstest]
fn test_update_call_to_management_canister(
    #[values(test_agent::Call::V2, test_agent::Call::V3)] endpoint: test_agent::Call,
    #[values(PrincipalId::default(), "224lq-3aaaa-aaaaf-ase7a-cai")]
    effective_canister_id: PrincipalId,
) {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();
    let config = Config {
        listen_addr: addr,
        // We set the timeout to 0, such that the replica responds with ACCEPTED instead of OK.
        ingress_message_certificate_timeout_seconds: 0,
        ..Default::default()
    };

    let management_canister = PrincipalId::default();

    let mut handlers = HttpEndpointBuilder::new(rt.handle().clone(), config).run();

    // Ingress filter mock that returns empty Ok(()) response.
    rt.spawn(async move {
        loop {
            let (_, resp) = handlers.ingress_filter.next_request().await.unwrap();
            resp.send_response(Ok(()))
        }
    });

    // Wait for the endpoint to be healthy.
    rt.block_on(async {
        wait_for_status_healthy(&addr).await.unwrap();
        let message =
            IngressMessage::default().with_canister_id(management_canister, effective_canister_id);
        let response = endpoint.call(addr, message).await;

        assert_eq!(
            StatusCode::ACCEPTED,
            response.status(),
            "Update call to management canister failed."
        );
    });
}

// Test that that http endpoint rejects calls with mismatch between canister id an effective canister id.
#[rstest]
fn test_unauthorized_call(
    #[values(test_agent::Call::V2, test_agent::Call::V3)] endpoint: test_agent::Call,
) {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();
    let config = Config {
        ingress_message_certificate_timeout_seconds: 0,
        listen_addr: addr,
        ..Default::default()
    };

    let mut handlers = HttpEndpointBuilder::new(rt.handle().clone(), config).run();

    let canister1 = "223xb-saaaa-aaaaf-arlqa-cai".parse().unwrap();
    let canister2 = "224lq-3aaaa-aaaaf-ase7a-cai".parse().unwrap();

    // Ingress filter mock that returns empty Ok(()) response.
    rt.spawn(async move {
        loop {
            let (_, resp) = handlers.ingress_filter.next_request().await.unwrap();
            resp.send_response(Ok(()))
        }
    });

    // Wait for the endpoint to be healthy.
    rt.block_on(async {
        wait_for_status_healthy(&addr).await.unwrap();
    });

    // Valid update call with canister_id = effective_canister_id
    rt.block_on(async move {
        let message = IngressMessage::default().with_canister_id(canister1, canister1);
        let valid_update_call = endpoint.call(addr, message).await;

        assert_eq!(
            StatusCode::ACCEPTED,
            valid_update_call.status(),
            "Valid update with, canister_id = effective_canister_id, failed."
        );
    });

    // Invalid update call with canister_id != effective_canister_id
    rt.block_on(async move {
        let message = IngressMessage::default().with_canister_id(canister1, canister2);
        let invalid_update_call = endpoint.call(addr, message).await;

        assert_eq!(StatusCode::BAD_REQUEST, invalid_update_call.status());

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

    let mut handlers = HttpEndpointBuilder::new(rt.handle().clone(), config).run();

    rt.spawn(async move {
        loop {
            let (_, resp) = handlers.query_execution.next_request().await.unwrap();
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
            wait_for_status_healthy(&addr).await.unwrap();

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

#[rstest]
#[case(test_agent::Call::V2, CBOR::Map(BTreeMap::from([
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
        ])))]
#[case(test_agent::Call::V3, CBOR::Map(BTreeMap::from([
            (
                CBOR::Text("status".to_string()),
                CBOR::Text("non_replicated_rejection".to_string()),
            ),
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
        ])))]
fn test_status_code_when_ingress_filter_fails(
    #[case] endpoint: test_agent::Call,
    #[case] expected_response: CBOR,
) {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();
    let config = Config {
        listen_addr: addr,
        ..Default::default()
    };

    let mut handlers = HttpEndpointBuilder::new(rt.handle().clone(), config).run();

    // handle the update call
    rt.spawn(async move {
        let request = handlers.ingress_filter.next_request().await;
        let (_, send_response) = request.unwrap();

        let response = UserError::new(ErrorCode::IngressHistoryFull, "Test reject message");
        send_response.send_response(Err(response));
    });

    rt.block_on(async move {
        wait_for_status_healthy(&addr).await.unwrap();
        let message = Default::default();
        let call_response = endpoint.call(addr, message).await;
        assert_eq!(
            call_response.status(),
            StatusCode::OK,
            "{:?}",
            call_response.text().await.unwrap()
        );

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

    let long_path: Path = (0..100)
        .map(|i| format!("hallo{}", i).into())
        .collect::<Vec<CryptoTreeHashLabel>>()
        .into();

    rt.block_on(async move {
        wait_for_status_healthy(&addr).await.unwrap();

        let response = test_agent::CanisterReadState::new(vec![long_path], PrincipalId::default())
            .read_state(addr)
            .await;

        assert_eq!(StatusCode::NOT_FOUND, response.status());
        assert_eq!(TEXT_PLAIN, response.headers().get(CONTENT_TYPE).unwrap());
        assert_eq!("Invalid path requested.", response.text().await.unwrap());
    });
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

    let mut handlers = HttpEndpointBuilder::new(rt.handle().clone(), config).run();

    // Mock the query handler to return CertifiedStateUnavailable.
    rt.spawn(async move {
        loop {
            let (_, resp) = handlers.query_execution.next_request().await.unwrap();
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

    let mock_certified_state = |certificate: TestCertificate| {
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
        wait_for_status_healthy(&addr).await.unwrap();

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

/// Assert that the ALPN protocol negotiation works for HTTP2 and HTTP/1.1.
#[rstest]
#[case("h2", vec![b"h3".to_vec(), b"h2".to_vec(), b"http/1.1".to_vec()])]
#[case("h2", vec![b"h2".to_vec(), b"http/1.1".to_vec()])]
#[case("http/1.1", vec![b"http/1.1".to_vec()])]
fn test_http_alpn_header_is_set(
    #[case] expected_alpn_protocol: &str,
    #[case] client_advertised_alpn_protocols: Vec<Vec<u8>>,
) {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();
    let config = Config {
        listen_addr: addr,
        ..Default::default()
    };

    let server_crypto = TempCryptoComponent::builder()
        .with_node_id(NODE_1)
        .with_keys(NodeKeysToGenerate::only_tls_key_and_cert())
        .build();
    HttpEndpointBuilder::new(rt.handle().clone(), config)
        .with_tls_config(server_crypto)
        .run();

    let socket = TcpSocket::new_v4().unwrap();

    #[derive(Debug)]
    struct NoVerify;
    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer,
            _intermediates: &[CertificateDer],
            _server_name: &ServerName,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ED25519]
        }
    }

    let mut accept_any_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();

    accept_any_config.alpn_protocols = client_advertised_alpn_protocols;

    rt.block_on(async move {
        let stream = socket.connect(addr).await.unwrap();
        let tls_connector = TlsConnector::from(Arc::new(accept_any_config));
        let tls = tls_connector
            .connect("lgtm".try_into().unwrap(), stream)
            .await
            .unwrap();
        let tls_data = tls.into_inner().1;
        let negotiated_alpn_protocol = std::str::from_utf8(
            tls_data
                .alpn_protocol()
                .expect("An ALPN protocol is negotiated."),
        )
        .unwrap();

        assert_eq!(
            negotiated_alpn_protocol, expected_alpn_protocol,
            "Negotiated ALPN protocol is not expected."
        );
    });
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
        wait_for_status_healthy(&addr).await.unwrap();

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

/// Test that the V3 call endpoint handles multiple requests with the same ingress message,
/// by returning `202` for subsequent concurrent requests.
#[test]
fn test_duplicate_requests_are_handled() {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();
    let config = Config {
        listen_addr: addr,
        ..Default::default()
    };

    let mut handlers = HttpEndpointBuilder::new(rt.handle().clone(), config).run();
    let message = IngressMessage::default();

    // Mock ingress filter to always accept the message.
    rt.spawn(async move {
        loop {
            let (_, resp) = handlers.ingress_filter.next_request().await.unwrap();
            resp.send_response(Ok(()))
        }
    });

    let first_request_submitted_to_ingress = Arc::new(tokio::sync::Notify::new());
    let first_request_submitted_to_ingress_clone = first_request_submitted_to_ingress.clone();

    rt.spawn(async move {
        loop {
            let new_ingress = handlers.ingress_rx.recv().await.unwrap();
            let UnvalidatedArtifactMutation::Insert((message, _)) = new_ingress else {
                panic!("Expected Insert");
            };

            let message_id = message.id();

            first_request_submitted_to_ingress_clone.notify_one();
            handlers
                .terminal_state_ingress_messages
                .try_send((message_id, Height::from(1)))
                .unwrap();
        }
    });

    rt.block_on(async {
        wait_for_status_healthy(&addr).await.unwrap();

        let first_request_join_handle = rt.spawn(test_agent::Call::V3.call(addr, message.clone()));
        first_request_submitted_to_ingress.notified().await;

        let second_request = test_agent::Call::V3.call(addr, message.clone()).await;
        handlers
            .certified_height_watcher
            .send(Height::from(1))
            .unwrap();

        assert_eq!(StatusCode::ACCEPTED, second_request.status());
        assert_eq!(
            second_request.text().await.unwrap(),
            "Duplicate request. Message is already being tracked and executed."
        );

        let first_request = first_request_join_handle.await.unwrap();

        assert_eq!(
            StatusCode::OK,
            first_request.status(),
            "{:?}",
            first_request.text().await
        );

        let response_body = first_request.bytes().await.unwrap();
        let response =
            serde_cbor::from_slice::<CBOR>(&response_body).expect("Response is a valid CBOR.");

        let CBOR::Map(response_map) = response else {
            panic!("Expected a map, got {:?}", response);
        };

        assert_eq!(
            response_map.get(&CBOR::Text("status".to_string())),
            Some(&CBOR::Text("replied".to_string()))
        );
    });
}

/// Tests that the endpoint responds with a certificate for ingress messages submitted
/// to the synchronous call.
#[rstest]
/// The message is certified after certified state transition.
#[case(Height::from(0), Some(Height::from(1)), Height::from(1))]
/// The message is already certified.
#[case(Height::from(1), None, Height::from(1))]
#[case(Height::from(1), Some(Height::from(0)), Height::from(1))]
fn test_sync_call_endpoint_responds_with_certificate(
    #[case] initial_certified_height: Height,
    #[case] transitioned_certified_height: Option<Height>,
    #[case] message_finalization_height: Height,
) {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();
    let config = Config {
        listen_addr: addr,
        ..Default::default()
    };

    let mut handlers = HttpEndpointBuilder::new(rt.handle().clone(), config)
        .with_certified_height(initial_certified_height)
        .run();

    let message = IngressMessage::default();

    // Mock ingress filter to always accept the message.
    rt.spawn(async move {
        loop {
            let (_, resp) = handlers.ingress_filter.next_request().await.unwrap();
            resp.send_response(Ok(()))
        }
    });

    rt.spawn(async move {
        let new_ingress = handlers.ingress_rx.recv().await.unwrap();
        let UnvalidatedArtifactMutation::Insert((message, _)) = new_ingress else {
            panic!("Expected Insert");
        };

        let message_id = message.id();
        handlers
            .terminal_state_ingress_messages
            .try_send((message_id, message_finalization_height))
            .unwrap();

        if let Some(transitioned_certified_height) = transitioned_certified_height {
            handlers
                .certified_height_watcher
                .send(transitioned_certified_height)
                .unwrap();
        }
    });

    rt.block_on(async {
        wait_for_status_healthy(&addr).await.unwrap();
        let response = test_agent::Call::V3.call(addr, message).await;

        assert_eq!(
            StatusCode::OK,
            response.status(),
            "{:?}",
            response.text().await
        );

        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            APPLICATION_CBOR,
        );

        let response_body = response.bytes().await.unwrap();
        let response =
            serde_cbor::from_slice::<CBOR>(&response_body).expect("Response is a valid CBOR.");

        let CBOR::Map(response_map) = response else {
            panic!("Expected a map, got {:?}", response);
        };

        assert_eq!(
            response_map.get(&CBOR::Text("status".to_string())),
            Some(&CBOR::Text("replied".to_string()))
        );

        let certificate = match response_map.get(&CBOR::Text("certificate".to_string())) {
            Some(CBOR::Bytes(certificate)) => certificate,
            Some(content) => panic!("Expected bytes for Certificate. Got {:?} instead", content),
            _ => panic!("Reply is missing."),
        };

        let _: Certificate = serde_cbor::from_slice(certificate).expect("Valid certificate");
    });
}

/// Tests that the /v3/.../call endpoint responds with `202 ACCEPTED` for
/// ingress messages that complete execution, but its height never
/// gets certified.
#[test]
fn test_synchronous_call_endpoint_no_certification() {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();
    let config = Config {
        listen_addr: addr,
        ingress_message_certificate_timeout_seconds: 2,
        ..Default::default()
    };

    let mut handlers = HttpEndpointBuilder::new(rt.handle().clone(), config)
        .with_certified_height(Height::from(0))
        .run();

    let message = IngressMessage::default();

    // Mock ingress filter to always accept the message.
    rt.spawn(async move {
        loop {
            let (_, resp) = handlers.ingress_filter.next_request().await.unwrap();
            resp.send_response(Ok(()))
        }
    });

    rt.spawn(async move {
        let new_ingress = handlers.ingress_rx.recv().await.unwrap();
        let UnvalidatedArtifactMutation::Insert((message, _)) = new_ingress else {
            panic!("Expected Insert");
        };
        let message_id = message.id();

        handlers
            .terminal_state_ingress_messages
            .try_send((message_id, Height::from(1)))
            .unwrap();
    });

    rt.block_on(async {
        wait_for_status_healthy(&addr).await.unwrap();
        let response = test_agent::Call::V3.call(addr, message).await;

        assert_eq!(
            StatusCode::ACCEPTED,
            response.status(),
            "{:?}",
            response.text().await
        );
    });
}

struct FakeCertifiedStateSnapshot;

impl CertifiedStateSnapshot for FakeCertifiedStateSnapshot {
    type State = ReplicatedState;

    fn get_state(&self) -> &ReplicatedState {
        unimplemented!()
    }

    fn get_height(&self) -> Height {
        unimplemented!()
    }

    fn read_certified_state(
        &self,
        _paths: &LabeledTree<()>,
    ) -> Option<(MixedHashTree, Certification)> {
        None
    }
}

/// Tests that the /v3/.../call endpoint responds with `202 ACCEPTED` for
/// ingress messages that complete execution and certification
/// but the state reader fails to read the certified state.
#[rstest]
#[case::certified_state_snapshot_unavailable(None)]
#[case::reading_certified_state_fails(Some(Box::new(FakeCertifiedStateSnapshot) as _))]
fn test_call_v3_response_when_state_reader_fails(
    #[case] certified_state_snapshot: Option<
        Box<dyn CertifiedStateSnapshot<State = ReplicatedState>>,
    >,
) {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();
    let config = Config {
        listen_addr: addr,
        max_request_size_bytes: 2048,
        ..Default::default()
    };

    let mut mock_state_manager = MockStateManager::new();
    mock_state_manager
        .expect_get_latest_state()
        .returning(default_get_latest_state);

    mock_state_manager
        .expect_read_certified_state()
        .returning(default_read_certified_state);

    mock_state_manager
        .expect_latest_certified_height()
        .returning(default_latest_certified_height);

    // Inject the mock certified state snapshot
    mock_state_manager
        .expect_get_certified_state_snapshot()
        .return_once(move || certified_state_snapshot);

    let mut handlers = HttpEndpointBuilder::new(rt.handle().clone(), config)
        .with_state_manager(mock_state_manager)
        .run();

    let message = IngressMessage::default();

    // Mock ingress filter to always accept the message.
    rt.spawn(async move {
        loop {
            let (_, resp) = handlers.ingress_filter.next_request().await.unwrap();
            resp.send_response(Ok(()))
        }
    });

    rt.spawn(async move {
        let new_ingress = handlers.ingress_rx.recv().await.unwrap();
        let UnvalidatedArtifactMutation::Insert((message, _)) = new_ingress else {
            panic!("Expected Insert");
        };
        let message_id = message.id();

        // Execute the ingress and certify it.
        handlers
            .terminal_state_ingress_messages
            .try_send((message_id, Height::from(1)))
            .unwrap();
        handlers
            .certified_height_watcher
            .send(Height::from(1))
            .unwrap();
    });

    rt.block_on(async {
        wait_for_status_healthy(&addr).await.unwrap();
        let response = test_agent::Call::V3.call(addr, message).await;
        let status = response.status();
        let text = response.text().await;
        assert_eq!(StatusCode::ACCEPTED, status, "{:?}", text.unwrap());

        assert_eq!(
            "Certified state is not available. Please try /read_state.",
            text.unwrap()
        )
    });
}

/// Tests that the HTTP endpoint return `INTERNAL_SERVER_ERROR`
/// if the call handler is unable to submit the ingress message to
/// P2P.
#[rstest]
fn test_call_response_when_p2p_not_running(
    #[values(test_agent::Call::V2, test_agent::Call::V3)] call_agent: test_agent::Call,
) {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();
    let config = Config {
        listen_addr: addr,
        // We set the timeout to 0, to avoid waiting for subscription.
        ingress_message_certificate_timeout_seconds: 0,
        ..Default::default()
    };

    let mut handlers = HttpEndpointBuilder::new(rt.handle().clone(), config).run();

    // Ingress filter mock that returns empty Ok(()) response.
    rt.spawn(async move {
        loop {
            let (_, resp) = handlers.ingress_filter.next_request().await.unwrap();
            resp.send_response(Ok(()))
        }
    });

    // Wait for the endpoint to be healthy.
    rt.block_on(async {
        wait_for_status_healthy(&addr).await.unwrap();
        // Drop the P2P receiver to simulate P2P not running.
        drop(handlers.ingress_rx);

        let response = call_agent.call(addr, IngressMessage::default()).await;

        assert_eq!(
            StatusCode::INTERNAL_SERVER_ERROR,
            response.status(),
            "{:?}",
            response.text().await
        );

        assert_eq!(
            "P2P is not running on this node.",
            response.text().await.unwrap()
        );
    });
}
