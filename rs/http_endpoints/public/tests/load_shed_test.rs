pub mod common;

use crate::common::{
    basic_consensus_pool_cache, basic_registry_client, basic_state_manager_mock,
    default_get_latest_state, default_latest_certified_height, default_read_certified_state,
    get_free_localhost_socket_addr, start_http_endpoint, wait_for_status_healthy,
};
use http::StatusCode;
use ic_agent::{
    agent::{http_transport::ReqwestHttpReplicaV2Transport, QueryBuilder},
    agent_error::HttpErrorPayload,
    export::Principal,
    hash_tree::Label,
    Agent, AgentError,
};
use ic_config::http_handler::Config;
use ic_interfaces_state_manager_mocks::MockStateManager;
use ic_types::messages::{Blob, HttpQueryResponse, HttpQueryResponseReply};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::{runtime::Runtime, sync::Notify};

/// Test concurrency limiter for `/query` endpoint and that when the load shedder kicks in
/// we return 429.
#[test]
fn test_load_shedding_query() {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();

    let config = Config {
        listen_addr: addr,
        max_query_concurrent_requests: 1,
        ..Default::default()
    };

    let mock_state_manager = basic_state_manager_mock();
    let mock_consensus_cache = basic_consensus_pool_cache();
    let mock_registry_client = basic_registry_client();

    let canister = Principal::from_text("223xb-saaaa-aaaaf-arlqa-cai").unwrap();

    let (_, _, mut query_handler) = start_http_endpoint(
        rt.handle().clone(),
        config,
        Arc::new(mock_state_manager),
        Arc::new(mock_consensus_cache),
        Arc::new(mock_registry_client),
    );

    let query_exec_running = Arc::new(Notify::new());
    let load_shedder_returned = Arc::new(Notify::new());

    let ok_agent = Agent::builder()
        .with_transport(ReqwestHttpReplicaV2Transport::create(format!("http://{}", addr)).unwrap())
        .build()
        .unwrap();

    let query = QueryBuilder::new(&ok_agent, canister, "test".to_string())
        .with_effective_canister_id(canister)
        .sign()
        .unwrap();

    let agent_clone = ok_agent.clone();
    let query_clone = query.clone();
    let load_shedder_returned_clone = load_shedder_returned.clone();
    let query_exec_running_clone = query_exec_running.clone();

    // This agent's request wil be load shedded.
    let load_shedded_agent = rt.spawn(async move {
        query_exec_running_clone.notified().await;

        let resp = agent_clone
            .query_signed(
                query_clone.effective_canister_id,
                query_clone.signed_query.clone(),
            )
            .await;

        load_shedder_returned_clone.notify_one();

        resp
    });

    // Mock query exec service
    rt.spawn(async move {
        let (_, resp) = query_handler.next_request().await.unwrap();
        query_exec_running.notify_one();
        load_shedder_returned.notified().await;

        resp.send_response(HttpQueryResponse::Replied {
            reply: HttpQueryResponseReply {
                arg: Blob("success".into()),
            },
        })
    });

    rt.block_on(async {
        wait_for_status_healthy(&ok_agent).await.unwrap();

        let resp = ok_agent
            .query_signed(query.effective_canister_id, query.signed_query.clone())
            .await;

        assert!(resp.is_ok(), "Received unexpeceted response: {:?}", resp);

        let resp = load_shedded_agent.await.unwrap();
        let expected_resp = StatusCode::TOO_MANY_REQUESTS;

        match resp {
            Err(AgentError::HttpError(HttpErrorPayload { status, .. })) => {
                assert_eq!(expected_resp, status)
            }
            _ => panic!(
                "Load shedder did not kick in. Received unexpeceted response: {:?}",
                resp
            ),
        }
    });
}

/// Test concurrency limiter for `/read_state` endpoint and that when the load shedder kicks in
/// we return 429.
/// Test scenario:
/// 1. Set the read state concurrency limiter to 1.
/// 2. We make two concurrent polls. We expect the last poll request to hit the load shedder.
#[test]
fn test_load_shedding_read_state() {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();

    let config = Config {
        listen_addr: addr,
        max_read_state_concurrent_requests: 1,
        ..Default::default()
    };

    let read_state_running = Arc::new(Notify::new());
    let load_shedder_returned = Arc::new(Notify::new());

    let load_shedder_returned_clone = load_shedder_returned.clone();
    let read_state_running_clone = read_state_running.clone();

    let service_is_healthy = Arc::new(AtomicBool::new(false));
    let service_is_healthy_clone = service_is_healthy.clone();

    let mut mock_state_manager = MockStateManager::new();

    mock_state_manager
        .expect_get_latest_state()
        .returning(default_get_latest_state);

    mock_state_manager
        .expect_latest_certified_height()
        .returning(default_latest_certified_height);

    let rt_clone: tokio::runtime::Handle = rt.handle().clone();
    mock_state_manager
        .expect_read_certified_state()
        .returning(move |labeled_tree| {
            // Need this check, otherwise wait_for_status_healthy() will be stuck.
            // This is due to status endpoint also relying on state_reader_executor.
            if service_is_healthy_clone.load(Ordering::Relaxed) {
                rt_clone.block_on(async {
                    read_state_running.notify_one();
                    load_shedder_returned.notified().await;
                })
            }
            default_read_certified_state(labeled_tree)
        });

    let mock_consensus_cache = basic_consensus_pool_cache();
    let mock_registry_client = basic_registry_client();

    let canister = Principal::from_text("223xb-saaaa-aaaaf-arlqa-cai").unwrap();

    let _ = start_http_endpoint(
        rt.handle().clone(),
        config,
        Arc::new(mock_state_manager),
        Arc::new(mock_consensus_cache),
        Arc::new(mock_registry_client),
    );

    let ok_agent = Agent::builder()
        .with_transport(ReqwestHttpReplicaV2Transport::create(format!("http://{}", addr)).unwrap())
        .build()
        .unwrap();
    let load_shedded_agent = ok_agent.clone();

    let paths: Vec<Vec<Label>> = vec![vec!["time".into()]];
    let paths_clone = paths.clone();

    // This agent's request wil be load shedded
    let load_shedded_agent_resp = rt.spawn(async move {
        read_state_running_clone.notified().await;

        let response = load_shedded_agent
            .read_state_raw(paths_clone, canister)
            .await;

        load_shedder_returned_clone.notify_one();

        response.map(|_| ())
    });

    rt.block_on(async {
        wait_for_status_healthy(&ok_agent).await.unwrap();
        service_is_healthy.store(true, Ordering::Relaxed);

        let response = ok_agent.read_state_raw(paths, canister).await;

        // first request should not hit load shedder
        assert!(
            !(matches!(response, Err(AgentError::HttpError(HttpErrorPayload { status, .. })) if StatusCode::TOO_MANY_REQUESTS == status
            )),
            "Load shedder kicked in. Received unexpeceted response: {:?}", response
        );

        let response = load_shedded_agent_resp.await.unwrap();

        // second request should hit load shedder
        assert!(
            matches!(response, Err(AgentError::HttpError(HttpErrorPayload { status, .. })) if StatusCode::TOO_MANY_REQUESTS == status
            ),
            "Load shedder did not kick in. Received unexpeceted response: {:?}", response
        );
    });
}
