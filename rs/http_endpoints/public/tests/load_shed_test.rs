pub mod common;

use crate::common::{
    HttpEndpointBuilder, MockIngressPoolThrottler, default_certified_state_reader,
    default_get_latest_state, default_latest_certified_height, default_read_certified_state,
    get_free_localhost_socket_addr,
};
use async_trait::async_trait;
use axum::body::Body;
use hyper::{Method, Request, StatusCode};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use ic_config::http_handler::Config;
use ic_crypto_tree_hash::{Label, Path};
use ic_http_endpoints_public::query;
use ic_http_endpoints_public::read_state;
use ic_http_endpoints_test_agent::{
    self, Call, CanisterReadState, IngressMessage, Query, wait_for_status_healthy,
};
use ic_interfaces_state_manager_mocks::MockStateManager;
use ic_pprof::{Error, PprofCollector};
use ic_types::PrincipalId;
use ic_types::{ingress::WasmResult, time::current_time};
use rstest::rstest;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{runtime::Runtime, sync::Notify};

/// Test concurrency limiter for `/query` endpoint and that when the load shedder kicks in
/// we return 429.
#[rstest]
fn test_load_shedding_query(
    #[values(query::Version::V2, query::Version::V3)] version: query::Version,
) {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();

    let config = Config {
        listen_addr: addr,
        max_query_concurrent_requests: 1,
        ..Default::default()
    };

    let mut handlers = HttpEndpointBuilder::new(rt.handle().clone(), config).run();

    let query_exec_running = Arc::new(Notify::new());
    let load_shedder_returned = Arc::new(Notify::new());

    let load_shedder_returned_clone = load_shedder_returned.clone();
    let query_exec_running_clone = query_exec_running.clone();

    // This request will be load shedded.
    let load_shedded_request = rt.spawn(async move {
        query_exec_running_clone.notified().await;

        let response = Query::new(PrincipalId::default(), PrincipalId::default(), version)
            .query(addr)
            .await;

        load_shedder_returned_clone.notify_one();

        response
    });

    // Mock query exec service
    rt.spawn(async move {
        let (_, resp) = handlers.query_execution.next_request().await.unwrap();
        query_exec_running.notify_one();
        load_shedder_returned.notified().await;

        resp.send_response(Ok((
            Ok(WasmResult::Reply("success".into())),
            current_time(),
        )))
    });

    rt.block_on(async {
        wait_for_status_healthy(&addr).await.unwrap();

        let response = Query::new(PrincipalId::default(), PrincipalId::default(), version)
            .query(addr)
            .await;

        assert_eq!(
            StatusCode::OK,
            response.status(),
            "Received unexpected response: {response:?}"
        );

        let response = load_shedded_request.await.unwrap();

        assert_eq!(
            StatusCode::TOO_MANY_REQUESTS,
            response.status(),
            "Concurrent request was not load shedded.",
        );
    });
}

/// Test concurrency limiter for `/read_state` endpoint and that when the load shedder kicks in
/// we return 429.
/// Test scenario:
/// 1. Set the read state concurrency limiter to 1.
/// 2. We make two concurrent polls. We expect the last poll request to hit the load shedder.
#[rstest]
fn test_load_shedding_read_state(
    #[values(read_state::canister::Version::V2, read_state::canister::Version::V3)]
    version: read_state::canister::Version,
) {
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
                    read_state_running_clone.notify_one();
                    load_shedder_returned_clone.notified().await;
                })
            }
            default_read_certified_state(labeled_tree)
        });

    let service_is_healthy_clone = service_is_healthy.clone();
    let read_state_running_clone = read_state_running.clone();
    let load_shedder_returned_clone = load_shedder_returned.clone();
    let rt_clone: tokio::runtime::Handle = rt.handle().clone();
    mock_state_manager
        .expect_get_certified_state_snapshot()
        .returning(move || {
            // Need this check, otherwise wait_for_status_healthy() will be stuck.
            // This is due to status endpoint also relying on state_reader_executor.
            if service_is_healthy_clone.load(Ordering::Relaxed) {
                rt_clone.block_on(async {
                    read_state_running_clone.notify_one();
                    load_shedder_returned_clone.notified().await;
                })
            }
            default_certified_state_reader()
        });

    let _ = HttpEndpointBuilder::new(rt.handle().clone(), config)
        .with_state_manager(mock_state_manager)
        .run();

    // This agent's request will be load shedded
    let load_shedded_request = rt.spawn(async move {
        read_state_running.notified().await;
        let response = CanisterReadState::new(
            vec![Path::from(Label::from("time"))],
            PrincipalId::default(),
            version,
        )
        .read_state(addr)
        .await;
        load_shedder_returned.notify_one();
        response
    });

    rt.block_on(async {
        wait_for_status_healthy(&addr).await.unwrap();
        service_is_healthy.store(true, Ordering::Relaxed);

        let response = CanisterReadState::new(
            vec![Path::from(Label::from("time"))],
            PrincipalId::default(),
            version,
        )
        .read_state(addr)
        .await;

        assert_eq!(
            StatusCode::OK,
            response.status(),
            "Received unexpected response {:?}",
            response.text().await.unwrap(),
        );

        let response = load_shedded_request.await.unwrap();

        assert_eq!(
            StatusCode::TOO_MANY_REQUESTS,
            response.status(),
            "Load shedder did not kick in."
        );
    });
}

/// Test concurrency limiter for `/_/pprof` endpoints, and that when the load shedder kicks in
/// we return 429.
/// Test scenario:
/// 1. Set the concurrency limiter for pprof services, `max_pprof_concurrent_requests`, to 1.
/// 2. Make 1 get request to `/_/pprof` where we wait before responding.
/// 3. Make requests to endpoints under `/_/prof` expecting them all to be load shedded.
/// 4. Return a response for the first request and ssert it does not get load shedded.
// TODO(MR-683): Address the regression and re-enable.
// #[test]
#[allow(dead_code)]
fn test_load_shedding_pprof() {
    // We have to create this custom MockPprof, as the `MockAll` crate
    // doesn't support async closures in `returning()` yet.
    // See: https://github.com/MystenLabs/sui/issues/5155
    struct MockPprof {
        buffer_filled: Arc<Notify>,
        load_shedded_responses_finished: Arc<Notify>,
    }
    impl MockPprof {
        pub fn new(
            buffer_filled: Arc<Notify>,
            load_shedded_responses_finished: Arc<Notify>,
        ) -> Self {
            Self {
                buffer_filled,
                load_shedded_responses_finished,
            }
        }
    }
    #[async_trait]
    impl PprofCollector for MockPprof {
        async fn profile(&self, _: Duration, _: i32) -> Result<Vec<u8>, Error> {
            Ok(Vec::new())
        }
        async fn flamegraph(&self, _: Duration, _: i32) -> Result<Vec<u8>, Error> {
            self.buffer_filled.notify_one();
            self.load_shedded_responses_finished.notified().await;
            Ok(Vec::new())
        }
    }

    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();

    let buffer_size = 1;

    let config = Config {
        listen_addr: addr,
        max_pprof_concurrent_requests: buffer_size,
        ..Default::default()
    };

    let buffer_filled = Arc::new(Notify::new());
    let load_shedded_responses_finished = Arc::new(Notify::new());

    let mock_pprof = MockPprof::new(
        buffer_filled.clone(),
        load_shedded_responses_finished.clone(),
    );

    let _ = HttpEndpointBuilder::new(rt.handle().clone(), config)
        .with_pprof_collector(mock_pprof)
        .run();

    let flame_graph_req = move || {
        Request::builder()
            .method(Method::GET)
            .uri(format!("http://{}/_/pprof/{}", addr, "flamegraph"))
            .body(Body::empty())
            .expect("request builder")
    };

    let profile_req = move || {
        Request::builder()
            .method(Method::GET)
            .uri(format!("http://{}/_/pprof/{}", addr, "profile"))
            .body(Body::empty())
            .expect("request builder")
    };

    let pprof_base_req = move || {
        Request::builder()
            .method(Method::GET)
            .uri(format!("http://{addr}/_/pprof"))
            .body(Body::empty())
            .expect("request builder")
    };

    // This request will fill the load shedder.
    let ok_request = rt.spawn(async move {
        let client = Client::builder(TokioExecutor::new()).build_http();
        let response = client.request(flame_graph_req()).await.unwrap();
        response.status()
    });

    rt.block_on(async {
        wait_for_status_healthy(&addr).await.unwrap();

        let requests: Vec<Box<dyn Fn() -> Request<Body>>> = vec![
            Box::new(flame_graph_req),
            Box::new(pprof_base_req),
            Box::new(profile_req),
        ];

        buffer_filled.notified().await;

        for request_builder in requests {
            let client = Client::builder(TokioExecutor::new()).build_http();
            let response = client.request(request_builder()).await.unwrap();

            assert_eq!(StatusCode::TOO_MANY_REQUESTS, response.status());
        }

        load_shedded_responses_finished.notify_one();

        assert_eq!(StatusCode::OK, ok_request.await.unwrap())
    });
}

/// Test concurrency limiter for `/v2/.../call` endpoint and that when the load shedder kicks in
/// we return 429.
/// Test scenario:
/// 1. Set the concurrency limiter for the call service, `max_call_concurrent_requests`, to 1.
/// 2. Send an ingress message where we wait with responding for the update call
///    inside the ingress filter service handle.
/// 3. Concurrently make another update call, and assert it hits the load shedder.
#[test]
fn test_load_shedding_update_call() {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();

    let config = Config {
        listen_addr: addr,
        max_call_concurrent_requests: 1,
        ..Default::default()
    };

    let mut handlers = HttpEndpointBuilder::new(rt.handle().clone(), config).run();

    let ingress_filter_running = Arc::new(Notify::new());
    let load_shedder_returned = Arc::new(Notify::new());

    let ingress_filter_running_clone = ingress_filter_running.clone();
    let load_shedder_returned_clone = load_shedder_returned.clone();

    let call_agent = Call::V2;

    let load_shedded_request_handle = rt.spawn(async move {
        ingress_filter_running_clone.notified().await;
        let response = call_agent.call(addr, IngressMessage::default()).await;
        load_shedder_returned_clone.notify_one();
        response
    });

    // Mock ingress filter
    rt.spawn(async move {
        let (_, resp) = handlers.ingress_filter.next_request().await.unwrap();
        ingress_filter_running.notify_one();
        load_shedder_returned.notified().await;
        resp.send_response(Ok(Ok(())))
    });

    rt.block_on(async {
        wait_for_status_healthy(&addr).await.unwrap();
        let response = call_agent.call(addr, IngressMessage::default()).await;
        assert_eq!(
            response.status(),
            StatusCode::ACCEPTED,
            "{:?}",
            response.text().await.unwrap()
        );

        let load_shedded_response = load_shedded_request_handle.await.unwrap();

        assert_eq!(
            StatusCode::TOO_MANY_REQUESTS,
            load_shedded_response.status()
        );
    })
}

/// Test that the call endpoints load shed requests when the ingress pool is full.
#[rstest]
#[case::v2_endpoint(Call::V2)]
#[case::v3_endpoint(Call::V3)]
#[case::v4_endpoint(Call::V4)]
fn test_load_shedding_update_call_when_ingress_pool_is_full(#[case] endpoint: Call) {
    use std::sync::RwLock;

    let rt = Runtime::new().unwrap();

    let mut mock_ingress_pool_throttler = MockIngressPoolThrottler::new();
    mock_ingress_pool_throttler
        .expect_exceeds_threshold()
        .return_const(true);

    let addr = get_free_localhost_socket_addr();
    let config = Config {
        listen_addr: addr,
        ..Default::default()
    };

    let mut _handlers = HttpEndpointBuilder::new(rt.handle().clone(), config)
        .with_ingress_pool_throttler(Arc::new(RwLock::new(mock_ingress_pool_throttler)))
        .run();

    rt.block_on(async move {
        wait_for_status_healthy(&addr).await.unwrap();
        let message = Default::default();
        let call_response = endpoint.call(addr, message).await;
        assert_eq!(
            call_response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{:?}",
            call_response.text().await.unwrap()
        );
    });
}

/// Test that the call endpoints load shed requests when the ingress channel is full.
#[rstest]
#[case::v2_endpoint(Call::V2)]
#[case::v3_endpoint(Call::V3)]
#[case::v4_endpoint(Call::V4)]
fn test_load_shedding_update_call_when_ingress_channel_is_full(#[case] endpoint: Call) {
    let rt = Runtime::new().unwrap();

    let addr = get_free_localhost_socket_addr();
    let config = Config {
        listen_addr: addr,
        ..Default::default()
    };

    let capacity = 5;
    let mut handlers = HttpEndpointBuilder::new(rt.handle().clone(), config)
        .with_ingress_channel_capacity(capacity)
        .run();

    // Mock ingress filter
    rt.spawn(async move {
        loop {
            let (_, resp) = handlers.ingress_filter.next_request().await.unwrap();
            resp.send_response(Ok(Ok(())));
        }
    });

    rt.block_on(async move {
        wait_for_status_healthy(&addr).await.unwrap();
        for _ in 0..capacity {
            let message = Default::default();
            let call_response = endpoint.call(addr, message).await;
            assert_eq!(
                call_response.status(),
                StatusCode::ACCEPTED,
                "{:?}",
                call_response.text().await.unwrap()
            );
        }
        let message = Default::default();
        let call_response = endpoint.call(addr, message).await;
        assert_eq!(
            call_response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{:?}",
            call_response.text().await.unwrap()
        );
    });
}
