//! Heavyweight `XNetClient` tests against HTTP servers running in spawned
//! threads.

use super::test_fixtures::*;
use super::*;
use axum::{
    http::{header::CONTENT_TYPE, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, MethodRouter},
    Router,
};
use hyper::Uri;
use ic_crypto_tls_interfaces_mocks::MockTlsConfig;
use ic_protobuf::messaging::xnet::v1 as pb;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_metrics::{fetch_histogram_vec_count, metric_vec, MetricVec};
use ic_test_utilities_types::ids::SUBNET_6;
use ic_types::{xnet::CertifiedStreamSlice, SubnetId};
use std::{net::SocketAddr, sync::Arc};

const DST_SUBNET: SubnetId = SUBNET_6;

const STREAM_BEGIN: u64 = 7;
const STREAM_END: u64 = 10;

async fn proto_axum_response<R, M>(r: R) -> impl IntoResponse
where
    M: ProtoProxy<R>,
{
    let buf = M::proxy_encode(r);

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, "application/x-protobuf".parse().unwrap());
    headers.insert(
        "X-Protobuf-Schema",
        "certified_stream_slice.proto".parse().unwrap(),
    );
    headers.insert(
        "X-Protobuf-Message",
        "xnet.v1.CertifiedStreamSlice".parse().unwrap(),
    );

    (headers, buf)
}

fn make_xnet_client(metrics: &MetricsRegistry, log: ReplicaLogger) -> XNetClientImpl {
    let registry = get_empty_registry_for_test();
    XNetClientImpl::new(
        metrics,
        tokio::runtime::Handle::current(),
        Arc::new(MockTlsConfig::new()) as Arc<_>,
        Arc::new(ProximityMap::new(LOCAL_NODE, registry, metrics, log)),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_success() {
    let metrics = MetricsRegistry::new();
    let slice = get_stream_slice_for_testing();
    let expected = slice.clone();

    let respond_with_slice =
        get(move || proto_axum_response::<_, pb::CertifiedStreamSlice>(slice.clone()));

    let result = with_test_replica_logger(|log| async {
        do_xnet_client_query(make_xnet_client(&metrics, log), respond_with_slice).await
    })
    .await;

    assert_eq!(expected, result.unwrap());
    assert_eq!(
        metric_vec(&[
            (&[("status", "success")], 1),
            (&[("status", "ProxyDecodeError")], 0)
        ]),
        response_counts(&metrics)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_garbage_response() {
    let metrics = MetricsRegistry::new();

    let respond_with_garbage = get(|| async { b"garbage".to_vec() });

    let result = with_test_replica_logger(|log| async {
        do_xnet_client_query(make_xnet_client(&metrics, log), respond_with_garbage).await
    })
    .await;

    match result {
        Err(XNetClientError::ProxyDecodeError(ProxyDecodeError::DecodeError(_))) => (),
        _ => panic!(
            "Expecting Err(ProxyDecodeError(DecodeError(_))), got {:?}",
            result
        ),
    }
    assert_eq!(
        metric_vec(&[
            (&[("status", "success")], 0),
            (&[("status", "ProxyDecodeError")], 1)
        ]),
        response_counts(&metrics)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_invalid_proto() {
    let metrics = MetricsRegistry::new();

    // Respond with an empty slice proto (i.e. `certification == None`).
    let slice = pb::CertifiedStreamSlice::default();
    let respond_with_invalid_proto =
        get(move || proto_axum_response::<_, pb::CertifiedStreamSlice>(slice.clone()));

    let result = with_test_replica_logger(|log| async {
        do_xnet_client_query(make_xnet_client(&metrics, log), respond_with_invalid_proto).await
    })
    .await;

    match result {
        Err(XNetClientError::ProxyDecodeError(ProxyDecodeError::MissingField(_))) => (),
        _ => panic!(
            "Expecting Err(ProxyDecodeError(MissingField(_))), got {:?}",
            result
        ),
    }
    assert_eq!(
        metric_vec(&[
            (&[("status", "success")], 0),
            (&[("status", "ProxyDecodeError")], 1)
        ]),
        response_counts(&metrics)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_no_content() {
    let metrics = MetricsRegistry::new();

    let respond_with_garbage = get(|| async { StatusCode::NO_CONTENT });

    let result = with_test_replica_logger(|log| async {
        do_xnet_client_query(make_xnet_client(&metrics, log), respond_with_garbage).await
    })
    .await;

    match result {
        Err(XNetClientError::NoContent) => (),
        _ => panic!("Expecting Err(NoContent), got {:?}", result),
    }
    assert_eq!(
        metric_vec(&[
            (&[("status", "success")], 0),
            (&[("status", "ProxyDecodeError")], 0)
        ]),
        response_counts(&metrics)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_error_response() {
    let metrics = MetricsRegistry::new();

    let respond_with_error =
        get(|| async { (StatusCode::INTERNAL_SERVER_ERROR, b"Oops".to_vec()) });

    let result = with_test_replica_logger(|log| async {
        do_xnet_client_query(make_xnet_client(&metrics, log), respond_with_error).await
    })
    .await;

    match result {
        Err(XNetClientError::ErrorResponse(hyper::StatusCode::INTERNAL_SERVER_ERROR, _)) => (),
        _ => panic!("Expecting Err(ErrorResponse(_)), got {:?}", result),
    }
    assert_eq!(
        metric_vec(&[
            (&[("status", "success")], 0),
            (&[("status", "ProxyDecodeError")], 0)
        ]),
        response_counts(&metrics)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_request_timeout() {
    let metrics = &MetricsRegistry::new();

    let sleep_when_responding = get(|| async {
        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
    });

    let result = with_test_replica_logger(|log| async {
        do_xnet_client_query(make_xnet_client(metrics, log), sleep_when_responding).await
    })
    .await;

    match result {
        Err(XNetClientError::Timeout) => (),
        _ => panic!("Expected Err(Timeout(_)), got {:?}", result),
    }
    assert_eq!(
        metric_vec(&[
            (&[("status", "success")], 0),
            (&[("status", "ProxyDecodeError")], 0)
        ]),
        response_counts(metrics)
    );
}

// For some reason `bind()` on Darwin behaves the same as `bind() + listen()`,
// which causes the request to block instead of failing. Only run this test on
// Linux.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_request_failed() {
    use nix::sys::socket::{
        bind, getsockname, socket, AddressFamily, SockFlag, SockType, SockaddrIn,
    };

    let metrics = &MetricsRegistry::new();

    // Bind to a port and hold on to it in order to block it from being used by
    // other threads/processes, but don't listen() on it.
    let address = SockaddrIn::new(127, 0, 0, 1, 0);
    let socket = socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .expect("Socket creation failed");
    bind(socket, &address).expect("bind() failed");
    let sa = getsockname::<SockaddrIn>(socket).expect("getsockname() failed");

    // URL to query a server that would be running on the allocated port.
    let url = format!("http://{}", sa).parse::<Uri>().unwrap();

    let result = with_test_replica_logger(|log| async {
        do_async_query(make_xnet_client(metrics, log), url).await
    })
    .await;

    match result {
        Err(XNetClientError::RequestFailed(_)) => (),
        _ => panic!("Expected Err(RequestFailed(_)), got {:?}", result),
    }
    assert_eq!(
        metric_vec(&[
            (&[("status", "success")], 0),
            (&[("status", "ProxyDecodeError")], 0)
        ]),
        response_counts(metrics)
    );
}

/// Returns the result of invoking `xnet_client.query()` against an HTTP server
/// in a spawned thread that processes a single request using `handle_request`.
async fn do_xnet_client_query(
    xnet_client: XNetClientImpl,
    method_router: MethodRouter,
) -> Result<CertifiedStreamSlice, XNetClientError> {
    let router = Router::new().route("/", method_router);
    let socket = start_server(router).await;
    let uri: Uri = format!("http://aaaaa-aa.1@{}:{}", socket.ip(), socket.port())
        .parse::<Uri>()
        .unwrap();

    do_async_query(xnet_client, uri).await
}

/// Helper for synchronously calling `query()` on the given `XNetClientImpl`,
/// with the given URL.
async fn do_async_query(
    xnet_client: XNetClientImpl,
    url: Uri,
) -> Result<CertifiedStreamSlice, XNetClientError> {
    let endpoint = EndpointLocator {
        node_id: LOCAL_NODE,
        url,
        proximity: PeerLocation::Local,
    };
    xnet_client.query(&endpoint).await
}

async fn start_server(router: Router) -> SocketAddr {
    let address = SocketAddr::from(([127, 0, 0, 1], 0));
    let listener = tokio::net::TcpListener::bind(address).await.unwrap();
    let socket = listener.local_addr().unwrap();
    let server = axum::serve(listener, router);
    tokio::spawn(async {
        server.await.unwrap();
    });
    socket
}
/// Generates a stream slice from `DST_SUBNET`.
fn get_stream_slice_for_testing() -> CertifiedStreamSlice {
    make_certified_stream_slice(
        DST_SUBNET,
        StreamConfig {
            message_begin: STREAM_BEGIN,
            message_end: STREAM_END,
            signal_end: 0,
        },
    )
}

/// Fetches the values of the `METRIC_RESPONSE_BODY_SIZE` histograms' `_count`
/// fields for all label values.
pub fn response_counts(metrics: &MetricsRegistry) -> MetricVec<u64> {
    fetch_histogram_vec_count(metrics, METRIC_RESPONSE_BODY_SIZE)
}
