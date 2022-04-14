//! Heavyweight `XNetClient` tests against HTTP servers running in spawned
//! threads.

use super::test_fixtures::*;
use super::*;
use hyper::Uri;
use ic_protobuf::messaging::xnet::v1 as pb;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_test_utilities::{
    crypto::fake_tls_handshake::FakeTlsHandshake,
    metrics::{fetch_histogram_vec_count, metric_vec, MetricVec},
    types::ids::SUBNET_6,
    with_test_replica_logger,
};
use ic_types::{xnet::CertifiedStreamSlice, SubnetId};
use std::io::Cursor;
use std::sync::Arc;
use std::{net::SocketAddr, sync::Barrier};
use tiny_http::{Request, Response, Server, StatusCode};

const DST_SUBNET: SubnetId = SUBNET_6;

const STREAM_BEGIN: u64 = 7;
const STREAM_END: u64 = 10;

fn proto_tiny_http_response<R, M>(r: R) -> Response<Cursor<Vec<u8>>>
where
    M: ProtoProxy<R>,
{
    use std::str::FromStr;
    let buf = M::proxy_encode(r).expect("Could not serialize response");

    fn header(text: &str) -> tiny_http::Header {
        tiny_http::Header::from_str(text).unwrap()
    }

    let mut response = Response::from_data(buf);
    // Headers borrowed from Spring Framework -- https://bit.ly/32EDqoo -- and Google's Protobuf
    // reference -- https://bit.ly/35Q4yml. Might come in handy for e.g. a browser extension.
    response.add_header(header("Content-Type: application/x-protobuf"));
    response.add_header(header("X-Protobuf-Schema: certified_stream_slice.proto"));
    response.add_header(header("X-Protobuf-Message: xnet.v1.CertifiedStreamSlice"));
    response
}

fn make_xnet_client(metrics: &MetricsRegistry, log: ReplicaLogger) -> XNetClientImpl {
    let registry = get_empty_registry_for_test();
    XNetClientImpl::new(
        metrics,
        tokio::runtime::Handle::current(),
        Arc::new(FakeTlsHandshake::new()) as Arc<_>,
        Arc::new(ProximityMap::new(LOCAL_NODE, registry, metrics, log)),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_success() {
    let metrics = MetricsRegistry::new();
    let slice = get_stream_slice_for_testing();
    let expected = slice.clone();

    let respond_with_slice = move |request: Request| {
        request
            .respond(proto_tiny_http_response::<_, pb::CertifiedStreamSlice>(
                slice.clone(),
            ))
            .unwrap_or_else(|e| panic!("Error responding: {}", e));
    };

    let result = with_test_replica_logger(|log| {
        do_xnet_client_query(make_xnet_client(&metrics, log), respond_with_slice)
    });

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
    let respond_with_garbage = |request: Request| {
        request
            .respond(Response::from_data(b"garbage".to_vec()))
            .unwrap_or_else(|e| panic!("Error responding: {}", e));
    };

    let result = with_test_replica_logger(|log| {
        do_xnet_client_query(make_xnet_client(&metrics, log), respond_with_garbage)
    });

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
    let respond_with_invalid_proto = move |request: Request| {
        let slice = pb::CertifiedStreamSlice::default();
        request
            .respond(proto_tiny_http_response::<_, pb::CertifiedStreamSlice>(
                slice,
            ))
            .unwrap_or_else(|e| panic!("Error responding: {}", e));
    };

    let result = with_test_replica_logger(|log| {
        do_xnet_client_query(make_xnet_client(&metrics, log), respond_with_invalid_proto)
    });

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
    let respond_with_garbage = move |request: Request| {
        request
            .respond(Response::from_data(b"".to_vec()).with_status_code(StatusCode(204)))
            .unwrap_or_else(|e| panic!("Error responding: {}", e));
    };

    let result = with_test_replica_logger(|log| {
        do_xnet_client_query(make_xnet_client(&metrics, log), respond_with_garbage)
    });

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
    let respond_with_error = move |request: Request| {
        request
            .respond(Response::from_data(b"Oops".to_vec()).with_status_code(StatusCode(500)))
            .unwrap_or_else(|e| panic!("Error responding: {}", e));
    };

    let result = with_test_replica_logger(|log| {
        do_xnet_client_query(make_xnet_client(&metrics, log), respond_with_error)
    });

    match result {
        Err(XNetClientError::ErrorResponse(reqwest::StatusCode::INTERNAL_SERVER_ERROR, _)) => (),
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

    // Use a barrier to prevent a response before `XNetClient` times out.
    let barrier = Arc::new(Barrier::new(2));
    let server_barrier = barrier.clone();

    let (server, url) = get_server_and_url_for_test();

    // Server thread.
    let join_handle = std::thread::spawn(move || match server.recv() {
        Ok(request) => {
            // Wait for the `XNetClient` to time out first.
            server_barrier.wait();

            request
                .respond(Response::from_data(b"garbage".to_vec()))
                .unwrap_or_else(|e| panic!("Error responding: {}", e));
        }

        Err(e) => panic!("server.recv() returned error: {}", e),
    });

    let result =
        with_test_replica_logger(|log| do_async_query(make_xnet_client(metrics, log), url));

    // Only let the server proceed after we've timed out.
    barrier.wait();

    // Join the server thread, ensure it didn't panic.
    join_handle
        .join()
        .unwrap_or_else(|e| panic!("Server thread has panicked: {:?}", e));

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
        bind, getsockname, socket, AddressFamily, InetAddr, SockAddr, SockFlag, SockType,
    };

    let metrics = &MetricsRegistry::new();

    // Bind to a port and hold on to it in order to block it from being used by
    // other threads/processes, but don't listen() on it.
    let address = SocketAddr::from(([127, 0, 0, 1], 0));
    let address = SockAddr::new_inet(InetAddr::from_std(&address));
    let socket = socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .expect("Socket creation failed");
    bind(socket, &address).expect("bind() failed");
    let sa = getsockname(socket).expect("getsockname() failed");

    // URL to query a server that would be running on the allocated port.
    let url = format!("http://{}", sa).parse::<Uri>().unwrap();

    let result =
        with_test_replica_logger(|log| do_async_query(make_xnet_client(metrics, log), url));

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
fn do_xnet_client_query<H: Fn(Request) + Send + 'static>(
    xnet_client: XNetClientImpl,
    handle_request: H,
) -> Result<CertifiedStreamSlice, XNetClientError> {
    let (server, uri) = get_server_and_url_for_test();

    // Use a barrier to ensure we only query after the server thread is running.
    let barrier = Arc::new(Barrier::new(2));
    let server_barrier = barrier.clone();

    // Spawn thread to have `server` handle a single request, using
    // `handle_request`.
    let join_handle = std::thread::spawn(move || {
        server_barrier.wait();
        match server.recv() {
            Ok(request) => handle_request(request),

            Err(e) => panic!("server.recv() returned error: {}", e),
        }
    });
    barrier.wait();

    let result = do_async_query(xnet_client, uri);

    // Join the server thread, ensure it didn't panic.
    join_handle
        .join()
        .unwrap_or_else(|e| panic!("Server thread has panicked: {:?}", e));

    result
}

/// Helper for synchronously calling `query()` on the given `XNetClientImpl`,
/// with the given URL.
fn do_async_query(
    xnet_client: XNetClientImpl,
    url: Uri,
) -> Result<CertifiedStreamSlice, XNetClientError> {
    let endpoint = EndpointLocator {
        node_id: LOCAL_NODE,
        url,
        proximity: PeerLocation::Local,
    };
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current()
            .block_on(async move { xnet_client.query(&endpoint).await })
    })
}

/// Creates an HTTP server listening on a free port, returning it and a URL to
/// query it by.
fn get_server_and_url_for_test() -> (Server, Uri) {
    // Create an HTTP server.
    let address = SocketAddr::from(([127, 0, 0, 1], 0));
    let server = Server::http(address).unwrap_or_else(|e| panic!("Failed to start server: {}", e));

    // A URL to query `server`.
    let address = server.server_addr();
    let url = format!("http://aaaaa-aa.1@{}:{}", address.ip(), address.port())
        .parse::<Uri>()
        .unwrap();

    (server, url)
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
