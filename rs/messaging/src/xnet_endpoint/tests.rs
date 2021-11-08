use super::*;
use bytes::Bytes;
use ic_interfaces::state_manager::{CertificationScope, StateManager};
use ic_protobuf::{messaging::xnet::v1 as pb, proxy::ProtoProxy};
use ic_replicated_state::{testing::ReplicatedStateTesting, ReplicatedState, Stream};
use ic_test_utilities::{
    crypto::fake_tls_handshake::FakeTlsHandshake,
    metrics::{
        fetch_histogram_stats, fetch_histogram_vec_count, metric_vec, HistogramStats, MetricVec,
    },
    registry::MockRegistryClient,
    state_manager::FakeStateManager,
    types::{
        ids::{canister_test_id, SUBNET_6, SUBNET_7},
        messages::RequestBuilder,
    },
    with_test_replica_logger,
};
use ic_types::{messages::CallbackId, xnet::StreamIndexedQueue, Height, SubnetId};
use maplit::btreemap;
use url::Url;

const SRC_CANISTER: u64 = 2;
const DST_CANISTER: u64 = 3;
const CALLBACK_ID: u64 = 4;
const DST_SUBNET: SubnetId = SUBNET_6;
const UNKNOWN_SUBNET: SubnetId = SUBNET_7;

const STREAM_BEGIN: StreamIndex = StreamIndex::new(7);
const STREAM_COUNT: u64 = 3;

pub(crate) struct EndpointTestFixture {
    pub state_manager: Arc<FakeStateManager>,
    pub registry_client: Arc<MockRegistryClient>,
    pub metrics: MetricsRegistry,
    pub tls_handshake: Arc<dyn TlsHandshake + Send + Sync>,
}

impl EndpointTestFixture {
    pub fn with_replicated_state() -> Self {
        let fixture = EndpointTestFixture::default();
        put_replicated_state_for_testing(Height::new(13), &*fixture.state_manager);
        fixture
    }

    /// Returns the values of the `METRIC_REQUEST_DURATION` histograms' `count`
    /// field for all label value combinations.
    pub fn request_counts(&self) -> MetricVec<u64> {
        fetch_histogram_vec_count(&self.metrics, METRIC_REQUEST_DURATION)
    }

    /// Returns the `METRIC_SLICE_PAYLOAD_SIZE` histogram's stats.
    pub fn slice_payload_size_stats(&self) -> HistogramStats {
        fetch_histogram_stats(&self.metrics, METRIC_SLICE_PAYLOAD_SIZE).unwrap()
    }

    /// Returns the values of the `METRIC_RESPONSE_SIZE` histograms' `count`
    /// field for all label values.
    pub fn response_size_counts(&self) -> MetricVec<u64> {
        fetch_histogram_vec_count(&self.metrics, METRIC_RESPONSE_SIZE)
    }
}

impl Default for EndpointTestFixture {
    fn default() -> EndpointTestFixture {
        EndpointTestFixture {
            metrics: MetricsRegistry::new(),
            state_manager: Arc::new(FakeStateManager::new()),
            registry_client: Arc::new(MockRegistryClient::new()),
            tls_handshake: Arc::new(FakeTlsHandshake::new()),
        }
    }
}

/// Tests the `/api/v1/streams` API endpoint.
///
/// Heavyweight test that starts an `XNetEndpoint` and queries it over HTTP.
#[test]
fn query_streams() {
    with_test_replica_logger(|log| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let fixture = EndpointTestFixture::with_replicated_state();

        let xnet_endpoint = XNetEndpoint::new(
            rt.handle().clone(),
            fixture.state_manager.clone(),
            fixture.tls_handshake.clone(),
            fixture.registry_client.clone(),
            Default::default(),
            &fixture.metrics,
            log,
        );

        let resp = rt.block_on(async move { http_get("/api/v1/streams", &xnet_endpoint).await });

        assert_eq!(format!("[\"{}\"]", DST_SUBNET), resp);
        assert_eq!(
            metric_vec(&[(&[("resource", "streams"), ("status", "200")], 1)]),
            fixture.request_counts()
        );
        assert_eq!(0, fixture.slice_payload_size_stats().count);
        assert_eq!(
            metric_vec(&[(&[("resource", "streams")], 1)]),
            fixture.response_size_counts()
        );
    });
}

/// Tests the `/api/v1/stream/{SubnetId}` API endpoint.
///
/// Heavyweight test that starts an `XNetEndpoint` and queries it over HTTP.
#[test]
fn query_stream() {
    with_test_replica_logger(|log| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let fixture = EndpointTestFixture::with_replicated_state();

        let xnet_endpoint = XNetEndpoint::new(
            rt.handle().clone(),
            fixture.state_manager.clone(),
            fixture.tls_handshake.clone(),
            fixture.registry_client.clone(),
            Default::default(),
            &fixture.metrics,
            log,
        );

        let resp = rt.block_on(async move {
            http_get(
                &format!(
                    "/api/v1/stream/{}?witness_begin={}&msg_begin={}",
                    DST_SUBNET,
                    STREAM_BEGIN,
                    STREAM_BEGIN.increment()
                ),
                &xnet_endpoint,
            )
            .await
        });

        let expected = fixture
            .state_manager
            .encode_certified_stream_slice(
                DST_SUBNET,
                Some(STREAM_BEGIN),
                Some(STREAM_BEGIN.increment()),
                None,
                None,
            )
            .unwrap();
        assert_eq!(
            expected,
            pb::CertifiedStreamSlice::proxy_decode(&resp).unwrap()
        );
        assert_eq!(
            metric_vec(&[(&[("resource", "stream"), ("status", "200")], 1)]),
            fixture.request_counts()
        );
        assert_eq!(1, fixture.slice_payload_size_stats().count);
        assert_eq!(
            metric_vec(&[(&[("resource", "stream")], 1)]),
            fixture.response_size_counts()
        );
    });
}

#[tokio::test]
async fn handle_streams() {
    let fixture = EndpointTestFixture::with_replicated_state();

    let url = Url::parse("http://localhost/api/v1/streams").unwrap();

    let response = route_request(
        url,
        &*fixture.state_manager,
        &XNetEndpointMetrics::new(&fixture.metrics),
    );
    let (parsed_status, body) = parse_response(response).await;

    assert_eq!(
        (200, format!("[\"{}\"]", DST_SUBNET).as_bytes()),
        (parsed_status, body.as_slice())
    );
    assert_eq!(
        metric_vec(&[(&[("resource", "streams"), ("status", "200")], 1)]),
        fixture.request_counts()
    );
    assert_eq!(0, fixture.slice_payload_size_stats().count);
    assert_eq!(
        metric_vec(&[(&[("resource", "streams")], 1)]),
        fixture.response_size_counts()
    );
}

/// Common implementation for all `handle_stream_` methods that query an
/// existing stream.
async fn handle_existing_stream_impl(
    msg_begin: StreamIndex,
    msg_limit: usize,
) -> ((u16, Vec<u8>), EndpointTestFixture) {
    let fixture = EndpointTestFixture::with_replicated_state();

    let url = Url::parse(&format!(
        "http://localhost/api/v1/stream/{}?msg_begin={}&msg_limit={}",
        DST_SUBNET, msg_begin, msg_limit
    ))
    .unwrap();

    let response = route_request(
        url,
        &*fixture.state_manager,
        &XNetEndpointMetrics::new(&fixture.metrics),
    );
    (parse_response(response).await, fixture)
}

/// Asserts that the response has status 200 OK and contains a stream slice from
/// `msg_begin` of length up to `msg_limit` and of size up to `byte_limit`.
fn assert_response_is_slice(
    status_code: u16,
    body: Vec<u8>,
    witness_begin: StreamIndex,
    msg_begin: StreamIndex,
    msg_limit: usize,
    byte_limit: Option<usize>,
) {
    let state_manager = EndpointTestFixture::with_replicated_state().state_manager;
    let expected = state_manager
        .encode_certified_stream_slice(
            DST_SUBNET,
            Some(witness_begin),
            Some(msg_begin),
            Some(msg_limit),
            byte_limit,
        )
        .unwrap();
    assert_eq!(
        (200, expected),
        (
            status_code,
            pb::CertifiedStreamSlice::proxy_decode(&body).unwrap()
        )
    );
}

/// Asserts that the response has status 416 Range Not Satisfiable and contains
/// an index out of bounds error message.
fn assert_response_is_index_out_of_bounds(status_code: u16, body: Vec<u8>, msg_begin: StreamIndex) {
    assert_eq!(
        (
            416,
            format!(
                "Requested slice begin {} is outside of stream message bounds [{}, {})",
                msg_begin,
                STREAM_BEGIN,
                STREAM_BEGIN.get() + STREAM_COUNT
            )
        ),
        (status_code, String::from_utf8_lossy(body.as_slice()).into())
    );
}

#[tokio::test]
async fn handle_stream_index_before_begin() {
    let (msg_begin, msg_limit) = (STREAM_BEGIN.decrement(), 1);

    let ((status_code, body), fixture) = handle_existing_stream_impl(msg_begin, msg_limit).await;

    assert_response_is_index_out_of_bounds(status_code, body, msg_begin);
    assert_eq!(
        metric_vec(&[(&[("resource", "stream"), ("status", "416")], 1)]),
        fixture.request_counts()
    );
    assert_eq!(0, fixture.slice_payload_size_stats().count);
    assert!(fixture.response_size_counts().is_empty());
}

#[tokio::test]
async fn handle_stream_index_at_begin() {
    let (msg_begin, msg_limit) = (STREAM_BEGIN, 1);

    let ((status_code, body), fixture) = handle_existing_stream_impl(msg_begin, msg_limit).await;

    assert_response_is_slice(status_code, body, msg_begin, msg_begin, msg_limit, None);
    assert_eq!(
        metric_vec(&[(&[("resource", "stream"), ("status", "200")], 1)]),
        fixture.request_counts()
    );
    assert_eq!(1, fixture.slice_payload_size_stats().count);
    assert_eq!(
        metric_vec(&[(&[("resource", "stream")], 1)]),
        fixture.response_size_counts()
    );
}

#[tokio::test]
async fn handle_stream() {
    let (msg_begin, msg_limit) = (STREAM_BEGIN.increment(), 1);

    let ((status_code, body), fixture) = handle_existing_stream_impl(msg_begin, msg_limit).await;

    assert_response_is_slice(status_code, body, msg_begin, msg_begin, msg_limit, None);
    assert_eq!(
        metric_vec(&[(&[("resource", "stream"), ("status", "200")], 1)]),
        fixture.request_counts()
    );
    assert_eq!(1, fixture.slice_payload_size_stats().count);
    assert_eq!(
        metric_vec(&[(&[("resource", "stream")], 1)]),
        fixture.response_size_counts()
    );
}

#[tokio::test]
async fn handle_stream_index_at_end() {
    let (msg_begin, msg_limit) = (STREAM_BEGIN + StreamIndex::new(STREAM_COUNT), 1);

    let ((status_code, body), fixture) = handle_existing_stream_impl(msg_begin, msg_limit).await;

    assert_response_is_slice(status_code, body, msg_begin, msg_begin, msg_limit, None);
    assert_eq!(
        metric_vec(&[(&[("resource", "stream"), ("status", "200")], 1)]),
        fixture.request_counts()
    );
    assert_eq!(1, fixture.slice_payload_size_stats().count);
    assert_eq!(
        metric_vec(&[(&[("resource", "stream")], 1)]),
        fixture.response_size_counts()
    );
}

#[tokio::test]
async fn handle_stream_index_after_end() {
    let (msg_begin, msg_limit) = (STREAM_BEGIN + StreamIndex::new(STREAM_COUNT + 1), 1);

    let ((status_code, body), fixture) = handle_existing_stream_impl(msg_begin, msg_limit).await;

    assert_response_is_index_out_of_bounds(status_code, body, msg_begin);
    assert_eq!(
        metric_vec(&[(&[("resource", "stream"), ("status", "416")], 1)]),
        fixture.request_counts()
    );
    assert_eq!(0, fixture.slice_payload_size_stats().count);
    assert!(fixture.response_size_counts().is_empty());
}

#[tokio::test]
async fn handle_stream_with_witness_begin() {
    let fixture = EndpointTestFixture::with_replicated_state();

    let witness_begin = STREAM_BEGIN.increment();
    let msg_begin = witness_begin.increment();
    let msg_limit = std::usize::MAX;
    let url = Url::parse(&format!(
        "http://localhost/api/v1/stream/{}?witness_begin={}&msg_begin={}",
        DST_SUBNET, witness_begin, msg_begin
    ))
    .unwrap();

    let response = route_request(
        url,
        &*fixture.state_manager,
        &XNetEndpointMetrics::new(&fixture.metrics),
    );
    let (status_code, body) = parse_response(response).await;

    assert_response_is_slice(status_code, body, witness_begin, msg_begin, msg_limit, None);
    assert_eq!(
        metric_vec(&[(&[("resource", "stream"), ("status", "200")], 1)]),
        fixture.request_counts()
    );
    assert_eq!(1, fixture.slice_payload_size_stats().count);
    assert_eq!(
        metric_vec(&[(&[("resource", "stream")], 1)]),
        fixture.response_size_counts()
    );
}

#[tokio::test]
async fn handle_stream_no_index() {
    let fixture = EndpointTestFixture::with_replicated_state();

    let msg_limit = 1;
    let url = Url::parse(&format!(
        "http://localhost/api/v1/stream/{}?msg_limit={}",
        DST_SUBNET, msg_limit
    ))
    .unwrap();

    let response = route_request(
        url,
        &*fixture.state_manager,
        &XNetEndpointMetrics::new(&fixture.metrics),
    );
    let (status_code, body) = parse_response(response).await;

    assert_response_is_slice(
        status_code,
        body,
        STREAM_BEGIN,
        STREAM_BEGIN,
        msg_limit,
        None,
    );
    assert_eq!(
        metric_vec(&[(&[("resource", "stream"), ("status", "200")], 1)]),
        fixture.request_counts()
    );
    assert_eq!(1, fixture.slice_payload_size_stats().count);
    assert_eq!(
        metric_vec(&[(&[("resource", "stream")], 1)]),
        fixture.response_size_counts()
    );
}

#[tokio::test]
async fn handle_stream_with_byte_limit() {
    let fixture = EndpointTestFixture::with_replicated_state();

    let msg_limit = 20;
    let url = Url::parse(&format!(
        "http://localhost/api/v1/stream/{}?msg_begin={}&msg_limit={}&byte_limit=0",
        DST_SUBNET, STREAM_BEGIN, msg_limit
    ))
    .unwrap();

    let response = route_request(
        url,
        &*fixture.state_manager,
        &XNetEndpointMetrics::new(&fixture.metrics),
    );
    let (status_code, body) = parse_response(response).await;

    assert_response_is_slice(
        status_code,
        body,
        STREAM_BEGIN,
        STREAM_BEGIN,
        msg_limit,
        Some(0),
    );
    assert_eq!(
        metric_vec(&[(&[("resource", "stream"), ("status", "200")], 1)]),
        fixture.request_counts()
    );
    assert_eq!(1, fixture.slice_payload_size_stats().count);
    assert_eq!(
        metric_vec(&[(&[("resource", "stream")], 1)]),
        fixture.response_size_counts()
    );
}

#[tokio::test]
async fn handle_stream_nonexistent() {
    let fixture = EndpointTestFixture::with_replicated_state();

    let url = Url::parse(&format!(
        "http://localhost/api/v1/stream/{}",
        UNKNOWN_SUBNET
    ))
    .unwrap();

    let response = route_request(
        url,
        &*fixture.state_manager,
        &XNetEndpointMetrics::new(&fixture.metrics),
    );
    let (status_code, body) = parse_response(response).await;

    assert_eq!((204, &b""[..]), (status_code, body.as_slice()));
    assert_eq!(
        metric_vec(&[(&[("resource", "stream"), ("status", "204")], 1)]),
        fixture.request_counts()
    );
    assert_eq!(0, fixture.slice_payload_size_stats().count);
    assert!(fixture.response_size_counts().is_empty());
}

#[tokio::test]
async fn handle_bad_api_path() {
    let fixture = EndpointTestFixture::with_replicated_state();
    let url = Url::parse("http://localhost/api/v1/bad/api/path").unwrap();

    let response = route_request(
        url,
        &*fixture.state_manager,
        &XNetEndpointMetrics::new(&fixture.metrics),
    );
    let (status_code, body) = parse_response(response).await;

    assert_eq!((404, &b"Not Found"[..]), (status_code, body.as_slice()));
    assert_eq!(
        metric_vec(&[(&[("resource", "error"), ("status", "404")], 1)]),
        fixture.request_counts()
    );
    assert_eq!(0, fixture.slice_payload_size_stats().count);
    assert!(fixture.response_size_counts().is_empty());
}

/// Commits a `ReplicatedState` containing a single stream for DST_SUBNET.
fn put_replicated_state_for_testing(
    h: Height,
    state_manager: &dyn StateManager<State = ReplicatedState>,
) {
    let (_height, mut state) = state_manager.take_tip();
    let stream = get_stream_for_testing();
    state.with_streams(btreemap![DST_SUBNET => stream]);
    state_manager.commit_and_certify(state, h, CertificationScope::Metadata);
}

/// Generates a stream containing `STREAM_COUNT` requests, beginning at
/// `STREAM_BEGIN`.
fn get_stream_for_testing() -> Stream {
    let message = RequestBuilder::default()
        .sender(canister_test_id(SRC_CANISTER))
        .receiver(canister_test_id(DST_CANISTER))
        .method_name("test_method".to_string())
        .sender_reply_callback(CallbackId::from(CALLBACK_ID))
        .build();

    let mut stream = Stream::new(
        StreamIndexedQueue::with_begin(STREAM_BEGIN),
        Default::default(),
    );

    for _ in 0..STREAM_COUNT {
        stream.push(message.clone().into());
    }
    stream
}

/// Queries the given path on a running `XNetEndpoint`.
async fn http_get(path: &str, xnet_endpoint: &XNetEndpoint) -> Bytes {
    let url = format!("http://localhost:{}{}", xnet_endpoint.server_port(), path);
    let url = reqwest::Url::parse(&url).unwrap_or_else(|_| panic!("Could not parse URL: {}", url));

    reqwest::get(url)
        .await
        .expect("couldn't execute a GET request")
        .bytes()
        .await
        .expect("couldn't extract bytes from an HTTP response")
}

/// Parses a `Response` into status code and body.
async fn parse_response(response: Response<Body>) -> (u16, Vec<u8>) {
    let status = response.status().as_u16();
    let body = hyper::body::to_bytes(response.into_body())
        .await
        .unwrap()
        .to_vec();
    (status, body)
}
