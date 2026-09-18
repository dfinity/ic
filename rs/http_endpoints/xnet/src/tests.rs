use super::*;
use bytes::Bytes;
use ic_crypto_tls_interfaces_mocks::MockTlsConfig;
use ic_interfaces_state_manager::{CertificationScope, StateManager};
use ic_logger::no_op_logger;
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_protobuf::{messaging::xnet::v1 as pb, proxy::ProtoProxy};
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::make_subnet_record_key;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_replicated_state::testing::{ReplicatedStateTesting, StreamTesting};
use ic_replicated_state::{ReplicatedState, Stream};
use ic_test_utilities::state_manager::FakeStateManager;
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_metrics::{
    HistogramStats, MetricVec, fetch_histogram_stats, fetch_histogram_vec_count,
    fetch_int_counter_vec, metric_vec,
};
use ic_test_utilities_types::ids::{
    NODE_3, NODE_5, NODE_42, SUBNET_6, SUBNET_7, SUBNET_12, canister_test_id,
};
use ic_test_utilities_types::messages::RequestBuilder;
use ic_types::{
    NodeId, RegistryVersion, SubnetId,
    messages::CallbackId,
    xnet::{CertifiedStreamSlice, StreamIndexedQueue},
};
use maplit::btreemap;
use std::sync::{Barrier, OnceLock};
use url::Url;

const SRC_CANISTER: u64 = 2;
const DST_CANISTER: u64 = 3;
const CALLBACK_ID: u64 = 4;
const DST_SUBNET: SubnetId = SUBNET_6;
/// An existent subnet for which we have no stream.
const NO_STREAM_SUBNET: SubnetId = SUBNET_7;
/// A nonexistent subnet (no registry record).
const UNKNOWN_SUBNET: SubnetId = SUBNET_12;

const STREAM_BEGIN: StreamIndex = StreamIndex::new(7);
const STREAM_COUNT: u64 = 3;

/// A node of `DST_SUBNET`, i.e. the only one allowed to fetch its stream.
const DST_SUBNET_NODE: NodeId = NODE_3;
/// A node of `NO_STREAM_SUBNET`.
const NO_STREAM_SUBNET_NODE: NodeId = NODE_5;
/// A node not belonging to any subnet.
const UNASSIGNED_NODE: NodeId = NODE_42;

const REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(1);

pub(crate) struct EndpointTestFixture {
    pub state_manager: Arc<FakeStateManager>,
    pub registry_client: Arc<FakeRegistryClient>,
    pub metrics: MetricsRegistry,
    pub tls_handshake: Arc<MockTlsConfig>,
    pub advert_handler: Arc<FakeAdvertHandler>,
    /// The `Context` backing `route_request()`, created on first use. A second one,
    /// or a `XNetEndpoint` alongside it, would panic on registering a second
    /// `XNetEndpointMetrics` with `metrics`.
    context: OnceLock<Context<FakeStateManager>>,
}

impl EndpointTestFixture {
    pub fn with_replicated_state() -> Self {
        Self::with_advert_outcome(|| Ok(XNetAdvertOutcome::Actionable))
    }

    /// As `with_replicated_state()`, but with an advert handler returning
    /// `outcome` for every advert.
    fn with_advert_outcome(
        outcome: impl Fn() -> Result<XNetAdvertOutcome, XNetAdvertError> + Send + Sync + 'static,
    ) -> Self {
        let fixture = EndpointTestFixture {
            metrics: MetricsRegistry::new(),
            state_manager: Arc::new(FakeStateManager::new()),
            registry_client: Arc::new(registry_with_subnet_memberships()),
            tls_handshake: Arc::new(MockTlsConfig::new()),
            advert_handler: FakeAdvertHandler::new(move |_, _| outcome()),
            context: OnceLock::new(),
        };
        put_replicated_state_for_testing(&*fixture.state_manager);
        fixture
    }

    /// Starts a `XNetEndpoint` listening on a free localhost port.
    fn new_endpoint(&self, runtime_handle: runtime::Handle, log: ReplicaLogger) -> XNetEndpoint {
        let addr = get_free_localhost_socket_addr();
        XNetEndpoint::new(
            runtime_handle,
            self.state_manager.clone(),
            self.advert_handler.clone(),
            self.tls_handshake.clone(),
            self.registry_client.clone(),
            Config {
                xnet_ip_addr: addr.ip().to_string(),
                xnet_port: addr.port(),
            },
            &self.metrics,
            log,
        )
    }

    /// Routes a GET for the given URL on behalf of `peer_node_id`.
    fn route_request(&self, url: Url, peer_node_id: Option<NodeId>) -> Response<Body> {
        let body = Bytes::new();
        route_request(url, Method::GET, Ok(body), peer_node_id, self.context())
    }

    /// Posts the given advert on behalf of `peer_node_id`.
    fn post_advert(
        &self,
        source_subnet: SubnetId,
        advert: &CertifiedStreamSlice,
        peer_node_id: Option<NodeId>,
    ) -> Response<Body> {
        let url = Url::parse(&format!("http://localhost/api/v1/advert/{source_subnet}")).unwrap();
        let body = Bytes::from(pb::CertifiedStreamSlice::proxy_encode(advert.clone()));
        route_request(url, Method::POST, Ok(body), peer_node_id, self.context())
    }

    fn context(&self) -> &Context<FakeStateManager> {
        self.context.get_or_init(|| Context {
            log: no_op_logger(),
            semaphore: Semaphore::new(XNetEndpoint::num_workers()).into(),
            metrics: XNetEndpointMetrics::new(&self.metrics).into(),
            certified_stream_store: self.state_manager.clone(),
            registry_client: self.registry_client.clone(),
            advert_handler: self.advert_handler.clone(),
            advert_rate_limiter: Default::default(),
            base_url: "http://localhost".try_into().unwrap(),
        })
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

    /// Returns the values of the `METRIC_ADVERTS` counters.
    pub fn advert_counts(&self) -> MetricVec<u64> {
        fetch_int_counter_vec(&self.metrics, METRIC_ADVERTS)
    }

    /// Returns the values of the `METRIC_ADVERT_VERIFICATION_FAILURES` counters.
    pub fn advert_verification_failure_counts(&self) -> MetricVec<u64> {
        fetch_int_counter_vec(&self.metrics, METRIC_ADVERT_VERIFICATION_FAILURES)
    }
}

/// A `XNetAdvertHandler` producing a canned outcome and recording the adverts
/// it was handed.
pub(crate) struct FakeAdvertHandler {
    #[allow(clippy::type_complexity)]
    outcome: Box<
        dyn Fn(SubnetId, CertifiedStreamSlice) -> Result<XNetAdvertOutcome, XNetAdvertError>
            + Send
            + Sync,
    >,
    adverts: Mutex<Vec<(SubnetId, CertifiedStreamSlice)>>,
    /// Canned reply to a `NothingNew` outcome.
    certified_header: Option<CertifiedStreamSlice>,
}

impl FakeAdvertHandler {
    fn new(
        outcome: impl Fn(SubnetId, CertifiedStreamSlice) -> Result<XNetAdvertOutcome, XNetAdvertError>
        + Send
        + Sync
        + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            outcome: Box::new(outcome),
            adverts: Default::default(),
            certified_header: None,
        })
    }

    fn with_certified_header(
        outcome: impl Fn(SubnetId, CertifiedStreamSlice) -> Result<XNetAdvertOutcome, XNetAdvertError>
        + Send
        + Sync
        + 'static,
        certified_header: CertifiedStreamSlice,
    ) -> Arc<Self> {
        Arc::new(Self {
            outcome: Box::new(outcome),
            adverts: Default::default(),
            certified_header: Some(certified_header),
        })
    }

    /// The adverts handled so far, in order.
    fn adverts(&self) -> Vec<(SubnetId, CertifiedStreamSlice)> {
        self.adverts.lock().unwrap().clone()
    }
}

impl XNetAdvertHandler for FakeAdvertHandler {
    fn handle_advert(
        &self,
        source_subnet: SubnetId,
        advert: CertifiedStreamSlice,
    ) -> Result<XNetAdvertOutcome, XNetAdvertError> {
        self.adverts
            .lock()
            .unwrap()
            .push((source_subnet, advert.clone()));
        (self.outcome)(source_subnet, advert)
    }

    fn certified_header(&self, _subnet_id: SubnetId) -> Option<CertifiedStreamSlice> {
        self.certified_header.clone()
    }
}

/// Returns a registry holding records for `DST_SUBNET` and `NO_STREAM_SUBNET`,
/// each with a single member; `UNASSIGNED_NODE` is a member of neither.
fn registry_with_subnet_memberships() -> FakeRegistryClient {
    let data_provider = ProtoRegistryDataProvider::new();
    for (subnet_id, node) in [
        (DST_SUBNET, DST_SUBNET_NODE),
        (NO_STREAM_SUBNET, NO_STREAM_SUBNET_NODE),
    ] {
        data_provider
            .add(
                &make_subnet_record_key(subnet_id),
                REGISTRY_VERSION,
                Some(SubnetRecord {
                    membership: vec![node.get().into_vec()],
                    ..Default::default()
                }),
            )
            .unwrap();
    }

    let registry_client = FakeRegistryClient::new(Arc::new(data_provider));
    registry_client.update_to_latest_version();
    registry_client
}

// Get a free port on this host to which we can connect transport to.
pub fn get_free_localhost_socket_addr() -> SocketAddr {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_reuseport(false).unwrap();
    socket.set_reuseaddr(false).unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    socket.local_addr().unwrap()
}

/// Tests the `/api/v1/streams` API endpoint.
///
/// Heavyweight test that starts an `XNetEndpoint` and queries it over HTTP.
#[test]
fn query_streams() {
    with_test_replica_logger(|log| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let fixture = EndpointTestFixture::with_replicated_state();

        let xnet_endpoint = fixture.new_endpoint(rt.handle().clone(), log);

        let resp = rt
            .block_on(async move { http_get(&http_url("/api/v1/streams", &xnet_endpoint)).await });

        assert_eq!(format!("[\"{DST_SUBNET}\"]"), resp);
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

        let xnet_endpoint = fixture.new_endpoint(rt.handle().clone(), log);

        let resp = rt.block_on(async move {
            http_get(&http_url(
                &format!(
                    "/api/v1/stream/{}?witness_begin={}&msg_begin={}",
                    DST_SUBNET,
                    STREAM_BEGIN,
                    STREAM_BEGIN.increment()
                ),
                &xnet_endpoint,
            ))
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

/// Tests that `/api/v1/{SubnetId}` API endpoint executes requests in parallel.
///
/// Heavyweight test that starts an `XNetEndpoint` and queries it over HTTP.
#[test]
fn query_stream_parallel() {
    with_test_replica_logger(|log| {
        let endpoint_rt = tokio::runtime::Runtime::new().unwrap();
        let fixture = EndpointTestFixture::with_replicated_state();

        *fixture
            .state_manager
            .encode_certified_stream_slice_barrier
            .write()
            .unwrap() = Barrier::new(XNetEndpoint::num_workers() + 1);

        let xnet_endpoint = fixture.new_endpoint(endpoint_rt.handle().clone(), log);

        let http_url = http_url(
            &format!(
                "/api/v1/stream/{}?witness_begin={}&msg_begin={}",
                DST_SUBNET,
                STREAM_BEGIN,
                STREAM_BEGIN.increment()
            ),
            &xnet_endpoint,
        );
        let mut handles = vec![];
        for _ in 0..XNetEndpoint::num_workers() {
            let http_url = http_url.clone();
            handles.push(std::thread::spawn(move || {
                let http_rt = tokio::runtime::Runtime::new().unwrap();
                http_rt.block_on(async move { http_get(&http_url).await });
            }));
        }
        // Expect no deadlock on the encode_barrier at pre_encode_certified_stream_slice
        fixture
            .state_manager
            .encode_certified_stream_slice_barrier
            .read()
            .unwrap()
            .wait();
        for h in handles {
            h.join().unwrap();
        }
    });
}

#[tokio::test]
async fn handle_streams() {
    let fixture = EndpointTestFixture::with_replicated_state();

    let url = Url::parse("http://localhost/api/v1/streams").unwrap();

    let response = fixture.route_request(url, Some(DST_SUBNET_NODE));
    let (parsed_status, body) = parse_response(response).await;

    assert_eq!(
        (200, format!("[\"{DST_SUBNET}\"]").as_bytes()),
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
        "http://localhost/api/v1/stream/{DST_SUBNET}?msg_begin={msg_begin}&msg_limit={msg_limit}"
    ))
    .unwrap();

    let response = fixture.route_request(url, Some(DST_SUBNET_NODE));
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
    let msg_limit = usize::MAX;
    let url = Url::parse(&format!(
        "http://localhost/api/v1/stream/{DST_SUBNET}?witness_begin={witness_begin}&msg_begin={msg_begin}"
    ))
    .unwrap();

    let response = fixture.route_request(url, Some(DST_SUBNET_NODE));
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
        "http://localhost/api/v1/stream/{DST_SUBNET}?msg_limit={msg_limit}"
    ))
    .unwrap();

    let response = fixture.route_request(url, Some(DST_SUBNET_NODE));
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
        "http://localhost/api/v1/stream/{DST_SUBNET}?msg_begin={STREAM_BEGIN}&msg_limit={msg_limit}&byte_limit=0"
    ))
    .unwrap();

    let response = fixture.route_request(url, Some(DST_SUBNET_NODE));
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
        "http://localhost/api/v1/stream/{NO_STREAM_SUBNET}"
    ))
    .unwrap();

    let response = fixture.route_request(url, Some(NO_STREAM_SUBNET_NODE));
    let (status_code, body) = parse_response(response).await;

    assert_eq!((204, &b""[..]), (status_code, body.as_slice()));
    assert_eq!(
        metric_vec(&[(&[("resource", "stream"), ("status", "204")], 1)]),
        fixture.request_counts()
    );
    assert_eq!(0, fixture.slice_payload_size_stats().count);
    assert!(fixture.response_size_counts().is_empty());
}

/// Common implementation for all `handle_stream` tests that expect a request
/// for `DST_SUBNET`'s stream to be refused.
async fn handle_refused_stream_impl(peer_node_id: NodeId) {
    let fixture = EndpointTestFixture::with_replicated_state();

    let url = Url::parse(&format!(
        "http://localhost/api/v1/stream/{DST_SUBNET}?msg_begin={STREAM_BEGIN}"
    ))
    .unwrap();

    let response = fixture.route_request(url, Some(peer_node_id));
    let (status_code, _body) = parse_response(response).await;

    assert_eq!(403, status_code);
    assert_eq!(
        metric_vec(&[(&[("resource", "stream"), ("status", "403")], 1)]),
        fixture.request_counts()
    );
    assert_eq!(0, fixture.slice_payload_size_stats().count);
    assert!(fixture.response_size_counts().is_empty());
}

#[tokio::test]
async fn handle_stream_for_other_subnet() {
    handle_refused_stream_impl(NO_STREAM_SUBNET_NODE).await;
}

#[tokio::test]
async fn handle_stream_from_unassigned_node() {
    handle_refused_stream_impl(UNASSIGNED_NODE).await;
}

/// Tests that a caller whose membership the registry cannot confirm is refused,
/// rather than assumed to be a member.
#[tokio::test]
async fn handle_stream_for_subnet_without_registry_record() {
    let fixture = EndpointTestFixture::with_replicated_state();

    let url = Url::parse(&format!("http://localhost/api/v1/stream/{UNKNOWN_SUBNET}")).unwrap();

    let response = fixture.route_request(url, Some(DST_SUBNET_NODE));

    assert_eq!(403, parse_response(response).await.0);
}

#[tokio::test]
async fn handle_bad_api_path() {
    let fixture = EndpointTestFixture::with_replicated_state();
    let url = Url::parse("http://localhost/api/v1/bad/api/path").unwrap();

    let response = fixture.route_request(url, Some(DST_SUBNET_NODE));
    let (status_code, body) = parse_response(response).await;

    assert_eq!((404, &b"Not Found"[..]), (status_code, body.as_slice()));
    assert_eq!(
        metric_vec(&[(&[("resource", "error"), ("status", "404")], 1)]),
        fixture.request_counts()
    );
    assert_eq!(0, fixture.slice_payload_size_stats().count);
    assert!(fixture.response_size_counts().is_empty());
}

#[tokio::test]
async fn handle_advert_actionable() {
    let fixture = EndpointTestFixture::with_advert_outcome(|| Ok(XNetAdvertOutcome::Actionable));
    let advert = header_only_slice();

    let response = fixture.post_advert(NO_STREAM_SUBNET, &advert, Some(NO_STREAM_SUBNET_NODE));

    assert_eq!((204, vec![]), parse_response(response).await);
    assert_eq!(
        vec![(NO_STREAM_SUBNET, advert)],
        fixture.advert_handler.adverts()
    );
    assert_eq!(
        metric_vec(&[(&[("status", &"actionable".to_string())], 1)]),
        fixture.advert_counts()
    );
}

#[tokio::test]
async fn handle_advert_nothing_new() {
    let expected_reply = header_only_slice();
    let fixture = EndpointTestFixture {
        advert_handler: FakeAdvertHandler::with_certified_header(
            |_, _| Ok(XNetAdvertOutcome::NothingNew),
            expected_reply.clone(),
        ),
        ..EndpointTestFixture::with_replicated_state()
    };

    let response = fixture.post_advert(
        NO_STREAM_SUBNET,
        &header_only_slice(),
        Some(NO_STREAM_SUBNET_NODE),
    );

    let (status_code, body) = parse_response(response).await;
    assert_eq!(
        (200, expected_reply),
        (
            status_code,
            pb::CertifiedStreamSlice::proxy_decode(body.as_slice()).unwrap()
        )
    );
    assert_eq!(
        metric_vec(&[(&[("status", &"nothing_new".to_string())], 1)]),
        fixture.advert_counts()
    );
}

/// Nothing new, but no stream to reply with: no content, no reply.
#[tokio::test]
async fn handle_advert_nothing_new_no_stream() {
    let fixture = EndpointTestFixture::with_advert_outcome(|| Ok(XNetAdvertOutcome::NothingNew));

    let response = fixture.post_advert(
        NO_STREAM_SUBNET,
        &header_only_slice(),
        Some(NO_STREAM_SUBNET_NODE),
    );

    assert_eq!((204, vec![]), parse_response(response).await);
}

/// Only a node of the source subnet may advertise for it.
#[tokio::test]
async fn handle_advert_from_non_member() {
    let fixture =
        EndpointTestFixture::with_advert_outcome(|| panic!("advert must not reach the handler"));

    let response = fixture.post_advert(
        NO_STREAM_SUBNET,
        &header_only_slice(),
        Some(DST_SUBNET_NODE),
    );

    assert_eq!(403, response.status().as_u16());
    assert!(fixture.advert_handler.adverts().is_empty());
    assert_eq!(
        metric_vec(&[(&[("status", &"403".to_string())], 1)]),
        fixture.advert_counts()
    );
}

/// An advert that fails to verify is attributed to the subnet that sent it.
#[tokio::test]
async fn handle_advert_invalid() {
    let fixture = EndpointTestFixture::with_advert_outcome(|| {
        Err(XNetAdvertError::Invalid("invalid signature".into()))
    });

    let response = fixture.post_advert(
        NO_STREAM_SUBNET,
        &header_only_slice(),
        Some(NO_STREAM_SUBNET_NODE),
    );

    assert_eq!(400, response.status().as_u16());
    assert_eq!(
        metric_vec(&[(&[("status", &"invalid".to_string())], 1)]),
        fixture.advert_counts()
    );
    assert_eq!(
        metric_vec(&[(&[("remote", &NO_STREAM_SUBNET.to_string())], 1)]),
        fixture.advert_verification_failure_counts()
    );
}

#[tokio::test]
async fn handle_advert_undecodable() {
    let fixture = EndpointTestFixture::with_replicated_state();
    let url = Url::parse(&format!(
        "http://localhost/api/v1/advert/{NO_STREAM_SUBNET}"
    ))
    .unwrap();

    let response = route_request(
        url,
        Method::POST,
        Ok(Bytes::from_static(b"garbage")),
        Some(NO_STREAM_SUBNET_NODE),
        fixture.context(),
    );

    assert_eq!(400, response.status().as_u16());
    assert!(fixture.advert_handler.adverts().is_empty());
    assert_eq!(
        metric_vec(&[(&[("status", &"400".to_string())], 1)]),
        fixture.advert_counts()
    );
}

/// A node may only advertise at the configured rate; the adverts beyond it are
/// rejected without reaching the handler.
#[tokio::test]
async fn handle_advert_rate_limited() {
    let fixture = EndpointTestFixture::with_replicated_state();
    let burst = ADVERT_RATE_LIMIT_BURST as usize;

    let advert = header_only_slice();
    let status_codes = (0..burst + 1)
        .map(|_| {
            fixture
                .post_advert(NO_STREAM_SUBNET, &advert, Some(NO_STREAM_SUBNET_NODE))
                .status()
                .as_u16()
        })
        .collect::<Vec<_>>();
    let mut expected = vec![204; burst];
    expected.push(429);
    assert_eq!(expected, status_codes);
    assert_eq!(burst, fixture.advert_handler.adverts().len());
    assert_eq!(
        metric_vec(&[
            (&[("status", &"actionable".to_string())], burst as u64),
            (&[("status", &"429".to_string())], 1)
        ]),
        fixture.advert_counts()
    );
}

/// Commits a `ReplicatedState` containing a single stream for DST_SUBNET.
fn put_replicated_state_for_testing(state_manager: &dyn StateManager<State = ReplicatedState>) {
    let (_height, mut state) = state_manager.take_tip();
    let stream = get_stream_for_testing();
    state.with_streams(btreemap![DST_SUBNET => stream]);
    state_manager.commit_and_certify(state, CertificationScope::Metadata, None);
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

/// Queries the given URL for the given path on a running `XNetEndpoint`.
fn http_url(path: &str, xnet_endpoint: &XNetEndpoint) -> String {
    let url = format!("http://localhost:{}{}", xnet_endpoint.server_port(), path);
    reqwest::Url::parse(&url)
        .unwrap_or_else(|_| panic!("Could not parse URL: {url}"))
        .to_string()
}

/// Queries the given URL.
async fn http_get(url: &str) -> Bytes {
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
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, body)
}

/// A header-only certified slice, to be used as an advert.
fn header_only_slice() -> CertifiedStreamSlice {
    EndpointTestFixture::with_replicated_state()
        .state_manager
        .encode_certified_stream_slice(DST_SUBNET, None, None, Some(0), None)
        .unwrap()
}
