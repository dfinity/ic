//! Populating the slice pool: pulling stream slices from peer subnets
//! (`PullTask`); handling the adverts they post to us (`XNetAdvertHandlerImpl`);
//! and advertising our own streams to them (`AdvertTask`).

mod proximity;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod xnet_client_tests;

pub use proximity::{GenRangeFn, ProximityMap};

use crate::certified_slice_pool::{
    CertifiedSlicePool, POOLED_SLICE_BYTE_SIZE_MAX, decode_slice_header,
};
use crate::{LABEL_STATUS, STATUS_SUCCESS};
use async_trait::async_trait;
use http_body_util::BodyExt;
use hyper::{Request, StatusCode, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use ic_config::message_routing::ADVERT_MAX_BODY_BYTES;
use ic_crypto_tls_interfaces::TlsConfig;
use ic_interfaces::messaging::{XNetAdvertError, XNetAdvertHandler, XNetAdvertOutcome};
use ic_interfaces_certified_stream_store::{
    CertifiedStreamStore, DecodeStreamError, EncodeStreamError,
};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateManager;
use ic_logger::{ReplicaLogger, error, info, log, warn};
use ic_metrics::MetricsRegistry;
use ic_metrics::buckets::decimal_buckets;
use ic_protobuf::messaging::xnet::v1 as pb;
use ic_protobuf::proxy::{ProtoProxy, ProxyDecodeError};
use ic_registry_client_helpers::node::{NodeRecord, NodeRegistry};
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_replicated_state::{ReplicatedState, replicated_state::ReplicatedStateMessageRouting};
use ic_types::messages::MAX_INTER_CANISTER_PAYLOAD_IN_BYTES;
use ic_types::registry::RegistryClientError;
use ic_types::xnet::{CertifiedStreamSlice, StreamHeader, StreamIndex};
use ic_types::{Height, NodeId, RegistryVersion, SubnetId};
use ic_xnet_hyper::TlsConnector;
use ic_xnet_uri::XNetAuthority;
use prometheus::{HistogramVec, IntCounter, IntCounterVec, IntGauge};
use rand::{Rng, thread_rng};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::runtime;
use tokio::sync::{mpsc, watch};

/// Represents the location of a peer
#[derive(Eq, PartialEq, Debug)]
pub enum PeerLocation {
    /// Peer in the same datacenter
    Local,

    /// Peer in other datacenter
    Remote,
}

impl From<PeerLocation> for &str {
    fn from(proximity: PeerLocation) -> Self {
        match proximity {
            PeerLocation::Local => "local",
            PeerLocation::Remote => "remote",
        }
    }
}

/// Metadata describing a replica's XNet endpoint.
#[derive(Eq, PartialEq, Debug)]
pub struct EndpointLocator {
    /// The ID of the node hosting the replica.
    node_id: NodeId,

    /// The endpoint URL.
    pub url: Uri,

    /// The proximity of the peer.
    proximity: PeerLocation,
}

/// Error resolving a peer subnet's nodes or their XNet endpoints.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to retrieve registry info for subnet {0}: {1}")]
    RegistryGetSubnetInfoFailed(SubnetId, RegistryClientError),
    #[error("No nodes in subnet {0}")]
    MissingSubnet(SubnetId),
    #[error("Failed to retrieve registry info for node {0}: {1}")]
    RegistryGetNodeInfoFailed(NodeId, RegistryClientError),
    #[error("No XNet endpoint info found for node {0}")]
    MissingXNetEndpoint(NodeId),
    #[error("Invalid XNet endpoint info for node {0}: {1}")]
    InvalidXNetEndpoint(NodeId, String),
}

impl Error {
    /// Returns the desired log level to be used with this `Error`.
    fn log_level(&self) -> slog::Level {
        match self {
            Error::InvalidXNetEndpoint(..) => slog::Level::Error,
            _ => slog::Level::Info,
        }
    }

    /// Maps the `Error` to a `status` label value.
    fn to_label_value(&self) -> &str {
        match self {
            Error::RegistryGetSubnetInfoFailed(..) => "RegistryGetSubnetInfoFailed",
            Error::MissingSubnet(..) => "MissingSubnet",
            Error::RegistryGetNodeInfoFailed(..) => "RegistryGetNodeInfoFailed",
            Error::MissingXNetEndpoint(..) => "MissingXNetEndpoint",
            Error::InvalidXNetEndpoint(..) => "InvalidXNetEndpoint",
        }
    }
}

/// Selects nodes on peer subnets based on proximity and health; and resolves
/// stream and advert XNet endpoints to `EndpointLocators`, consisting of URL,
/// node ID and proximity.
pub struct XNetEndpointResolver {
    /// Used for retrieving a subnet's nodes, in order to poll their
    /// `XNetEndpoints` for `CertifiedStreamSlices` to be included into
    /// `XNetPayloads`.
    registry: Arc<dyn RegistryClient>,

    /// This node's subnet ID.
    subnet_id: SubnetId,

    /// This node's operator ID.
    node_operator_id: Vec<u8>,

    /// Used for probabilistically selecting uniformly random or proximity-weighted
    /// healthy replicas.
    proximity_map: Arc<ProximityMap>,
}

impl XNetEndpointResolver {
    pub fn new(
        registry: Arc<dyn RegistryClient>,
        node_id: NodeId,
        subnet_id: SubnetId,
        proximity_map: Arc<ProximityMap>,
        log: ReplicaLogger,
    ) -> Self {
        let newest_registry = registry.get_latest_version();
        let node_operator_id = get_node_operator_id(
            &node_id,
            registry.as_ref(),
            &newest_registry,
            &log,
        )
        .unwrap_or_else(|| {
            panic!(
                "Could not read own node's ({node_id:?}) node record from registry of version ({newest_registry:?})."
            )
        });
        Self {
            registry,
            subnet_id,
            node_operator_id,
            proximity_map,
        }
    }

    /// Returns the `/api/v1/stream` `XNetEndpoint` URL of a random
    /// proximity-weighted node on `subnet_id`, for a slice of at most `byte_limit`
    /// bytes beginning at `msg_begin`, with a witness beginning at `witness_begin`.
    ///
    /// # Errors
    ///
    /// Returns an error if retrieving the node registry entry fails; if the
    /// requested subnet is missing or has no nodes; or if the node address
    /// is invalid.
    pub fn xnet_stream_url(
        &self,
        subnet_id: SubnetId,
        witness_begin: StreamIndex,
        msg_begin: StreamIndex,
        byte_limit: usize,
    ) -> Result<EndpointLocator, Error> {
        assert!(witness_begin <= msg_begin);

        let version = self.registry.get_latest_version();
        let (node, node_record) = self.proximity_map.pick_node(subnet_id, version)?;

        self.endpoint_locator(
            node,
            node_record,
            version,
            &format!(
                "stream/{}?msg_begin={}&witness_begin={}&byte_limit={}",
                self.subnet_id, msg_begin, witness_begin, byte_limit
            ),
        )
    }

    /// Returns the `/api/v1/advert` `XNetEndpoint` URL of the given node, for
    /// advertising our certified header to.
    ///
    /// # Errors
    ///
    /// Returns an error if retrieving the node registry entry fails; or if the
    /// node address is invalid.
    pub fn xnet_advert_url(&self, node: NodeId) -> Result<EndpointLocator, Error> {
        let version = self.registry.get_latest_version();
        let node_record = get_node_record(node, self.registry.as_ref(), version)?;

        self.endpoint_locator(
            node,
            node_record,
            version,
            &format!("advert/{}", self.subnet_id),
        )
    }

    /// Resolves `node` to the `XNetEndpoint` URL of `path`, e.g.
    /// `stream/{SubnetId}?msg_begin=...`, at the given registry version.
    fn endpoint_locator(
        &self,
        node: NodeId,
        node_record: NodeRecord,
        version: RegistryVersion,
        path: &str,
    ) -> Result<EndpointLocator, Error> {
        let proximity = if node_record.node_operator_id == self.node_operator_id {
            PeerLocation::Local
        } else {
            PeerLocation::Remote
        };

        let xnet_endpoint = node_record.xnet.ok_or(Error::MissingXNetEndpoint(node))?;

        let socket_addr = SocketAddr::new(
            xnet_endpoint.ip_addr.parse().map_err(|_| {
                Error::InvalidXNetEndpoint(node, format!("bad ip addr {}", xnet_endpoint.ip_addr))
            })?,
            u16::try_from(xnet_endpoint.port).map_err(|_| {
                Error::InvalidXNetEndpoint(node, format!("bad port {}", xnet_endpoint.port))
            })?,
        );

        let authority = XNetAuthority {
            node_id: node,
            registry_version: version,
            address: socket_addr,
        };

        let url = format!("http://{authority}/api/v1/{path}");

        url.parse::<Uri>()
            .map_err(|e| {
                panic!("Could not parse URL {url} : {e}");
            })
            .map(|url| EndpointLocator {
                node_id: node,
                url,
                proximity,
            })
    }

    /// Picks `advert_target_count()` nodes of `subnet_id` to advertise to, sampled
    /// uniformly (not by proximity, to avoid bias) from among the healthy ones,
    /// unless too few are.
    ///
    /// # Errors
    ///
    /// Returns an error if reading the registry fails; or if either subnet is
    /// missing or has no nodes.
    pub fn advert_targets(&self, subnet_id: SubnetId) -> Result<Vec<NodeId>, Error> {
        // No `ValidationContext` here, so go with the latest.
        let version = self.registry.get_latest_version();
        let own_subnet_size =
            get_subnet_nodes(self.subnet_id, self.registry.as_ref(), version)?.len();
        let nodes = get_subnet_nodes(subnet_id, self.registry.as_ref(), version)?;

        let count = advert_target_count(own_subnet_size, nodes.len());
        Ok(self.proximity_map.uniform_sample(count, nodes))
    }
}

#[derive(Debug, Error)]
pub enum XNetClientError {
    #[error("XNet request timed out")]
    Timeout,
    #[error("XNet request failed: {0}")]
    RequestFailed(hyper_util::client::legacy::Error),
    #[error("No stream")]
    NoContent,
    #[error("HTTP {0}: {1}")]
    ErrorResponse(hyper::StatusCode, String),
    #[error("Error reading response body: {0}")]
    BodyReadError(Box<dyn std::error::Error + Send + Sync>),
    #[error("Error decoding XNet proto into Rust struct: {0}")]
    ProxyDecodeError(ProxyDecodeError),
    #[error("Advert of {0} bytes exceeds the {ADVERT_MAX_BODY_BYTES} byte limit")]
    AdvertTooLarge(usize),
}

impl XNetClientError {
    /// Returns `true` if this error means that the node failed to serve the
    /// request: we could not connect to it, it timed out, or it responded with
    /// a 5xx status code or something we could not make sense of. Whereas a 204
    /// (`NoContent`) or 4xx status code point to a (likely) healthy node.
    fn is_node_failure(&self) -> bool {
        match self {
            // Self-explanatory.
            XNetClientError::Timeout
            // Could be anything, but usually "XNet request failed: client error (Connect)".
            | XNetClientError::RequestFailed(..)
            // Not observed in the wild, but it would likely imply a misbehaving server (e.g.
            // oversized response).
            | XNetClientError::BodyReadError(..)
            // Not observed in the wild, but it would likely imply a misbehaving server.
            | XNetClientError::ProxyDecodeError(..) => true,

            // Only a failure if the server returned a 5xx status code. Even though 503 is
            // transient (full queue), it is probably a good idea to give the server some
            // breathing room.
            XNetClientError::ErrorResponse(status_code, ..) => status_code.is_server_error(),

            // Definitely not an error, there's merely no new content.
            XNetClientError::NoContent => false,

            // Our own doing, nothing to do with the node.
            XNetClientError::AdvertTooLarge(..) => false,
        }
    }

    /// Maps an `XNetClientError` to a `status` label value.
    fn to_label_value(&self) -> String {
        match self {
            XNetClientError::Timeout => "Timeout".to_string(),
            XNetClientError::RequestFailed(..) => "RequestFailed".to_string(),
            XNetClientError::NoContent => "NoContent".to_string(),
            XNetClientError::ErrorResponse(status, _) => format!("HTTP_{}", status.as_u16()),
            XNetClientError::BodyReadError(..) => "BodyReadError".to_string(),
            XNetClientError::ProxyDecodeError(..) => STATUS_DECODE_ERROR.to_string(),
            XNetClientError::AdvertTooLarge(..) => "AdvertTooLarge".to_string(),
        }
    }
}

/// An async `XNetEndpoint` client.
///
/// The `async_trait` attribute is necessary both here and on every
/// implementation because we use `dyn XNetClient`.
#[async_trait]
pub trait XNetClient: Sync + Send {
    /// Queries the given `XNetEndpoint` for a `CertifiedStreamSlice`.
    ///
    /// On success, returns the deserialized slice.
    async fn query(
        &self,
        endpoint: &EndpointLocator,
    ) -> Result<CertifiedStreamSlice, XNetClientError>;

    /// Posts an advert — our own certified stream header — to the given
    /// `XNetEndpoint`.
    ///
    /// On success, returns the peer's response: its certified header iff it already
    /// reflects the contents of the advert, else `None`.
    async fn post_advert(
        &self,
        endpoint: &EndpointLocator,
        advert: CertifiedStreamSlice,
    ) -> Result<Option<CertifiedStreamSlice>, XNetClientError>;
}

type XNetRequestBody = http_body_util::Full<hyper::body::Bytes>;

/// The default `XNetClient` implementation, wrapping an HTTP client (for both
/// configuration and connection pooling).
pub(crate) struct XNetClientImpl {
    /// HTTP client for querying and advertising.
    http_client: Client<TlsConnector, XNetRequestBody>,

    /// Response body (encoded slice) size.
    response_body_size: HistogramVec,

    /// Proximity map to update with the outcome of every request; and with the
    /// time-to-first-byte of every query.
    proximity_map: Arc<ProximityMap>,
}

impl XNetClientImpl {
    /// Creates a new `XNetClientImpl` with a request timeout of 5 seconds, at
    /// most 1 idle connection per host and HTTP/2 keep-alive pings.
    pub(crate) fn new(
        metrics_registry: &MetricsRegistry,
        tls: Arc<dyn TlsConfig>,
        proximity_map: Arc<ProximityMap>,
    ) -> XNetClientImpl {
        #[cfg(not(test))]
        let https = TlsConnector::new(tls);
        #[cfg(test)]
        let https = TlsConnector::new_for_tests(tls);

        // TODO(MR-28) Make timeout configurable.
        //
        // HTTP/2 keep-alive pings are necessary to evict dead pooled connections:
        // cancelling a request (e.g. due to the 5-second query timeout) only resets
        // the respective stream, it does not affect the underlying connection. And
        // the pool only drops connections that report themselves as closed. So
        // without keep-alive a connection that is dead or stalled (e.g. due to
        // packet loss while under load) would be reused indefinitely, with every
        // query against it timing out. With keep-alive, such a connection is closed
        // within `interval + timeout` seconds and a fresh connection is established
        // on the next query.
        let http_client: Client<TlsConnector, XNetRequestBody> =
            Client::builder(TokioExecutor::new())
                .http2_only(true)
                // Timer required by HTTP/2 keep-alive.
                .timer(TokioTimer::new())
                .http2_keep_alive_interval(Some(Duration::from_secs(10)))
                .http2_keep_alive_timeout(Duration::from_secs(5))
                .http2_keep_alive_while_idle(true)
                .pool_timer(TokioTimer::new())
                .pool_idle_timeout(Some(Duration::from_secs(600)))
                .pool_max_idle_per_host(1)
                .build(https);

        let response_body_size = metrics_registry.histogram_vec(
            METRIC_RESPONSE_BODY_SIZE,
            "Response body (encoded slice) size in bytes, by decode status.",
            // 10 B - 50 MB
            decimal_buckets(1, 7),
            &[LABEL_STATUS],
        );
        response_body_size.with_label_values(&[STATUS_SUCCESS]);
        response_body_size.with_label_values(&[STATUS_DECODE_ERROR]);

        XNetClientImpl {
            http_client,
            response_body_size,
            proximity_map,
        }
    }

    async fn query_impl(
        &self,
        endpoint: &EndpointLocator,
    ) -> Result<CertifiedStreamSlice, XNetClientError> {
        // TODO(MR-28) Make timeout configurable.
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            let request_start = Instant::now();

            let response = self
                .http_client
                .get(endpoint.url.clone())
                .await
                .map_err(XNetClientError::RequestFailed)?;

            // While this is not exactly roundtrip time (it may include multiple roundtrips
            // e.g. if a TLS connection needs to be established first), it is a good enough
            // approximation. Else, we would have to use explicit pings to measure actual
            // roundtrip times.
            self.proximity_map.observe_roundtrip_time(
                endpoint.node_id,
                Instant::now().saturating_duration_since(request_start),
            );

            let status = response.status();

            let content =
                http_body_util::Limited::new(response.into_body(), 2 * POOLED_SLICE_BYTE_SIZE_MAX)
                    .collect()
                    .await
                    .map(|collected| collected.to_bytes())
                    .map_err(XNetClientError::BodyReadError)?;

            Ok((status, content))
        })
        .await;

        let (status, bytes) = result.map_err(|_| XNetClientError::Timeout)??;

        match status {
            StatusCode::OK => match pb::CertifiedStreamSlice::proxy_decode(bytes.as_ref()) {
                Ok(slice) => {
                    self.response_body_size
                        .with_label_values(&[STATUS_SUCCESS])
                        .observe(bytes.len() as f64);
                    Ok(slice)
                }
                Err(err) => {
                    self.response_body_size
                        .with_label_values(&[STATUS_DECODE_ERROR])
                        .observe(bytes.len() as f64);
                    Err(XNetClientError::ProxyDecodeError(err))
                }
            },

            StatusCode::NO_CONTENT => Err(XNetClientError::NoContent),

            _ => Err(XNetClientError::ErrorResponse(
                status,
                String::from_utf8_lossy(bytes.as_ref()).to_string(),
            )),
        }
    }

    async fn post_advert_impl(
        &self,
        endpoint: &EndpointLocator,
        advert: CertifiedStreamSlice,
    ) -> Result<Option<CertifiedStreamSlice>, XNetClientError> {
        let body = pb::CertifiedStreamSlice::proxy_encode(advert);
        // The receiver refuses anything larger, so there is no point in sending it.
        if body.len() > ADVERT_MAX_BODY_BYTES {
            return Err(XNetClientError::AdvertTooLarge(body.len()));
        }
        let request = Request::post(endpoint.url.clone())
            .header(hyper::header::CONTENT_TYPE, "application/x-protobuf")
            .body(XNetRequestBody::from(body))
            .expect("failed to build advert request");

        // TODO(MR-28) Make timeout configurable.
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            let response = self
                .http_client
                .request(request)
                .await
                .map_err(XNetClientError::RequestFailed)?;

            let status = response.status();

            // A reply is a header-only slice, just like the advert.
            let content = http_body_util::Limited::new(response.into_body(), ADVERT_MAX_BODY_BYTES)
                .collect()
                .await
                .map(|collected| collected.to_bytes())
                .map_err(XNetClientError::BodyReadError)?;

            Ok((status, content))
        })
        .await;

        let (status, bytes) = result.map_err(|_| XNetClientError::Timeout)??;

        match status {
            // Advert accepted.
            StatusCode::NO_CONTENT => Ok(None),

            // Everything in our advert was already inducted and certified: the reply is a
            // certified header that proves it.
            StatusCode::OK => pb::CertifiedStreamSlice::proxy_decode(bytes.as_ref())
                .map(Some)
                .map_err(XNetClientError::ProxyDecodeError),

            _ => Err(XNetClientError::ErrorResponse(
                status,
                String::from_utf8_lossy(bytes.as_ref()).to_string(),
            )),
        }
    }

    /// Updates the node's health status, based on whether it served the request.
    fn update_node_health<T>(&self, node_id: NodeId, result: &Result<T, XNetClientError>) {
        match result {
            Err(e) if e.is_node_failure() => self.proximity_map.observe_failure(node_id),
            _ => self.proximity_map.observe_success(node_id),
        }
    }
}

#[async_trait]
impl XNetClient for XNetClientImpl {
    async fn query(
        &self,
        endpoint: &EndpointLocator,
    ) -> Result<CertifiedStreamSlice, XNetClientError> {
        let result = self.query_impl(endpoint).await;
        self.update_node_health(endpoint.node_id, &result);
        result
    }

    async fn post_advert(
        &self,
        endpoint: &EndpointLocator,
        advert: CertifiedStreamSlice,
    ) -> Result<Option<CertifiedStreamSlice>, XNetClientError> {
        let result = self.post_advert_impl(endpoint, advert).await;
        self.update_node_health(endpoint.node_id, &result);
        result
    }
}

/// Handles the adverts peers post to us, and any headers they reply to ours
/// with; and decides which subnets we owe an advert to. Has no state of its
/// own, it shares the slice pool with `XNetPayloadBuilderImpl`.
pub(crate) struct XNetAdvertHandlerImpl {
    /// Used for reading the certified state: to classify adverts against, and to
    /// decide which adverts we owe.
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,

    /// Used for verifying adverts and encoding our own certified headers.
    certified_stream_store: Arc<dyn CertifiedStreamStore>,

    /// Used for retrieving the registry version to verify adverts against.
    registry: Arc<dyn RegistryClient>,

    /// Classifies adverts against the pooled slices and stream positions; and
    /// holds the recorded headers.
    slice_pool: Arc<Mutex<CertifiedSlicePool>>,

    log: ReplicaLogger,
}

impl XNetAdvertHandlerImpl {
    pub(crate) fn new(
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        certified_stream_store: Arc<dyn CertifiedStreamStore>,
        registry: Arc<dyn RegistryClient>,
        slice_pool: Arc<Mutex<CertifiedSlicePool>>,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            state_manager,
            certified_stream_store,
            registry,
            slice_pool,
            log,
        }
    }

    /// Classifies an advertised header by the strongest statement we can make
    /// about its content; see `XNetAdvertOutcome`.
    fn classify_advert(&self, source_subnet: SubnetId, header: &StreamHeader) -> XNetAdvertOutcome {
        // Only a certified header proves that there is nothing new, so the test for
        // whether to reply must come from the certified state, same as the reply.
        let state = self.state_manager.get_latest_certified_state();
        let own_stream = state
            .as_ref()
            .and_then(|state| state.get_ref().streams().get(&source_subnet));

        if let Some(stream) = own_stream {
            // `NothingNew` if our certified stream has signals for all advertised messages;
            // no messages before the advertised `signals_end`; and no reject signals before
            // the advertised `begin`.
            if header.end() <= stream.signals_end()
                && header.signals_end() <= stream.messages_begin()
                && !stream.has_reject_signal_between(StreamIndex::from(0), header.begin())
            {
                return XNetAdvertOutcome::NothingNew;
            }
        }

        self.slice_pool
            .lock()
            .unwrap()
            .classify_advert(source_subnet, header, own_stream)
    }

    /// Returns the certified headers for every subnet we owe an advert to.
    fn adverts_owed(&self) -> Vec<(SubnetId, CertifiedStreamSlice)> {
        self.subnets_owed_adverts()
            .into_iter()
            .filter_map(|subnet_id| Some((subnet_id, self.certified_header(subnet_id)?)))
            .collect()
    }

    /// Returns the subnets we owe an advert to, as of our latest certified state:
    /// those whose stream holds messages; and those that we have signals for,
    /// relative to the recorded header.
    fn subnets_owed_adverts(&self) -> Vec<SubnetId> {
        let Some(state) = self.state_manager.get_latest_certified_state() else {
            return Vec::new();
        };
        let state = state.get_ref();
        let slice_pool = self.slice_pool.lock().unwrap();

        state
            .streams()
            .iter()
            // The loopback stream is not routed through XNet.
            .filter(|(subnet_id, _)| **subnet_id != state.metadata.own_subnet_id)
            .filter(|(subnet_id, stream)| {
                let peer_begin = slice_pool
                    .peer_header(**subnet_id)
                    .map_or(StreamIndex::from(0), |header| header.begin());
                !stream.messages().is_empty() || stream.signals_end() > peer_begin
            })
            .map(|(subnet_id, _)| *subnet_id)
            .collect()
    }
}

impl XNetAdvertHandler for XNetAdvertHandlerImpl {
    fn handle_advert(
        &self,
        source_subnet: SubnetId,
        advert: CertifiedStreamSlice,
    ) -> Result<XNetAdvertOutcome, XNetAdvertError> {
        // Decode without verifying: classifying the claimed header is cheap, and the
        // outcomes that do not act (due to no new content) don't need verification.
        let claimed = decode_slice_header(&advert.payload)
            .map_err(|err| XNetAdvertError::DecodeError(err.to_string()))?;
        let outcome = self.classify_advert(source_subnet, &claimed);
        match outcome {
            // Valid or not, there is nothing for us to see here.
            XNetAdvertOutcome::InPayload | XNetAdvertOutcome::Pooled => return Ok(outcome),

            // A duplicate of a previously recorded header: re-enqueue _the recorded header_
            // for a pull, in case we tried and failed before.
            XNetAdvertOutcome::Duplicate => {
                self.slice_pool.lock().unwrap().schedule_pull(source_subnet);
                return Ok(outcome);
            }

            // Don't bother verifying the signature if we wouldn't record it anyway.
            // Producing a reply is cheaper and we already checked the node's membership.
            XNetAdvertOutcome::NothingNew
                if !self
                    .slice_pool
                    .lock()
                    .unwrap()
                    .advances_recorded_peer_header(source_subnet, &claimed) =>
            {
                return Ok(outcome);
            }

            // Verify that the header is signed by `source_subnet` before recording it or
            // acting on it.
            XNetAdvertOutcome::NothingNew | XNetAdvertOutcome::Actionable => {}
        }

        // Use the latest registry version for validation. There is a potential race
        // condition here, but it's benign: our and the peer's views of the subnet
        // record will converge eventually, and unblock validation.
        let registry_version = self.registry.get_latest_version();
        let slice = self
            .certified_stream_store
            .decode_certified_stream_slice(source_subnet, registry_version, &advert)
            .map_err(|err| match err {
                DecodeStreamError::InvalidSignature(_) => XNetAdvertError::InvalidSignature,
                _ => XNetAdvertError::DecodeError(err.to_string()),
            })?;
        debug_assert_eq!(slice.header(), &claimed, "Inconsistent slice decoding");

        {
            let mut slice_pool = self.slice_pool.lock().unwrap();
            if outcome == XNetAdvertOutcome::Actionable {
                slice_pool.schedule_pull(source_subnet);
            }

            // Record every verified header: the recorded header shows how far the peer has
            // garbage collected its messages, which is what tells us whether we still owe
            // it an advert.
            slice_pool.record_peer_header(source_subnet, slice.header());
        }

        Ok(outcome)
    }

    fn certified_header(&self, subnet_id: SubnetId) -> Option<CertifiedStreamSlice> {
        match self.certified_stream_store.encode_certified_stream_slice(
            subnet_id,
            None,
            None,
            Some(0),
            None,
        ) {
            Ok(slice) => Some(slice),

            Err(EncodeStreamError::NoStreamForSubnet(_)) => None,

            Err(err @ EncodeStreamError::InvalidSliceBegin { .. })
            | Err(err @ EncodeStreamError::InvalidSliceIndices { .. }) => {
                error!(
                    self.log,
                    "Unreachable: failed to encode certified stream slice for subnet {subnet_id}: {err}"
                );
                debug_assert!(false);
                None
            }
        }
    }
}

/// Retrieves the given node's operator ID at the given registry version.
///
/// Returns `None` if the node record does not exist or the registry read
/// failed.
fn get_node_operator_id(
    node: &NodeId,
    registry: &dyn RegistryClient,
    registry_version: &RegistryVersion,
    log: &ReplicaLogger,
) -> Option<Vec<u8>> {
    registry
        .get_node_record(*node, *registry_version)
        .unwrap_or_else(|_| {
            info!(log, "Failed to retrieve registry record for node {node}");
            None
        })
        .map(|r| r.node_operator_id)
}

/// Retrieves the given node's `NodeRecord` at the given registry version.
fn get_node_record(
    node: NodeId,
    registry: &dyn RegistryClient,
    version: RegistryVersion,
) -> Result<NodeRecord, Error> {
    registry
        .get_node_record(node, version)
        .map_err(|e| Error::RegistryGetNodeInfoFailed(node, e))?
        .ok_or(Error::MissingXNetEndpoint(node))
}

/// Retrieves the nodes of the given subnet at the given registry version.
///
/// Returns an error if the subnet is missing or has no nodes.
fn get_subnet_nodes(
    subnet: SubnetId,
    registry: &dyn RegistryClient,
    version: RegistryVersion,
) -> Result<Vec<NodeId>, Error> {
    registry
        .get_node_ids_on_subnet(subnet, version)
        .map_err(|e| Error::RegistryGetSubnetInfoFailed(subnet, e))?
        .filter(|nodes| !nodes.is_empty())
        .ok_or(Error::MissingSubnet(subnet))
}

/// Expected number of copies of an advert that each node of the destination
/// subnet should receive; from which the number of targets advertised to by
/// each source node is derived.
const ADVERTS_PER_NODE: usize = 3;

struct AdvertTaskMetrics {
    /// Adverts sent, by destination subnet and outcome.
    adverts_sent: IntCounterVec,

    /// Advert send duration, by outcome.
    send_advert_duration: HistogramVec,

    /// Outstanding advert posts.
    outstanding_adverts: IntGauge,
}

impl AdvertTaskMetrics {
    fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            adverts_sent: metrics_registry.int_counter_vec(
                METRIC_ADVERTS_SENT,
                "Adverts sent, by destination subnet and outcome.",
                &[LABEL_REMOTE, LABEL_STATUS],
            ),
            send_advert_duration: metrics_registry.histogram_vec(
                METRIC_SEND_ADVERT_DURATION,
                "Advert send duration, by outcome.",
                // 0.1ms - 5s
                decimal_buckets(-4, 0),
                &[LABEL_STATUS],
            ),
            outstanding_adverts: metrics_registry
                .int_gauge(METRIC_OUTSTANDING_ADVERTS, "Outstanding advert posts."),
        }
    }
}

/// The reason why an advert could not be posted; or its reply handled.
#[derive(Debug, Error)]
enum AdvertError {
    #[error("Failed to resolve the advert endpoint: {0}")]
    Resolve(#[from] Error),
    #[error("Failed to post the advert: {0}")]
    Post(#[from] XNetClientError),
    #[error("Failed to handle advert reply: {0}")]
    HandleReply(#[from] XNetAdvertError),
}

impl AdvertError {
    /// Maps the error to a `status` label value.
    fn to_label_value(&self) -> String {
        match self {
            AdvertError::Resolve(err) => err.to_label_value().to_string(),
            AdvertError::Post(err) => err.to_label_value(),
            AdvertError::HandleReply(err) => err.as_str().to_string(),
        }
    }
}

/// Advertises our streams to their respective destination subnets.
///
/// The counterpart of `PullTask`, for sending adverts. On every new
/// certified height, advertises our stream for each subnet that may not have
/// seen all of it, to a few of that subnet's nodes, picked at random.
pub(crate) struct AdvertTask {
    /// Decides which subnets we owe an advert to; and handles the headers that
    /// peers reply with, as it handles the adverts they post to us.
    advert_handler: Arc<XNetAdvertHandlerImpl>,

    /// Picks the nodes to advertise to and resolves their URLs.
    endpoint_resolver: Arc<XNetEndpointResolver>,

    /// Async client for posting adverts to `XNetEndpoints`.
    xnet_client: Arc<dyn XNetClient>,

    metrics: AdvertTaskMetrics,

    log: ReplicaLogger,
}

impl AdvertTask {
    pub(crate) fn new(
        advert_handler: Arc<XNetAdvertHandlerImpl>,
        endpoint_resolver: Arc<XNetEndpointResolver>,
        xnet_client: Arc<dyn XNetClient>,
        metrics_registry: &MetricsRegistry,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            advert_handler,
            endpoint_resolver,
            xnet_client,
            metrics: AdvertTaskMetrics::new(metrics_registry),
            log,
        }
    }

    /// Starts an async task advertising streams with new content on every change of
    /// `max_certified_height_rx`. It ends once the sender is dropped.
    pub(crate) fn start(
        self,
        mut max_certified_height_rx: watch::Receiver<Height>,
        runtime_handle: &runtime::Handle,
    ) {
        let task = Arc::new(self);
        runtime_handle.spawn(async move {
            while max_certified_height_rx.changed().await.is_ok() {
                task.advertise().await;
            }
        });
    }

    /// Posts our certified header to the chosen targets, for every subnet we owe an
    /// advert to. Does not wait for the posts to complete.
    async fn advertise(self: &Arc<Self>) {
        let task = Arc::clone(self);
        let adverts = match tokio::task::spawn_blocking(move || task.adverts_to_send()).await {
            Ok(adverts) => adverts,
            Err(err) => {
                warn!(self.log, "Failed to join advert blocking thread: {}", err);
                return;
            }
        };

        for (subnet_id, advert, targets) in adverts {
            for node in targets {
                let task = Arc::clone(self);
                let advert = advert.clone();
                tokio::spawn(async move { task.advertise_to(subnet_id, node, advert).await });
            }
        }
    }

    /// Returns our certified header and the nodes to post it to, for every subnet
    /// we owe an advert to.
    fn adverts_to_send(&self) -> Vec<(SubnetId, CertifiedStreamSlice, Vec<NodeId>)> {
        self.advert_handler
            .adverts_owed()
            .into_iter()
            .filter_map(|(subnet_id, advert)| {
                match self.endpoint_resolver.advert_targets(subnet_id) {
                    Ok(targets) => Some((subnet_id, advert, targets)),
                    Err(err) => {
                        log!(
                            self.log,
                            err.log_level(),
                            "Failed to advertise to {subnet_id}: {err}"
                        );
                        self.metrics
                            .adverts_sent
                            .with_label_values(&[&subnet_id.to_string(), err.to_label_value()])
                            .inc();
                        None
                    }
                }
            })
            .collect()
    }

    /// Calls `post_advert()`, to send `advert` and handle any response; and
    /// records the outcome.
    async fn advertise_to(&self, subnet_id: SubnetId, node: NodeId, advert: CertifiedStreamSlice) {
        let since = Instant::now();
        let status = match self.post_advert(subnet_id, node, advert).await {
            // Advert delivered and accepted.
            Ok(None) => STATUS_SUCCESS.to_string(),

            // Peer had already processed our stream and responded with its header as proof.
            // This is the outcome of us having processed that header.
            Ok(Some(outcome)) => outcome.as_str().to_string(),

            // A bad reply implicates the node, which only the log names, so always log.
            Err(err @ AdvertError::HandleReply(_)) => {
                warn!(
                    self.log,
                    "Failed to handle advert response for {subnet_id} from node {node}: {err}"
                );
                err.to_label_value()
            }

            // Advert could not be delivered.
            Err(err) => {
                if pass_log_sampling() {
                    info!(
                        self.log,
                        "Failed to advertise to {subnet_id} at node {node}: {err}"
                    );
                }
                err.to_label_value()
            }
        };

        self.metrics
            .adverts_sent
            .with_label_values(&[&subnet_id.to_string(), &status])
            .inc();
        self.metrics
            .send_advert_duration
            .with_label_values(&[&status])
            .observe(since.elapsed().as_secs_f64());
    }

    /// Posts `advert` to `node` of `subnet_id` and feeds a header returned in the
    /// reply, if any, back to the advert handler.
    async fn post_advert(
        &self,
        subnet_id: SubnetId,
        node: NodeId,
        advert: CertifiedStreamSlice,
    ) -> Result<Option<XNetAdvertOutcome>, AdvertError> {
        let endpoint = self.endpoint_resolver.xnet_advert_url(node)?;

        self.metrics.outstanding_adverts.inc();
        let result = self.xnet_client.post_advert(&endpoint, advert).await;
        self.metrics.outstanding_adverts.dec();

        let Some(reply) = result? else {
            return Ok(None);
        };

        // The peer already had the advertised content and it replied with a certified
        // header proving it. `handle_advert()` verifies the threshold signature,
        // so offload it to a blocking task.
        let advert_handler = Arc::clone(&self.advert_handler);
        let outcome =
            tokio::task::spawn_blocking(move || advert_handler.handle_advert(subnet_id, reply))
                .await
                .expect("Handling an advert reply panicked")?;
        Ok(Some(outcome))
    }
}

/// Number of nodes of a subnet of `peer_subnet_size` nodes that each of our
/// nodes should advertise to, for each of the peer's nodes to receive
/// `ADVERTS_PER_NODE` adverts, based on the two subnet sizes.
fn advert_target_count(own_subnet_size: usize, peer_subnet_size: usize) -> usize {
    (ADVERTS_PER_NODE * peer_subnet_size)
        .div_ceil(own_subnet_size.max(1))
        .clamp(1, peer_subnet_size.max(1))
}

pub const METRIC_PULL_ATTEMPT_COUNT: &str = "xnet_builder_pull_attempt_count";
pub const METRIC_QUERY_SLICE_DURATION: &str = "xnet_builder_query_slice_duration_seconds";
pub const METRIC_RESPONSE_BODY_SIZE: &str = "xnet_builder_response_body_size_bytes";
pub const METRIC_OUTSTANDING_XNET_QUERIES: &str = "xnet_builder_outstanding_queries";
pub const METRIC_ADVERTS_SENT: &str = "xnet_builder_adverts_sent_total";
pub const METRIC_SEND_ADVERT_DURATION: &str = "xnet_builder_advert_send_duration_seconds";
pub const METRIC_OUTSTANDING_ADVERTS: &str = "xnet_builder_outstanding_adverts";
pub const METRIC_SHADOW_PULLS: &str = "xnet_builder_shadow_pulls_total";
pub const LABEL_PROXIMITY: &str = "proximity";
pub const LABEL_REMOTE: &str = "remote";
pub const LABEL_SCHEDULED: &str = "scheduled";
pub const LABEL_POOLED: &str = "pooled";
pub const STATUS_DECODE_ERROR: &str = "ProxyDecodeError";

/// Metrics of `PullTask`.
pub struct PullTaskMetrics {
    /// Records pull attempts, by status. Orthogonal to slice queries, as some
    /// attempts may fail before querying (e.g. due to registry errors) and
    /// some successful queries may produce invalid slices.
    pub pull_attempt_count: IntCounterVec,
    /// Records the time it took to query a slice to be included into the
    /// payload, by status. Orthogonal to pull attempts, as some attempts may
    /// fail before querying (e.g. due to registry errors) and some successful
    /// queries may produce invalid slices.
    pub query_slice_duration: HistogramVec,
    /// Track outstanding background query tasks
    pub outstanding_queries: IntGauge,
    /// Count of pulled slices larger than the requested size.
    pub pull_size_too_large: IntCounter,
    /// Temporary: completed pulls, by remote subnet; whether advert-driven pulling
    /// would have scheduled them; and whether they pooled anything.
    ///
    /// Not fully independent of the sweep: pulled headers are recorded too, so a
    /// pull extending an already pooled prefix counts as scheduled even without an
    /// advert. Unscheduled pulls that pool something point to missed adverts.
    pub shadow_pulls: IntCounterVec,
}

impl PullTaskMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            pull_attempt_count: metrics_registry.int_counter_vec(
                METRIC_PULL_ATTEMPT_COUNT,
                "Attempted XNet pulls, by status.",
                &[LABEL_STATUS],
            ),
            query_slice_duration: metrics_registry.histogram_vec(
                METRIC_QUERY_SLICE_DURATION,
                "The time it took to query a slice to be included into the payload, by status and proximity.",
                // 0.1ms - 5s
                decimal_buckets(-4, 0),
                &[LABEL_STATUS, LABEL_PROXIMITY],
            ),
            outstanding_queries: metrics_registry.int_gauge(
                METRIC_OUTSTANDING_XNET_QUERIES,
                "Number of xnet queries that have not finished",
            ),
            pull_size_too_large: metrics_registry.int_counter(
                "xnet_builder_pull_size_too_large_count",
                "Count of pulled slices larger than the requested size",
            ),
            shadow_pulls: metrics_registry.int_counter_vec(
                METRIC_SHADOW_PULLS,
                "Completed pulls, by remote subnet; whether advert-driven pulling would have scheduled them; and whether they pooled anything.",
                &[LABEL_REMOTE, LABEL_SCHEDULED, LABEL_POOLED],
            ),
        }
    }

    /// Increments the `pull_attempt_count` counter for the given status.
    fn observe_pull_attempt(&self, status: &str) {
        self.pull_attempt_count.with_label_values(&[status]).inc();
    }

    /// Observes the elapsed `query_slice_duration` under the given status.
    fn observe_query_slice_duration(&self, status: &str, proximity: &str, since: Instant) {
        self.query_slice_duration
            .with_label_values(&[status, proximity])
            .observe(since.elapsed().as_secs_f64());
    }

    /// Records a completed pull from `subnet_id`.
    fn observe_shadow_pull(&self, subnet_id: SubnetId, scheduled: bool, pooled: bool) {
        self.shadow_pulls
            .with_label_values(&[
                &subnet_id.to_string(),
                &scheduled.to_string(),
                &pooled.to_string(),
            ])
            .inc();
    }
}

/// Describes the slice to be pulled from a subnet: messages from `msg_begin`,
/// with a witness from `witness_begin`, of at most `byte_limit` bytes.
pub struct PullIndices {
    pub witness_begin: StreamIndex,
    pub msg_begin: StreamIndex,
    pub byte_limit: usize,
}

/// A handle for a `PullTask` to be used for triggering pool refills and
/// terminating the task (by dropping the handle).
pub struct RefillTaskHandle(pub Mutex<mpsc::Sender<RegistryVersion>>);

impl RefillTaskHandle {
    /// Triggers a slice pool refill, validating slices against the given registry
    /// version.
    pub fn trigger_refill(&self, registry_version: RegistryVersion) {
        // We don't care if the send succeeded or not. If it didn't, the refill task is
        // just behind.
        self.0.lock().unwrap().try_send(registry_version).ok();
    }
}

/// An async task that pulls stream slices into the slice pool.
pub struct PullTask {
    /// The slice pool that this task populates.
    pool: Arc<Mutex<CertifiedSlicePool>>,

    endpoint_resolver: Arc<XNetEndpointResolver>,

    /// Async client for querying `XNetEndpoints`.
    xnet_client: Arc<dyn XNetClient>,

    /// Used for validating slices before they are pooled.
    certified_stream_store: Arc<dyn CertifiedStreamStore>,

    /// Tokio runtime to be used for spawning async query tasks.
    runtime_handle: runtime::Handle,

    metrics: PullTaskMetrics,

    log: ReplicaLogger,
}

impl PullTask {
    /// Starts an async task that fills the slice pool in the background.
    pub fn start(
        pool: Arc<Mutex<CertifiedSlicePool>>,
        endpoint_resolver: Arc<XNetEndpointResolver>,
        xnet_client: Arc<dyn XNetClient>,
        certified_stream_store: Arc<dyn CertifiedStreamStore>,
        runtime_handle: runtime::Handle,
        metrics_registry: &MetricsRegistry,
        log: ReplicaLogger,
    ) -> RefillTaskHandle {
        let (refill_trigger, mut refill_receiver) = mpsc::channel(1);
        let task = Arc::new(Self {
            pool,
            endpoint_resolver,
            xnet_client,
            certified_stream_store,
            runtime_handle: runtime_handle.clone(),
            metrics: PullTaskMetrics::new(metrics_registry),
            log,
        });

        runtime_handle.spawn(async move {
            while let Some(registry_version) = refill_receiver.recv().await {
                task.refill_pool(registry_version);
            }
        });

        RefillTaskHandle(Mutex::new(refill_trigger))
    }

    /// Queries all subnets for new slices and puts / appends them to the pool after
    /// validation against the given registry version.
    ///
    /// Also unschedules every subnet it pulls from, as advert-driven pulling
    /// would; and records whether it was scheduled and whether the pull pooled
    /// anything.
    fn refill_pool(self: &Arc<Self>, registry_version: RegistryVersion) {
        let pulls: Vec<_> = {
            let mut pool = self.pool.lock().unwrap();
            pool.refill_stream_slice_indices(self.endpoint_resolver.subnet_id)
                .into_iter()
                .map(|(subnet_id, indices)| (subnet_id, indices, pool.unschedule_pull(subnet_id)))
                .collect()
        };

        for (subnet_id, indices, scheduled) in pulls {
            let task = Arc::clone(self);
            self.runtime_handle.spawn(async move {
                if let Ok(pooled) = task.pull(subnet_id, indices, registry_version).await {
                    task.metrics
                        .observe_shadow_pull(subnet_id, scheduled, pooled);
                }
            });
        }
    }

    /// Queries a node of `subnet_id` for the slice described by `indices`; and
    /// puts / appends it to the pool after validation against `registry_version`.
    ///
    /// Returns whether the pulled slice was pooled (`false` if there is no stream);
    /// or `Err(())` if the pull failed (already logged and recorded).
    async fn pull(
        self: &Arc<Self>,
        subnet_id: SubnetId,
        indices: PullIndices,
        registry_version: RegistryVersion,
    ) -> Result<bool, ()> {
        // `XNetEndpoint` URL of a node on `subnet_id`.
        let endpoint = match self.endpoint_resolver.xnet_stream_url(
            subnet_id,
            indices.witness_begin,
            indices.msg_begin,
            indices.byte_limit,
        ) {
            Ok(endpoint) => endpoint,
            Err(e) => {
                log!(self.log, e.log_level(), "{}", e);
                self.metrics.observe_pull_attempt(e.to_label_value());
                return Err(());
            }
        };

        let since = Instant::now();
        self.metrics.outstanding_queries.inc();
        let query_result = self.xnet_client.query(&endpoint).await;
        self.metrics.outstanding_queries.dec();
        let proximity = endpoint.proximity.into();

        match query_result {
            Ok(slice) => {
                let is_suffix = indices.witness_begin != indices.msg_begin;

                // Log and instrument pulled slices above the requested byte limit. In the
                // future, we may drop such slices.
                let byte_limit = if is_suffix {
                    indices.byte_limit
                } else {
                    // A complete slice always includes the first message, regardless of byte limit.
                    indices
                        .byte_limit
                        .max(MAX_INTER_CANISTER_PAYLOAD_IN_BYTES.get() as usize)
                };
                if slice.payload.len() > byte_limit * 11 / 10 + 1024 {
                    warn!(
                        self.log,
                        "Stream from {subnet_id}: pulled payload size ({}) exceeds byte limit ({byte_limit})",
                        slice.payload.len()
                    );
                    self.metrics.pull_size_too_large.inc();
                }

                // A suffix is appended to the pooled slice; a complete slice replaces it.
                let put_or_append = if is_suffix {
                    CertifiedSlicePool::append
                } else {
                    CertifiedSlicePool::put
                };
                // Blocking because validation verifies the threshold signature.
                let task = Arc::clone(self);
                match tokio::task::spawn_blocking(move || {
                    put_or_append(
                        &task.pool,
                        subnet_id,
                        slice,
                        task.certified_stream_store.as_ref(),
                        registry_version,
                        &task.log,
                    )
                })
                .await
                {
                    Ok(res) => {
                        let status = match &res {
                            Ok(_) => STATUS_SUCCESS,
                            Err(e) => e.to_label_value(),
                        };

                        self.metrics
                            .observe_query_slice_duration(status, proximity, since);
                        self.metrics.observe_pull_attempt(status);
                        res.map_err(|_| ())
                    }

                    Err(err) => {
                        warn!(
                            self.log,
                            "Failed to join pool refill blocking thread: {err}"
                        );
                        Err(())
                    }
                }
            }

            Err(e) => {
                self.metrics
                    .observe_query_slice_duration(&e.to_label_value(), proximity, since);
                self.metrics.observe_pull_attempt(&e.to_label_value());
                if let XNetClientError::NoContent = e {
                    return Ok(false);
                }
                if pass_log_sampling() {
                    info!(
                        self.log,
                        "Failed to query stream slice for subnet {subnet_id} from node {}: {e}",
                        endpoint.node_id,
                    );
                }
                Err(())
            }
        }
    }
}

fn pass_log_sampling() -> bool {
    /// The fraction of INFO logs related to stream pulls and adverts that XNet
    /// payload builder displays. The logs become very polluted if we don't
    /// sample them.
    const LOG_PASS_THROUGH_RATE: f64 = 0.05;

    thread_rng().gen_bool(LOG_PASS_THROUGH_RATE)
}
