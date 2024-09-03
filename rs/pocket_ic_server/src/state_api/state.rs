/// This module contains the core state of the PocketIc server.
/// Axum handlers operate on a global state of type ApiState, whose
/// interface guarantees consistency and determinism.
use crate::pocket_ic::{
    AdvanceTimeAndTick, ApiResponse, CanisterHttpAdapters, EffectivePrincipal, GetCanisterHttp,
    MockCanisterHttp, PocketIc,
};
use crate::state_api::canister_id::{self, DomainResolver, ResolvesDomain};
use crate::{InstanceId, OpId, Operation};
use axum::{
    extract::{Request as AxumRequest, State},
    response::{IntoResponse, Response},
};
use axum_server::tls_rustls::RustlsConfig;
use axum_server::Handle;
use base64;
use fqdn::{fqdn, FQDN};
use futures::future::Shared;
use http::{
    header::{
        ACCEPT_RANGES, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, COOKIE, DNT,
        IF_MODIFIED_SINCE, IF_NONE_MATCH, RANGE, USER_AGENT,
    },
    HeaderName, Method, StatusCode,
};
use http_body_util::{BodyExt, LengthLimitError, Limited};
use ic_http_endpoints_public::cors_layer;
use ic_http_gateway::{CanisterRequest, HttpGatewayClient, HttpGatewayRequestArgs};
use ic_https_outcalls_adapter::CanisterHttp;
use ic_https_outcalls_adapter_client::grpc_status_code_to_reject;
use ic_https_outcalls_service::{
    canister_http_service_server::CanisterHttpService, CanisterHttpSendRequest,
    CanisterHttpSendResponse, HttpHeader, HttpMethod,
};
use ic_state_machine_tests::RejectCode;
use ic_types::{
    canister_http::{CanisterHttpRequestId, MAX_CANISTER_HTTP_RESPONSE_BYTES},
    CanisterId, PrincipalId, SubnetId,
};
use pocket_ic::common::rest::{
    CanisterHttpHeader, CanisterHttpMethod, CanisterHttpReject, CanisterHttpReply,
    CanisterHttpRequest, CanisterHttpResponse, HttpGatewayBackend, HttpGatewayConfig,
    HttpGatewayDetails, HttpGatewayInfo, MockCanisterHttpResponse, Topology,
};
use pocket_ic::{ErrorCode, UserError, WasmResult};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt, path::PathBuf, str::FromStr, sync::Arc, time::Duration};
use tokio::{
    sync::mpsc::error::TryRecvError,
    sync::mpsc::Receiver,
    sync::{mpsc, Mutex, RwLock},
    task::{spawn, spawn_blocking, JoinHandle},
    time::{self, sleep, Instant},
};
use tonic::Request;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, trace};

// The maximum wait time for a computation to finish synchronously.
const DEFAULT_SYNC_WAIT_DURATION: Duration = Duration::from_secs(10);

// The timeout for executing an operation in auto progress mode.
const AUTO_PROGRESS_OPERATION_TIMEOUT: Duration = Duration::from_secs(10);
// The minimum delay between consecutive attempts to run an operation in auto progress mode.
const MIN_OPERATION_DELAY: Duration = Duration::from_millis(100);
// The minimum delay between consecutive attempts to read the graph in auto progress mode.
const READ_GRAPH_DELAY: Duration = Duration::from_millis(100);

pub const STATE_LABEL_HASH_SIZE: usize = 32;

/// Uniquely identifies a state.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Default, Deserialize)]
pub struct StateLabel(pub [u8; STATE_LABEL_HASH_SIZE]);

// The only error condition is if the vector has the wrong size.
pub struct InvalidSize;

impl std::fmt::Debug for StateLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StateLabel(")?;
        self.0.iter().try_for_each(|b| write!(f, "{:02X}", b))?;
        write!(f, ")")
    }
}

impl std::convert::TryFrom<Vec<u8>> for StateLabel {
    // The input vector having the wrong size is the only possible error condition.
    type Error = InvalidSize;

    fn try_from(v: Vec<u8>) -> Result<StateLabel, InvalidSize> {
        if v.len() != STATE_LABEL_HASH_SIZE {
            return Err(InvalidSize);
        }

        let mut res = StateLabel::default();
        res.0[0..STATE_LABEL_HASH_SIZE].clone_from_slice(v.as_slice());
        Ok(res)
    }
}

struct ProgressThread {
    handle: JoinHandle<()>,
    sender: mpsc::Sender<()>,
}

/// The state of the PocketIC API.
pub struct ApiState {
    // impl note: If locks are acquired on multiple fields, acquire first on `instances`, then on `canister_http_adapters`, and then on `graph`.
    instances: Arc<RwLock<Vec<Mutex<InstanceState>>>>,
    canister_http_adapters: Arc<RwLock<HashMap<InstanceId, CanisterHttpAdapters>>>,
    graph: Arc<RwLock<HashMap<StateLabel, Computations>>>,
    // threads making IC instances progress automatically
    progress_threads: RwLock<Vec<Mutex<Option<ProgressThread>>>>,
    sync_wait_time: Duration,
    // PocketIC server port
    port: Option<u16>,
    // HTTP gateway infos (`None` = stopped)
    http_gateways: Arc<RwLock<Vec<Option<HttpGatewayDetails>>>>,
}

#[derive(Default)]
pub struct PocketIcApiStateBuilder {
    initial_instances: Vec<PocketIc>,
    sync_wait_time: Option<Duration>,
    port: Option<u16>,
}

impl PocketIcApiStateBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    /// Computations are dispatched into background tasks. If a computation takes longer than
    /// [sync_wait_time], the update-operation returns, indicating that the given instance is busy.
    pub fn with_sync_wait_time(self, sync_wait_time: Duration) -> Self {
        Self {
            sync_wait_time: Some(sync_wait_time),
            ..self
        }
    }

    pub fn with_port(self, port: u16) -> Self {
        Self {
            port: Some(port),
            ..self
        }
    }

    /// Will make the given instance available in the initial state.
    pub fn add_initial_instance(mut self, instance: PocketIc) -> Self {
        self.initial_instances.push(instance);
        self
    }

    pub fn build(self) -> Arc<ApiState> {
        let graph: HashMap<StateLabel, Computations> = self
            .initial_instances
            .iter()
            .map(|i| (i.get_state_label(), Computations::default()))
            .collect();
        let graph = RwLock::new(graph);

        let canister_http_adapters = RwLock::new(
            self.initial_instances
                .iter()
                .enumerate()
                .map(|(instance_id, instance)| (instance_id, instance.canister_http_adapters()))
                .collect(),
        );

        let instances: Vec<_> = self
            .initial_instances
            .into_iter()
            .map(|inst| Mutex::new(InstanceState::Available(inst)))
            .collect();
        let instances_len = instances.len();
        let instances = RwLock::new(instances);

        let progress_threads = RwLock::new((0..instances_len).map(|_| Mutex::new(None)).collect());

        let sync_wait_time = self.sync_wait_time.unwrap_or(DEFAULT_SYNC_WAIT_DURATION);

        Arc::new(ApiState {
            instances: instances.into(),
            canister_http_adapters: canister_http_adapters.into(),
            graph: graph.into(),
            progress_threads,
            sync_wait_time,
            port: self.port,
            http_gateways: Arc::new(RwLock::new(Vec::new())),
        })
    }
}

#[derive(Clone)]
pub enum OpOut {
    NoOutput,
    Time(u64),
    CanisterResult(Result<WasmResult, UserError>),
    CanisterId(CanisterId),
    Cycles(u128),
    Bytes(Vec<u8>),
    StableMemBytes(Vec<u8>),
    MaybeSubnetId(Option<SubnetId>),
    Error(PocketIcError),
    RawResponse(Shared<ApiResponse>),
    Pruned,
    MessageId((EffectivePrincipal, Vec<u8>)),
    Topology(Topology),
    CanisterHttp(Vec<CanisterHttpRequest>),
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize)]
pub enum PocketIcError {
    CanisterNotFound(CanisterId),
    BadIngressMessage(String),
    SubnetNotFound(candid::Principal),
    RequestRoutingError(String),
    InvalidCanisterHttpRequestId((SubnetId, CanisterHttpRequestId)),
}

impl From<Result<ic_state_machine_tests::WasmResult, ic_state_machine_tests::UserError>> for OpOut {
    fn from(
        r: Result<ic_state_machine_tests::WasmResult, ic_state_machine_tests::UserError>,
    ) -> Self {
        let res = {
            match r {
                Ok(ic_state_machine_tests::WasmResult::Reply(wasm)) => Ok(WasmResult::Reply(wasm)),
                Ok(ic_state_machine_tests::WasmResult::Reject(s)) => Ok(WasmResult::Reject(s)),
                Err(user_err) => Err(UserError {
                    code: ErrorCode::try_from(user_err.code() as u64).unwrap(),
                    description: user_err.description().to_string(),
                }),
            }
        };
        OpOut::CanisterResult(res)
    }
}

// TODO: Remove this Into: It's only used in the InstallCanisterAsController Operation, which also should be removed.
impl From<Result<(), ic_state_machine_tests::UserError>> for OpOut {
    fn from(r: Result<(), ic_state_machine_tests::UserError>) -> Self {
        let res = {
            match r {
                Ok(_) => Ok(WasmResult::Reply(vec![])),
                Err(user_err) => Err(UserError {
                    code: ErrorCode::try_from(user_err.code() as u64).unwrap(),
                    description: user_err.description().to_string(),
                }),
            }
        };
        OpOut::CanisterResult(res)
    }
}

impl std::fmt::Debug for OpOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpOut::NoOutput => write!(f, "NoOutput"),
            OpOut::Time(x) => write!(f, "Time({})", x),
            OpOut::Topology(t) => write!(f, "Topology({:?})", t),
            OpOut::CanisterId(cid) => write!(f, "CanisterId({})", cid),
            OpOut::Cycles(x) => write!(f, "Cycles({})", x),
            OpOut::CanisterResult(Ok(x)) => write!(f, "CanisterResult: Ok({:?})", x),
            OpOut::CanisterResult(Err(x)) => write!(f, "CanisterResult: Err({})", x),
            OpOut::Error(PocketIcError::CanisterNotFound(cid)) => {
                write!(f, "CanisterNotFound({})", cid)
            }
            OpOut::Error(PocketIcError::BadIngressMessage(msg)) => {
                write!(f, "BadIngressMessage({})", msg)
            }
            OpOut::Error(PocketIcError::SubnetNotFound(sid)) => {
                write!(f, "SubnetNotFound({})", sid)
            }
            OpOut::Error(PocketIcError::RequestRoutingError(msg)) => {
                write!(f, "RequestRoutingError({:?})", msg)
            }
            OpOut::Error(PocketIcError::InvalidCanisterHttpRequestId((
                subnet_id,
                canister_http_request_id,
            ))) => {
                write!(
                    f,
                    "InvalidCanisterHttpRequestId({},{:?})",
                    subnet_id, canister_http_request_id
                )
            }
            OpOut::Bytes(bytes) => write!(f, "Bytes({})", base64::encode(bytes)),
            OpOut::StableMemBytes(bytes) => write!(f, "StableMemory({})", base64::encode(bytes)),
            OpOut::MaybeSubnetId(Some(subnet_id)) => write!(f, "SubnetId({})", subnet_id),
            OpOut::MaybeSubnetId(None) => write!(f, "NoSubnetId"),
            OpOut::RawResponse(fut) => {
                write!(
                    f,
                    "ApiResp({:?})",
                    fut.peek().map(|(status, headers, bytes)| format!(
                        "{}:{:?}:{}",
                        status,
                        headers,
                        base64::encode(bytes)
                    ))
                )
            }
            OpOut::Pruned => write!(f, "Pruned"),
            OpOut::MessageId((effective_principal, message_id)) => {
                write!(
                    f,
                    "MessageId({:?},{})",
                    effective_principal,
                    hex::encode(message_id)
                )
            }
            OpOut::CanisterHttp(canister_http_reqeusts) => {
                write!(f, "CanisterHttp({:?})", canister_http_reqeusts)
            }
        }
    }
}

pub type Computations = HashMap<OpId, (StateLabel, OpOut)>;

/// The PocketIcApiState has a vector with elements of InstanceState.
/// When an operation is bound to an instance, the corresponding element in the
/// vector is replaced by a Busy variant which contains information about the
/// computation that is currently running. Afterwards, the instance is put back as
/// Available.
pub enum InstanceState {
    Busy {
        state_label: StateLabel,
        op_id: OpId,
    },
    Available(PocketIc),
    Deleted,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpdateError {
    message: String,
}

pub type UpdateResult = std::result::Result<UpdateReply, UpdateError>;

/// An operation bound to an instance can be dispatched, which updates the instance.
/// If the instance is already busy with an operation, the initial state and that operation
/// are returned.
/// If the result can be read from a cache, or if the computation is a fast read, an Output is
/// returned directly.
/// If the computation can be run and takes longer, a Started variant is returned, containing the
/// requested op and the initial state.
#[derive(Debug)]
pub enum UpdateReply {
    /// The requested instance is busy executing another update.
    Busy {
        state_label: StateLabel,
        op_id: OpId,
    },
    /// The requested instance is busy executing this current update.
    Started {
        state_label: StateLabel,
        op_id: OpId,
    },
    // This request is either cached or quickly executable, so we return
    // the output immediately.
    Output(OpOut),
}

impl UpdateReply {
    pub fn get_in_progress(&self) -> Option<(StateLabel, OpId)> {
        match self {
            Self::Busy { state_label, op_id } => Some((state_label.clone(), op_id.clone())),
            Self::Started { state_label, op_id } => Some((state_label.clone(), op_id.clone())),
            _ => None,
        }
    }
}

/// This trait lets us put a mock of the pocket_ic into the PocketIcApiState.
pub trait HasStateLabel {
    fn get_state_label(&self) -> StateLabel;
}

enum ApiVersion {
    V2,
    V3,
}

impl std::fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiVersion::V2 => write!(f, "v2"),
            ApiVersion::V3 => write!(f, "v3"),
        }
    }
}

fn received_stop_signal(rx: &mut Receiver<()>) -> bool {
    match rx.try_recv() {
        Ok(_) | Err(TryRecvError::Disconnected) => true,
        Err(TryRecvError::Empty) => false,
    }
}

// ADAPTED from ic-gateway

const HEADER_IC_CANISTER_ID: HeaderName = HeaderName::from_static("x-ic-canister-id");
const MAX_REQUEST_BODY_SIZE: usize = 10 * 1_048_576;
const MINUTE: Duration = Duration::from_secs(60);

fn layer(methods: &[Method]) -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(methods.to_vec())
        .expose_headers([
            ACCEPT_RANGES,
            CONTENT_LENGTH,
            CONTENT_RANGE,
            HEADER_IC_CANISTER_ID,
        ])
        .allow_headers([
            USER_AGENT,
            DNT,
            IF_NONE_MATCH,
            IF_MODIFIED_SINCE,
            CACHE_CONTROL,
            CONTENT_TYPE,
            RANGE,
            COOKIE,
            HEADER_IC_CANISTER_ID,
        ])
        .max_age(10 * MINUTE)
}

// Categorized possible causes for request processing failures
// Not using Error as inner type since it's not cloneable
#[derive(Clone, Debug)]
enum ErrorCause {
    ConnectionFailure(String),
    UnableToReadBody(String),
    RequestTooLarge,
    NoAuthority,
    UnknownDomain,
    CanisterIdNotFound,
}

impl ErrorCause {
    const fn status_code(&self) -> StatusCode {
        match self {
            Self::ConnectionFailure(_) => StatusCode::BAD_GATEWAY,
            Self::UnableToReadBody(_) => StatusCode::REQUEST_TIMEOUT,
            Self::RequestTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::NoAuthority => StatusCode::BAD_REQUEST,
            Self::UnknownDomain => StatusCode::BAD_REQUEST,
            Self::CanisterIdNotFound => StatusCode::BAD_REQUEST,
        }
    }

    fn details(&self) -> Option<String> {
        match self {
            Self::ConnectionFailure(x) => Some(x.clone()),
            Self::UnableToReadBody(x) => Some(x.clone()),
            _ => None,
        }
    }
}

impl fmt::Display for ErrorCause {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::ConnectionFailure(_) => write!(f, "connection_failure"),
            Self::UnableToReadBody(_) => write!(f, "unable_to_read_body"),
            Self::RequestTooLarge => write!(f, "request_too_large"),
            Self::NoAuthority => write!(f, "no_authority"),
            Self::UnknownDomain => write!(f, "unknown_domain"),
            Self::CanisterIdNotFound => write!(f, "canister_id_not_found"),
        }
    }
}

// Creates the response from ErrorCause and injects itself into extensions to be visible by middleware
impl IntoResponse for ErrorCause {
    fn into_response(self) -> Response {
        let body = self
            .details()
            .map_or_else(|| self.to_string(), |x| format!("{self}: {x}\n"));

        let mut resp = (self.status_code(), body).into_response();

        resp.extensions_mut().insert(self);
        resp
    }
}

pub(crate) struct HandlerState {
    client: HttpGatewayClient,
    resolver: DomainResolver,
}

impl HandlerState {
    fn new(client: HttpGatewayClient, resolver: DomainResolver) -> Self {
        Self { client, resolver }
    }

    pub(crate) fn resolver(&self) -> &DomainResolver {
        &self.resolver
    }
}

// Main HTTP->IC request handler
async fn handler(
    State(state): State<Arc<HandlerState>>,
    host_canister_id: Option<canister_id::HostHeader>,
    query_param_canister_id: Option<canister_id::QueryParam>,
    referer_host_canister_id: Option<canister_id::RefererHeaderHost>,
    referer_query_param_canister_id: Option<canister_id::RefererHeaderQueryParam>,
    request: AxumRequest,
) -> Result<Response, ErrorCause> {
    // Extract the authority
    let Some(authority) = extract_authority(&request) else {
        return Err(ErrorCause::NoAuthority);
    };

    // Resolve the domain
    let lookup = state
        .resolver
        .resolve(&authority)
        .ok_or(ErrorCause::UnknownDomain)?;

    let canister_id = lookup.canister_id;
    let host_canister_id = host_canister_id.map(|v| v.0);
    let query_param_canister_id = query_param_canister_id.map(|v| v.0);
    let referer_host_canister_id = referer_host_canister_id.map(|v| v.0);
    let referer_query_param_canister_id = referer_query_param_canister_id.map(|v| v.0);
    let canister_id = canister_id
        .or(host_canister_id)
        .or(query_param_canister_id)
        .or(referer_host_canister_id)
        .or(referer_query_param_canister_id)
        .ok_or(ErrorCause::CanisterIdNotFound)?;

    let (parts, body) = request.into_parts();

    // Collect the request body up to the limit
    let body = Limited::new(body, MAX_REQUEST_BODY_SIZE)
        .collect()
        .await
        .map_err(|e| {
            // TODO improve the inferring somehow
            e.downcast_ref::<LengthLimitError>().map_or_else(
                || ErrorCause::UnableToReadBody(e.to_string()),
                |_| ErrorCause::RequestTooLarge,
            )
        })?
        .to_bytes()
        .to_vec();

    let args = HttpGatewayRequestArgs {
        canister_request: CanisterRequest::from_parts(parts, body),
        canister_id,
    };

    let resp = {
        // Execute the request
        let mut req = state.client.request(args);
        // Skip verification if it's disabled globally or if it is a "raw" request.
        req.unsafe_set_skip_verification(!lookup.verify);
        req.send().await
    };

    // Convert it into Axum response
    let response = resp.canister_response.into_response();

    Ok(response)
}

// Attempts to extract host from HTTP2 "authority" pseudo-header or from HTTP/1.1 "Host" header
fn extract_authority(request: &AxumRequest) -> Option<FQDN> {
    // Try HTTP2 first, then Host header
    request
        .uri()
        .authority()
        .map(|x| x.host())
        .or_else(|| {
            request
                .headers()
                .get(http::header::HOST)
                .and_then(|x| x.to_str().ok())
                // Split if it has a port
                .and_then(|x| x.split(':').next())
        })
        .and_then(|x| FQDN::from_str(x).ok())
}

// END ADAPTED from ic-gateway

impl ApiState {
    // Helper function for auto progress mode.
    // Executes an operation to completion and returns its `OpOut`
    // or `None` if the auto progress mode received a stop signal.
    async fn execute_operation(
        instances: Arc<RwLock<Vec<Mutex<InstanceState>>>>,
        graph: Arc<RwLock<HashMap<StateLabel, Computations>>>,
        instance_id: InstanceId,
        op: impl Operation + Send + Sync + 'static,
        rx: &mut Receiver<()>,
    ) -> Option<OpOut> {
        let op = Arc::new(op);
        loop {
            // It is safe to unwrap as there can only be an error if the instance does not exist
            // and there cannot be a progress thread for a non-existing instance (progress threads
            // are stopped before an instance is deleted).
            match Self::update_instances_with_timeout(
                instances.clone(),
                graph.clone(),
                op.clone(),
                instance_id,
                AUTO_PROGRESS_OPERATION_TIMEOUT,
            )
            .await
            .unwrap()
            {
                UpdateReply::Started { state_label, op_id } => {
                    break loop {
                        sleep(READ_GRAPH_DELAY).await;
                        if let Some((_, op_out)) =
                            Self::read_result(graph.clone(), &state_label, &op_id)
                        {
                            break Some(op_out);
                        }
                        if received_stop_signal(rx) {
                            break None;
                        }
                    }
                }
                UpdateReply::Busy { .. } => {}
                UpdateReply::Output(op_out) => break Some(op_out),
            };
            if received_stop_signal(rx) {
                break None;
            }
        }
    }

    /// For polling:
    /// The client lib dispatches a long running operation and gets a Started {state_label, op_id}.
    /// It then polls on that via this state tree api function.
    pub fn read_result(
        graph: Arc<RwLock<HashMap<StateLabel, Computations>>>,
        state_label: &StateLabel,
        op_id: &OpId,
    ) -> Option<(StateLabel, OpOut)> {
        if let Some((new_state_label, op_out)) = graph.try_read().ok()?.get(state_label)?.get(op_id)
        {
            Some((new_state_label.clone(), op_out.clone()))
        } else {
            None
        }
    }

    pub fn get_graph(&self) -> Arc<RwLock<HashMap<StateLabel, Computations>>> {
        self.graph.clone()
    }

    pub async fn add_instance(&self, instance: PocketIc) -> InstanceId {
        let mut instances = self.instances.write().await;
        let mut canister_http_adapters = self.canister_http_adapters.write().await;
        let mut progress_threads = self.progress_threads.write().await;
        let instance_id = instances.len();
        canister_http_adapters.insert(instance_id, instance.canister_http_adapters().clone());
        instances.push(Mutex::new(InstanceState::Available(instance)));
        progress_threads.push(Mutex::new(None));
        instance_id
    }

    pub async fn delete_instance(&self, instance_id: InstanceId) {
        self.stop_progress(instance_id).await;
        let instances = self.instances.read().await;
        let mut canister_http_adapters = self.canister_http_adapters.write().await;
        loop {
            let mut instance_state = instances[instance_id].lock().await;
            match std::mem::replace(&mut *instance_state, InstanceState::Deleted) {
                InstanceState::Available(pocket_ic) => {
                    std::mem::drop(pocket_ic);
                    canister_http_adapters.remove(&instance_id);
                    break;
                }
                InstanceState::Deleted => {
                    break;
                }
                InstanceState::Busy { .. } => {}
            }
            drop(instance_state);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    pub async fn create_http_gateway(
        &self,
        http_gateway_config: HttpGatewayConfig,
    ) -> Result<HttpGatewayInfo, String> {
        use crate::state_api::routes::verify_cbor_content_header;
        use axum::extract::{DefaultBodyLimit, Path, State};
        use axum::routing::{get, post};
        use axum::Router;
        use http_body_util::Full;
        use hyper::body::{Bytes, Incoming};
        use hyper::header::CONTENT_TYPE;
        use hyper::{Method, Request, Response as HyperResponse, StatusCode};
        use hyper_util::client::legacy::{connect::HttpConnector, Client};

        async fn handler_status(
            State(replica_url): State<String>,
            bytes: Bytes,
        ) -> Result<HyperResponse<Incoming>, ErrorCause> {
            let client =
                Client::builder(hyper_util::rt::TokioExecutor::new()).build(HttpConnector::new());
            let url = format!("{}/api/v2/status", replica_url);
            let req = Request::builder()
                .uri(url)
                .header(CONTENT_TYPE, "application/cbor")
                .body(Full::<Bytes>::new(bytes))
                .unwrap();
            client
                .request(req)
                .await
                .map_err(|e| ErrorCause::ConnectionFailure(e.to_string()))
        }

        async fn handler_api_canister(
            api_version: ApiVersion,
            replica_url: String,
            effective_canister_id: CanisterId,
            endpoint: &str,
            bytes: Bytes,
        ) -> Result<HyperResponse<Incoming>, ErrorCause> {
            let client =
                Client::builder(hyper_util::rt::TokioExecutor::new()).build(HttpConnector::new());
            let url = format!(
                "{}/api/{}/canister/{}/{}",
                replica_url, api_version, effective_canister_id, endpoint
            );
            let req = Request::builder()
                .method(Method::POST)
                .uri(url)
                .header(CONTENT_TYPE, "application/cbor")
                .body(Full::<Bytes>::new(bytes))
                .unwrap();
            client
                .request(req)
                .await
                .map_err(|e| ErrorCause::ConnectionFailure(e.to_string()))
        }

        async fn handler_api_subnet(
            api_version: ApiVersion,
            replica_url: String,
            subnet_id: SubnetId,
            endpoint: &str,
            bytes: Bytes,
        ) -> Result<HyperResponse<Incoming>, ErrorCause> {
            let client =
                Client::builder(hyper_util::rt::TokioExecutor::new()).build(HttpConnector::new());
            let url = format!(
                "{}/api/{}/subnet/{}/{}",
                replica_url, api_version, subnet_id, endpoint
            );
            let req = Request::builder()
                .method(Method::POST)
                .uri(url)
                .header(CONTENT_TYPE, "application/cbor")
                .body(Full::<Bytes>::new(bytes))
                .unwrap();
            client
                .request(req)
                .await
                .map_err(|e| ErrorCause::ConnectionFailure(e.to_string()))
        }

        async fn handler_call_v2(
            State(replica_url): State<String>,
            Path(effective_canister_id): Path<CanisterId>,
            bytes: Bytes,
        ) -> Result<HyperResponse<Incoming>, ErrorCause> {
            handler_api_canister(
                ApiVersion::V2,
                replica_url,
                effective_canister_id,
                "call",
                bytes,
            )
            .await
        }

        async fn handler_call_v3(
            State(replica_url): State<String>,
            Path(effective_canister_id): Path<CanisterId>,
            bytes: Bytes,
        ) -> Result<HyperResponse<Incoming>, ErrorCause> {
            handler_api_canister(
                ApiVersion::V3,
                replica_url,
                effective_canister_id,
                "call",
                bytes,
            )
            .await
        }

        async fn handler_query(
            State(replica_url): State<String>,
            Path(effective_canister_id): Path<CanisterId>,
            bytes: Bytes,
        ) -> Result<HyperResponse<Incoming>, ErrorCause> {
            handler_api_canister(
                ApiVersion::V2,
                replica_url,
                effective_canister_id,
                "query",
                bytes,
            )
            .await
        }

        async fn handler_canister_read_state(
            State(replica_url): State<String>,
            Path(effective_canister_id): Path<CanisterId>,
            bytes: Bytes,
        ) -> Result<HyperResponse<Incoming>, ErrorCause> {
            handler_api_canister(
                ApiVersion::V2,
                replica_url,
                effective_canister_id,
                "read_state",
                bytes,
            )
            .await
        }

        async fn handler_subnet_read_state(
            State(replica_url): State<String>,
            Path(subnet_id): Path<SubnetId>,
            bytes: Bytes,
        ) -> Result<HyperResponse<Incoming>, ErrorCause> {
            handler_api_subnet(ApiVersion::V2, replica_url, subnet_id, "read_state", bytes).await
        }

        let ip_addr = http_gateway_config
            .ip_addr
            .unwrap_or("127.0.0.1".to_string());
        let port = http_gateway_config.port.unwrap_or_default();
        let addr = format!("{}:{}", ip_addr, port);
        let listener = std::net::TcpListener::bind(&addr)
            .unwrap_or_else(|_| panic!("Failed to start HTTP gateway on port {}", port));
        let real_port = listener.local_addr().unwrap().port();

        let pocket_ic_server_port = self.port.unwrap();
        let replica_url = match http_gateway_config.forward_to {
            HttpGatewayBackend::Replica(ref replica_url) => replica_url.clone(),
            HttpGatewayBackend::PocketIcInstance(instance_id) => {
                format!(
                    "http://localhost:{}/instances/{}/",
                    pocket_ic_server_port, instance_id
                )
            }
        };
        let agent = ic_agent::Agent::builder()
            .with_url(replica_url.clone())
            .build()
            .unwrap();
        agent.fetch_root_key().await.map_err(|e| e.to_string())?;

        let mut http_gateways = self.http_gateways.write().await;
        let instance_id = http_gateways.len();
        let http_gateway_details = HttpGatewayDetails {
            instance_id,
            port: real_port,
            forward_to: http_gateway_config.forward_to.clone(),
            domains: http_gateway_config.domains.clone(),
            https_config: http_gateway_config.https_config.clone(),
        };
        http_gateways.push(Some(http_gateway_details));
        drop(http_gateways);

        let http_gateways = self.http_gateways.clone();
        let handle = Handle::new();
        let shutdown_handle = handle.clone();
        let axum_handle = handle.clone();
        spawn(async move {
            let client = ic_http_gateway::HttpGatewayClientBuilder::new()
                .with_agent(agent)
                .build()
                .unwrap();
            let domain_resolver = DomainResolver::new(
                http_gateway_config
                    .domains
                    .unwrap_or(vec!["localhost".to_string()])
                    .iter()
                    .map(|d| fqdn!(d))
                    .collect(),
            );
            let state_handler = Arc::new(HandlerState::new(client, domain_resolver.clone()));

            let router_api_v2 = Router::new()
                .route(
                    "/canister/:ecid/call",
                    post(handler_call_v2)
                        .layer(axum::middleware::from_fn(verify_cbor_content_header)),
                )
                .route(
                    "/canister/:ecid/query",
                    post(handler_query)
                        .layer(axum::middleware::from_fn(verify_cbor_content_header)),
                )
                .route(
                    "/canister/:ecid/read_state",
                    post(handler_canister_read_state)
                        .layer(axum::middleware::from_fn(verify_cbor_content_header)),
                )
                .route(
                    "/subnet/:sid/read_state",
                    post(handler_subnet_read_state)
                        .layer(axum::middleware::from_fn(verify_cbor_content_header)),
                )
                .route("/status", get(handler_status))
                .fallback(|| async { (StatusCode::NOT_FOUND, "") });
            let router_api_v3 = Router::new()
                .route(
                    "/canister/:ecid/call",
                    post(handler_call_v3)
                        .layer(axum::middleware::from_fn(verify_cbor_content_header)),
                )
                .fallback(|| async { (StatusCode::NOT_FOUND, "") });
            let router = Router::new()
                .nest("/api/v2", router_api_v2)
                .nest("/api/v3", router_api_v3)
                .fallback(
                    post(handler)
                        .get(handler)
                        .put(handler)
                        .delete(handler)
                        .layer(layer(&[
                            Method::HEAD,
                            Method::GET,
                            Method::POST,
                            Method::PUT,
                            Method::DELETE,
                        ]))
                        .with_state(state_handler),
                )
                .layer(DefaultBodyLimit::disable())
                .layer(cors_layer())
                .with_state(replica_url.trim_end_matches('/').to_string())
                .into_make_service();

            let http_gateways_for_shutdown = http_gateways.clone();
            tokio::spawn(async move {
                loop {
                    let guard = http_gateways_for_shutdown.read().await;
                    if guard[instance_id].is_none() {
                        shutdown_handle.shutdown();
                        break;
                    }
                    drop(guard);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            });
            if let Some(https_config) = http_gateway_config.https_config {
                let config = RustlsConfig::from_pem_file(
                    PathBuf::from(https_config.cert_path),
                    PathBuf::from(https_config.key_path),
                )
                .await;
                match config {
                    Ok(config) => {
                        axum_server::from_tcp_rustls(listener, config)
                            .handle(axum_handle)
                            .serve(router)
                            .await
                            .unwrap();
                    }
                    Err(e) => {
                        error!("TLS config could not be created: {:?}", e);
                        let mut guard = http_gateways.write().await;
                        guard[instance_id] = None;
                        return;
                    }
                }
            } else {
                axum_server::from_tcp(listener)
                    .handle(axum_handle)
                    .serve(router)
                    .await
                    .unwrap();
            }

            info!("Terminating HTTP gateway.");
        });

        // Wait until the HTTP gateway starts listening.
        while handle.listening().await.is_none() {}

        Ok(HttpGatewayInfo {
            instance_id,
            port: real_port,
        })
    }

    pub async fn stop_http_gateway(&self, instance_id: InstanceId) {
        let mut http_gateways = self.http_gateways.write().await;
        if instance_id < http_gateways.len() {
            http_gateways[instance_id] = None;
        }
    }

    async fn make_http_request(
        canister_http_request: CanisterHttpRequest,
        canister_http_adapter: &CanisterHttp,
    ) -> Result<CanisterHttpReply, (RejectCode, String)> {
        let canister_http_request = CanisterHttpSendRequest {
            url: canister_http_request.url,
            method: match canister_http_request.http_method {
                CanisterHttpMethod::GET => HttpMethod::Get.into(),
                CanisterHttpMethod::POST => HttpMethod::Post.into(),
                CanisterHttpMethod::HEAD => HttpMethod::Head.into(),
            },
            max_response_size_bytes: canister_http_request
                .max_response_bytes
                .unwrap_or(MAX_CANISTER_HTTP_RESPONSE_BYTES),
            headers: canister_http_request
                .headers
                .into_iter()
                .map(|h| HttpHeader {
                    name: h.name,
                    value: h.value,
                })
                .collect(),
            body: canister_http_request.body,
            socks_proxy_allowed: false,
        };
        let request = Request::new(canister_http_request);
        canister_http_adapter
            .canister_http_send(request)
            .await
            .map(|adapter_response| {
                let CanisterHttpSendResponse {
                    status,
                    headers,
                    content: body,
                } = adapter_response.into_inner();
                CanisterHttpReply {
                    status: status.try_into().unwrap(),
                    headers: headers
                        .into_iter()
                        .map(|HttpHeader { name, value }| CanisterHttpHeader { name, value })
                        .collect(),
                    body,
                }
            })
            .map_err(|grpc_status| {
                (
                    grpc_status_code_to_reject(grpc_status.code()),
                    grpc_status.message().to_string(),
                )
            })
    }

    async fn process_canister_http_requests(
        instances: Arc<RwLock<Vec<Mutex<InstanceState>>>>,
        canister_http_adapters: Arc<RwLock<HashMap<InstanceId, CanisterHttpAdapters>>>,
        graph: Arc<RwLock<HashMap<StateLabel, Computations>>>,
        instance_id: InstanceId,
        rx: &mut Receiver<()>,
    ) -> Option<()> {
        let get_canister_http_op = GetCanisterHttp;
        let canister_http_requests = match Self::execute_operation(
            instances.clone(),
            graph.clone(),
            instance_id,
            get_canister_http_op,
            rx,
        )
        .await?
        {
            OpOut::CanisterHttp(canister_http) => canister_http,
            out => panic!("Unexpected OpOut: {:?}", out),
        };
        let mut mock_canister_http_responses = vec![];
        for canister_http_request in canister_http_requests {
            let subnet_id = canister_http_request.subnet_id;
            let request_id = canister_http_request.request_id;
            let canister_http_adapters = canister_http_adapters.read().await;
            let canister_http_adapters = canister_http_adapters
                .get(&instance_id)
                .unwrap()
                .lock()
                .await;
            let canister_http_adapter = canister_http_adapters
                .get(&SubnetId::from(PrincipalId::from(subnet_id)))
                .unwrap();
            let response =
                match Self::make_http_request(canister_http_request, canister_http_adapter).await {
                    Ok(reply) => CanisterHttpResponse::CanisterHttpReply(reply),
                    Err((reject_code, e)) => {
                        CanisterHttpResponse::CanisterHttpReject(CanisterHttpReject {
                            reject_code: reject_code as u64,
                            message: e,
                        })
                    }
                };
            let mock_canister_http_response = MockCanisterHttpResponse {
                subnet_id,
                request_id,
                response,
            };
            mock_canister_http_responses.push(mock_canister_http_response);
        }
        for mock_canister_http_response in mock_canister_http_responses {
            let mock_canister_http_op = MockCanisterHttp {
                mock_canister_http_response,
            };
            Self::execute_operation(
                instances.clone(),
                graph.clone(),
                instance_id,
                mock_canister_http_op,
                rx,
            )
            .await?;
        }
        Some(())
    }

    pub async fn auto_progress(
        &self,
        instance_id: InstanceId,
        artificial_delay_ms: Option<u64>,
    ) -> Result<(), String> {
        let artificial_delay = Duration::from_millis(artificial_delay_ms.unwrap_or_default());
        let progress_threads = self.progress_threads.read().await;
        let mut progress_thread = progress_threads[instance_id].lock().await;
        let instances = self.instances.clone();
        let canister_http_adapters = self.canister_http_adapters.clone();
        let graph = self.graph.clone();
        if progress_thread.is_none() {
            let (tx, mut rx) = mpsc::channel::<()>(1);
            let handle = spawn(async move {
                let mut now = Instant::now();
                loop {
                    let start = Instant::now();
                    let old = std::mem::replace(&mut now, Instant::now());
                    let op = AdvanceTimeAndTick(now.duration_since(old));
                    if Self::execute_operation(
                        instances.clone(),
                        graph.clone(),
                        instance_id,
                        op,
                        &mut rx,
                    )
                    .await
                    .is_none()
                    {
                        return;
                    }
                    if Self::process_canister_http_requests(
                        instances.clone(),
                        canister_http_adapters.clone(),
                        graph.clone(),
                        instance_id,
                        &mut rx,
                    )
                    .await
                    .is_none()
                    {
                        return;
                    }
                    let duration = start.elapsed();
                    sleep(std::cmp::max(
                        duration,
                        std::cmp::max(artificial_delay, MIN_OPERATION_DELAY),
                    ))
                    .await;
                    if received_stop_signal(&mut rx) {
                        return;
                    }
                }
            });
            *progress_thread = Some(ProgressThread { handle, sender: tx });
            Ok(())
        } else {
            Err("Auto progress mode has already been enabled.".to_string())
        }
    }

    pub async fn stop_progress(&self, instance_id: InstanceId) {
        let progress_threads = self.progress_threads.read().await;
        let mut progress_thread = progress_threads[instance_id].lock().await;
        if let Some(t) = progress_thread.take() {
            t.sender.send(()).await.unwrap();
            t.handle.await.unwrap();
        }
    }

    pub async fn list_instance_states(&self) -> Vec<String> {
        let instances = self.instances.read().await;
        let mut res = vec![];

        for instance_state in &*instances {
            let instance_state = &*instance_state.lock().await;
            match instance_state {
                InstanceState::Busy { state_label, op_id } => {
                    res.push(format!("Busy({:?}, {:?})", state_label, op_id))
                }
                InstanceState::Available(_) => res.push("Available".to_string()),
                InstanceState::Deleted => res.push("Deleted".to_string()),
            }
        }
        res
    }

    pub async fn list_http_gateways(&self) -> Vec<HttpGatewayDetails> {
        self.http_gateways
            .read()
            .await
            .clone()
            .into_iter()
            .flatten()
            .collect()
    }

    /// An operation bound to an instance (a Computation) can update the PocketIC state.
    ///
    /// * If the instance is busy executing an operation, the call returns [UpdateReply::Busy]
    ///   immediately. In that case, the state label and operation id contained in the result
    ///   indicate that the instance is busy with a previous operation.
    ///
    /// * If the instance is available and the computation exceeds a (short) timeout,
    ///   [UpdateReply::Busy] is returned.
    ///
    /// * If the computation finished within the timeout, [UpdateReply::Output] is returned
    ///   containing the result.
    ///
    /// Operations are _not_ queued by default. Thus, if the instance is busy with an existing operation,
    /// the client has to retry until the operation is done. Some operations for which the client
    /// might be unable to retry are exceptions to this rule and they are queued up implicitly
    /// by a retry mechanism inside PocketIc.
    pub async fn update<O>(&self, op: Arc<O>, instance_id: InstanceId) -> UpdateResult
    where
        O: Operation + Send + Sync + 'static,
    {
        self.update_with_timeout(op, instance_id, None).await
    }

    /// Same as [Self::update] except that the timeout can be specified manually. This is useful in
    /// cases when clients want to enforce a long-running blocking call.
    pub async fn update_with_timeout<O>(
        &self,
        op: Arc<O>,
        instance_id: InstanceId,
        sync_wait_time: Option<Duration>,
    ) -> UpdateResult
    where
        O: Operation + Send + Sync + 'static,
    {
        let sync_wait_time = sync_wait_time.unwrap_or(self.sync_wait_time);
        Self::update_instances_with_timeout(
            self.instances.clone(),
            self.graph.clone(),
            op,
            instance_id,
            sync_wait_time,
        )
        .await
    }

    /// Same as [Self::update] except that the timeout can be specified manually. This is useful in
    /// cases when clients want to enforce a long-running blocking call.
    async fn update_instances_with_timeout<O>(
        instances: Arc<RwLock<Vec<Mutex<InstanceState>>>>,
        graph: Arc<RwLock<HashMap<StateLabel, Computations>>>,
        op: Arc<O>,
        instance_id: InstanceId,
        sync_wait_time: Duration,
    ) -> UpdateResult
    where
        O: Operation + Send + Sync + 'static,
    {
        let op_id = op.id().0;
        trace!(
            "update_with_timeout::start instance_id={} op_id={}",
            instance_id,
            op_id,
        );
        let instances_cloned = instances.clone();
        let instances_locked = instances_cloned.read().await;
        let (bg_task, busy_outcome) = if let Some(instance_mutex) =
            instances_locked.get(instance_id)
        {
            let mut instance_state = instance_mutex.lock().await;
            // If this instance is busy, return the running op and initial state
            match &*instance_state {
                InstanceState::Deleted => {
                    return Err(UpdateError {
                        message: "Instance was deleted".to_string(),
                    });
                }
                // TODO: cache lookup possible with this state_label and our own op_id
                InstanceState::Busy { state_label, op_id } => {
                    return Ok(UpdateReply::Busy {
                        state_label: state_label.clone(),
                        op_id: op_id.clone(),
                    });
                }
                InstanceState::Available(pocket_ic) => {
                    // move pocket_ic out

                    let state_label = pocket_ic.get_state_label();
                    let op_id = op.id();
                    let busy = InstanceState::Busy {
                        state_label: state_label.clone(),
                        op_id: op_id.clone(),
                    };
                    let InstanceState::Available(mut pocket_ic) =
                        std::mem::replace(&mut *instance_state, busy)
                    else {
                        unreachable!()
                    };

                    let bg_task = {
                        let old_state_label = state_label.clone();
                        let op_id = op_id.clone();
                        let graph = graph.clone();
                        move || {
                            trace!(
                                "bg_task::start instance_id={} state_label={:?} op_id={}",
                                instance_id,
                                old_state_label,
                                op_id.0,
                            );
                            let result = op.compute(&mut pocket_ic);
                            let new_state_label = pocket_ic.get_state_label();
                            // add result to graph, but grab instance lock first!
                            let instances = instances.blocking_read();
                            let mut graph_guard = graph.blocking_write();
                            let cached_computations =
                                graph_guard.entry(old_state_label.clone()).or_default();
                            cached_computations
                                .insert(op_id.clone(), (new_state_label, result.clone()));
                            drop(graph_guard);
                            let mut instance_state = instances[instance_id].blocking_lock();
                            if let InstanceState::Deleted = &*instance_state {
                                error!("The instance is deleted immediately after an operation. This is a bug!");
                                std::mem::drop(pocket_ic);
                            } else {
                                *instance_state = InstanceState::Available(pocket_ic);
                            }
                            trace!("bg_task::end instance_id={} op_id={}", instance_id, op_id.0);
                            // also return old_state_label so we can prune graph if we return quickly
                            (result, old_state_label)
                        }
                    };

                    // cache miss: replace pocket_ic instance in the vector with Busy
                    (bg_task, UpdateReply::Started { state_label, op_id })
                }
            }
        } else {
            return Err(UpdateError {
                message: "Instance not found".to_string(),
            });
        };
        // drop lock, otherwise we end up with a deadlock
        std::mem::drop(instances_locked);

        // We schedule a blocking background task on the tokio runtime. Note that if all
        // blocking workers are busy, the task is put on a queue (which is what we want).
        //
        // Note: One issue here is that we drop the join handle "on the floor". Threads
        // that are not awaited upon before exiting the process are known to cause spurios
        // issues. This should not be a problem as the tokio Executor will wait
        // indefinitively for threads to return, unless a shutdown timeout is configured.
        //
        // See: https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html
        let bg_handle = spawn_blocking(bg_task);

        // if the operation returns "in time", we return the result, otherwise we indicate to the
        // client that the instance is busy.
        //
        // note: this assumes that cancelling the JoinHandle does not stop the execution of the
        // background task. This only works because the background thread, in this case, is a
        // kernel thread.
        if let Ok(Ok((op_out, old_state_label))) = time::timeout(sync_wait_time, bg_handle).await {
            trace!(
                "update_with_timeout::synchronous instance_id={} op_id={}",
                instance_id,
                op_id,
            );
            // prune this sync computation from graph, but only the value
            let mut graph_guard = graph.write().await;
            let cached_computations = graph_guard.entry(old_state_label.clone()).or_default();
            let (new_state_label, _) = cached_computations.get(&OpId(op_id.clone())).unwrap();
            cached_computations.insert(OpId(op_id), (new_state_label.clone(), OpOut::Pruned));
            drop(graph_guard);

            return Ok(UpdateReply::Output(op_out));
        }

        trace!(
            "update_with_timeout::timeout instance_id={} op_id={}",
            instance_id,
            op_id,
        );
        Ok(busy_outcome)
    }
}

impl std::fmt::Debug for InstanceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Busy { state_label, op_id } => {
                write!(f, "Busy {{ {state_label:?}, {op_id:?} }}")?
            }
            Self::Available(pic) => write!(f, "Available({:?})", pic.get_state_label())?,
            Self::Deleted => write!(f, "Deleted")?,
        }
        Ok(())
    }
}

impl std::fmt::Debug for ApiState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let instances = self.instances.blocking_read();
        let graph = self.graph.blocking_read();

        writeln!(f, "Instances:")?;
        for (idx, instance) in instances.iter().enumerate() {
            writeln!(f, "  [{idx}] {instance:?}")?;
        }

        writeln!(f, "Graph:")?;
        for (k, v) in graph.iter() {
            writeln!(f, "  {k:?} => {v:?}")?;
        }
        Ok(())
    }
}
