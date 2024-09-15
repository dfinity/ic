/// This module contains the route handlers for the PocketIc server.
///
/// A handler may receive a representation of a PocketIc Operation in the request
/// body. This has to be canonicalized into a PocketIc Operation before we can
/// deterministically update the PocketIc state machine.
///
use super::state::{ApiState, OpOut, PocketIcError, StateLabel, UpdateReply};
use crate::pocket_ic::{
    AddCycles, AwaitIngressMessage, CallRequest, CallRequestVersion, CanisterReadStateRequest,
    DashboardRequest, ExecuteIngressMessage, GetCanisterHttp, GetCyclesBalance, GetStableMemory,
    GetSubnet, GetTime, GetTopology, MockCanisterHttp, PubKey, Query, QueryRequest,
    SetStableMemory, SetTime, StatusRequest, SubmitIngressMessage, SubnetReadStateRequest, Tick,
};
use crate::{async_trait, pocket_ic::PocketIc, BlobStore, InstanceId, OpId, Operation};
use aide::{
    axum::routing::{delete, get, post, ApiMethodRouter},
    axum::ApiRouter,
    NoApi,
};

use axum::{
    body::{Body, Bytes},
    extract::{self, Path, State},
    http::{self, HeaderMap, HeaderName, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use axum_extra::headers;
use axum_extra::headers::HeaderMapExt;
use backoff::backoff::Backoff;
use backoff::{ExponentialBackoff, ExponentialBackoffBuilder};
use hyper::header;
use ic_http_endpoints_public::cors_layer;
use ic_state_machine_tests::Level;
use ic_types::{CanisterId, SubnetId};
use pocket_ic::common::rest::{
    self, ApiResponse, AutoProgressConfig, ExtendedSubnetConfigSet, HttpGatewayConfig,
    HttpGatewayDetails, InstanceConfig, MockCanisterHttpResponse, RawAddCycles, RawCanisterCall,
    RawCanisterHttpRequest, RawCanisterId, RawCanisterResult, RawCycles, RawMessageId,
    RawMockCanisterHttpResponse, RawSetStableMemory, RawStableMemory, RawSubmitIngressResult,
    RawSubnetId, RawTime, RawWasmResult, Topology,
};
use pocket_ic::WasmResult;
use serde::Serialize;
use std::str::FromStr;
use std::{collections::BTreeMap, fs::File, sync::Arc, time::Duration};
use tokio::{runtime::Runtime, sync::RwLock, time::Instant};
use tower_http::limit::RequestBodyLimitLayer;
use tracing::trace;

type PocketHttpResponse = (BTreeMap<String, Vec<u8>>, Vec<u8>);

/// Name of a header that allows clients to specify for how long their are willing to wait for a
/// response on a open http request.
pub static TIMEOUT_HEADER_NAME: HeaderName = HeaderName::from_static("processing-timeout-ms");
const RETRY_TIMEOUT_S: u64 = 300;

#[derive(Clone)]
pub struct AppState {
    pub api_state: Arc<ApiState>,
    pub min_alive_until: Arc<RwLock<Instant>>,
    pub runtime: Arc<Runtime>,
    pub blob_store: Arc<dyn BlobStore>,
}

pub fn instance_read_routes<S>() -> ApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    AppState: extract::FromRef<S>,
{
    ApiRouter::new()
        .directory_route("/query", post(handler_json_query))
        .directory_route("/topology", get(handler_topology))
        .directory_route("/get_time", get(handler_get_time))
        .directory_route("/get_canister_http", get(handler_get_canister_http))
        .directory_route("/get_cycles", post(handler_get_cycles))
        .directory_route("/get_stable_memory", post(handler_get_stable_memory))
        .directory_route("/get_subnet", post(handler_get_subnet))
        .directory_route("/pub_key", post(handler_pub_key))
}

pub fn instance_update_routes<S>() -> ApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    AppState: extract::FromRef<S>,
{
    ApiRouter::new()
        .directory_route(
            "/submit_ingress_message",
            post(handler_submit_ingress_message),
        )
        .directory_route(
            "/await_ingress_message",
            post(handler_await_ingress_message),
        )
        .directory_route(
            "/execute_ingress_message",
            post(handler_execute_ingress_message),
        )
        .directory_route("/set_time", post(handler_set_time))
        .directory_route("/add_cycles", post(handler_add_cycles))
        .directory_route("/set_stable_memory", post(handler_set_stable_memory))
        .directory_route("/tick", post(handler_tick))
        .directory_route("/mock_canister_http", post(handler_mock_canister_http))
}

pub fn instance_api_v2_routes<S>() -> ApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    AppState: extract::FromRef<S>,
{
    ApiRouter::new()
        .directory_route("/status", get(handler_status))
        .directory_route(
            "/canister/:ecid/call",
            post(handler_call_v2)
                .layer(RequestBodyLimitLayer::new(
                    4 * 1024 * 1024, // MAX_REQUEST_BODY_SIZE in BN
                ))
                .layer(axum::middleware::from_fn(verify_cbor_content_header)),
        )
        .directory_route(
            "/canister/:ecid/query",
            post(handler_query)
                .layer(RequestBodyLimitLayer::new(
                    4 * 1024 * 1024, // MAX_REQUEST_BODY_SIZE in BN
                ))
                .layer(axum::middleware::from_fn(verify_cbor_content_header)),
        )
        .directory_route(
            "/canister/:ecid/read_state",
            post(handler_canister_read_state)
                .layer(RequestBodyLimitLayer::new(
                    4 * 1024 * 1024, // MAX_REQUEST_BODY_SIZE in BN
                ))
                .layer(axum::middleware::from_fn(verify_cbor_content_header)),
        )
        .directory_route(
            "/subnet/:sid/read_state",
            post(handler_subnet_read_state)
                .layer(RequestBodyLimitLayer::new(
                    4 * 1024 * 1024, // MAX_REQUEST_BODY_SIZE in BN
                ))
                .layer(axum::middleware::from_fn(verify_cbor_content_header)),
        )
}

pub fn instance_api_v3_routes<S>() -> ApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    AppState: extract::FromRef<S>,
{
    ApiRouter::new().directory_route(
        "/canister/:ecid/call",
        post(handler_call_v3)
            .layer(RequestBodyLimitLayer::new(
                4 * 1024 * 1024, // MAX_REQUEST_BODY_SIZE in BN
            ))
            .layer(axum::middleware::from_fn(verify_cbor_content_header)),
    )
}

pub fn instances_routes<S>() -> ApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    AppState: extract::FromRef<S>,
{
    ApiRouter::new()
        //
        // List all IC instances.
        .api_route("/", get(list_instances))
        //
        // Create a new IC instance. Takes a SubnetConfig which must contain at least one subnet.
        // Returns an InstanceId.
        .api_route("/", post(create_instance))
        //
        // Deletes an instance.
        .directory_route("/:id", delete(delete_instance))
        //
        // All the read-only endpoints
        .nest("/:id/read", instance_read_routes())
        //
        // All the state-changing endpoints
        .nest("/:id/update", instance_update_routes())
        //
        // All the api v2 endpoints
        .nest("/:id/api/v2", instance_api_v2_routes())
        //
        // All the api v3 endpoints
        .nest("/:id/api/v3", instance_api_v3_routes())
        //
        // The instance dashboard
        .api_route("/:id/_/dashboard", get(handler_dashboard))
        // Configures an IC instance to make progress automatically,
        // i.e., periodically update the time of the IC instance
        // to the real time and execute rounds on the subnets.
        .api_route("/:id/auto_progress", post(auto_progress))
        //
        // Stop automatic progress (see endpoint `auto_progress`)
        // on an IC instance.
        .api_route("/:id/stop_progress", post(stop_progress))
        .layer(cors_layer())
}

pub fn http_gateway_routes<S>() -> ApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    AppState: extract::FromRef<S>,
{
    ApiRouter::new()
        // List all HTTP gateways.
        .api_route("/", get(list_http_gateways))
        // Create a new HTTP gateway instance. Takes a HttpGatewayConfig.
        // Returns an InstanceId and the HTTP gateway's port.
        .api_route("/", post(create_http_gateway))
        // Stops an HTTP gateway.
        .api_route("/:id/stop", post(stop_http_gateway))
}

async fn run_operation<T: Serialize + FromOpOut>(
    api_state: Arc<ApiState>,
    instance_id: InstanceId,
    timeout: Option<Duration>,
    op: impl Operation + Send + Sync + 'static,
) -> (StatusCode, ApiResponse<T>) {
    let retry_if_busy = op.retry_if_busy();
    let op = Arc::new(op);
    let mut retry_policy: ExponentialBackoff = ExponentialBackoffBuilder::new()
        .with_initial_interval(Duration::from_millis(10))
        .with_max_interval(Duration::from_secs(1))
        .with_multiplier(2.0)
        .with_max_elapsed_time(Some(Duration::from_secs(RETRY_TIMEOUT_S)))
        .build();
    loop {
        match api_state
            .update_with_timeout(op.clone(), instance_id, timeout)
            .await
        {
            Err(e) => {
                break (
                    StatusCode::BAD_REQUEST,
                    ApiResponse::Error {
                        message: format!("{:?}", e),
                    },
                )
            }
            Ok(update_reply) => {
                match update_reply {
                    // If the op_id of the ongoing operation is the requested one, we return code 202.
                    UpdateReply::Started { state_label, op_id } => {
                        break (
                            StatusCode::ACCEPTED,
                            ApiResponse::Started {
                                state_label: base64::encode_config(state_label.0, base64::URL_SAFE),
                                op_id: op_id.0.to_string(),
                            },
                        );
                    }
                    // Otherwise, the instance is busy with a different computation, so we retry (if appliacable) or return 409.
                    UpdateReply::Busy { state_label, op_id } => {
                        if retry_if_busy {
                            trace!("run_operation::retry_busy instance_id={} state_label={:?} op_id={}", instance_id, state_label, op_id.0);
                            match retry_policy.next_backoff() {
                                Some(duration) => tokio::time::sleep(duration).await,
                                None => {
                                    break (
                                        StatusCode::TOO_MANY_REQUESTS,
                                        ApiResponse::Error {
                                            message: "Service is overloaded, try again later."
                                                .to_string(),
                                        },
                                    )
                                }
                            }
                        } else {
                            break (
                                StatusCode::CONFLICT,
                                ApiResponse::Busy {
                                    state_label: base64::encode_config(
                                        state_label.0,
                                        base64::URL_SAFE,
                                    ),
                                    op_id: op_id.0.to_string(),
                                },
                            );
                        }
                    }
                    UpdateReply::Output(op_out) => break FromOpOut::from(op_out).await,
                }
            }
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct OpConversionError;

#[async_trait]
trait FromOpOut: Sized {
    async fn from(value: OpOut) -> (StatusCode, ApiResponse<Self>);
}

#[async_trait]
impl<T: TryFrom<OpOut>> FromOpOut for T {
    async fn from(value: OpOut) -> (StatusCode, ApiResponse<T>) {
        // match errors explicitly to make sure they have a 4xx status code
        match value {
            OpOut::Error(e) => (
                StatusCode::BAD_REQUEST,
                ApiResponse::Error {
                    message: format!("{:?}", e),
                },
            ),
            val => {
                if let Ok(t) = T::try_from(val) {
                    (StatusCode::OK, ApiResponse::Success(t))
                } else {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        ApiResponse::Error {
                            message: "operation returned invalid type".into(),
                        },
                    )
                }
            }
        }
    }
}

impl TryFrom<OpOut> for RawTime {
    type Error = OpConversionError;
    fn try_from(value: OpOut) -> Result<Self, Self::Error> {
        match value {
            OpOut::Time(time) => Ok(RawTime {
                nanos_since_epoch: time,
            }),
            _ => Err(OpConversionError),
        }
    }
}

impl TryFrom<OpOut> for Topology {
    type Error = OpConversionError;
    fn try_from(value: OpOut) -> Result<Self, Self::Error> {
        match value {
            OpOut::Topology(topology) => Ok(topology),
            _ => Err(OpConversionError),
        }
    }
}

impl TryFrom<OpOut> for () {
    type Error = OpConversionError;
    fn try_from(value: OpOut) -> Result<Self, Self::Error> {
        match value {
            OpOut::NoOutput => Ok(()),
            _ => Err(OpConversionError),
        }
    }
}

impl TryFrom<OpOut> for RawCycles {
    type Error = OpConversionError;
    fn try_from(value: OpOut) -> Result<Self, Self::Error> {
        match value {
            OpOut::Cycles(cycles) => Ok(RawCycles { cycles }),
            _ => Err(OpConversionError),
        }
    }
}

impl TryFrom<OpOut> for RawStableMemory {
    type Error = OpConversionError;
    fn try_from(value: OpOut) -> Result<Self, Self::Error> {
        match value {
            OpOut::StableMemBytes(stable_memory) => Ok(RawStableMemory {
                blob: stable_memory,
            }),
            _ => Err(OpConversionError),
        }
    }
}

impl TryFrom<OpOut> for RawCanisterResult {
    type Error = OpConversionError;
    fn try_from(value: OpOut) -> Result<Self, Self::Error> {
        match value {
            OpOut::CanisterResult(wasm_result) => {
                let inner = match wasm_result {
                    Ok(WasmResult::Reply(wasm_result)) => {
                        RawCanisterResult::Ok(RawWasmResult::Reply(wasm_result))
                    }
                    Ok(WasmResult::Reject(error_message)) => {
                        RawCanisterResult::Ok(RawWasmResult::Reject(error_message))
                    }
                    Err(user_error) => RawCanisterResult::Err(user_error),
                };
                Ok(inner)
            }
            _ => Err(OpConversionError),
        }
    }
}

impl TryFrom<OpOut> for PocketIcError {
    type Error = OpConversionError;
    fn try_from(value: OpOut) -> Result<Self, Self::Error> {
        match value {
            OpOut::Error(e) => Ok(e),
            _ => Err(OpConversionError),
        }
    }
}

impl TryFrom<OpOut> for RawCanisterId {
    type Error = OpConversionError;
    fn try_from(value: OpOut) -> Result<Self, Self::Error> {
        match value {
            OpOut::CanisterId(canister_id) => Ok(RawCanisterId {
                canister_id: canister_id.get().to_vec(),
            }),
            _ => Err(OpConversionError),
        }
    }
}

impl TryFrom<OpOut> for Option<RawSubnetId> {
    type Error = OpConversionError;
    fn try_from(value: OpOut) -> Result<Self, Self::Error> {
        match value {
            OpOut::MaybeSubnetId(maybe_subnet_id) => {
                Ok(maybe_subnet_id.map(|subnet_id| RawSubnetId {
                    subnet_id: subnet_id.get().to_vec(),
                }))
            }
            _ => Err(OpConversionError),
        }
    }
}

impl TryFrom<OpOut> for Vec<u8> {
    type Error = OpConversionError;
    fn try_from(value: OpOut) -> Result<Self, Self::Error> {
        match value {
            OpOut::Bytes(bytes) => Ok(bytes),
            _ => Err(OpConversionError),
        }
    }
}

impl TryFrom<OpOut> for RawSubmitIngressResult {
    type Error = OpConversionError;
    fn try_from(value: OpOut) -> Result<Self, Self::Error> {
        match value {
            OpOut::MessageId((effective_principal, message_id)) => {
                Ok(RawSubmitIngressResult::Ok(RawMessageId {
                    effective_principal: effective_principal.into(),
                    message_id,
                }))
            }
            OpOut::CanisterResult(Err(user_error)) => Ok(RawSubmitIngressResult::Err(user_error)),
            _ => Err(OpConversionError),
        }
    }
}

impl TryFrom<OpOut> for Vec<RawCanisterHttpRequest> {
    type Error = OpConversionError;
    fn try_from(value: OpOut) -> Result<Self, Self::Error> {
        match value {
            OpOut::CanisterHttp(canister_http_requests) => Ok(canister_http_requests
                .into_iter()
                .map(|r| r.into())
                .collect()),
            _ => Err(OpConversionError),
        }
    }
}

#[async_trait]
impl FromOpOut for PocketHttpResponse {
    async fn from(value: OpOut) -> (StatusCode, ApiResponse<PocketHttpResponse>) {
        match value {
            OpOut::RawResponse(fut) => {
                let (status, headers, bytes) = fut.await;
                (
                    StatusCode::from_u16(status).unwrap(),
                    ApiResponse::Success((headers, bytes)),
                )
            }
            OpOut::Error(PocketIcError::RequestRoutingError(e)) => {
                (StatusCode::BAD_REQUEST, ApiResponse::Error { message: e })
            }
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ApiResponse::Error {
                    message: "operation returned invalid type".into(),
                },
            ),
        }
    }
}

// ----------------------------------------------------------------------------------------------------------------- //
// Read handlers

pub async fn handler_json_query(
    State(AppState { api_state, .. }): State<AppState>,
    Path(instance_id): Path<InstanceId>,
    headers: HeaderMap,
    extract::Json(raw_canister_call): extract::Json<RawCanisterCall>,
) -> (StatusCode, Json<ApiResponse<RawCanisterResult>>) {
    let timeout = timeout_or_default(headers);
    match crate::pocket_ic::CanisterCall::try_from(raw_canister_call) {
        Ok(canister_call) => {
            let query_op = Query(canister_call);
            // TODO: how to know what run_operation returns, i.e. to what to parse it? (type safety?)
            // (applies to all handlers)
            let (code, response) = run_operation(api_state, instance_id, timeout, query_op).await;
            (code, Json(response))
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::Error {
                message: format!("{:?}", e),
            }),
        ),
    }
}

pub async fn handler_topology(
    State(AppState { api_state, .. }): State<AppState>,
    headers: HeaderMap,
    Path(instance_id): Path<InstanceId>,
) -> (StatusCode, Json<ApiResponse<Topology>>) {
    let timeout = timeout_or_default(headers);
    let op = GetTopology {};
    let (code, response) = run_operation(api_state, instance_id, timeout, op).await;
    (code, Json(response))
}

pub async fn handler_get_time(
    State(AppState { api_state, .. }): State<AppState>,
    headers: HeaderMap,
    Path(instance_id): Path<InstanceId>,
) -> (StatusCode, Json<ApiResponse<RawTime>>) {
    let timeout = timeout_or_default(headers);
    let time_op = GetTime {};
    let (code, response) = run_operation(api_state, instance_id, timeout, time_op).await;
    (code, Json(response))
}

pub async fn handler_get_canister_http(
    State(AppState { api_state, .. }): State<AppState>,
    headers: HeaderMap,
    Path(instance_id): Path<InstanceId>,
) -> (StatusCode, Json<ApiResponse<Vec<RawCanisterHttpRequest>>>) {
    let timeout = timeout_or_default(headers);
    let op = GetCanisterHttp {};
    let (code, response) = run_operation(api_state, instance_id, timeout, op).await;
    (code, Json(response))
}

pub async fn handler_mock_canister_http(
    State(AppState { api_state, .. }): State<AppState>,
    headers: HeaderMap,
    Path(instance_id): Path<InstanceId>,
    axum::extract::Json(raw_mock_canister_http_response): axum::extract::Json<
        RawMockCanisterHttpResponse,
    >,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let timeout = timeout_or_default(headers);
    let mock_canister_http_response: MockCanisterHttpResponse =
        raw_mock_canister_http_response.into();
    let op = MockCanisterHttp {
        mock_canister_http_response,
    };
    let (code, response) = run_operation(api_state, instance_id, timeout, op).await;
    (code, Json(response))
}

pub async fn handler_get_cycles(
    State(AppState { api_state, .. }): State<AppState>,
    Path(instance_id): Path<InstanceId>,
    headers: HeaderMap,
    extract::Json(raw_canister_id): extract::Json<RawCanisterId>,
) -> (StatusCode, Json<ApiResponse<RawCycles>>) {
    let timeout = timeout_or_default(headers);
    match CanisterId::try_from(raw_canister_id.canister_id) {
        Ok(canister_id) => {
            let get_op = GetCyclesBalance { canister_id };
            let (code, response) = run_operation(api_state, instance_id, timeout, get_op).await;
            (code, Json(response))
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::Error {
                message: format!("{:?}", e),
            }),
        ),
    }
}

pub async fn handler_get_stable_memory(
    State(AppState { api_state, .. }): State<AppState>,
    Path(instance_id): Path<InstanceId>,
    headers: HeaderMap,
    axum::extract::Json(raw_canister_id): axum::extract::Json<RawCanisterId>,
) -> (StatusCode, Json<ApiResponse<RawStableMemory>>) {
    let timeout = timeout_or_default(headers);
    match CanisterId::try_from(raw_canister_id.canister_id) {
        Ok(canister_id) => {
            let get_op = GetStableMemory { canister_id };
            let (code, response) = run_operation(api_state, instance_id, timeout, get_op).await;
            (code, Json(response))
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::Error {
                message: format!("{:?}", e),
            }),
        ),
    }
}

pub async fn handler_get_subnet(
    State(AppState { api_state, .. }): State<AppState>,
    Path(instance_id): Path<InstanceId>,
    headers: HeaderMap,
    axum::extract::Json(raw_canister_id): axum::extract::Json<RawCanisterId>,
) -> (StatusCode, Json<ApiResponse<Option<RawSubnetId>>>) {
    let timeout = timeout_or_default(headers);
    match CanisterId::try_from(raw_canister_id.canister_id) {
        Ok(canister_id) => {
            let op = GetSubnet { canister_id };
            let (code, res) = run_operation(api_state, instance_id, timeout, op).await;
            (code, Json(res))
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::Error {
                message: format!("{:?}", e),
            }),
        ),
    }
}

pub async fn handler_pub_key(
    State(AppState { api_state, .. }): State<AppState>,
    Path(instance_id): Path<InstanceId>,
    headers: HeaderMap,
    extract::Json(RawSubnetId { subnet_id }): extract::Json<RawSubnetId>,
) -> (StatusCode, Json<ApiResponse<Vec<u8>>>) {
    let timeout = timeout_or_default(headers);
    let subnet_id = ic_types::SubnetId::new(ic_types::PrincipalId(candid::Principal::from_slice(
        &subnet_id,
    )));
    let op = PubKey { subnet_id };
    let (code, res) = run_operation(api_state, instance_id, timeout, op).await;
    (code, Json(res))
}

pub async fn handler_dashboard(
    State(AppState { api_state, .. }): State<AppState>,
    NoApi(Path(instance_id)): NoApi<Path<InstanceId>>,
) -> (StatusCode, NoApi<Response<Body>>) {
    let op = DashboardRequest {};
    handle_raw(api_state, instance_id, op).await
}

pub async fn handler_status(
    State(AppState { api_state, .. }): State<AppState>,
    NoApi(Path(instance_id)): NoApi<Path<InstanceId>>,
    bytes: Bytes,
) -> (StatusCode, NoApi<Response<Body>>) {
    let op = StatusRequest { bytes };
    handle_raw(api_state, instance_id, op).await
}

pub async fn handler_call_v3(
    State(AppState { api_state, .. }): State<AppState>,
    NoApi(Path((instance_id, effective_canister_id))): NoApi<Path<(InstanceId, CanisterId)>>,
    bytes: Bytes,
) -> (StatusCode, NoApi<Response<Body>>) {
    let op = CallRequest {
        effective_canister_id,
        bytes,
        version: CallRequestVersion::V3,
    };
    handle_raw(api_state, instance_id, op).await
}

pub async fn handler_call_v2(
    State(AppState { api_state, .. }): State<AppState>,
    NoApi(Path((instance_id, effective_canister_id))): NoApi<Path<(InstanceId, CanisterId)>>,
    bytes: Bytes,
) -> (StatusCode, NoApi<Response<Body>>) {
    let op = CallRequest {
        effective_canister_id,
        bytes,
        version: CallRequestVersion::V2,
    };
    handle_raw(api_state, instance_id, op).await
}

pub async fn handler_query(
    State(AppState { api_state, .. }): State<AppState>,
    NoApi(Path((instance_id, effective_canister_id))): NoApi<Path<(InstanceId, CanisterId)>>,
    bytes: Bytes,
) -> (StatusCode, NoApi<Response<Body>>) {
    let op = QueryRequest {
        effective_canister_id,
        bytes,
    };
    handle_raw(api_state, instance_id, op).await
}

pub async fn handler_canister_read_state(
    State(AppState { api_state, .. }): State<AppState>,
    NoApi(Path((instance_id, effective_canister_id))): NoApi<Path<(InstanceId, CanisterId)>>,
    bytes: Bytes,
) -> (StatusCode, NoApi<Response<Body>>) {
    let op = CanisterReadStateRequest {
        effective_canister_id,
        bytes,
    };
    handle_raw(api_state, instance_id, op).await
}

pub async fn handler_subnet_read_state(
    State(AppState { api_state, .. }): State<AppState>,
    NoApi(Path((instance_id, subnet_id))): NoApi<Path<(InstanceId, SubnetId)>>,
    bytes: Bytes,
) -> (StatusCode, NoApi<Response<Body>>) {
    let op = SubnetReadStateRequest { subnet_id, bytes };
    handle_raw(api_state, instance_id, op).await
}

async fn handle_raw<T: Operation + Send + Sync + 'static>(
    api_state: Arc<ApiState>,
    instance_id: InstanceId,
    op: T,
) -> (StatusCode, NoApi<Response<Body>>) {
    let (code, res): (StatusCode, ApiResponse<PocketHttpResponse>) =
        run_operation(api_state, instance_id, None, op).await;
    let response = match res {
        ApiResponse::Success((headers, bytes)) => {
            let mut resp = Response::builder().status(code);
            for (name, value) in headers {
                resp = resp.header(name, value);
            }
            resp.body(Body::from(bytes)).unwrap()
        }
        ApiResponse::Error { message } => make_plaintext_response(code, message),
        ApiResponse::Busy { .. } | ApiResponse::Started { .. } => {
            make_plaintext_response(code, format!("{:?}", res))
        }
    };
    (code, NoApi(response))
}

/// The result of a long running PocketIC operation is stored in a graph as an OpOut variant.
/// When polling, the type (and therefore the variant) is no longer known. Therefore we need
/// to try every variant and immediately convert to an axum::Response so that axum understands
/// the return type.
async fn op_out_to_response(op_out: OpOut) -> Response {
    match op_out {
        OpOut::Pruned => (
            StatusCode::GONE,
            Json(ApiResponse::<()>::Error {
                message: "Pruned".to_owned(),
            })
            .into_response(),
        )
            .into_response(),
        opout @ OpOut::MessageId(_) => (
            StatusCode::OK,
            Json(ApiResponse::Success(
                RawSubmitIngressResult::try_from(opout).unwrap(),
            )),
        )
            .into_response(),
        OpOut::NoOutput => (
            StatusCode::OK,
            Json(ApiResponse::Success(())).into_response(),
        )
            .into_response(),
        OpOut::Topology(topology) => {
            (StatusCode::OK, Json(ApiResponse::Success(topology))).into_response()
        }
        opout @ OpOut::Time(_) => (
            StatusCode::OK,
            Json(ApiResponse::Success(RawTime::try_from(opout).unwrap())),
        )
            .into_response(),
        opout @ OpOut::CanisterResult(_) => (
            StatusCode::OK,
            Json(ApiResponse::Success(
                RawCanisterResult::try_from(opout).unwrap(),
            )),
        )
            .into_response(),
        opout @ OpOut::CanisterId(_) => (
            StatusCode::OK,
            Json(ApiResponse::Success(
                RawCanisterId::try_from(opout).unwrap(),
            )),
        )
            .into_response(),
        opout @ OpOut::Cycles(_) => (
            StatusCode::OK,
            Json(ApiResponse::Success(RawCycles::try_from(opout).unwrap())),
        )
            .into_response(),
        opout @ OpOut::Bytes(_) => (
            StatusCode::OK,
            Json(ApiResponse::Success(Vec::<u8>::try_from(opout).unwrap())),
        )
            .into_response(),
        opout @ OpOut::StableMemBytes(_) => (
            StatusCode::OK,
            Json(ApiResponse::Success(
                RawStableMemory::try_from(opout).unwrap(),
            )),
        )
            .into_response(),
        opout @ OpOut::MaybeSubnetId(_) => (
            StatusCode::OK,
            Json(ApiResponse::Success(
                Option::<RawSubnetId>::try_from(opout).unwrap(),
            )),
        )
            .into_response(),
        opout @ OpOut::Error(_) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::Error {
                message: format!("{:?}", PocketIcError::try_from(opout).unwrap()),
            }),
        )
            .into_response(),
        opout @ OpOut::CanisterHttp(_) => (
            StatusCode::OK,
            Json(ApiResponse::Success(
                Vec::<RawCanisterHttpRequest>::try_from(opout).unwrap(),
            )),
        )
            .into_response(),
        OpOut::RawResponse(fut) => {
            let (status, headers, bytes) = fut.await;
            let code = StatusCode::from_u16(status).unwrap();
            let mut resp = Response::builder().status(code);
            for (name, value) in headers {
                resp = resp.header(name, value);
            }
            resp.body(Body::from(bytes)).unwrap()
        }
    }
}

/// Read a node in the graph of computations. Needed for polling for a previous ApiResponse::Started reply.
pub async fn handler_read_graph(
    State(AppState { api_state, .. }): State<AppState>,
    // TODO: type state label and op id correctly but such that axum can handle it
    Path((state_label_str, op_id_str)): Path<(String, String)>,
) -> Response {
    let Ok(vec) = base64::decode_config(state_label_str.as_bytes(), base64::URL_SAFE) else {
        return (StatusCode::BAD_REQUEST, "malformed state_label").into_response();
    };
    if let Ok(state_label) = StateLabel::try_from(vec) {
        let op_id = OpId(op_id_str.clone());
        // TODO: use new_state_label and return it to library
        if let Some((_new_state_label, op_out)) =
            ApiState::read_result(api_state.get_graph(), &state_label, &op_id)
        {
            op_out_to_response(op_out).await
        } else {
            (
                StatusCode::NOT_FOUND,
                Json(ApiResponse::<()>::Error {
                    message: format!(
                        "state_label / op_id not found: {} (base64: {}) / {}",
                        state_label_str,
                        base64::encode_config(state_label.0, base64::URL_SAFE),
                        op_id_str,
                    ),
                }),
            )
                .into_response()
        }
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::Error {
                message: "Bad state_label".to_string(),
            }),
        )
            .into_response()
    }
}

// ----------------------------------------------------------------------------------------------------------------- //
// Update handlers

pub async fn handler_submit_ingress_message(
    State(AppState { api_state, .. }): State<AppState>,
    Path(instance_id): Path<InstanceId>,
    headers: HeaderMap,
    extract::Json(raw_canister_call): extract::Json<RawCanisterCall>,
) -> (StatusCode, Json<ApiResponse<RawSubmitIngressResult>>) {
    let timeout = timeout_or_default(headers);
    match crate::pocket_ic::CanisterCall::try_from(raw_canister_call) {
        Ok(canister_call) => {
            let ingress_op = SubmitIngressMessage(canister_call);
            let (code, response) = run_operation(api_state, instance_id, timeout, ingress_op).await;
            (code, Json(response))
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::Error {
                message: format!("{:?}", e),
            }),
        ),
    }
}

pub async fn handler_await_ingress_message(
    State(AppState { api_state, .. }): State<AppState>,
    Path(instance_id): Path<InstanceId>,
    headers: HeaderMap,
    extract::Json(raw_message_id): extract::Json<RawMessageId>,
) -> (StatusCode, Json<ApiResponse<RawCanisterResult>>) {
    let timeout = timeout_or_default(headers);
    match crate::pocket_ic::MessageId::try_from(raw_message_id) {
        Ok(message_id) => {
            let ingress_op = AwaitIngressMessage(message_id);
            let (code, response) = run_operation(api_state, instance_id, timeout, ingress_op).await;
            (code, Json(response))
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::Error {
                message: format!("{:?}", e),
            }),
        ),
    }
}

pub async fn handler_execute_ingress_message(
    State(AppState { api_state, .. }): State<AppState>,
    Path(instance_id): Path<InstanceId>,
    headers: HeaderMap,
    extract::Json(raw_canister_call): extract::Json<RawCanisterCall>,
) -> (StatusCode, Json<ApiResponse<RawCanisterResult>>) {
    let timeout = timeout_or_default(headers);
    match crate::pocket_ic::CanisterCall::try_from(raw_canister_call) {
        Ok(canister_call) => {
            let ingress_op = ExecuteIngressMessage(canister_call);
            let (code, response) = run_operation(api_state, instance_id, timeout, ingress_op).await;
            (code, Json(response))
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::Error {
                message: format!("{:?}", e),
            }),
        ),
    }
}

pub async fn handler_set_time(
    State(AppState { api_state, .. }): State<AppState>,
    Path(instance_id): Path<InstanceId>,
    headers: HeaderMap,
    axum::extract::Json(time): axum::extract::Json<rest::RawTime>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let timeout = timeout_or_default(headers);
    let op = SetTime {
        time: ic_types::Time::from_nanos_since_unix_epoch(time.nanos_since_epoch),
    };
    let (code, response) = run_operation(api_state, instance_id, timeout, op).await;
    (code, Json(response))
}

pub async fn handler_add_cycles(
    State(AppState { api_state, .. }): State<AppState>,
    Path(instance_id): Path<InstanceId>,
    headers: HeaderMap,
    extract::Json(raw_add_cycles): extract::Json<RawAddCycles>,
) -> (StatusCode, Json<ApiResponse<RawCycles>>) {
    let timeout = timeout_or_default(headers);
    match AddCycles::try_from(raw_add_cycles) {
        Ok(add_op) => {
            let (code, response) = run_operation(api_state, instance_id, timeout, add_op).await;
            (code, Json(response))
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::Error {
                message: format!("{:?}", e),
            }),
        ),
    }
}

pub async fn handler_set_stable_memory(
    State(AppState {
        api_state,
        min_alive_until: _,
        runtime: _,
        blob_store,
    }): State<AppState>,
    Path(instance_id): Path<InstanceId>,
    headers: HeaderMap,
    axum::extract::Json(raw): axum::extract::Json<RawSetStableMemory>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let timeout = timeout_or_default(headers);
    match SetStableMemory::from_store(raw, blob_store).await {
        Ok(set_op) => {
            let (code, response) = run_operation(api_state, instance_id, timeout, set_op).await;
            (code, Json(response))
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::Error {
                message: format!("{:?}", e),
            }),
        ),
    }
}

pub async fn handler_tick(
    State(AppState { api_state, .. }): State<AppState>,
    Path(instance_id): Path<InstanceId>,
    headers: HeaderMap,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let timeout = timeout_or_default(headers);
    let op = Tick;
    let (code, res) = run_operation(api_state, instance_id, timeout, op).await;
    (code, Json(res))
}

// ----------------------------------------------------------------------------------------------------------------- //
// Other handlers

pub async fn status() -> StatusCode {
    StatusCode::OK
}

fn contains_unimplemented(config: ExtendedSubnetConfigSet) -> bool {
    Iterator::any(
        &mut vec![config.sns, config.ii, config.fiduciary, config.bitcoin]
            .into_iter()
            .flatten()
            .chain(config.system)
            .chain(config.application)
            .chain(config.verified_application),
        |spec: pocket_ic::common::rest::SubnetSpec| {
            spec.get_subnet_id().is_some() || !spec.is_supported()
        },
    ) || config
        .nns
        .map(|spec| !spec.is_supported())
        .unwrap_or_default()
}

/// Create a new empty IC instance from a given subnet configuration.
/// The new InstanceId will be returned.
pub async fn create_instance(
    State(AppState {
        api_state,
        min_alive_until: _,
        runtime,
        blob_store: _,
    }): State<AppState>,
    extract::Json(instance_config): extract::Json<InstanceConfig>,
) -> (StatusCode, Json<rest::CreateInstanceResponse>) {
    let subnet_configs = instance_config.subnet_config_set;
    if (instance_config.state_dir.is_none()
        || File::open(
            instance_config
                .state_dir
                .clone()
                .unwrap()
                .join("topology.json"),
        )
        .is_err())
        && subnet_configs.validate().is_err()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(rest::CreateInstanceResponse::Error {
                message: "Bad config".to_owned(),
            }),
        );
    }
    // TODO: Remove this once the SubnetStateConfig variants are implemented
    if contains_unimplemented(subnet_configs.clone()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(rest::CreateInstanceResponse::Error {
                message: "SubnetStateConfig::FromPath is currently only implemented for NNS. SubnetStateConfig::FromBlobStore is not yet implemented".to_owned(),
            }),
        );
    }

    let log_level = if let Some(log_level) = instance_config.log_level {
        match Level::from_str(&log_level) {
            Ok(log_level) => Some(log_level),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(rest::CreateInstanceResponse::Error {
                        message: format!("Failed to parse log level: {:?}", e),
                    }),
                )
            }
        }
    } else {
        None
    };

    let pocket_ic = tokio::task::spawn_blocking(move || {
        PocketIc::new(
            runtime,
            subnet_configs,
            instance_config.state_dir,
            instance_config.nonmainnet_features,
            log_level,
            instance_config.bitcoind_addr,
        )
    })
    .await
    .expect("Failed to launch PocketIC");

    let topology = pocket_ic.topology().clone();
    let instance_id = api_state.add_instance(pocket_ic).await;
    (
        StatusCode::CREATED,
        Json(rest::CreateInstanceResponse::Created {
            instance_id,
            topology,
        }),
    )
}

pub async fn list_instances(
    State(AppState { api_state, .. }): State<AppState>,
) -> Json<Vec<String>> {
    let instances = api_state.list_instance_states().await;
    Json(instances)
}

pub async fn delete_instance(
    State(AppState { api_state, .. }): State<AppState>,
    Path(id): Path<InstanceId>,
) -> StatusCode {
    api_state.delete_instance(id).await;
    StatusCode::OK
}

pub async fn list_http_gateways(
    State(AppState { api_state, .. }): State<AppState>,
) -> Json<Vec<HttpGatewayDetails>> {
    let http_gateways = api_state.list_http_gateways().await;
    Json(http_gateways)
}

/// Create a new HTTP gateway instance from a given HTTP gateway configuration.
/// The new InstanceId and HTTP gateway's port will be returned.
pub async fn create_http_gateway(
    State(AppState { api_state, .. }): State<AppState>,
    extract::Json(http_gateway_config): extract::Json<HttpGatewayConfig>,
) -> (StatusCode, Json<rest::CreateHttpGatewayResponse>) {
    match api_state.create_http_gateway(http_gateway_config).await {
        Ok(http_gateway_info) => (
            StatusCode::CREATED,
            Json(rest::CreateHttpGatewayResponse::Created(http_gateway_info)),
        ),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(rest::CreateHttpGatewayResponse::Error { message: e }),
        ),
    }
}

/// Stops an HTTP gateway instance.
pub async fn stop_http_gateway(
    State(AppState { api_state, .. }): State<AppState>,
    Path(id): Path<InstanceId>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    api_state.stop_http_gateway(id).await;
    (StatusCode::OK, Json(ApiResponse::Success(())))
}

pub async fn auto_progress(
    State(AppState { api_state, .. }): State<AppState>,
    Path(id): Path<InstanceId>,
    extract::Json(auto_progress_config): extract::Json<AutoProgressConfig>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    if let Err(e) = api_state
        .auto_progress(id, auto_progress_config.artificial_delay_ms)
        .await
    {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::Error { message: e }),
        )
    } else {
        (StatusCode::OK, Json(ApiResponse::Success(())))
    }
}

pub async fn stop_progress(
    State(AppState { api_state, .. }): State<AppState>,
    Path(id): Path<InstanceId>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    api_state.stop_progress(id).await;
    (StatusCode::OK, Json(ApiResponse::Success(())))
}

pub trait RouterExt<S>
where
    S: Clone + Send + Sync + 'static,
{
    fn directory_route(self, path: &str, method_router: ApiMethodRouter<S>) -> Self;
}

impl<S> RouterExt<S> for ApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    fn directory_route(self, path: &str, method_router: ApiMethodRouter<S>) -> Self {
        self.api_route(path, method_router.clone())
            .route(&format!("{path}/"), method_router)
    }
}

/// A typed header that a client can use to specify the maximum duration it is willing to wait for a
/// synchronous response.
pub struct ProcessingTimeout(pub Duration);

impl headers::Header for ProcessingTimeout {
    fn name() -> &'static http::header::HeaderName {
        &TIMEOUT_HEADER_NAME
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, headers::Error>
    where
        I: Iterator<Item = &'i http::header::HeaderValue>,
    {
        fn to_invalid<E>(_: E) -> headers::Error {
            headers::Error::invalid()
        }

        let value = values.next().ok_or_else(headers::Error::invalid)?;
        let nanos = value
            .to_str()
            .map_err(to_invalid)?
            .parse::<u64>()
            .map_err(to_invalid)?;
        Ok(Self(Duration::from_millis(nanos)))
    }

    fn encode<E>(&self, values: &mut E)
    where
        E: Extend<http::header::HeaderValue>,
    {
        let nanos = self.0.as_millis();
        let value = http::header::HeaderValue::from_str(&format!("{nanos}")).unwrap();

        values.extend(std::iter::once(value));
    }
}

pub fn timeout_or_default(header_map: HeaderMap) -> Option<Duration> {
    header_map.typed_get::<ProcessingTimeout>().map(|x| x.0)
}

// ----------------------------------------------------------------------------------------------------------------- //
// HTTP handler helpers

const CONTENT_TYPE_TEXT: &str = "text/plain";

fn make_plaintext_response(status: StatusCode, message: String) -> Response<Body> {
    let mut resp = Response::new(Body::from(message));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(CONTENT_TYPE_TEXT),
    );
    resp
}

pub async fn verify_cbor_content_header(
    request: axum::extract::Request,
    next: Next,
) -> axum::response::Response {
    const CONTENT_TYPE_CBOR: &str = "application/cbor";
    if !request
        .headers()
        .get_all(http::header::CONTENT_TYPE)
        .iter()
        .any(|value| {
            if let Ok(v) = value.to_str() {
                return v.to_lowercase() == CONTENT_TYPE_CBOR;
            }
            false
        })
    {
        return make_plaintext_response(
            StatusCode::BAD_REQUEST,
            format!("Unexpected content-type, expected {}.", CONTENT_TYPE_CBOR),
        );
    }

    next.run(request).await
}
