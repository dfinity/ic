/// This module contains the route handlers for the PocketIc server.
///
/// A handler may receive a representation of a PocketIc Operation in the request
/// body. This has to be canonicalized into a PocketIc Operation before we can
/// deterministically update the PocketIc state machine.
///
use super::state::{ApiState, OpOut, PocketIcError, UpdateReply};
use crate::pocket_ic::GetSubnet;
use crate::pocket_ic::{
    AddCycles, ExecuteIngressMessage, GetCyclesBalance, GetStableMemory, GetTime, PubKey, Query,
    SetStableMemory, SetTime, Tick,
};
use crate::{pocket_ic::PocketIc, BlobStore, InstanceId, Operation};
use aide::axum::routing::{delete, get, post, ApiMethodRouter};
use aide::axum::ApiRouter;
use axum::{
    extract::{self, Path, State},
    http::{self, HeaderMap, HeaderName, StatusCode},
    Json,
};
use axum_extra::headers;
use axum_extra::headers::HeaderMapExt;
use backoff::backoff::Backoff;
use backoff::exponential::ExponentialBackoffBuilder;
use backoff::ExponentialBackoff;
use ic_types::CanisterId;
use pocket_ic::common::rest::{
    self, ApiResponse, ExtendedSubnetConfigSet, RawAddCycles, RawCanisterCall, RawCanisterId,
    RawCanisterResult, RawCycles, RawSetStableMemory, RawStableMemory, RawSubnetId, RawTime,
    RawWasmResult,
};
use pocket_ic::WasmResult;
use serde::Serialize;
use std::{sync::Arc, time::Duration};
use tokio::{runtime::Runtime, sync::RwLock, time::Instant};
use tracing::trace;

/// Name of a header that allows clients to specify for how long their are willing to wait for a
/// response on a open http request.
pub static TIMEOUT_HEADER_NAME: HeaderName = HeaderName::from_static("processing-timeout-ms");

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
        .directory_route("/query", post(handler_query))
        .directory_route("/get_time", get(handler_get_time))
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
            "/execute_ingress_message",
            post(handler_execute_ingress_message),
        )
        .directory_route("/set_time", post(handler_set_time))
        .directory_route("/add_cycles", post(handler_add_cycles))
        .directory_route("/set_stable_memory", post(handler_set_stable_memory))
        .directory_route("/tick", post(handler_tick))
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
}

async fn run_operation<T: Serialize>(
    api_state: Arc<ApiState>,
    instance_id: InstanceId,
    timeout: Option<Duration>,
    op: impl Operation + Send + Sync + 'static,
) -> (StatusCode, ApiResponse<T>)
where
    (StatusCode, ApiResponse<T>): From<OpOut>,
{
    let retry_if_busy = op.retry_if_busy();
    let op = Arc::new(op);
    let mut retry_policy: ExponentialBackoff = ExponentialBackoffBuilder::new()
        .with_initial_interval(Duration::from_millis(10))
        .with_max_interval(Duration::from_secs(1))
        .with_multiplier(2.0)
        .with_max_elapsed_time(Some(Duration::from_secs(60 * 5)))
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
                                state_label: format!("{:?}", state_label),
                                op_id: format!("{:?}", op_id),
                            },
                        )
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
                                    state_label: format!("{:?}", state_label),
                                    op_id: format!("{:?}", op_id),
                                },
                            );
                        }
                    }
                    UpdateReply::Output(op_out) => break op_out.into(),
                }
            }
        }
    }
}

impl From<OpOut> for (StatusCode, ApiResponse<RawTime>) {
    fn from(value: OpOut) -> Self {
        match value {
            OpOut::Time(time) => (
                StatusCode::OK,
                ApiResponse::Success(RawTime {
                    nanos_since_epoch: time,
                }),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ApiResponse::Error {
                    message: "operation returned invalid type".into(),
                },
            ),
        }
    }
}

impl From<OpOut> for (StatusCode, ApiResponse<()>) {
    fn from(value: OpOut) -> Self {
        match value {
            OpOut::NoOutput => (StatusCode::OK, ApiResponse::Success(())),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ApiResponse::Error {
                    message: "operation returned invalid type".into(),
                },
            ),
        }
    }
}

impl From<OpOut> for (StatusCode, ApiResponse<RawCycles>) {
    fn from(value: OpOut) -> Self {
        match value {
            OpOut::Cycles(cycles) => (StatusCode::OK, ApiResponse::Success(RawCycles { cycles })),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ApiResponse::Error {
                    message: "operation returned invalid type".into(),
                },
            ),
        }
    }
}

impl From<OpOut> for (StatusCode, ApiResponse<RawStableMemory>) {
    fn from(value: OpOut) -> Self {
        match value {
            OpOut::Bytes(stable_memory) => (
                StatusCode::OK,
                ApiResponse::Success(RawStableMemory {
                    blob: stable_memory,
                }),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ApiResponse::Error {
                    message: "operation returned invalid type".into(),
                },
            ),
        }
    }
}

impl From<OpOut> for (StatusCode, ApiResponse<RawCanisterResult>) {
    fn from(value: OpOut) -> Self {
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
                (StatusCode::OK, ApiResponse::Success(inner))
            }
            OpOut::Error(e) => (
                StatusCode::BAD_REQUEST,
                ApiResponse::Error {
                    message: format!("Canister call returned an error: {:?}", e),
                },
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ApiResponse::Error {
                    message: "operation returned invalid type".into(),
                },
            ),
        }
    }
}

impl From<OpOut> for (StatusCode, ApiResponse<RawCanisterId>) {
    fn from(value: OpOut) -> Self {
        match value {
            OpOut::CanisterId(canister_id) => (
                StatusCode::OK,
                ApiResponse::Success(RawCanisterId {
                    canister_id: canister_id.get().to_vec(),
                }),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ApiResponse::Error {
                    message: "operation returned invalid type".into(),
                },
            ),
        }
    }
}

impl From<OpOut> for (StatusCode, ApiResponse<Option<RawSubnetId>>) {
    fn from(value: OpOut) -> Self {
        match value {
            OpOut::SubnetId(subnet_id) => (
                StatusCode::OK,
                ApiResponse::Success(Some(RawSubnetId {
                    subnet_id: subnet_id.get().to_vec(),
                })),
            ),
            OpOut::Error(PocketIcError::CanisterNotFound(_)) => {
                (StatusCode::OK, ApiResponse::Success(None))
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

impl From<OpOut> for (StatusCode, ApiResponse<Vec<u8>>) {
    fn from(value: OpOut) -> Self {
        match value {
            OpOut::Bytes(bytes) => (StatusCode::OK, ApiResponse::Success(bytes)),
            OpOut::Error(e) => (
                StatusCode::BAD_REQUEST,
                ApiResponse::Error {
                    message: format!("Call returned an error: {:?}", e),
                },
            ),
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

pub async fn handler_query(
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

// ----------------------------------------------------------------------------------------------------------------- //
// Update handlers

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
            .chain(config.application),
        |spec: pocket_ic::common::rest::SubnetSpec| {
            spec.get_subnet_id().is_some()
                || matches!(
                    spec,
                    pocket_ic::common::rest::SubnetSpec::FromBlobStore(_, _)
                )
        },
    ) || matches!(
        config.nns,
        Some(pocket_ic::common::rest::SubnetSpec::FromBlobStore(_, _))
    )
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
    extract::Json(subnet_configs): extract::Json<ExtendedSubnetConfigSet>,
) -> (StatusCode, Json<rest::CreateInstanceResponse>) {
    if subnet_configs.validate().is_err() {
        return (
            StatusCode::BAD_REQUEST,
            Json(rest::CreateInstanceResponse::Error {
                message: "Bad config".to_owned(),
            }),
        );
    }
    // TODO: Remove this once the SubnetSpec variants are implemented
    if contains_unimplemented(subnet_configs.clone()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(rest::CreateInstanceResponse::Error {
                message: "SubnetSpec::FromPath is currently only implemented for NNS. SubnetSpec::FromBlobStore is not yet implemented".to_owned(),
            }),
        );
    }

    let pocket_ic = tokio::task::spawn_blocking(move || PocketIc::new(runtime, subnet_configs))
        .await
        .expect("Failed to launch PocketIC");

    let topology = pocket_ic.topology.clone();
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
