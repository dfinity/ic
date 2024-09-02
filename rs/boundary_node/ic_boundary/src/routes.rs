#![allow(clippy::declare_interior_mutable_const)]

use std::{
    fmt,
    hash::{Hash, Hasher},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use anyhow::anyhow;
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use axum::{
    body::Body,
    extract::{MatchedPath, Path, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    BoxError, Extension,
};
use bytes::Bytes;
use candid::{CandidType, Decode, Principal};
use http::header::{HeaderValue, CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS};
use ic_bn_lib::http::{
    body::buffer_body, headers::*, proxy, Client as HttpClient, Error as IcBnError,
};
use ic_types::{
    messages::{Blob, HttpStatusResponse, ReplicaHealthStatus},
    CanisterId, PrincipalId, SubnetId,
};

use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use strum::{Display, IntoStaticStr};
use tower_governor::errors::GovernorError;
use url::Url;

use crate::{
    cache::CacheStatus,
    core::{decoder_config, MAX_REQUEST_BODY_SIZE},
    http::error_infer,
    persist::{RouteSubnet, Routes},
    retry::RetryResult,
    snapshot::{Node, RegistrySnapshot},
};

// TODO which one to use?
const IC_API_VERSION: &str = "0.18.0";
pub const ANONYMOUS_PRINCIPAL: Principal = Principal::anonymous();
const METHOD_HTTP: &str = "http_request";

const HEADERS_HIDE_HTTP_REQUEST: [&str; 4] =
    ["x-real-ip", "x-forwarded-for", "x-request-id", "user-agent"];

// Rust const/static concat is non-existent, so we have to repeat
pub const PATH_STATUS: &str = "/api/v2/status";
pub const PATH_QUERY: &str = "/api/v2/canister/:canister_id/query";
pub const PATH_CALL: &str = "/api/v2/canister/:canister_id/call";
pub const PATH_CALL_V3: &str = "/api/v3/canister/:canister_id/call";
pub const PATH_READ_STATE: &str = "/api/v2/canister/:canister_id/read_state";
pub const PATH_SUBNET_READ_STATE: &str = "/api/v2/subnet/:subnet_id/read_state";
pub const PATH_HEALTH: &str = "/health";

lazy_static! {
    pub static ref UUID_REGEX: Regex =
        Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").unwrap();
}

// Type of IC request
#[derive(Debug, Default, Clone, Copy, Display, PartialEq, Eq, Hash, IntoStaticStr, Deserialize)]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum RequestType {
    #[default]
    Unknown,
    Status,
    Query,
    Call,
    CallV3,
    ReadState,
    ReadStateSubnet,
}

impl RequestType {
    pub fn is_call(&self) -> bool {
        matches!(self, Self::Call | Self::CallV3)
    }
}

#[derive(Debug, Clone, Display)]
#[strum(serialize_all = "snake_case")]
pub enum RateLimitCause {
    Normal,
    Bouncer,
    Generic,
}

// Categorized possible causes for request processing failures
// Not using Error as inner type since it's not cloneable
#[derive(Debug, Clone)]
pub enum ErrorCause {
    BodyTimedOut,
    UnableToReadBody(String),
    PayloadTooLarge(usize),
    UnableToParseCBOR(String),
    UnableToParseHTTPArg(String),
    LoadShed,
    MalformedRequest(String),
    MalformedResponse(String),
    NoRoutingTable,
    SubnetNotFound,
    NoHealthyNodes,
    ReplicaErrorDNS(String),
    ReplicaErrorConnect,
    ReplicaTimeout,
    ReplicaTLSErrorOther(String),
    ReplicaTLSErrorCert(String),
    ReplicaErrorOther(String),
    RateLimited(RateLimitCause),
    Other(String),
}

impl ErrorCause {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            Self::BodyTimedOut => StatusCode::REQUEST_TIMEOUT,
            Self::UnableToReadBody(_) => StatusCode::REQUEST_TIMEOUT,
            Self::UnableToParseCBOR(_) => StatusCode::BAD_REQUEST,
            Self::UnableToParseHTTPArg(_) => StatusCode::BAD_REQUEST,
            Self::LoadShed => StatusCode::TOO_MANY_REQUESTS,
            Self::MalformedRequest(_) => StatusCode::BAD_REQUEST,
            Self::MalformedResponse(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NoRoutingTable => StatusCode::SERVICE_UNAVAILABLE,
            Self::SubnetNotFound => StatusCode::BAD_REQUEST, // TODO change to 404?
            Self::NoHealthyNodes => StatusCode::SERVICE_UNAVAILABLE,
            Self::ReplicaErrorDNS(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::ReplicaErrorConnect => StatusCode::SERVICE_UNAVAILABLE,
            Self::ReplicaTimeout => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ReplicaTLSErrorOther(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::ReplicaTLSErrorCert(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::ReplicaErrorOther(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::RateLimited(_) => StatusCode::TOO_MANY_REQUESTS,
        }
    }

    pub fn details(&self) -> Option<String> {
        match self {
            Self::Other(x) => Some(x.clone()),
            Self::PayloadTooLarge(x) => Some(format!("maximum body size is {x} bytes")),
            Self::UnableToReadBody(x) => Some(x.clone()),
            Self::UnableToParseCBOR(x) => Some(x.clone()),
            Self::UnableToParseHTTPArg(x) => Some(x.clone()),
            Self::LoadShed => Some("Overloaded".into()),
            Self::MalformedRequest(x) => Some(x.clone()),
            Self::MalformedResponse(x) => Some(x.clone()),
            Self::ReplicaErrorDNS(x) => Some(x.clone()),
            Self::ReplicaTLSErrorOther(x) => Some(x.clone()),
            Self::ReplicaTLSErrorCert(x) => Some(x.clone()),
            Self::ReplicaErrorOther(x) => Some(x.clone()),
            _ => None,
        }
    }

    pub fn retriable(&self) -> bool {
        !matches!(self, Self::PayloadTooLarge(_) | Self::MalformedResponse(_))
    }
}

// TODO use strum
impl fmt::Display for ErrorCause {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Other(_) => write!(f, "general_error"),
            Self::BodyTimedOut => write!(f, "body_timed_out"),
            Self::UnableToReadBody(_) => write!(f, "unable_to_read_body"),
            Self::PayloadTooLarge(_) => write!(f, "payload_too_large"),
            Self::UnableToParseCBOR(_) => write!(f, "unable_to_parse_cbor"),
            Self::UnableToParseHTTPArg(_) => write!(f, "unable_to_parse_http_arg"),
            Self::LoadShed => write!(f, "load_shed"),
            Self::MalformedRequest(_) => write!(f, "malformed_request"),
            Self::MalformedResponse(_) => write!(f, "malformed_response"),
            Self::NoRoutingTable => write!(f, "no_routing_table"),
            Self::SubnetNotFound => write!(f, "subnet_not_found"),
            Self::NoHealthyNodes => write!(f, "no_healthy_nodes"),
            Self::ReplicaErrorDNS(_) => write!(f, "replica_error_dns"),
            Self::ReplicaErrorConnect => write!(f, "replica_error_connect"),
            Self::ReplicaTimeout => write!(f, "replica_timeout"),
            Self::ReplicaTLSErrorOther(_) => write!(f, "replica_tls_error"),
            Self::ReplicaTLSErrorCert(_) => write!(f, "replica_tls_error_cert"),
            Self::ReplicaErrorOther(_) => write!(f, "replica_error_other"),
            Self::RateLimited(x) => write!(f, "rate_limited_{x}"),
        }
    }
}

// Creates the response from ErrorCause and injects itself into extensions to be visible by middleware
impl IntoResponse for ErrorCause {
    fn into_response(self) -> Response {
        let mut body = self.to_string();

        if let Some(v) = self.details() {
            body = format!("{body}: {v}");
        }

        let mut resp = (self.status_code(), format!("{body}\n")).into_response();
        resp.extensions_mut().insert(self);
        resp
    }
}

#[derive(Clone, CandidType, Deserialize, Hash, PartialEq)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
}

// Object that holds per-request information
#[derive(Default, Clone)]
pub struct RequestContext {
    pub request_type: RequestType,
    pub request_size: u32,

    // CBOR fields
    pub canister_id: Option<Principal>,
    pub sender: Option<Principal>,
    pub method_name: Option<String>,
    pub nonce: Option<Vec<u8>>,
    pub ingress_expiry: Option<u64>,
    pub arg: Option<Vec<u8>>,

    // Filled in when the request is HTTP
    pub http_request: Option<HttpRequest>,
}

impl RequestContext {
    pub fn is_anonymous(&self) -> Option<bool> {
        self.sender.map(|x| x == ANONYMOUS_PRINCIPAL)
    }
}

// Hash and Eq are implemented for request caching
// They should both work on the same fields so that
// k1 == k2 && hash(k1) == hash(k2)
impl Hash for RequestContext {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.canister_id.hash(state);
        self.sender.hash(state);
        self.method_name.hash(state);
        self.ingress_expiry.hash(state);

        // Hash http_request if it's present, arg otherwise
        // They're mutually exclusive
        if self.http_request.is_some() {
            self.http_request.hash(state);
        } else {
            self.arg.hash(state);
        }
    }
}

impl PartialEq for RequestContext {
    fn eq(&self, other: &Self) -> bool {
        let r = self.canister_id == other.canister_id
            && self.sender == other.sender
            && self.method_name == other.method_name
            && self.ingress_expiry == other.ingress_expiry;

        // Same as in hash()
        if self.http_request.is_some() {
            r && self.http_request == other.http_request
        } else {
            r && self.arg == other.arg
        }
    }
}
impl Eq for RequestContext {}

// This is the subset of the request fields
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ICRequestContent {
    sender: Principal,
    canister_id: Option<Principal>,
    method_name: Option<String>,
    nonce: Option<Blob>,
    ingress_expiry: Option<u64>,
    arg: Option<Blob>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ICRequestEnvelope {
    content: ICRequestContent,
}

#[async_trait]
pub trait Proxy: Sync + Send {
    async fn proxy(&self, request: Request<Body>, url: Url) -> Result<Response, ErrorCause>;
}

pub trait Lookup: Sync + Send {
    fn lookup_subnet_by_canister_id(&self, id: &CanisterId)
        -> Result<Arc<RouteSubnet>, ErrorCause>;
    fn lookup_subnet_by_id(&self, id: &SubnetId) -> Result<Arc<RouteSubnet>, ErrorCause>;
}

#[async_trait]
pub trait Health: Sync + Send {
    async fn health(&self) -> ReplicaHealthStatus;
}

#[async_trait]
pub trait RootKey: Sync + Send {
    async fn root_key(&self) -> Option<Vec<u8>>;
}

// Router that helps handlers do their job by looking up in routing table
// and owning HTTP client for outgoing requests
#[derive(Clone)]
pub struct ProxyRouter {
    http_client: Arc<dyn HttpClient>,
    published_routes: Arc<ArcSwapOption<Routes>>,
    published_registry_snapshot: Arc<ArcSwapOption<RegistrySnapshot>>,
}

impl ProxyRouter {
    pub fn new(
        http_client: Arc<dyn HttpClient>,
        published_routes: Arc<ArcSwapOption<Routes>>,
        published_registry_snapshot: Arc<ArcSwapOption<RegistrySnapshot>>,
    ) -> Self {
        Self {
            http_client,
            published_routes,
            published_registry_snapshot,
        }
    }
}

#[async_trait]
impl Proxy for ProxyRouter {
    async fn proxy(&self, request: Request, url: Url) -> Result<Response, ErrorCause> {
        // TODO map errors
        let response = proxy::proxy(url, request, &self.http_client)
            .await
            .map_err(|e| error_infer(&e))?;

        Ok(response)
    }
}

#[async_trait]
impl Lookup for ProxyRouter {
    fn lookup_subnet_by_canister_id(
        &self,
        canister_id: &CanisterId,
    ) -> Result<Arc<RouteSubnet>, ErrorCause> {
        let subnet = self
            .published_routes
            .load_full()
            .ok_or(ErrorCause::NoRoutingTable)? // No routing table present
            .lookup_by_canister_id(canister_id.get_ref().0)
            .ok_or(ErrorCause::SubnetNotFound)?; // Requested canister route wasn't found

        Ok(subnet)
    }

    fn lookup_subnet_by_id(&self, subnet_id: &SubnetId) -> Result<Arc<RouteSubnet>, ErrorCause> {
        let subnet = self
            .published_routes
            .load_full()
            .ok_or(ErrorCause::NoRoutingTable)? // No routing table present
            .lookup_by_id(subnet_id.get_ref().0)
            .ok_or(ErrorCause::SubnetNotFound)?; // Requested subnet_id route wasn't found

        Ok(subnet)
    }
}

#[async_trait]
impl RootKey for ProxyRouter {
    async fn root_key(&self) -> Option<Vec<u8>> {
        self.published_registry_snapshot
            .load_full()
            .map(|x| x.nns_public_key.clone())
    }
}

#[async_trait]
impl Health for ProxyRouter {
    async fn health(&self) -> ReplicaHealthStatus {
        // Return healthy state if we have at least one healthy replica node
        // TODO increase threshold? change logic?
        match self.published_routes.load_full() {
            Some(rt) => {
                if rt.node_count > 0 {
                    ReplicaHealthStatus::Healthy
                } else {
                    // There's no generic "Unhealthy" state it seems, should we use Starting?
                    ReplicaHealthStatus::CertifiedStateBehind
                }
            }

            // Usually this is only for the first 10sec after startup
            None => ReplicaHealthStatus::Starting,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("status {0}: {1}")]
    _Custom(StatusCode, String),

    #[error("proxy error: {0}")]
    ProxyError(ErrorCause),

    #[error(transparent)]
    Unspecified(#[from] anyhow::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::_Custom(c, b) => (c, b).into_response(),
            ApiError::ProxyError(c) => c.into_response(),
            ApiError::Unspecified(err) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
            }
        }
    }
}

impl From<ErrorCause> for ApiError {
    fn from(c: ErrorCause) -> Self {
        ApiError::ProxyError(c)
    }
}

impl From<BoxError> for ApiError {
    fn from(item: BoxError) -> Self {
        if !item.is::<GovernorError>() {
            return ApiError::Unspecified(anyhow!(item.to_string()));
        }

        // it's a GovernorError
        let error = item.downcast_ref::<GovernorError>().unwrap().to_owned();
        match error {
            GovernorError::TooManyRequests { .. } => {
                ApiError::from(ErrorCause::RateLimited(RateLimitCause::Normal))
            }
            GovernorError::UnableToExtractKey => ApiError::from(ErrorCause::Other(
                "unable to extract rate-limiting key".into(),
            )),
            GovernorError::Other { msg, .. } => ApiError::from(ErrorCause::Other(format!(
                "governor_error: {}",
                msg.unwrap_or_default()
            ))),
        }
    }
}

pub async fn validate_canister_request(
    matched_path: MatchedPath,
    canister_id: Path<String>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, ApiError> {
    let request_type = match matched_path.as_str() {
        PATH_QUERY => RequestType::Query,
        PATH_CALL => RequestType::Call,
        PATH_CALL_V3 => RequestType::CallV3,
        PATH_READ_STATE => RequestType::ReadState,
        _ => panic!("unknown path, should never happen"),
    };

    request.extensions_mut().insert(request_type);

    // Decode canister_id from URL
    let canister_id = CanisterId::from_str(&canister_id).map_err(|err| {
        ErrorCause::MalformedRequest(format!("Unable to decode canister_id from URL: {err}"))
    })?;

    request.extensions_mut().insert(canister_id);

    let mut resp = next.run(request).await;

    resp.headers_mut().insert(
        X_IC_CANISTER_ID,
        HeaderValue::from_maybe_shared(Bytes::from(canister_id.to_string())).unwrap(),
    );

    Ok(resp)
}

pub async fn validate_subnet_request(
    matched_path: MatchedPath,
    subnet_id: Path<String>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, ApiError> {
    let request_type = match matched_path.as_str() {
        PATH_SUBNET_READ_STATE => RequestType::ReadStateSubnet,
        _ => panic!("unknown path, should never happen"),
    };

    request.extensions_mut().insert(request_type);

    // Decode canister_id from URL
    let principal_id: PrincipalId = Principal::from_text(subnet_id.as_str())
        .map_err(|err| {
            ErrorCause::MalformedRequest(format!("Unable to decode subnet_id from URL: {err}"))
        })?
        .into();
    let subnet_id = SubnetId::from(principal_id);

    request.extensions_mut().insert(subnet_id);

    let resp = next.run(request).await;

    Ok(resp)
}

pub async fn validate_request(request: Request, next: Next) -> Result<impl IntoResponse, ApiError> {
    if let Some(id_header) = request.headers().get(X_REQUEST_ID) {
        let is_valid_id = id_header
            .to_str()
            .map(|id| UUID_REGEX.is_match(id))
            .unwrap_or(false);

        if !is_valid_id {
            #[allow(clippy::borrow_interior_mutable_const)]
            return Err(ErrorCause::MalformedRequest(format!(
                "value of '{X_REQUEST_ID}' header is not in UUID format"
            ))
            .into());
        }
    }

    let resp = next.run(request).await;
    Ok(resp)
}

// Middleware: preprocess the request before handing it over to handlers
pub async fn preprocess_request(
    Extension(request_type): Extension<RequestType>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, ApiError> {
    // Consume body
    let (parts, body) = request.into_parts();
    let body = buffer_body(body, MAX_REQUEST_BODY_SIZE, Duration::from_secs(60))
        .await
        .map_err(|e| match e {
            IcBnError::BodyReadingFailed(v) => ErrorCause::UnableToReadBody(v),
            IcBnError::BodyTooBig => ErrorCause::PayloadTooLarge(MAX_REQUEST_BODY_SIZE),
            IcBnError::BodyTimedOut => ErrorCause::BodyTimedOut,
            _ => ErrorCause::Other(e.to_string()),
        })?;

    // Parse the request body
    let envelope: ICRequestEnvelope = serde_cbor::from_slice(&body)
        .map_err(|err| ErrorCause::UnableToParseCBOR(err.to_string()))?;
    let content = envelope.content;

    // Check if the request is HTTP and try to parse the arg
    let (arg, http_request) = match (&content.method_name, content.arg) {
        (Some(method), Some(arg)) => {
            if request_type == RequestType::Query && method == METHOD_HTTP {
                let mut req: HttpRequest = Decode!([decoder_config()]; &arg.0, HttpRequest)
                    .map_err(|err| {
                        ErrorCause::UnableToParseHTTPArg(format!(
                            "unable to decode arg as HttpRequest: {err}"
                        ))
                    })?;

                // Remove specific headers
                req.headers
                    .retain(|x| !HEADERS_HIDE_HTTP_REQUEST.contains(&(x.0.as_str())));

                // Drop the arg as it's now redundant
                (None, Some(req))
            } else {
                (Some(arg), None)
            }
        }

        (_, arg) => (arg, None),
    };

    // Construct the context
    let ctx = RequestContext {
        request_type,
        request_size: body.len() as u32,
        sender: Some(content.sender),
        canister_id: content.canister_id,
        method_name: content.method_name,
        ingress_expiry: content.ingress_expiry,
        arg: arg.map(|x| x.0),
        nonce: content.nonce.map(|x| x.0),
        http_request,
    };

    let ctx = Arc::new(ctx);

    // Reconstruct request back from parts
    let mut request = Request::from_parts(parts, Body::from(body));

    // Inject variables into the request
    request.extensions_mut().insert(ctx.clone());

    // Pass request to the next processor
    let mut response = next.run(request).await;

    // Inject context into the response for access by other middleware
    response.extensions_mut().insert(ctx);

    Ok(response)
}

// Middleware: looks up the target subnet in the routing table
pub async fn lookup_subnet(
    State(lk): State<Arc<dyn Lookup>>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, ApiError> {
    let subnet = if let Some(canister_id) = request.extensions().get::<CanisterId>() {
        lk.lookup_subnet_by_canister_id(canister_id)?
    } else if let Some(subnet_id) = request.extensions().get::<SubnetId>() {
        lk.lookup_subnet_by_id(subnet_id)?
    } else {
        panic!("canister_id and subnet_id can't be both empty for a request")
    };

    // Inject subnet into request
    request.extensions_mut().insert(Arc::clone(&subnet));

    // Pass request to the next processor
    let mut response = next.run(request).await;

    // Inject subnet into the response for access by other middleware
    response.extensions_mut().insert(subnet);

    Ok(response)
}

// Middleware: postprocess the response
pub async fn postprocess_response(request: Request, next: Next) -> impl IntoResponse {
    let mut response = next.run(request).await;

    let error_cause = response
        .extensions()
        .get::<ErrorCause>()
        .map(|x| x.to_string())
        .unwrap_or("none".into());

    // Set the correct content-type for all replies if it's not an error
    if error_cause == "none" && response.status().is_success() {
        response
            .headers_mut()
            .insert(CONTENT_TYPE, CONTENT_TYPE_CBOR);
        response
            .headers_mut()
            .insert(X_CONTENT_TYPE_OPTIONS, X_CONTENT_TYPE_OPTIONS_NO_SNIFF);
        response
            .headers_mut()
            .insert(X_FRAME_OPTIONS, X_FRAME_OPTIONS_DENY);
    }

    response.headers_mut().insert(
        X_IC_ERROR_CAUSE,
        HeaderValue::from_maybe_shared(Bytes::from(error_cause)).unwrap(),
    );

    // Add cache status if there's one
    let cache_status = response.extensions().get::<CacheStatus>().cloned();
    if let Some(v) = cache_status {
        response.headers_mut().insert(
            X_IC_CACHE_STATUS,
            HeaderValue::from_maybe_shared(Bytes::from(v.to_string())).unwrap(),
        );

        if let CacheStatus::Bypass(v) = v {
            response.headers_mut().insert(
                X_IC_CACHE_BYPASS_REASON,
                HeaderValue::from_maybe_shared(Bytes::from(v.to_string())).unwrap(),
            );
        }
    }

    if let Some(v) = response.extensions().get::<Arc<RouteSubnet>>().cloned() {
        response.headers_mut().insert(
            X_IC_SUBNET_ID,
            HeaderValue::from_maybe_shared(Bytes::from(v.id.to_string())).unwrap(),
        );
    }

    let node = response.extensions().get::<Arc<Node>>().cloned();
    if let Some(v) = node {
        // Principals and subnet type are always ASCII printable, so unwrap is safe
        response.headers_mut().insert(
            X_IC_NODE_ID,
            HeaderValue::from_maybe_shared(Bytes::from(v.id.to_string())).unwrap(),
        );

        response.headers_mut().insert(
            X_IC_SUBNET_TYPE,
            HeaderValue::from_str(v.subnet_type.as_ref()).unwrap(),
        );
    }

    if let Some(ctx) = response.extensions().get::<Arc<RequestContext>>().cloned() {
        response.headers_mut().insert(
            X_IC_REQUEST_TYPE,
            HeaderValue::from_maybe_shared(Bytes::from(ctx.request_type.to_string())).unwrap(),
        );

        ctx.canister_id.and_then(|v| {
            response.headers_mut().insert(
                X_IC_CANISTER_ID_CBOR,
                HeaderValue::from_maybe_shared(Bytes::from(v.to_string())).unwrap(),
            )
        });

        ctx.sender.and_then(|v| {
            response.headers_mut().insert(
                X_IC_SENDER,
                HeaderValue::from_maybe_shared(Bytes::from(v.to_string())).unwrap(),
            )
        });

        ctx.method_name.as_ref().and_then(|v| {
            response.headers_mut().insert(
                X_IC_METHOD_NAME,
                HeaderValue::from_maybe_shared(Bytes::from(v.clone())).unwrap(),
            )
        });
    }

    let retry_result = response.extensions().get::<RetryResult>().cloned();
    if let Some(v) = retry_result {
        response.headers_mut().insert(
            X_IC_RETRIES,
            HeaderValue::from_maybe_shared(Bytes::from(v.retries.to_string())).unwrap(),
        );
    }

    response
}

// Handler: emit an HTTP status code that signals the service's state
pub async fn health(State(h): State<Arc<dyn Health>>) -> impl IntoResponse {
    if h.health().await == ReplicaHealthStatus::Healthy {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

// Handler: processes IC status call
pub async fn status(
    State((rk, h)): State<(Arc<dyn RootKey>, Arc<dyn Health>)>,
) -> impl IntoResponse {
    let health = h.health().await;

    let status = HttpStatusResponse {
        ic_api_version: IC_API_VERSION.to_string(),
        root_key: rk.root_key().await.map(|x| x.into()),
        impl_version: None,
        impl_hash: None,
        replica_health_status: Some(health),
        certified_height: None,
    };

    // Serialize to CBOR
    let mut ser = serde_cbor::Serializer::new(Vec::new());
    // These should not really fail, better to panic if something in serde changes which would cause them to fail
    ser.self_describe().unwrap();
    status.serialize(&mut ser).unwrap();
    let cbor = ser.into_inner();

    // Construct response and inject health status for middleware
    let mut response = cbor.into_response();
    response.extensions_mut().insert(health);
    response
        .headers_mut()
        .insert(CONTENT_TYPE, CONTENT_TYPE_CBOR);
    response
        .headers_mut()
        .insert(X_CONTENT_TYPE_OPTIONS, X_CONTENT_TYPE_OPTIONS_NO_SNIFF);
    response
        .headers_mut()
        .insert(X_FRAME_OPTIONS, X_FRAME_OPTIONS_DENY);

    response
}

// Handler: Unified handler for query/call/read_state calls
pub async fn handle_canister(
    State(p): State<Arc<dyn Proxy>>,
    Extension(ctx): Extension<Arc<RequestContext>>,
    Extension(canister_id): Extension<CanisterId>,
    Extension(node): Extension<Arc<Node>>,
    request: Request<Body>,
) -> Result<impl IntoResponse, ApiError> {
    let url = node
        .build_url(ctx.request_type, canister_id.into())
        .map_err(|e| ErrorCause::Other(format!("failed to build request url: {e}")))?;
    // Proxy the request
    let resp = p.proxy(request, url).await?;

    Ok(resp)
}

pub async fn handle_subnet(
    State(p): State<Arc<dyn Proxy>>,
    Extension(ctx): Extension<Arc<RequestContext>>,
    Extension(subnet_id): Extension<SubnetId>,
    Extension(node): Extension<Arc<Node>>,
    request: Request<Body>,
) -> Result<impl IntoResponse, ApiError> {
    let url = node
        .build_url(ctx.request_type, subnet_id.get().into())
        .map_err(|e| ErrorCause::Other(format!("failed to build request url: {e}")))?;
    // Proxy the request
    let resp = p.proxy(request, url).await?;

    Ok(resp)
}

#[cfg(test)]
pub mod test;
