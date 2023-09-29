use std::{
    fmt,
    hash::{Hash, Hasher},
    str::FromStr,
    sync::Arc,
};

use anyhow::anyhow;
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use axum::{
    body::{Body, StreamBody},
    extract::{rejection::PathRejection, MatchedPath, Path, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    BoxError, Extension,
};
use candid::Principal;
use http::{
    header::{HeaderName, HeaderValue, CONTENT_TYPE},
    Method,
};
use ic_types::messages::{Blob, HttpStatusResponse, ReplicaHealthStatus};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use tower_governor::errors::GovernorError;
use url::Url;

#[cfg(feature = "tls")]
use {
    axum::{
        extract::{Host, OriginalUri},
        http::{uri::PathAndQuery, Uri},
        response::Redirect,
    },
    tokio::sync::RwLock,
};

use crate::{cache::CacheStatus, http::HttpClient, persist::Routes, snapshot::Node};

// TODO which one to use?
const IC_API_VERSION: &str = "0.18.0";
pub const ANONYMOUS_PRINCIPAL: Principal = Principal::anonymous();

// Clippy complains that these are interior-mutable.
// We don't mutate them, so silence it.
// https://rust-lang.github.io/rust-clippy/master/index.html#/declare_interior_mutable_const
#[allow(clippy::declare_interior_mutable_const)]
const CONTENT_TYPE_CBOR: HeaderValue = HeaderValue::from_static("application/cbor");
#[allow(clippy::declare_interior_mutable_const)]
const HEADER_IC_CACHE: HeaderName = HeaderName::from_static("x-ic-cache-status");

// Rust const/static concat is non-existent, so we have to repeat
pub const PATH_STATUS: &str = "/api/v2/status";
pub const PATH_QUERY: &str = "/api/v2/canister/:canister_id/query";
pub const PATH_CALL: &str = "/api/v2/canister/:canister_id/call";
pub const PATH_READ_STATE: &str = "/api/v2/canister/:canister_id/read_state";

// Type of IC request
#[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestType {
    #[default]
    Status,
    Query,
    Call,
    ReadState,
}

impl fmt::Display for RequestType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Status => write!(f, "status"),
            Self::Query => write!(f, "query"),
            Self::Call => write!(f, "call"),
            Self::ReadState => write!(f, "read_state"),
        }
    }
}

// Categorized possible causes for request processing failures
// Use String and not Error since it's not cloneable
#[derive(Debug, Clone)]
pub enum ErrorCause {
    UnableToReadBody,
    UnableToParseCBOR(String), // TODO just use MalformedRequest?
    MalformedRequest(String),
    MalformedResponse(String),
    NoRoutingTable,
    SubnetNotFound,
    NoHealthyNodes,
    ReplicaUnreachable(String),
    TooManyRequests,
    Other(String),
}

impl ErrorCause {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::UnableToReadBody => StatusCode::BAD_REQUEST,
            Self::UnableToParseCBOR(_) => StatusCode::BAD_REQUEST,
            Self::MalformedRequest(_) => StatusCode::BAD_REQUEST,
            Self::MalformedResponse(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NoRoutingTable => StatusCode::INTERNAL_SERVER_ERROR,
            Self::SubnetNotFound => StatusCode::BAD_REQUEST, // TODO change to 404?
            Self::NoHealthyNodes => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ReplicaUnreachable(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
        }
    }

    pub fn details(&self) -> Option<String> {
        match self {
            Self::Other(x) => Some(x.clone()),
            Self::UnableToParseCBOR(x) => Some(x.clone()),
            Self::MalformedRequest(x) => Some(x.clone()),
            Self::MalformedResponse(x) => Some(x.clone()),
            Self::ReplicaUnreachable(x) => Some(x.clone()),
            _ => None,
        }
    }
}

impl fmt::Display for ErrorCause {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Other(_) => write!(f, "general_error"),
            Self::UnableToReadBody => write!(f, "unable_to_read_body"),
            Self::UnableToParseCBOR(_) => write!(f, "unable_to_parse_cbor"),
            Self::MalformedRequest(_) => write!(f, "malformed_request"),
            Self::MalformedResponse(_) => write!(f, "malformed_response"),
            Self::NoRoutingTable => write!(f, "no_routing_table"),
            Self::SubnetNotFound => write!(f, "subnet_not_found"),
            Self::NoHealthyNodes => write!(f, "no_healthy_nodes"),
            Self::ReplicaUnreachable(_) => write!(f, "replica_unreachable"),
            Self::TooManyRequests => write!(f, "rate_limited"),
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

// Object that holds per-request information
#[derive(Default, Clone)]
pub struct RequestContext {
    pub request_type: RequestType,
    pub canister_id: Option<Principal>,
    pub node: Option<Node>,
    pub request_size: u32,

    // CBOR fields
    pub canister_id_cbor: Option<Principal>,
    pub sender: Option<Principal>,
    pub method_name: Option<String>,
    pub nonce: Option<Vec<u8>>,
    pub ingress_expiry: Option<u64>,
    pub arg: Option<Vec<u8>>,
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
        self.arg.hash(state);
    }
}

impl PartialEq for RequestContext {
    fn eq(&self, other: &Self) -> bool {
        self.canister_id == other.canister_id
            && self.sender == other.sender
            && self.method_name == other.method_name
            && self.ingress_expiry == other.ingress_expiry
            && self.arg == other.arg
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
    async fn proxy(
        &self,
        request_type: RequestType,
        request: Request<Body>,
        node: Node,
        canister_id: Principal,
    ) -> Result<Response, ErrorCause>;
}

#[async_trait]
pub trait Lookup: Sync + Send {
    async fn lookup(&self, id: &Principal) -> Result<Node, ErrorCause>;
}

#[async_trait]
pub trait Health: Sync + Send {
    async fn health(&self) -> ReplicaHealthStatus;
}

#[async_trait]
pub trait RootKey: Sync + Send {
    async fn root_key(&self) -> Vec<u8>;
}

// Router that helps handlers do their job by looking up in routing table
// and owning HTTP client for outgoing requests
#[derive(Clone)]
pub struct ProxyRouter {
    http_client: Arc<dyn HttpClient>,
    published_routes: Arc<ArcSwapOption<Routes>>,
    root_key: Vec<u8>,
}

impl ProxyRouter {
    pub fn new(
        http_client: Arc<dyn HttpClient>,
        published_routes: Arc<ArcSwapOption<Routes>>,
        root_key: Vec<u8>,
    ) -> Self {
        Self {
            http_client,
            published_routes,
            root_key,
        }
    }
}

#[async_trait]
impl Proxy for ProxyRouter {
    async fn proxy(
        &self,
        request_type: RequestType,
        request: Request<Body>,
        node: Node,
        canister_id: Principal,
    ) -> Result<Response, ErrorCause> {
        // Prepare the request
        let (parts, body) = request.into_parts();

        // Create request
        let u = Url::from_str(&format!(
            "https://{}:{}/api/v2/canister/{canister_id}/{request_type}",
            node.id, node.port,
        ))
        .map_err(|e| ErrorCause::Other(format!("failed to build request url: {e}")))?;

        let mut request = reqwest::Request::new(Method::POST, u);
        *request.headers_mut() = parts.headers;
        *request.body_mut() = Some(body.into());

        // Execute request
        let response = self
            .http_client
            .execute(request)
            .await
            .map_err(|e| ErrorCause::ReplicaUnreachable(format!("HTTP call failed: {e}")))?;

        // Convert Reqwest response into Axum one with body streaming
        let status = response.status();
        let headers = response.headers().clone();

        let mut response = StreamBody::new(response.bytes_stream()).into_response();
        *response.status_mut() = status;
        *response.headers_mut() = headers;

        Ok(response)
    }
}

#[async_trait]
impl Lookup for ProxyRouter {
    async fn lookup(&self, id: &Principal) -> Result<Node, ErrorCause> {
        let subnet = self
            .published_routes
            .load_full()
            .ok_or(ErrorCause::NoRoutingTable)? // No routing table present
            .lookup(id.to_owned())
            .ok_or(ErrorCause::SubnetNotFound)?; // Requested canister route wasn't found

        // Pick random node
        let node = subnet
            .nodes
            .choose(&mut rand::thread_rng())
            .ok_or(ErrorCause::NoHealthyNodes)? // No healhy nodes in subnet
            .clone();

        Ok(node)
    }
}

#[async_trait]
impl RootKey for ProxyRouter {
    async fn root_key(&self) -> Vec<u8> {
        self.root_key.clone()
    }
}

#[async_trait]
impl Health for ProxyRouter {
    async fn health(&self) -> ReplicaHealthStatus {
        // Return healthy state if we have at least one healthy replica node
        // TODO increase threshold? change logic?
        let rt = self.published_routes.load_full();

        match rt {
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

#[cfg(feature = "tls")]
pub async fn acme_challenge(
    Extension(token): Extension<Arc<RwLock<Option<String>>>>,
) -> impl IntoResponse {
    token.read().await.clone().unwrap_or_default()
}

#[cfg(feature = "tls")]
pub async fn redirect_to_https(
    Host(host): Host,
    OriginalUri(uri): OriginalUri,
) -> impl IntoResponse {
    let fallback_path = PathAndQuery::from_static("/");
    let pq = uri.path_and_query().unwrap_or(&fallback_path).as_str();

    Redirect::permanent(
        &Uri::builder()
            .scheme("https") // redirect to https
            .authority(host) // re-use the same host
            .path_and_query(pq) // re-use the same path and query
            .build()
            .unwrap()
            .to_string(),
    )
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
            GovernorError::TooManyRequests { .. } => ApiError::from(ErrorCause::TooManyRequests),
            GovernorError::UnableToExtractKey => {
                ApiError::Unspecified(anyhow!("unable to extract rate-limiting key"))
            }
            GovernorError::Other { .. } => ApiError::Unspecified(anyhow!("GovernorError")),
        }
    }
}

// Preprocess the request before handing it over to handlers
pub async fn preprocess_request(
    State(lk): State<Arc<dyn Lookup>>,
    canister_id: Result<Path<String>, PathRejection>,
    matched_path: MatchedPath,
    request: Request<Body>,
    next: Next<Body>,
) -> Result<impl IntoResponse, ApiError> {
    // Derive request type
    let request_type = match matched_path.as_str() {
        PATH_QUERY => RequestType::Query,
        PATH_CALL => RequestType::Call,
        PATH_READ_STATE => RequestType::ReadState,
        PATH_STATUS => RequestType::Status,
        _ => panic!("unknown path, should never happen"),
    };

    // No preprocessing needed if it's a status request
    if request_type == RequestType::Status {
        return Ok(next.run(request).await);
    }

    // This is always Ok for non-status calls
    let canister_id = canister_id.unwrap().0;

    // Decode canister_id from URL
    let canister_id = Principal::from_text(canister_id).map_err(|err| {
        ErrorCause::MalformedRequest(format!("Unable to decode canister_id from URL: {err}"))
    })?;

    // Consume body
    let (parts, body) = request.into_parts();
    let body = hyper::body::to_bytes(body)
        .await
        .map_err(|_| ErrorCause::UnableToReadBody)?
        .to_vec();

    // Parse the request body
    let envelope: ICRequestEnvelope = serde_cbor::from_slice(&body)
        .map_err(|err| ErrorCause::UnableToParseCBOR(err.to_string()))?;
    let content = envelope.content;

    // Try to look up a target node using canister id
    let node = Some(lk.lookup(&canister_id).await?);

    // Construct the context
    let ctx = RequestContext {
        request_type,
        node,
        request_size: body.len() as u32,
        canister_id: Some(canister_id),
        sender: Some(content.sender),
        canister_id_cbor: content.canister_id,
        method_name: content.method_name,
        ingress_expiry: content.ingress_expiry,
        arg: content.arg.map(|x| x.0),
        nonce: content.nonce.map(|x| x.0),
    };

    // Reconstruct request back from parts
    let mut request = Request::from_parts(parts, hyper::Body::from(body));

    // Inject context into request
    request.extensions_mut().insert(ctx.clone());

    // Pass request to the next processor
    let mut response = next.run(request).await;

    // Inject context into the response for access by other middleware
    response.extensions_mut().insert(ctx);

    Ok(response)
}

pub async fn postprocess_response(request: Request<Body>, next: Next<Body>) -> impl IntoResponse {
    let mut response = next.run(request).await;

    // Set the correct content-type for all replies if it's not an error
    let error_cause = response.extensions().get::<ErrorCause>();
    if error_cause.is_none() {
        response
            .headers_mut()
            .insert(CONTENT_TYPE, CONTENT_TYPE_CBOR);
    }

    // Add cache status if there's one
    let cache_status = response.extensions().get::<CacheStatus>().cloned();
    if let Some(v) = cache_status {
        response.headers_mut().insert(
            HEADER_IC_CACHE,
            HeaderValue::from_str(v.to_string().as_str()).unwrap(),
        );
    }

    response
}

// Handles IC status call
pub async fn status(
    State((rk, h)): State<(Arc<dyn RootKey>, Arc<dyn Health>)>,
) -> Result<impl IntoResponse, ApiError> {
    let response = HttpStatusResponse {
        ic_api_version: IC_API_VERSION.to_string(),
        root_key: Some(rk.root_key().await.into()),
        impl_version: None,
        impl_hash: None,
        replica_health_status: Some(h.health().await),
        certified_height: None,
    };

    let mut ser = serde_cbor::Serializer::new(Vec::new());
    ser.self_describe()
        .map_err(|_| ApiError::Unspecified(anyhow!("unable to add self-describe tag")))?;

    response
        .serialize(&mut ser)
        .map_err(|_| ApiError::Unspecified(anyhow!("unable to serialize response to cbor")))?;

    let cbor = ser.into_inner();

    Ok(cbor.into_response())
}

// Unified handler for query/call/read_state calls
pub async fn handle_call(
    State(p): State<Arc<dyn Proxy>>,
    Extension(ctx): Extension<RequestContext>,
    request: Request<Body>,
) -> Result<impl IntoResponse, ApiError> {
    // Proxy the request
    // node and canister_id will be Some() if we got here, otherwise preprocess_request() would refuse request earlier
    let resp = p
        .proxy(
            ctx.request_type,
            request,
            ctx.node.clone().unwrap(),
            ctx.canister_id.unwrap(),
        )
        .await?;

    Ok(resp)
}

#[cfg(test)]
pub mod test;
