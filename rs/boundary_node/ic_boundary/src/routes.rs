use anyhow::{anyhow, Error};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use axum::{
    body::{Body, StreamBody},
    extract::{Path, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    BoxError, Extension,
};
use candid::Principal;
use http::{header, request::Parts, Method};
use ic_types::messages::{HttpStatusResponse, ReplicaHealthStatus};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr, sync::Arc};
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

use crate::{http::HttpClient, persist::Routes, snapshot::Node};

const ANONYMOUS_PRINCIPAL: Principal = Principal::anonymous();

// Type of IC request
#[derive(Default, Clone, Copy, PartialEq)]
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
#[derive(Debug, Default, Clone)]
pub enum ErrorCause {
    #[default]
    NoError,
    UnableToReadBody,
    UnableToParseCBOR(String), // TODO just use MalformedRequest?
    MalformedRequest(String),
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
            Self::NoError => StatusCode::OK,
            Self::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::UnableToReadBody => StatusCode::BAD_REQUEST,
            Self::UnableToParseCBOR(_) => StatusCode::BAD_REQUEST,
            Self::MalformedRequest(_) => StatusCode::BAD_REQUEST,
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
            Self::ReplicaUnreachable(x) => Some(x.clone()),
            Self::TooManyRequests => Some(String::from("rate_limited")),
            _ => None,
        }
    }
}

impl fmt::Display for ErrorCause {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::NoError => write!(f, "no_error"),
            Self::Other(_) => write!(f, "general_error"),
            Self::UnableToReadBody => write!(f, "unable_to_read_body"),
            Self::UnableToParseCBOR(_) => write!(f, "unable_to_parse_cbor"),
            Self::MalformedRequest(_) => write!(f, "malformed_request"),
            Self::NoRoutingTable => write!(f, "no_routing_table"),
            Self::SubnetNotFound => write!(f, "subnet_not_found"),
            Self::NoHealthyNodes => write!(f, "no_healthy_nodes"),
            Self::ReplicaUnreachable(_) => write!(f, "replica_unreachable"),
            Self::TooManyRequests => write!(f, "rate_limited"),
        }
    }
}

// Object that holds per-request information
#[derive(Default, Clone)]
pub struct RequestContext {
    pub canister_id: Option<Principal>,
    pub canister_id_cbor: Option<Principal>,
    pub node: Option<Node>,
    pub sender: Option<Principal>,
    pub method_name: Option<String>,
    pub request_type: RequestType,
    pub error_cause: ErrorCause,
    pub request_size: u32,
}

impl RequestContext {
    pub fn is_anonymous(&self) -> Option<bool> {
        self.sender.map(|x| x == ANONYMOUS_PRINCIPAL)
    }
}

// This is the subset of the request fields
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ICRequestContent {
    sender: Principal,
    canister_id: Option<Principal>,
    method_name: Option<String>,
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

// Consumes request and returns it as byte slice
pub async fn read_body(request: Request<Body>) -> Result<(Parts, Vec<u8>), ErrorCause> {
    let (parts, body) = request.into_parts();
    let body = hyper::body::to_bytes(body)
        .await
        .map_err(|_| ErrorCause::UnableToReadBody)?
        .to_vec();

    Ok((parts, body))
}

// Parses body as a generic CBOR request and enriches the context
pub fn parse_body(ctx: &mut RequestContext, body: &[u8]) -> Result<(), Error> {
    let envelope: ICRequestEnvelope = serde_cbor::from_slice(body)?;
    let content = envelope.content;

    ctx.sender = Some(content.sender);
    ctx.canister_id_cbor = content.canister_id;
    ctx.method_name = content.method_name;

    Ok(())
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
        (match self {
            ApiError::_Custom(c, b) => (c, b),
            ApiError::ProxyError(c) => (c.status_code(), c.to_string()),
            ApiError::Unspecified(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
        })
        .into_response()
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

pub async fn postprocess_response(request: Request<Body>, next: Next<Body>) -> impl IntoResponse {
    let mut resp = next.run(request).await;

    // Set the correct content-type for all replies
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/cbor"),
    );

    resp
}

// Preprocess the request before handing it over to handlers
pub async fn preprocess_request(
    State(lk): State<Arc<dyn Lookup>>,
    Path(canister_id): Path<String>,
    request: Request<Body>,
    next: Next<Body>,
) -> Result<impl IntoResponse, ApiError> {
    let mut ctx = RequestContext::default();

    // Consume body
    let (parts, body) = read_body(request).await?;
    ctx.request_size = body.len() as u32;

    // Get canister_id from URL
    let canister_id = Principal::from_text(canister_id).map_err(|err| {
        ErrorCause::MalformedRequest(format!("Unable to decode canister_id from URL: {err}"))
    })?;

    ctx.canister_id = Some(canister_id);

    parse_body(&mut ctx, &body).map_err(|err| ErrorCause::UnableToParseCBOR(err.to_string()))?;

    // Try to look up a target node using canister id
    ctx.node = Some(lk.lookup(&canister_id).await?);

    // Reconstruct request back from parts
    let mut request = Request::from_parts(parts, hyper::Body::from(body));
    request.extensions_mut().insert(ctx);

    // Pass request to the next processor
    let resp = next.run(request).await;

    Ok(resp)
}

// Handles IC status call
pub async fn status(
    State((rk, h)): State<(Arc<dyn RootKey>, Arc<dyn Health>)>,
) -> Result<impl IntoResponse, ApiError> {
    let response = HttpStatusResponse {
        // TODO which one to use?
        ic_api_version: "0.18.0".to_string(),
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

// Handler for query calls
pub async fn query(
    State(p): State<Arc<dyn Proxy>>,
    Extension(mut ctx): Extension<RequestContext>,
    request: Request<Body>,
) -> Result<impl IntoResponse, ApiError> {
    // These will be Some() if we got here, otherwise middleware would refuse request earlier
    ctx.request_type = RequestType::Query;
    let canister_id = ctx.canister_id.unwrap();
    let node = ctx.node.clone().unwrap();

    // Proxy the request
    let mut resp = p
        .proxy(RequestType::Query, request, node, canister_id)
        .await?;

    // Inject context into response
    resp.extensions_mut().insert(ctx);

    Ok(resp)
}

// Handler for update calls
pub async fn call(
    State(p): State<Arc<dyn Proxy>>,
    Extension(mut ctx): Extension<RequestContext>,
    request: Request<Body>,
) -> Result<impl IntoResponse, ApiError> {
    ctx.request_type = RequestType::Call;
    // These will be Some() if we got here, otherwise middleware would refuse request earlier
    let canister_id = ctx.canister_id.unwrap();
    let node = ctx.node.clone().unwrap();

    // Proxy the request
    let mut resp = p
        .proxy(RequestType::Call, request, node, canister_id)
        .await?;

    // Inject context into response
    resp.extensions_mut().insert(ctx);

    Ok(resp)
}

// Handler for read_state
pub async fn read_state(
    State(p): State<Arc<dyn Proxy>>,
    Extension(mut ctx): Extension<RequestContext>,
    request: Request<Body>,
) -> Result<impl IntoResponse, ApiError> {
    ctx.request_type = RequestType::ReadState;
    // These will be Some() if we got here, otherwise middleware would refuse request earlier
    let canister_id = ctx.canister_id.unwrap();
    let node = ctx.node.clone().unwrap();

    // Proxy the request
    let mut resp = p
        .proxy(RequestType::ReadState, request, node, canister_id)
        .await?;

    // Inject context into response
    resp.extensions_mut().insert(ctx);

    Ok(resp)
}

#[cfg(test)]
pub mod test;
