use std::{fmt, io::Read, sync::Arc};

use anyhow::{anyhow, Context, Error};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use axum::{
    body::{Body, Bytes, StreamBody},
    extract::{Host, MatchedPath, OriginalUri, RawBody, State},
    http::{uri::PathAndQuery, Request, StatusCode, Uri},
    middleware::{self, Next},
    response::{IntoResponse, IntoResponseParts, Redirect, Response, ResponseParts},
    Extension,
};
use bytes::Buf;
use candid::Principal;
use futures_util::{StreamExt, TryFutureExt};
use http::request::Parts;
use ic_types::{
    messages::{
        HttpQueryContent, HttpRequestEnvelope, HttpStatusResponse, HttpUserQuery,
        ReplicaHealthStatus,
    },
    CanisterId,
};
use rand::seq::SliceRandom;
use reqwest::Response as ReqwestResponse;
use tokio::sync::RwLock;
use tower_http::request_id::{MakeRequestId, RequestId};
use tracing::{error, info};

use crate::{persist::Routes, snapshot::Node};

#[derive(Default, Clone)]
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

#[derive(Default, Clone, Copy)]
pub enum ErrorCause {
    #[default]
    NoError,
    UnableToReadBody,
    UnableToParseCBOR,
    NoRoutingTable,
    SubnetNotFound,
    NoHealthyNodes,
    ReplicaUnreachable,
}

impl ErrorCause {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::NoError => StatusCode::OK,
            Self::UnableToReadBody => StatusCode::BAD_REQUEST,
            Self::UnableToParseCBOR => StatusCode::BAD_REQUEST,
            Self::NoRoutingTable => StatusCode::INTERNAL_SERVER_ERROR,
            Self::SubnetNotFound => StatusCode::BAD_REQUEST,
            Self::NoHealthyNodes => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ReplicaUnreachable => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl fmt::Display for ErrorCause {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::NoError => write!(f, "no_error"),
            Self::UnableToReadBody => write!(f, "unable_to_read_body"),
            Self::UnableToParseCBOR => write!(f, "unable_to_parse_cbor"),
            Self::NoRoutingTable => write!(f, "no_routing_table"),
            Self::SubnetNotFound => write!(f, "subnet_not_found"),
            Self::NoHealthyNodes => write!(f, "no_healthy_nodes"),
            Self::ReplicaUnreachable => write!(f, "replica_unreachable"),
        }
    }
}

#[derive(Default, Clone)]
pub struct RequestContext {
    canister_id: Option<Principal>,
    sender: Option<Principal>,
    method_name: Option<String>,
    request_type: RequestType,
    error_cause: ErrorCause,
    status_replica: Option<u16>,
}

impl RequestContext {
    fn respond(&mut self, cause: ErrorCause) -> Response {
        self.error_cause = cause;
        (Extension(self.clone()), cause.status_code()).into_response()
    }
}

#[async_trait]
pub trait Proxier {
    async fn proxy(
        &self,
        node: Node,
        canister_id: Principal,
        parts: Parts,
        body: Vec<u8>,
    ) -> Result<ReqwestResponse, Error>;

    fn lookup_node(&self, canister_id: Principal) -> Result<Node, ErrorCause>;

    fn health(&self) -> ReplicaHealthStatus;
}

pub struct ProxyRouter {
    http_client: Arc<reqwest::Client>,
    published_routes: Arc<ArcSwapOption<Routes>>,
}

// Holds the stuff that's shared between handlers and implements some methods
impl ProxyRouter {
    pub fn new(
        http_client: Arc<reqwest::Client>,
        published_routes: Arc<ArcSwapOption<Routes>>,
    ) -> Self {
        Self {
            http_client,
            published_routes,
        }
    }
}

#[async_trait]
impl Proxier for ProxyRouter {
    async fn proxy(
        &self,
        node: Node,
        canister_id: Principal,
        parts: Parts,
        body: Vec<u8>,
    ) -> Result<ReqwestResponse, Error> {
        // Prepare the request
        let url = format!(
            "https://{}:{}/api/v2/canister/{}/query",
            node.id, node.port, canister_id
        );

        let request = self
            .http_client
            .post(url)
            .headers(parts.headers)
            .body(body)
            .build()
            .unwrap(); // TODO can this even fail?

        // Send the request
        self.http_client
            .execute(request)
            .await
            .map_err(|e| anyhow!("HTTP request failed: {e}"))
    }

    fn lookup_node(&self, canister_id: Principal) -> Result<Node, ErrorCause> {
        let subnet = self
            .published_routes
            .load_full()
            .ok_or(ErrorCause::NoHealthyNodes)? // No routing table present
            .lookup(canister_id)
            .ok_or(ErrorCause::SubnetNotFound)?; // Requested canister route wasn't found. TODO change to 404?

        // Pick random node
        let node = subnet
            .nodes
            .choose(&mut rand::thread_rng())
            .ok_or(ErrorCause::NoHealthyNodes)? // No healhy nodes in subnet
            .clone();

        Ok(node)
    }

    fn health(&self) -> ReplicaHealthStatus {
        // Return healthy state if we have at least one healthy replica node
        // TOOD increase threshold? change logic?
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

pub async fn log_request(req: Request<Body>, next: Next<Body>) -> Result<Response, StatusCode> {
    let resp = next.run(req).await;

    let ctx = resp
        .extensions()
        .get::<RequestContext>()
        .cloned()
        .unwrap_or_default();

    let request_id = resp
        .extensions()
        .get::<RequestId>()
        .unwrap()
        .header_value()
        .to_str()
        .unwrap();

    info!(
        request_id,
        request_type = format!("{}", ctx.request_type),
        error_cause = format!("{}", ctx.error_cause),
        status_replica = ctx.status_replica.unwrap_or_default(),
        canister_id = ctx.canister_id.map(|x| x.to_string()),
        sender = ctx.sender.map(|x| x.to_string()),
        method_name = ctx.method_name,
    );

    Ok(resp)
}

pub async fn read_body(request: Request<Body>) -> Result<(Parts, Vec<u8>), ErrorCause> {
    let (parts, body) = request.into_parts();
    let body = hyper::body::to_bytes(body)
        .await
        .map_err(|_| ErrorCause::UnableToReadBody)?
        .to_vec();

    Ok((parts, body))
}

pub async fn status(State(state): State<Arc<impl Proxier>>) -> Response {
    let response = HttpStatusResponse {
        // TODO which one to use?
        ic_api_version: "0.18.0".to_string(),
        root_key: None,
        impl_version: None,
        impl_hash: None,
        replica_health_status: Some(state.health()),
        certified_height: None,
    };

    // This shouldn't fail
    serde_cbor::to_vec(&response).unwrap().into_response()
}

// Implement query call
pub async fn query(
    State(state): State<Arc<impl Proxier>>,
    request: Request<Body>,
) -> Result<Response, Response> {
    // Init the request context
    let mut ctx = RequestContext::default();

    // Buffer the entire request body
    let (parts, body) = read_body(request).await.map_err(|e| ctx.respond(e))?;

    // Parse body as a CBOR
    let query: HttpRequestEnvelope<HttpQueryContent> =
        serde_cbor::from_slice(&body).map_err(|_| ctx.respond(ErrorCause::UnableToParseCBOR))?;

    // TODO signature verification here?

    let HttpQueryContent::Query { query } = query.content;

    // Decode principals from BLOBs
    let canister_id = Principal::from_slice(&query.canister_id.0);
    let sender = Principal::from_slice(&query.sender.0);

    // Enrich request context
    ctx.request_type = RequestType::Query;
    ctx.canister_id = Some(canister_id);
    ctx.sender = Some(sender);
    ctx.method_name = Some(query.method_name.clone());

    // Try to look up a target node using canister id
    let node = state.lookup_node(canister_id).map_err(|e| ctx.respond(e))?;

    // Proxy the request
    let resp = state
        .proxy(node, canister_id, parts, body)
        .await
        .map_err(|_| ctx.respond(ErrorCause::ReplicaUnreachable))?;

    // Prepare the response and send it back to client using body streaming
    let status = resp.status();
    let headers = resp.headers().clone();
    ctx.status_replica = Some(status.as_u16());

    let mut response = StreamBody::new(resp.bytes_stream()).into_response();
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response.extensions_mut().insert(ctx);

    Ok(response)
}

pub async fn call(State(st): State<Arc<impl Proxier>>) -> impl IntoResponse {
    "Hello, World!"
}

pub async fn read_state(State(st): State<Arc<impl Proxier>>) -> impl IntoResponse {
    "Hello, World!"
}

#[cfg(test)]
pub mod test;
