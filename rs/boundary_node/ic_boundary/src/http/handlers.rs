use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    response::IntoResponse,
    Extension,
};

use http::header::{CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS};
use ic_bn_lib::http::headers::{
    CONTENT_TYPE_CBOR, X_CONTENT_TYPE_OPTIONS_NO_SNIFF, X_FRAME_OPTIONS_DENY,
};
use ic_types::{
    messages::{HttpStatusResponse, ReplicaHealthStatus},
    CanisterId, SubnetId,
};
use serde::Serialize;

use crate::{
    errors::{ApiError, ErrorCause},
    routes::RequestContext,
    snapshot::Node,
};

pub use crate::routes::{Health, Proxy, RootKey};

// Handler: emit an HTTP status code that signals the service's state
pub async fn health(State(h): State<Arc<dyn Health>>) -> impl IntoResponse {
    if h.health() == ReplicaHealthStatus::Healthy {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

// Handler: processes IC status call
pub async fn status(
    State((rk, h)): State<(Arc<dyn RootKey>, Arc<dyn Health>)>,
) -> impl IntoResponse {
    let health = h.health();

    let status = HttpStatusResponse {
        root_key: rk.root_key().map(|x| x.into()),
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
