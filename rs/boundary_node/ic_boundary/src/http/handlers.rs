use std::sync::Arc;

use axum::{
    body::Body,
    extract::{
        ws::{CloseFrame, Message, Utf8Bytes, WebSocket, WebSocketUpgrade},
        Path, Request, State,
    },
    http::StatusCode,
    response::IntoResponse,
    Extension,
};
use bytes::Bytes;
use candid::Principal;
use http::header::{CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS};
use ic_bn_lib::{
    http::headers::{CONTENT_TYPE_CBOR, X_CONTENT_TYPE_OPTIONS_NO_SNIFF, X_FRAME_OPTIONS_DENY},
    pubsub::{Broker, Subscriber},
};
use ic_types::{
    messages::{HttpStatusResponse, ReplicaHealthStatus},
    CanisterId, SubnetId,
};
use serde::Serialize;
use tokio::{select, sync::broadcast::error::RecvError};

use crate::{
    errors::{ApiError, ErrorCause},
    routes::{Lookup, RequestContext},
    snapshot::Node,
};

pub use crate::routes::{Health, Proxy, RootKey};

#[derive(Clone, derive_new::new)]
pub struct LogsState {
    broker: Arc<Broker<Bytes, Principal>>,
    route_lookup: Arc<dyn Lookup>,
}

pub async fn logs_canister(
    ws: WebSocketUpgrade,
    Path(canister_id): Path<CanisterId>,
    State(state): State<LogsState>,
) -> impl IntoResponse {
    if state
        .route_lookup
        .lookup_subnet_by_canister_id(&canister_id)
        .is_err()
    {
        return (
            StatusCode::NOT_FOUND,
            "The provided canister ID wasn't found in the routing table",
        )
            .into_response();
    }

    // Try to subscribe to a given topic
    let Ok(sub) = state.broker.subscribe(&canister_id.get().0) else {
        return (StatusCode::TOO_MANY_REQUESTS, "Too many subscribers").into_response();
    };

    ws.on_upgrade(move |socket| logs_canister_ws(socket, sub))
        .into_response()
}

async fn logs_canister_ws(mut socket: WebSocket, mut sub: Subscriber<Bytes>) {
    loop {
        select! {
            biased;

            // Discard whatever client might send us and check for disconnects
            res = socket.recv() => {
                match res {
                    None => return,
                    Some(Err(_)) => return,
                    _ => {},
                }
            }

            // Read log messages from the topic
            msg = sub.recv() => {
                match msg {
                    Ok(v) => {
                        // Send the message to the client
                        if socket.send(Message::Binary(v)).await.is_err() {
                            return;
                        }
                    },

                    Err(RecvError::Lagged(_)) => {
                        // Just ignore if the client is lagging
                    },

                    Err(RecvError::Closed) => {
                        let _ = socket
                            .send(Message::Close(Some(CloseFrame {
                                code: 410,
                                reason: Utf8Bytes::from_static("Closed due to inactivity"),
                            })))
                            .await;

                        return
                    },
                }
            }
        }
    }
}

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
