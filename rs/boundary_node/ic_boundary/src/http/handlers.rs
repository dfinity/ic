#[cfg(test)]
use std::net::SocketAddr;
use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
};

#[cfg(test)]
use axum::extract::ConnectInfo;
use axum::{
    Extension,
    body::Body,
    extract::{
        Path, Request, State,
        ws::{CloseFrame, Message, Utf8Bytes, WebSocket, WebSocketUpgrade},
    },
    http::StatusCode,
    response::IntoResponse,
};
use bytes::Bytes;
use candid::Principal;
use http::header::{CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS};
use ic_bn_lib::{
    http::headers::{CONTENT_TYPE_CBOR, X_CONTENT_TYPE_OPTIONS_NO_SNIFF, X_FRAME_OPTIONS_DENY},
    pubsub::{Broker, Subscriber},
};
use ic_types::{
    CanisterId, SubnetId,
    messages::{HttpStatusResponse, ReplicaHealthStatus},
};
use moka::sync::{Cache, CacheBuilder};
use serde::Serialize;
use tokio::{select, sync::broadcast::error::RecvError};

use crate::{
    errors::{ApiError, ErrorCause},
    routes::{Lookup, RequestContext},
    snapshot::Node,
};

pub use crate::routes::{Health, Proxy, RootKey};

#[derive(Clone)]
pub struct LogsState {
    broker: Arc<Broker<Bytes, Principal>>,
    route_lookup: Arc<dyn Lookup>,
    ip_cache: Cache<(IpAddr, Principal), Arc<Mutex<u16>>>,
    max_subscribers_per_ip_per_topic: u16,
}

impl LogsState {
    pub fn new(
        broker: Arc<Broker<Bytes, Principal>>,
        route_lookup: Arc<dyn Lookup>,
        max_subscribers_per_ip_per_topic: u16,
    ) -> Self {
        // Some sensible defaults for now.
        // Cache key+value should consume around 60-70 bytes, so we can spare a ~100MB for the cache I guess.
        let ip_cache = CacheBuilder::new(2_000_000).build();

        Self {
            broker,
            route_lookup,
            ip_cache,
            max_subscribers_per_ip_per_topic,
        }
    }
}

/// Handles websocket requests for canister logs
pub async fn logs_canister(
    ws: WebSocketUpgrade,
    #[cfg(not(test))] Extension(conn_info): Extension<Arc<ic_bn_lib_common::types::http::ConnInfo>>,
    #[cfg(test)] ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(canister_id): Path<CanisterId>,
    State(state): State<Arc<LogsState>>,
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

    #[cfg(not(test))]
    let ip = conn_info.remote_addr.ip();
    #[cfg(test)]
    let ip = addr.ip();
    let canister_id = canister_id.get().0;

    // Get or create a counter
    let counter = state
        .ip_cache
        .get_with((ip, canister_id), || Arc::new(Mutex::new(0)));

    // Make mutex scope narrower
    let sub = {
        // Check if we're over the limit
        let mut counter = counter.lock().unwrap();
        if *counter >= state.max_subscribers_per_ip_per_topic {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "Too many subscribers from your IP address to this Canister",
            )
                .into_response();
        }

        // Try to subscribe to a given topic
        let Ok(sub) = state.broker.subscribe(&canister_id) else {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "Too many subscribers to this Canister",
            )
                .into_response();
        };

        // Increment the counter
        *counter += 1;
        sub
    };

    // Upgrade to websocket & fire up the processing loop
    ws.on_upgrade(move |socket| logs_canister_ws(socket, sub, state, counter, ip, canister_id))
        .into_response()
}

/// Handles websocket requests for canister logs: inner part
async fn logs_canister_ws(
    mut socket: WebSocket,
    mut sub: Subscriber<Bytes>,
    state: Arc<LogsState>,
    counter: Arc<Mutex<u16>>,
    ip: IpAddr,
    canister_id: Principal,
) {
    loop {
        select! {
            biased;

            // Discard whatever client might send us and check for disconnects
            res = socket.recv() => {
                match res {
                    None => break,
                    Some(Err(_)) => break,
                    _ => {},
                }
            }

            // Read log messages from the topic
            msg = sub.recv() => {
                match msg {
                    Ok(v) => {
                        // Send the message to the client
                        if socket.send(Message::Binary(v)).await.is_err() {
                            break;
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

                        break;
                    },
                }
            }
        }
    }

    // When the connection is done - decrement the counter and remove it if it has reached zero
    let mut counter = counter.lock().unwrap();
    *counter -= 1;
    if *counter == 0 {
        state.ip_cache.invalidate(&(ip, canister_id));
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

#[cfg(test)]
mod test {
    use axum::{Router, routing::any};
    use futures_util::StreamExt;
    use ic_bn_lib::pubsub::BrokerBuilder;
    use ic_bn_lib_common::principal;
    use tokio_tungstenite::tungstenite;

    use super::*;
    use crate::persist::test::generate_test_subnets;
    use crate::snapshot::Subnet;
    use std::future::IntoFuture;
    use std::net::{Ipv4Addr, SocketAddr};

    struct TestRouteLookup;

    impl Lookup for TestRouteLookup {
        fn lookup_subnet_by_canister_id(
            &self,
            _id: &CanisterId,
        ) -> Result<Arc<Subnet>, ErrorCause> {
            Ok(Arc::new(generate_test_subnets(0)[0].clone()))
        }

        fn lookup_subnet_by_id(&self, _id: &SubnetId) -> Result<Arc<Subnet>, ErrorCause> {
            Err(ErrorCause::NoRoutingTable)
        }
    }

    #[tokio::test]
    async fn test_websockets() {
        // Listen on random port
        let listener = tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let broker = Arc::new(BrokerBuilder::new().with_max_subscribers(5).build());
        let state = LogsState::new(broker.clone(), Arc::new(TestRouteLookup), 3);
        let router = Router::new()
            .route("/logs/canister/{canister_id}", any(logs_canister))
            .with_state(Arc::new(state));

        // Run Axum router
        tokio::spawn(
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .into_future(),
        );

        // Check basic functionality

        // Create 3 subscribers for the same canister over Websocket
        let (mut socket1, _) =
            tokio_tungstenite::connect_async(format!("ws://{addr}/logs/canister/aaaaa-aa"))
                .await
                .unwrap();

        let (mut socket2, _) =
            tokio_tungstenite::connect_async(format!("ws://{addr}/logs/canister/aaaaa-aa"))
                .await
                .unwrap();

        let (socket3, _) =
            tokio_tungstenite::connect_async(format!("ws://{addr}/logs/canister/aaaaa-aa"))
                .await
                .unwrap();

        // Make sure 4th subscriber is rejected
        assert!(
            tokio_tungstenite::connect_async(format!("ws://{addr}/logs/canister/aaaaa-aa"))
                .await
                .is_err()
        );

        // Make sure we can subscribe again if we disconnect one of the subscribers
        drop(socket3);

        let (mut socket3, _) =
            tokio_tungstenite::connect_async(format!("ws://{addr}/logs/canister/aaaaa-aa"))
                .await
                .unwrap();

        // But we can subscribe to another canister
        let (mut socket4, _) =
            tokio_tungstenite::connect_async(format!("ws://{addr}/logs/canister/f7crg-kabae"))
                .await
                .unwrap();

        // Send message over broker to 1st canister
        broker
            .publish(&principal!("aaaaa-aa"), "foobar".into())
            .unwrap();

        // Make sure message reaches all subscirbers
        let msg = match socket1.next().await.unwrap().unwrap() {
            tungstenite::Message::Binary(msg) => msg,
            _ => panic!("unexpected type"),
        };
        assert_eq!(msg, Bytes::from("foobar"));

        let msg = match socket2.next().await.unwrap().unwrap() {
            tungstenite::Message::Binary(msg) => msg,
            _ => panic!("unexpected type"),
        };
        assert_eq!(msg, Bytes::from("foobar"));

        let msg = match socket3.next().await.unwrap().unwrap() {
            tungstenite::Message::Binary(msg) => msg,
            _ => panic!("unexpected type"),
        };
        assert_eq!(msg, Bytes::from("foobar"));

        // Send message over broker to 2nd canister
        broker
            .publish(&principal!("f7crg-kabae"), "deadbeef".into())
            .unwrap();

        // Make sure we get it
        let msg = match socket4.next().await.unwrap().unwrap() {
            tungstenite::Message::Binary(msg) => msg,
            _ => panic!("unexpected type"),
        };
        assert_eq!(msg, Bytes::from("deadbeef"));
    }
}
