use std::{
    hash::{Hash, Hasher},
    sync::Arc,
};

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Extension,
};
use candid::{CandidType, Principal};
use http::header::{CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS};
use ic_bn_lib::http::{headers::*, proxy, Client as HttpClient};
pub use ic_bn_lib::types::RequestType;
use ic_types::{
    messages::{HttpStatusResponse, ReplicaHealthStatus},
    CanisterId, SubnetId,
};
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    errors::{ApiError, ErrorCause},
    http::error_infer,
    persist::{RouteSubnet, Routes},
    snapshot::{Node, RegistrySnapshot},
};

pub const ANONYMOUS_PRINCIPAL: Principal = Principal::anonymous();

// Rust const/static concat is non-existent, so we have to repeat
pub const PATH_STATUS: &str = "/api/v2/status";
pub const PATH_QUERY: &str = "/api/v2/canister/{canister_id}/query";
pub const PATH_CALL: &str = "/api/v2/canister/{canister_id}/call";
pub const PATH_CALL_V3: &str = "/api/v3/canister/{canister_id}/call";
pub const PATH_READ_STATE: &str = "/api/v2/canister/{canister_id}/read_state";
pub const PATH_SUBNET_READ_STATE: &str = "/api/v2/subnet/{subnet_id}/read_state";
pub const PATH_HEALTH: &str = "/health";

lazy_static! {
    pub static ref UUID_REGEX: Regex =
        Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").unwrap();
}

#[derive(Debug, Clone, PartialEq, Hash, CandidType, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
}

// Object that holds per-request information
#[derive(Debug, Clone, Default)]
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

#[async_trait]
pub trait Proxy: Sync + Send {
    async fn proxy(&self, request: Request<Body>, url: Url) -> Result<Response, ErrorCause>;
}

pub trait Lookup: Sync + Send {
    fn lookup_subnet_by_canister_id(&self, id: &CanisterId)
        -> Result<Arc<RouteSubnet>, ErrorCause>;
    fn lookup_subnet_by_id(&self, id: &SubnetId) -> Result<Arc<RouteSubnet>, ErrorCause>;
}

pub trait Health: Sync + Send {
    fn health(&self) -> ReplicaHealthStatus;
}

pub trait RootKey: Sync + Send {
    fn root_key(&self) -> Option<Vec<u8>>;
}

// Router that helps handlers do their job by looking up in routing table
// and owning HTTP client for outgoing requests
#[derive(Clone)]
pub struct ProxyRouter {
    http_client: Arc<dyn HttpClient>,
    published_routes: Arc<ArcSwapOption<Routes>>,
    published_registry_snapshot: Arc<ArcSwapOption<RegistrySnapshot>>,
    subnets_alive_threshold: f64,
    nodes_per_subnet_alive_threshold: f64,
}

impl ProxyRouter {
    pub fn new(
        http_client: Arc<dyn HttpClient>,
        published_routes: Arc<ArcSwapOption<Routes>>,
        published_registry_snapshot: Arc<ArcSwapOption<RegistrySnapshot>>,
        subnets_alive_threshold: f64,
        nodes_per_subnet_alive_threshold: f64,
    ) -> Self {
        Self {
            http_client,
            published_routes,
            published_registry_snapshot,
            subnets_alive_threshold,
            nodes_per_subnet_alive_threshold,
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
            .ok_or(ErrorCause::CanisterNotFound)?; // Requested canister route wasn't found

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

impl RootKey for ProxyRouter {
    fn root_key(&self) -> Option<Vec<u8>> {
        self.published_registry_snapshot
            .load_full()
            .map(|x| x.nns_public_key.clone())
    }
}

impl Health for ProxyRouter {
    fn health(&self) -> ReplicaHealthStatus {
        match (
            self.published_routes.load_full(),
            self.published_registry_snapshot.load_full(),
        ) {
            (Some(rt), Some(snap)) => {
                if snap.subnets.is_empty() {
                    return ReplicaHealthStatus::CertifiedStateBehind;
                }

                // Count the number of healthy subnets
                let healthy_subnets_count = snap
                    .subnets
                    .iter()
                    .filter(|&subnet| {
                        if subnet.nodes.is_empty() {
                            return false;
                        }

                        // Get number of nodes in this subnet from the active routing table.
                        // If, for some reason, the subnet isn't there (it should be) - assume the number is 0
                        let healthy_nodes = rt
                            .subnet_map
                            .get(&subnet.id)
                            .map(|x| x.nodes.len())
                            .unwrap_or_default();

                        // See if this subnet can be considered healthy
                        (healthy_nodes as f64) / (subnet.nodes.len() as f64)
                            >= self.nodes_per_subnet_alive_threshold
                    })
                    .count();

                // See if we have enough healthy subnets to consider ourselves healthy
                if (healthy_subnets_count as f64) / (snap.subnets.len() as f64)
                    >= self.subnets_alive_threshold
                {
                    ReplicaHealthStatus::Healthy
                } else {
                    // There's no generic "Unhealthy" state it seems, should we use Starting?
                    ReplicaHealthStatus::CertifiedStateBehind
                }
            }

            // Usually this is only for the first 10sec after startup
            _ => ReplicaHealthStatus::Starting,
        }
    }
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
pub(crate) mod test {
    use super::*;

    use std::sync::Arc;

    use anyhow::Error;
    use axum::{body::Body, http::Request, routing::method_routing::get, Router};
    use ethnum::u256;
    use http::header::{
        HeaderName, HeaderValue, CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
    };
    use ic_types::{
        messages::{
            Blob, HttpCallContent, HttpCanisterUpdate, HttpQueryContent, HttpReadState,
            HttpReadStateContent, HttpRequestEnvelope, HttpUserQuery,
        },
        PrincipalId,
    };
    use tower::Service;

    use crate::{
        persist::{test::node, Persist, Persister},
        snapshot::test::test_registry_snapshot,
        test_utils::{setup_test_router, TestHttpClient},
    };

    pub fn test_node(id: u64) -> Arc<Node> {
        node(id, Principal::from_text("f7crg-kabae").unwrap())
    }

    pub fn test_route_subnet_with_id(id: String, n: usize) -> RouteSubnet {
        let mut nodes = Vec::new();

        for i in 0..n {
            nodes.push(test_node(i as u64));
        }

        // "casting integer literal to `u32` is unnecessary"
        // fck clippy
        let zero = 0u32;

        RouteSubnet {
            id: Principal::from_text(id).unwrap(),
            range_start: u256::from(zero),
            range_end: u256::from(zero),
            nodes,
        }
    }

    pub fn test_route_subnet(n: usize) -> RouteSubnet {
        test_route_subnet_with_id("f7crg-kabae".into(), n)
    }

    fn assert_header(headers: &http::HeaderMap, name: HeaderName, expected_value: &str) {
        assert!(headers.contains_key(&name), "Header {} is missing", name);
        assert_eq!(
            headers.get(&name).unwrap(),
            &HeaderValue::from_str(expected_value).unwrap(),
            "Header {} does not match expected value: {}",
            name,
            expected_value,
        );
    }

    #[tokio::test]
    async fn test_health() -> Result<(), Error> {
        let published_routes = Arc::new(ArcSwapOption::empty());
        let published_registry_snapshot = Arc::new(ArcSwapOption::empty());

        let persister = Persister::new(published_routes.clone());

        let http_client = Arc::new(TestHttpClient(1));
        let proxy_router = Arc::new(ProxyRouter::new(
            http_client,
            published_routes,
            published_registry_snapshot.clone(),
            0.51,
            0.6666,
        ));

        // Install snapshot
        let (snapshot, _, _) = test_registry_snapshot(5, 3);
        published_registry_snapshot.store(Some(Arc::new(snapshot.clone())));

        // Initial state
        assert_eq!(proxy_router.health(), ReplicaHealthStatus::Starting);

        let state_health = proxy_router.clone() as Arc<dyn Health>;
        let mut app = Router::new().route(PATH_HEALTH, get(health).with_state(state_health));

        // Test healthy
        let request = Request::builder()
            .method("GET")
            .uri("http://localhost/health")
            .body(Body::from(""))
            .unwrap();

        let resp = app.call(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        // Check when all nodes healthy
        persister.persist(snapshot.subnets.clone());
        assert_eq!(proxy_router.health(), ReplicaHealthStatus::Healthy);

        // Test healthy
        let request = Request::builder()
            .method("GET")
            .uri("http://localhost/health")
            .body(Body::from(""))
            .unwrap();

        let resp = app.call(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Check when 3/5 subnets present (> threshold)
        let subnets = snapshot
            .subnets
            .clone()
            .into_iter()
            .enumerate()
            .filter(|(i, _)| *i <= 2)
            .map(|x| x.1)
            .collect::<Vec<_>>();

        persister.persist(subnets);
        assert_eq!(proxy_router.health(), ReplicaHealthStatus::Healthy);

        // Check when 2/5 subnets present (< threshold)
        let subnets = snapshot
            .subnets
            .clone()
            .into_iter()
            .enumerate()
            .filter(|(i, _)| *i <= 1)
            .map(|x| x.1)
            .collect::<Vec<_>>();
        persister.persist(subnets);

        assert_eq!(
            proxy_router.health(),
            ReplicaHealthStatus::CertifiedStateBehind
        );

        // Check when 2/3 nodes in each subnet are healthy (> threshold)
        let subnets = snapshot
            .subnets
            .clone()
            .into_iter()
            .map(|mut x| {
                x.nodes = x
                    .nodes
                    .into_iter()
                    .enumerate()
                    .filter(|(i, _)| *i <= 1)
                    .map(|x| x.1)
                    .collect::<Vec<_>>();
                x
            })
            .collect::<Vec<_>>();

        persister.persist(subnets);
        assert_eq!(proxy_router.health(), ReplicaHealthStatus::Healthy);

        // Check when 1/3 nodes in each subnet are healthy (< threshold)
        let subnets = snapshot
            .subnets
            .clone()
            .into_iter()
            .map(|mut x| {
                x.nodes = vec![x.nodes[0].clone()];
                x
            })
            .collect::<Vec<_>>();
        persister.persist(subnets);
        assert_eq!(
            proxy_router.health(),
            ReplicaHealthStatus::CertifiedStateBehind
        );

        // Check when 2/3 nodes in 3/5 subnets are available (> threshold) and 1/3 nodes in 2/5 subnets (< threshold)
        let subnets = snapshot
            .subnets
            .clone()
            .into_iter()
            .enumerate()
            .map(|(i, mut x)| {
                if i > 2 {
                    x.nodes = vec![x.nodes[0].clone()];
                } else {
                    x.nodes = vec![x.nodes[0].clone(), x.nodes[1].clone()];
                }

                x
            })
            .collect::<Vec<_>>();
        persister.persist(subnets);
        assert_eq!(proxy_router.health(), ReplicaHealthStatus::Healthy);

        // Check when 1/3 nodes in 3/5 subnets are available (< threshold) and 2/3 nodes in 2/5 subnets (> threshold)
        let subnets = snapshot
            .subnets
            .clone()
            .into_iter()
            .enumerate()
            .map(|(i, mut x)| {
                if i > 2 {
                    x.nodes = vec![x.nodes[0].clone(), x.nodes[1].clone()];
                } else {
                    x.nodes = vec![x.nodes[0].clone()];
                }

                x
            })
            .collect::<Vec<_>>();
        persister.persist(subnets);
        assert_eq!(
            proxy_router.health(),
            ReplicaHealthStatus::CertifiedStateBehind
        );

        // Install snapshot with zero subnets
        let (snapshot, _, _) = test_registry_snapshot(0, 0);
        published_registry_snapshot.store(Some(Arc::new(snapshot.clone())));
        persister.persist(snapshot.subnets.clone());

        // Make sure it doesn't crash
        assert_eq!(
            proxy_router.health(),
            ReplicaHealthStatus::CertifiedStateBehind
        );

        // Install snapshot with subnets which have zero nodes
        let (snapshot, _, _) = test_registry_snapshot(5, 0);
        published_registry_snapshot.store(Some(Arc::new(snapshot.clone())));
        persister.persist(snapshot.subnets.clone());

        // Make sure it doesn't crash
        assert_eq!(
            proxy_router.health(),
            ReplicaHealthStatus::CertifiedStateBehind
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_status() -> Result<(), Error> {
        const ROOT_KEY: &[u8] = &[
            48, 129, 130, 48, 29, 6, 13, 43, 6, 1, 4, 1, 130, 220, 124, 5, 3, 1, 2, 1, 6, 12, 43,
            6, 1, 4, 1, 130, 220, 124, 5, 3, 2, 1, 3, 97, 0, 164, 11, 155, 160, 188, 41, 117, 229,
            63, 252, 167, 119, 29, 30, 227, 98, 237, 74, 46, 188, 146, 183, 47, 146, 73, 22, 138,
            98, 134, 4, 227, 191, 162, 241, 66, 98, 49, 165, 59, 251, 105, 165, 137, 20, 84, 15,
            168, 196, 17, 178, 140, 45, 29, 63, 7, 53, 150, 40, 122, 4, 40, 149, 203, 233, 231, 66,
            46, 244, 167, 99, 183, 61, 131, 19, 223, 201, 237, 51, 94, 24, 59, 178, 188, 224, 198,
            44, 183, 41, 121, 43, 119, 84, 128, 45, 105, 10,
        ];

        let published_routes = Arc::new(ArcSwapOption::empty());
        let published_registry_snapshot = Arc::new(ArcSwapOption::empty());

        let persister = Persister::new(published_routes.clone());
        let (mut snapshot, _, _) = test_registry_snapshot(5, 3);
        snapshot.nns_public_key = ROOT_KEY.into();
        published_registry_snapshot.store(Some(Arc::new(snapshot.clone())));

        let http_client = Arc::new(TestHttpClient(1));
        let proxy_router = Arc::new(ProxyRouter::new(
            http_client,
            published_routes,
            published_registry_snapshot,
            0.51,
            0.6666,
        ));

        // Mark all nodes healthy
        persister.persist(snapshot.subnets.clone());

        let (state_rootkey, state_health) = (
            proxy_router.clone() as Arc<dyn RootKey>,
            proxy_router.clone() as Arc<dyn Health>,
        );

        let mut app = Router::new().route(
            PATH_STATUS,
            get(status).with_state((state_rootkey, state_health)),
        );

        // Test healthy
        let request = Request::builder()
            .method("GET")
            .uri("http://localhost/api/v2/status")
            .body(Body::from(""))
            .unwrap();

        let resp = app.call(request).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);

        let (parts, body) = resp.into_parts();
        let body = axum::body::to_bytes(body, usize::MAX)
            .await
            .unwrap()
            .to_vec();

        let health: HttpStatusResponse = serde_cbor::from_slice(&body)?;
        assert_eq!(
            health.replica_health_status,
            Some(ReplicaHealthStatus::Healthy)
        );
        assert_eq!(health.root_key.as_deref(), Some(&ROOT_KEY.to_vec()));

        let headers = parts.headers;
        assert_header(&headers, CONTENT_TYPE, "application/cbor");
        assert_header(&headers, X_CONTENT_TYPE_OPTIONS, "nosniff");
        assert_header(&headers, X_FRAME_OPTIONS, "DENY");

        Ok(())
    }

    #[tokio::test]
    async fn test_all_call_types() -> Result<(), Error> {
        let (mut app, subnets) = setup_test_router(false, false, 10, 1, 1024, None);
        let node = subnets[0].nodes[0].clone();

        let sender = Principal::from_text("sqjm4-qahae-aq").unwrap();
        let canister_id = CanisterId::from_u64(100);

        // Test query
        let content = HttpQueryContent::Query {
            query: HttpUserQuery {
                canister_id: Blob(canister_id.get().as_slice().to_vec()),
                method_name: "foobar".to_string(),
                arg: Blob(vec![]),
                sender: Blob(sender.as_slice().to_vec()),
                nonce: None,
                ingress_expiry: 1234,
            },
        };

        let envelope = HttpRequestEnvelope::<HttpQueryContent> {
            content,
            sender_delegation: None,
            sender_pubkey: None,
            sender_sig: None,
        };

        let body = serde_cbor::to_vec(&envelope).unwrap();

        let request = Request::builder()
            .method("POST")
            .uri(format!(
                "http://localhost/api/v2/canister/{canister_id}/query"
            ))
            .body(Body::from(body))
            .unwrap();

        let resp = app.call(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let (parts, body) = resp.into_parts();

        // Check response headers
        let headers = parts.headers;
        assert_header(&headers, X_IC_NODE_ID, &node.id.to_string());
        assert_header(&headers, X_IC_SUBNET_ID, &node.subnet_id.to_string());
        assert_header(&headers, X_IC_SUBNET_TYPE, node.subnet_type.as_ref());
        assert_header(&headers, X_IC_SENDER, &sender.to_string());
        assert_header(&headers, X_IC_CANISTER_ID, &canister_id.to_string());
        assert_header(&headers, X_IC_METHOD_NAME, "foobar");
        assert_header(&headers, X_IC_REQUEST_TYPE, "query");
        assert_header(&headers, CONTENT_TYPE, "application/cbor");
        assert_header(&headers, X_CONTENT_TYPE_OPTIONS, "nosniff");
        assert_header(&headers, X_FRAME_OPTIONS, "DENY");

        let body = axum::body::to_bytes(body, usize::MAX)
            .await
            .unwrap()
            .to_vec();
        let body = String::from_utf8_lossy(&body);
        assert_eq!(body, "a".repeat(1024));

        // Test call
        let content = HttpCallContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(canister_id.get().as_slice().to_vec()),
                method_name: "foobar".to_string(),
                arg: Blob(vec![]),
                sender: Blob(sender.as_slice().to_vec()),
                nonce: None,
                ingress_expiry: 1234,
            },
        };

        let envelope = HttpRequestEnvelope::<HttpCallContent> {
            content,
            sender_delegation: None,
            sender_pubkey: None,
            sender_sig: None,
        };

        let body = serde_cbor::to_vec(&envelope).unwrap();

        let request = Request::builder()
            .method("POST")
            .uri(format!(
                "http://localhost/api/v2/canister/{canister_id}/call"
            ))
            .body(Body::from(body))
            .unwrap();

        let resp = app.call(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let (_parts, body) = resp.into_parts();
        let body = axum::body::to_bytes(body, usize::MAX)
            .await
            .unwrap()
            .to_vec();
        let body = String::from_utf8_lossy(&body);
        assert_eq!(body, "a".repeat(1024));

        // Test call v3
        let content = HttpCallContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(canister_id.get().as_slice().to_vec()),
                method_name: "foobar".to_string(),
                arg: Blob(vec![]),
                sender: Blob(sender.as_slice().to_vec()),
                nonce: None,
                ingress_expiry: 1234,
            },
        };

        let envelope = HttpRequestEnvelope::<HttpCallContent> {
            content,
            sender_delegation: None,
            sender_pubkey: None,
            sender_sig: None,
        };

        let body = serde_cbor::to_vec(&envelope).unwrap();

        let request = Request::builder()
            .method("POST")
            .uri(format!(
                "http://localhost/api/v3/canister/{canister_id}/call"
            ))
            .body(Body::from(body))
            .unwrap();

        let resp = app.call(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let (_parts, body) = resp.into_parts();
        let body = axum::body::to_bytes(body, usize::MAX)
            .await
            .unwrap()
            .to_vec();
        let body = String::from_utf8_lossy(&body);
        assert_eq!(body, "a".repeat(1024));

        // Test canister read_state
        let content = HttpReadStateContent::ReadState {
            read_state: HttpReadState {
                sender: Blob(sender.as_slice().to_vec()),
                nonce: None,
                ingress_expiry: 1234,
                paths: vec![],
            },
        };

        let envelope = HttpRequestEnvelope::<HttpReadStateContent> {
            content,
            sender_delegation: None,
            sender_pubkey: None,
            sender_sig: None,
        };

        let body = serde_cbor::to_vec(&envelope).unwrap();

        let request = Request::builder()
            .method("POST")
            .uri(format!(
                "http://localhost/api/v2/canister/{canister_id}/read_state"
            ))
            .body(Body::from(body))
            .unwrap();

        let resp = app.call(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let (parts, body) = resp.into_parts();

        // Check response headers
        let headers = parts.headers;
        // Make sure that the canister_id is there even if the CBOR does not have it
        assert_header(&headers, X_IC_CANISTER_ID, &canister_id.to_string());
        assert_header(&headers, CONTENT_TYPE, "application/cbor");
        assert_header(&headers, X_CONTENT_TYPE_OPTIONS, "nosniff");
        assert_header(&headers, X_FRAME_OPTIONS, "DENY");
        let body = axum::body::to_bytes(body, usize::MAX)
            .await
            .unwrap()
            .to_vec();
        let body = String::from_utf8_lossy(&body);
        assert_eq!(body, "a".repeat(1024));

        // Test subnet read_state
        let content = HttpReadStateContent::ReadState {
            read_state: HttpReadState {
                sender: Blob(sender.as_slice().to_vec()),
                nonce: None,
                ingress_expiry: 1234,
                paths: vec![],
            },
        };

        let envelope = HttpRequestEnvelope::<HttpReadStateContent> {
            content,
            sender_delegation: None,
            sender_pubkey: None,
            sender_sig: None,
        };

        let body = serde_cbor::to_vec(&envelope).unwrap();

        let subnet_id: SubnetId = PrincipalId(subnets[0].id).into();

        let request = Request::builder()
            .method("POST")
            .uri(format!(
                "http://localhost/api/v2/subnet/{subnet_id}/read_state"
            ))
            .body(Body::from(body))
            .unwrap();

        let resp = app.call(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let (parts, body) = resp.into_parts();

        // Check response headers
        let headers = parts.headers;
        // Make sure that the subnet_id is there even if the CBOR does not have it
        assert_header(&headers, X_IC_SUBNET_ID, &subnet_id.to_string());
        assert_header(&headers, CONTENT_TYPE, "application/cbor");
        assert_header(&headers, X_CONTENT_TYPE_OPTIONS, "nosniff");
        assert_header(&headers, X_FRAME_OPTIONS, "DENY");
        let body = axum::body::to_bytes(body, usize::MAX)
            .await
            .unwrap()
            .to_vec();
        let body = String::from_utf8_lossy(&body);
        assert_eq!(body, "a".repeat(1024));

        Ok(())
    }
}
