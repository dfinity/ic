use super::*;

use std::sync::{Arc, Mutex};

use anyhow::Error;
use axum::{
    body::Body, http::Request, middleware, response::IntoResponse, routing::method_routing::get,
    Router,
};
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
use prometheus::Registry;
use tower::{Service, ServiceBuilder};
use tower_http::{request_id::MakeRequestUuid, ServiceBuilderExt};

use crate::{
    metrics::{metrics_middleware_status, HttpMetricParamsStatus},
    persist::test::node,
    test_utils::setup_test_router,
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

#[derive(Clone)]
struct ProxyRouter {
    root_key: Vec<u8>,
    health: Arc<Mutex<ReplicaHealthStatus>>,
}

impl ProxyRouter {
    fn set_health(&self, new: ReplicaHealthStatus) {
        let mut h = self.health.lock().unwrap();
        *h = new;
    }
}

#[async_trait]
impl Proxy for ProxyRouter {
    async fn proxy(&self, _request: Request<Body>, _url: Url) -> Result<Response, ErrorCause> {
        let mut resp = "test_response".into_response();

        let status = StatusCode::OK;

        *resp.status_mut() = status;
        Ok(resp)
    }
}

impl Lookup for ProxyRouter {
    fn lookup_subnet_by_canister_id(&self, _: &CanisterId) -> Result<Arc<RouteSubnet>, ErrorCause> {
        Ok(Arc::new(test_route_subnet(1)))
    }
    fn lookup_subnet_by_id(&self, _: &SubnetId) -> Result<Arc<RouteSubnet>, ErrorCause> {
        Ok(Arc::new(test_route_subnet(1)))
    }
}

#[async_trait]
impl RootKey for ProxyRouter {
    async fn root_key(&self) -> Option<Vec<u8>> {
        Some(self.root_key.clone())
    }
}

#[async_trait]
impl Health for ProxyRouter {
    async fn health(&self) -> ReplicaHealthStatus {
        *self.health.lock().unwrap()
    }
}

#[tokio::test]
async fn test_middleware_validate_canister_request() -> Result<(), Error> {
    let mut app = Router::new().route(PATH_QUERY, get(|| async {})).layer(
        ServiceBuilder::new()
            .layer(middleware::from_fn(validate_request))
            .layer(middleware::from_fn(validate_canister_request))
            .set_x_request_id(MakeRequestUuid)
            .propagate_x_request_id(),
    );

    let url = "http://localhost/api/v2/canister/s6hwe-laaaa-aaaab-qaeba-cai/query";

    // case 1: no 'x-request-id' header, middleware generates one with a random uuid
    let request = Request::builder()
        .method("GET")
        .uri(url)
        .body(Body::from(""))
        .unwrap();
    let resp = app.call(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let request_id = resp
        .headers()
        .get(HEADER_X_REQUEST_ID)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(UUID_REGEX.is_match(request_id));

    // Check if canister id header is correct
    let canister_id = resp
        .headers()
        .get(HEADER_IC_CANISTER_ID)
        .unwrap()
        .to_str()
        .unwrap();

    assert_eq!(canister_id, "s6hwe-laaaa-aaaab-qaeba-cai");

    // case 2: 'x-request-id' header contains a valid uuid, this uuid is not overwritten by middleware
    let request = Request::builder()
        .method("GET")
        .uri(url)
        .header(HEADER_X_REQUEST_ID, "40a6d613-149e-4bde-8443-33593fd2fd17")
        .body(Body::from(""))
        .unwrap();
    let resp = app.call(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(HEADER_X_REQUEST_ID).unwrap(),
        "40a6d613-149e-4bde-8443-33593fd2fd17"
    );

    // case 3: 'x-request-id' header contains an invalid uuid
    #[allow(clippy::borrow_interior_mutable_const)]
    let expected_failure = format!(
        "malformed_request: value of '{HEADER_X_REQUEST_ID}' header is not in UUID format\n"
    );

    let request = Request::builder()
        .method("GET")
        .uri(url)
        .header(HEADER_X_REQUEST_ID, "1")
        .body(Body::from(""))
        .unwrap();
    let resp = app.call(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = hyper::body::to_bytes(resp).await.unwrap().to_vec();
    let body = String::from_utf8_lossy(&body);
    assert_eq!(body, expected_failure);

    // case 4: 'x-request-id' header contains an invalid (not hyphenated) uuid
    let request = Request::builder()
        .method("GET")
        .uri(url)
        .header(HEADER_X_REQUEST_ID, "40a6d613149e4bde844333593fd2fd17")
        .body(Body::from(""))
        .unwrap();
    let resp = app.call(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = hyper::body::to_bytes(resp).await.unwrap().to_vec();
    let body = String::from_utf8_lossy(&body);
    assert_eq!(body, expected_failure);

    // case 5: 'x-request-id' header is empty
    let request = Request::builder()
        .method("GET")
        .uri(url)
        .header(HEADER_X_REQUEST_ID, "")
        .body(Body::from(""))
        .unwrap();
    let resp = app.call(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = hyper::body::to_bytes(resp).await.unwrap().to_vec();
    let body = String::from_utf8_lossy(&body);
    assert_eq!(body, expected_failure);

    Ok(())
}

#[tokio::test]
async fn test_middleware_validate_subnet_request() -> Result<(), Error> {
    let mut app = Router::new()
        .route(PATH_SUBNET_READ_STATE, get(|| async {}))
        .layer(
            ServiceBuilder::new()
                .layer(middleware::from_fn(validate_request))
                .layer(middleware::from_fn(validate_subnet_request))
                .set_x_request_id(MakeRequestUuid)
                .propagate_x_request_id(),
        );

    let url = "http://localhost/api/v2/subnet/s6hwe-laaaa-aaaab-qaeba-cai/read_state";

    // case 1: no 'x-request-id' header, middleware generates one with a random uuid
    let request = Request::builder()
        .method("GET")
        .uri(url)
        .body(Body::from(""))
        .unwrap();
    let resp = app.call(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let request_id = resp
        .headers()
        .get(HEADER_X_REQUEST_ID)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(UUID_REGEX.is_match(request_id));

    // case 2: 'x-request-id' header contains a valid uuid, this uuid is not overwritten by middleware
    let request = Request::builder()
        .method("GET")
        .uri(url)
        .header(HEADER_X_REQUEST_ID, "40a6d613-149e-4bde-8443-33593fd2fd17")
        .body(Body::from(""))
        .unwrap();
    let resp = app.call(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(HEADER_X_REQUEST_ID).unwrap(),
        "40a6d613-149e-4bde-8443-33593fd2fd17"
    );

    // case 3: 'x-request-id' header contains an invalid uuid
    #[allow(clippy::borrow_interior_mutable_const)]
    let expected_failure = format!(
        "malformed_request: value of '{HEADER_X_REQUEST_ID}' header is not in UUID format\n"
    );

    let request = Request::builder()
        .method("GET")
        .uri(url)
        .header(HEADER_X_REQUEST_ID, "1")
        .body(Body::from(""))
        .unwrap();
    let resp = app.call(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = hyper::body::to_bytes(resp).await.unwrap().to_vec();
    let body = String::from_utf8_lossy(&body);
    assert_eq!(body, expected_failure);

    // case 4: 'x-request-id' header contains an invalid (not hyphenated) uuid
    let request = Request::builder()
        .method("GET")
        .uri(url)
        .header(HEADER_X_REQUEST_ID, "40a6d613149e4bde844333593fd2fd17")
        .body(Body::from(""))
        .unwrap();
    let resp = app.call(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = hyper::body::to_bytes(resp).await.unwrap().to_vec();
    let body = String::from_utf8_lossy(&body);
    assert_eq!(body, expected_failure);

    // case 5: 'x-request-id' header is empty
    let request = Request::builder()
        .method("GET")
        .uri(url)
        .header(HEADER_X_REQUEST_ID, "")
        .body(Body::from(""))
        .unwrap();
    let resp = app.call(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = hyper::body::to_bytes(resp).await.unwrap().to_vec();
    let body = String::from_utf8_lossy(&body);
    assert_eq!(body, expected_failure);

    Ok(())
}

#[tokio::test]
async fn test_health() -> Result<(), Error> {
    let root_key = vec![8, 6, 7, 5, 3, 0, 9];

    let proxy_router = Arc::new(ProxyRouter {
        root_key: root_key.clone(),
        health: Arc::new(Mutex::new(ReplicaHealthStatus::Healthy)),
    });

    let state_health = proxy_router.clone() as Arc<dyn Health>;
    let mut app = Router::new().route(PATH_HEALTH, get(health).with_state(state_health));

    // Test healthy
    let request = Request::builder()
        .method("GET")
        .uri("http://localhost/health")
        .body(Body::from(""))
        .unwrap();

    let resp = app.call(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Test starting
    proxy_router.set_health(ReplicaHealthStatus::Starting);

    let request = Request::builder()
        .method("GET")
        .uri("http://localhost/health")
        .body(Body::from(""))
        .unwrap();

    let resp = app.call(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    Ok(())
}

#[tokio::test]
async fn test_status() -> Result<(), Error> {
    let root_key = vec![8, 6, 7, 5, 3, 0, 9];

    let proxy_router = Arc::new(ProxyRouter {
        root_key: root_key.clone(),
        health: Arc::new(Mutex::new(ReplicaHealthStatus::Healthy)),
    });

    let (state_rootkey, state_health) = (
        proxy_router.clone() as Arc<dyn RootKey>,
        proxy_router.clone() as Arc<dyn Health>,
    );

    let registry: Registry = Registry::new_custom(None, None)?;
    let metric_params = HttpMetricParamsStatus::new(&registry);

    let mut app = Router::new()
        .route(
            PATH_STATUS,
            get(status).with_state((state_rootkey, state_health)),
        )
        .layer(middleware::from_fn_with_state(
            metric_params,
            metrics_middleware_status,
        ));

    // Test healthy
    let request = Request::builder()
        .method("GET")
        .uri("http://localhost/api/v2/status")
        .body(Body::from(""))
        .unwrap();

    let resp = app.call(request).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let (parts, body) = resp.into_parts();
    let body = hyper::body::to_bytes(body).await.unwrap().to_vec();

    let health: HttpStatusResponse = serde_cbor::from_slice(&body)?;
    assert_eq!(
        health.replica_health_status,
        Some(ReplicaHealthStatus::Healthy)
    );
    assert_eq!(health.root_key.as_deref(), Some(&root_key),);

    let headers = parts.headers;
    assert_header(&headers, CONTENT_TYPE, "application/cbor");
    assert_header(&headers, X_CONTENT_TYPE_OPTIONS, "nosniff");
    assert_header(&headers, X_FRAME_OPTIONS, "DENY");

    // Test starting
    proxy_router.set_health(ReplicaHealthStatus::Starting);

    let request = Request::builder()
        .method("GET")
        .uri("http://localhost/api/v2/status")
        .body(Body::from(""))
        .unwrap();

    let resp = app.call(request).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let (parts, body) = resp.into_parts();
    let body = hyper::body::to_bytes(body).await.unwrap().to_vec();

    let health: HttpStatusResponse = serde_cbor::from_slice(&body)?;
    assert_eq!(
        health.replica_health_status,
        Some(ReplicaHealthStatus::Starting)
    );

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
    assert_header(&headers, HEADER_IC_NODE_ID, &node.id.to_string());
    assert_header(&headers, HEADER_IC_SUBNET_ID, &node.subnet_id.to_string());
    assert_header(&headers, HEADER_IC_SUBNET_TYPE, node.subnet_type.as_ref());
    assert_header(&headers, HEADER_IC_SENDER, &sender.to_string());
    assert_header(&headers, HEADER_IC_CANISTER_ID, &canister_id.to_string());
    assert_header(&headers, HEADER_IC_METHOD_NAME, "foobar");
    assert_header(&headers, HEADER_IC_REQUEST_TYPE, "query");
    assert_header(&headers, CONTENT_TYPE, "application/cbor");
    assert_header(&headers, X_CONTENT_TYPE_OPTIONS, "nosniff");
    assert_header(&headers, X_FRAME_OPTIONS, "DENY");

    let body = hyper::body::to_bytes(body).await.unwrap().to_vec();
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
    let body = hyper::body::to_bytes(body).await.unwrap().to_vec();
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
    let body = hyper::body::to_bytes(body).await.unwrap().to_vec();
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
    assert_header(&headers, HEADER_IC_CANISTER_ID, &canister_id.to_string());
    assert_header(&headers, CONTENT_TYPE, "application/cbor");
    assert_header(&headers, X_CONTENT_TYPE_OPTIONS, "nosniff");
    assert_header(&headers, X_FRAME_OPTIONS, "DENY");
    let body = hyper::body::to_bytes(body).await.unwrap().to_vec();
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
    assert_header(&headers, HEADER_IC_SUBNET_ID, &subnet_id.to_string());
    assert_header(&headers, CONTENT_TYPE, "application/cbor");
    assert_header(&headers, X_CONTENT_TYPE_OPTIONS, "nosniff");
    assert_header(&headers, X_FRAME_OPTIONS, "DENY");
    let body = hyper::body::to_bytes(body).await.unwrap().to_vec();
    let body = String::from_utf8_lossy(&body);
    assert_eq!(body, "a".repeat(1024));

    Ok(())
}
