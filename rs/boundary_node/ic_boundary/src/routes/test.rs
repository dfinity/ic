use super::*;

use std::sync::Arc;

use anyhow::Error;
use axum::{body::Body, http::Request, middleware, routing::method_routing::get, Router};
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
use tower::{Service, ServiceBuilder};
use tower_http::{request_id::MakeRequestUuid, ServiceBuilderExt};

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
    let request_id = resp.headers().get(X_REQUEST_ID).unwrap().to_str().unwrap();
    assert!(UUID_REGEX.is_match(request_id));

    // Check if canister id header is correct
    let canister_id = resp
        .headers()
        .get(X_IC_CANISTER_ID)
        .unwrap()
        .to_str()
        .unwrap();

    assert_eq!(canister_id, "s6hwe-laaaa-aaaab-qaeba-cai");

    // case 2: 'x-request-id' header contains a valid uuid, this uuid is not overwritten by middleware
    let request = Request::builder()
        .method("GET")
        .uri(url)
        .header(X_REQUEST_ID, "40a6d613-149e-4bde-8443-33593fd2fd17")
        .body(Body::from(""))
        .unwrap();
    let resp = app.call(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(X_REQUEST_ID).unwrap(),
        "40a6d613-149e-4bde-8443-33593fd2fd17"
    );

    // case 3: 'x-request-id' header contains an invalid uuid
    #[allow(clippy::borrow_interior_mutable_const)]
    let expected_failure =
        format!("error: malformed_request\ndetails: Unable to parse the request ID in the '{X_REQUEST_ID}': the value is not in UUID format");

    let request = Request::builder()
        .method("GET")
        .uri(url)
        .header(X_REQUEST_ID, "1")
        .body(Body::from(""))
        .unwrap();
    let resp = app.call(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let (_, body) = resp.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap()
        .to_vec();
    let body = String::from_utf8_lossy(&body);
    assert_eq!(body, expected_failure);

    // case 4: 'x-request-id' header contains an invalid (not hyphenated) uuid
    let request = Request::builder()
        .method("GET")
        .uri(url)
        .header(X_REQUEST_ID, "40a6d613149e4bde844333593fd2fd17")
        .body(Body::from(""))
        .unwrap();
    let resp = app.call(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let (_, body) = resp.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap()
        .to_vec();
    let body = String::from_utf8_lossy(&body);
    assert_eq!(body, expected_failure);

    // case 5: 'x-request-id' header is empty
    let request = Request::builder()
        .method("GET")
        .uri(url)
        .header(X_REQUEST_ID, "")
        .body(Body::from(""))
        .unwrap();
    let resp = app.call(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let (_, body) = resp.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap()
        .to_vec();
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
    let request_id = resp.headers().get(X_REQUEST_ID).unwrap().to_str().unwrap();
    assert!(UUID_REGEX.is_match(request_id));

    // case 2: 'x-request-id' header contains a valid uuid, this uuid is not overwritten by middleware
    let request = Request::builder()
        .method("GET")
        .uri(url)
        .header(X_REQUEST_ID, "40a6d613-149e-4bde-8443-33593fd2fd17")
        .body(Body::from(""))
        .unwrap();
    let resp = app.call(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(X_REQUEST_ID).unwrap(),
        "40a6d613-149e-4bde-8443-33593fd2fd17"
    );

    // case 3: 'x-request-id' header contains an invalid uuid
    #[allow(clippy::borrow_interior_mutable_const)]
    let expected_failure =
        format!("error: malformed_request\ndetails: Unable to parse the request ID in the '{X_REQUEST_ID}': the value is not in UUID format");

    let request = Request::builder()
        .method("GET")
        .uri(url)
        .header(X_REQUEST_ID, "1")
        .body(Body::from(""))
        .unwrap();
    let resp = app.call(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let (_, body) = resp.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap()
        .to_vec();
    let body = String::from_utf8_lossy(&body);
    assert_eq!(body, expected_failure);

    // case 4: 'x-request-id' header contains an invalid (not hyphenated) uuid
    let request = Request::builder()
        .method("GET")
        .uri(url)
        .header(X_REQUEST_ID, "40a6d613149e4bde844333593fd2fd17")
        .body(Body::from(""))
        .unwrap();
    let resp = app.call(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let (_, body) = resp.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap()
        .to_vec();
    let body = String::from_utf8_lossy(&body);
    assert_eq!(body, expected_failure);

    // case 5: 'x-request-id' header is empty
    let request = Request::builder()
        .method("GET")
        .uri(url)
        .header(X_REQUEST_ID, "")
        .body(Body::from(""))
        .unwrap();
    let resp = app.call(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let (_, body) = resp.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap()
        .to_vec();
    let body = String::from_utf8_lossy(&body);
    assert_eq!(body, expected_failure);

    Ok(())
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
        48, 129, 130, 48, 29, 6, 13, 43, 6, 1, 4, 1, 130, 220, 124, 5, 3, 1, 2, 1, 6, 12, 43, 6, 1,
        4, 1, 130, 220, 124, 5, 3, 2, 1, 3, 97, 0, 164, 11, 155, 160, 188, 41, 117, 229, 63, 252,
        167, 119, 29, 30, 227, 98, 237, 74, 46, 188, 146, 183, 47, 146, 73, 22, 138, 98, 134, 4,
        227, 191, 162, 241, 66, 98, 49, 165, 59, 251, 105, 165, 137, 20, 84, 15, 168, 196, 17, 178,
        140, 45, 29, 63, 7, 53, 150, 40, 122, 4, 40, 149, 203, 233, 231, 66, 46, 244, 167, 99, 183,
        61, 131, 19, 223, 201, 237, 51, 94, 24, 59, 178, 188, 224, 198, 44, 183, 41, 121, 43, 119,
        84, 128, 45, 105, 10,
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
