use super::*;

use crate::persist::test::node;
use anyhow::Error;
use axum::{
    body::Body,
    http::Request,
    middleware,
    response::IntoResponse,
    routing::method_routing::{get, post},
    Router,
};
use ic_types::messages::{Blob, HttpQueryContent, HttpRequestEnvelope, HttpUserQuery};
use tower::{Service, ServiceBuilder};
use tower_http::{request_id::MakeRequestUuid, ServiceBuilderExt};

#[derive(Clone)]
struct ProxyRouter {
    node: Node,
    root_key: Vec<u8>,
}

#[async_trait]
impl Proxy for ProxyRouter {
    async fn proxy(
        &self,
        _request_type: RequestType,
        _request: Request<Body>,
        _node: Node,
        _canister_id: CanisterId,
    ) -> Result<Response, ErrorCause> {
        Ok("test_response".into_response())
    }
}

#[async_trait]
impl Lookup for ProxyRouter {
    async fn lookup(&self, _: &CanisterId) -> Result<Node, ErrorCause> {
        Ok(self.node.clone())
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
        ReplicaHealthStatus::Healthy
    }
}

#[tokio::test]
async fn test_middleware_validate_request() -> Result<(), Error> {
    let node = node(0, Principal::from_text("f7crg-kabae").unwrap());
    let root_key = vec![8, 6, 7, 5, 3, 0, 9];

    let proxy_router = Arc::new(ProxyRouter {
        node,
        root_key: root_key.clone(),
    });

    let (state_rootkey, state_health) = (
        proxy_router.clone() as Arc<dyn RootKey>,
        proxy_router.clone() as Arc<dyn Health>,
    );

    // NOTE: this router should be aligned with the one in core.rs, otherwise this testing is useless.
    let mut app = Router::new()
        .route(
            PATH_STATUS,
            get(status).with_state((state_rootkey, state_health)),
        )
        .layer(
            ServiceBuilder::new()
                .layer(middleware::from_fn(validate_request))
                .set_x_request_id(MakeRequestUuid)
                .propagate_x_request_id(),
        );

    // case 1: no 'x-request-id' header, middleware generates one with a random uuid
    let request = Request::builder()
        .method("GET")
        .uri("http://localhost/api/v2/status")
        .body(Body::from(""))
        .unwrap();
    let resp = app.call(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let request_id = resp
        .headers()
        .get("x-request-id")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(UUID_REGEX.is_match(request_id));

    // case 2: 'x-request-id' header contains a valid uuid, this uuid is not overwritten by middleware
    let request = Request::builder()
        .method("GET")
        .uri("http://localhost/api/v2/status")
        .header("x-request-id", "40a6d613-149e-4bde-8443-33593fd2fd17")
        .body(Body::from(""))
        .unwrap();
    let resp = app.call(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-request-id").unwrap(),
        "40a6d613-149e-4bde-8443-33593fd2fd17"
    );
    // case 3: 'x-request-id' header contains an invalid uuid
    let expected_failure =
        "malformed_request: Value of 'x-request-id' header is not in version 4 uuid format\n";
    let request = Request::builder()
        .method("GET")
        .uri("http://localhost/api/v2/status")
        .header("x-request-id", "1")
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
        .uri("http://localhost/api/v2/status")
        .header("x-request-id", "40a6d613149e4bde844333593fd2fd17")
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
        .uri("http://localhost/api/v2/status")
        .header("x-request-id", "")
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
async fn test_status() -> Result<(), Error> {
    let node = node(0, Principal::from_text("f7crg-kabae").unwrap());
    let root_key = vec![8, 6, 7, 5, 3, 0, 9];

    let proxy_router = Arc::new(ProxyRouter {
        node,
        root_key: root_key.clone(),
    });

    let (state_rootkey, state_health) = (
        proxy_router.clone() as Arc<dyn RootKey>,
        proxy_router.clone() as Arc<dyn Health>,
    );

    let mut app = Router::new()
        .route(
            PATH_STATUS,
            get(status).with_state((state_rootkey, state_health)),
        )
        .layer(middleware::from_fn(validate_request));

    let request = Request::builder()
        .method("GET")
        .uri("http://localhost/api/v2/status")
        .body(Body::from(""))
        .unwrap();

    let resp = app.call(request).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let (_parts, body) = resp.into_parts();
    let body = hyper::body::to_bytes(body).await.unwrap().to_vec();

    let health: HttpStatusResponse = serde_cbor::from_slice(&body)?;
    assert_eq!(
        health.replica_health_status,
        Some(ReplicaHealthStatus::Healthy)
    );
    assert_eq!(health.root_key.as_deref(), Some(&root_key),);

    Ok(())
}

#[tokio::test]
async fn test_query() -> Result<(), Error> {
    let node = node(0, Principal::from_text("f7crg-kabae").unwrap());
    let root_key = vec![8, 6, 7, 5, 3, 0, 9];
    let state = Arc::new(ProxyRouter {
        node: node.clone(),
        root_key,
    });

    let (state_lookup, state_proxy) = (
        state.clone() as Arc<dyn Lookup>,
        state.clone() as Arc<dyn Proxy>,
    );

    let sender = Principal::from_text("sqjm4-qahae-aq").unwrap();
    let canister_id = Principal::from_text("sxiki-5ygae-aq").unwrap();

    let content = HttpQueryContent::Query {
        query: HttpUserQuery {
            canister_id: Blob(canister_id.as_slice().to_vec()),
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

    // here the middlewares are applied bottom->top
    let mut app = Router::new()
        .route(PATH_QUERY, post(handle_call).with_state(state_proxy))
        .layer(middleware::from_fn_with_state(state_lookup, lookup_node))
        .layer(middleware::from_fn(preprocess_request));

    let resp = app.call(request).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let (_parts, body) = resp.into_parts();
    let body = hyper::body::to_bytes(body).await.unwrap().to_vec();
    let body = String::from_utf8_lossy(&body);
    assert_eq!(body, "test_response");

    Ok(())
}
