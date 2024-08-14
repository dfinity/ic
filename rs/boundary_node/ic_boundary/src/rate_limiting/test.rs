use super::*;

use anyhow::Error;
use axum::{
    body::Body,
    extract::ConnectInfo,
    http::Request,
    middleware::Next,
    middleware::{self},
    response::IntoResponse,
    routing::method_routing::post,
    Router,
};
use http::StatusCode;
use ic_types::{
    messages::{Blob, HttpCallContent, HttpCanisterUpdate, HttpRequestEnvelope},
    CanisterId,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tower::Service;

use crate::{
    routes::test::test_route_subnet_with_id, socket::TcpConnectInfo, test_utils::setup_test_router,
};

async fn dummy_call(_request: Request<Body>) -> Result<impl IntoResponse, ApiError> {
    Ok("foo".into_response())
}

async fn body_to_subnet_context(
    request: Request<Body>,
    next: Next<Body>,
) -> Result<impl IntoResponse, ApiError> {
    let (parts, body) = request.into_parts();
    let body_vec = hyper::body::to_bytes(body).await.unwrap().to_vec();
    let subnet_id = String::from_utf8(body_vec.clone()).unwrap();
    let mut request = Request::from_parts(parts, hyper::Body::from(body_vec));
    request
        .extensions_mut()
        .insert(Arc::new(test_route_subnet_with_id(subnet_id, 0)));
    let resp = next.run(request).await;
    Ok(resp)
}

async fn add_ip_to_request(
    mut request: Request<Body>,
    next: Next<Body>,
) -> Result<impl IntoResponse, ApiError> {
    request
        .extensions_mut()
        .insert(ConnectInfo(TcpConnectInfo(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            8080,
        ))));
    let resp = next.run(request).await;
    Ok(resp)
}

fn request_with_subnet_id(subnet_id: &str) -> Request<Body> {
    Request::post("/")
        .body(Body::from(String::from(subnet_id)))
        .unwrap()
}

#[tokio::test]
async fn test_no_rate_limit() -> Result<(), Error> {
    let app = Router::new().route("/", post(dummy_call));

    let mut app = app
        .layer(middleware::from_fn(body_to_subnet_context))
        .layer(middleware::from_fn(add_ip_to_request));

    let subnet_id_1 = "f7crg-kabae";
    let request1 = request_with_subnet_id(subnet_id_1);
    let response1 = app.call(request1).await.unwrap();
    let request2 = request_with_subnet_id(subnet_id_1);
    let response2 = app.call(request2).await.unwrap();
    let request3 = request_with_subnet_id(subnet_id_1);
    let response3 = app.call(request3).await.unwrap();
    assert_eq!(response1.status(), StatusCode::OK);
    assert_eq!(response2.status(), StatusCode::OK);
    assert_eq!(response3.status(), StatusCode::OK);

    Ok(())
}

#[tokio::test]
async fn test_ip_rate_limit() -> Result<(), Error> {
    let app = Router::new().route("/", post(dummy_call));
    let app = RateLimit::try_from(2).unwrap().add_ip_rate_limiting(app);
    let mut app = app
        .layer(middleware::from_fn(body_to_subnet_context))
        .layer(middleware::from_fn(add_ip_to_request));

    let subnet_id_1 = "f7crg-kabae";
    let request1 = request_with_subnet_id(subnet_id_1);
    let response1 = app.call(request1).await.unwrap();
    let request2 = request_with_subnet_id(subnet_id_1);
    let response2 = app.call(request2).await.unwrap();
    let request3 = request_with_subnet_id(subnet_id_1);
    let response3 = app.call(request3).await.unwrap();
    assert_eq!(response1.status(), StatusCode::OK);
    assert_eq!(response2.status(), StatusCode::OK);
    assert_eq!(response3.status(), StatusCode::TOO_MANY_REQUESTS);

    Ok(())
}

#[tokio::test]
async fn test_subnet_rate_limit() -> Result<(), Error> {
    let app = Router::new().route("/", post(dummy_call));
    let app = RateLimit::try_from(2)
        .unwrap()
        .add_subnet_rate_limiting(app);
    let mut app = app
        .layer(middleware::from_fn(body_to_subnet_context))
        .layer(middleware::from_fn(add_ip_to_request));

    let subnet_id_1 = "f7crg-kabae";
    let subnet_id_2 = "sqjm4-qahae-aq";
    let request1 = request_with_subnet_id(subnet_id_1);
    let response1 = app.call(request1).await.unwrap();
    let request2 = request_with_subnet_id(subnet_id_1);
    let response2 = app.call(request2).await.unwrap();

    let request3 = request_with_subnet_id(subnet_id_2);
    let response3 = app.call(request3).await.unwrap();
    let request4 = request_with_subnet_id(subnet_id_2);
    let response4 = app.call(request4).await.unwrap();

    let request5 = request_with_subnet_id(subnet_id_1);
    let response5 = app.call(request5).await.unwrap();
    let request6 = request_with_subnet_id(subnet_id_2);
    let response6 = app.call(request6).await.unwrap();

    assert_eq!(response1.status(), StatusCode::OK);
    assert_eq!(response2.status(), StatusCode::OK);
    assert_eq!(response3.status(), StatusCode::OK);
    assert_eq!(response4.status(), StatusCode::OK);
    assert_eq!(response5.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response6.status(), StatusCode::TOO_MANY_REQUESTS);

    Ok(())
}

#[tokio::test]
async fn test_subnet_rate_limit_with_router() -> Result<(), Error> {
    let (mut app, _) = setup_test_router(false, false, 10, 1, 1024, Some(1));

    let sender = Principal::from_text("sqjm4-qahae-aq").unwrap();
    let canister_id = CanisterId::from_u64(100);

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

    // Test call #1 (should work)
    let request = Request::builder()
        .method("POST")
        .uri(format!(
            "http://localhost/api/v2/canister/{canister_id}/call"
        ))
        .body(Body::from(body.clone()))
        .unwrap();

    let resp = app.call(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    // Test call #2 (should fail)
    let request = Request::builder()
        .method("POST")
        .uri(format!(
            "http://localhost/api/v2/canister/{canister_id}/call"
        ))
        .body(Body::from(body))
        .unwrap();

    let resp = app.call(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    Ok(())
}

#[tokio::test]
async fn test_subnet_rate_limit_with_router_v3() -> Result<(), Error> {
    let (mut app, _) = setup_test_router(false, false, 10, 1, 1024, Some(1));

    let sender = Principal::from_text("sqjm4-qahae-aq").unwrap();
    let canister_id = CanisterId::from_u64(100);

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

    // Test call #1 (should work)
    let request = Request::builder()
        .method("POST")
        .uri(format!(
            "http://localhost/api/v3/canister/{canister_id}/call"
        ))
        .body(Body::from(body.clone()))
        .unwrap();

    let resp = app.call(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    // Test call #2 (should fail)
    let request = Request::builder()
        .method("POST")
        .uri(format!(
            "http://localhost/api/v3/canister/{canister_id}/call"
        ))
        .body(Body::from(body))
        .unwrap();

    let resp = app.call(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    Ok(())
}
