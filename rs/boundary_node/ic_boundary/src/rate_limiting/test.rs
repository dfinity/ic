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
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tower::Service;

use crate::{routes::test::test_route_subnet_with_id, socket::TcpConnectInfo};

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
