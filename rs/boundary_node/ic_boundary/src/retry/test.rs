use super::*;

use std::{
    str::FromStr,
    sync::{Arc, RwLock},
};

use anyhow::Error;
use axum::{
    body::Body, extract::State, http::Request, middleware, response::IntoResponse,
    routing::method_routing::post, Router,
};
use candid::Principal;
use http::StatusCode;
use ic_types::CanisterId;
use tower::Service;

use crate::routes::{test::test_route_subnet, RequestType};

struct TestState {
    failures: u8,
    fail_code: StatusCode,
    error_cause: Option<ErrorCause>,
}

fn gen_request(request_type: RequestType) -> Request<Body> {
    let ctx = RequestContext {
        request_type,
        canister_id: Some(Principal::from_text("f7crg-kabae").unwrap()),
        sender: Some(Principal::from_text("f7crg-kabae").unwrap()),
        method_name: Some("foo".into()),
        ingress_expiry: Some(1),
        arg: Some(vec![1, 2, 3, 4]),
        ..Default::default()
    };

    let ctx = Arc::new(ctx);

    let mut req = Request::post("/").body(Body::from("foobar")).unwrap();
    req.extensions_mut().insert(ctx);
    req.extensions_mut()
        .insert(CanisterId::from_str("f7crg-kabae").unwrap());
    req.extensions_mut().insert(Arc::new(test_route_subnet(10)));

    req
}

// Generate a response
async fn handler(State(state): State<Arc<RwLock<TestState>>>) -> impl IntoResponse {
    let mut s = state.write().unwrap();

    let mut resp = "foobar".into_response();

    if let Some(v) = &s.error_cause {
        resp.extensions_mut().insert(v.clone());
    }

    if s.failures > 0 {
        s.failures -= 1;
        *resp.status_mut() = s.fail_code;
    }

    resp
}

#[tokio::test]
async fn test_retry() -> Result<(), Error> {
    let state = Arc::new(RwLock::new(TestState {
        failures: 2,
        fail_code: StatusCode::INTERNAL_SERVER_ERROR,
        error_cause: None,
    }));

    let mut app = Router::new()
        .route("/", post(handler).with_state(Arc::clone(&state)))
        .layer(middleware::from_fn_with_state(
            RetryParams {
                retry_count: 3,
                retry_update_call: false,
                disable_latency_routing: true,
            },
            retry_request,
        ));

    // Check successful retry
    let req = gen_request(RequestType::Query);
    let res = app.call(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Check retries exhaustion
    {
        state.write().unwrap().failures = 4;
    }

    let req = gen_request(RequestType::Query);
    let res = app.call(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // Check non-retriable status code
    {
        state.write().unwrap().failures = 2;
        state.write().unwrap().fail_code = StatusCode::BAD_REQUEST;
    }

    let req = gen_request(RequestType::Query);
    let res = app.call(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Check update call not retried
    {
        state.write().unwrap().failures = 2;
        state.write().unwrap().fail_code = StatusCode::INTERNAL_SERVER_ERROR;
    }

    let req = gen_request(RequestType::Call);
    let res = app.call(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // Check retriable ErrorCause
    {
        state.write().unwrap().failures = 2;
        state.write().unwrap().error_cause = Some(ErrorCause::ReplicaErrorConnect);
    }

    let req = gen_request(RequestType::Query);
    let res = app.call(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Check non-retriable ErrorCause
    {
        state.write().unwrap().failures = 2;
        state.write().unwrap().error_cause = Some(ErrorCause::PayloadTooLarge(123));
    }

    let req = gen_request(RequestType::Query);
    let res = app.call(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // Check update call retried
    let mut app = Router::new()
        .route("/", post(handler).with_state(Arc::clone(&state)))
        .layer(middleware::from_fn_with_state(
            RetryParams {
                retry_count: 3,
                retry_update_call: true,
                disable_latency_routing: true,
            },
            retry_request,
        ));

    {
        state.write().unwrap().failures = 2;
        state.write().unwrap().error_cause = None;
    }

    let req = gen_request(RequestType::Call);
    let res = app.call(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    Ok(())
}
