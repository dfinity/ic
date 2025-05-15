use super::*;

use std::{sync::Arc, time::Duration};

use axum::{
    body::Body, http::Request, middleware, response::IntoResponse, routing::method_routing::post,
    Extension, Router,
};
use candid::Principal;
use http::StatusCode;
use ic_bn_lib::http::cache::{CacheBypassReason, CacheStatus};
use tower::Service;

use crate::routes::ANONYMOUS_PRINCIPAL;

const CANISTER_1: &str = "sqjm4-qahae-aq";
const MAX_RESP_SIZE: usize = 1024;
const MAX_MEM_SIZE: u64 = 32768;
const DEFAULT_SIZE: u64 = 8;

fn gen_request_with_params(
    canister_id: &str,
    nonce: bool,
    size: u64,
    ingress_expiry: u64,
    anonymous: bool,
    status_code: StatusCode,
) -> Request<Body> {
    let mut req = Request::post("/").body(Body::from("foobar")).unwrap();

    let mut ctx = RequestContext {
        request_type: RequestType::Query,
        canister_id: Some(Principal::from_text(canister_id).unwrap()),
        sender: Some(if anonymous {
            ANONYMOUS_PRINCIPAL
        } else {
            Principal::from_text("f7crg-kabae").unwrap()
        }),
        method_name: Some("foo".into()),
        ingress_expiry: Some(ingress_expiry),
        arg: Some(vec![1, 2, 3, 4]),
        ..Default::default()
    };

    if nonce {
        ctx.nonce = Some(vec![1, 2, 3, 4]);
    }

    let ctx = Arc::new(ctx);

    req.extensions_mut().insert(ctx);
    req.extensions_mut().insert(size);
    req.extensions_mut().insert(status_code);

    req
}

fn gen_request(canister_id: &str, nonce: bool) -> Request<Body> {
    gen_request_with_params(canister_id, nonce, DEFAULT_SIZE, 0, true, StatusCode::OK)
}

// Generate a response with a requested size
async fn handler(
    Extension(size): Extension<u64>,
    Extension(status_code): Extension<StatusCode>,
) -> impl IntoResponse {
    (status_code, "a".repeat(size as usize))
}

#[tokio::test]
async fn test_cache() -> Result<(), Error> {
    // Check that we fail if item size >= max size
    let cli = cli::Cache {
        cache_size: Some(MAX_MEM_SIZE),
        cache_max_item_size: MAX_RESP_SIZE,
        cache_ttl: Duration::from_secs(3600),
        cache_non_anonymous: false,
    };

    let cache_state = Arc::new(CacheState::new(&cli, &Registry::new()).unwrap());

    let mut app = Router::new()
        .route("/", post(handler))
        .layer(middleware::from_fn_with_state(
            cache_state,
            cache_middleware,
        ));

    // Check non-anonymous
    let req = gen_request_with_params(CANISTER_1, false, DEFAULT_SIZE, 0, false, StatusCode::OK);
    let res = app.call(req).await.unwrap();
    let cs = res
        .extensions()
        .get::<CacheStatus<BypassReasonIC>>()
        .cloned()
        .unwrap();
    assert_eq!(
        cs,
        CacheStatus::Bypass(CacheBypassReason::Custom(BypassReasonIC::NonAnonymous))
    );

    // Check non-2xx
    let req = gen_request_with_params(
        CANISTER_1,
        false,
        DEFAULT_SIZE,
        0,
        true,
        StatusCode::SERVICE_UNAVAILABLE,
    );
    let res = app.call(req).await.unwrap();
    let cs = res
        .extensions()
        .get::<CacheStatus<BypassReasonIC>>()
        .cloned()
        .unwrap();
    assert_eq!(cs, CacheStatus::Bypass(CacheBypassReason::HTTPError));

    // Check cache hits and misses
    let req = gen_request(CANISTER_1, false);
    let res = app.call(req).await.unwrap();
    let cs = res
        .extensions()
        .get::<CacheStatus<BypassReasonIC>>()
        .cloned()
        .unwrap();
    assert_eq!(cs, CacheStatus::Miss);

    let req = gen_request(CANISTER_1, false);
    let res = app.call(req).await.unwrap();
    let cs = res
        .extensions()
        .get::<CacheStatus<BypassReasonIC>>()
        .cloned()
        .unwrap();
    assert_eq!(cs, CacheStatus::Hit);

    // Check if the body from cache is correct
    let (_, body) = res.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap()
        .to_vec();
    let body = String::from_utf8_lossy(&body);
    assert_eq!("a".repeat(DEFAULT_SIZE as usize), body);

    // Check with nonce
    let req = gen_request(CANISTER_1, true);
    let res = app.call(req).await.unwrap();
    let cs = res
        .extensions()
        .get::<CacheStatus<BypassReasonIC>>()
        .cloned()
        .unwrap();
    assert_eq!(
        cs,
        CacheStatus::Bypass(CacheBypassReason::Custom(BypassReasonIC::Nonce))
    );

    Ok(())
}
