use super::*;

use std::sync::Arc;

use axum::{
    body::Body, http::Request, middleware, response::IntoResponse, routing::method_routing::post,
    Router,
};
use candid::Principal;
use http::header::HeaderValue;
use tower::Service;

use crate::routes::ANONYMOUS_PRINCIPAL;

const CANISTER_1: &str = "sqjm4-qahae-aq";
const CANISTER_2: &str = "sxiki-5ygae-aq";
const MAX_RESP_SIZE: usize = 1024;
const MAX_MEM_SIZE: usize = 32768;

fn gen_request_with_params(
    canister_id: &str,
    nonce: bool,
    size: usize,
    ingress_expiry: u64,
    anonymous: bool,
) -> Request<Body> {
    let mut req = Request::post("/").body(Body::from("foobar")).unwrap();

    let mut ctx = RequestContext {
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

    req.extensions_mut().insert(ctx);
    req.extensions_mut().insert(size);

    req
}

fn gen_request(canister_id: &str, nonce: bool) -> Request<Body> {
    gen_request_with_params(canister_id, nonce, 8, 0, true)
}

// Generate a response with a requested size
async fn handler(request: Request<Body>) -> impl IntoResponse {
    let size = request.extensions().get::<usize>().cloned().unwrap();
    "a".repeat(size)
}

#[tokio::test]
async fn test_cache() -> Result<(), Error> {
    // Check that we fail if item size >= max size
    assert!(Cache::new(1024, 1024, Duration::from_secs(60), false).is_err());

    let cache = Cache::new(
        MAX_MEM_SIZE as u64,
        MAX_RESP_SIZE,
        Duration::from_secs(3600),
        false,
    )?;
    let cache = Arc::new(cache);

    let mut app = Router::new()
        .route("/", post(handler))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&cache),
            cache_middleware,
        ));

    // Check non-anonymous
    cache.clear().unwrap();
    let req = gen_request_with_params(CANISTER_1, false, 8, 0, false);
    let res = app.call(req).await.unwrap();
    let cs = res.extensions().get::<CacheStatus>().cloned().unwrap();
    assert_eq!(cs, CacheStatus::Bypass(CacheBypassReason::NonAnonymous));

    // Check cache hits and misses
    let req = gen_request(CANISTER_1, false);
    let res = app.call(req).await.unwrap();
    let cs = res.extensions().get::<CacheStatus>().cloned().unwrap();
    assert_eq!(cs, CacheStatus::Miss);

    let req = gen_request(CANISTER_1, false);
    let res = app.call(req).await.unwrap();
    let cs = res.extensions().get::<CacheStatus>().cloned().unwrap();
    assert_eq!(cs, CacheStatus::Hit);

    // Try other canister
    let req = gen_request(CANISTER_2, false);
    let res = app.call(req).await.unwrap();
    let cs = res.extensions().get::<CacheStatus>().cloned().unwrap();
    assert_eq!(cs, CacheStatus::Miss);

    let req = gen_request(CANISTER_2, false);
    let res = app.call(req).await.unwrap();
    let cs = res.extensions().get::<CacheStatus>().cloned().unwrap();
    assert_eq!(cs, CacheStatus::Hit);

    // Check with nonce
    let req = gen_request(CANISTER_1, true);
    let res = app.call(req).await.unwrap();
    let cs = res.extensions().get::<CacheStatus>().cloned().unwrap();
    assert_eq!(cs, CacheStatus::Bypass(CacheBypassReason::Nonce));

    // Check Cache-Control
    for &v in SKIP_CACHE_DIRECTIVES.iter() {
        let mut req = gen_request(CANISTER_1, false);
        req.headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_str(v).unwrap());
        let res = app.call(req).await.unwrap();
        let cs = res.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(cs, CacheStatus::Bypass(CacheBypassReason::CacheControl));
    }

    // Check cache flushing
    cache.clear().unwrap();
    assert_eq!(cache.len(), 0);

    let req = gen_request(CANISTER_1, false);
    let res = app.call(req).await.unwrap();
    let cs = res.extensions().get::<CacheStatus>().cloned().unwrap();
    assert_eq!(cs, CacheStatus::Miss);

    let req = gen_request(CANISTER_2, false);
    let res = app.call(req).await.unwrap();
    let cs = res.extensions().get::<CacheStatus>().cloned().unwrap();
    assert_eq!(cs, CacheStatus::Miss);

    // Check too big requests
    cache.clear().unwrap();
    let req = gen_request_with_params(CANISTER_1, false, MAX_RESP_SIZE, 0, true);
    let res = app.call(req).await.unwrap();
    let cs = res.extensions().get::<CacheStatus>().cloned().unwrap();
    assert_eq!(cs, CacheStatus::Miss);

    cache.clear().unwrap();
    let req = gen_request_with_params(CANISTER_1, false, MAX_RESP_SIZE + 1, 0, true);
    let res = app.call(req).await.unwrap();
    let cs = res.extensions().get::<CacheStatus>().cloned().unwrap();
    assert_eq!(cs, CacheStatus::Bypass(CacheBypassReason::TooBig));

    // Check memory limits
    cache.clear().unwrap();
    let max_items = MAX_MEM_SIZE / MAX_RESP_SIZE;

    for i in 0..max_items + 1 {
        let req = gen_request_with_params(CANISTER_1, false, MAX_RESP_SIZE, i as u64, true);
        let res = app.call(req).await.unwrap();
        let cs = res.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(cs, CacheStatus::Miss);
    }

    // Make sure that some of the entries were evicted
    assert!(cache.len() < max_items);

    Ok(())
}
