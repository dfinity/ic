use super::*;

use anyhow::Error;
use axum::{
    body::Body, http::Request, middleware, response::IntoResponse, routing::method_routing::post,
    Router,
};
use http::StatusCode;
use tower::Service;

// pass canister id from request to response
async fn handler() -> impl IntoResponse {
    "foobaz"
}

fn gen_req_ledger(method: String) -> Request<Body> {
    let mut req = Request::post("/").body(Body::from("foobar")).unwrap();

    let ctx = RequestContext {
        request_type: RequestType::Call,
        method_name: Some(method),
        arg: None,
        ..Default::default()
    };
    let ctx = Arc::new(ctx);

    req.extensions_mut().insert(ctx);
    req.extensions_mut().insert(*LEDGER_CANISTER_ID);

    req
}

#[tokio::test]
async fn test_ledger_transfer_ratelimit() -> Result<(), Error> {
    let state = Arc::new(LedgerRatelimitState::new(2));

    let mut app = Router::new()
        .route("/", post(handler))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            ledger_ratelimit_transfer_mw,
        ));

    // Check non-transfer calls (not rate limited)
    for _ in 1..20 {
        let req = gen_req_ledger("foobar".into());
        let res = app.call(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    // Check transfer calls (rate limited)
    for m in LEDGER_METHODS_TRANSFER {
        // Refill the tokens
        state.reset();

        for _ in 0..2 {
            let req = gen_req_ledger(m.into());
            let res = app.call(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
        }

        for _ in 0..5 {
            let req = gen_req_ledger(m.into());
            let res = app.call(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
        }

        // Refill the tokens
        state.reset();

        let req = gen_req_ledger(m.into());
        let res = app.call(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    Ok(())
}
