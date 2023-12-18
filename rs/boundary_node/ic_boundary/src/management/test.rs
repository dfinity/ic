use super::*;

use axum::{
    body::Body, http::Request, middleware, response::IntoResponse, routing::method_routing::post,
    Router,
};
use candid::{Encode, Nat};
use http::StatusCode;
use icrc_ledger_types::icrc1::account::Account;
use std::str::FromStr;
use tower::Service;

fn gen_req(canister_id: CanisterId, network: BitcoinNetwork, method: String) -> Request<Body> {
    let mut req = Request::post("/").body(Body::from("foobar")).unwrap();

    let network = BitcoinNetworkRecord {
        network: network.into(),
    };

    let ctx = RequestContext {
        method_name: Some(method),
        arg: Encode!(&network).ok(),
        ..Default::default()
    };

    req.extensions_mut().insert(ctx);
    req.extensions_mut().insert(canister_id);

    req
}

fn gen_req_ledger(request_type: RequestType) -> Request<Body> {
    let mut req = Request::post("/").body(Body::from("foobar")).unwrap();

    let ctx = RequestContext {
        request_type,
        ..Default::default()
    };

    req.extensions_mut().insert(ctx);
    req.extensions_mut().insert(*LEDGER_CANISTER_ID);

    req
}

fn gen_req_ledger_transfer(method: String, memo: String) -> Request<Body> {
    let mut req = Request::post("/").body(Body::from("foobar")).unwrap();

    let transfer = TransferArg {
        from_subaccount: None,
        to: Account::from_str("sqjm4-qahae-aq").unwrap(),
        memo: Some(Memo::from(memo.as_bytes().to_vec())),
        fee: None,
        created_at_time: None,
        amount: Nat::from(0),
    };

    let ctx = RequestContext {
        request_type: RequestType::Call,
        method_name: Some(method),
        arg: Encode!(&transfer).ok(),
        ..Default::default()
    };

    req.extensions_mut().insert(ctx);
    req.extensions_mut().insert(*LEDGER_CANISTER_ID);

    req
}

// pass canister id from request to response
async fn handler() -> impl IntoResponse {
    "foobaz"
}

#[tokio::test]
async fn test_btc_mw() -> Result<(), Error> {
    let mut app = Router::new()
        .route("/", post(handler))
        .layer(middleware::from_fn(btc_mw));

    // Check mainnet/method1
    let req = gen_req(
        MANAGEMENT_CANISTER_ID_PRINCIPAL,
        BitcoinNetwork::Mainnet,
        QueryMethod::BitcoinGetBalanceQuery.to_string(),
    );
    let res = app.call(req).await.unwrap();
    let canister_id = res.extensions().get::<CanisterId>().cloned().unwrap();
    assert_eq!(canister_id, *BITCOIN_MAINNET_CANISTER_ID_PRINCIPAL);

    // Check testnet/method2
    let req = gen_req(
        MANAGEMENT_CANISTER_ID_PRINCIPAL,
        BitcoinNetwork::Testnet,
        QueryMethod::BitcoinGetUtxosQuery.to_string(),
    );
    let res = app.call(req).await.unwrap();
    let canister_id = res.extensions().get::<CanisterId>().cloned().unwrap();
    assert_eq!(canister_id, *BITCOIN_TESTNET_CANISTER_ID_PRINCIPAL);

    // Check invalid network
    let req = gen_req(
        MANAGEMENT_CANISTER_ID_PRINCIPAL,
        BitcoinNetwork::Regtest,
        QueryMethod::BitcoinGetUtxosQuery.to_string(),
    );
    let res = app.call(req).await.unwrap();
    let error_cause = res.extensions().get::<ErrorCause>().cloned().unwrap();
    assert!(matches!(error_cause, ErrorCause::MalformedRequest(_)));

    // Check some other method, shouldn't change canister id
    let req = gen_req(
        MANAGEMENT_CANISTER_ID_PRINCIPAL,
        BitcoinNetwork::Regtest,
        "foobar".to_string(),
    );
    let res = app.call(req).await.unwrap();
    let canister_id = res.extensions().get::<CanisterId>();
    assert!(canister_id.is_none());

    // Check non-management canister, shouldn't change it
    let canister_id = CanisterId::from_str("sqjm4-qahae-aq").unwrap();
    let req = gen_req(
        canister_id,
        BitcoinNetwork::Testnet,
        QueryMethod::BitcoinGetUtxosQuery.to_string(),
    );
    let res = app.call(req).await.unwrap();
    let canister_id_out = res.extensions().get::<CanisterId>();
    assert!(canister_id_out.is_none());

    Ok(())
}

#[tokio::test]
async fn test_ledger_ratelimit() -> Result<(), Error> {
    let state = Arc::new(LedgerRatelimitState::new(2));

    let mut app = Router::new()
        .route("/", post(handler))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            ledger_ratelimit_mw,
        ));

    // Check non-ledger calls (not rate limited)
    for _ in 1..20 {
        let req = gen_req_ledger(RequestType::Query);
        let res = app.call(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    // Check ledger calls (rate limited)
    // Refill the tokens to max
    state.reset();

    let req = gen_req_ledger(RequestType::Call);
    let res = app.call(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let req = gen_req_ledger(RequestType::Call);
    let res = app.call(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let req = gen_req_ledger(RequestType::Call);
    let res = app.call(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);

    let req = gen_req_ledger(RequestType::Call);
    let res = app.call(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);

    // Refill the tokens to max
    state.reset();

    let req = gen_req_ledger(RequestType::Call);
    let res = app.call(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    Ok(())
}

#[tokio::test]
async fn test_ledger_ratelimit_zero_transfer() -> Result<(), Error> {
    let state = Arc::new(LedgerRatelimitState::new(2));

    let mut app = Router::new()
        .route("/", post(handler))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            ledger_ratelimit_transfer_mw,
        ));

    // Check non-transfer calls (not rate limited)
    for _ in 0..5 {
        let req = gen_req_ledger_transfer("foo".into(), "bar".into());
        let res = app.call(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    // Check transfer calls with other memo (not rate limited)
    for &m in LEDGER_METHODS_TRANSFER.iter() {
        for _ in 0..5 {
            let req = gen_req_ledger_transfer(m.into(), "bar".into());
            let res = app.call(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
        }
    }

    // Check tranfer calls zero amount (rate limited)
    for &m in LEDGER_METHODS_TRANSFER.iter() {
        // Refill the tokens to max
        state.reset();

        for _ in 0..2 {
            let req = gen_req_ledger_transfer(m.into(), LEDGER_MEMO_STRING.into());
            let res = app.call(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
        }

        for _ in 0..2 {
            let req = gen_req_ledger_transfer(m.into(), LEDGER_MEMO_STRING.into());
            let res = app.call(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
        }

        // Refill the tokens to max
        state.reset();

        let req = gen_req_ledger_transfer(m.into(), LEDGER_MEMO_STRING.into());
        let res = app.call(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    Ok(())
}
