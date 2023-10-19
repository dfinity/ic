use super::*;

use axum::{
    body::Body, http::Request, middleware, response::IntoResponse, routing::method_routing::post,
    Router,
};
use candid::Encode;
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

// pass canister id from request to response
async fn handler(Extension(canister_id): Extension<CanisterId>) -> impl IntoResponse {
    (Extension(canister_id), "foobaz")
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
    let canister_id = res.extensions().get::<CanisterId>().cloned().unwrap();
    assert_eq!(canister_id, MANAGEMENT_CANISTER_ID_PRINCIPAL);

    // Check non-management canister, shouldn't change it
    let canister_id = CanisterId::from_str("sqjm4-qahae-aq").unwrap();
    let req = gen_req(
        canister_id,
        BitcoinNetwork::Testnet,
        QueryMethod::BitcoinGetUtxosQuery.to_string(),
    );
    let res = app.call(req).await.unwrap();
    let canister_id_out = res.extensions().get::<CanisterId>().cloned().unwrap();
    assert_eq!(canister_id, canister_id_out);

    Ok(())
}
