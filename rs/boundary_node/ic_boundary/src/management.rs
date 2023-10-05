use anyhow::{anyhow, Context, Error};
use axum::{body::Body, middleware::Next, response::IntoResponse, Extension};
use candid::{CandidType, Decode, Principal};
use http::Request;
use ic_btc_interface::{Network as BitcoinNetwork, NetworkInRequest};
use ic_ic00_types::QueryMethod;
use serde::Deserialize;

use crate::routes::{ApiError, ErrorCause, RequestContext};

pub async fn btc_mw(
    Extension((
        mgmt_id,    // management canister id
        testnet_id, // testnet btc canister id
        mainnet_id, // mainnet btc canister id
    )): Extension<(Principal, Principal, Principal)>,
    Extension(ctx): Extension<RequestContext>,
    mut request: Request<Body>,
    next: Next<Body>,
) -> Result<impl IntoResponse, ApiError> {
    let is_match = |ctx: &RequestContext| {
        let (id, method) = match (ctx.canister_id, ctx.method_name.clone()) {
            (Some(id), Some(method)) => (id, method),
            _ => return false,
        };

        // Check canister ID
        if id != mgmt_id {
            return false;
        }

        // Check canister method
        [
            QueryMethod::BitcoinGetBalanceQuery.to_string(),
            QueryMethod::BitcoinGetUtxosQuery.to_string(),
        ]
        .contains(&method)
    };

    if is_match(&ctx) {
        let id = match extract_btc_network(&ctx) {
            Ok(BitcoinNetwork::Mainnet) => Ok(mainnet_id),
            Ok(BitcoinNetwork::Testnet) => Ok(testnet_id),
            Ok(n) => Err(ApiError::ProxyError(ErrorCause::MalformedRequest(format!(
                "invalid network {n}"
            )))),
            Err(err) => Err(ApiError::ProxyError(ErrorCause::Other(format!(
                "failed to extract btc network {err}"
            )))),
        }?;

        request.extensions_mut().insert(RequestContext {
            canister_id: Some(id),
            ..ctx
        });
    }

    Ok(next.run(request).await)
}

#[derive(CandidType, Deserialize)]
struct BitcoinNetworkRecord {
    network: NetworkInRequest,
}

fn extract_btc_network(ctx: &RequestContext) -> Result<BitcoinNetwork, Error> {
    let arg = ctx.arg.as_ref().ok_or_else(|| anyhow!("missing arg"))?;
    let r = Decode!(arg, BitcoinNetworkRecord).context("failed to decode arg")?;

    Ok(r.network.into())
}
