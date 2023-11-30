use std::str::FromStr;

use anyhow::{anyhow, Context, Error};
use axum::{body::Body, middleware::Next, response::IntoResponse, Extension};
use candid::{CandidType, Decode};
use http::Request;
use ic_btc_interface::{Network as BitcoinNetwork, NetworkInRequest};
use ic_config::execution_environment::{BITCOIN_MAINNET_CANISTER_ID, BITCOIN_TESTNET_CANISTER_ID};
use ic_ic00_types::QueryMethod;
use ic_types::CanisterId;
use lazy_static::lazy_static;
use serde::Deserialize;

use crate::{
    core::MANAGEMENT_CANISTER_ID_PRINCIPAL,
    routes::{ApiError, ErrorCause, RequestContext},
};

lazy_static! {
    static ref BITCOIN_MAINNET_CANISTER_ID_PRINCIPAL: CanisterId =
        CanisterId::from_str(BITCOIN_MAINNET_CANISTER_ID).unwrap();
    static ref BITCOIN_TESTNET_CANISTER_ID_PRINCIPAL: CanisterId =
        CanisterId::from_str(BITCOIN_TESTNET_CANISTER_ID).unwrap();
    static ref BITCOIN_METHODS: [String; 2] = [
        QueryMethod::BitcoinGetBalanceQuery.to_string(),
        QueryMethod::BitcoinGetUtxosQuery.to_string(),
    ];
}

pub async fn btc_mw(
    Extension(ctx): Extension<RequestContext>,
    Extension(canister_id): Extension<CanisterId>,
    mut request: Request<Body>,
    next: Next<Body>,
) -> Result<impl IntoResponse, ApiError> {
    let is_match = |ctx: &RequestContext| {
        let method = match &ctx.method_name {
            Some(v) => v,
            None => return false,
        };

        // Check canister ID
        if canister_id != MANAGEMENT_CANISTER_ID_PRINCIPAL {
            return false;
        }

        // Check canister method
        (*BITCOIN_METHODS).contains(method)
    };

    if !is_match(&ctx) {
        return Ok(next.run(request).await);
    }

    let canister_id = match extract_btc_network(&ctx) {
        Ok(BitcoinNetwork::Mainnet) => Ok(*BITCOIN_MAINNET_CANISTER_ID_PRINCIPAL),
        Ok(BitcoinNetwork::Testnet) => Ok(*BITCOIN_TESTNET_CANISTER_ID_PRINCIPAL),
        Ok(n) => Err(ApiError::ProxyError(ErrorCause::MalformedRequest(format!(
            "invalid network {n}"
        )))),
        Err(err) => Err(ApiError::ProxyError(ErrorCause::MalformedRequest(format!(
            "failed to extract btc network: {err}"
        )))),
    }?;

    request.extensions_mut().insert(canister_id);
    let mut response = next.run(request).await;
    // Override the canister_id in the response to properly log it
    response.extensions_mut().insert(canister_id);

    Ok(response)
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

#[cfg(test)]
pub mod test;
