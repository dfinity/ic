use std::{str::FromStr, sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Error};
use axum::{body::Body, extract::State, middleware::Next, response::IntoResponse, Extension};
use candid::{CandidType, Decode};
use http::Request;
use ic_btc_interface::{Network as BitcoinNetwork, NetworkInRequest};
use ic_config::execution_environment::{BITCOIN_MAINNET_CANISTER_ID, BITCOIN_TESTNET_CANISTER_ID};
use ic_management_canister_types::QueryMethod;
use ic_types::CanisterId;
use lazy_static::lazy_static;
use ratelimit::Ratelimiter;
use serde::Deserialize;

use crate::{
    core::{decoder_config, MANAGEMENT_CANISTER_ID_PRINCIPAL},
    routes::{ApiError, ErrorCause, RateLimitCause, RequestContext, RequestType},
};

const LEDGER_METHODS_TRANSFER: [&str; 4] = [
    "transfer",
    "icrc1_transfer",
    "icrc2_transfer_from",
    "icrc2_approve",
];

lazy_static! {
    static ref BITCOIN_MAINNET_CANISTER_ID_PRINCIPAL: CanisterId =
        CanisterId::from_str(BITCOIN_MAINNET_CANISTER_ID).unwrap();
    static ref BITCOIN_TESTNET_CANISTER_ID_PRINCIPAL: CanisterId =
        CanisterId::from_str(BITCOIN_TESTNET_CANISTER_ID).unwrap();
    static ref BITCOIN_METHODS: [String; 2] = [
        QueryMethod::BitcoinGetBalanceQuery.to_string(),
        QueryMethod::BitcoinGetUtxosQuery.to_string(),
    ];
    static ref LEDGER_CANISTER_ID: CanisterId =
        CanisterId::from_str("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap();
}

pub async fn btc_mw(
    Extension(ctx): Extension<Arc<RequestContext>>,
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
    let r =
        Decode!([decoder_config()]; arg, BitcoinNetworkRecord).context("failed to decode arg")?;

    Ok(r.network.into())
}

fn is_ledger_call(ctx: &RequestContext, canister_id: &CanisterId) -> bool {
    ctx.request_type == RequestType::Call && *canister_id == *LEDGER_CANISTER_ID
}

fn is_ledger_call_transfer(ctx: &RequestContext, canister_id: &CanisterId) -> bool {
    if !is_ledger_call(ctx, canister_id) {
        return false;
    }

    ctx.method_name
        .as_ref()
        .map(|x| LEDGER_METHODS_TRANSFER.contains(&x.as_str()))
        == Some(true)
}

pub struct LedgerRatelimitState {
    limiter: Ratelimiter,
}

impl LedgerRatelimitState {
    pub fn new(rate_per_second: u32) -> Self {
        let interval = Duration::from_secs(1).checked_div(rate_per_second).unwrap();

        Self {
            limiter: Ratelimiter::builder(1, interval)
                .max_tokens(rate_per_second as u64)
                .initial_available(rate_per_second as u64)
                .build()
                .unwrap(),
        }
    }

    // For tests
    #[allow(dead_code)]
    pub fn reset(&self) {
        self.limiter
            .set_available(self.limiter.max_tokens())
            .unwrap()
    }
}

pub async fn ledger_ratelimit_transfer_mw(
    State(state): State<Arc<LedgerRatelimitState>>,
    Extension(ctx): Extension<Arc<RequestContext>>,
    Extension(canister_id): Extension<CanisterId>,
    request: Request<Body>,
    next: Next<Body>,
) -> Result<impl IntoResponse, ApiError> {
    // Check if we need to ratelimit this request
    if !is_ledger_call_transfer(&ctx, &canister_id) {
        return Ok(next.run(request).await);
    }

    // Try to obtain a token and fail with 429 if unable to
    if state.limiter.try_wait().is_err() {
        return Err(ErrorCause::RateLimited(RateLimitCause::LedgerTransfer).into());
    }

    Ok(next.run(request).await)
}

#[cfg(test)]
pub mod test;
