use std::{str::FromStr, sync::Arc, time::Duration};

use axum::{body::Body, extract::State, middleware::Next, response::IntoResponse, Extension};
use http::Request;
use ic_types::CanisterId;
use lazy_static::lazy_static;
use ratelimit::Ratelimiter;

use crate::routes::{ApiError, ErrorCause, RateLimitCause, RequestContext, RequestType};

const LEDGER_METHODS_TRANSFER: [&str; 4] = [
    "transfer",
    "icrc1_transfer",
    "icrc2_transfer_from",
    "icrc2_approve",
];

lazy_static! {
    static ref LEDGER_CANISTER_ID: CanisterId =
        CanisterId::from_str("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap();
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
