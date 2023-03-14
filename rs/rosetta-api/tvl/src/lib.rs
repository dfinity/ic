use crate::memory::push_entry;
use crate::memory::{get_last_icp_price_ts, get_last_locked_icp_ts, EntryType, TVL_TIMESERIES};
use crate::state::{mutate_state, read_state, replace_state};
use crate::types::{
    Asset, AssetClass, GetExchangeRateRequest, GetExchangeRateResult, GovernanceCachedMetrics,
    GovernanceError, TvlArgs, TvlResult, TvlResultError,
};
use candid::utils::{ArgumentDecoder, ArgumentEncoder};
use candid::Nat;
use candid::Principal;
use state::TvlState;
use std::time::Duration;

mod memory;
pub mod metrics;
mod state;
pub mod types;

const SEC_NANOS: u64 = 1_000_000_000;
const E8S: u64 = 100_000_000;

// We query XRC data slightly in the past to be sure to have a price with consensus.
const XRC_MARGIN_SEC: u64 = 5 * 60;

pub fn init(args: TvlArgs) {
    init_state(args);
    init_timers();
}

pub async fn post_upgrade(args: TvlArgs) {
    init_state(args);
    mutate_state(|s| {
        s.last_ts_icp_price = get_last_icp_price_ts();
        s.last_ts_icp_locked = get_last_locked_icp_ts();
    });
    // Timers have to be restarted after canister upgrade.
    init_timers();
}

fn init_state(args: TvlArgs) {
    replace_state(TvlState {
        governance_principal: args.governance_id.get(),
        xrc_principal: args.xrc_id.get(),
        update_period: args.update_period,
        last_ts_icp_price: 0,
        last_ts_icp_locked: 0,
    });
}

pub fn init_timers() {
    let update_period = read_state(|s| s.update_period);

    ic_cdk_timers::set_timer_interval(Duration::from_secs(update_period), || {
        ic_cdk::spawn(async {
            update_icp_price().await;
        })
    });
    ic_cdk_timers::set_timer_interval(Duration::from_secs(update_period), || {
        ic_cdk::spawn(async {
            update_locked_amount().await;
        });
    });
}

/// Retrieve last data from timeseries. Perform a TVL update if none is present.
pub async fn get_tvl() -> Result<TvlResult, TvlResultError> {
    TVL_TIMESERIES.with(|map| {
        let (last_ts_icp_price, last_ts_icp_locked) =
            read_state(|s| (s.last_ts_icp_price, s.last_ts_icp_locked));

        if let Some(price) = map
            .borrow()
            .get(&(last_ts_icp_price, crate::memory::EntryType::ICPrice as u32))
        {
            if let Some(locked_amount) = map.borrow().get(&(
                last_ts_icp_locked,
                crate::memory::EntryType::LockedIcp as u32,
            )) {
                let lock_amount_f64 = (locked_amount / E8S) as f64;
                let price_f64 = (price / E8S) as f64;
                let tvl = Nat::from((price_f64 * lock_amount_f64) as u64);

                return Ok(TvlResult {
                    time_sec: Nat::from(last_ts_icp_price),
                    tvl,
                });
            }
            return Err(TvlResultError {
                message: "No ICP locked amount entry.".into(),
            });
        }
        Err(TvlResultError {
            message: "No ICP price entry.".into(),
        })
    })
}

fn convert_to_8_decimals(amount: u64, decimals: u32) -> u64 {
    if decimals >= 8 {
        // If there are at least 8 decimal places, divide by 10^(decimals - 8)
        // to shift the decimal point to the left.
        amount / 10u64.pow(decimals - 8)
    } else {
        // If there are fewer than 8 decimal places, multiply by 10^(8 - decimals)
        // to shift the decimal point to the right.
        amount * 10u64.pow(8 - decimals)
    }
}

pub async fn update_icp_price() -> Option<u64> {
    let xrc_result = get_exchange_rate().await;
    if let Ok(GetExchangeRateResult::Ok(xr)) = xrc_result {
        let time_sec = xr.timestamp;
        let icp_price = convert_to_8_decimals(xr.rate, xr.metadata.decimals);
        push_entry(time_sec, EntryType::ICPrice, icp_price);
        return Some(icp_price);
    }
    None
}

pub async fn update_locked_amount() -> Option<u64> {
    if let Ok(metrics) = get_metrics().await {
        ic_cdk::println!("{:?}", metrics);
        push_entry(
            ic_cdk::api::time(),
            EntryType::LockedIcp,
            metrics.total_locked_e8s,
        );
        return Some(metrics.total_locked_e8s);
    }
    None
}

/// Query the XRC canister to retrieve the last ICP/USD price.
async fn get_exchange_rate() -> Result<GetExchangeRateResult, String> {
    let icp = Asset {
        symbol: "ICP".to_string(),
        class: AssetClass::Cryptocurrency,
    };
    let usd = Asset {
        symbol: "USD".to_string(),
        class: AssetClass::FiatCurrency,
    };

    // Take few minutes back to be sure to have data.
    let timestamp_sec = ic_cdk::api::time() / SEC_NANOS - XRC_MARGIN_SEC;

    // Retrieve last ICP/USD value.
    let args = GetExchangeRateRequest {
        base_asset: icp,
        quote_asset: usd,
        timestamp: Some(timestamp_sec),
    };

    let xrc_id = read_state(|s| s.xrc_principal);

    ic_cdk::println!("Calling XRC canister ({})", xrc_id);
    let res_xrc: Result<(GetExchangeRateResult,), (i32, String)> =
        call(xrc_id.0, "get_exchange_rate", (args,)).await;
    ic_cdk::println!("{:?}", res_xrc);
    match res_xrc {
        Ok((xr,)) => Ok(xr),
        Err((code, msg)) => Err(format!(
            "Error while calling XRC canister ({}): {:?}",
            code, msg
        )),
    }
}

/// Retrieve the metrics from the Governance canister.
async fn get_metrics() -> Result<GovernanceCachedMetrics, GovernanceError> {
    let gov_id = read_state(|s| s.governance_principal);
    ic_cdk::println!("Calling Governance canister ({})", gov_id);
    let res_gov: (Result<GovernanceCachedMetrics, GovernanceError>,) =
        call(gov_id.0, "get_metrics", ())
            .await
            .expect("Error while calling Governance canister");
    ic_cdk::println!("Governance call result: {:?}", res_gov);
    res_gov.0
}

async fn call<In, Out>(id: Principal, method: &str, args: In) -> Result<Out, (i32, String)>
where
    In: ArgumentEncoder + Send,
    Out: for<'a> ArgumentDecoder<'a>,
{
    ic_cdk::call(id, method, args)
        .await
        .map_err(|(code, msg)| (code as i32, msg))
}
