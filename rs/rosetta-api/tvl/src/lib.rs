mod memory;
pub mod metrics;
mod state;
pub mod types;

use crate::memory::{FX_TIMESERIES, LOCKED_E8S_TIMESERIES, TVL_TIMESERIES};
use crate::types::{
    Asset, AssetClass, ExchangeRate, GetExchangeRateRequest, GetExchangeRateResult,
    GovernanceCachedMetrics, GovernanceError, InitArgs, TimeseriesEntry, TimeseriesResult,
    TvlResult, TvlResultError, TvlTimeseriesResult,
};
use candid::utils::{ArgumentDecoder, ArgumentEncoder};
use candid::Nat;
use candid::Principal;
use ic_cdk_timers::set_timer_interval;
use state::TvlState;
use std::cell::RefCell;
use std::time::Duration;

const NANO: u64 = 1_000_000_000;

const E8S: u64 = 100_000_000;

// We query XRC data slightly in the past to be sure to have a price with consensus.
const XRC_MARGIN_SEC: u64 = 5 * 60;
// The payment required for querying the XRC canister.
const XRC_CALL_COST_CYCLES: u64 = 10_000_000_000;

thread_local! {
    static STATE: RefCell<Option<TvlState>> = RefCell::new(None);
}

pub fn init(args: InitArgs) {
    ic_cdk::println!("Initializing TVL canister...");
    init_state(args);
    start_tvl_updater();
}

pub async fn post_upgrade(args: Option<InitArgs>) {
    if let Some(upgrade_args) = args {
        // Allows to change XRC and/or governance canister reference as well as update delay.
        init_state(upgrade_args);
    }
    // Timers have to be restarted after canister upgrade.
    start_tvl_updater();
}

fn init_state(args: InitArgs) {
    STATE.with(|cell| {
        cell.replace(Some(TvlState {
            governance_principal: args.governance_id.get(),
            xrc_principal: args.xrc_id.get(),
            update_period: args.update_period,
        }))
    });
}

/// Start a recurring update of TVL values.
fn start_tvl_updater() {
    STATE.with(|s| {
        let _id = set_timer_interval(
            Duration::from_secs(s.borrow().as_ref().expect("State not set").update_period),
            || ic_cdk::spawn(call_update_tvl()),
        );
    });
}

async fn call_update_tvl() {
    let cur_time = ic_cdk::api::time() / NANO;
    ic_cdk::api::print(format!("[{}] Updating TVL...", cur_time));
    if let Err(e) = update_tvl().await {
        ic_cdk::println!("Cannot update TVL: {}", e.message);
    }
}

/// Retrieve last data from timeseries. Perform a TVL update if none is present.
pub async fn get_tvl() -> Result<TvlResult, TvlResultError> {
    ic_cdk::println!("Getting last TVL");
    let last: Option<TvlResult> = TVL_TIMESERIES.with(|map| {
        if let Some((time_sec, tvl)) = map.borrow().iter().last() {
            Some(TvlResult {
                time_sec: Nat::from(time_sec),
                tvl: Nat::from(tvl),
            })
        } else {
            None
        }
    });

    if let Some(tvl) = last {
        return Ok(tvl);
    }
    // If no result is available yet, update TVL now.
    update_tvl().await
}

/// Return the timeseries of TVL stored in stable memory.
pub async fn get_tvl_timeseries() -> TvlTimeseriesResult {
    ic_cdk::println!("Getting TVL timeseries");
    let mut timeseries = vec![];
    TVL_TIMESERIES.with(|map| {
        for (time_sec, tvl) in map.borrow().iter() {
            timeseries.push(TvlResult {
                time_sec: Nat::from(time_sec),
                tvl: Nat::from(tvl),
            });
        }
    });
    TvlTimeseriesResult { timeseries }
}

/// Return the timeseries of exchange rates stored in stable memory.
pub async fn get_xr_timeseries() -> TimeseriesResult {
    ic_cdk::println!("Getting exchange rate timeseries");
    let mut timeseries = vec![];
    FX_TIMESERIES.with(|map| {
        for (time_sec, tvl) in map.borrow().iter() {
            timeseries.push(TimeseriesEntry {
                time_sec: Nat::from(time_sec),
                value: Nat::from(tvl),
            });
        }
    });
    TimeseriesResult { timeseries }
}

/// Return the timeseries of exchange rates stored in stable memory.
pub async fn get_locked_e8s_timeseries() -> TimeseriesResult {
    ic_cdk::println!("Getting locked e8s timeseries");
    let mut timeseries = vec![];
    LOCKED_E8S_TIMESERIES.with(|map| {
        for (time_sec, tvl) in map.borrow().iter() {
            timeseries.push(TimeseriesEntry {
                time_sec: Nat::from(time_sec),
                value: Nat::from(tvl),
            });
        }
    });
    TimeseriesResult { timeseries }
}

/// Update the TVL timeseries by using data from XRC and Governance canisters.
async fn update_tvl() -> Result<TvlResult, TvlResultError> {
    // Parallel calls to XRC and Governance canisters.
    let f_res_xrc = get_exchange_rate();
    let f_res_gov = get_metrics();
    let (res_xrc, res_gov) = futures::future::join(f_res_xrc, f_res_gov).await;

    if res_gov.is_err() {
        return Err(TvlResultError {
            message: String::from("Cannot retrieve locked neurons."),
        });
    }
    let metrics = res_gov.unwrap();
    store_locked_e8s(&metrics);

    if res_xrc.is_err() {
        return Err(TvlResultError {
            message: String::from("Cannot retrieve exchange rate."),
        });
    }
    let res_xrc = res_xrc.unwrap();
    match res_xrc {
        GetExchangeRateResult::Ok(xr) => {
            store_exchange_rate(&xr);

            // We can insert one data per day (per metrics) or one per received xr.
            let time_sec = xr.timestamp;
            // let time_sec = metrics.timestamp_seconds;

            let decimals = u64::pow(10, xr.metadata.decimals);

            let total_locked_e8s = metrics.total_locked_e8s;
            let total_locked_icp = total_locked_e8s / E8S;

            let tvl = total_locked_icp * xr.rate / decimals;

            ic_cdk::println!(
                "Storing TVL {} from ICP: {}, and exchange rate: {} (decimals: {})",
                tvl,
                total_locked_icp,
                xr.rate,
                decimals
            );

            // Store TVL timeseries.
            store_tvl(time_sec, tvl);

            Ok(TvlResult {
                time_sec: Nat::from(time_sec),
                tvl: Nat::from(tvl),
            })
        }
        GetExchangeRateResult::Err(xre) => Err(TvlResultError {
            message: format!("Error while retrieving exchange rate: {:?}", xre),
        }),
    }
}

/// Store exchange rate in stable memory.
fn store_exchange_rate(xr: &ExchangeRate) {
    FX_TIMESERIES.with(|m| {
        let mut map = m.borrow_mut();
        let _ = map.insert(xr.timestamp, xr.rate);
    });
}

/// Store total locked e8s in stable memory.
fn store_locked_e8s(metrics: &GovernanceCachedMetrics) {
    LOCKED_E8S_TIMESERIES.with(|m| {
        let mut map = m.borrow_mut();
        let _ = map.insert(metrics.timestamp_seconds, metrics.total_locked_e8s);
    });
}

/// Store total value locked (in USD) in stable memory.
fn store_tvl(timestamp: u64, tvl_e8s: u64) {
    TVL_TIMESERIES.with(|m| {
        let mut map = m.borrow_mut();
        let _ = map.insert(timestamp, tvl_e8s);
    });
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
    let timestamp_sec = ic_cdk::api::time() / NANO - XRC_MARGIN_SEC;

    // Retrieve last ICP/USD value.
    let args = GetExchangeRateRequest {
        base_asset: icp,
        quote_asset: usd,
        timestamp: Some(timestamp_sec),
    };

    let xrc_id = STATE.with(|s| s.borrow().as_ref().expect("State not set").xrc_principal);

    ic_cdk::println!("Calling XRC canister ({})", xrc_id);
    let res_xrc: Result<(GetExchangeRateResult,), (i32, String)> =
        call_with_payment(xrc_id.0, "get_exchange_rate", (args,), XRC_CALL_COST_CYCLES).await;
    match res_xrc {
        Ok((xr,)) => {
            // ic_cdk::println!("XRC call result: {:?}", xr);
            Ok(xr)
        }
        Err((code, msg)) => Err(format!(
            "Error while calling XRC canister ({}): {:?}",
            code, msg
        )),
    }
}

/// Retrieve the metrics from the Governance canister.
async fn get_metrics() -> Result<GovernanceCachedMetrics, GovernanceError> {
    let gov_id = STATE.with(|s| {
        s.borrow()
            .as_ref()
            .expect("State not set")
            .governance_principal
    });
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

async fn call_with_payment<In, Out>(
    id: Principal,
    method: &str,
    args: In,
    cycles: u64,
) -> Result<Out, (i32, String)>
where
    In: ArgumentEncoder + Send,
    Out: for<'a> ArgumentDecoder<'a>,
{
    ic_cdk::api::call::call_with_payment(id, method, args, cycles)
        .await
        .map_err(|(code, msg)| (code as i32, msg))
}
