use crate::memory::push_entry;
use crate::memory::{EntryType, TVL_TIMESERIES};
use crate::state::{mutate_state, read_state, replace_state};
use crate::types::{
    Asset, AssetClass, GetExchangeRateRequest, GetExchangeRateResult, GovernanceCachedMetrics,
    GovernanceError, TvlArgs, TvlResult, TvlResultError,
};
use candid::utils::{ArgumentDecoder, ArgumentEncoder};
use candid::{CandidType, Nat, Principal};
use ic_base_types::PrincipalId;
use state::TvlState;
use std::str::FromStr;
use std::time::Duration;

pub mod dashboard;
mod memory;
pub mod metrics;
mod state;
pub mod types;

const SEC_NANOS: u64 = 1_000_000_000;
const E8S: u64 = 100_000_000;
// By default we update data four times a day.
pub const DEFAULT_UPDATE_PERIOD: u64 = 60 * 60 * 6;
pub const ONE_DAY: Duration = Duration::from_secs(24 * 60 * 60);
const DEFAULT_GOVERNANCE_PRINCIPAL: &str = "rrkah-fqaaa-aaaaa-aaaaq-cai";
const DEFAULT_XRC_PRINCIPAL: &str = "uf6dk-hyaaa-aaaaq-qaaaq-cai";

// We query XRC data slightly in the past to be sure to have a price with consensus.
const XRC_MARGIN_SEC: u64 = 5 * 60;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, CandidType, candid::Deserialize)]
pub enum FiatCurrency {
    USD,
    EUR,
    CNY,
    JPY,
    GBP,
}

impl std::fmt::Display for FiatCurrency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                FiatCurrency::USD => "USD",
                FiatCurrency::EUR => "EUR",
                FiatCurrency::CNY => "CNY",
                FiatCurrency::JPY => "JPY",
                FiatCurrency::GBP => "GBP",
            }
        )
    }
}

pub const OTHER_CURRENCIES: [FiatCurrency; 4] = [
    FiatCurrency::EUR,
    FiatCurrency::CNY,
    FiatCurrency::JPY,
    FiatCurrency::GBP,
];

#[derive(Clone, Eq, PartialEq, Debug, CandidType, candid::Deserialize)]
pub struct TvlRequest {
    pub currency: FiatCurrency,
}

pub fn init(args: TvlArgs) {
    init_state(args);
    init_timers();
}

pub async fn post_upgrade(args: TvlArgs) {
    init_state(args);
    mutate_state(|s| {
        s.populate_state();
    });
    // Timers have to be restarted after canister upgrade.
    init_timers();
}

fn init_state(args: TvlArgs) {
    replace_state(TvlState {
        governance_principal: args
            .governance_id
            .unwrap_or_else(|| PrincipalId::from_str(DEFAULT_GOVERNANCE_PRINCIPAL).unwrap()),
        xrc_principal: args
            .xrc_id
            .unwrap_or_else(|| PrincipalId::from_str(DEFAULT_XRC_PRINCIPAL).unwrap()),
        update_period: Duration::from_secs(args.update_period.unwrap_or(DEFAULT_UPDATE_PERIOD)),
        last_icp_rate: 0,
        last_icp_rate_ts: 0,
        last_icp_locked: 0,
        last_icp_locked_ts: 0,
        exchange_rate: Default::default(),
        currencies_to_fetch: Default::default(),
    });
}

pub fn init_timers() {
    let update_period = read_state(|s| s.update_period);

    ic_cdk_timers::set_timer_interval(update_period, || {
        ic_cdk::spawn(async {
            update_icp_price().await;
        })
    });
    ic_cdk_timers::set_timer_interval(update_period, || {
        ic_cdk::spawn(async {
            update_locked_amount().await;
        });
    });
    ic_cdk_timers::set_timer_interval(ONE_DAY, || {
        ic_cdk::spawn(async {
            let is_currencies_to_fetch_empty = read_state(|s| s.currencies_to_fetch.is_empty());
            mutate_state(|s| {
                for currency in OTHER_CURRENCIES {
                    s.currencies_to_fetch.insert(currency);
                }
            });
            if is_currencies_to_fetch_empty {
                update_fiat_rates().await;
            }
        });
    });
}

pub fn multiply_e8s(amount: u64, rate: u64) -> u64 {
    const E8_FACTOR: u128 = 10_u128.pow(8); // 10^8

    let amount_u128 = amount as u128;
    let rate_u128 = rate as u128;
    let result_u128 = amount_u128 * rate_u128 / E8_FACTOR;
    result_u128 as u64
}

/// Retrieve last data from timeseries. Perform a TVL update if none is present.
pub async fn get_tvl(req: Option<TvlRequest>) -> Result<TvlResult, TvlResultError> {
    let (last_icp_rate, last_icp_locked) = read_state(|s| (s.last_icp_rate, s.last_icp_locked));
    let tvl = multiply_e8s(last_icp_rate, last_icp_locked);
    if let Some(req) = req {
        let currency = req.currency;
        match read_state(|s| s.exchange_rate.get(&currency).cloned()) {
            Some(rate) => {
                return Ok(TvlResult {
                    time_sec: Nat::from(read_state(|s| s.last_icp_rate_ts)),
                    tvl: Nat::from(multiply_e8s(tvl, rate) / E8S),
                });
            }
            None => {
                return Err(TvlResultError {
                    message: format!("No {} entry yet.", currency),
                });
            }
        }
    }

    Ok(TvlResult {
        time_sec: Nat::from(read_state(|s| s.last_icp_rate_ts)),
        tvl: Nat::from(tvl / E8S),
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
    let icp = Asset {
        symbol: "ICP".to_string(),
        class: AssetClass::Cryptocurrency,
    };
    let usd = Asset {
        symbol: "USD".to_string(),
        class: AssetClass::FiatCurrency,
    };
    let xrc_result = get_exchange_rate(icp, usd).await;
    if let Ok(GetExchangeRateResult::Ok(xr)) = xrc_result {
        let time_sec = xr.timestamp;
        let icp_price = convert_to_8_decimals(xr.rate, xr.metadata.decimals);
        push_entry(time_sec, EntryType::ICPrice, icp_price);
        return Some(icp_price);
    }
    None
}

pub async fn update_fiat_rates() {
    let fiat_currencies = read_state(|s| {
        s.currencies_to_fetch
            .iter()
            .cloned()
            .collect::<Vec<FiatCurrency>>()
    });
    let base_asset = Asset {
        symbol: "USD".to_string(),
        class: AssetClass::FiatCurrency,
    };
    for currency in fiat_currencies {
        ic_cdk::println!("Fetching rate for currency: {:?}", currency);
        let quote_asset = Asset {
            symbol: currency.to_string(),
            class: AssetClass::FiatCurrency,
        };
        let xrc_result = get_exchange_rate(base_asset.clone(), quote_asset.clone()).await;
        if let Ok(GetExchangeRateResult::Ok(xr)) = xrc_result {
            if xr.quote_asset != quote_asset || xr.base_asset != base_asset.clone() {
                continue;
            }

            let exchange_rate = convert_to_8_decimals(xr.rate, xr.metadata.decimals);
            let currency_clone = currency.clone();
            match currency_clone {
                FiatCurrency::EUR => {
                    push_entry(xr.timestamp, currency_clone.into(), exchange_rate);
                }
                FiatCurrency::CNY => {
                    push_entry(xr.timestamp, currency_clone.into(), exchange_rate);
                }
                FiatCurrency::JPY => {
                    push_entry(xr.timestamp, currency_clone.into(), exchange_rate);
                }
                FiatCurrency::GBP => {
                    push_entry(xr.timestamp, currency_clone.into(), exchange_rate);
                }
                _ => continue,
            }
            mutate_state(|s| {
                s.currencies_to_fetch.remove(&currency);
                s.exchange_rate
                    .entry(currency)
                    .and_modify(|curr| *curr = exchange_rate)
                    .or_insert(exchange_rate);
            });
        }
    }
    if read_state(|s| !s.currencies_to_fetch.is_empty()) {
        ic_cdk_timers::set_timer(Duration::from_secs(0), || {
            ic_cdk::spawn(async {
                update_fiat_rates().await;
            });
        });
    }
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
async fn get_exchange_rate(
    base_asset: Asset,
    quote_asset: Asset,
) -> Result<GetExchangeRateResult, String> {
    // Take few minutes back to be sure to have data.
    let timestamp_sec = ic_cdk::api::time() / SEC_NANOS - XRC_MARGIN_SEC;

    // Retrieve last ICP/USD value.
    let args = GetExchangeRateRequest {
        base_asset,
        quote_asset,
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
