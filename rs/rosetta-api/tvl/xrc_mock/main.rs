use candid::{candid_method, CandidType};
use ic_base_types::CanisterId;
use ic_cdk_macros::init;
use std::cell::RefCell;

#[derive(CandidType, Debug, candid::Deserialize, PartialEq, Eq)]
pub struct InitArgs {
    pub governance_id: CanisterId,
    pub xrc_id: CanisterId,
    pub update_period: u64,
}

// XRC types.
#[derive(CandidType, Clone, Debug, candid::Deserialize, PartialEq, Eq)]
pub enum AssetClass {
    Cryptocurrency,
    FiatCurrency,
}

#[derive(CandidType, Clone, Debug, candid::Deserialize, PartialEq, Eq)]
pub struct Asset {
    pub symbol: String,
    pub class: AssetClass,
}

#[derive(CandidType, Clone, Debug, candid::Deserialize, PartialEq, Eq)]
pub struct GetExchangeRateRequest {
    pub base_asset: Asset,
    pub quote_asset: Asset,
    // An optional timestamp to get the rate for a specific time period.
    pub timestamp: Option<u64>,
}

#[derive(CandidType, Clone, Debug, candid::Deserialize, PartialEq, Eq)]
pub struct ExchangeRateMetadata {
    pub decimals: u32,
    pub base_asset_num_received_rates: u64,
    pub base_asset_num_queried_sources: u64,
    pub quote_asset_num_received_rates: u64,
    pub quote_asset_num_queried_sources: u64,
    pub standard_deviation: u64,
    pub forex_timestamp: Option<u64>,
}

#[derive(CandidType, Clone, Debug, candid::Deserialize, PartialEq, Eq)]
pub struct ExchangeRate {
    pub base_asset: Asset,
    pub quote_asset: Asset,
    pub timestamp: u64,
    pub rate: u64,
    pub metadata: ExchangeRateMetadata,
}

#[derive(CandidType, Clone, Debug, candid::Deserialize, PartialEq, Eq)]
pub struct ExchangeRateError {}

#[derive(CandidType, Clone, Debug, candid::Deserialize, PartialEq, Eq)]
pub enum GetExchangeRateResult {
    // Successfully retrieved the exchange rate from the cache or API calls.
    Ok(ExchangeRate),
    // Failed to retrieve the exchange rate due to invalid API calls, invalid timestamp, etc.
    Err(ExchangeRateError),
}

fn main() {}

#[ic_cdk_macros::update]
#[candid_method(update)]
async fn get_exchange_rate(_request: GetExchangeRateRequest) -> GetExchangeRateResult {
    GetExchangeRateResult::Ok(ExchangeRate {
        base_asset: Asset {
            symbol: "ICP".into(),
            class: AssetClass::Cryptocurrency,
        },
        quote_asset: Asset {
            symbol: "USD".into(),
            class: AssetClass::FiatCurrency,
        },
        timestamp: ic_cdk::api::time(),
        rate: PRICE.with(|price| *price.borrow()),
        metadata: ExchangeRateMetadata {
            decimals: 8,
            base_asset_num_received_rates: 0,
            base_asset_num_queried_sources: 0,
            quote_asset_num_received_rates: 0,
            quote_asset_num_queried_sources: 0,
            standard_deviation: 0,
            forex_timestamp: None,
        },
    })
}

thread_local! {
    static PRICE: RefCell<u64> = RefCell::new(0);
}

#[init]
fn init(init_price: u64) {
    PRICE.with(|price| *price.borrow_mut() = init_price)
}
