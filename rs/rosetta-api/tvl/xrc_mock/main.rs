use candid::{candid_method, CandidType};
use ic_base_types::CanisterId;
use ic_cdk_macros::init;
use ic_xrc_types::{
    Asset, AssetClass, ExchangeRate, ExchangeRateMetadata, GetExchangeRateRequest,
    GetExchangeRateResult,
};
use std::cell::RefCell;

#[derive(CandidType, Debug, candid::Deserialize, PartialEq, Eq)]
pub struct InitArgs {
    pub governance_id: CanisterId,
    pub xrc_id: CanisterId,
    pub update_period: u64,
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
        timestamp: ic_cdk::api::time() + 6,
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
