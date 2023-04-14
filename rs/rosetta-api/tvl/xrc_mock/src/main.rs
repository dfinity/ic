use candid::candid_method;
use ic_cdk_macros::init;
use ic_xrc_types::{
    Asset, AssetClass, ExchangeRate, ExchangeRateMetadata, GetExchangeRateRequest,
    GetExchangeRateResult,
};
use xrc_mock::XrcMockInitPayload;

use std::cell::RefCell;

fn main() {}

#[ic_cdk_macros::update]
#[candid_method(update)]
async fn get_exchange_rate(_request: GetExchangeRateRequest) -> GetExchangeRateResult {
    RESPONSE.with(
        |cell| match cell.borrow().as_ref().expect("Response has not been set") {
            xrc_mock::Response::ExchangeRate(rate) => GetExchangeRateResult::Ok(ExchangeRate {
                base_asset: rate.base_asset.clone().unwrap_or_else(|| Asset {
                    symbol: "ICP".into(),
                    class: AssetClass::Cryptocurrency,
                }),
                quote_asset: rate.quote_asset.clone().unwrap_or_else(|| Asset {
                    symbol: "USD".into(),
                    class: AssetClass::FiatCurrency,
                }),
                // Add 6 to the timestamp to differentiate from the governance canister time.
                timestamp: (ic_cdk::api::time() / 1_000_000_000) + 6,
                rate: rate.rate,
                metadata: rate.metadata.clone().unwrap_or(ExchangeRateMetadata {
                    decimals: 8,
                    base_asset_num_received_rates: 0,
                    base_asset_num_queried_sources: 0,
                    quote_asset_num_received_rates: 0,
                    quote_asset_num_queried_sources: 0,
                    standard_deviation: 0,
                    forex_timestamp: None,
                }),
            }),
            xrc_mock::Response::Error(error) => GetExchangeRateResult::Err(error.clone()),
        },
    )
}

thread_local! {
    static RESPONSE: RefCell<Option<xrc_mock::Response>> = RefCell::new(None);
}

#[init]
fn init(args: XrcMockInitPayload) {
    RESPONSE.with(|response| response.replace(Some(args.response)));
}
