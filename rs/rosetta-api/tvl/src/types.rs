use candid::{CandidType, Nat};
use ic_base_types::PrincipalId;

#[derive(Eq, PartialEq, Debug, CandidType, candid::Deserialize)]
pub struct TvlArgs {
    pub governance_id: Option<PrincipalId>,
    pub xrc_id: Option<PrincipalId>,
    pub update_period: Option<u64>,
}

// Timeseries types.
#[derive(Eq, PartialEq, Debug, CandidType, candid::Deserialize)]
pub struct TimeseriesEntry {
    pub time_sec: Nat,
    pub value: Nat,
}

#[derive(Eq, PartialEq, Debug, CandidType, candid::Deserialize)]
pub struct TimeseriesResult {
    pub timeseries: Vec<TimeseriesEntry>,
}

// TVL types.
#[derive(Eq, PartialEq, Debug, CandidType, candid::Deserialize)]
pub struct TvlResultError {
    pub message: String,
}

#[derive(Eq, PartialEq, Debug, CandidType, candid::Deserialize)]
pub struct TvlResult {
    pub time_sec: Nat,
    pub tvl: Nat,
}

// XRC types.
#[derive(Clone, Eq, PartialEq, Debug, CandidType, candid::Deserialize)]
pub enum AssetClass {
    Cryptocurrency,
    FiatCurrency,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, candid::Deserialize)]
pub struct Asset {
    pub symbol: String,
    pub class: AssetClass,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, candid::Deserialize)]
pub struct GetExchangeRateRequest {
    pub base_asset: Asset,
    pub quote_asset: Asset,
    // An optional timestamp to get the rate for a specific time period.
    pub timestamp: Option<u64>,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, candid::Deserialize)]
pub struct ExchangeRateMetadata {
    pub decimals: u32,
    pub base_asset_num_received_rates: u64,
    pub base_asset_num_queried_sources: u64,
    pub quote_asset_num_received_rates: u64,
    pub quote_asset_num_queried_sources: u64,
    pub standard_deviation: u64,
    pub forex_timestamp: Option<u64>,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, candid::Deserialize)]
pub struct ExchangeRate {
    pub base_asset: Asset,
    pub quote_asset: Asset,
    pub timestamp: u64,
    pub rate: u64,
    pub metadata: ExchangeRateMetadata,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, candid::Deserialize)]
pub enum ExchangeRateError {
    // Returned when the canister receives a call from the anonymous principal.
    AnonymousPrincipalNotAllowed,
    /// Returned when the canister is in process of retrieving a rate from an exchange.
    Pending,
    // Returned when the base asset rates are not found from the exchanges HTTP outcalls.
    CryptoBaseAssetNotFound,
    // Returned when the quote asset rates are not found from the exchanges HTTP outcalls.
    CryptoQuoteAssetNotFound,
    // Returned when the stablecoin rates are not found from the exchanges HTTP outcalls needed for computing a crypto/fiat pair.
    StablecoinRateNotFound,
    // Returned when there are not enough stablecoin rates to determine the forex/USDT rate.
    StablecoinRateTooFewRates,
    // Returned when the stablecoin rate is zero.
    StablecoinRateZeroRate,
    // Returned when a rate for the provided forex asset could not be found at the provided timestamp.
    ForexInvalidTimestamp,
    // Returned when the forex base asset is found.
    ForexBaseAssetNotFound,
    // Returned when the forex quote asset is found.
    ForexQuoteAssetNotFound,
    // Returned when neither forex asset is found.
    ForexAssetsNotFound,
    // Returned when the caller is not the CMC and there are too many active requests.
    RateLimited,
    // Returned when the caller does not send enough cycles to make a request.
    NotEnoughCycles,
    // Returned when the canister fails to accept enough cycles.
    FailedToAcceptCycles,
    /// Returned if too many collected rates deviate substantially.
    InconsistentRatesReceived,
    // Until candid bug is fixed, new errors after launch will be placed here.
    Other {
        code: u32,
        description: String,
    },
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, candid::Deserialize)]
pub enum GetExchangeRateResult {
    // Successfully retrieved the exchange rate from the cache or API calls.
    Ok(ExchangeRate),
    // Failed to retrieve the exchange rate due to invalid API calls, invalid timestamp, etc.
    Err(ExchangeRateError),
}

#[derive(Clone, PartialEq, Debug, candid::CandidType, candid::Deserialize, serde::Serialize)]
pub struct GovernanceCachedMetrics {
    pub timestamp_seconds: u64,
    pub total_supply_icp: u64,
    pub dissolving_neurons_count: u64,
    pub dissolving_neurons_e8s_buckets: ::std::collections::HashMap<u64, f64>,
    pub dissolving_neurons_count_buckets: ::std::collections::HashMap<u64, u64>,
    pub not_dissolving_neurons_count: u64,
    pub not_dissolving_neurons_e8s_buckets: ::std::collections::HashMap<u64, f64>,
    pub not_dissolving_neurons_count_buckets: ::std::collections::HashMap<u64, u64>,
    pub dissolved_neurons_count: u64,
    pub dissolved_neurons_e8s: u64,
    pub garbage_collectable_neurons_count: u64,
    pub neurons_with_invalid_stake_count: u64,
    pub total_staked_e8s: u64,
    pub neurons_with_less_than_6_months_dissolve_delay_count: u64,
    pub neurons_with_less_than_6_months_dissolve_delay_e8s: u64,
    pub community_fund_total_staked_e8s: u64,
    pub community_fund_total_maturity_e8s_equivalent: u64,
    pub total_locked_e8s: u64,
}

#[derive(Clone, PartialEq, Debug, candid::CandidType, candid::Deserialize, serde::Serialize)]
pub struct GovernanceError {
    pub error_type: i32,
    pub error_message: String,
}
