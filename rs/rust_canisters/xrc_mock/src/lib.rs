use candid::CandidType;
use ic_xrc_types::{Asset, ExchangeRateError, ExchangeRateMetadata};

#[derive(Debug, CandidType, candid::Deserialize, Clone)]
pub struct XrcMockInitPayload {
    pub response: Response,
}

#[derive(Debug, CandidType, candid::Deserialize, Clone)]
pub struct ExchangeRate {
    pub base_asset: Option<Asset>,
    pub quote_asset: Option<Asset>,
    pub metadata: Option<ExchangeRateMetadata>,
    pub rate: u64,
}

#[derive(Debug, CandidType, candid::Deserialize, Clone)]
pub enum Response {
    ExchangeRate(ExchangeRate),
    Error(ExchangeRateError),
}

#[derive(Debug, CandidType, candid::Deserialize, Clone)]
pub struct SetExchangeRate {
    pub base_asset: String,
    pub quote_asset: String,
    pub rate: u64,
}
