use candid::CandidType;
use ic_xrc_types::{Asset, ExchangeRateError, ExchangeRateMetadata};

#[derive(CandidType, Debug, candid::Deserialize)]
pub struct XrcMockInitPayload {
    pub response: Response,
}

#[derive(CandidType, Debug, candid::Deserialize)]
pub struct ExchangeRate {
    pub base_asset: Option<Asset>,
    pub quote_asset: Option<Asset>,
    pub metadata: Option<ExchangeRateMetadata>,
    pub rate: u64,
}

#[derive(CandidType, Debug, candid::Deserialize)]
pub enum Response {
    ExchangeRate(ExchangeRate),
    Error(ExchangeRateError),
}

#[derive(CandidType, Debug, candid::Deserialize)]
pub struct SetExchangeRate {
    pub base_asset: String,
    pub quote_asset: String,
    pub rate: u64,
}
