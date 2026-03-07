use async_trait::async_trait;
use ic_base_types::CanisterId;
use ic_cdk::call::{Call, CallFailed, InsufficientLiquidCycleBalance};
use ic_xrc_types::{
    Asset, AssetClass, ExchangeRate, ExchangeRateError, GetExchangeRateRequest,
    GetExchangeRateResult,
};

pub const ICP_SYMBOL: &str = "ICP";
/// CXDR is an asset whose rate is derived from more sources than the XDR rate.
pub const CXDR_SYMBOL: &str = "CXDR";

/// The minimum number of received sources to consider an ICP/CXDR rate's base asset valid.
pub const MINIMUM_ICP_SOURCES: usize = 4;

/// The minimum number of received sources to consider an ICP/CXDR rate's quote asset valid.
pub const MINIMUM_CXDR_SOURCES: usize = 4;

/// Permyriad has 4 decimal places.
const PERMYRIAD_DECIMAL_PLACES: u32 = 4;

/// Failures that can occur when calling the XRC canister.
#[derive(Debug)]
pub enum GetExchangeRateError {
    Xrc(ExchangeRateError),
    Call { code: i32, message: String },
}

impl std::fmt::Display for GetExchangeRateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GetExchangeRateError::Xrc(error) => match error {
                ExchangeRateError::AnonymousPrincipalNotAllowed => {
                    write!(f, "The XRC does not accept calls from anonymous principals")
                }
                ExchangeRateError::Pending => {
                    write!(f, "The XRC is processing a similar request")
                }
                ExchangeRateError::CryptoBaseAssetNotFound => {
                    write!(f, "The crypto base asset could not be found")
                }
                ExchangeRateError::CryptoQuoteAssetNotFound => {
                    write!(f, "The crypto quote asset could not be found")
                }
                ExchangeRateError::StablecoinRateNotFound => {
                    write!(
                        f,
                        "The XRC could not retrieve the necessary stablecoin rates"
                    )
                }
                ExchangeRateError::StablecoinRateTooFewRates => {
                    write!(f, "The XRC could not find enough stablecoin rates")
                }
                ExchangeRateError::StablecoinRateZeroRate => {
                    write!(
                        f,
                        "The XRC's stablecoin rate is zero and it cannot determine a valid rate"
                    )
                }
                ExchangeRateError::ForexInvalidTimestamp => {
                    write!(f, "The request's timestamp could not be found in the XRC")
                }
                ExchangeRateError::ForexBaseAssetNotFound => {
                    write!(f, "The forex base asset in the request could not be found")
                }
                ExchangeRateError::ForexQuoteAssetNotFound => {
                    write!(f, "The forex quote asset in the request could not be found")
                }
                ExchangeRateError::ForexAssetsNotFound => {
                    write!(f, "The forex assets in the request could not be found")
                }
                ExchangeRateError::RateLimited => {
                    write!(f, "Request to the XRC has been rate limited")
                }
                ExchangeRateError::NotEnoughCycles => {
                    write!(f, "Not enough cycles sent to the XRC")
                }
                ExchangeRateError::InconsistentRatesReceived => {
                    write!(f, "Inconsistency between the collected rates occurred")
                }
                ExchangeRateError::Other(err) => {
                    write!(f, "Code: {} Message: {}", err.code, err.description)
                }
            },
            GetExchangeRateError::Call { code, message } => {
                write!(f, "Code: {code} Message: {message}")
            }
        }
    }
}

/// Validation errors for an exchange rate returned by the XRC.
#[derive(Debug)]
pub enum ValidateExchangeRateError {
    NotEnoughIcpSources { received: usize, queried: usize },
    NotEnoughCxdrSources { received: usize, queried: usize },
}

impl std::fmt::Display for ValidateExchangeRateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidateExchangeRateError::NotEnoughIcpSources { received, queried } => write!(
                f,
                "Not enough exchange sources for rate's ICP base asset. \
                 Expected: {MINIMUM_ICP_SOURCES} Received: {received} Queried: {queried}"
            ),
            ValidateExchangeRateError::NotEnoughCxdrSources { received, queried } => write!(
                f,
                "Not enough forex sources for rate's CXDR quote asset. \
                 Expected: {MINIMUM_CXDR_SOURCES} Received: {received} Queried: {queried}"
            ),
        }
    }
}

/// Validates that an ICP/CXDR exchange rate has enough sources.
pub fn validate_exchange_rate(
    exchange_rate: &ExchangeRate,
) -> Result<(), ValidateExchangeRateError> {
    if exchange_rate.metadata.base_asset_num_received_rates < MINIMUM_ICP_SOURCES {
        return Err(ValidateExchangeRateError::NotEnoughIcpSources {
            received: exchange_rate.metadata.base_asset_num_received_rates,
            queried: exchange_rate.metadata.base_asset_num_queried_sources,
        });
    }

    if exchange_rate.metadata.quote_asset_num_received_rates < MINIMUM_CXDR_SOURCES {
        return Err(ValidateExchangeRateError::NotEnoughCxdrSources {
            received: exchange_rate.metadata.quote_asset_num_received_rates,
            queried: exchange_rate.metadata.quote_asset_num_queried_sources,
        });
    }

    Ok(())
}

/// Converts an `ExchangeRate` from the XRC canister to `xdr_permyriad_per_icp`.
///
/// The XRC rate has `metadata.decimals` decimal places. We convert it to permyriad
/// (4 decimal places) by multiplying or dividing by 10^|decimals - 4|.
pub fn exchange_rate_to_xdr_permyriad(rate: &ExchangeRate) -> u64 {
    let decimals = rate.metadata.decimals;
    let power_diff = PERMYRIAD_DECIMAL_PLACES.abs_diff(decimals);
    match decimals.cmp(&PERMYRIAD_DECIMAL_PLACES) {
        std::cmp::Ordering::Greater => rate.rate.saturating_div(10u64.pow(power_diff)),
        std::cmp::Ordering::Less => rate.rate.saturating_mul(10u64.pow(power_diff)),
        std::cmp::Ordering::Equal => rate.rate,
    }
}

/// A client for fetching ICP/CXDR exchange rates from the Exchange Rate Canister (XRC).
#[async_trait]
pub trait ExchangeRateCanisterClient: Send + Sync {
    /// Fetch the ICP/CXDR rate. Pass `timestamp` (Unix seconds, rounded to midnight UTC of the
    /// target day) to request a historical day's rate; pass `None` for the latest available rate.
    async fn get_exchange_rate(
        &self,
        timestamp: Option<u64>,
    ) -> Result<ExchangeRate, GetExchangeRateError>;
}

/// The real implementation that calls the XRC canister using a bounded-wait call.
pub struct RealExchangeRateCanisterClient(CanisterId);

impl RealExchangeRateCanisterClient {
    pub fn new(canister_id: CanisterId) -> Self {
        Self(canister_id)
    }
}

#[async_trait]
impl ExchangeRateCanisterClient for RealExchangeRateCanisterClient {
    async fn get_exchange_rate(
        &self,
        timestamp: Option<u64>,
    ) -> Result<ExchangeRate, GetExchangeRateError> {
        let request = GetExchangeRateRequest {
            base_asset: Asset {
                class: AssetClass::Cryptocurrency,
                symbol: ICP_SYMBOL.to_string(),
            },
            quote_asset: Asset {
                class: AssetClass::FiatCurrency,
                symbol: CXDR_SYMBOL.to_string(),
            },
            timestamp,
        };

        let result = Call::bounded_wait(self.0.get().0, "get_exchange_rate")
            .with_arg(request)
            .await
            .map_err(call_failed_to_get_exchange_rate_error)?;

        result
            .candid::<GetExchangeRateResult>()
            .map_err(|err| GetExchangeRateError::Call {
                code: -1,
                message: format!(
                    "Got a reply from the Exchange Rate canister, \
                     but it was not decodable as a GetExchangeRateResult: {err:?}",
                ),
            })?
            .map_err(GetExchangeRateError::Xrc)
    }
}

fn call_failed_to_get_exchange_rate_error(call_failed: CallFailed) -> GetExchangeRateError {
    let (code, message) = match call_failed {
        CallFailed::InsufficientLiquidCycleBalance(err) => {
            let InsufficientLiquidCycleBalance {
                available,
                required,
            } = err;
            let message = format!(
                "Insufficient liquid cycle balance to call the Exchange Rate canister: \
                 available={available} vs. required={required}",
            );
            (-1, message)
        }

        CallFailed::CallPerformFailed(_no_data) => (
            -1,
            "The underlying ic0.call_perform operation returned a non-zero code.".to_string(),
        ),

        CallFailed::CallRejected(err) => {
            let code = err.reject_code().map(|code| code as i32).unwrap_or(-1);
            let message = err.reject_message().to_string();
            (code, message)
        }
    };

    GetExchangeRateError::Call { code, message }
}
