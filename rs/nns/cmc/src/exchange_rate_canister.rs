use std::{cell::RefCell, thread::LocalKey};

use crate::{
    environment::Environment, mutate_state, read_state, set_icp_xdr_conversion_rate, State,
    ONE_MINUTE_SECONDS,
};
use async_trait::async_trait;
use candid::CandidType;
use cycles_minting_canister::IcpXdrConversionRate;
use dfn_candid::candid_one;
use dfn_core::{api::call_with_cleanup, CanisterId};
use ic_xrc_types::{
    Asset, AssetClass, ExchangeRate, ExchangeRateError, GetExchangeRateRequest,
    GetExchangeRateResult,
};
use serde::{Deserialize, Serialize};

const ICP_SYMBOL: &str = "ICP";
/// CXDR is an asset whose rate is derived from more sources than the XDR rate.
const CXDR_SYMBOL: &str = "CXDR";

/// If the rate is older than this value, the CMC should ask for a new rate.
const REFRESH_RATE_INTERVAL_SECONDS: u64 = 5 * ONE_MINUTE_SECONDS;

#[async_trait]
pub trait ExchangeRateCanisterClient {
    async fn get_exchange_rate(&self) -> Result<ExchangeRate, GetExchangeRateError>;
}

pub struct RealExchangeRateCanisterClient(CanisterId);

impl RealExchangeRateCanisterClient {
    pub fn new(canister_id: CanisterId) -> Self {
        Self(canister_id)
    }
}

#[async_trait]
impl ExchangeRateCanisterClient for RealExchangeRateCanisterClient {
    async fn get_exchange_rate(&self) -> Result<ExchangeRate, GetExchangeRateError> {
        let payload = GetExchangeRateRequest {
            base_asset: Asset {
                class: AssetClass::Cryptocurrency,
                symbol: ICP_SYMBOL.to_string(),
            },
            quote_asset: Asset {
                class: AssetClass::FiatCurrency,
                symbol: CXDR_SYMBOL.to_string(),
            },
            timestamp: None,
        };
        let result: Result<GetExchangeRateResult, (Option<i32>, String)> =
            call_with_cleanup(self.0, "get_exchange_rate", candid_one, payload).await;
        result
            .map_err(|(code, message)| GetExchangeRateError::Call {
                code: code.unwrap_or(-1),
                message,
            })?
            .map_err(GetExchangeRateError::Xrc)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, CandidType, Eq, PartialEq, Debug)]
pub enum UpdateExchangeRateState {
    Inactive,
    InProgress,
}

impl Default for UpdateExchangeRateState {
    fn default() -> Self {
        Self::Inactive
    }
}

/// Only one UpdateExchangeRateGuard can be created at a time.
/// Assign UpdateExchangeRateGuard::new() to a local variable before calling the
/// Exchange Rate Canister to ensure there are no simultaneous calls.
struct UpdateExchangeRateGuard(&'static LocalKey<RefCell<Option<State>>>);

impl UpdateExchangeRateGuard {
    /// Set the calling status to active.
    fn new(
        safe_state: &'static LocalKey<RefCell<Option<State>>>,
    ) -> Result<Self, UpdateExchangeRateError> {
        let current_call_state = read_state(safe_state, |state| {
            state
                .update_exchange_rate_canister_state
                .unwrap_or_default()
        });

        if current_call_state == UpdateExchangeRateState::InProgress {
            return Err(UpdateExchangeRateError::UpdateAlreadyInProgress);
        }

        mutate_state(safe_state, |state| {
            state
                .update_exchange_rate_canister_state
                .replace(UpdateExchangeRateState::InProgress);
        });

        Ok(Self(safe_state))
    }

    async fn with_guard<F>(
        safe_state: &'static LocalKey<RefCell<Option<State>>>,
        future: F,
    ) -> Result<(), UpdateExchangeRateError>
    where
        F: std::future::Future<Output = Result<(), UpdateExchangeRateError>>,
    {
        let _guard = Self::new(safe_state)?;
        future.await
    }
}

impl Drop for UpdateExchangeRateGuard {
    /// On drop, set the calling status to inactive.
    fn drop(&mut self) {
        mutate_state(self.0, |state| {
            state
                .update_exchange_rate_canister_state
                .replace(UpdateExchangeRateState::Inactive)
        });
    }
}

#[derive(Debug)]
pub enum GetExchangeRateError {
    Xrc(ExchangeRateError),
    Call { code: i32, message: String },
}

impl std::fmt::Display for GetExchangeRateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GetExchangeRateError::Xrc(error) => {
                match error {
                    ExchangeRateError::AnonymousPrincipalNotAllowed => {
                        write!(f, "The XRC does not accept calls from anonymous prinicpals")
                    }
                    // Note: The CMC is a privileged canister so it will bypass this error.
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
                        write!(f, "The XRC's stablecoin rate is zero and it cannot determine a valid rate")
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
                    // Note: The CMC is a privileged canister in the XRC so it can ignore these errors.
                    // This is merely for completeness.
                    ExchangeRateError::RateLimited => {
                        write!(f, "Request to the XRC has been rate limited")
                    }
                    // Note: The CMC does not need to send cycles as it is a privileged canister.
                    // This is merely for completeness.
                    ExchangeRateError::NotEnoughCycles => {
                        write!(f, "Not enough cycles sent to the XRC")
                    }
                    ExchangeRateError::InconsistentRatesReceived => {
                        write!(f, "Inconsistency between the collected rates occurred")
                    }
                    ExchangeRateError::Other(err) => {
                        write!(f, "Code: {} Message: {}", err.code, err.description)
                    }
                }
            }
            GetExchangeRateError::Call { code, message } => {
                write!(f, "Code: {} Message: {}", code, message)
            }
        }
    }
}

#[derive(Debug)]
pub enum UpdateExchangeRateError {
    NewRateNotNeeded,
    UpdateAlreadyInProgress,
    FailedToRetrieveRate(String),
    FailedToSetRate(String),
}

impl std::fmt::Display for UpdateExchangeRateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateExchangeRateError::NewRateNotNeeded => write!(f, "New rate not needed"),
            UpdateExchangeRateError::UpdateAlreadyInProgress => {
                write!(f, "Updating exchange rate already in progress")
            }
            UpdateExchangeRateError::FailedToRetrieveRate(message) => {
                write!(
                    f,
                    "Failed to retrieve rate from exchange rate canister: {}",
                    message
                )
            }
            UpdateExchangeRateError::FailedToSetRate(message) => {
                write!(
                    f,
                    "Failed to set conversion rate from exchange rate canister: {}",
                    message
                )
            }
        }
    }
}

/// The periodic task for collecting the ICP/XDR rate from the Exchange Rate Canister.
/// To avoid having multiple calls sent to the Exchange Rate Canister,
/// this function contains a guard to ensure multiple calls cannot be made until
/// the prior call is complete.
pub async fn update_exchange_rate(
    safe_state: &'static LocalKey<RefCell<Option<State>>>,
    env: &impl Environment,
    xrc_client: &impl ExchangeRateCanisterClient,
) -> Result<(), UpdateExchangeRateError> {
    UpdateExchangeRateGuard::with_guard(safe_state, async {
        let now_timestamp_seconds = env.now_timestamp_seconds();
        let current_minute_seconds =
            round_down_to_multiple_of(now_timestamp_seconds, ONE_MINUTE_SECONDS);

        let current_icp_xdr_conversion_rate =
            read_state(safe_state, |state| state.icp_xdr_conversion_rate.clone());
        if !requires_new_rate(&current_icp_xdr_conversion_rate, current_minute_seconds) {
            return Err(UpdateExchangeRateError::NewRateNotNeeded);
        }

        let call_xrc_result = xrc_client.get_exchange_rate().await;
        match call_xrc_result {
            Ok(exchange_rate) => {
                // TODO(ER-4018): validate the rate
                let icp_xdr_conversion_rate = IcpXdrConversionRate::from(exchange_rate);
                if let Err(error) =
                    set_icp_xdr_conversion_rate(safe_state, env, icp_xdr_conversion_rate)
                {
                    return Err(UpdateExchangeRateError::FailedToSetRate(error));
                }
            }
            Err(error) => {
                return Err(UpdateExchangeRateError::FailedToRetrieveRate(
                    error.to_string(),
                ));
            }
        };

        Ok(())
    })
    .await
}

/// Round down an u64 to the given u64 multiple.
fn round_down_to_multiple_of(value: u64, multiple: u64) -> u64 {
    (value / multiple) * multiple
}

/// Check if the CMC is ready to retrieve a new rate from the XRC.
fn requires_new_rate(
    icp_xdr_conversion_rate: &Option<IcpXdrConversionRate>,
    current_minute_seconds: u64,
) -> bool {
    match icp_xdr_conversion_rate {
        Some(ref rate) => {
            // Check if the time is on a five-minute interval. This is done to keep the CMC relatively
            // in sync with the conversion rate providers that will be running every 10 minutes.
            let is_on_five_minute_interval = (current_minute_seconds / ONE_MINUTE_SECONDS) % 5 == 0;
            let is_old = rate
                .timestamp_seconds
                .saturating_add(REFRESH_RATE_INTERVAL_SECONDS)
                <= current_minute_seconds;
            is_on_five_minute_interval && is_old
        }
        None => true,
    }
}

#[cfg(test)]
mod test {

    use std::{
        cell::RefCell,
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    use super::*;

    use crate::environment::Environment;

    use futures::FutureExt;
    use ic_xrc_types::ExchangeRateMetadata;

    #[derive(Default)]
    pub struct TestExchangeRateCanisterEnvironment {
        pub now_timestamp_seconds: u64,
        pub certified_data: RefCell<Vec<u8>>,
    }

    impl Environment for TestExchangeRateCanisterEnvironment {
        fn now_timestamp_seconds(&self) -> u64 {
            self.now_timestamp_seconds
        }

        fn set_certified_data(&self, data: &[u8]) {
            *self.certified_data.borrow_mut() = data.to_vec();
        }
    }

    type GetExchangeRateResults = VecDeque<Result<ExchangeRate, GetExchangeRateError>>;

    struct MockExchangeRateCanisterClient {
        calls: Arc<Mutex<GetExchangeRateResults>>,
    }

    impl MockExchangeRateCanisterClient {
        fn new(queue: GetExchangeRateResults) -> Self {
            Self {
                calls: Arc::new(Mutex::new(queue)),
            }
        }
    }

    #[async_trait]
    impl ExchangeRateCanisterClient for MockExchangeRateCanisterClient {
        async fn get_exchange_rate(&self) -> Result<ExchangeRate, GetExchangeRateError> {
            self.calls.lock().unwrap().pop_front().unwrap()
        }
    }

    fn new_exchange_rate(timestamp: u64) -> ExchangeRate {
        ExchangeRate {
            base_asset: Asset {
                symbol: ICP_SYMBOL.to_string(),
                class: AssetClass::Cryptocurrency,
            },
            quote_asset: Asset {
                symbol: CXDR_SYMBOL.to_string(),
                class: AssetClass::FiatCurrency,
            },
            timestamp,
            rate: 20_000_000_000, // 20 XDR = 1 ICP
            metadata: ExchangeRateMetadata {
                decimals: 9,
                base_asset_num_queried_sources: 0,
                base_asset_num_received_rates: 0,
                quote_asset_num_queried_sources: 0,
                quote_asset_num_received_rates: 0,
                standard_deviation: 0,
                forex_timestamp: Some(0),
            },
        }
    }

    #[test]
    fn test_round_down_to_multiple_of() {
        // Timestamp round down
        let value = 1620633658;
        let rounded_down_value = round_down_to_multiple_of(value, ONE_MINUTE_SECONDS);
        assert_eq!(1620633600, rounded_down_value);

        let value = 13;
        let rounded_down_value = round_down_to_multiple_of(value, 5);
        assert_eq!(10, rounded_down_value);

        let value = 199;
        let rounded_down_value = round_down_to_multiple_of(value, 200);
        assert_eq!(0, rounded_down_value);
    }

    #[test]
    fn test_is_ready_for_new_rate() {
        // Initial timestamp
        let current_minute_seconds = 1620633600;
        let icp_xdr_conversion_rate = Some(IcpXdrConversionRate {
            timestamp_seconds: 1620633600,    // 10 May 2021 10:00:00 AM CEST
            xdr_permyriad_per_icp: 1_000_000, // 100 XDR = 1 ICP
        });

        assert!(
            !requires_new_rate(&icp_xdr_conversion_rate, current_minute_seconds),
            "Current time equals the rate timestamp, no rate is needed."
        );
        // Initial timestamp + refresh rate
        let current_minute_seconds_with_refresh_rate =
            current_minute_seconds.saturating_add(REFRESH_RATE_INTERVAL_SECONDS);
        assert!(
            requires_new_rate(
                &icp_xdr_conversion_rate,
                current_minute_seconds_with_refresh_rate
            ),
            "Current time is ahead by the refresh rate interval, a new rate is needed."
        );

        // Initial timestamp + (refresh rate - 1)
        let current_minute_seconds_with_refresh_rate_less_1 =
            current_minute_seconds.saturating_add(REFRESH_RATE_INTERVAL_SECONDS - 1);
        assert!(
            !requires_new_rate(
                &icp_xdr_conversion_rate,
                current_minute_seconds_with_refresh_rate_less_1
            ),
            "Current time is ahead by the the refresh rate less one, no new rate is needed."
        );

        // Timestamp is not on a five-minute interval
        let current_minute_seconds_plus_one_minute =
            current_minute_seconds.saturating_add(ONE_MINUTE_SECONDS);
        assert!(
            !requires_new_rate(
                &icp_xdr_conversion_rate,
                current_minute_seconds_plus_one_minute
            ),
            "Current time is not on a five-minute interval, no new rate is needed."
        );

        assert!(
            requires_new_rate(&None, current_minute_seconds),
            "No rate present in state, a new rate is needed."
        );
    }

    #[test]
    fn test_periodic_does_not_call_while_there_is_another_active_call() {
        // Set to active to trigger the error.
        thread_local! {
            static STATE: RefCell<Option<State>> = RefCell::new(Some(State {
                update_exchange_rate_canister_state: Some(UpdateExchangeRateState::InProgress),
                ..State::default()
            }));
        }
        let env = TestExchangeRateCanisterEnvironment {
            now_timestamp_seconds: 1680044700,
            ..Default::default()
        };
        let xrc_client = MockExchangeRateCanisterClient::new(
            vec![Ok(new_exchange_rate(env.now_timestamp_seconds()))].into(),
        );

        let result = update_exchange_rate(&STATE, &env, &xrc_client)
            .now_or_never()
            .unwrap();

        assert!(matches!(
            result,
            Err(UpdateExchangeRateError::UpdateAlreadyInProgress)
        ));
        assert!(!xrc_client.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn test_periodic_does_not_call_if_new_rate_is_not_required() {
        thread_local! {
            static STATE: RefCell<Option<State>> = RefCell::new(Some(State::default()));
        }

        let env = TestExchangeRateCanisterEnvironment {
            now_timestamp_seconds: 1680044760,
            ..Default::default()
        };
        let xrc_client = MockExchangeRateCanisterClient::new(
            vec![Ok(new_exchange_rate(env.now_timestamp_seconds()))].into(),
        );
        let result = update_exchange_rate(&STATE, &env, &xrc_client)
            .now_or_never()
            .unwrap();

        assert!(matches!(
            result,
            Err(UpdateExchangeRateError::NewRateNotNeeded)
        ));
        assert!(!xrc_client.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn test_periodic_calls_the_xrc_and_call_fails() {
        thread_local! {
            static STATE: RefCell<Option<State>> = RefCell::new(Some(State::default()));
        }

        let env = TestExchangeRateCanisterEnvironment {
            now_timestamp_seconds: 1680044700,
            ..Default::default()
        };
        let xrc_client = MockExchangeRateCanisterClient::new(
            vec![Err(GetExchangeRateError::Xrc(
                ExchangeRateError::CryptoBaseAssetNotFound,
            ))]
            .into(),
        );
        let result = update_exchange_rate(&STATE, &env, &xrc_client)
            .now_or_never()
            .unwrap();

        assert!(
            matches!(result, Err(UpdateExchangeRateError::FailedToRetrieveRate(message)) if message == "The crypto base asset could not be found")
        );
        assert!(xrc_client.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn test_periodic_calls_the_xrc_and_setting_rate_fails() {
        thread_local! {
            static STATE: RefCell<Option<State>> = RefCell::new(Some(State::default()));
        }

        let env = TestExchangeRateCanisterEnvironment {
            now_timestamp_seconds: 1680044700,
            ..Default::default()
        };
        // Set the rate timestamp to zero to trigger an error while setting the rate.
        let xrc_client = MockExchangeRateCanisterClient::new(vec![Ok(new_exchange_rate(0))].into());
        let result = update_exchange_rate(&STATE, &env, &xrc_client)
            .now_or_never()
            .unwrap();

        assert!(
            matches!(result, Err(UpdateExchangeRateError::FailedToSetRate(message)) if message == "Proposed conversion rate must have greater timestamp than current one")
        );
        assert!(xrc_client.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn test_periodic_calls_the_xrc_and_sets_the_rate() {
        thread_local! {
            static STATE: RefCell<Option<State>> = RefCell::new(Some(State::default()));
        }

        let env = TestExchangeRateCanisterEnvironment {
            now_timestamp_seconds: 1680044700,
            ..Default::default()
        };
        let xrc_client = MockExchangeRateCanisterClient::new(
            vec![Ok(new_exchange_rate(env.now_timestamp_seconds()))].into(),
        );

        let result = update_exchange_rate(&STATE, &env, &xrc_client)
            .now_or_never()
            .unwrap();

        assert!(matches!(result, Ok(_)), "{:?}", result);
        assert!(xrc_client.calls.lock().unwrap().is_empty());
        let icp_xdr_conversion_rate =
            read_state(&STATE, |state| state.icp_xdr_conversion_rate.clone());
        assert!(
            matches!(icp_xdr_conversion_rate, Some(rate) if rate.xdr_permyriad_per_icp == 200_000 && rate.timestamp_seconds == 1680044700)
        );
        // Ensure the certified data has been set.
        assert!(!env.certified_data.borrow().is_empty());
    }
}
