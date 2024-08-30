use crate::{
    environment::Environment, mutate_state, read_state, set_icp_xdr_conversion_rate, State,
    ONE_MINUTE_SECONDS,
};
use async_trait::async_trait;
use candid::CandidType;
use cycles_minting_canister::IcpXdrConversionRate;
use dfn_candid::candid_one;
use dfn_core::{api::call_with_cleanup, CanisterId};
use ic_nns_common::types::UpdateIcpXdrConversionRatePayloadReason;
use ic_xrc_types::{
    Asset, AssetClass, ExchangeRate, ExchangeRateError, GetExchangeRateRequest,
    GetExchangeRateResult,
};
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, thread::LocalKey};

const ICP_SYMBOL: &str = "ICP";
/// CXDR is an asset whose rate is derived from more sources than the XDR rate.
const CXDR_SYMBOL: &str = "CXDR";

/// If the rate is older than this value, the CMC should ask for a new rate.
const REFRESH_RATE_INTERVAL_SECONDS: u64 = 5 * ONE_MINUTE_SECONDS;

/// The minimum number of received sources to consider an ICP/CXDR rate's base asset valid.
const MINIMUM_ICP_SOURCES: usize = 4;

/// The minimum number of received sources to consider an ICP/CXDR rate's quote asset valid.
const MINIMUM_CXDR_SOURCES: usize = 4;

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

#[repr(u8)]
#[derive(Serialize, Deserialize, Clone, Copy, CandidType, Eq, PartialEq, Debug)]
pub enum UpdateExchangeRateState {
    Disabled = 0,
    GetRateAt(u64) = 1,
    InProgress = 2,
}

impl From<&UpdateExchangeRateState> for u8 {
    fn from(value: &UpdateExchangeRateState) -> Self {
        match value {
            UpdateExchangeRateState::Disabled => 0,
            UpdateExchangeRateState::GetRateAt(_) => 1,
            UpdateExchangeRateState::InProgress => 2,
        }
    }
}

impl Default for UpdateExchangeRateState {
    fn default() -> Self {
        // 10 May 2021 10:00:00 AM CEST
        Self::GetRateAt(1620633600)
    }
}

impl UpdateExchangeRateState {
    fn get_rate_at_next_refresh_rate_interval(current_timestamp_seconds: u64) -> Self {
        let maybe_next_multiple =
            get_next_multiple_of(current_timestamp_seconds, REFRESH_RATE_INTERVAL_SECONDS);
        match maybe_next_multiple {
            Some(next_timestamp) => UpdateExchangeRateState::GetRateAt(next_timestamp),
            None => UpdateExchangeRateState::Disabled,
        }
    }

    fn get_rate_at_next_minute(current_timestamp_seconds: u64) -> Self {
        let maybe_next_multiple =
            get_next_multiple_of(current_timestamp_seconds, ONE_MINUTE_SECONDS);
        match maybe_next_multiple {
            Some(next_timestamp) => UpdateExchangeRateState::GetRateAt(next_timestamp),
            None => UpdateExchangeRateState::Disabled,
        }
    }
}

/// Get the "next multiple" of a value, that is, the smallest number which (1) can be divided by
/// `multiple`, and (2) is greater than `value`. Returns None if `multiple` zero or if the result
/// would overflow u64.
fn get_next_multiple_of(value: u64, multiple: u64) -> Option<u64> {
    // If `multiple` is 0, None will be returned here as expected.
    let quotient = value.checked_div(multiple)?;

    // This should not overflow since `quotient` * `multiple` should be no more than `value`,
    // although the compiler doesn't know that.
    let previous_multiple = quotient.checked_mul(multiple)?;

    // This could overflow (e.g. if `value` is u64::MAX and `multiple` is 2), but that's fine.
    previous_multiple.checked_add(multiple)
}

/// Only one UpdateExchangeRateGuard can be created at a time.
/// Assign UpdateExchangeRateGuard::new() to a local variable before calling the
/// Exchange Rate Canister to ensure there are no simultaneous calls.
struct UpdateExchangeRateGuard {
    safe_state: &'static LocalKey<RefCell<Option<State>>>,
    current_minute_in_seconds: u64,
}

impl UpdateExchangeRateGuard {
    /// Set the calling status to active.
    fn new(
        safe_state: &'static LocalKey<RefCell<Option<State>>>,
        current_minute_in_seconds: u64,
    ) -> Result<Self, UpdateExchangeRateError> {
        let current_call_state = read_state(safe_state, |state| {
            state
                .update_exchange_rate_canister_state
                .unwrap_or_default()
        });

        if current_call_state == UpdateExchangeRateState::Disabled {
            return Err(UpdateExchangeRateError::Disabled);
        }

        if current_call_state == UpdateExchangeRateState::InProgress {
            return Err(UpdateExchangeRateError::UpdateAlreadyInProgress);
        }

        if let UpdateExchangeRateState::GetRateAt(next_attempt_seconds) = current_call_state {
            if current_minute_in_seconds < next_attempt_seconds {
                return Err(UpdateExchangeRateError::NotReadyToGetRate(
                    next_attempt_seconds,
                ));
            }
        }

        mutate_state(safe_state, |state| {
            state
                .update_exchange_rate_canister_state
                .replace(UpdateExchangeRateState::InProgress);
        });

        Ok(Self {
            safe_state,
            current_minute_in_seconds,
        })
    }

    // This function helps schedule the next attempt at retrieving a rate from
    // the exchange rate canister. If the result of the in progress call is successful,
    // a new attempt to get the rate is schedule at the next five minute interval (:00, :05, :10, ...).
    // If the result has failed due to a failure receiving the rate or the rate was
    // determined to be invalid, a new attempt is schedule for the next minute.
    //
    // If the update cycle has been disabled, this function skips the scheduling.
    fn schedule_next_attempt(&self, result: &Result<(), UpdateExchangeRateError>) {
        mutate_state(self.safe_state, |state| {
            if let Some(UpdateExchangeRateState::Disabled) =
                state.update_exchange_rate_canister_state
            {
                return;
            }

            match result {
                Ok(_) => {
                    state.update_exchange_rate_canister_state.replace(
                        UpdateExchangeRateState::get_rate_at_next_refresh_rate_interval(
                            self.current_minute_in_seconds,
                        ),
                    );
                }
                Err(error) => match error {
                    UpdateExchangeRateError::UpdateAlreadyInProgress => {}
                    UpdateExchangeRateError::Disabled => {}
                    UpdateExchangeRateError::NotReadyToGetRate(_) => {}
                    UpdateExchangeRateError::FailedToRetrieveRate(_)
                    | UpdateExchangeRateError::FailedToSetRate(_)
                    | UpdateExchangeRateError::InvalidRate(_) => {
                        state.update_exchange_rate_canister_state.replace(
                            UpdateExchangeRateState::get_rate_at_next_minute(
                                self.current_minute_in_seconds,
                            ),
                        );
                    }
                },
            }
        });
    }

    async fn with_guard<F>(
        safe_state: &'static LocalKey<RefCell<Option<State>>>,
        current_minute_seconds: u64,
        future: F,
    ) -> Result<(), UpdateExchangeRateError>
    where
        F: std::future::Future<Output = Result<(), UpdateExchangeRateError>>,
    {
        let guard = Self::new(safe_state, current_minute_seconds)?;
        let result = future.await;
        // Check the result. Based on the contents, this will affect the next
        // update state.
        guard.schedule_next_attempt(&result);
        result
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
                        write!(f, "The XRC does not accept calls from anonymous principals")
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
    UpdateAlreadyInProgress,
    Disabled,
    FailedToRetrieveRate(String),
    FailedToSetRate(String),
    InvalidRate(String),
    NotReadyToGetRate(u64),
}

impl std::fmt::Display for UpdateExchangeRateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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
            UpdateExchangeRateError::Disabled => write!(
                f,
                "Updating the exchange rate has been disabled due to a diverged rate"
            ),
            UpdateExchangeRateError::InvalidRate(message) => {
                write!(
                    f,
                    "Rate from exchange rate canister failed to validate: {}",
                    message
                )
            }
            UpdateExchangeRateError::NotReadyToGetRate(timestamp) => {
                write!(
                    f,
                    "Waiting to reattempt calling the exchange rate canister again at {}",
                    timestamp
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
    let now_timestamp_seconds = env.now_timestamp_seconds();
    let current_minute_seconds =
        round_down_to_multiple_of(now_timestamp_seconds, ONE_MINUTE_SECONDS);

    UpdateExchangeRateGuard::with_guard(safe_state, current_minute_seconds, async {
        let call_xrc_result = xrc_client.get_exchange_rate().await;
        // Check if updating the rate via the exchange rate canister was disabled while retrieving the rate.
        // If it has, exit early.
        let is_updating_rate_disabled = read_state(safe_state, |state| {
            state
                .update_exchange_rate_canister_state
                .unwrap_or_default()
                == UpdateExchangeRateState::Disabled
        });
        if is_updating_rate_disabled {
            return Err(UpdateExchangeRateError::Disabled);
        }

        match call_xrc_result {
            Ok(exchange_rate) => {
                validate_exchange_rate(&exchange_rate)
                    .map_err(|error| UpdateExchangeRateError::InvalidRate(error.to_string()))?;
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

/// Takes the reason from an exchange rate proposal payload as input in order to
/// determine if the CMC should continue using the exchange rate canister. If
/// the reason is a diverged rate, requesting the rate from the exchange rate
/// canister is disabled until a proposal comes in with a reason stating old rate.
pub fn set_update_exchange_rate_state(
    safe_state: &'static LocalKey<RefCell<Option<State>>>,
    maybe_reason: &Option<UpdateIcpXdrConversionRatePayloadReason>,
    rate_timestamp_seconds: u64,
) {
    if let Some(ref reason) = maybe_reason {
        mutate_state(safe_state, |state| {
            let current_update_exchange_rate_state = state
                .update_exchange_rate_canister_state
                .unwrap_or_default();
            match reason {
                UpdateIcpXdrConversionRatePayloadReason::EnableAutomaticExchangeRateUpdates => {
                    if current_update_exchange_rate_state == UpdateExchangeRateState::Disabled {
                        state.update_exchange_rate_canister_state.replace(
                            UpdateExchangeRateState::get_rate_at_next_refresh_rate_interval(
                                rate_timestamp_seconds,
                            ),
                        );
                    }
                }
                UpdateIcpXdrConversionRatePayloadReason::DivergedRate => {
                    state
                        .update_exchange_rate_canister_state
                        .replace(UpdateExchangeRateState::Disabled);
                }
                UpdateIcpXdrConversionRatePayloadReason::OldRate => {
                    if current_update_exchange_rate_state == UpdateExchangeRateState::Disabled {
                        return;
                    }

                    state.update_exchange_rate_canister_state.replace(
                        UpdateExchangeRateState::get_rate_at_next_refresh_rate_interval(
                            rate_timestamp_seconds,
                        ),
                    );
                }
            }
        });
    }
}

enum ValidateExchangeRateError {
    NotEnoughIcpSources { received: usize, queried: usize },
    NotEnoughCxdrSources { received: usize, queried: usize },
}

impl std::fmt::Display for ValidateExchangeRateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidateExchangeRateError::NotEnoughIcpSources { received, queried } => write!(f, "Not enough exchange sources for rate's ICP base asset. Expected: {} Received: {} Queried: {}", MINIMUM_ICP_SOURCES, received, queried),
            ValidateExchangeRateError::NotEnoughCxdrSources { received, queried } => write!(f, "Not enough forex sources for rate's CXDR quote asset. Expected: {} Received: {} Queried: {}", MINIMUM_CXDR_SOURCES, received, queried),
        }
    }
}

fn validate_exchange_rate(exchange_rate: &ExchangeRate) -> Result<(), ValidateExchangeRateError> {
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

#[cfg(test)]
mod test {

    use super::*;
    use crate::environment::Environment;
    use crate::{
        DEFAULT_ICP_XDR_CONVERSION_RATE_TIMESTAMP_SECONDS,
        DEFAULT_XDR_PERMYRIAD_PER_ICP_CONVERSION_RATE,
    };
    use futures::FutureExt;
    use ic_xrc_types::ExchangeRateMetadata;
    use std::{
        cell::RefCell,
        collections::VecDeque,
        sync::{Arc, Mutex},
        time::UNIX_EPOCH,
    };

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

    impl TestExchangeRateCanisterEnvironment {
        fn advance_now_timestamp_seconds(&mut self, seconds: u64) {
            self.now_timestamp_seconds += seconds;
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

    fn new_exchange_rate(
        timestamp: u64,
        base_asset_num_received_rates: usize,
        quote_asset_num_received_rates: usize,
    ) -> ExchangeRate {
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
                base_asset_num_queried_sources: 7,
                base_asset_num_received_rates,
                quote_asset_num_queried_sources: 7,
                quote_asset_num_received_rates,
                standard_deviation: 0,
                forex_timestamp: Some(0),
            },
        }
    }

    #[test]
    fn test_get_next_multiple_of() {
        let value = 1620633658;
        let next_multiple = get_next_multiple_of(value, ONE_MINUTE_SECONDS);
        assert!(matches!(next_multiple, Some(1620633660)));

        let value = 300;
        let next_multiple = get_next_multiple_of(value, REFRESH_RATE_INTERVAL_SECONDS);
        assert!(matches!(next_multiple, Some(600)));

        let next_multiple = get_next_multiple_of(u64::MAX, REFRESH_RATE_INTERVAL_SECONDS);
        assert!(next_multiple.is_none());
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
            vec![Ok(new_exchange_rate(
                env.now_timestamp_seconds(),
                MINIMUM_ICP_SOURCES,
                MINIMUM_CXDR_SOURCES,
            ))]
            .into(),
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
    fn test_periodic_does_not_call_if_the_scheduled_time_as_not_occurred_yet() {
        let now_timestamp_seconds = 1680044760;
        thread_local! {
            static STATE: RefCell<Option<State>> = RefCell::new(Some(State::default()));
        }

        mutate_state(&STATE, |state| {
            state.update_exchange_rate_canister_state.replace(
                UpdateExchangeRateState::get_rate_at_next_refresh_rate_interval(
                    now_timestamp_seconds,
                ),
            );
        });

        let env = TestExchangeRateCanisterEnvironment {
            now_timestamp_seconds,
            ..Default::default()
        };
        let xrc_client = MockExchangeRateCanisterClient::new(
            vec![Ok(new_exchange_rate(
                env.now_timestamp_seconds(),
                MINIMUM_ICP_SOURCES,
                MINIMUM_CXDR_SOURCES,
            ))]
            .into(),
        );
        let result = update_exchange_rate(&STATE, &env, &xrc_client)
            .now_or_never()
            .unwrap();

        assert!(matches!(
            result,
            Err(UpdateExchangeRateError::NotReadyToGetRate(1680045000))
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
        // Set the rate timestamp to a minute prior of the initial rate to trigger an error while setting the rate.
        let xrc_client = MockExchangeRateCanisterClient::new(
            vec![Ok(new_exchange_rate(
                1620633540,
                MINIMUM_ICP_SOURCES,
                MINIMUM_CXDR_SOURCES,
            ))]
            .into(),
        );
        let result = update_exchange_rate(&STATE, &env, &xrc_client)
            .now_or_never()
            .unwrap();

        assert!(
            matches!(result, Err(UpdateExchangeRateError::FailedToSetRate(message)) if message == "Proposed conversion rate must have greater timestamp than current one")
        );
        assert!(xrc_client.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn test_periodic_calls_the_xrc_and_not_enough_icp_sources_received() {
        thread_local! {
            static STATE: RefCell<Option<State>> = RefCell::new(Some(State::default()));
        }

        let mut env = TestExchangeRateCanisterEnvironment {
            now_timestamp_seconds: 1680044700,
            ..Default::default()
        };
        // Set the rate's ICP sources to just below the required amount to trigger a validation error.
        let xrc_client = MockExchangeRateCanisterClient::new(
            vec![
                Ok(new_exchange_rate(
                    env.now_timestamp_seconds(),
                    MINIMUM_ICP_SOURCES.saturating_sub(1),
                    MINIMUM_CXDR_SOURCES,
                )),
                Ok(new_exchange_rate(env.now_timestamp_seconds() + 60, 7, 7)),
                Ok(new_exchange_rate(env.now_timestamp_seconds() + 300, 7, 7)),
            ]
            .into(),
        );
        let result = update_exchange_rate(&STATE, &env, &xrc_client)
            .now_or_never()
            .unwrap();

        assert!(
            matches!(result, Err(UpdateExchangeRateError::InvalidRate(message)) if message == format!("Not enough exchange sources for rate's ICP base asset. Expected: {} Received: {} Queried: 7", MINIMUM_ICP_SOURCES, MINIMUM_ICP_SOURCES.saturating_sub(1))),
        );
        assert_eq!(xrc_client.calls.lock().unwrap().len(), 2);
        let update_state = read_state(&STATE, |state| {
            state
                .update_exchange_rate_canister_state
                .expect("update state should be set")
        });
        assert!(matches!(
            update_state,
            UpdateExchangeRateState::GetRateAt(1680044760)
        ));

        // Attempt another call. This should fail as there was a failed attempt.
        let result = update_exchange_rate(&STATE, &env, &xrc_client)
            .now_or_never()
            .unwrap();
        assert!(matches!(
            result,
            Err(UpdateExchangeRateError::NotReadyToGetRate(1680044760))
        ));

        // Attempt another call but a minute after.
        env.advance_now_timestamp_seconds(60);
        let result = update_exchange_rate(&STATE, &env, &xrc_client)
            .now_or_never()
            .unwrap();
        assert!(result.is_ok());
        let update_state = read_state(&STATE, |state| {
            state
                .update_exchange_rate_canister_state
                .expect("update state should be set")
        });
        assert!(matches!(
            update_state,
            UpdateExchangeRateState::GetRateAt(1680045000)
        ));
        assert_eq!(xrc_client.calls.lock().unwrap().len(), 1);

        // Attempt another call but at the next five minute interval.
        env.advance_now_timestamp_seconds(240);
        let result = update_exchange_rate(&STATE, &env, &xrc_client)
            .now_or_never()
            .unwrap();
        assert!(result.is_ok());
        assert!(xrc_client.calls.lock().unwrap().is_empty());
        let update_state = read_state(&STATE, |state| {
            state
                .update_exchange_rate_canister_state
                .expect("update state should be set")
        });
        assert!(matches!(
            update_state,
            UpdateExchangeRateState::GetRateAt(1680045300)
        ));
        assert!(xrc_client.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn test_periodic_calls_the_xrc_and_not_enough_cxdr_sources_received() {
        thread_local! {
            static STATE: RefCell<Option<State>> = RefCell::new(Some(State::default()));
        }

        let env = TestExchangeRateCanisterEnvironment {
            now_timestamp_seconds: 1680044700,
            ..Default::default()
        };
        // Set the rate's ICP sources to just below the required amount to trigger a validation error.
        let xrc_client = MockExchangeRateCanisterClient::new(
            vec![Ok(new_exchange_rate(
                env.now_timestamp_seconds(),
                MINIMUM_ICP_SOURCES,
                MINIMUM_CXDR_SOURCES.saturating_sub(1),
            ))]
            .into(),
        );
        let result = update_exchange_rate(&STATE, &env, &xrc_client)
            .now_or_never()
            .unwrap();

        assert!(
            matches!(result, Err(UpdateExchangeRateError::InvalidRate(message)) if message == format!("Not enough forex sources for rate's CXDR quote asset. Expected: {} Received: {} Queried: 7", MINIMUM_CXDR_SOURCES, MINIMUM_CXDR_SOURCES.saturating_sub(1))),
        );
        let update_state = read_state(&STATE, |state| {
            state
                .update_exchange_rate_canister_state
                .expect("update state should be set")
        });
        assert!(matches!(
            update_state,
            UpdateExchangeRateState::GetRateAt(1680044760)
        ));
        assert!(xrc_client.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn test_periodic_calls_the_xrc_and_if_the_call_fails_it_attempts_again_a_minute_later() {
        thread_local! {
            static STATE: RefCell<Option<State>> = RefCell::new(Some(State::default()));
        }

        let env = TestExchangeRateCanisterEnvironment {
            now_timestamp_seconds: 1680044700,
            ..Default::default()
        };
        // Set the rate's ICP sources to just below the required amount to trigger a validation error.
        let xrc_client = MockExchangeRateCanisterClient::new(
            vec![Err(GetExchangeRateError::Call {
                code: 0,
                message: "error".to_string(),
            })]
            .into(),
        );
        let result = update_exchange_rate(&STATE, &env, &xrc_client)
            .now_or_never()
            .unwrap();

        assert!(matches!(
            result,
            Err(UpdateExchangeRateError::FailedToRetrieveRate(_))
        ),);
        let update_state = read_state(&STATE, |state| {
            state
                .update_exchange_rate_canister_state
                .expect("update state should be set")
        });
        assert!(matches!(
            update_state,
            UpdateExchangeRateState::GetRateAt(1680044760)
        ));
        assert!(xrc_client.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn test_periodic_calls_the_xrc_and_rejects_the_rates_timestamp_then_sets_the_next_attempt_a_minute_in_future(
    ) {
        thread_local! {
            static STATE: RefCell<Option<State>> = RefCell::new(Some(State::default()));
        }

        let env = TestExchangeRateCanisterEnvironment {
            now_timestamp_seconds: 1680044700,
            ..Default::default()
        };
        // Set the rate's ICP sources to just below the required amount to trigger a validation error.
        let xrc_client = MockExchangeRateCanisterClient::new(
            vec![Ok(new_exchange_rate(
                0,
                MINIMUM_ICP_SOURCES,
                MINIMUM_CXDR_SOURCES,
            ))]
            .into(),
        );
        let result = update_exchange_rate(&STATE, &env, &xrc_client)
            .now_or_never()
            .unwrap();

        assert!(matches!(
            result,
            Err(UpdateExchangeRateError::FailedToSetRate(_))
        ),);
        let update_state = read_state(&STATE, |state| {
            state
                .update_exchange_rate_canister_state
                .expect("update state should be set")
        });
        assert!(matches!(
            update_state,
            UpdateExchangeRateState::GetRateAt(1680044760)
        ));
        assert!(xrc_client.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn test_periodic_calls_the_xrc_and_sets_the_rate() {
        thread_local! {
            static STATE: RefCell<Option<State>> = RefCell::new(Some(State::default()));
        }

        let average_icp_xdr_conversion_rate = read_state(&STATE, |state| {
            state.average_icp_xdr_conversion_rate.clone()
        });

        // Require starting with the expected initial ICP/XDR conversion rate.
        let initial_average_icp_xdr_conversion_rate = Some(IcpXdrConversionRate {
            timestamp_seconds: DEFAULT_ICP_XDR_CONVERSION_RATE_TIMESTAMP_SECONDS,
            xdr_permyriad_per_icp: DEFAULT_XDR_PERMYRIAD_PER_ICP_CONVERSION_RATE,
        });
        assert_eq!(
            average_icp_xdr_conversion_rate,
            initial_average_icp_xdr_conversion_rate
        );

        let now_timestamp_seconds = (dfn_core::api::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 60)
            * 60;

        let env = TestExchangeRateCanisterEnvironment {
            now_timestamp_seconds,
            ..Default::default()
        };
        let xrc_client = MockExchangeRateCanisterClient::new(
            vec![Ok(new_exchange_rate(
                env.now_timestamp_seconds(),
                MINIMUM_ICP_SOURCES,
                MINIMUM_CXDR_SOURCES,
            ))]
            .into(),
        );

        let result = update_exchange_rate(&STATE, &env, &xrc_client)
            .now_or_never()
            .unwrap();

        assert!(result.is_ok(), "{:?}", result);
        assert!(xrc_client.calls.lock().unwrap().is_empty());
        let icp_xdr_conversion_rate =
            read_state(&STATE, |state| state.icp_xdr_conversion_rate.clone());
        let expected_rate_timestamp = (now_timestamp_seconds / 60) * 60;
        assert!(
            matches!(icp_xdr_conversion_rate, Some(ref rate) if rate.xdr_permyriad_per_icp == 200_000 && rate.timestamp_seconds == expected_rate_timestamp),
            "rate: {:#?} expected timestamp: {}",
            icp_xdr_conversion_rate,
            expected_rate_timestamp
        );
        // Ensure the certified data has been set.
        assert!(!env.certified_data.borrow().is_empty());

        let average_icp_xdr_conversion_rate = read_state(&STATE, |state| {
            state.average_icp_xdr_conversion_rate.clone()
        });

        // Ensure the observed ICP/XDR conversion rate is different from the initial one.
        assert_ne!(
            average_icp_xdr_conversion_rate,
            initial_average_icp_xdr_conversion_rate
        );

        assert!(
            matches!(average_icp_xdr_conversion_rate, Some(ref rate) if rate.xdr_permyriad_per_icp == 200_000),
            "rate: {:#?}",
            icp_xdr_conversion_rate
        );
    }

    #[test]
    fn test_periodic_does_not_set_the_rate_if_the_state_updates_to_disabled_while_calling_xrc() {
        thread_local! {
            static STATE: RefCell<Option<State>> = RefCell::new(Some(State::default()));
        }

        struct TestExchangeRateCanisterClient;

        #[async_trait]
        impl ExchangeRateCanisterClient for TestExchangeRateCanisterClient {
            async fn get_exchange_rate(&self) -> Result<ExchangeRate, GetExchangeRateError> {
                mutate_state(&STATE, |state| {
                    // Set the state to disabled to simulate a diverged rate proposal came during call to XRC.
                    state
                        .update_exchange_rate_canister_state
                        .replace(UpdateExchangeRateState::Disabled);
                });
                Ok(new_exchange_rate(
                    1680044700,
                    MINIMUM_ICP_SOURCES,
                    MINIMUM_CXDR_SOURCES,
                ))
            }
        }

        let env = TestExchangeRateCanisterEnvironment {
            now_timestamp_seconds: 1680044700,
            ..Default::default()
        };
        let xrc_client = TestExchangeRateCanisterClient;

        let result = update_exchange_rate(&STATE, &env, &xrc_client)
            .now_or_never()
            .unwrap();

        assert!(matches!(result, Err(UpdateExchangeRateError::Disabled)));
        let icp_xdr_conversion_rate =
            read_state(&STATE, |state| state.icp_xdr_conversion_rate.clone());
        assert!(
            matches!(icp_xdr_conversion_rate, Some(rate) if rate.xdr_permyriad_per_icp == 1_000_000 && rate.timestamp_seconds == 1620633600)
        );
    }

    #[test]
    fn test_set_update_exchange_rate_state() {
        thread_local! {
            static STATE: RefCell<Option<State>> = RefCell::new(Some(State::default()));
        }

        set_update_exchange_rate_state(&STATE, &None, 0);
        let update_exchange_rate_canister_state =
            read_state(&STATE, |state| state.update_exchange_rate_canister_state);
        assert!(matches!(
            update_exchange_rate_canister_state,
            Some(UpdateExchangeRateState::GetRateAt(1620633600))
        ));

        set_update_exchange_rate_state(
            &STATE,
            &Some(UpdateIcpXdrConversionRatePayloadReason::DivergedRate),
            1680045300,
        );
        let update_exchange_rate_canister_state =
            read_state(&STATE, |state| state.update_exchange_rate_canister_state);
        assert!(matches!(
            update_exchange_rate_canister_state,
            Some(UpdateExchangeRateState::Disabled)
        ));

        set_update_exchange_rate_state(
            &STATE,
            &Some(UpdateIcpXdrConversionRatePayloadReason::OldRate),
            1680045600,
        );
        let update_exchange_rate_canister_state =
            read_state(&STATE, |state| state.update_exchange_rate_canister_state);
        assert!(matches!(
            update_exchange_rate_canister_state,
            Some(UpdateExchangeRateState::Disabled)
        ));

        set_update_exchange_rate_state(
            &STATE,
            &Some(UpdateIcpXdrConversionRatePayloadReason::EnableAutomaticExchangeRateUpdates),
            1680045900,
        );
        let update_exchange_rate_canister_state =
            read_state(&STATE, |state| state.update_exchange_rate_canister_state);
        assert!(matches!(
            update_exchange_rate_canister_state,
            Some(UpdateExchangeRateState::GetRateAt(1680046200))
        ));
    }
}
