use crate::{
    governance::{Governance, LOG_PREFIX},
    pb::v1::{IcpPriceHistory, MaturityModulation, SampledPrice},
};
use async_trait::async_trait;
use ic_cdk::println;
use ic_nervous_system_clients::exchange_rate_canister_client::{
    ExchangeRateCanisterClient, exchange_rate_to_permyriad, validate_exchange_rate,
};
use ic_nervous_system_timer_task::RecurringAsyncTask;
use std::cell::RefCell;
use std::sync::Arc;
use std::thread::LocalKey;
use std::time::Duration;

pub(crate) const ONE_DAY_SECONDS: u64 = 86_400;

// ---- Maturity modulation algorithm ----
//
// Maturity modulation is the conversion factor from maturity to ICP. It is designed to have a
// stabilizing effect on the price of ICP: when the recent ICP price is above its long-term
// average, modulation is positive (more ICP per maturity), encouraging selling pressure; when
// below, modulation is negative (less ICP per maturity), discouraging selling.
//
// The result is in permyriad. For example, if this returns `mm` and the maturity being converted
// is `r`, the ICP minted is `r * (1 + mm / 10_000)`.

/// Window size for the "current" ICP price estimate used in maturity modulation. A short window
/// tracks recent price movements.
const MATURITY_MODULATION_CURRENT_ICP_PRICE_WINDOW_DAYS: usize = 7;

/// Window size for the "reference" (long-term average) ICP price used in maturity modulation.
const MATURITY_MODULATION_REFERENCE_ICP_PRICE_WINDOW_DAYS: usize = 365;

/// The sorted rate vector must hold enough days for the longest averaging window.
const MAX_RATES_BUFFER_SIZE: usize = MATURITY_MODULATION_REFERENCE_ICP_PRICE_WINDOW_DAYS;

/// How much the relative difference between current and reference ICP price affects maturity
/// modulation. k = 0.25 means a 10% price increase yields a 2.5% modulation boost.
/// Expressed in permyriad: 0.25 * 10_000 = 2_500.
const MATURITY_MODULATION_SENSITIVITY_PERMYRIAD: i64 = 2_500;

/// Maximum daily change in maturity modulation: 0.3% = 30 permyriad.
const MATURITY_MODULATION_DAILY_SPEED_LIMIT_PERMYRIAD: i64 = 30;

/// Lower bound for Mission 70 maturity modulation: -10% = -1000 permyriad.
pub(crate) const MATURITY_MODULATION_MIN_PERMYRIAD_MISSION_70: i64 = -1_000;

/// Upper bound for Mission 70 maturity modulation: +2% = 200 permyriad.
pub(crate) const MATURITY_MODULATION_MAX_PERMYRIAD_MISSION_70: i64 = 200;

/// Delay between consecutive XRC calls while backfilling historical rates. At 5 seconds per call,
/// filling the full 365-day window takes about 30 minutes.
const BACKFILL_INTERVAL_SECONDS: u64 = 5;

/// Retry delay after a transient XRC failure. Short so we recover quickly without hammering XRC.
const ERROR_RETRY_INTERVAL_SECONDS: u64 = 60;

/// Compute the average `xdr_permyriad_per_icp` over the most recent `window_days` days ending
/// at `current_day` (exclusive of `current_day - window_days`, inclusive of `current_day`).
/// Returns `None` if there are no rates in the window.
pub(crate) fn compute_average_icp_xdr_rate(
    rates: &[SampledPrice],
    current_day: u64,
    window_days: usize,
) -> Option<u64> {
    let window_start = current_day.saturating_sub(window_days as u64);
    let filtered: Vec<u64> = rates
        .iter()
        .filter(|r| {
            let day = r.timestamp_seconds / ONE_DAY_SECONDS;
            day > window_start && day <= current_day
        })
        .map(|r| r.xdr_permyriad_per_icp)
        .collect();
    let count = filtered.len() as u64;
    if (count as usize) < window_days {
        println!(
            "{}compute_average_icp_xdr_rate: only {} of {} days available in window (current_day={})",
            LOG_PREFIX, count, window_days, current_day
        );
    }
    if count == 0 {
        return None;
    }
    let sum: u128 = filtered.into_iter().map(|r| r as u128).sum();
    Some((sum / count as u128) as u64)
}

/// Compute the new maturity modulation in permyriad.
///
/// Compares the current ICP price (7-day moving average) to the reference ICP price (365-day
/// moving average) and computes:
///
///   `target = sensitivity * (current_price - reference_price) / reference_price`
///
/// Then applies a daily speed limit (smoothing), followed by global bounds which have final say.
fn compute_maturity_modulation_permyriad(
    rates: &[SampledPrice],
    current_day: u64,
    previous_permyriad: i64,
    previous_day: u64,
) -> i64 {
    let Some(recent_icp_price) = compute_average_icp_xdr_rate(
        rates,
        current_day,
        MATURITY_MODULATION_CURRENT_ICP_PRICE_WINDOW_DAYS,
    ) else {
        println!(
            "{}compute_maturity_modulation_permyriad: insufficient recent price data; keeping previous value {}",
            LOG_PREFIX, previous_permyriad
        );
        return previous_permyriad;
    };

    let Some(reference_icp_price) = compute_average_icp_xdr_rate(
        rates,
        current_day,
        MATURITY_MODULATION_REFERENCE_ICP_PRICE_WINDOW_DAYS,
    ) else {
        println!(
            "{}compute_maturity_modulation_permyriad: insufficient reference price data; keeping previous value {}",
            LOG_PREFIX, previous_permyriad
        );
        return previous_permyriad;
    };

    if reference_icp_price == 0 {
        println!(
            "{}compute_maturity_modulation_permyriad: reference price is zero; keeping previous value {}",
            LOG_PREFIX, previous_permyriad
        );
        return previous_permyriad;
    }

    let target_modulation = {
        let recent = recent_icp_price as i128;
        let reference = reference_icp_price as i128;
        let sensitivity = MATURITY_MODULATION_SENSITIVITY_PERMYRIAD as i128;
        sensitivity * (recent - reference) / reference
    };

    // Limit day-to-day change.
    let days_elapsed = current_day.saturating_sub(previous_day);
    let max_change = if days_elapsed > 1 {
        // The timer missed one or more days — allow proportionally more change.
        println!(
            "{}compute_maturity_modulation_permyriad: {} days elapsed since last update (current_day={}, previous_day={})",
            LOG_PREFIX, days_elapsed, current_day, previous_day
        );
        MATURITY_MODULATION_DAILY_SPEED_LIMIT_PERMYRIAD.saturating_mul(days_elapsed as i64)
    } else if days_elapsed == 1 {
        MATURITY_MODULATION_DAILY_SPEED_LIMIT_PERMYRIAD
    } else {
        // days_elapsed == 0: either same day or current_day < previous_day (should not happen).
        // Allow at least one day of movement.
        println!(
            "{}compute_maturity_modulation_permyriad: days_elapsed=0 (current_day={}, previous_day={}); treating as 1 day",
            LOG_PREFIX, current_day, previous_day
        );
        MATURITY_MODULATION_DAILY_SPEED_LIMIT_PERMYRIAD
    };
    let speed_limited = target_modulation.clamp(
        previous_permyriad.saturating_sub(max_change) as i128,
        previous_permyriad.saturating_add(max_change) as i128,
    );

    // Global bounds have final say. The result is within [MIN, MAX] which fit in i64, so the
    // cast is safe.
    speed_limited.clamp(
        MATURITY_MODULATION_MIN_PERMYRIAD_MISSION_70 as i128,
        MATURITY_MODULATION_MAX_PERMYRIAD_MISSION_70 as i128,
    ) as i64
}

pub(super) struct UpdateIcpXdrRateRelatedData {
    governance: &'static LocalKey<RefCell<Governance>>,
    xrc_client: Arc<dyn ExchangeRateCanisterClient>,
}

impl UpdateIcpXdrRateRelatedData {
    pub fn new(
        governance: &'static LocalKey<RefCell<Governance>>,
        xrc_client: Arc<dyn ExchangeRateCanisterClient>,
    ) -> Self {
        Self {
            governance,
            xrc_client,
        }
    }

    /// Returns the oldest missing day in `[current_day - 364, current_day]`, or `None` if the
    /// history is complete (every day in that range is present).
    ///
    /// Walks the sorted rates slice and the expected day range together in O(n).
    fn get_day_to_fetch(&self, current_day: u64) -> Option<u64> {
        self.governance.with_borrow(|gov| {
            let icp_xdr_rates = &gov
                .heap_data
                .icp_price_history
                .as_ref()
                .map(|h| &h.icp_xdr_rates[..])
                .unwrap_or(&[]);
            let oldest_needed = current_day.saturating_sub(MAX_RATES_BUFFER_SIZE as u64 - 1);
            let mut rate_idx = 0;
            for day in oldest_needed..=current_day {
                let midnight = day * ONE_DAY_SECONDS;
                while rate_idx < icp_xdr_rates.len()
                    && icp_xdr_rates[rate_idx].timestamp_seconds < midnight
                {
                    rate_idx += 1;
                }
                if rate_idx >= icp_xdr_rates.len()
                    || icp_xdr_rates[rate_idx].timestamp_seconds != midnight
                {
                    return Some(day);
                }
                rate_idx += 1;
            }
            None
        })
    }

    /// Fetches the ICP/XDR rate from XRC for `timestamp`, validates, and converts.
    /// Returns `None` if any step fails (errors are logged).
    async fn fetch_and_validate_rate(&self, timestamp: u64) -> Option<SampledPrice> {
        let exchange_rate = match self
            .xrc_client
            .get_icp_to_xdr_exchange_rate(Some(timestamp))
            .await
        {
            Ok(rate) => rate,
            Err(err) => {
                println!(
                    "{}UpdateIcpXdrRateRelatedData: XRC call failed: {}",
                    LOG_PREFIX, err
                );
                return None;
            }
        };

        if let Err(err) = validate_exchange_rate(&exchange_rate) {
            println!(
                "{}UpdateIcpXdrRateRelatedData: XRC rate failed validation: {}",
                LOG_PREFIX, err
            );
            return None;
        }

        // Verify that XRC returned a rate for the day we requested. If not, the rate
        // won't fill the expected slot and backfill would loop on the same day.
        if exchange_rate.timestamp != timestamp {
            println!(
                "{}UpdateIcpXdrRateRelatedData: requested timestamp {} but XRC returned {}; ignoring.",
                LOG_PREFIX, timestamp, exchange_rate.timestamp
            );
            return None;
        }

        let rate = SampledPrice::from(&exchange_rate);
        if rate.xdr_permyriad_per_icp == 0 {
            println!(
                "{}UpdateIcpXdrRateRelatedData: received zero XDR/ICP rate; ignoring.",
                LOG_PREFIX
            );
            return None;
        }

        Some(rate)
    }
}

/// Returns the duration until the next UTC midnight (i.e. the start of the next day).
fn duration_until_next_midnight_utc(timestamp_seconds: u64) -> Duration {
    let next_midnight_timestamp_seconds =
        (timestamp_seconds / ONE_DAY_SECONDS + 1) * ONE_DAY_SECONDS;
    Duration::from_secs(next_midnight_timestamp_seconds - timestamp_seconds)
}

impl From<&ic_xrc_types::ExchangeRate> for SampledPrice {
    fn from(exchange_rate: &ic_xrc_types::ExchangeRate) -> Self {
        if !exchange_rate.timestamp.is_multiple_of(ONE_DAY_SECONDS) {
            println!(
                "{}SampledPrice::from: XRC timestamp {} is not aligned to midnight UTC",
                LOG_PREFIX, exchange_rate.timestamp
            );
        }
        Self {
            timestamp_seconds: exchange_rate.timestamp,
            xdr_permyriad_per_icp: exchange_rate_to_permyriad(exchange_rate),
        }
    }
}

/// Inserts new_rate into icp_price_history, maintaining chronological order.
///
/// (It is assumed that icp_price_history is originally in chronological order.)
///
/// If there is an existing entry with the same day, replaces it.
///
/// If the result of insertion causes the length to exceed MAX_RATES_BUFFER_SIZE (365),
/// pops the first element.
fn update_rates_buffer(icp_price_history: &mut IcpPriceHistory, new_rate: SampledPrice) {
    let rates = &mut icp_price_history.icp_xdr_rates;

    match rates.binary_search_by_key(&new_rate.timestamp_seconds, |r| r.timestamp_seconds) {
        Ok(pos) => {
            // Shouldn't happen: we only fetch days absent from the buffer.
            println!(
                "{}update_rates_buffer: replacing existing entry for timestamp {} (old={}, new={})",
                LOG_PREFIX,
                new_rate.timestamp_seconds,
                rates[pos].xdr_permyriad_per_icp,
                new_rate.xdr_permyriad_per_icp,
            );
            rates[pos] = new_rate;
            return;
        }
        Err(pos) => {
            // Insert the new rate into the already-sorted vector at the correct position (O(n)
            // shift). New rates usually arrive in order, so pos == rates.len() is the common case.
            rates.insert(pos, new_rate);
        }
    }

    // Evict the oldest entry when the buffer is full. Since we insert at most one entry at a time,
    // the length can exceed capacity by at most one.
    if rates.len() > MAX_RATES_BUFFER_SIZE {
        rates.remove(0);
    }
}

/// Recomputes maturity modulation from the current price history and updates `maturity_modulation`.
///
/// Callers must ensure the 365-day window is fully populated before calling this function.
fn update_maturity_modulation(
    icp_price_history: &IcpPriceHistory,
    maturity_modulation: &mut MaturityModulation,
    current_day: u64,
) {
    if maturity_modulation.updated_at_days_since_epoch == Some(current_day) {
        return;
    }

    let previous_permyriad = maturity_modulation.current_value_permyriad.unwrap_or(0) as i64;
    let previous_day = maturity_modulation.updated_at_days_since_epoch.unwrap_or(0);

    let new_permyriad = compute_maturity_modulation_permyriad(
        &icp_price_history.icp_xdr_rates,
        current_day,
        previous_permyriad,
        previous_day,
    );

    maturity_modulation.current_value_permyriad = Some(new_permyriad as i32);
    maturity_modulation.updated_at_days_since_epoch = Some(current_day);
}

#[async_trait]
impl RecurringAsyncTask for UpdateIcpXdrRateRelatedData {
    async fn execute(self) -> (Duration, Self) {
        let current_day = self
            .governance
            .with_borrow(|gov| gov.env.now() / ONE_DAY_SECONDS);

        // Determine which price to fetch.
        let Some(day_to_fetch) = self.get_day_to_fetch(current_day) else {
            // History is already complete. This is unexpected (the timer delay should prevent it),
            // but not harmful — just log and wait for the next day.
            println!(
                "{}UpdateIcpXdrRateRelatedData: history already complete for day {}; \
                 nothing to fetch.",
                LOG_PREFIX, current_day
            );

            // History is complete for current_day: compute maturity modulation.
            self.governance.with_borrow_mut(|gov| {
                let data = &mut gov.heap_data;
                let Some(icp_price_history) = data.icp_price_history.as_ref() else {
                    println!(
                        "{}UpdateIcpXdrRateRelatedData: icp_price_history is None \
                         despite history being complete; skipping modulation update.",
                        LOG_PREFIX
                    );
                    return;
                };
                let maturity_modulation = data
                    .maturity_modulation
                    .get_or_insert_with(MaturityModulation::default);
                update_maturity_modulation(icp_price_history, maturity_modulation, current_day);
                println!(
                    "{}UpdateIcpXdrRateRelatedData: maturity modulation {} permyriad \
                     (day={}, buffer_size={})",
                    LOG_PREFIX,
                    maturity_modulation.current_value_permyriad.unwrap_or(0),
                    current_day,
                    icp_price_history.icp_xdr_rates.len(),
                );
            });

            let now = self.governance.with_borrow(|gov| gov.env.now());
            return (duration_until_next_midnight_utc(now), self);
        };

        // Fetch missing price.
        let Some(rate) = self
            .fetch_and_validate_rate(day_to_fetch * ONE_DAY_SECONDS)
            .await
        else {
            return (Duration::from_secs(ERROR_RETRY_INTERVAL_SECONDS), self);
        };

        // Insert new/missing exchange rate into price history.
        self.governance.with_borrow_mut(|gov| {
            let history = gov
                .heap_data
                .icp_price_history
                .get_or_insert_with(IcpPriceHistory::default);
            update_rates_buffer(history, rate);
        });

        // Wait the backfill interval. The next iteration will either fetch the next missing day,
        // or — if history is now complete — update maturity modulation via the branch above.
        (Duration::from_secs(BACKFILL_INTERVAL_SECONDS), self)
    }

    fn initial_delay(&self) -> Duration {
        let current_day = self
            .governance
            .with_borrow(|gov| gov.env.now() / ONE_DAY_SECONDS);
        if self.get_day_to_fetch(current_day).is_some() {
            Duration::ZERO
        } else {
            let now = self.governance.with_borrow(|gov| gov.env.now());
            duration_until_next_midnight_utc(now)
        }
    }

    const NAME: &'static str = "UpdateIcpXdrRateRelatedData";
}

#[cfg(test)]
#[path = "update_icp_xdr_rate_related_data_tests.rs"]
mod tests;
