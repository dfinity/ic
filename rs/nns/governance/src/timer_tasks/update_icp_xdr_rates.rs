use crate::{
    governance::{Governance, LOG_PREFIX},
    pb::v1::{IcpXdrRate, IcpXdrRateHistory},
};
use async_trait::async_trait;
use ic_cdk::println;
use ic_nervous_system_clients::exchange_rate_canister_client::{
    ExchangeRateCanisterClient, exchange_rate_to_xdr_permyriad, validate_exchange_rate,
};
use ic_nervous_system_governance::maturity_modulation::{
    MAX_MATURITY_MODULATION_PERMYRIAD, MIN_MATURITY_MODULATION_PERMYRIAD,
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

/// The ring buffer must hold enough days for the longest averaging window.
const MAX_RATES_BUFFER_SIZE: usize = MATURITY_MODULATION_REFERENCE_ICP_PRICE_WINDOW_DAYS;

/// How much the relative difference between current and reference ICP price affects maturity
/// modulation. k = 0.25 means a 10% price increase yields a 2.5% modulation boost.
/// Expressed in permyriad: 0.25 * 10_000 = 2_500.
const MATURITY_MODULATION_SENSITIVITY_PERMYRIAD: i32 = 2_500;

/// Maximum daily change in maturity modulation: 0.3% = 30 permyriad.
const MATURITY_MODULATION_DAILY_SPEED_LIMIT_PERMYRIAD: i32 = 30;

/// Delay between consecutive XRC calls while backfilling historical rates. At 5 seconds per call,
/// filling the full 365-day window takes about 30 minutes.
const BACKFILL_INTERVAL_SECONDS: u64 = 5;

/// Compute the average `xdr_permyriad_per_icp` over the most recent `window_days` days ending
/// at `current_day` (exclusive of `current_day - window_days`, inclusive of `current_day`).
/// Returns `None` if there are no rates in the window.
pub(crate) fn compute_average_icp_xdr_rate(
    rates: &[IcpXdrRate],
    current_day: u64,
    window_days: usize,
) -> Option<u64> {
    let window_start = current_day.saturating_sub(window_days as u64);
    let filtered: Vec<u64> = rates
        .iter()
        .filter(|r| r.days_since_epoch > window_start && r.days_since_epoch <= current_day)
        .map(|r| r.xdr_permyriad_per_icp)
        .collect();
    let count = filtered.len() as u64;
    if count == 0 {
        return None;
    }
    let sum: u64 = filtered.into_iter().sum();
    Some(sum / count)
}

/// Compute the new maturity modulation in permyriad.
///
/// Compares the current ICP price (7-day moving average) to the reference ICP price (365-day
/// moving average) and computes:
///
///   `w_raw = sensitivity * (current_price - reference_price) / reference_price`
///
/// Then applies a daily speed limit (smoothing), followed by global bounds which have final say.
fn compute_maturity_modulation_permyriad(
    rates: &[IcpXdrRate],
    current_day: u64,
    previous_permyriad: i32,
    previous_day: u64,
) -> i32 {
    let recent_icp_price = compute_average_icp_xdr_rate(
        rates,
        current_day,
        MATURITY_MODULATION_CURRENT_ICP_PRICE_WINDOW_DAYS,
    );
    let reference_icp_price = compute_average_icp_xdr_rate(
        rates,
        current_day,
        MATURITY_MODULATION_REFERENCE_ICP_PRICE_WINDOW_DAYS,
    );

    let w_raw = match (recent_icp_price, reference_icp_price) {
        (Some(recent), Some(reference)) if reference > 0 => {
            let recent = recent as i64;
            let reference = reference as i64;
            (MATURITY_MODULATION_SENSITIVITY_PERMYRIAD as i64) * (recent - reference) / reference
        }
        // When price data is insufficient we cannot compute a meaningful modulation. Keeping the
        // previous value avoids a disruptive jump to zero that would affect pending disbursements.
        _ => return previous_permyriad,
    };

    // Limit day-to-day change.
    let days_elapsed = current_day.saturating_sub(previous_day).max(1);
    let max_change =
        MATURITY_MODULATION_DAILY_SPEED_LIMIT_PERMYRIAD.saturating_mul(days_elapsed as i32);
    let w_speed_limited = (w_raw as i32).clamp(
        previous_permyriad.saturating_sub(max_change),
        previous_permyriad.saturating_add(max_change),
    );

    // Global bounds have final say.
    w_speed_limited.clamp(
        MIN_MATURITY_MODULATION_PERMYRIAD,
        MAX_MATURITY_MODULATION_PERMYRIAD,
    )
}

pub(super) struct UpdateIcpXdrRatesTask {
    governance: &'static LocalKey<RefCell<Governance>>,
    xrc_client: Arc<dyn ExchangeRateCanisterClient>,
}

impl UpdateIcpXdrRatesTask {
    pub fn new(
        governance: &'static LocalKey<RefCell<Governance>>,
        xrc_client: Arc<dyn ExchangeRateCanisterClient>,
    ) -> Self {
        Self {
            governance,
            xrc_client,
        }
    }
}

/// Returns the newest day in `[current_day - 364, current_day]` that has no entry in `rates`, or
/// `None` if every day in that range is present. Searching newest-first ensures today's rate is
/// fetched before older ones.
fn find_newest_missing_day(rates: &[IcpXdrRate], current_day: u64) -> Option<u64> {
    let oldest_needed = current_day.saturating_sub(MAX_RATES_BUFFER_SIZE as u64 - 1);
    (oldest_needed..=current_day)
        .rev()
        .find(|&day| !rates.iter().any(|r| r.days_since_epoch == day))
}

/// Returns the number of seconds until the next UTC midnight (i.e. the start of the next day).
fn seconds_until_next_midnight(now: u64) -> u64 {
    // Next multiple of ONE_DAY_SECONDS strictly greater than `now`.
    let next_midnight = (now / ONE_DAY_SECONDS + 1) * ONE_DAY_SECONDS;
    next_midnight - now
}

/// Adds a new rate to the ring buffer, replacing any existing entry for the same day or dropping
/// the oldest entry if the buffer is full.
fn update_rates_buffer(data: &mut IcpXdrRateHistory, new_rate: IcpXdrRate) {
    // Dedup: replace existing entry for the same day.
    if let Some(pos) = data
        .recent_icp_xdr_rates
        .iter()
        .position(|r| r.days_since_epoch == new_rate.days_since_epoch)
    {
        data.recent_icp_xdr_rates[pos] = new_rate;
        return;
    }

    data.recent_icp_xdr_rates.push(new_rate);

    // Keep sorted by days_since_epoch (ascending).
    data.recent_icp_xdr_rates
        .sort_unstable_by_key(|r| r.days_since_epoch);

    // Cap at MAX_RATES_BUFFER_SIZE by removing the oldest entries.
    while data.recent_icp_xdr_rates.len() > MAX_RATES_BUFFER_SIZE {
        data.recent_icp_xdr_rates.remove(0);
    }
}

#[async_trait]
impl RecurringAsyncTask for UpdateIcpXdrRatesTask {
    async fn execute(self) -> (Duration, Self) {
        // Determine whether we need to backfill a historical rate or fetch today's.
        let (current_day, backfill_day) = self.governance.with_borrow(|gov| {
            let current_day = gov.env.now() / ONE_DAY_SECONDS;
            let rates = gov
                .heap_data
                .icp_xdr_rate_history
                .as_ref()
                .map(|d| d.recent_icp_xdr_rates.as_slice())
                .unwrap_or(&[]);
            let backfill_day = find_newest_missing_day(rates, current_day);
            (current_day, backfill_day)
        });

        let is_backfilling = backfill_day.is_some();
        let now = self.governance.with_borrow(|gov| gov.env.now());
        let next_delay = if is_backfilling {
            Duration::from_secs(BACKFILL_INTERVAL_SECONDS)
        } else {
            Duration::from_secs(seconds_until_next_midnight(now))
        };

        // When backfilling, request the rate at midnight UTC of the target day. When fully
        // populated, pass None to get the latest rate.
        let timestamp = backfill_day.map(|day| day * ONE_DAY_SECONDS);

        let exchange_rate = match self.xrc_client.get_exchange_rate(timestamp).await {
            Ok(rate) => rate,
            Err(err) => {
                println!(
                    "{}UpdateIcpXdrRatesTask: XRC call failed: {}",
                    LOG_PREFIX, err
                );
                return (next_delay, self);
            }
        };

        if let Err(err) = validate_exchange_rate(&exchange_rate) {
            println!(
                "{}UpdateIcpXdrRatesTask: XRC rate failed validation: {}",
                LOG_PREFIX, err
            );
            return (next_delay, self);
        }

        let xdr_permyriad_per_icp = exchange_rate_to_xdr_permyriad(&exchange_rate);
        if xdr_permyriad_per_icp == 0 {
            println!(
                "{}UpdateIcpXdrRatesTask: received zero XDR/ICP rate; ignoring.",
                LOG_PREFIX
            );
            return (next_delay, self);
        }

        // Use the timestamp from the XRC response to determine the day, since the XRC may round
        // to the nearest forex day.
        let rate_day = exchange_rate.timestamp / ONE_DAY_SECONDS;

        self.governance.with_borrow_mut(|gov| {
            let new_rate_entry = IcpXdrRate {
                days_since_epoch: rate_day,
                xdr_permyriad_per_icp,
            };

            let (new_permyriad, avg_30d, buffer_size) = {
                let data = gov
                    .heap_data
                    .icp_xdr_rate_history
                    .get_or_insert_with(IcpXdrRateHistory::default);

                update_rates_buffer(data, new_rate_entry);

                let previous_permyriad = data.current_maturity_modulation_permyriad.unwrap_or(0);
                let previous_day = data
                    .maturity_modulation_updated_at_days_since_epoch
                    .unwrap_or(0);

                let new_permyriad = compute_maturity_modulation_permyriad(
                    &data.recent_icp_xdr_rates,
                    current_day,
                    previous_permyriad,
                    previous_day,
                );

                let avg_30d =
                    compute_average_icp_xdr_rate(&data.recent_icp_xdr_rates, current_day, 30);

                data.current_maturity_modulation_permyriad = Some(new_permyriad);
                data.maturity_modulation_updated_at_days_since_epoch = Some(current_day);

                (new_permyriad, avg_30d, data.recent_icp_xdr_rates.len())
                // `data` borrow ends here.
            };

            println!(
                "{}UpdateIcpXdrRatesTask: {} maturity modulation {} permyriad \
                 (xdr_permyriad_per_icp={}, rate_day={}, buffer_size={})",
                LOG_PREFIX,
                if is_backfilling {
                    "backfill:"
                } else {
                    "computed"
                },
                new_permyriad,
                xdr_permyriad_per_icp,
                rate_day,
                buffer_size,
            );

            // Keep xdr_conversion_rate up-to-date so that icp_xdr_rate() and node provider
            // reward calculations reflect the locally computed 30-day average.
            if let Some(avg_rate) = avg_30d {
                gov.heap_data.xdr_conversion_rate.timestamp_seconds = current_day * ONE_DAY_SECONDS;
                gov.heap_data.xdr_conversion_rate.xdr_permyriad_per_icp = avg_rate;
            }
        });

        (next_delay, self)
    }

    fn initial_delay(&self) -> Duration {
        Duration::ZERO
    }

    const NAME: &'static str = "update_icp_xdr_rates";
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rate(days: u64, rate: u64) -> IcpXdrRate {
        IcpXdrRate {
            days_since_epoch: days,
            xdr_permyriad_per_icp: rate,
        }
    }

    fn make_history(rates: Vec<IcpXdrRate>) -> IcpXdrRateHistory {
        IcpXdrRateHistory {
            recent_icp_xdr_rates: rates,
            current_maturity_modulation_permyriad: None,
            maturity_modulation_updated_at_days_since_epoch: None,
        }
    }

    #[test]
    fn test_update_rates_buffer_dedup_same_day() {
        let mut data = make_history(vec![make_rate(100, 50_000)]);
        update_rates_buffer(&mut data, make_rate(100, 55_000));
        assert_eq!(data.recent_icp_xdr_rates.len(), 1);
        assert_eq!(data.recent_icp_xdr_rates[0].xdr_permyriad_per_icp, 55_000);
    }

    #[test]
    fn test_update_rates_buffer_adds_new_day() {
        let mut data = make_history(vec![make_rate(100, 50_000)]);
        update_rates_buffer(&mut data, make_rate(101, 52_000));
        assert_eq!(data.recent_icp_xdr_rates.len(), 2);
        assert_eq!(data.recent_icp_xdr_rates[1].days_since_epoch, 101);
    }

    #[test]
    fn test_update_rates_buffer_sorted() {
        let mut data = make_history(vec![make_rate(100, 50_000), make_rate(102, 51_000)]);
        update_rates_buffer(&mut data, make_rate(101, 52_000));
        let days: Vec<u64> = data
            .recent_icp_xdr_rates
            .iter()
            .map(|r| r.days_since_epoch)
            .collect();
        assert_eq!(days, vec![100, 101, 102]);
    }

    #[test]
    fn test_update_rates_buffer_caps_at_max() {
        let rates: Vec<IcpXdrRate> = (0..MAX_RATES_BUFFER_SIZE as u64)
            .map(|d| make_rate(d, 50_000))
            .collect();
        let mut data = make_history(rates);
        // Adding one more entry should drop the oldest.
        update_rates_buffer(&mut data, make_rate(MAX_RATES_BUFFER_SIZE as u64, 55_000));
        assert_eq!(data.recent_icp_xdr_rates.len(), MAX_RATES_BUFFER_SIZE);
        assert_eq!(data.recent_icp_xdr_rates[0].days_since_epoch, 1);
        assert_eq!(
            data.recent_icp_xdr_rates[MAX_RATES_BUFFER_SIZE - 1].days_since_epoch,
            MAX_RATES_BUFFER_SIZE as u64
        );
    }

    #[test]
    fn test_compute_maturity_modulation_no_data() {
        // With no rates, should return previous_permyriad unchanged.
        let result = compute_maturity_modulation_permyriad(&[], 100, 50, 99);
        assert_eq!(result, 50);
    }

    #[test]
    fn test_compute_maturity_modulation_stable_price() {
        // When recent == reference, modulation should be 0.
        let rates: Vec<IcpXdrRate> = (1..=365).map(|d| make_rate(d, 50_000)).collect();
        let result = compute_maturity_modulation_permyriad(&rates, 365, 0, 364);
        assert_eq!(result, 0);
    }

    #[test]
    fn test_compute_maturity_modulation_price_increase() {
        // Recent price > reference price => positive modulation (capped by speed limit from 0).
        let mut rates: Vec<IcpXdrRate> = (1..=358).map(|d| make_rate(d, 50_000)).collect();
        for d in 359..=365 {
            rates.push(make_rate(d, 60_000));
        }
        let result = compute_maturity_modulation_permyriad(&rates, 365, 0, 364);
        assert!(result > 0);
        assert!(result <= MATURITY_MODULATION_DAILY_SPEED_LIMIT_PERMYRIAD);
    }

    #[test]
    fn test_compute_maturity_modulation_respects_global_bounds() {
        // Even with extreme speed limit allowance, global bounds cap the result.
        let rates: Vec<IcpXdrRate> = (1..=365).map(|d| make_rate(d, 50_000)).collect();
        let result = compute_maturity_modulation_permyriad(
            &rates,
            365,
            MAX_MATURITY_MODULATION_PERMYRIAD,
            0, // large gap => large speed allowance
        );
        assert!(result <= MAX_MATURITY_MODULATION_PERMYRIAD);
    }

    #[test]
    fn test_seconds_until_next_midnight() {
        // Exactly at midnight: should be one full day.
        assert_eq!(seconds_until_next_midnight(0), ONE_DAY_SECONDS);
        assert_eq!(
            seconds_until_next_midnight(ONE_DAY_SECONDS),
            ONE_DAY_SECONDS
        );

        // Noon → 12 hours until midnight.
        assert_eq!(
            seconds_until_next_midnight(ONE_DAY_SECONDS / 2),
            ONE_DAY_SECONDS / 2
        );

        // 1 second past midnight → almost a full day remaining.
        assert_eq!(
            seconds_until_next_midnight(ONE_DAY_SECONDS + 1),
            ONE_DAY_SECONDS - 1
        );
    }
}
