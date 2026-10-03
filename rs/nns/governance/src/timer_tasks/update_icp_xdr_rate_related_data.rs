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
///
/// For each day in the window, uses that day's rate if present, otherwise falls back to the most
/// recent prior day's rate (Last Observation Carried Forward). This keeps the average meaningful
/// even when XRC fails to return a rate for one or more days. The fallback is computation-only;
/// nothing is written back to `rates`.
///
/// Returns `None` only when LOCF never finds a value to carry — i.e., no rate in the buffer has
/// a timestamp at or before `current_day` (so every day in the window is skipped). If a rate
/// appears partway into the window, leading days that precede it are skipped and the average is
/// computed over the days that do have a value.
pub(crate) fn compute_average_icp_xdr_rate(
    rates: &[SampledPrice],
    current_day: u64,
    window_days: usize,
) -> Option<u64> {
    if window_days == 0 {
        return None;
    }
    let oldest_day_in_window = current_day
        .saturating_sub(window_days as u64)
        .saturating_add(1);

    // Single linear pass: walk days and rates together, carrying the latest seen value forward.
    // For each day, advance through every rate at or before that day so `current_value` holds
    // the LOCF value when we sum. Days iterated before the first rate appears contribute
    // nothing (LOCF has no prior to carry forward).
    let mut rate_idx = 0;
    let mut current_value: Option<u64> = None;
    let mut sum: u128 = 0;
    let mut count: u64 = 0;
    for day in oldest_day_in_window..=current_day {
        let midnight = day * ONE_DAY_SECONDS;
        while rate_idx < rates.len() && rates[rate_idx].timestamp_seconds <= midnight {
            current_value = Some(rates[rate_idx].xdr_permyriad_per_icp);
            rate_idx += 1;
        }
        if let Some(v) = current_value {
            sum += v as u128;
            count += 1;
        }
    }

    if (count as usize) < window_days {
        println!(
            "{}compute_average_icp_xdr_rate: only {} of {} days have a rate available \
             (current_day={})",
            LOG_PREFIX, count, window_days, current_day
        );
    }
    if count == 0 {
        return None;
    }
    Some((sum / count as u128) as u64)
}

/// Compute the new maturity modulation in permyriad.
///
/// Compares the current ICP price (7-day moving average) to the reference ICP price (365-day
/// moving average) and computes:
///
///   `target = sensitivity * (current_price - reference_price) / reference_price`
///
/// On the first calculation (`previous` is `None`), the target is returned subject only to global
/// bounds — the speed limit needs a baseline to be meaningful. On subsequent calculations a daily
/// speed limit smooths day-to-day change, and global bounds have final say.
///
/// Returns `Err` with a reason if the inputs make the calculation impossible (e.g. price history
/// is incomplete or the reference price is zero). Callers that hit `Err` should leave the prior
/// modulation value untouched and log the reason.
fn compute_maturity_modulation_permyriad(
    rates: &[SampledPrice],
    current_day: u64,
    previous: Option<(i64, u64)>,
) -> Result<i64, String> {
    let recent_icp_price = compute_average_icp_xdr_rate(
        rates,
        current_day,
        MATURITY_MODULATION_CURRENT_ICP_PRICE_WINDOW_DAYS,
    )
    .ok_or_else(|| "no rate available for the recent price window".to_string())?;

    let reference_icp_price = compute_average_icp_xdr_rate(
        rates,
        current_day,
        MATURITY_MODULATION_REFERENCE_ICP_PRICE_WINDOW_DAYS,
    )
    .ok_or_else(|| "no rate available for the reference price window".to_string())?;

    if reference_icp_price == 0 {
        return Err("reference price averaged to zero".to_string());
    }

    let target_modulation = {
        let recent = recent_icp_price as i128;
        let reference = reference_icp_price as i128;
        let sensitivity = MATURITY_MODULATION_SENSITIVITY_PERMYRIAD as i128;
        sensitivity * (recent - reference) / reference
    };

    let speed_limited = match previous {
        // First calculation: no baseline to smooth from, so jump straight to target.
        None => target_modulation,
        Some((previous_permyriad, previous_day)) => {
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
            target_modulation.clamp(
                previous_permyriad.saturating_sub(max_change) as i128,
                previous_permyriad.saturating_add(max_change) as i128,
            )
        }
    };

    // Global bounds have final say. The result is within [MIN, MAX] which fit in i64, so the
    // cast is safe.
    Ok(speed_limited.clamp(
        MATURITY_MODULATION_MIN_PERMYRIAD_MISSION_70 as i128,
        MATURITY_MODULATION_MAX_PERMYRIAD_MISSION_70 as i128,
    ) as i64)
}

pub(super) struct UpdateIcpXdrRateRelatedData {
    governance: &'static LocalKey<RefCell<Governance>>,
    xrc_client: Arc<dyn ExchangeRateCanisterClient>,
    /// Highest day attempted in the current backfill round. Failed fetches advance this so the
    /// next tick moves on to other missing days instead of looping on one that keeps failing.
    /// Reset to `None` at the end of a round (when maturity modulation is updated). The state is
    /// in-memory only and resets across canister upgrades; that just means the next round retries
    /// everything from scratch, which is what the next-midnight tick would do anyway.
    last_attempted_day_in_round: Option<u64>,
}

impl UpdateIcpXdrRateRelatedData {
    pub fn new(
        governance: &'static LocalKey<RefCell<Governance>>,
        xrc_client: Arc<dyn ExchangeRateCanisterClient>,
    ) -> Self {
        Self {
            governance,
            xrc_client,
            last_attempted_day_in_round: None,
        }
    }

    /// Returns the oldest missing day in `[current_day - 364, current_day]` that is strictly
    /// greater than `self.last_attempted_day_in_round`, or `None` if no such day exists (either the
    /// history is complete or every missing day in the window has been attempted this round).
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
            let start_day = match self.last_attempted_day_in_round {
                Some(d) => d.saturating_add(1).max(oldest_needed),
                None => oldest_needed,
            };
            if start_day > current_day {
                return None;
            }
            let mut rate_idx = icp_xdr_rates
                .partition_point(|r| r.timestamp_seconds < start_day * ONE_DAY_SECONDS);
            for day in start_day..=current_day {
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
/// Eviction of stale entries is done separately by [`evict_stale_rates`], anchored on
/// `current_day` rather than buffer length, since gaps from failed fetches mean buffer size
/// does not correspond to lookback coverage.
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
        }
        Err(pos) => {
            // Insert the new rate into the already-sorted vector at the correct position (O(n)
            // shift). New rates usually arrive in order, so pos == rates.len() is the common case.
            rates.insert(pos, new_rate);
        }
    }
}

/// Drops entries before the lookback window, but keeps the single most-recent entry from before
/// the window (the LOCF seed). The seed lets `compute_average_icp_xdr_rate` carry a value forward
/// into any leading days of the window that are missing because their fetches failed.
///
/// Eviction is timestamp-based, not size-based: with gaps from failed fetches, the buffer may
/// hold fewer entries than the window spans, so capping by length would discard days that are
/// still within the window.
fn evict_stale_rates(icp_price_history: &mut IcpPriceHistory, current_day: u64) {
    let oldest_kept_day = current_day.saturating_sub(MAX_RATES_BUFFER_SIZE as u64 - 1);
    let oldest_kept_seconds = oldest_kept_day * ONE_DAY_SECONDS;
    let rates = &mut icp_price_history.icp_xdr_rates;
    // Number of entries strictly before the window. We keep the most recent of these as the LOCF
    // seed; the rest (older ones) are dropped.
    let before_window = rates.partition_point(|r| r.timestamp_seconds < oldest_kept_seconds);
    let drop_count = before_window.saturating_sub(1);
    if drop_count > 0 {
        rates.drain(0..drop_count);
    }
}

/// Recomputes maturity modulation from the current price history and updates `maturity_modulation`.
///
/// Tolerates gaps in the price history: averages use LOCF in `compute_average_icp_xdr_rate`. If
/// the buffer has no rate at or before any day in the recent window, the calculation returns
/// `Err` and the prior modulation value is preserved.
fn update_maturity_modulation(
    icp_price_history: &IcpPriceHistory,
    maturity_modulation: &mut MaturityModulation,
    current_day: u64,
) {
    if maturity_modulation.updated_at_days_since_epoch == current_day {
        return;
    }

    // `updated_at_days_since_epoch == 0` is the "never measured" sentinel; in that case there is
    // no baseline to smooth from and `compute_maturity_modulation_permyriad` should jump straight
    // to the target.
    let previous = if maturity_modulation.updated_at_days_since_epoch == 0 {
        None
    } else {
        Some((
            maturity_modulation.current_value_permyriad as i64,
            maturity_modulation.updated_at_days_since_epoch,
        ))
    };

    match compute_maturity_modulation_permyriad(
        &icp_price_history.icp_xdr_rates,
        current_day,
        previous,
    ) {
        Ok(new_permyriad) => {
            maturity_modulation.current_value_permyriad = new_permyriad as i32;
            maturity_modulation.updated_at_days_since_epoch = current_day;
        }
        Err(reason) => {
            // Reaches this branch only when the buffer has no rate at or before any day in the
            // recent window (e.g., a fresh canister where every backfill fetch has failed so far,
            // or every fetched rate was zero). Log and leave the prior modulation untouched —
            // subsequent rounds will retry the missing days.
            println!(
                "{}update_maturity_modulation: skipping update: {}; leaving prior modulation \
                 unchanged",
                LOG_PREFIX, reason
            );
        }
    }
}

#[async_trait]
impl RecurringAsyncTask for UpdateIcpXdrRateRelatedData {
    async fn execute(mut self) -> (Duration, Self) {
        let now = self.governance.with_borrow(|gov| gov.env.now());
        let current_day = now / ONE_DAY_SECONDS;

        // Drop entries that have rolled out of the lookback window. With timestamp-based
        // eviction, gaps from failed fetches do not cause us to evict days still within the
        // window.
        self.governance.with_borrow_mut(|gov| {
            if let Some(history) = gov.heap_data.icp_price_history.as_mut() {
                evict_stale_rates(history, current_day);
            }
        });

        // Guard against firing before midnight has actually rolled over: if maturity modulation
        // has already been updated for `current_day`, the timer fired early. Reschedule for the
        // next midnight without doing any work.
        let already_updated_today = self.governance.with_borrow(|gov| {
            gov.heap_data
                .maturity_modulation
                .as_ref()
                .map(|mm| mm.updated_at_days_since_epoch)
                == Some(current_day)
        });
        if already_updated_today {
            return (duration_until_next_midnight_utc(now), self);
        }

        // Determine which price to fetch.
        let Some(day_to_fetch) = self.get_day_to_fetch(current_day) else {
            // Every missing day in the lookback window has been attempted this round (or none
            // was missing to begin with). Compute maturity modulation with what we have — gaps
            // are tolerated via LOCF in compute_average_icp_xdr_rate — then sleep until the next
            // midnight, when a fresh round retries any days that are still missing.
            self.governance.with_borrow_mut(|gov| {
                let data = &mut gov.heap_data;
                let Some(icp_price_history) = data.icp_price_history.as_ref() else {
                    println!(
                        "{}UpdateIcpXdrRateRelatedData: icp_price_history is None; \
                         skipping modulation update.",
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
                    maturity_modulation.current_value_permyriad,
                    current_day,
                    icp_price_history.icp_xdr_rates.len(),
                );
            });

            self.last_attempted_day_in_round = None;
            return (duration_until_next_midnight_utc(now), self);
        };

        // Attempt the next missing day. Advance the cursor whether the fetch succeeds or fails
        // so the next tick moves on instead of looping on a day that keeps failing. Failed days
        // will be retried by the next midnight's fresh round (until they fall out of the window).
        let maybe_rate = self
            .fetch_and_validate_rate(day_to_fetch * ONE_DAY_SECONDS)
            .await;
        self.last_attempted_day_in_round = Some(day_to_fetch);

        let Some(rate) = maybe_rate else {
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
        // or — if no missing days remain — update maturity modulation via the branch above.
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
