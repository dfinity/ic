use std::{ops::Range, time::Duration};

use crate::{CallCanisters, ProgressNetwork};

pub mod nns;
pub mod sns;

/// First, advances time by `expected_event_interval_seconds.start` seconds.
/// Then, gradually advances time by up to the length of the interval `expected_event_interval_seconds`,
/// observing the state using the provided `observe` function after each (evenly-timed) tick.
/// - If the observed state matches the `expected` state, it returns `Ok(())`.
/// - If the timeout is reached, it returns an error with the last observation.
///
/// The frequency of ticks is 1 per second for small intervals of `expected_event_interval_seconds`, and gradually
/// lower for larger intervals to guarantee at most 500 ticks.
///
/// Example:
/// ```
/// let upgrade_journal_interval_seconds = 60 * 60;
/// await_with_timeout(
///     &agent,
///     0..upgrade_journal_interval_seconds,
///     |agent| async {
///         sns.governance.get_upgrade_journal(agent, GetUpgradeJournalRequest::default())
///             .await
///             .upgrade_steps
///             .unwrap()
///             .versions
///     },
///     &vec![initial_sns_version.clone()],
/// )
/// .await
/// .unwrap();
/// ```
pub async fn await_with_timeout<'a, C, T, F, Fut>(
    agent: &'a C,
    expected_event_interval_seconds: Range<u64>,
    observe: F,
    expected: &T,
) -> Result<(), String>
where
    C: CallCanisters + ProgressNetwork,
    T: std::cmp::PartialEq + std::fmt::Debug,
    F: Fn(&'a C) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    assert!(
        expected_event_interval_seconds.start < expected_event_interval_seconds.end,
        "expected_event_interval_seconds.start must be less than expected_event_interval_seconds.end"
    );
    let timeout_seconds =
        expected_event_interval_seconds.end - expected_event_interval_seconds.start;
    agent
        .progress(Duration::from_secs(expected_event_interval_seconds.start))
        .await;

    let mut counter = 0;
    let num_ticks = timeout_seconds.min(500);
    let seconds_per_tick = (timeout_seconds as f64 / num_ticks as f64).ceil() as u64;

    loop {
        agent.progress(Duration::from_secs(seconds_per_tick)).await;

        let observed = observe(agent).await;
        if observed == *expected {
            return Ok(());
        }

        counter += 1;
        if counter > num_ticks {
            return Err(format!(
                "Observed state: {observed:?}\n!= Expected state {expected:?}\nafter {timeout_seconds} seconds ({counter} ticks of {seconds_per_tick}s each)",
            ));
        }
    }
}
