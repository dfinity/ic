use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
    str::FromStr,
};

/// A rule of a [RetentionPolicy]: keep the newest state of every `period_days`-long time window
/// (aligned on the Unix epoch), as long as it is at most `time_to_live_days` older than the newest
/// state.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct RetentionRule {
    pub period_days: u64,
    pub time_to_live_days: u64,
}

impl Display for RetentionRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Keep one state every {} days, until they are older than {} days",
            self.period_days, self.time_to_live_days
        )
    }
}

/// Parses a rule from `<PERIOD_DAYS>:<TIME_TO_LIVE_DAYS>`, e.g. `16:182`.
impl FromStr for RetentionRule {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (period_days, time_to_live_days) = s.split_once(':').ok_or_else(|| {
            format!("Invalid rule {s:?}: expected <PERIOD_DAYS>:<TIME_TO_LIVE_DAYS>")
        })?;
        let parse_days = |days: &str| {
            days.parse::<u64>()
                .map_err(|err| format!("Invalid number of days {days:?} in rule {s:?}: {err}"))
        };
        Ok(Self {
            period_days: parse_days(period_days)?,
            time_to_live_days: parse_days(time_to_live_days)?,
        })
    }
}

impl RetentionRule {
    fn time_to_live(&self) -> TimeDelta {
        days(self.time_to_live_days).unwrap_or(TimeDelta::MAX)
    }

    /// Returns the index of the time window containing the given timestamp.
    fn window(&self, timestamp: DateTime<Utc>) -> i64 {
        let period_secs = days(self.period_days)
            .map_or(i64::MAX, |period| period.num_seconds())
            .max(1);
        timestamp.timestamp().div_euclid(period_secs)
    }
}

/// Decides which states of a subnet to delete from the cold storage.
///
/// A state is kept if any of the rules keeps it. Regardless of the rules, the oldest state (i.e.
/// the one with the minimum height) is always kept, as it is the starting point to replay to any
/// height. The newest state is always kept too, as well as states whose archiving timestamp
/// cannot be read. All the other states are deleted.
///
/// Ages are measured relative to the newest state, so nothing gets deleted if no new state is
/// cold stored.
///
/// Example:
/// ```json
/// "cold_storage_retention_policy": {
///     "dry_run": false,
///     "rules": [
///         { "period_days": 1,   "time_to_live_days": 30 },
///         { "period_days": 16,  "time_to_live_days": 182 },
///         { "period_days": 56,  "time_to_live_days": 365 },
///         { "period_days": 120, "time_to_live_days": 3650 }
///     ]
/// }
/// ```
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct RetentionPolicy {
    pub rules: Vec<RetentionRule>,
    /// If set, the states which should be deleted are only reported, and not deleted.
    pub dry_run: bool,
}

impl Display for RetentionPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rules_str = self
            .rules
            .iter()
            .map(|rule| rule.to_string())
            .collect::<Vec<String>>()
            .join(", ");
        let dry_run_str = if self.dry_run { " (dry run)" } else { "" };
        write!(f, "Retention Policy{dry_run_str}: [{rules_str}]")
    }
}

/// A state in the cold storage, as seen by the [RetentionPolicy].
#[derive(Clone, Debug)]
pub(crate) struct ColdStoredState {
    pub(crate) height: u64,
    /// When the state was archived, or `None` if it couldn't be read.
    pub(crate) timestamp: Option<DateTime<Utc>>,
}

impl RetentionPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.rules.is_empty() {
            return Err("The retention policy must have at least one rule".to_string());
        }
        for rule in &self.rules {
            if rule.period_days == 0 {
                return Err(format!(
                    "Invalid rule \"{rule}\": the period must be greater than zero"
                ));
            }
            if rule.time_to_live_days < rule.period_days {
                return Err(format!(
                    "Invalid rule \"{rule}\": the time to live must be at least the period"
                ));
            }
            if days(rule.time_to_live_days).is_none() {
                return Err(format!(
                    "Invalid rule \"{rule}\": the time to live is too large"
                ));
            }
        }
        Ok(())
    }

    /// Returns the heights of the given states which should be deleted.
    pub(crate) fn heights_to_delete(&self, states: &[ColdStoredState]) -> BTreeSet<u64> {
        let mut heights_to_keep = BTreeSet::new();

        // The oldest state is the starting point to replay to any height.
        if let Some(oldest_height) = states.iter().map(|state| state.height).min() {
            heights_to_keep.insert(oldest_height);
        }

        // We cannot tell how old these states are, so we don't delete them.
        heights_to_keep.extend(
            states
                .iter()
                .filter(|state| state.timestamp.is_none())
                .map(|state| state.height),
        );

        let mut dated_states: Vec<_> = states
            .iter()
            .filter_map(|state| state.timestamp.map(|timestamp| (timestamp, state.height)))
            .collect();
        dated_states.sort();

        if let Some(&(newest_timestamp, newest_height)) = dated_states.last() {
            heights_to_keep.insert(newest_height);

            for rule in &self.rules {
                // States are sorted in ascending order, so the last state inserted in each window
                // is the newest one.
                let mut newest_per_window = BTreeMap::new();
                for &(timestamp, height) in &dated_states {
                    if newest_timestamp - timestamp <= rule.time_to_live() {
                        newest_per_window.insert(rule.window(timestamp), height);
                    }
                }
                heights_to_keep.extend(newest_per_window.into_values());
            }
        }

        states
            .iter()
            .map(|state| state.height)
            .filter(|height| !heights_to_keep.contains(height))
            .collect()
    }
}

fn days(n: u64) -> Option<TimeDelta> {
    i64::try_from(n).ok().and_then(TimeDelta::try_days)
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use super::*;

    // Rule 1: For the first month, we would like to keep everything.
    // Rule 2: For the first 6 months, we would like to be able to replay in 4 days to any height.
    // Assuming replaying is 4 times as fast as real time, this means we need to keep one state
    // every 16 days.
    // Rule 3: For the first year, we would like to be able to replay in 2 weeks to any height.
    // With the same reasoning as above, this means we need to keep one state every 8 weeks.
    // Rule 4: For the first 10 years, we would like to be able to replay in 1 month to any height.
    // With the same reasoning as above, this means we need to keep one state every 4 months.
    static AGGRESSIVE_POLICY: LazyLock<RetentionPolicy> = LazyLock::new(|| {
        policy(&[
            (1, 30),     // 1 month
            (16, 182),   // 6 months
            (56, 365),   // 1 year
            (120, 3650), // 10 years
        ])
    });

    fn policy(rules: &[(u64, u64)]) -> RetentionPolicy {
        RetentionPolicy {
            rules: rules
                .iter()
                .map(|&(period_days, time_to_live_days)| RetentionRule {
                    period_days,
                    time_to_live_days,
                })
                .collect(),
            dry_run: false,
        }
    }

    fn height(day: u64) -> u64 {
        day * 1000
    }

    /// A state archived at the given number of days after the Unix epoch.
    fn state(day: u64) -> ColdStoredState {
        ColdStoredState {
            height: height(day),
            timestamp: Some(DateTime::UNIX_EPOCH + TimeDelta::days(day as i64)),
        }
    }

    fn states(days: impl IntoIterator<Item = u64>) -> Vec<ColdStoredState> {
        days.into_iter().map(state).collect()
    }

    fn heights(days: impl IntoIterator<Item = u64>) -> BTreeSet<u64> {
        days.into_iter().map(height).collect()
    }

    #[test]
    fn nothing_to_delete_without_states_test() {
        assert_eq!(AGGRESSIVE_POLICY.heights_to_delete(&[]), BTreeSet::new());
    }

    #[test]
    fn single_state_is_kept_test() {
        assert_eq!(
            AGGRESSIVE_POLICY.heights_to_delete(&states([42])),
            BTreeSet::new()
        );
    }

    #[test]
    fn keeps_newest_state_of_each_window_within_time_to_live_test() {
        let policy = policy(&[(1, 30), (7, 90)]);

        let to_delete = policy.heights_to_delete(&states(0..=100));

        // The oldest state, the newest state of each 7-day window not older than 90 days, and
        // all the states not older than 30 days.
        let to_keep = heights(
            [0, 13, 20, 27, 34, 41, 48, 55, 62, 69]
                .into_iter()
                .chain(70..=100),
        );
        assert_eq!(to_delete, &heights(0..=100) - &to_keep);
    }

    #[test]
    fn oldest_and_newest_states_are_always_kept_test() {
        let policy = policy(&[(10, 10)]);

        let to_delete = policy.heights_to_delete(&states(0..=100));

        assert_eq!(to_delete, heights(1..=98));
    }

    #[test]
    fn states_without_timestamp_are_kept_test() {
        let policy = policy(&[(10, 10)]);
        let mut all_states = states(0..=100);
        all_states.push(ColdStoredState {
            height: 50_500,
            timestamp: None,
        });

        let to_delete = policy.heights_to_delete(&all_states);

        assert_eq!(to_delete, heights(1..=98));
    }

    #[test]
    fn result_does_not_depend_on_the_order_of_states_test() {
        let sorted_states = states(0..=1000);
        let expected = AGGRESSIVE_POLICY.heights_to_delete(&sorted_states);

        let mut reversed_states = sorted_states.clone();
        reversed_states.reverse();
        let mut shuffled_states = sorted_states.clone();
        shuffled_states.sort_by_key(|state| (state.height % 7, state.height % 13));

        assert_eq!(
            AGGRESSIVE_POLICY.heights_to_delete(&reversed_states),
            expected
        );
        assert_eq!(
            AGGRESSIVE_POLICY.heights_to_delete(&shuffled_states),
            expected
        );
    }

    /// Simulates 11 years of daily cold storage, applying the policy every day.
    #[test]
    fn daily_application_of_aggressive_policy_test() {
        let policy = &*AGGRESSIVE_POLICY;
        let max_kept_states = 2 + policy
            .rules
            .iter()
            .map(|rule| rule.time_to_live_days / rule.period_days + 2)
            .sum::<u64>() as usize;

        let mut kept_states = Vec::new();
        for newest_day in 0..=11 * 365 {
            kept_states.push(state(newest_day));
            let to_delete = policy.heights_to_delete(&kept_states);
            kept_states.retain(|state| !to_delete.contains(&state.height));

            let kept_days: Vec<u64> = kept_states
                .iter()
                .map(|state| state.height / 1000)
                .collect();

            assert_eq!(kept_days.first(), Some(&0));
            assert_eq!(kept_days.last(), Some(&newest_day));
            assert!(kept_states.len() <= max_kept_states);

            // Within the time to live of each rule, there is no gap longer than its period.
            for rule in &policy.rules {
                for pair in kept_days.windows(2) {
                    if newest_day - pair[0] <= rule.time_to_live_days {
                        assert!(
                            pair[1] - pair[0] <= rule.period_days,
                            "Gap between days {} and {} on day {newest_day} breaks rule \"{rule}\"",
                            pair[0],
                            pair[1],
                        );
                    }
                }
            }

            // Applying the policy every day is the same as applying it once to all the states.
            if newest_day % 30 == 0 {
                let all_states = states(0..=newest_day);
                let to_delete_at_once = policy.heights_to_delete(&all_states);
                let kept_at_once: Vec<u64> = (0..=newest_day)
                    .filter(|&day| !to_delete_at_once.contains(&height(day)))
                    .collect();
                assert_eq!(kept_days, kept_at_once);
            }
        }
    }

    #[test]
    fn parse_rule_test() {
        assert_eq!(
            "16:182".parse::<RetentionRule>(),
            Ok(RetentionRule {
                period_days: 16,
                time_to_live_days: 182,
            })
        );
        for invalid_rule in ["", "16", "16:", ":182", "16:182:1", "a:182", "-1:182"] {
            assert!(
                invalid_rule.parse::<RetentionRule>().is_err(),
                "{invalid_rule:?} should not parse"
            );
        }
    }

    #[test]
    fn validate_test() {
        assert!(AGGRESSIVE_POLICY.validate().is_ok());
        assert!(policy(&[]).validate().is_err());
        assert!(policy(&[(0, 10)]).validate().is_err());
        assert!(policy(&[(10, 9)]).validate().is_err());
        assert!(policy(&[(1, u64::MAX)]).validate().is_err());
        assert!(policy(&[(1, 30), (10, 9)]).validate().is_err());
    }
}
