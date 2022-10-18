//! Code for the computation of rewards distributions.
//!
//! This module makes use of floating-point computations. This is a reasonable
//! choice for computing rewards because:
//!
//! * Floating-point computations are deterministic and fully specified in wasm.
//!   In particular, rounding behavior is fully specified: https://www.w3.org/TR/wasm-core-1/#floating-point-operations%E2%91%A0
//!
//! * Floating-point operations are allowed in canister code.
//!
//! * The computation here happens pre-minting, and therefore there is no
//!   constraint that mandate fixed-precision.
//!
//! * Floating point makes code easier since the reward pool is specified as a
//!   fraction of the total Token supply.

use crate::{governance::log_prefix, pb::v1::VotingRewardsParameters, types::ONE_DAY_SECONDS};
use ic_nervous_system_common::i2d;
use lazy_static::lazy_static;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::fmt::Debug;
use std::ops::{Add, Div, Mul, Range, RangeBounds, Sub};

lazy_static! {
    pub static ref SECONDS_PER_DAY: Decimal = Decimal::new(24 * 60 * 60, 0);
    pub static ref DAYS_PER_SECOND: Decimal = dec!(1) / *SECONDS_PER_DAY;

    // Astronomers, avert your eyes!
    pub static ref NOMINAL_DAYS_PER_YEAR: Decimal = dec!(365.25);
}

// ---- NON-BOILERPLATE CODE STARTS HERE ----------------------------------
// Because this module has very little "real" code and a lot of boilerplate
// and comments, all the interesting code is grouped here at the top.

// ----------------
// Arithmetic types
// ----------------
//
// The Instant and Duration types defined here are analogous to the types in
// std::time with the same names. These custom types make it more convenient to
// work with GrowthRate, also defined here.
//
// Design note: These use Decimal internally for more precise arithmetic.
//
// Minor design note: Internally, these use days as the unit of time. This made
// sense in the context of NNS, because there is a new reward round every
// day.

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Instant {
    days_since_start_time: Decimal,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Duration {
    pub days: Decimal,
}

/// A dimensionless quantity divided by a duration.
///
/// E.g. 5% per year would be represented as RewardRate::from_basis_points(500).
/// At this rate, if you start with 100 tokens, then after 1 year, you would
/// have 5 token's worth of maturity (this assumes that there is no
/// compounding). The following code would make that calculation:
///
///   let principal: rust_decimal::Decimal = i2d(100);
///   let reward_rate = RewardRate::from_basis_points(500);
///   let one_year: reward::Duration = NOMINAL_DAYS_PER_YEAR;
///
///   let maturity = principal * reward_rate * one_year;
///
/// Nominally, a year has 365.25 days. Therefore, if we start with the same 100
/// tokens, but we only wait 1 week (7 days), then, you would end up with 100 *
/// (0.05 * 7 / 365.25) = 0.0958_2477 (rounded towards zero) token's worth of
/// maturity.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct RewardRate {
    per_year: Decimal,
}

impl RewardRate {
    pub fn from_basis_points(basis_points: u64) -> Self {
        let per_year = i2d(basis_points) / i2d(10_000);
        Self { per_year }
    }

    fn per_day(&self) -> Decimal {
        self.per_year / *NOMINAL_DAYS_PER_YEAR
    }
}

/// A function that linearly maps values in the from Range to the to Range.
// TODO: Generic-ify, and (move to a place where this can be) share(d) more broadly.
#[derive(Clone, PartialEq, Eq, Debug)]
struct LinearMap {
    from: Range<Decimal>,
    to: Range<Decimal>,
}

impl LinearMap {
    pub fn new(from: Range<Decimal>, to: Range<Decimal>) -> Self {
        // from must have nonzero length.
        assert!(from.end != from.start, "{:#?}", from);
        Self { from, to }
    }

    pub fn apply(&self, x: Decimal) -> Decimal {
        let Self { from, to } = &self;

        // t varies from 0 to 1 as x varies from from.start to from.end...
        let t = (x - from.start) / (from.end - from.start);

        // Thus, the result varies from
        //   to.start * 1 + to.end * 0 = to.start
        // to
        //   to.start * (1 - 1) + to.end * 1 = to.end
        to.start * (dec!(1) - t) + to.end * t
    }
}

impl VotingRewardsParameters {
    /// This is an upper bound for `initial_reward_rate_basis_points_ceiling`. High values
    /// may improve the incentives when voting, but too-high values may also lead
    /// to an over-concentration of voting power and high inflation.
    pub const INITIAL_REWARD_RATE_BASIS_POINTS_CEILING: u64 = 10_000;

    /// Returns Ok if self is usable.
    ///
    /// If Err is returned, it contains a description (for human consumption) of
    /// what makes self defective.
    ///
    /// All fields are requried.
    ///
    /// Each field has a range of allowed values. Those limits are just sanity
    /// checks. All "sensible" values are allowed.
    ///
    /// Some "highly not sensible" values are allowed (e.g. 90% growth rate)
    /// simply because the transition between "sensible" and "insane" is
    /// gradual, not hard.
    pub fn validate(&self) -> Result<(), String> {
        let mut defects = vec![];

        defects.append(&mut self.round_duration_seconds_defects());
        defects.append(&mut self.reward_rate_transition_duration_seconds_defects());
        defects.append(&mut self.initial_reward_rate_basis_points_defects());
        defects.append(&mut self.final_reward_rate_basis_points_defects());

        if defects.is_empty() {
            Ok(())
        } else {
            Err(defects.join("\n"))
        }
    }

    /// Voting rewards are calculated in way that is very analogous to
    /// (non-compounding) interest in a bank account.
    ///
    /// In a bank account with non-compounding interest, the amount of interest
    /// that is earned is proportional to the amount of money in the account
    /// (traditionally, called the "principal", though we use that word
    /// differently in the IC), and the amount of time that the money has been
    /// in the account. The constant of proportionality is aptly named the
    /// "interest rate" (see also the RewardRate type). Therefore, the amount of
    /// (non-compounding) interest that the account earns is given by the
    /// following expression:
    ///
    ///   principal * interest_rate * duration
    ///
    /// In the context of voting rewards, principal is analogous to the total
    /// supply of tokens. Whereas, this method calculates the middle factor in
    /// the above formula. Finally, reward period is used as the duration (See
    /// the round_duration method).
    ///
    /// The growth rate varies with time. The schedule is very much analogous to
    /// the one used by NNS, which is documented here:
    /// https://wiki.internetcomputer.org/wiki/Staking,_voting_and_rewards#Voting_Rewards
    pub fn reward_rate(&self, round: u64) -> RewardRate {
        let round_duration_seconds = self
            .round_duration_seconds
            .expect("round_duration_seconds unset");
        let days_per_round = i2d(round_duration_seconds) * *DAYS_PER_SECOND;
        let t = Instant {
            days_since_start_time: i2d(round) * days_per_round,
        };

        // t cannot be before start_time, because days_since_start_time_unsigned is unsigned.

        if t >= self.rate_transition_end_instant() {
            return self.final_reward_rate();
        }

        // Calculate "variable reward_rate", i.e. rate on top of the final
        // growth rate that should apply at instant t.
        let reward_rate_transition_duration_seconds = self
            .reward_rate_transition_duration_seconds
            .expect("reward_rate_transition_duration_seconds unset");
        let transition_round_count =
            reward_rate_transition_duration_seconds / round_duration_seconds;
        let transition = LinearMap::new(dec!(1)..i2d(transition_round_count), dec!(1)..dec!(0));
        // s linearly varies from 1 -> 0 as t varies from
        // start_instant -> rate_transition_end_instant
        let s = transition.apply(i2d(round));
        // s2 varies quadratically from 1 -> 0 (again, as t varies from
        // start_instant to rate_transition_end_instant), and flattens out as t
        // approaches rate_transition_end_instant.
        let s2 = s * s;
        // This looks backwards, but we think of variable rate as being added to
        // final growth rate, not initial, and the amount to add is up to
        // initial - final (where initial is thought of as being greater than
        // final).
        let dr = self.initial_reward_rate() - self.final_reward_rate();
        // variable_reward_rate varies from dr to 0 as round varies from
        // 1 to transition_round_count.
        let variable_reward_rate = s2 * dr;

        self.final_reward_rate() + variable_reward_rate
    }

    /// The number of rounds of voting rewards that have elapsed since start
    /// time (which is the genesis of the SNS, stored in
    /// `governance.proto.genesis_timestamp_seconds`).
    ///
    /// E.g. starting from genesis, once round_duration has elapsed (or
    /// shortly thereafter), then this would return 1.
    pub fn most_recent_round(
        &self,
        timestamp_seconds: u64,
        sns_genesis_timestamp_seconds: u64,
    ) -> u64 {
        if timestamp_seconds < sns_genesis_timestamp_seconds {
            println!(
                "{}ERROR: timestamp_seconds ({}) less that sns_genesis ({})",
                log_prefix(),
                timestamp_seconds,
                sns_genesis_timestamp_seconds,
            );
            return 0;
        }

        let d_seconds = timestamp_seconds - sns_genesis_timestamp_seconds;
        let round_duration_seconds = self
            .round_duration_seconds
            .expect("round_duration_seconds unset");
        assert!(
            round_duration_seconds > 0,
            "round_duration_seconds not positive: {}",
            round_duration_seconds
        );
        d_seconds / round_duration_seconds
    }

    /// The length of a reward round.
    pub fn round_duration(&self) -> Duration {
        let seconds = i2d(self
            .round_duration_seconds
            .expect("round_duration_seconds unset"));
        Duration {
            days: seconds * *DAYS_PER_SECOND,
        }
    }

    fn round_duration_seconds_defects(&self) -> Vec<String> {
        require_field_set_and_in_range("round_duration_seconds", &self.round_duration_seconds, 1..)
    }

    fn reward_rate_transition_duration_seconds_defects(&self) -> Vec<String> {
        require_field_set_and_in_range(
            "reward_rate_transition_duration_seconds",
            &self.reward_rate_transition_duration_seconds,
            // Conceptually, allowing 0 make sense, but for convenience of
            // implementation, we disallow 0 to avoid division by zero (in
            // LinearMap).
            1..,
        )
    }

    fn initial_reward_rate_basis_points_defects(&self) -> Vec<String> {
        require_field_set_and_in_range(
            "initial_reward_rate_basis_points",
            &self.initial_reward_rate_basis_points,
            ..Self::INITIAL_REWARD_RATE_BASIS_POINTS_CEILING,
        )
    }

    fn final_reward_rate_basis_points_defects(&self) -> Vec<String> {
        let max = self.initial_reward_rate_basis_points.unwrap_or_default();
        require_field_set_and_in_range(
            "final_reward_rate_basis_points",
            &self.final_reward_rate_basis_points,
            ..=max,
        )
    }

    pub fn rate_transition_end_instant(&self) -> Instant {
        let seconds = self
            .reward_rate_transition_duration_seconds
            .expect("reward_rate_transition_duration_seconds unset");

        Instant {
            days_since_start_time: i2d(seconds) * *DAYS_PER_SECOND,
        }
    }

    pub fn initial_reward_rate(&self) -> RewardRate {
        RewardRate::from_basis_points(self.initial_reward_rate_basis_points.unwrap_or_default())
    }

    pub fn final_reward_rate(&self) -> RewardRate {
        RewardRate::from_basis_points(self.final_reward_rate_basis_points.unwrap_or_default())
    }

    pub fn with_default_values() -> Self {
        Self {
            round_duration_seconds: Some(ONE_DAY_SECONDS),
            reward_rate_transition_duration_seconds: Some(1),
            initial_reward_rate_basis_points: Some(0),
            final_reward_rate_basis_points: Some(0),
        }
    }
    /// Any empty fields of `self` are overwritten with the corresponding fields of `base`.
    pub fn inherit_from(&self, base: &Self) -> Self {
        Self {
            round_duration_seconds: self.round_duration_seconds.or(base.round_duration_seconds),
            reward_rate_transition_duration_seconds: self
                .reward_rate_transition_duration_seconds
                .or(base.reward_rate_transition_duration_seconds),
            initial_reward_rate_basis_points: self
                .initial_reward_rate_basis_points
                .or(base.initial_reward_rate_basis_points),
            final_reward_rate_basis_points: self
                .final_reward_rate_basis_points
                .or(base.final_reward_rate_basis_points),
        }
    }
}

/// Returns a list of defect( description)s.
// TODO: Generic-ify (generalize) and/or macro (avoid repetition between
// field_name and value argument).
fn require_field_set_and_in_range(
    field_name: &str,
    value: &Option<u64>,
    valid_range: impl RangeBounds<u64> + Debug,
) -> Vec<String> {
    let mut result = vec![];

    let value = match value {
        Some(value) => value,
        None => {
            result.push(format!("{} is required.", field_name));
            return result;
        }
    };

    if !valid_range.contains(value) {
        result.push(format!("{} not in {:#?}.", field_name, valid_range));
    }

    result
}

// ---- REAL-CODE ENDS HERE ---------------------------------------------

// Explication for the implementation of
// `rewards_pool_to_distribute_in_supply_fraction`
//
// The relevant extract from the spec is:
//
// -------------------------------------------------------------------------
// We derive the nominal maximum quantity of Tokens that can be
// minted and distributed as rewards from the current Token supply and
// the days since Genesis. To begin with, this is equal to 10% of the
// Token supply divided by the number of days in the year (365 normally,
// 366 in a leap year). Over 8 years, this falls to 5%. Note that since
// the supply of Tokens might grow (or even in theory fall) during this time,
// voting rewards may not halve in practice.
//
// * We want the rate at genesis to be 10% per year
// * We want the rate at genesis + 8 years to be 5% per year, and to be flat
//   thereafter
// * We want the rate to be a quadratic function of time
// * We want the rate to be differentiable wrt time at the point where it
//   becomes flat
// -------------------------------------------------------------------------
//
// Calling R0 the initial rate at genesis time G, Rf the final rate, and T the
// time at which the rate becomes flat, the unique solution is:
//
// R(t) = Rf + (R0-Rf) [ (t-T) / (G-T) ]^2
//
// Note that:
// R(G) = Rf + (R0-Rf) [ (G- T) / (G-T) ] ^ 2 = Rf + (R0-Rf) = R0
// R(T) = Rf + (R0-Rf) [ (T- T) / (G-T) ] ^ 2 = Rf
// R'(t) = 2 (R0-Rf)  (t-T) / ( G-T )^2
// R'(T) = 0
//
// ---- Arithmetic ----------------------------------
// There's no way in Rust to derive Add, Sub, etc. So we must have a ton of
// boilerplate for arithmetic. The rest of this module is boring stuff.

impl Sub for Instant {
    type Output = Duration;
    fn sub(self, other: Instant) -> Self::Output {
        Duration {
            days: self.days_since_start_time - other.days_since_start_time,
        }
    }
}
impl Mul<Duration> for RewardRate {
    type Output = Decimal;
    fn mul(self, other: Duration) -> Self::Output {
        self.per_day() * other.days
    }
}
impl Mul<RewardRate> for Duration {
    type Output = Decimal;
    fn mul(self, other: RewardRate) -> Self::Output {
        self.days * other.per_day()
    }
}
impl Sub for RewardRate {
    type Output = RewardRate;
    fn sub(self, other: RewardRate) -> Self::Output {
        RewardRate {
            per_year: self.per_year - other.per_year,
        }
    }
}
impl Add for RewardRate {
    type Output = RewardRate;
    fn add(self, other: RewardRate) -> Self::Output {
        RewardRate {
            per_year: self.per_year + other.per_year,
        }
    }
}
impl Mul<RewardRate> for Decimal {
    type Output = RewardRate;
    fn mul(self, other: RewardRate) -> Self::Output {
        RewardRate {
            per_year: self * other.per_year,
        }
    }
}

impl Div<Duration> for Duration {
    type Output = Decimal;
    fn div(self, other: Duration) -> Self::Output {
        self.days / other.days
    }
}

// Surprisingly, Clippy complains that the `use` statement and the
// assert_approx_eq! macro are unused. This is very strange, so
// just tell clippy to keep quiet.
#[allow(unused_imports, unused_macros)]
#[cfg(test)]
mod test {
    use super::*;
    use crate::tests::{assert_is_err, assert_is_ok};

    #[test]
    fn linear_map() {
        let map = LinearMap::new(dec!(5.0)..dec!(6.0), dec!(100.0)..dec!(200.0));

        // Look at the extrema (this should be a no-brainer).
        assert_eq!(map.apply(dec!(5.0)), dec!(100.0));
        assert_eq!(map.apply(dec!(6.0)), dec!(200.0));

        // Look at the middle.
        assert_eq!(map.apply(dec!(5.50)), dec!(150.0));
        assert_eq!(map.apply(dec!(5.25)), dec!(125.0));
        assert_eq!(map.apply(dec!(5.75)), dec!(175.0));
    }

    const TRANSITION_ROUND_COUNT: u64 = 42;

    const VOTING_REWARDS_PARAMETERS: VotingRewardsParameters = VotingRewardsParameters {
        round_duration_seconds: Some(7 * 24 * 60 * 60), // 1 week
        reward_rate_transition_duration_seconds: Some(TRANSITION_ROUND_COUNT * 7 * 24 * 60 * 60), // 42 weeks
        initial_reward_rate_basis_points: Some(200), // 2%
        final_reward_rate_basis_points: Some(100),   // 1%
    };

    #[test]
    fn test_subject_validates() {
        assert_is_ok(VOTING_REWARDS_PARAMETERS.validate());
    }

    #[test]
    fn reward_rate_flattens_out() {
        let expected = RewardRate::from_basis_points(100);
        assert_eq!(VOTING_REWARDS_PARAMETERS.reward_rate(42), expected,);
        assert_eq!(VOTING_REWARDS_PARAMETERS.reward_rate(42 + 5), expected,);
        assert_eq!(VOTING_REWARDS_PARAMETERS.reward_rate(123456), expected,);
    }

    #[test]
    fn reward_for_first_day() {
        assert_eq!(
            VOTING_REWARDS_PARAMETERS.reward_rate(1),
            RewardRate::from_basis_points(200),
        );
    }

    // Now that we have looked at the extrema, lets begin looking at the middle
    // of the transition phase (the more interesting area).
    #[test]
    fn reward_is_bounded_during_transition() {
        let r_i = VOTING_REWARDS_PARAMETERS.initial_reward_rate();
        let r_f = VOTING_REWARDS_PARAMETERS.final_reward_rate();

        for round in 2..TRANSITION_ROUND_COUNT {
            let reward_rate = VOTING_REWARDS_PARAMETERS.reward_rate(round);
            assert!(
                reward_rate < r_i,
                "round = {}, r_i = {:#?}, reward_rate = {:#?}",
                round,
                r_i,
                reward_rate,
            );
            assert!(
                reward_rate > r_f,
                "round = {}, r_f = {:#?}, reward_rate = {:#?}",
                round,
                r_f,
                reward_rate,
            );
        }
    }

    #[test]
    fn reward_is_convex_and_decreasing() {
        for reward_round in 1..=(TRANSITION_ROUND_COUNT - 2) {
            let previous = VOTING_REWARDS_PARAMETERS.reward_rate(reward_round);
            let current = VOTING_REWARDS_PARAMETERS.reward_rate(reward_round + 1);
            let next = VOTING_REWARDS_PARAMETERS.reward_rate(reward_round + 2);
            // First "derivative" is negative.
            assert!(previous > current);
            assert!(current > next);
            // Second "derivative" is positive.
            assert!(current - previous < next - current);
        }
    }

    #[test]
    fn test_round_duration_seconds_validation() {
        assert_is_err(
            VotingRewardsParameters {
                round_duration_seconds: None,
                ..VOTING_REWARDS_PARAMETERS
            }
            .validate(),
        );
        assert_is_err(
            VotingRewardsParameters {
                round_duration_seconds: Some(0),
                ..VOTING_REWARDS_PARAMETERS
            }
            .validate(),
        );
    }

    #[test]
    fn test_reward_rate_transition_duration_seconds_validation() {
        assert_is_err(
            VotingRewardsParameters {
                reward_rate_transition_duration_seconds: None,
                ..VOTING_REWARDS_PARAMETERS
            }
            .validate(),
        );
        assert_is_err(
            VotingRewardsParameters {
                reward_rate_transition_duration_seconds: Some(0),
                ..VOTING_REWARDS_PARAMETERS
            }
            .validate(),
        );
    }

    #[test]
    fn test_initial_reward_rate_basis_points_validation() {
        assert_is_err(
            VotingRewardsParameters {
                initial_reward_rate_basis_points: None,
                ..VOTING_REWARDS_PARAMETERS
            }
            .validate(),
        );
        assert_is_err(
            VotingRewardsParameters {
                initial_reward_rate_basis_points: Some(10_001), // > 100%
                ..VOTING_REWARDS_PARAMETERS
            }
            .validate(),
        );
    }

    #[test]
    fn test_final_reward_rate_basis_points_validation() {
        assert_is_err(
            VotingRewardsParameters {
                final_reward_rate_basis_points: None,
                ..VOTING_REWARDS_PARAMETERS
            }
            .validate(),
        );

        let max = VOTING_REWARDS_PARAMETERS
            .initial_reward_rate_basis_points
            .unwrap();
        assert_is_ok(
            VotingRewardsParameters {
                final_reward_rate_basis_points: Some(max),
                ..VOTING_REWARDS_PARAMETERS
            }
            .validate(),
        );
        assert_is_err(
            VotingRewardsParameters {
                final_reward_rate_basis_points: Some(max + 1),
                ..VOTING_REWARDS_PARAMETERS
            }
            .validate(),
        );
    }
}
