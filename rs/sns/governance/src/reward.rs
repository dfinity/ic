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

use crate::pb::v1::VotingRewardsParameters;
use ic_nervous_system_common::i2d;
use lazy_static::lazy_static;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::{
    fmt::Debug,
    ops::{Add, Div, Mul, Range, RangeBounds, Sub},
};

lazy_static! {
    pub static ref ONE_DAY_SECONDS: Decimal = Decimal::new(ic_nervous_system_common::ONE_DAY_SECONDS as i64, 0);
    pub static ref DAYS_PER_SECOND: Decimal = dec!(1) / *ONE_DAY_SECONDS;

    // Astronomers, avert your eyes!
    pub static ref NOMINAL_DAYS_PER_YEAR: Decimal = dec!(365.25);

    pub static ref GENESIS: Instant = Instant::from_seconds_since_genesis(dec!(0));

    // 1 year (nominal duration in seconds).
    //
    // This limit is just to prevent "insane" values. Being within this limit
    // does NOT mean that an "advisable" value has been chosen!
    //
    // The corresponding minimum is 1 s. (As with the maximum, just because a
    // value does not violate this limit does not mean it is advisable.)
    pub static ref MAX_REWARD_ROUND_DURATION_SECONDS: u64 =
        u64::try_from(*NOMINAL_DAYS_PER_YEAR * *ONE_DAY_SECONDS)
            .expect("Unable to convert a Decimal into a u64.");
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

impl Instant {
    pub fn from_seconds_since_genesis(seconds: Decimal) -> Self {
        Self {
            days_since_start_time: seconds * *DAYS_PER_SECOND,
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Duration {
    days: Decimal,
}

impl Duration {
    pub fn from_secs(seconds: Decimal) -> Self {
        Self {
            days: seconds * *DAYS_PER_SECOND,
        }
    }

    pub fn as_secs(&self) -> Decimal {
        self.days * *ONE_DAY_SECONDS
    }
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
        // But if from.end == from.start, we set t to 1 to avoid division by
        // zero.
        let t = if from.end == from.start {
            i2d(1)
        } else {
            (x - from.start) / (from.end - from.start)
        };

        // Thus, the result varies from
        //   to.start * 1 + to.end * 0 = to.start
        // to
        //   to.start * (1 - 1) + to.end * 1 = to.end
        to.start * (i2d(1) - t) + to.end * t
    }
}

lazy_static! {
    static ref DEFAULT_VOTING_REWARDS_PARAMETERS: VotingRewardsParameters =
        VotingRewardsParameters::default();
}

impl Default for &VotingRewardsParameters {
    fn default() -> Self {
        &DEFAULT_VOTING_REWARDS_PARAMETERS
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
    /// All fields are required.
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
    pub fn reward_rate_at(&self, now: Instant) -> RewardRate {
        let reward_rate_transition_duration_seconds = self
            .reward_rate_transition_duration_seconds
            .expect("reward_rate_transition_duration_seconds unset");

        let time_since_genesis = {
            let result = now - *GENESIS;
            // For the purposes of determining reward rate, treat times before
            // genesis the same as at genesis. This is not expected to occur in
            // practice. This code is just being extra defensive.
            if result.as_secs() < i2d(0) {
                Duration { days: i2d(0) }
            } else {
                result
            }
        };
        if reward_rate_transition_duration_seconds == 0
            || time_since_genesis.as_secs() >= i2d(reward_rate_transition_duration_seconds)
        {
            return self.final_reward_rate();
        }

        // s linearly varies from 1 -> 0 as seconds_since_genesis varies from 0
        // to reward_rate_transition_duration_seconds.
        let transition = LinearMap::new(
            dec!(0)..i2d(reward_rate_transition_duration_seconds),
            dec!(1)..dec!(0),
        );
        let s = transition.apply(time_since_genesis.as_secs());
        // s2 varies quadratically from 1 -> 0 (again, as seconds_since_genesis
        // varies from 0 to reward_rate_transition_duration_seconds), and
        // flattens out as seconds_since_genesis approaches
        // reward_rate_transition_duration_seconds.
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
        require_field_set_and_in_range(
            "round_duration_seconds",
            &self.round_duration_seconds,
            1..=*MAX_REWARD_ROUND_DURATION_SECONDS,
        )
    }

    fn reward_rate_transition_duration_seconds_defects(&self) -> Vec<String> {
        require_field_set_and_in_range(
            "reward_rate_transition_duration_seconds",
            &self.reward_rate_transition_duration_seconds,
            0..,
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
            round_duration_seconds: Some(ic_nervous_system_common::ONE_DAY_SECONDS),
            reward_rate_transition_duration_seconds: Some(0),
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
impl Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, rhs: Duration) -> Self {
        Self {
            days_since_start_time: self.days_since_start_time + rhs.days,
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
    use ic_nervous_system_common::{assert_is_err, assert_is_ok, E8};
    use pretty_assertions::{assert_eq, assert_ne};

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

    fn round_number_to_instant(r: u64) -> Instant {
        Instant::from_seconds_since_genesis(i2d(r * VOTING_REWARDS_PARAMETERS
            .round_duration_seconds
            .unwrap()))
    }

    #[test]
    fn test_subject_validates() {
        assert_is_ok!(VOTING_REWARDS_PARAMETERS.validate());
    }

    #[test]
    fn reward_rate_zero() {
        let expected = RewardRate::from_basis_points(
            VOTING_REWARDS_PARAMETERS
                .final_reward_rate_basis_points
                .unwrap(),
        );
        let parameters_with_zero_transition_duration_seconds = VotingRewardsParameters {
            reward_rate_transition_duration_seconds: Some(0),
            ..VOTING_REWARDS_PARAMETERS
        };
        for round_number in 1..=100 {
            assert_eq!(
                parameters_with_zero_transition_duration_seconds
                    .reward_rate_at(round_number_to_instant(round_number),),
                expected,
            );
        }
    }

    #[test]
    fn round_duration_is_transition_duration() {
        let parameters = VotingRewardsParameters {
            round_duration_seconds: Some(100),
            reward_rate_transition_duration_seconds: Some(100),
            ..VOTING_REWARDS_PARAMETERS
        };
        let expected = RewardRate::from_basis_points(100);
        assert_eq!(
            parameters.reward_rate_at(round_number_to_instant(100)),
            expected,
        );
    }

    #[test]
    fn reward_rate_flattens_out() {
        let final_reward_rate = RewardRate::from_basis_points(
            VOTING_REWARDS_PARAMETERS.final_reward_rate_basis_points(),
        );
        assert_eq!(
            VOTING_REWARDS_PARAMETERS.reward_rate_at(round_number_to_instant(42)),
            final_reward_rate
        );
        assert_eq!(
            VOTING_REWARDS_PARAMETERS.reward_rate_at(round_number_to_instant(42 + 5)),
            final_reward_rate
        );
        assert_eq!(
            VOTING_REWARDS_PARAMETERS.reward_rate_at(round_number_to_instant(123456)),
            final_reward_rate
        );

        // The reward rate should not be the final reward rate at time zero.
        assert!(
            VOTING_REWARDS_PARAMETERS.reward_rate_at(round_number_to_instant(0))
                != final_reward_rate
        );
    }

    #[test]
    fn reward_for_first_day() {
        assert_eq!(
            VOTING_REWARDS_PARAMETERS.reward_rate_at(round_number_to_instant(0)),
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
            let reward_rate =
                VOTING_REWARDS_PARAMETERS.reward_rate_at(round_number_to_instant(round));
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
            let previous =
                VOTING_REWARDS_PARAMETERS.reward_rate_at(round_number_to_instant(reward_round));
            let current =
                VOTING_REWARDS_PARAMETERS.reward_rate_at(round_number_to_instant(reward_round + 1));
            let next =
                VOTING_REWARDS_PARAMETERS.reward_rate_at(round_number_to_instant(reward_round + 2));
            // First "derivative" is negative.
            assert!(previous > current);
            assert!(current > next);
            // Second "derivative" is positive.
            assert!(current - previous < next - current);
        }
    }

    #[test]
    fn test_round_duration_seconds_validation() {
        assert_is_err!(VotingRewardsParameters {
            round_duration_seconds: None,
            ..VOTING_REWARDS_PARAMETERS
        }
        .validate());
        assert_is_err!(VotingRewardsParameters {
            round_duration_seconds: Some(0),
            ..VOTING_REWARDS_PARAMETERS
        }
        .validate());
        assert_is_err!(VotingRewardsParameters {
            round_duration_seconds: Some(31557601), // 365.25 days + 1 s.
            ..VOTING_REWARDS_PARAMETERS
        }
        .validate());
        assert_is_ok!(VotingRewardsParameters {
            round_duration_seconds: Some(31557600), // This is just shy of our "insane" threshold.
            ..VOTING_REWARDS_PARAMETERS
        }
        .validate());
    }

    #[test]
    fn test_reward_rate_transition_duration_seconds_validation() {
        assert_is_err!(VotingRewardsParameters {
            reward_rate_transition_duration_seconds: None,
            ..VOTING_REWARDS_PARAMETERS
        }
        .validate());
    }

    #[test]
    fn test_reward_rate_transition_duration_seconds_validation_accepts_zero() {
        let parameters = VotingRewardsParameters {
            reward_rate_transition_duration_seconds: Some(0),
            ..VOTING_REWARDS_PARAMETERS
        };
        assert_is_ok!(parameters.validate());

        // Make sure that the reward_rate_at method doesn't explode when the
        // reward rate transition duration is zero.
        for seconds_since_genesis in [
            0, // The most interesting value.
            1,
            2,
            3,
            10,
            100,
            1_000,
            10_000,
            100_000,
            1_000_000,
            10_000_000,
            100_000_000,
        ] {
            let extra = Duration::from_secs(Decimal::from(seconds_since_genesis));
            let observed_reward_rate = parameters.reward_rate_at(*GENESIS + extra);
            assert_eq!(
                observed_reward_rate.per_year,
                i2d(parameters.final_reward_rate_basis_points.unwrap()) / i2d(10_000),
                "seconds_since_genesis = {}, observed_reward_rate = {:#?} ",
                seconds_since_genesis,
                observed_reward_rate,
            );
        }
    }

    #[test]
    fn test_initial_reward_rate_basis_points_validation() {
        assert_is_err!(VotingRewardsParameters {
            initial_reward_rate_basis_points: None,
            ..VOTING_REWARDS_PARAMETERS
        }
        .validate());
        assert_is_err!(VotingRewardsParameters {
            initial_reward_rate_basis_points: Some(10_001), // > 100%
            ..VOTING_REWARDS_PARAMETERS
        }
        .validate());

        let valid = VotingRewardsParameters {
            initial_reward_rate_basis_points: Some(1_00), // 1%
            ..VOTING_REWARDS_PARAMETERS
        };
        assert_is_ok!(valid.validate());

        // reward_rate_at treats times before genesis the same as at genesis.
        for seconds_before_genesis in [1, 2, 3, 10] {
            let instant = *GENESIS + Duration::from_secs(i2d(0) - i2d(seconds_before_genesis));

            assert_eq!(
                valid.reward_rate_at(instant).per_year,
                i2d(valid.initial_reward_rate_basis_points.unwrap()) / i2d(10_000),
            );
        }
    }

    #[test]
    fn test_final_reward_rate_basis_points_validation() {
        assert_is_err!(VotingRewardsParameters {
            final_reward_rate_basis_points: None,
            ..VOTING_REWARDS_PARAMETERS
        }
        .validate());

        let max = VOTING_REWARDS_PARAMETERS
            .initial_reward_rate_basis_points
            .unwrap();
        assert_is_ok!(VotingRewardsParameters {
            final_reward_rate_basis_points: Some(max),
            ..VOTING_REWARDS_PARAMETERS
        }
        .validate());
        assert_is_err!(VotingRewardsParameters {
            final_reward_rate_basis_points: Some(max + 1),
            ..VOTING_REWARDS_PARAMETERS
        }
        .validate());
    }
}
