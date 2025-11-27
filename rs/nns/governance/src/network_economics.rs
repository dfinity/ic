use crate::pb::v1::{
    NetworkEconomics, NeuronsFundEconomics, NeuronsFundMatchedFundingCurveCoefficients,
    VotingPowerEconomics,
};
use ic_nervous_system_common::{E8, ONE_DAY_SECONDS, ONE_MONTH_SECONDS};
use ic_nervous_system_linear_map::LinearMap;
use ic_nervous_system_proto::pb::v1::{Decimal as DecimalProto, Percentage};
use icp_ledger::DEFAULT_TRANSFER_FEE;
use rust_decimal::Decimal;
use std::ops::RangeInclusive;
use std::time::Duration;

impl NetworkEconomics {
    /// The multiplier applied to minimum_icp_xdr_rate to convert the XDR unit to basis_points
    pub const ICP_XDR_RATE_TO_BASIS_POINT_MULTIPLIER: u64 = 100;

    // The default values for network economics (until we initialize it).
    // Can't implement Default since it conflicts with Prost's.
    pub fn with_default_values() -> Self {
        Self {
            reject_cost_e8s: E8,                                        // 1 ICP
            neuron_management_fee_per_proposal_e8s: 1_000_000,          // 0.01 ICP
            neuron_minimum_stake_e8s: E8,                               // 1 ICP
            neuron_spawn_dissolve_delay_seconds: ONE_DAY_SECONDS * 7,   // 7 days
            maximum_node_provider_rewards_e8s: 1_000_000 * 100_000_000, // 1M ICP
            minimum_icp_xdr_rate: 100,                                  // 1 XDR
            transaction_fee_e8s: DEFAULT_TRANSFER_FEE.get_e8s(),
            max_proposals_to_keep_per_topic: 100,
            neurons_fund_economics: Some(NeuronsFundEconomics::with_default_values()),
            voting_power_economics: Some(VotingPowerEconomics::with_default_values()),
        }
    }

    pub fn apply_changes_and_validate(
        &self,
        changes: &NetworkEconomics,
    ) -> Result<Self, Vec<String>> {
        let result = changes.inherit_from(self);
        result.validate()?;
        Ok(result)
    }

    /// This verifies the following:
    ///
    ///     1. max_proposals_to_keep_per_topic > 0. The problem with 0 is that
    ///        all future proposals would be blocked. Of course, in practice,
    ///        this would never occur, because ManageNetworkEconomics does not
    ///        have the ability to set this field to 0, and it already has
    ///        positive value.
    ///
    ///     2. neurons_fund_economics and voting_power_economics are
    ///
    ///         i.  set. In practice, we would not encounter None here, for
    ///             reasons similar to why we would not see
    ///             max_proposals_to_keep_per_topic being set to 0.
    ///
    ///         ii. valid, according to their types. See their respective
    ///             validate methods: [NeuronsFundEconomics::validate],
    ///             [VotingPowerEconomics::validate].
    ///
    /// If Err is returned, it will be a nonempty Vec of defects.
    ///
    // Other fields are allowed to be 0, but this would never occur in practice
    // for the same reason that in practice, we would not observe that
    // max_proposals_to_keep_per_topic is set to 0.
    //
    // It is redundant that Vec<String> is wrapped in Result. We do this for
    // consistency with other validate methods.
    fn validate(&self) -> Result<(), Vec<String>> {
        let mut defects = vec![];

        if self.max_proposals_to_keep_per_topic == 0 {
            // This would not occur in practice, because ManageNetworkEconomics
            // proposals do not have the ability to set this (nor any other
            // field) to zero (and the current value is also already not zero).
            defects.push("max_proposals_to_keep_per_topic must be positive.".to_string());
        }

        // Substructs must be set.
        if self.neurons_fund_economics.is_none() {
            defects.push("neurons_fund_economics must be set.".to_string());
        }
        if self.voting_power_economics.is_none() {
            defects.push("voting_power_economics must be set.".to_string());
        }

        // Validate substructs (according to their type).
        if let Some(neurons_fund_economics) = self.neurons_fund_economics.as_ref()
            && let Err(mut neurons_fund_defects) = neurons_fund_economics.validate()
        {
            defects.append(&mut neurons_fund_defects)
        };
        if let Some(voting_power_economics) = self.voting_power_economics.as_ref()
            && let Err(mut voting_power_defects) = voting_power_economics.validate()
        {
            defects.append(&mut voting_power_defects)
        }

        if !defects.is_empty() {
            return Err(defects);
        }

        Ok(())
    }
}

impl NeuronsFundEconomics {
    /// This verifies the following:
    ///
    ///     1. All fields are set.
    ///
    ///     2. max >= min. In particular, maximum_icp_xdr_rate vs. minimum_icp_xdr_rate.
    ///
    ///     3. neurons_fund_matched_funding_curve_coefficients is valid per its
    ///     type. (See NeuronsFundMatchedFundingCurveCoefficients::validate).
    ///
    /// If Err is returned, it will be a nonempty Vec of defects.
    fn validate(&self) -> Result<(), Vec<String>> {
        let Self {
            maximum_icp_xdr_rate,
            minimum_icp_xdr_rate,
            max_theoretical_neurons_fund_participation_amount_xdr,
            neurons_fund_matched_funding_curve_coefficients,
        } = self;

        let mut defects = vec![];

        // Everything must be set.
        if maximum_icp_xdr_rate.is_none() {
            defects.push("maximum_icp_xdr_rate must be set.".to_string());
        }
        if minimum_icp_xdr_rate.is_none() {
            defects.push("minimum_icp_xdr_rate must be set.".to_string());
        }
        if max_theoretical_neurons_fund_participation_amount_xdr.is_none() {
            defects.push(
                "max_theoretical_neurons_fund_participation_amount_xdr must be set.".to_string(),
            );
        }
        if neurons_fund_matched_funding_curve_coefficients.is_none() {
            defects
                .push("neurons_fund_matched_funding_curve_coefficients must be set.".to_string());
        }

        // Validate that max >= min.
        if let (Some(maximum_icp_xdr_rate), Some(minimum_icp_xdr_rate)) =
            (maximum_icp_xdr_rate, minimum_icp_xdr_rate)
            && maximum_icp_xdr_rate < minimum_icp_xdr_rate
        {
            defects.push(format!(
                    "maximum_icp_xdr_rate ({maximum_icp_xdr_rate}) must be greater than or equal to minimum_icp_xdr_rate ({minimum_icp_xdr_rate}).",
                ));
        }

        // Validate substruct(s) (according to their type).
        if let Some(neurons_fund_matched_funding_curve_coefficients) = self
            .neurons_fund_matched_funding_curve_coefficients
            .as_ref()
            && let Err(mut neurons_fund_matched_funding_curve_coefficients_defects) =
                neurons_fund_matched_funding_curve_coefficients.validate()
        {
            defects.append(&mut neurons_fund_matched_funding_curve_coefficients_defects);
        }

        if !defects.is_empty() {
            return Err(defects);
        }

        Ok(())
    }
}

impl NeuronsFundMatchedFundingCurveCoefficients {
    /// This verifies the following:
    ///
    ///     1. All fields are set.
    ///
    ///     2. All (Decimal) values are valid for their type (i.e. can be
    ///        converted to rust_decimal::Decimal).
    ///
    ///     3. one_third_participation_milestone_xdr <
    ///        full_participation_milestone_xdr.
    ///
    /// If Err is returned, it will be a nonempty Vec of defects.
    fn validate(&self) -> Result<(), Vec<String>> {
        let Self {
            contribution_threshold_xdr,
            one_third_participation_milestone_xdr,
            full_participation_milestone_xdr,
        } = self;

        let mut defects = vec![];

        // Everything must be set.
        if contribution_threshold_xdr.is_none() {
            defects.push("contribution_threshold_xdr must be set.".to_string());
        }
        if one_third_participation_milestone_xdr.is_none() {
            defects.push("one_third_participation_milestone_xdr must be set.".to_string());
        }
        if full_participation_milestone_xdr.is_none() {
            defects.push("full_participation_milestone_xdr must be set.".to_string());
        }

        // All values must be valid (per their type).
        fn try_convert_decimal(
            original: &Option<DecimalProto>,
        ) -> Result<Decimal, /* human_readable */ &str> {
            const DEFAULT_DECIMAL: DecimalProto = DecimalProto {
                human_readable: None,
            };

            let human_readable: &str = original
                .as_ref()
                .unwrap_or(&DEFAULT_DECIMAL)
                .human_readable
                .as_deref()
                .unwrap_or("");

            Decimal::try_from(human_readable).map_err(|_ignore| human_readable)
        }

        let _contribution_threshold_xdr = try_convert_decimal(contribution_threshold_xdr)
            .inspect_err(|original| {
                defects.push(format!(
                    "contribution_threshold_xdr ({original}) is not a Decimal."
                ));
            });
        let one_third_participation_milestone_xdr =
            try_convert_decimal(one_third_participation_milestone_xdr).inspect_err(|original| {
                defects.push(format!(
                    "one_third_participation_milestone_xdr ({original}) is not a Decimal."
                ));
            });
        let full_participation_milestone_xdr =
            try_convert_decimal(full_participation_milestone_xdr).inspect_err(|original| {
                defects.push(format!(
                    "full_participation_milestone_xdr ({original}) is not a Decimal."
                ));
            });

        // later milestones must be > earlier ones
        if let (Ok(one_third_participation_milestone_xdr), Ok(full_participation_milestone_xdr)) = (
            one_third_participation_milestone_xdr,
            full_participation_milestone_xdr,
        ) && one_third_participation_milestone_xdr >= full_participation_milestone_xdr
        {
            defects.push(format!(
                    "one_third_participation_milestone_xdr ({one_third_participation_milestone_xdr}) must be less than full_participation_milestone_xdr ({full_participation_milestone_xdr}).",
                ));
        }

        if !defects.is_empty() {
            return Err(defects);
        }

        Ok(())
    }
}

impl VotingPowerEconomics {
    pub const DEFAULT: Self = Self {
        start_reducing_voting_power_after_seconds: Some(
            Self::DEFAULT_START_REDUCING_VOTING_POWER_AFTER_SECONDS,
        ),
        clear_following_after_seconds: Some(Self::DEFAULT_CLEAR_FOLLOWING_AFTER_SECONDS),
        neuron_minimum_dissolve_delay_to_vote_seconds: Some(
            Self::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS,
        ),
    };

    /// Only neurons with at least this dissolve delay may submit proposals.
    ///
    /// When a proposal is created, neurons with dissolve delay (in seconds) less than
    /// `VotingPowerEconomics.min_dissolve_delay_seconds` receive no ballot (to be filled out)
    /// for that proposal. Thus, such neurons cannot vote on the proposal.
    pub const DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS: u64 = 6 * ONE_MONTH_SECONDS;

    /// A proposal to set `VotingPowerEconomics.min_dissolve_delay_seconds` must specify a value
    /// for this field that falls within this range. Changing the lower bound of this parameter
    /// requires manually checking how it might interact with other aspects of the NNS.
    /// In particular, it is not currently possible for a dissolved neuron to cast a vote, as
    /// the minimal dissolve delay to be eligible for voting exceeds the maximal voting period.
    /// Thus, there may be implicit dependencies of the NNS itself or its clients on this aspect,
    /// which originate from the time when the minimum dissolve delay to vote was an internal NNS
    /// constant.
    pub const NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS_BOUNDS: RangeInclusive<u64> =
        (3 * ONE_MONTH_SECONDS)..=(6 * ONE_MONTH_SECONDS);

    pub const DEFAULT_START_REDUCING_VOTING_POWER_AFTER_SECONDS: u64 = 6 * ONE_MONTH_SECONDS;

    pub const DEFAULT_CLEAR_FOLLOWING_AFTER_SECONDS: u64 = ONE_MONTH_SECONDS;

    pub fn with_default_values() -> Self {
        Self::DEFAULT
    }

    /// Returns 1 if a neuron has refreshed (its voting power/following)
    /// recently.
    ///
    /// Otherwise, if a neuron has not refreshed for >
    /// start_reducing_voting_power_after_seconds, returns < 1 (but >= 0).
    ///
    /// Once a neuron has not refresehd for
    /// start_reducing_voting_power_after_seconds +
    /// clear_following_after_seconds, this returns 0.
    ///
    /// Between these two points, the decrease is linear.
    pub fn deciding_voting_power_adjustment_factor(
        &self,
        time_since_last_voting_power_refreshed: Duration,
    ) -> Decimal {
        self.deciding_voting_power_adjustment_factor_function()
            .apply(time_since_last_voting_power_refreshed.as_secs())
            .clamp(Decimal::from(0), Decimal::from(1))
    }

    fn deciding_voting_power_adjustment_factor_function(&self) -> LinearMap {
        let from_range = {
            let begin = self.get_start_reducing_voting_power_after_seconds();
            let end = begin.saturating_add(self.get_clear_following_after_seconds());

            begin..end
        };

        #[allow(clippy::reversed_empty_ranges)]
        let to_range = 1..0;

        LinearMap::new(from_range, to_range)
    }

    pub fn get_start_reducing_voting_power_after_seconds(&self) -> u64 {
        self.start_reducing_voting_power_after_seconds
            .unwrap_or(Self::DEFAULT_START_REDUCING_VOTING_POWER_AFTER_SECONDS)
    }

    pub fn get_clear_following_after_seconds(&self) -> u64 {
        self.clear_following_after_seconds
            .unwrap_or(Self::DEFAULT_CLEAR_FOLLOWING_AFTER_SECONDS)
    }

    /// This just validates that all fields are set.
    ///
    /// They are allowed to be set to 0 though.
    ///
    /// In practice, we would never see None in any fields, because
    /// ManageNetworkEconomics has no way to set fields to None (see impl
    /// InheritFrom for Option), and in production, these fields are already set
    /// to Some.
    ///
    /// If Err is returned, it will be a nonempty Vec of defects.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut defects = vec![];

        if self.start_reducing_voting_power_after_seconds.is_none() {
            // In practice, this cannot occur, because there is no way for
            // ManageNetworkEconomics proposals to set this to None, and its
            // current value is already Some.
            defects.push("start_reducing_voting_power_after_seconds must be set.".to_string());
        }

        if self.clear_following_after_seconds.is_none() {
            // Ditto comment regarding start_reducing_voting_power_after_seconds.
            defects.push("clear_following_after_seconds must be set.".to_string());
        }

        if let Some(delay) = self.neuron_minimum_dissolve_delay_to_vote_seconds {
            if !VotingPowerEconomics::NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS_BOUNDS
                .contains(&delay)
            {
                let defect = format!(
                    "neuron_minimum_dissolve_delay_to_vote_seconds ({:?}) must be between three \
                     and six months.",
                    self.neuron_minimum_dissolve_delay_to_vote_seconds
                );
                defects.push(defect);
            }
        } else {
            defects.push("neuron_minimum_dissolve_delay_to_vote_seconds must be set.".to_string());
        }

        if !defects.is_empty() {
            return Err(defects);
        }

        Ok(())
    }
}

// Seems like there is probably some way we can make #[derive(...)] generate
// implementations of this, because the hand-crafted implementations below are
// pretty dang (if not completely) repetitive. OTOH, it would be a lot of work,
// and it is not clear that we would use it many times.
trait InheritFrom {
    /// Returns a modified copy of self where fields containing 0 are replaced
    /// with the value from base.
    fn inherit_from(&self, base: &Self) -> Self;
}

// Ideally, we'd use num_traits::Zero to give a generic implementation that
// applies to all integer types, but Rust refuses to allow that in the presence
// of impl InheritFrom for Option<T> below. If only there was some way we could
// tell Rust, "ok, but this impl does not apply when the type happens to be
// Option", but that doesn't exist (yet). Fortunately, we do not use a wide
// range of integer types. Therefore, only this one is needed (for now).
impl InheritFrom for u64 {
    fn inherit_from(&self, base: &Self) -> Self {
        if self == &0_u64 {
            return *base;
        }

        *self
    }
}

impl InheritFrom for u32 {
    fn inherit_from(&self, base: &Self) -> Self {
        if self == &0_u32 {
            return *base;
        }

        *self
    }
}

impl InheritFrom for ic_nervous_system_proto::pb::v1::Decimal {
    fn inherit_from(&self, base: &Self) -> Self {
        if self
            == &(ic_nervous_system_proto::pb::v1::Decimal {
                human_readable: Some("0".to_string()),
            })
        {
            return base.clone();
        }

        self.clone()
    }
}

impl InheritFrom for Percentage {
    fn inherit_from(&self, base: &Self) -> Self {
        if self
            == &(Percentage {
                basis_points: Some(0),
            })
        {
            return *base;
        }

        *self
    }
}

impl<T> InheritFrom for Option<T>
where
    T: InheritFrom + Clone,
{
    fn inherit_from(&self, base: &Self) -> Self {
        match (self, base) {
            (Some(me), Some(base)) => Some(me.inherit_from(base)),
            (Some(_), None) => self.clone(),
            (None, base) => base.clone(),
        }
    }
}

impl InheritFrom for NetworkEconomics {
    fn inherit_from(&self, base: &Self) -> Self {
        Self {
            reject_cost_e8s: self.reject_cost_e8s.inherit_from(&base.reject_cost_e8s),
            neuron_minimum_stake_e8s: self
                .neuron_minimum_stake_e8s
                .inherit_from(&base.neuron_minimum_stake_e8s),
            neuron_management_fee_per_proposal_e8s: self
                .neuron_management_fee_per_proposal_e8s
                .inherit_from(&base.neuron_management_fee_per_proposal_e8s),
            minimum_icp_xdr_rate: self
                .minimum_icp_xdr_rate
                .inherit_from(&base.minimum_icp_xdr_rate),
            neuron_spawn_dissolve_delay_seconds: self
                .neuron_spawn_dissolve_delay_seconds
                .inherit_from(&base.neuron_spawn_dissolve_delay_seconds),
            maximum_node_provider_rewards_e8s: self
                .maximum_node_provider_rewards_e8s
                .inherit_from(&base.maximum_node_provider_rewards_e8s),
            transaction_fee_e8s: self
                .transaction_fee_e8s
                .inherit_from(&base.transaction_fee_e8s),
            max_proposals_to_keep_per_topic: self
                .max_proposals_to_keep_per_topic
                .inherit_from(&base.max_proposals_to_keep_per_topic),

            neurons_fund_economics: self
                .neurons_fund_economics
                .inherit_from(&base.neurons_fund_economics),
            voting_power_economics: self
                .voting_power_economics
                .inherit_from(&base.voting_power_economics),
        }
    }
}

impl InheritFrom for NeuronsFundEconomics {
    fn inherit_from(&self, base: &Self) -> Self {
        Self {
            max_theoretical_neurons_fund_participation_amount_xdr: self
                .max_theoretical_neurons_fund_participation_amount_xdr
                .inherit_from(&base.max_theoretical_neurons_fund_participation_amount_xdr),

            maximum_icp_xdr_rate: self
                .maximum_icp_xdr_rate
                .inherit_from(&base.maximum_icp_xdr_rate),

            minimum_icp_xdr_rate: self
                .minimum_icp_xdr_rate
                .inherit_from(&base.minimum_icp_xdr_rate),

            neurons_fund_matched_funding_curve_coefficients: self
                .neurons_fund_matched_funding_curve_coefficients
                .inherit_from(&base.neurons_fund_matched_funding_curve_coefficients),
        }
    }
}

impl InheritFrom for NeuronsFundMatchedFundingCurveCoefficients {
    fn inherit_from(&self, base: &Self) -> Self {
        Self {
            contribution_threshold_xdr: self
                .contribution_threshold_xdr
                .inherit_from(&base.contribution_threshold_xdr),

            full_participation_milestone_xdr: self
                .full_participation_milestone_xdr
                .inherit_from(&base.full_participation_milestone_xdr),

            one_third_participation_milestone_xdr: self
                .one_third_participation_milestone_xdr
                .inherit_from(&base.one_third_participation_milestone_xdr),
        }
    }
}

impl InheritFrom for VotingPowerEconomics {
    fn inherit_from(&self, base: &Self) -> Self {
        Self {
            start_reducing_voting_power_after_seconds: self
                .start_reducing_voting_power_after_seconds
                .inherit_from(&base.start_reducing_voting_power_after_seconds),

            clear_following_after_seconds: self
                .clear_following_after_seconds
                .inherit_from(&base.clear_following_after_seconds),
            neuron_minimum_dissolve_delay_to_vote_seconds: self
                .neuron_minimum_dissolve_delay_to_vote_seconds
                .inherit_from(&base.neuron_minimum_dissolve_delay_to_vote_seconds),
        }
    }
}

#[cfg(test)]
#[path = "./network_economics_tests.rs"]
mod network_economics_tests;
