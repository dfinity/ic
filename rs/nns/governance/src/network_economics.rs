use crate::pb::v1::{NetworkEconomics, NeuronsFundEconomics, VotingPowerEconomics, NeuronsFundMatchedFundingCurveCoefficients};
use ic_nervous_system_common::{E8, ONE_DAY_SECONDS, ONE_MONTH_SECONDS};
use ic_nervous_system_proto::pb::v1::Percentage;
use ic_nervous_system_linear_map::LinearMap;
use icp_ledger::DEFAULT_TRANSFER_FEE;
use rust_decimal::Decimal;
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
}

impl VotingPowerEconomics {
    pub const DEFAULT: Self = Self {
        start_reducing_voting_power_after_seconds: Some(
            Self::DEFAULT_START_REDUCING_VOTING_POWER_AFTER_SECONDS,
        ),
        clear_following_after_seconds: Some(Self::DEFAULT_CLEAR_FOLLOWING_AFTER_SECONDS),
    };

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
            let end = begin + self.get_clear_following_after_seconds();

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
}

// Seems like there is probably some way we can make #[derive(...)] generate
// implementations of this, because the hand-crafted implementations below are
// pretty dang (if not completely) repetitive. OTOH, it would be a lot of work,
// and it is not clear that we would use it many times.
pub(crate) trait InheritFrom {
    /// Returns a modified copy of self where fields containing 0 are replaced
    /// with the value from filler.
    fn inherit_from(&self, filler: &Self) -> Self;
}

// Ideally, we'd use num_traits::Zero to give a generic implementation that
// applies to all integer types, but Rust refuses to allow that in the presence
// of impl InheritFrom for Option<T> below. If only there was some way we could
// tell Rust, "ok, but this impl does not apply when the type happens to be
// Option", but that doesn't exist (yet). Fortunately, we do not use a wide
// range of integer types. Therefore, only this one is needed (for now).
impl InheritFrom for u64 {
    fn inherit_from(&self, filler: &Self) -> Self {
        if self == &0_u64 {
            return *filler;
        }

        *self
    }
}

impl InheritFrom for u32 {
    fn inherit_from(&self, filler: &Self) -> Self {
        if self == &0_u32 {
            return *filler;
        }

        *self
    }
}

impl InheritFrom for ic_nervous_system_proto::pb::v1::Decimal {
    fn inherit_from(&self, filler: &Self) -> Self {
        if self == &(ic_nervous_system_proto::pb::v1::Decimal {
            human_readable: Some("0".to_string()),
        }) {
            return filler.clone();
        }

        self.clone()
    }
}

impl InheritFrom for Percentage {
    fn inherit_from(&self, filler: &Self) -> Self {
        if self == &(Percentage { basis_points: Some(0) }) {
            return *filler;
        }

        *self
    }
}

impl<T> InheritFrom for Option<T>
where
    T: InheritFrom + Clone,
{
    fn inherit_from(&self, filler: &Self) -> Self {
        match (self, filler) {
            (Some(me), Some(filler)) => Some(me.inherit_from(filler)),
            (Some(_), None) => self.clone(),
            (None, filler) => filler.clone(),
        }
    }
}

impl InheritFrom for NetworkEconomics {
    fn inherit_from(&self, filler: &Self) -> Self {
        Self {
            reject_cost_e8s: self.reject_cost_e8s.inherit_from(&filler.reject_cost_e8s),
            neuron_minimum_stake_e8s: self
                .neuron_minimum_stake_e8s
                .inherit_from(&filler.neuron_minimum_stake_e8s),
            neuron_management_fee_per_proposal_e8s: self
                .neuron_management_fee_per_proposal_e8s
                .inherit_from(&filler.neuron_management_fee_per_proposal_e8s),
            minimum_icp_xdr_rate: self
                .minimum_icp_xdr_rate
                .inherit_from(&filler.minimum_icp_xdr_rate),
            neuron_spawn_dissolve_delay_seconds: self
                .neuron_spawn_dissolve_delay_seconds
                .inherit_from(&filler.neuron_spawn_dissolve_delay_seconds),
            maximum_node_provider_rewards_e8s: self
                .maximum_node_provider_rewards_e8s
                .inherit_from(&filler.maximum_node_provider_rewards_e8s),
            transaction_fee_e8s: self
                .transaction_fee_e8s
                .inherit_from(&filler.transaction_fee_e8s),
            max_proposals_to_keep_per_topic: self
                .max_proposals_to_keep_per_topic
                .inherit_from(&filler.max_proposals_to_keep_per_topic),

            neurons_fund_economics: self
                .neurons_fund_economics
                .inherit_from(&filler.neurons_fund_economics),
            voting_power_economics: self
                .voting_power_economics
                .inherit_from(&filler.voting_power_economics),
        }
    }
}

impl InheritFrom for NeuronsFundEconomics {
    fn inherit_from(&self, filler: &Self) -> Self {
        Self {
            max_theoretical_neurons_fund_participation_amount_xdr: self
                .max_theoretical_neurons_fund_participation_amount_xdr
                .inherit_from(&filler.max_theoretical_neurons_fund_participation_amount_xdr),

            maximum_icp_xdr_rate: self
                .maximum_icp_xdr_rate
                .inherit_from(&filler.maximum_icp_xdr_rate),

            minimum_icp_xdr_rate: self
                .minimum_icp_xdr_rate
                .inherit_from(&filler.minimum_icp_xdr_rate),

            neurons_fund_matched_funding_curve_coefficients: self
                .neurons_fund_matched_funding_curve_coefficients
                .inherit_from(&filler.neurons_fund_matched_funding_curve_coefficients),
        }
    }
}

impl InheritFrom for NeuronsFundMatchedFundingCurveCoefficients {
    fn inherit_from(&self, filler: &Self) -> Self {
        Self {
            contribution_threshold_xdr: self
                .contribution_threshold_xdr
                .inherit_from(&filler.contribution_threshold_xdr),

            full_participation_milestone_xdr: self
                .full_participation_milestone_xdr
                .inherit_from(&filler.full_participation_milestone_xdr),

            one_third_participation_milestone_xdr: self
                .one_third_participation_milestone_xdr
                .inherit_from(&filler.one_third_participation_milestone_xdr),
        }
    }
}

impl InheritFrom for VotingPowerEconomics {
    fn inherit_from(&self, filler: &Self) -> Self {
        Self {
            start_reducing_voting_power_after_seconds: self
                .start_reducing_voting_power_after_seconds
                .inherit_from(&filler.start_reducing_voting_power_after_seconds),

            clear_following_after_seconds: self
                .clear_following_after_seconds
                .inherit_from(&filler.clear_following_after_seconds),
        }
    }
}
