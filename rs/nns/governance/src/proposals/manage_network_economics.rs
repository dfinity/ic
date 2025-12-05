use crate::{
    pb::v1::{
        NetworkEconomics, NeuronsFundEconomics, NeuronsFundMatchedFundingCurveCoefficients,
        SelfDescribingValue, VotingPowerEconomics,
    },
    proposals::self_describing::{LocallyDescribableProposalAction, ValueBuilder},
};

use ic_nervous_system_proto::pb::v1::{Decimal, Percentage};

impl LocallyDescribableProposalAction for NetworkEconomics {
    const TYPE_NAME: &'static str = "Manage Network Economics";
    const TYPE_DESCRIPTION: &'static str = "Updates the network economics parameters that control various costs, rewards, and \
        thresholds in the Network Nervous System, including proposal costs, neuron staking \
        requirements, transaction fees, and voting power economics.";

    fn to_self_describing_value(&self) -> SelfDescribingValue {
        ValueBuilder::new()
            .add_field("reject_cost_e8s", self.reject_cost_e8s)
            .add_field("neuron_minimum_stake_e8s", self.neuron_minimum_stake_e8s)
            .add_field(
                "neuron_management_fee_per_proposal_e8s",
                self.neuron_management_fee_per_proposal_e8s,
            )
            .add_field("minimum_icp_xdr_rate", self.minimum_icp_xdr_rate)
            .add_field(
                "neuron_spawn_dissolve_delay_seconds",
                self.neuron_spawn_dissolve_delay_seconds,
            )
            .add_field(
                "maximum_node_provider_rewards_e8s",
                self.maximum_node_provider_rewards_e8s,
            )
            .add_field("transaction_fee_e8s", self.transaction_fee_e8s)
            .add_field(
                "max_proposals_to_keep_per_topic",
                self.max_proposals_to_keep_per_topic,
            )
            .add_field(
                "neurons_fund_economics",
                self.neurons_fund_economics.clone(),
            )
            .add_field("voting_power_economics", self.voting_power_economics)
            .build()
    }
}

impl From<NeuronsFundEconomics> for SelfDescribingValue {
    fn from(economics: NeuronsFundEconomics) -> Self {
        ValueBuilder::new()
            .add_field(
                "max_theoretical_neurons_fund_participation_amount_xdr",
                economics.max_theoretical_neurons_fund_participation_amount_xdr,
            )
            .add_field(
                "neurons_fund_matched_funding_curve_coefficients",
                economics.neurons_fund_matched_funding_curve_coefficients,
            )
            .add_field("minimum_icp_xdr_rate", economics.minimum_icp_xdr_rate)
            .add_field("maximum_icp_xdr_rate", economics.maximum_icp_xdr_rate)
            .build()
    }
}

impl From<Percentage> for SelfDescribingValue {
    fn from(percentage: Percentage) -> Self {
        ValueBuilder::new()
            .add_field("basis_points", percentage.basis_points)
            .build()
    }
}

impl From<Decimal> for SelfDescribingValue {
    fn from(decimal: Decimal) -> Self {
        ValueBuilder::new()
            .add_field("human_readable", decimal.human_readable)
            .build()
    }
}

impl From<NeuronsFundMatchedFundingCurveCoefficients> for SelfDescribingValue {
    fn from(coefficients: NeuronsFundMatchedFundingCurveCoefficients) -> Self {
        ValueBuilder::new()
            .add_field(
                "contribution_threshold_xdr",
                coefficients.contribution_threshold_xdr,
            )
            .add_field(
                "one_third_participation_milestone_xdr",
                coefficients.one_third_participation_milestone_xdr,
            )
            .add_field(
                "full_participation_milestone_xdr",
                coefficients.full_participation_milestone_xdr,
            )
            .build()
    }
}

impl From<VotingPowerEconomics> for SelfDescribingValue {
    fn from(economics: VotingPowerEconomics) -> Self {
        ValueBuilder::new()
            .add_field(
                "start_reducing_voting_power_after_seconds",
                economics.start_reducing_voting_power_after_seconds,
            )
            .add_field(
                "clear_following_after_seconds",
                economics.clear_following_after_seconds,
            )
            .add_field(
                "neuron_minimum_dissolve_delay_to_vote_seconds",
                economics.neuron_minimum_dissolve_delay_to_vote_seconds,
            )
            .build()
    }
}

#[cfg(test)]
#[path = "manage_network_economics_tests.rs"]
mod tests;
