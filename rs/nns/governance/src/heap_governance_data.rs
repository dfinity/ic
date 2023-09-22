use crate::pb::v1::{
    governance::{GovernanceCachedMetrics, MakingSnsProposal, NeuronInFlightCommand},
    neuron::Followees,
    Governance as GovernanceProto, MostRecentMonthlyNodeProviderRewards, NetworkEconomics, Neuron,
    NeuronStakeTransfer, NodeProvider, ProposalData, RewardEvent,
};
use std::collections::{BTreeMap, HashMap};

/// A GovernanceProto representation on the heap, which should have everything except for neurons.
/// This should never be serialized by itself, but reassembled into GovernanceProto in pre_upgrade.
/// See crate::pb::v1::Governance for the meaning of each field.
#[derive(Clone, Default)]
pub struct HeapGovernanceData {
    pub proposals: BTreeMap<u64, ProposalData>,
    pub to_claim_transfers: Vec<NeuronStakeTransfer>,
    pub wait_for_quiet_threshold_seconds: u64,
    pub economics: Option<NetworkEconomics>,
    pub latest_reward_event: Option<RewardEvent>,
    pub in_flight_commands: HashMap<u64, NeuronInFlightCommand>,
    pub genesis_timestamp_seconds: u64,
    pub node_providers: Vec<NodeProvider>,
    pub default_followees: HashMap<i32, Followees>,
    pub short_voting_period_seconds: u64,
    pub metrics: Option<GovernanceCachedMetrics>,
    pub most_recent_monthly_node_provider_rewards: Option<MostRecentMonthlyNodeProviderRewards>,
    pub cached_daily_maturity_modulation_basis_points: Option<i32>,
    pub maturity_modulation_last_updated_at_timestamp_seconds: Option<u64>,
    pub spawning_neurons: Option<bool>,
    pub making_sns_proposal: Option<MakingSnsProposal>,
}

/// Splits the governance proto (from UPGRADES_MEMORY) into HeapGovernanceData and neurons, because
/// we have a dedicated struct NeuronStore owning the heap neurons.
pub fn split_governance_proto(
    governance_proto: GovernanceProto,
) -> (BTreeMap<u64, Neuron>, HeapGovernanceData) {
    // DO NOT USE THE .. CATCH-ALL SYNTAX HERE.
    // OTHERWISE, YOU WILL ALMOST CERTAINLY EXPERIENCE
    //   **DATA LOSS**
    // FOR THE SAME REASON, DO NOT DO
    //     new_field: _,
    let GovernanceProto {
        neurons,
        proposals,
        to_claim_transfers,
        wait_for_quiet_threshold_seconds,
        economics,
        latest_reward_event,
        in_flight_commands,
        genesis_timestamp_seconds,
        node_providers,
        default_followees,
        short_voting_period_seconds,
        metrics,
        most_recent_monthly_node_provider_rewards,
        cached_daily_maturity_modulation_basis_points,
        maturity_modulation_last_updated_at_timestamp_seconds,
        spawning_neurons,
        making_sns_proposal,
    } = governance_proto;
    (
        neurons,
        HeapGovernanceData {
            proposals,
            to_claim_transfers,
            wait_for_quiet_threshold_seconds,
            economics,
            latest_reward_event,
            in_flight_commands,
            genesis_timestamp_seconds,
            node_providers,
            default_followees,
            short_voting_period_seconds,
            metrics,
            most_recent_monthly_node_provider_rewards,
            cached_daily_maturity_modulation_basis_points,
            maturity_modulation_last_updated_at_timestamp_seconds,
            spawning_neurons,
            making_sns_proposal,
        },
    )
}

/// Reassemblees the GovernanceProto from the HeapGovernanceData and the neurons, so that
/// it can be serialized into UPGRADES_MEMORY.
pub fn reassemble_governance_proto(
    neurons: BTreeMap<u64, Neuron>,
    heap_governance_proto: HeapGovernanceData,
) -> GovernanceProto {
    // DO NOT USE THE .. CATCH-ALL SYNTAX HERE.
    // OTHERWISE, YOU WILL ALMOST CERTAINLY EXPERIENCE
    //   **DATA LOSS**
    // FOR THE SAME REASON, DO NOT DO
    //     new_field: _,
    let HeapGovernanceData {
        proposals,
        to_claim_transfers,
        wait_for_quiet_threshold_seconds,
        economics,
        latest_reward_event,
        in_flight_commands,
        genesis_timestamp_seconds,
        node_providers,
        default_followees,
        short_voting_period_seconds,
        metrics,
        most_recent_monthly_node_provider_rewards,
        cached_daily_maturity_modulation_basis_points,
        maturity_modulation_last_updated_at_timestamp_seconds,
        spawning_neurons,
        making_sns_proposal,
    } = heap_governance_proto;

    GovernanceProto {
        neurons,
        proposals,
        to_claim_transfers,
        wait_for_quiet_threshold_seconds,
        economics,
        latest_reward_event,
        in_flight_commands,
        genesis_timestamp_seconds,
        node_providers,
        default_followees,
        short_voting_period_seconds,
        metrics,
        most_recent_monthly_node_provider_rewards,
        cached_daily_maturity_modulation_basis_points,
        maturity_modulation_last_updated_at_timestamp_seconds,
        spawning_neurons,
        making_sns_proposal,
    }
}
