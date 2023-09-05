use crate::pb::v1::{
    governance::{GovernanceCachedMetrics, MakingSnsProposal, Migrations, NeuronInFlightCommand},
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
    pub neuron_management_voting_period_seconds: u64,
    pub metrics: Option<GovernanceCachedMetrics>,
    pub most_recent_monthly_node_provider_rewards: Option<MostRecentMonthlyNodeProviderRewards>,
    pub cached_daily_maturity_modulation_basis_points: Option<i32>,
    pub maturity_modulation_last_updated_at_timestamp_seconds: Option<u64>,
    pub spawning_neurons: Option<bool>,
    pub making_sns_proposal: Option<MakingSnsProposal>,
    pub migrations: Option<Migrations>,
}

/// Splits the governance proto (from UPGRADES_MEMORY) into HeapGovernanceData and neurons, because
/// we have a dedicated struct NeuronStore owning the heap neurons.
/// Does not guarantee round-trip equivalence between this and
/// reassemble_governance_proto if the proto has fields that are None, as they might be filled in by default values.
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
        neuron_management_voting_period_seconds,
        metrics,
        most_recent_monthly_node_provider_rewards,
        cached_daily_maturity_modulation_basis_points,
        maturity_modulation_last_updated_at_timestamp_seconds,
        spawning_neurons,
        making_sns_proposal,
        migrations,
    } = governance_proto;

    let neuron_management_voting_period_seconds =
        neuron_management_voting_period_seconds.unwrap_or(48 * 60 * 60);

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
            neuron_management_voting_period_seconds,
            metrics,
            most_recent_monthly_node_provider_rewards,
            cached_daily_maturity_modulation_basis_points,
            maturity_modulation_last_updated_at_timestamp_seconds,
            spawning_neurons,
            making_sns_proposal,
            migrations,
        },
    )
}

/// Reassembles the GovernanceProto from the HeapGovernanceData and the neurons, so that
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
        neuron_management_voting_period_seconds,
        metrics,
        most_recent_monthly_node_provider_rewards,
        cached_daily_maturity_modulation_basis_points,
        maturity_modulation_last_updated_at_timestamp_seconds,
        spawning_neurons,
        making_sns_proposal,
        migrations,
    } = heap_governance_proto;

    let neuron_management_voting_period_seconds = Some(neuron_management_voting_period_seconds);

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
        neuron_management_voting_period_seconds,
        metrics,
        most_recent_monthly_node_provider_rewards,
        cached_daily_maturity_modulation_basis_points,
        maturity_modulation_last_updated_at_timestamp_seconds,
        spawning_neurons,
        making_sns_proposal,
        migrations,
    }
}

#[test]
fn private_voting_period_assumed_to_be_48h() {
    // split_governance_proto should return a HeapGovernanceData where the neuron_management_voting_period_seconds is 0 when given a default input
    let (_, heap_governance_proto) = split_governance_proto(GovernanceProto::default());
    assert_eq!(
        heap_governance_proto.neuron_management_voting_period_seconds,
        48 * 60 * 60
    );
}
