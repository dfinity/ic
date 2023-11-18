use crate::{
    pb::v1::{
        governance::{
            followers_map::Followers, FollowersMap, GovernanceCachedMetrics, MakingSnsProposal,
            Migrations, NeuronInFlightCommand,
        },
        neuron::Followees,
        Governance as GovernanceProto, MostRecentMonthlyNodeProviderRewards, NetworkEconomics,
        Neuron, NeuronStakeTransfer, NodeProvider, ProposalData, RewardEvent,
    },
    storage::{NeuronIdU64, Signed32, TopicSigned32},
};
use ic_nervous_system_governance::index::neuron_following::HeapNeuronFollowingIndex;
use ic_nns_common::pb::v1::NeuronId;
use std::collections::{BTreeMap, HashMap};

/// A GovernanceProto representation on the heap, which should have everything except for neurons.
/// This should never be serialized by itself, but reassembled into GovernanceProto in pre_upgrade.
/// See crate::pb::v1::Governance for the meaning of each field.
#[derive(Clone, Debug, Default)]
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

fn proto_to_heap_topic_followee_index(
    proto: HashMap<i32, FollowersMap>,
) -> HeapNeuronFollowingIndex<NeuronIdU64, TopicSigned32> {
    let map = proto
        .into_iter()
        .map(|(topic_i32, followers_map)| {
            let topic = Signed32(topic_i32);

            let followers_map = followers_map
                .followers_map
                .into_iter()
                .map(|(neuron_id, followers)| {
                    let followers = followers
                        .followers
                        .into_iter()
                        .map(|neuron_id| neuron_id.id)
                        .collect();
                    (neuron_id, followers)
                })
                .collect();
            (topic, followers_map)
        })
        .collect();
    HeapNeuronFollowingIndex::new(map)
}

fn heap_topic_followee_index_to_proto(
    heap: HeapNeuronFollowingIndex<NeuronIdU64, TopicSigned32>,
) -> HashMap<i32, FollowersMap> {
    heap.into_inner()
        .into_iter()
        .map(|(topic, followers_map)| {
            let topic = topic.0;
            let followers_map = followers_map
                .into_iter()
                .map(|(followee, followers)| {
                    let followers = Followers {
                        followers: followers.into_iter().map(|id| NeuronId { id }).collect(),
                    };
                    (followee, followers)
                })
                .collect();

            let followers_map = FollowersMap { followers_map };

            (topic, followers_map)
        })
        .collect()
}

/// Splits the governance proto (from UPGRADES_MEMORY) into HeapGovernanceData and neurons, because
/// we have a dedicated struct NeuronStore owning the heap neurons.
/// Does not guarantee round-trip equivalence between this and
/// reassemble_governance_proto if the proto has fields that are None, as they might be filled in by default values.
pub fn split_governance_proto(
    governance_proto: GovernanceProto,
) -> (
    BTreeMap<u64, Neuron>,
    HeapNeuronFollowingIndex<NeuronIdU64, TopicSigned32>,
    HeapGovernanceData,
) {
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
        topic_followee_index,
    } = governance_proto;

    let neuron_management_voting_period_seconds =
        neuron_management_voting_period_seconds.unwrap_or(48 * 60 * 60);
    let topic_followee_index = proto_to_heap_topic_followee_index(topic_followee_index);

    (
        neurons,
        topic_followee_index,
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
    topic_followee_index: HeapNeuronFollowingIndex<NeuronIdU64, TopicSigned32>,
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
        topic_followee_index: heap_topic_followee_index_to_proto(topic_followee_index),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::pb::v1::{Neuron, ProposalData};

    use maplit::{btreemap, hashmap};

    // The members are chosen to be the simplest form that's not their default().
    fn simple_governance_proto() -> GovernanceProto {
        GovernanceProto {
            neurons: btreemap! {
                1 => Neuron::default(),
            },
            proposals: btreemap! {
                1 => ProposalData::default(),
            },
            to_claim_transfers: vec![NeuronStakeTransfer::default()],
            wait_for_quiet_threshold_seconds: 2,
            economics: Some(NetworkEconomics::default()),
            latest_reward_event: Some(RewardEvent::default()),
            in_flight_commands: hashmap! { 1 => NeuronInFlightCommand::default() },
            genesis_timestamp_seconds: 3,
            node_providers: vec![NodeProvider::default()],
            default_followees: hashmap! { 1 => Followees::default() },
            short_voting_period_seconds: 4,
            neuron_management_voting_period_seconds: Some(5),
            metrics: Some(GovernanceCachedMetrics::default()),
            most_recent_monthly_node_provider_rewards: Some(
                MostRecentMonthlyNodeProviderRewards::default(),
            ),
            cached_daily_maturity_modulation_basis_points: Some(6),
            maturity_modulation_last_updated_at_timestamp_seconds: Some(7),
            spawning_neurons: Some(true),
            making_sns_proposal: Some(MakingSnsProposal::default()),
            migrations: Some(Migrations::default()),
            topic_followee_index: Default::default(),
        }
    }

    #[test]
    fn split_and_reassemble_equal() {
        let governance_proto = simple_governance_proto();

        let (heap_neurons, topic_followee_index, heap_governance_data) =
            split_governance_proto(governance_proto.clone());

        let reassembled_governance_proto =
            reassemble_governance_proto(heap_neurons, topic_followee_index, heap_governance_data);

        assert_eq!(reassembled_governance_proto, governance_proto);
    }

    #[test]
    fn test_split_and_reassemble_with_topic_follower_index() {
        let mut governance_proto = simple_governance_proto();
        governance_proto.topic_followee_index = hashmap! {
            1 => FollowersMap {
                followers_map: hashmap! {
                    2 => Followers {
                        followers: vec![NeuronId { id: 3 }],
                    },
                },
            }
        };

        let (heap_neurons, topic_followee_index, heap_governance_data) =
            split_governance_proto(governance_proto.clone());

        let reassembled_governance_proto =
            reassemble_governance_proto(heap_neurons, topic_followee_index, heap_governance_data);

        assert_eq!(reassembled_governance_proto.topic_followee_index.len(), 1);
        assert_eq!(reassembled_governance_proto, governance_proto);
    }

    #[test]
    fn split_and_reassemble_not_equal() {
        let governance_proto = GovernanceProto {
            neuron_management_voting_period_seconds: None,
            ..simple_governance_proto()
        };

        let (heap_neurons, topic_followee_index, heap_governance_data) =
            split_governance_proto(governance_proto.clone());
        let reassembled_governance_proto =
            reassemble_governance_proto(heap_neurons, topic_followee_index, heap_governance_data);

        assert_eq!(
            reassembled_governance_proto,
            GovernanceProto {
                neuron_management_voting_period_seconds: Some(48 * 60 * 60),
                ..governance_proto
            }
        );
    }

    #[test]
    fn private_voting_period_assumed_to_be_48h() {
        // split_governance_proto should return a HeapGovernanceData where the neuron_management_voting_period_seconds is 0 when given a default input
        let (_, _, heap_governance_proto) = split_governance_proto(GovernanceProto::default());
        assert_eq!(
            heap_governance_proto.neuron_management_voting_period_seconds,
            48 * 60 * 60
        );
    }
}
