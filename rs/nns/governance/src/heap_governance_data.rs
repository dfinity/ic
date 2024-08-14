use crate::pb::v1::{
    governance::{
        FollowersMap, GovernanceCachedMetrics, MakingSnsProposal, Migrations, NeuronInFlightCommand,
    },
    neuron::Followees,
    Governance as GovernanceProto, MonthlyNodeProviderRewards, NetworkEconomics, Neuron,
    NeuronStakeTransfer, NodeProvider, ProposalData, RestoreAgingSummary, RewardEvent,
    XdrConversionRate as XdrConversionRatePb,
};
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
    pub most_recent_monthly_node_provider_rewards: Option<MonthlyNodeProviderRewards>,
    pub cached_daily_maturity_modulation_basis_points: Option<i32>,
    pub maturity_modulation_last_updated_at_timestamp_seconds: Option<u64>,
    pub spawning_neurons: Option<bool>,
    pub making_sns_proposal: Option<MakingSnsProposal>,
    pub migrations: Option<Migrations>,
    pub xdr_conversion_rate: XdrConversionRate,
    pub restore_aging_summary: Option<RestoreAgingSummary>,
}

/// Internal representation for `XdrConversionRatePb`.
#[derive(Clone, Debug, Default)]
pub struct XdrConversionRate {
    /// Time at which this rate has been fetched.
    pub timestamp_seconds: u64,

    /// Number of 1/10,000ths of XDR that 1 ICP is worth.
    pub xdr_permyriad_per_icp: u64,
}

impl TryFrom<XdrConversionRatePb> for XdrConversionRate {
    type Error = String;

    fn try_from(src: XdrConversionRatePb) -> Result<Self, Self::Error> {
        let XdrConversionRatePb {
            timestamp_seconds,
            xdr_permyriad_per_icp,
        } = src;

        let Some(timestamp_seconds) = timestamp_seconds else {
            return Err("XdrConversionRate.timestamp_seconds must be specified.".to_string());
        };

        let Some(xdr_permyriad_per_icp) = xdr_permyriad_per_icp else {
            return Err("XdrConversionRate.xdr_permyriad_per_icp must be specified.".to_string());
        };

        Ok(Self {
            timestamp_seconds,
            xdr_permyriad_per_icp,
        })
    }
}

impl From<XdrConversionRate> for XdrConversionRatePb {
    fn from(src: XdrConversionRate) -> Self {
        let XdrConversionRate {
            timestamp_seconds,
            xdr_permyriad_per_icp,
        } = src;

        Self {
            timestamp_seconds: Some(timestamp_seconds),
            xdr_permyriad_per_icp: Some(xdr_permyriad_per_icp),
        }
    }
}

/// Splits the governance proto (from UPGRADES_MEMORY) into HeapGovernanceData and neurons, because
/// we have a dedicated struct NeuronStore owning the heap neurons.
/// Does not guarantee round-trip equivalence between this and
/// reassemble_governance_proto if the proto has fields that are None, as they might be filled in by default values.
pub fn split_governance_proto(
    governance_proto: GovernanceProto,
) -> (
    BTreeMap<u64, Neuron>,
    HashMap<i32, FollowersMap>,
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
        xdr_conversion_rate,
        restore_aging_summary,
    } = governance_proto;

    let neuron_management_voting_period_seconds =
        neuron_management_voting_period_seconds.unwrap_or(48 * 60 * 60);

    let xdr_conversion_rate =
        xdr_conversion_rate.expect("Governance.xdr_conversion_rate must be specified.");

    let xdr_conversion_rate =
        XdrConversionRate::try_from(xdr_conversion_rate).unwrap_or_else(|err| {
            panic!("Deserialization failed for XdrConversionRate: {}", err);
        });

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
            xdr_conversion_rate,
            restore_aging_summary,
        },
    )
}

/// Reassembles the GovernanceProto from the HeapGovernanceData and the neurons, so that
/// it can be serialized into UPGRADES_MEMORY.
pub fn reassemble_governance_proto(
    neurons: BTreeMap<u64, Neuron>,
    topic_followee_index: HashMap<i32, FollowersMap>,
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
        xdr_conversion_rate,
        restore_aging_summary,
    } = heap_governance_proto;

    let neuron_management_voting_period_seconds = Some(neuron_management_voting_period_seconds);

    let xdr_conversion_rate = XdrConversionRatePb::from(xdr_conversion_rate);

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
        topic_followee_index,
        xdr_conversion_rate: Some(xdr_conversion_rate),
        restore_aging_summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::pb::v1::{governance::followers_map::Followers, Neuron, ProposalData};

    use ic_nns_common::pb::v1::NeuronId;
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
            most_recent_monthly_node_provider_rewards: Some(MonthlyNodeProviderRewards::default()),
            cached_daily_maturity_modulation_basis_points: Some(6),
            maturity_modulation_last_updated_at_timestamp_seconds: Some(7),
            spawning_neurons: Some(true),
            making_sns_proposal: Some(MakingSnsProposal::default()),
            migrations: Some(Migrations::default()),
            topic_followee_index: hashmap! {
                1 => FollowersMap {
                    followers_map: hashmap! {
                        2 => Followers {
                            followers: vec![NeuronId { id: 3 }],
                        },
                    },
                }
            },
            xdr_conversion_rate: Some(XdrConversionRatePb {
                timestamp_seconds: Some(1),
                xdr_permyriad_per_icp: Some(50_000),
            }),
            restore_aging_summary: None,
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
        let governance_proto = GovernanceProto {
            xdr_conversion_rate: Some(XdrConversionRatePb::with_default_values()),
            ..GovernanceProto::default()
        };
        // split_governance_proto should return a HeapGovernanceData where the neuron_management_voting_period_seconds is 0 when given a default input
        let (_, _, heap_governance_proto) = split_governance_proto(governance_proto);
        assert_eq!(
            heap_governance_proto.neuron_management_voting_period_seconds,
            48 * 60 * 60
        );
    }
}
