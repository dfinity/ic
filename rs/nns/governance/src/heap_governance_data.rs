use crate::{
    neuron::Neuron,
    pb::v1::{
        Followees, Governance as GovernanceProto, MonthlyNodeProviderRewards, NetworkEconomics,
        NeuronStakeTransfer, NodeProvider, ProposalData, RestoreAgingSummary, RewardEvent, Topic,
        XdrConversionRate as XdrConversionRatePb,
        governance::{GovernanceCachedMetrics, NeuronInFlightCommand},
    },
};
use ic_nns_governance_api::{
    Governance as ApiGovernance, XdrConversionRate as ApiXdrConversionRate,
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
    pub xdr_conversion_rate: XdrConversionRate,
    pub restore_aging_summary: Option<RestoreAgingSummary>,
    pub topic_of_garbage_collected_proposals: HashMap<u64, Topic>,
}

/// Internal representation for `XdrConversionRatePb`.
#[derive(Clone, Debug, Default, PartialEq)]
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

impl From<Option<ApiXdrConversionRate>> for XdrConversionRate {
    fn from(src: Option<ApiXdrConversionRate>) -> Self {
        let timestamp_seconds = src.as_ref().and_then(|x| x.timestamp_seconds);
        let xdr_permyriad_per_icp = src.as_ref().and_then(|x| x.xdr_permyriad_per_icp);

        match (timestamp_seconds, xdr_permyriad_per_icp) {
            (Some(timestamp_seconds), Some(xdr_permyriad_per_icp)) => Self {
                timestamp_seconds,
                xdr_permyriad_per_icp,
            },
            _ => Self {
                timestamp_seconds: 0,
                xdr_permyriad_per_icp: 10_000,
            },
        }
    }
}

/// Converts a vector of u8s to array of length 32, which is the length needed for our rng seed.
/// If the array is the wrong size, this returns an error.
fn vec_to_array(v: Vec<u8>) -> Result<[u8; 32], String> {
    <[u8; 32]>::try_from(v).map_err(|v| format!("Expected 32 bytes, got {}", v.len()))
}

/// Initializes the governance data from the api type (init arg). Returns the neurons (separately,
/// since the neurons are stored in stable memory) and the heap governance data.
pub fn initialize_governance(
    initial_governance: ApiGovernance,
    now_seconds: u64,
) -> (BTreeMap<u64, Neuron>, HeapGovernanceData) {
    // First, destructure the ApiGovernance.
    let ApiGovernance {
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
        xdr_conversion_rate,
        restore_aging_summary,
    } = initial_governance;

    // Second, do trivial conversions.
    let proposals = proposals.into_iter().map(|(k, v)| (k, v.into())).collect();
    let to_claim_transfers = to_claim_transfers.into_iter().map(|x| x.into()).collect();
    let economics = economics.map(|x| x.into());
    let in_flight_commands = in_flight_commands
        .into_iter()
        .map(|(k, v)| (k, v.into()))
        .collect();
    let node_providers = node_providers.into_iter().map(|x| x.into()).collect();
    let default_followees = default_followees
        .into_iter()
        .map(|(k, v)| (k, v.into()))
        .collect();
    let metrics = metrics.map(|x| x.into());
    let most_recent_monthly_node_provider_rewards =
        most_recent_monthly_node_provider_rewards.map(|x| x.into());
    let restore_aging_summary = restore_aging_summary.map(|x| x.into());

    // Third, fill in the missing fields.
    let genesis_timestamp_seconds = if genesis_timestamp_seconds == 0 {
        now_seconds
    } else {
        genesis_timestamp_seconds
    };
    let latest_reward_event = Some(latest_reward_event.map(RewardEvent::from).unwrap_or(
        RewardEvent {
            actual_timestamp_seconds: now_seconds,
            day_after_genesis: 0,
            settled_proposals: vec![],
            distributed_e8s_equivalent: 0,
            total_available_e8s_equivalent: 0,
            rounds_since_last_distribution: Some(0),
            latest_round_available_e8s_equivalent: Some(0),
        },
    ));
    let neuron_management_voting_period_seconds =
        neuron_management_voting_period_seconds.unwrap_or(48 * 60 * 60);
    let xdr_conversion_rate = XdrConversionRate::from(xdr_conversion_rate);

    // Fourth, convert the neurons.
    let neurons = neurons
        .into_iter()
        .map(|(k, v)| (k, Neuron::try_from(v).expect("Invalid neuron")))
        .collect();

    // Fifth, assemble the HeapGovernanceData.
    let heap_governance_data = HeapGovernanceData {
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
        xdr_conversion_rate,
        restore_aging_summary,
        topic_of_garbage_collected_proposals: HashMap::new(),
    };

    // Finally, return the result.
    (neurons, heap_governance_data)
}

/// Splits the governance proto (from UPGRADES_MEMORY) into HeapGovernanceData and neurons, because
/// we have a dedicated struct NeuronStore owning the heap neurons.
/// Does not guarantee round-trip equivalence between this and
/// reassemble_governance_proto if the proto has fields that are None, as they might be filled in by default values.
#[allow(clippy::type_complexity)]
pub fn split_governance_proto(
    governance_proto: GovernanceProto,
) -> (HeapGovernanceData, Option<[u8; 32]>) {
    // DO NOT USE THE .. CATCH-ALL SYNTAX HERE.
    // OTHERWISE, YOU WILL ALMOST CERTAINLY EXPERIENCE
    //   **DATA LOSS**
    // FOR THE SAME REASON, DO NOT DO
    //     new_field: _,
    let GovernanceProto {
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
        xdr_conversion_rate,
        restore_aging_summary,
        topic_of_garbage_collected_proposals,
        rng_seed,
    } = governance_proto;

    let neuron_management_voting_period_seconds = neuron_management_voting_period_seconds
        .expect("Governance.neuron_management_voting_period_seconds must be specified.");

    let xdr_conversion_rate =
        xdr_conversion_rate.expect("Governance.xdr_conversion_rate must be specified.");

    let xdr_conversion_rate =
        XdrConversionRate::try_from(xdr_conversion_rate).unwrap_or_else(|err| {
            panic!("Deserialization failed for XdrConversionRate: {err}");
        });

    let rng_seed = rng_seed
        .map(|seed| vec_to_array(seed).ok())
        .and_then(|seed| seed);

    (
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

            xdr_conversion_rate,
            restore_aging_summary,
            topic_of_garbage_collected_proposals: topic_of_garbage_collected_proposals
                .into_iter()
                .map(|(k, v)| (k, Topic::try_from(v).unwrap_or(Topic::Unspecified)))
                .collect(),
        },
        rng_seed,
    )
}

/// Reassembles the GovernanceProto from the HeapGovernanceData and the neurons, so that
/// it can be serialized into UPGRADES_MEMORY.
pub fn reassemble_governance_proto(
    heap_governance_proto: HeapGovernanceData,
    rng_seed: Option<[u8; 32]>,
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

        xdr_conversion_rate,
        restore_aging_summary,
        topic_of_garbage_collected_proposals,
    } = heap_governance_proto;

    let neuron_management_voting_period_seconds = Some(neuron_management_voting_period_seconds);

    let xdr_conversion_rate = XdrConversionRatePb::from(xdr_conversion_rate);

    GovernanceProto {
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

        xdr_conversion_rate: Some(xdr_conversion_rate),
        restore_aging_summary,
        topic_of_garbage_collected_proposals: topic_of_garbage_collected_proposals
            .into_iter()
            .map(|(k, v)| (k, v as i32))
            .collect(),
        rng_seed: rng_seed.map(|seed| seed.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::pb::v1::ProposalData;

    use maplit::{btreemap, hashmap};

    // The members are chosen to be the simplest form that's not their default().
    fn simple_governance_proto() -> GovernanceProto {
        GovernanceProto {
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
            xdr_conversion_rate: Some(XdrConversionRatePb {
                timestamp_seconds: Some(1),
                xdr_permyriad_per_icp: Some(50_000),
            }),
            restore_aging_summary: None,
            topic_of_garbage_collected_proposals: hashmap! { 1 => Topic::Unspecified as i32 },
            rng_seed: Some(vec![1u8; 32]),
        }
    }

    #[test]
    fn split_and_reassemble_equal() {
        let governance_proto = simple_governance_proto();

        let (heap_governance_data, rng_seed) = split_governance_proto(governance_proto.clone());

        let reassembled_governance_proto =
            reassemble_governance_proto(heap_governance_data, rng_seed);

        assert_eq!(reassembled_governance_proto, governance_proto);
    }

    #[test]
    fn initialize_governance_fills_in_missing_fields() {
        let now_seconds = 1749068771;
        let (_, heap_governance_data) =
            initialize_governance(ApiGovernance::default(), now_seconds);

        assert_eq!(
            heap_governance_data.neuron_management_voting_period_seconds,
            48 * 60 * 60
        );
        assert_eq!(heap_governance_data.genesis_timestamp_seconds, now_seconds);
        assert_eq!(
            heap_governance_data.xdr_conversion_rate,
            XdrConversionRate {
                timestamp_seconds: 0,
                xdr_permyriad_per_icp: 10_000,
            }
        );
        assert_eq!(
            heap_governance_data.latest_reward_event,
            Some(RewardEvent {
                actual_timestamp_seconds: now_seconds,
                day_after_genesis: 0,
                settled_proposals: vec![],
                distributed_e8s_equivalent: 0,
                total_available_e8s_equivalent: 0,
                rounds_since_last_distribution: Some(0),
                latest_round_available_e8s_equivalent: Some(0),
            })
        );
    }
}
