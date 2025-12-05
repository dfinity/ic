use super::*;
use crate::proposals::self_describing::LocallyDescribableProposalAction;
use ic_nns_governance_api::SelfDescribingValue;
use maplit::hashmap;

#[test]
fn test_network_economics_all_fields() {
    let network_economics = NetworkEconomics::with_default_values();

    let self_describing_value =
        SelfDescribingValue::from(network_economics.to_self_describing_value());

    assert_eq!(
        self_describing_value,
        SelfDescribingValue::Map(hashmap! {
            "reject_cost_e8s".to_string() =>
                SelfDescribingValue::Nat(candid::Nat::from(100_000_000u64)),
            "neuron_minimum_stake_e8s".to_string() =>
                SelfDescribingValue::Nat(candid::Nat::from(100_000_000u64)),
            "neuron_management_fee_per_proposal_e8s".to_string() =>
                SelfDescribingValue::Nat(candid::Nat::from(1_000_000u64)),
            "minimum_icp_xdr_rate".to_string() =>
                SelfDescribingValue::Nat(candid::Nat::from(100u64)),
            "neuron_spawn_dissolve_delay_seconds".to_string() =>
                SelfDescribingValue::Nat(candid::Nat::from(604_800u64)),
            "maximum_node_provider_rewards_e8s".to_string() =>
                SelfDescribingValue::Nat(candid::Nat::from(100_000_000_000_000u64)),
            "transaction_fee_e8s".to_string() =>
                SelfDescribingValue::Nat(candid::Nat::from(10_000u64)),
            "max_proposals_to_keep_per_topic".to_string() =>
                SelfDescribingValue::Nat(candid::Nat::from(100u32)),
            "neurons_fund_economics".to_string() =>
                SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Map(hashmap! {
                        "max_theoretical_neurons_fund_participation_amount_xdr".to_string() =>
                            SelfDescribingValue::Array(vec![
                                SelfDescribingValue::Map(hashmap! {
                                    "human_readable".to_string() =>
                                        SelfDescribingValue::Array(vec![SelfDescribingValue::Text("750_000.0".to_string())]),
                                }),
                            ]),
                        "neurons_fund_matched_funding_curve_coefficients".to_string() =>
                            SelfDescribingValue::Array(vec![
                                SelfDescribingValue::Map(hashmap! {
                                    "contribution_threshold_xdr".to_string() =>
                                        SelfDescribingValue::Array(vec![
                                            SelfDescribingValue::Map(hashmap! {
                                                "human_readable".to_string() =>
                                                    SelfDescribingValue::Array(vec![SelfDescribingValue::Text("75_000.0".to_string())]),
                                            }),
                                        ]),
                                    "one_third_participation_milestone_xdr".to_string() =>
                                        SelfDescribingValue::Array(vec![
                                            SelfDescribingValue::Map(hashmap! {
                                                "human_readable".to_string() =>
                                                    SelfDescribingValue::Array(vec![SelfDescribingValue::Text("225_000.0".to_string())]),
                                            }),
                                        ]),
                                    "full_participation_milestone_xdr".to_string() =>
                                        SelfDescribingValue::Array(vec![
                                            SelfDescribingValue::Map(hashmap! {
                                                "human_readable".to_string() =>
                                                    SelfDescribingValue::Array(vec![SelfDescribingValue::Text("375_000.0".to_string())]),
                                            }),
                                        ]),
                                }),
                            ]),
                        "minimum_icp_xdr_rate".to_string() =>
                            SelfDescribingValue::Array(vec![
                                SelfDescribingValue::Map(hashmap! {
                                    "basis_points".to_string() =>
                                        SelfDescribingValue::Array(vec![SelfDescribingValue::Nat(candid::Nat::from(10_000u64))]),
                                }),
                            ]),
                        "maximum_icp_xdr_rate".to_string() =>
                            SelfDescribingValue::Array(vec![
                                SelfDescribingValue::Map(hashmap! {
                                    "basis_points".to_string() =>
                                        SelfDescribingValue::Array(vec![SelfDescribingValue::Nat(candid::Nat::from(1_000_000u64))]),
                                }),
                            ]),
                    }),
                ]),
            "voting_power_economics".to_string() =>
                SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Map(hashmap! {
                        "start_reducing_voting_power_after_seconds".to_string() =>
                            SelfDescribingValue::Array(vec![SelfDescribingValue::Nat(candid::Nat::from(15_778_800u64))]),
                        "clear_following_after_seconds".to_string() =>
                            SelfDescribingValue::Array(vec![SelfDescribingValue::Nat(candid::Nat::from(2_629_800u64))]),
                        "neuron_minimum_dissolve_delay_to_vote_seconds".to_string() =>
                            SelfDescribingValue::Array(vec![SelfDescribingValue::Nat(candid::Nat::from(15_778_800u64))]),
                    }),
                ]),
        })
    );
}

#[test]
fn test_network_economics_minimal() {
    let network_economics = NetworkEconomics {
        neurons_fund_economics: None,
        voting_power_economics: None,
        ..NetworkEconomics::with_default_values()
    };

    let self_describing_value =
        SelfDescribingValue::from(network_economics.to_self_describing_value());

    assert_eq!(
        self_describing_value,
        SelfDescribingValue::Map(hashmap! {
            "reject_cost_e8s".to_string() =>
                SelfDescribingValue::Nat(candid::Nat::from(100_000_000u64)),
            "neuron_minimum_stake_e8s".to_string() =>
                SelfDescribingValue::Nat(candid::Nat::from(100_000_000u64)),
            "neuron_management_fee_per_proposal_e8s".to_string() =>
                SelfDescribingValue::Nat(candid::Nat::from(1_000_000u64)),
            "minimum_icp_xdr_rate".to_string() =>
                SelfDescribingValue::Nat(candid::Nat::from(100u64)),
            "neuron_spawn_dissolve_delay_seconds".to_string() =>
                SelfDescribingValue::Nat(candid::Nat::from(604_800u64)),
            "maximum_node_provider_rewards_e8s".to_string() =>
                SelfDescribingValue::Nat(candid::Nat::from(100_000_000_000_000u64)),
            "transaction_fee_e8s".to_string() =>
                SelfDescribingValue::Nat(candid::Nat::from(10_000u64)),
            "max_proposals_to_keep_per_topic".to_string() =>
                SelfDescribingValue::Nat(candid::Nat::from(100u32)),
            "neurons_fund_economics".to_string() =>
                SelfDescribingValue::Array(vec![]),
            "voting_power_economics".to_string() =>
                SelfDescribingValue::Array(vec![]),
        })
    );
}
