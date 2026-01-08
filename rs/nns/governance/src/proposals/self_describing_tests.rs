use super::*;

use crate::{
    governance::test_data::{CREATE_SERVICE_NERVOUS_SYSTEM, IMAGE_1, IMAGE_2},
    pb::v1::{NetworkEconomics, SelfDescribingValue as SelfDescribingValuePb, Topic},
};

use ic_base_types::PrincipalId;
use ic_nns_governance_api::SelfDescribingValue;
use ic_nns_governance_derive_self_describing::SelfDescribing;
use maplit::hashmap;

#[track_caller]
fn assert_proposal_action_self_describing_value_is(
    action: impl LocallyDescribableProposalAction,
    expected: SelfDescribingValue,
) {
    let SelfDescribingProposalAction { value, .. } = action.to_self_describing_action();
    // Use SelfDescribingValue for testing because: (1) it should only be used for API responses, and (2) it's
    // more straightforward to construct (while the protobuf type only exists for storage).
    let value = SelfDescribingValue::from(value.unwrap());
    assert_eq!(value, expected);
}

#[test]
fn test_prost_enum_to_self_describing() {
    let test_cases = vec![
        (Topic::Unspecified as i32, "Unspecified"),
        (Topic::Governance as i32, "Governance"),
        (100_i32, "UNKNOWN_TOPIC_100"),
    ];
    for (value, expected) in test_cases {
        let prost_enum = SelfDescribingProstEnum::<Topic>::new(value);
        assert_eq!(
            SelfDescribingValue::from(SelfDescribingValuePb::from(prost_enum)),
            SelfDescribingValue::from(expected)
        );
    }
}

#[test]
fn test_motion_to_self_describing() {
    let motion = Motion {
        motion_text: "This is a motion".to_string(),
    };
    assert_proposal_action_self_describing_value_is(
        motion,
        SelfDescribingValue::Map(hashmap! {
            "motion_text".to_string() => SelfDescribingValue::from("This is a motion"),
        }),
    );
}

#[test]
fn test_approve_genesis_kyc_to_self_describing() {
    let approve_genesis_kyc = ApproveGenesisKyc {
        principals: vec![
            PrincipalId::new_user_test_id(1),
            PrincipalId::new_user_test_id(2),
        ],
    };
    assert_proposal_action_self_describing_value_is(
        approve_genesis_kyc,
        SelfDescribingValue::Map(hashmap! {
            "principals".to_string() => SelfDescribingValue::Array(vec![
                SelfDescribingValue::from("6fyp7-3ibaa-aaaaa-aaaap-4ai"),
                SelfDescribingValue::from("djduj-3qcaa-aaaaa-aaaap-4ai"),
            ]),
        }),
    );
}

#[test]
fn test_network_economics_to_self_describing_all_fields() {
    assert_self_describing_value_is(
        NetworkEconomics {
            // We want to avoid the reject_cost_e8s from being set to the same value as the
            // neuron_minimum_stake_e8s, so we set it to a different value here.
            reject_cost_e8s: 1_000_000_000_u64,
            ..NetworkEconomics::with_default_values()
        },
        SelfDescribingValue::Map(hashmap! {
            "reject_cost_e8s".to_string() =>
                SelfDescribingValue::from(1_000_000_000_u64),
            "neuron_minimum_stake_e8s".to_string() =>
                SelfDescribingValue::from(100_000_000_u64),
            "neuron_management_fee_per_proposal_e8s".to_string() =>
                SelfDescribingValue::from(1_000_000_u64),
            "minimum_icp_xdr_rate".to_string() =>
                SelfDescribingValue::from(100_u64),
            "neuron_spawn_dissolve_delay_seconds".to_string() =>
                SelfDescribingValue::from(604_800_u64),
            "maximum_node_provider_rewards_e8s".to_string() =>
                SelfDescribingValue::from(100_000_000_000_000_u64),
            "transaction_fee_e8s".to_string() =>
                SelfDescribingValue::from(10_000_u64),
            "max_proposals_to_keep_per_topic".to_string() =>
                SelfDescribingValue::from(100_u32),
            "neurons_fund_economics".to_string() =>
                SelfDescribingValue::Map(hashmap! {
                    "max_theoretical_neurons_fund_participation_amount_xdr".to_string() =>
                        SelfDescribingValue::from("750_000.0"),
                    "neurons_fund_matched_funding_curve_coefficients".to_string() =>
                        SelfDescribingValue::Map(hashmap! {
                            "contribution_threshold_xdr".to_string() =>
                                SelfDescribingValue::from("75_000.0"),
                            "one_third_participation_milestone_xdr".to_string() =>
                                SelfDescribingValue::from("225_000.0"),
                            "full_participation_milestone_xdr".to_string() =>
                                SelfDescribingValue::from("375_000.0"),
                        }),
                    "minimum_icp_xdr_rate".to_string() =>
                        SelfDescribingValue::Map(hashmap! {
                            "basis_points".to_string() => SelfDescribingValue::from(10000_u64),
                        }),
                    "maximum_icp_xdr_rate".to_string() =>
                        SelfDescribingValue::Map(hashmap! {
                            "basis_points".to_string() => SelfDescribingValue::from(1000000_u64),
                        }),
                }),
            "voting_power_economics".to_string() =>
                SelfDescribingValue::Map(hashmap! {
                    "start_reducing_voting_power_after_seconds".to_string() =>
                        SelfDescribingValue::from(15_778_800_u64),
                    "clear_following_after_seconds".to_string() =>
                        SelfDescribingValue::from(2_629_800_u64),
                    "neuron_minimum_dissolve_delay_to_vote_seconds".to_string() =>
                        SelfDescribingValue::from(15_778_800_u64),
                }),
        }),
    );
}

#[test]
fn test_network_economics_to_self_describing_minimal() {
    assert_self_describing_value_is(
        NetworkEconomics {
            neurons_fund_economics: None,
            voting_power_economics: None,
            // We want to avoid the reject_cost_e8s from being set to the same value as the
            // neuron_minimum_stake_e8s, so we set it to a different value here.
            reject_cost_e8s: 1_000_000_000_u64,
            ..NetworkEconomics::with_default_values()
        },
        SelfDescribingValue::Map(hashmap! {
            "reject_cost_e8s".to_string() =>
                SelfDescribingValue::from(1_000_000_000_u64),
            "neuron_minimum_stake_e8s".to_string() =>
                SelfDescribingValue::from(100_000_000_u64),
            "neuron_management_fee_per_proposal_e8s".to_string() =>
                SelfDescribingValue::from(1_000_000_u64),
            "minimum_icp_xdr_rate".to_string() =>
                SelfDescribingValue::from(100_u64),
            "neuron_spawn_dissolve_delay_seconds".to_string() =>
                SelfDescribingValue::from(604_800_u64),
            "maximum_node_provider_rewards_e8s".to_string() =>
                SelfDescribingValue::from(100_000_000_000_000_u64),
            "transaction_fee_e8s".to_string() =>
                SelfDescribingValue::from(10_000_u64),
            "max_proposals_to_keep_per_topic".to_string() =>
                SelfDescribingValue::from(100_u32),
            "neurons_fund_economics".to_string() =>
                SelfDescribingValue::Null,
            "voting_power_economics".to_string() =>
                SelfDescribingValue::Null,
        }),
    );
}

#[test]
fn test_create_service_nervous_system_to_self_describing() {
    assert_proposal_action_self_describing_value_is(
        CREATE_SERVICE_NERVOUS_SYSTEM.clone(),
        SelfDescribingValue::Map(hashmap! {
            "name".to_string() => SelfDescribingValue::from("Hello, world!"),
            "description".to_string() => SelfDescribingValue::from("Best app that you ever did saw."),
            "url".to_string() => SelfDescribingValue::from("https://best.app"),
            "logo".to_string() => SelfDescribingValue::Map(hashmap! {
                "base64_encoding".to_string() => SelfDescribingValue::from(IMAGE_1),
            }),
            "fallback_controller_principal_ids".to_string() => SelfDescribingValue::Array(vec![
                SelfDescribingValue::from("iakpb-r4pky-cqaaa-aaaap-4ai"),
            ]),
            "dapp_canisters".to_string() => SelfDescribingValue::Array(vec![
                SelfDescribingValue::from("uc7f6-kaaaa-aaaaq-qaaaa-cai"),
            ]),
            "initial_token_distribution".to_string() => SelfDescribingValue::Map(hashmap! {
                "developer_distribution".to_string() => SelfDescribingValue::Map(hashmap! {
                    "developer_neurons".to_string() => SelfDescribingValue::Array(vec![
                        SelfDescribingValue::Map(hashmap! {
                            "controller".to_string() => SelfDescribingValue::from("qarve-vpdvu-gaaaa-aaaap-4ai"),
                            "dissolve_delay".to_string() => SelfDescribingValue::Map(hashmap! {
                                "seconds".to_string() => SelfDescribingValue::from(15_778_800_u64),
                            }),
                            "memo".to_string() => SelfDescribingValue::from(763535_u64),
                            "stake".to_string() => SelfDescribingValue::Map(hashmap! {
                                "e8s".to_string() => SelfDescribingValue::from(756575_u64),
                            }),
                            "vesting_period".to_string() => SelfDescribingValue::Map(hashmap! {
                                "seconds".to_string() => SelfDescribingValue::from(0_u64),
                            }),
                        }),
                    ]),
                }),
                "treasury_distribution".to_string() => SelfDescribingValue::Map(hashmap! {
                    "total".to_string() => SelfDescribingValue::Map(hashmap! {
                        "e8s".to_string() => SelfDescribingValue::from(307064_u64),
                    }),
                }),
                "swap_distribution".to_string() => SelfDescribingValue::Map(hashmap! {
                    "total".to_string() => SelfDescribingValue::Map(hashmap! {
                        "e8s".to_string() => SelfDescribingValue::from(1_840_880_000_u64),
                    }),
                }),
            }),
            "ledger_parameters".to_string() => SelfDescribingValue::Map(hashmap! {
                "transaction_fee".to_string() => SelfDescribingValue::Map(hashmap! {
                    "e8s".to_string() => SelfDescribingValue::from(11143_u64),
                }),
                "token_name".to_string() => SelfDescribingValue::from("Most valuable SNS of all time."),
                "token_symbol".to_string() => SelfDescribingValue::from("Kanye"),
                "token_logo".to_string() => SelfDescribingValue::Map(hashmap! {
                    "base64_encoding".to_string() => SelfDescribingValue::from(IMAGE_2),
                }),
            }),
            "governance_parameters".to_string() => SelfDescribingValue::Map(hashmap! {
                "proposal_rejection_fee".to_string() => SelfDescribingValue::Map(hashmap! {
                    "e8s".to_string() => SelfDescribingValue::from(372250_u64),
                }),
                "proposal_initial_voting_period".to_string() => SelfDescribingValue::Map(hashmap! {
                    "seconds".to_string() => SelfDescribingValue::from(709_499_u64),
                }),
                "proposal_wait_for_quiet_deadline_increase".to_string() => SelfDescribingValue::Map(hashmap! {
                    "seconds".to_string() => SelfDescribingValue::from(75_891_u64),
                }),
                "neuron_minimum_stake".to_string() => SelfDescribingValue::Map(hashmap! {
                    "e8s".to_string() => SelfDescribingValue::from(250_000_u64),
                }),
                "neuron_minimum_dissolve_delay_to_vote".to_string() => SelfDescribingValue::Map(hashmap! {
                    "seconds".to_string() => SelfDescribingValue::from(482538_u64),
                }),
                "neuron_maximum_dissolve_delay".to_string() => SelfDescribingValue::Map(hashmap! {
                    "seconds".to_string() => SelfDescribingValue::from(31_557_600_u64),
                }),
                "neuron_maximum_dissolve_delay_bonus".to_string() => SelfDescribingValue::Map(hashmap! {
                    "basis_points".to_string() => SelfDescribingValue::from(1800_u64),
                }),
                "neuron_maximum_age_for_age_bonus".to_string() => SelfDescribingValue::Map(hashmap! {
                    "seconds".to_string() => SelfDescribingValue::from(740908_u64),
                }),
                "neuron_maximum_age_bonus".to_string() => SelfDescribingValue::Map(hashmap! {
                    "basis_points".to_string() => SelfDescribingValue::from(5400_u64),
                }),
                "voting_reward_parameters".to_string() => SelfDescribingValue::Map(hashmap! {
                    "initial_reward_rate".to_string() => SelfDescribingValue::Map(hashmap! {
                        "basis_points".to_string() => SelfDescribingValue::from(2592_u64),
                    }),
                    "final_reward_rate".to_string() => SelfDescribingValue::Map(hashmap! {
                        "basis_points".to_string() => SelfDescribingValue::from(740_u64),
                    }),
                    "reward_rate_transition_duration".to_string() => SelfDescribingValue::Map(hashmap! {
                        "seconds".to_string() => SelfDescribingValue::from(378025_u64),
                    }),
                }),
            }),
            "swap_parameters".to_string() => SelfDescribingValue::Map(hashmap! {
                "minimum_participants".to_string() => SelfDescribingValue::from(50_u64),
                "minimum_direct_participation_icp".to_string() => SelfDescribingValue::Map(hashmap! {
                    "e8s".to_string() => SelfDescribingValue::from(6_200_000_000_u64),
                }),
                "maximum_direct_participation_icp".to_string() => SelfDescribingValue::Map(hashmap! {
                    "e8s".to_string() => SelfDescribingValue::from(18_900_000_000_u64),
                }),
                "minimum_participant_icp".to_string() => SelfDescribingValue::Map(hashmap! {
                    "e8s".to_string() => SelfDescribingValue::from(100_000_000_u64),
                }),
                "maximum_participant_icp".to_string() => SelfDescribingValue::Map(hashmap! {
                    "e8s".to_string() => SelfDescribingValue::from(10_000_000_000_u64),
                }),
                "neuron_basket_construction_parameters".to_string() => SelfDescribingValue::Map(hashmap! {
                    "count".to_string() => SelfDescribingValue::from(2_u64),
                    "dissolve_delay_interval".to_string() => SelfDescribingValue::Map(hashmap! {
                        "seconds".to_string() => SelfDescribingValue::from(10_001_u64),
                    }),
                }),
                "confirmation_text".to_string() => SelfDescribingValue::from("Confirm you are a human"),
                "restricted_countries".to_string() => SelfDescribingValue::Map(hashmap! {
                    "iso_codes".to_string() => SelfDescribingValue::Array(vec![SelfDescribingValue::from("CH")]),
                }),
                "start_time".to_string() => SelfDescribingValue::Map(hashmap! {
                    "seconds_after_utc_midnight".to_string() => SelfDescribingValue::from(0_u64),
                }),
                "duration".to_string() => SelfDescribingValue::Map(hashmap! {
                    "seconds".to_string() => SelfDescribingValue::from(604_800_u64),
                }),
                "neurons_fund_participation".to_string() => SelfDescribingValue::from(0_u64),
                "minimum_icp".to_string() => SelfDescribingValue::Null,
                "maximum_icp".to_string() => SelfDescribingValue::Null,
                "neurons_fund_investment_icp".to_string() => SelfDescribingValue::Null,
            }),
        }),
    );
}

// Tests for the SelfDescribing derive macro

/// Test struct with named fields.
#[derive(SelfDescribing)]
struct TestNamedStruct {
    name: String,
    count: Option<u64>,
}

/// Test enum with all unit variants.
#[derive(SelfDescribing)]
enum TestAllUnitEnum {
    VariantA,
    VariantB,
    VariantC,
}

/// Test wrapper struct for single-tuple enum variant testing.
#[derive(SelfDescribing)]
struct InnerValue {
    id: u64,
}

/// Test enum with single-tuple variants.
#[derive(SelfDescribing)]
#[allow(dead_code)]
enum TestSingleTupleEnum {
    First(InnerValue),
    Second(InnerValue),
}

/// Test enum with mixed variants (unit and single-tuple).
#[derive(SelfDescribing)]
enum TestMixedEnum {
    Empty,
    WithValue(InnerValue),
}

#[track_caller]
fn assert_self_describing_value_is<T>(value: T, expected: SelfDescribingValue)
where
    crate::pb::v1::SelfDescribingValue: From<T>,
{
    assert_eq!(
        SelfDescribingValue::from(SelfDescribingValuePb::from(value)),
        expected
    );
}

#[test]
fn test_derive_named_struct() {
    assert_self_describing_value_is(
        TestNamedStruct {
            name: "test".to_string(),
            count: Some(42),
        },
        SelfDescribingValue::Map(hashmap! {
            "name".to_string() => SelfDescribingValue::from("test"),
            "count".to_string() => SelfDescribingValue::from(42_u64),
        }),
    );
}

#[test]
fn test_derive_all_unit_enum() {
    for (variant, expected_name) in [
        (TestAllUnitEnum::VariantA, "VariantA"),
        (TestAllUnitEnum::VariantB, "VariantB"),
        (TestAllUnitEnum::VariantC, "VariantC"),
    ] {
        assert_self_describing_value_is(variant, SelfDescribingValue::from(expected_name));
    }
}

#[test]
fn test_derive_single_tuple_enum() {
    assert_self_describing_value_is(
        TestSingleTupleEnum::First(InnerValue { id: 123 }),
        SelfDescribingValue::Map(hashmap! {
            "First".to_string() => SelfDescribingValue::Map(hashmap! {
                "id".to_string() => SelfDescribingValue::Nat(candid::Nat::from(123_u64)),
            }),
        }),
    );
}

#[test]
fn test_derive_mixed_enum_unit_variant() {
    assert_self_describing_value_is(
        TestMixedEnum::Empty,
        SelfDescribingValue::Text("Empty".to_string()),
    );
}

#[test]
fn test_derive_mixed_enum_tuple_variant() {
    assert_self_describing_value_is(
        TestMixedEnum::WithValue(InnerValue { id: 456 }),
        SelfDescribingValue::Map(hashmap! {
            "WithValue".to_string() => SelfDescribingValue::Map(hashmap! {
                "id".to_string() => SelfDescribingValue::Nat(candid::Nat::from(456_u64)),
            }),
        }),
    );
}
