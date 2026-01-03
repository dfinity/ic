use super::*;

use crate::pb::v1::{NetworkEconomics, SelfDescribingValue as SelfDescribingValuePb, Topic};

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
            SelfDescribingValue::Text(expected.to_string())
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
            "motion_text".to_string() => SelfDescribingValue::Text("This is a motion".to_string()),
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
                SelfDescribingValue::Text("6fyp7-3ibaa-aaaaa-aaaap-4ai".to_string()),
                SelfDescribingValue::Text("djduj-3qcaa-aaaaa-aaaap-4ai".to_string()),
            ]),
        }),
    );
}

#[test]
fn test_network_economics_to_self_describing_all_fields() {
    use SelfDescribingValue::*;

    assert_self_describing_value_is(
        NetworkEconomics {
            // We want to avoid the reject_cost_e8s from being set to the same value as the
            // neuron_minimum_stake_e8s, so we set it to a different value here.
            reject_cost_e8s: 1_000_000_000_u64,
            ..NetworkEconomics::with_default_values()
        },
        SelfDescribingValue::Map(hashmap! {
            "reject_cost_e8s".to_string() =>
                Nat(candid::Nat::from(1_000_000_000_u64)),
            "neuron_minimum_stake_e8s".to_string() =>
                Nat(candid::Nat::from(100_000_000_u64)),
            "neuron_management_fee_per_proposal_e8s".to_string() =>
                Nat(candid::Nat::from(1_000_000_u64)),
            "minimum_icp_xdr_rate".to_string() =>
                Nat(candid::Nat::from(100_u64)),
            "neuron_spawn_dissolve_delay_seconds".to_string() =>
                Nat(candid::Nat::from(604_800_u64)),
            "maximum_node_provider_rewards_e8s".to_string() =>
                Nat(candid::Nat::from(100_000_000_000_000_u64)),
            "transaction_fee_e8s".to_string() =>
                Nat(candid::Nat::from(10_000_u64)),
            "max_proposals_to_keep_per_topic".to_string() =>
                Nat(candid::Nat::from(100_u32)),
            "neurons_fund_economics".to_string() =>
                Map(hashmap! {
                    "max_theoretical_neurons_fund_participation_amount_xdr".to_string() =>
                        Text("750_000.0".to_string()),
                    "neurons_fund_matched_funding_curve_coefficients".to_string() =>
                        Map(hashmap! {
                            "contribution_threshold_xdr".to_string() =>
                                Text("75_000.0".to_string()),
                            "one_third_participation_milestone_xdr".to_string() =>
                                Text("225_000.0".to_string()),
                            "full_participation_milestone_xdr".to_string() =>
                                Text("375_000.0".to_string()),
                        }),
                    "minimum_icp_xdr_rate".to_string() =>
                        Map(hashmap! {
                            "basis_points".to_string() => Nat(candid::Nat::from(10000_u64)),
                        }),
                    "maximum_icp_xdr_rate".to_string() =>
                        Map(hashmap! {
                            "basis_points".to_string() => Nat(candid::Nat::from(1000000_u64)),
                        }),
                }),
            "voting_power_economics".to_string() =>
                Map(hashmap! {
                    "start_reducing_voting_power_after_seconds".to_string() =>
                        Nat(candid::Nat::from(15_778_800_u64)),
                    "clear_following_after_seconds".to_string() =>
                        Nat(candid::Nat::from(2_629_800_u64)),
                    "neuron_minimum_dissolve_delay_to_vote_seconds".to_string() =>
                        Nat(candid::Nat::from(15_778_800_u64)),
                }),
        }),
    );
}

#[test]
fn test_network_economics_to_self_describing_minimal() {
    use SelfDescribingValue::*;

    assert_self_describing_value_is(
        NetworkEconomics {
            neurons_fund_economics: None,
            voting_power_economics: None,
            // We want to avoid the reject_cost_e8s from being set to the same value as the
            // neuron_minimum_stake_e8s, so we set it to a different value here.
            reject_cost_e8s: 1_000_000_000_u64,
            ..NetworkEconomics::with_default_values()
        },
        Map(hashmap! {
            "reject_cost_e8s".to_string() =>
                Nat(candid::Nat::from(1_000_000_000_u64)),
            "neuron_minimum_stake_e8s".to_string() =>
                Nat(candid::Nat::from(100_000_000_u64)),
            "neuron_management_fee_per_proposal_e8s".to_string() =>
                Nat(candid::Nat::from(1_000_000_u64)),
            "minimum_icp_xdr_rate".to_string() =>
                Nat(candid::Nat::from(100_u64)),
            "neuron_spawn_dissolve_delay_seconds".to_string() =>
                Nat(candid::Nat::from(604_800_u64)),
            "maximum_node_provider_rewards_e8s".to_string() =>
                Nat(candid::Nat::from(100_000_000_000_000_u64)),
            "transaction_fee_e8s".to_string() =>
                Nat(candid::Nat::from(10_000_u64)),
            "max_proposals_to_keep_per_topic".to_string() =>
                Nat(candid::Nat::from(100_u32)),
            "neurons_fund_economics".to_string() =>
                Null,
            "voting_power_economics".to_string() =>
                Null,
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
            "name".to_string() => SelfDescribingValue::Text("test".to_string()),
            "count".to_string() => SelfDescribingValue::Nat(candid::Nat::from(42u64)),
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
        assert_self_describing_value_is(
            variant,
            SelfDescribingValue::Text(expected_name.to_string()),
        );
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
        SelfDescribingValue::Map(hashmap! {
            "Empty".to_string() => SelfDescribingValue::Null,
        }),
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
