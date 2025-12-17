use super::*;

use crate::pb::v1::{SelfDescribingValue as SelfDescribingValuePb, Topic};

use ic_base_types::PrincipalId;
use ic_nns_governance_api::SelfDescribingValue;
use ic_nns_governance_derive_self_describing::SelfDescribing;
use maplit::hashmap;

#[track_caller]
fn assert_self_describing_value_is(
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
    assert_self_describing_value_is(
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
    assert_self_describing_value_is(
        approve_genesis_kyc,
        SelfDescribingValue::Map(hashmap! {
            "principals".to_string() => SelfDescribingValue::Array(vec![
                SelfDescribingValue::Text("6fyp7-3ibaa-aaaaa-aaaap-4ai".to_string()),
                SelfDescribingValue::Text("djduj-3qcaa-aaaaa-aaaap-4ai".to_string()),
            ]),
        }),
    );
}

// Tests for the SelfDescribing derive macro

/// Test struct with named fields.
#[derive(SelfDescribing)]
struct TestNamedStruct {
    name: String,
    count: u64,
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

#[test]
fn test_derive_named_struct() {
    let test_struct = TestNamedStruct {
        name: "test".to_string(),
        count: 42,
    };
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(test_struct));
    assert_eq!(
        value,
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
        let value = SelfDescribingValue::from(SelfDescribingValuePb::from(variant));
        assert_eq!(value, SelfDescribingValue::Text(expected_name.to_string()));
    }
}

#[test]
fn test_derive_single_tuple_enum() {
    let variant = TestSingleTupleEnum::First(InnerValue { id: 123 });
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(variant));
    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "First".to_string() => SelfDescribingValue::Map(hashmap! {
                "id".to_string() => SelfDescribingValue::Nat(candid::Nat::from(123u64)),
            }),
        }),
    );
}

#[test]
fn test_derive_mixed_enum_unit_variant() {
    let variant = TestMixedEnum::Empty;
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(variant));
    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "Empty".to_string() => SelfDescribingValue::Array(vec![]),
        }),
    );
}

#[test]
fn test_derive_mixed_enum_tuple_variant() {
    let variant = TestMixedEnum::WithValue(InnerValue { id: 456 });
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(variant));
    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "WithValue".to_string() => SelfDescribingValue::Map(hashmap! {
                "id".to_string() => SelfDescribingValue::Nat(candid::Nat::from(456u64)),
            }),
        }),
    );
}
