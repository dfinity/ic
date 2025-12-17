use super::*;

use crate::pb::v1::{SelfDescribingValue as SelfDescribingValuePb, Topic};

use ic_base_types::PrincipalId;
use ic_nns_governance_api::SelfDescribingValue;
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
