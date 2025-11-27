use super::*;

use ic_base_types::PrincipalId;
use ic_nns_governance_api::SelfDescribingValue as ApiValue;
use maplit::hashmap;

#[track_caller]
fn assert_self_describing_value_is(
    action: impl LocallyDescribableProposalAction,
    expected: ApiValue,
) {
    let SelfDescribingProposalAction { value, .. } = action.to_self_describing_action();
    // Use ApiValue for testing because: (1) it should only be used for API responses, and (2) it's
    // more straightforward to construct (while the protobuf type only exists for storage).
    let value = ApiValue::from(value.unwrap());
    assert_eq!(value, expected);
}

#[test]
fn test_motion_to_self_describing() {
    let motion = Motion {
        motion_text: "This is a motion".to_string(),
    };
    assert_self_describing_value_is(
        motion,
        ApiValue::Map(hashmap! {
            "motion_text".to_string() => ApiValue::Text("This is a motion".to_string()),
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
        ApiValue::Map(hashmap! {
            "principals".to_string() => ApiValue::Array(vec![
                ApiValue::Text("6fyp7-3ibaa-aaaaa-aaaap-4ai".to_string()),
                ApiValue::Text("djduj-3qcaa-aaaaa-aaaap-4ai".to_string()),
            ]),
        }),
    );
}
