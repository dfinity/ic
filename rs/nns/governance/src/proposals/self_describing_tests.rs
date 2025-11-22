use super::*;

use ic_nns_governance_api::Value as ApiValue;
use maplit::hashmap;

fn assert_self_describing_value_is(
    action: impl LocallyDescribableProposalAction,
    expected: ApiValue,
) {
    let SelfDescribingProposalAction { value, .. } = action.to_self_describing();
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
