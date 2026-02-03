use crate::{
    pb::v1::TakeCanisterSnapshot, proposals::self_describing::LocallyDescribableProposalAction,
};
use ic_base_types::PrincipalId;
use ic_nns_governance_api::SelfDescribingValue;
use maplit::hashmap;

#[test]
fn test_take_canister_snapshot_to_self_describing() {
    let canister_id = PrincipalId::new_user_test_id(123);
    let replace_snapshot = vec![1, 2, 3, 4];

    let take_snapshot = TakeCanisterSnapshot {
        canister_id: Some(canister_id),
        replace_snapshot: Some(replace_snapshot.clone()),
    };

    let action = take_snapshot.to_self_describing_action();
    let value = SelfDescribingValue::from(action.value.unwrap());

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "canister_id".to_string() => SelfDescribingValue::from(canister_id),
            "replace_snapshot".to_string() => SelfDescribingValue::from(replace_snapshot),
        })
    );
}

#[test]
fn test_take_canister_snapshot_to_self_describing_without_replace_snapshot() {
    let canister_id = PrincipalId::new_user_test_id(456);

    let take_snapshot = TakeCanisterSnapshot {
        canister_id: Some(canister_id),
        replace_snapshot: None,
    };

    let action = take_snapshot.to_self_describing_action();
    let value = SelfDescribingValue::from(action.value.unwrap());

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "canister_id".to_string() => SelfDescribingValue::from(canister_id),
            "replace_snapshot".to_string() => SelfDescribingValue::Null,
        })
    );
}
