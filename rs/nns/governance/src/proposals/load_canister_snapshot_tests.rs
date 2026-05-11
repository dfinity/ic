use crate::pb::v1::{LoadCanisterSnapshot, SelfDescribingValue as SelfDescribingValuePb};
use ic_base_types::PrincipalId;
use ic_nns_governance_api::SelfDescribingValue;
use maplit::hashmap;

#[test]
fn test_load_canister_snapshot_to_self_describing() {
    let canister_id = PrincipalId::new_user_test_id(123);
    let snapshot_id = vec![5, 6, 7, 8];

    let load_snapshot = LoadCanisterSnapshot {
        canister_id: Some(canister_id),
        snapshot_id: snapshot_id.clone(),
    };

    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(load_snapshot));

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "canister_id".to_string() => SelfDescribingValue::from(canister_id),
            "snapshot_id".to_string() => SelfDescribingValue::from(snapshot_id),
        })
    );
}
